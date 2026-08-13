//! An ACME CA, answered in this process.
//!
//! Enough of RFC 8555 to take spaceport through a whole order: a directory, a
//! nonce, an account, an order with one authorization and one `http-01`
//! challenge, and a certificate at the end of it. Requests never leave the
//! process — [`super::Transport::Supplied`] hands instant-acme an HTTP client
//! that is this.
//!
//! The part that makes it worth having: when spaceport says the challenge is
//! ready, this fetches the answer **through the real edge router**, the same
//! way a CA would fetch it over port 80. So what is under test is the wiring
//! spaceport owns — publish the token, answer for exactly as long as the order
//! is in flight, stop — and not a mock of it.
//!
//! What it deliberately does not do is verify the JWS signatures. Signing is
//! instant-acme's job and it has its own tests for it; re-checking it here
//! would only test that this file and that crate agree.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::acme::{Challenges, certificate};
use crate::edge::routes;

/// A CA that issues to anybody who can answer a challenge.
pub(super) struct FakeDirectory {
    challenges: Arc<Challenges>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Accounts registered, and the contacts they gave.
    registrations: Vec<Vec<String>>,
    /// Orders placed, by number.
    orders: Vec<Order>,
    /// Hosts whose challenge this actually fetched and accepted.
    validated: Vec<String>,
    /// Refuse every challenge, however correct the answer.
    refuse_validation: bool,
    /// Offer only a challenge type spaceport cannot answer.
    only_dns: bool,
}

struct Order {
    host: String,
    token: String,
    status: &'static str,
    certificate: Option<String>,
}

impl FakeDirectory {
    /// The directory URL this answers on. Never resolved, never connected to.
    pub(super) const URL: &'static str = "https://acme.test/directory";

    pub(super) fn new(challenges: Arc<Challenges>) -> Arc<Self> {
        Arc::new(Self {
            challenges,
            state: Mutex::new(State::default()),
        })
    }

    /// A transport that reaches this directory and nothing else.
    pub(super) fn transport(self: &Arc<Self>) -> super::Transport {
        let directory = self.clone();

        super::Transport::Supplied(Box::new(move || {
            Box::new(FakeClient {
                directory: directory.clone(),
            })
        }))
    }

    /// How many accounts have been registered here.
    pub(super) fn registrations(&self) -> usize {
        self.state.lock().unwrap().registrations.len()
    }

    /// The contacts each registration gave.
    pub(super) fn contacts(&self) -> Vec<Vec<String>> {
        self.state.lock().unwrap().registrations.clone()
    }

    /// The hosts whose challenge this fetched and accepted.
    pub(super) fn validated(&self) -> Vec<String> {
        self.state.lock().unwrap().validated.clone()
    }

    /// Behave like a CA whose lookup lands somewhere else entirely — the shape
    /// of every "the DNS does not point here yet" failure.
    pub(super) fn refuse_validation(&self) {
        self.state.lock().unwrap().refuse_validation = true;
    }

    /// Offer only `dns-01`, which spaceport has no way to answer.
    pub(super) fn offer_only_dns(&self) {
        self.state.lock().unwrap().only_dns = true;
    }

    async fn handle(&self, request: Request<BodyWrapper<Bytes>>) -> Response<Body> {
        let path = request.uri().path().to_owned();
        let body = request
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();
        let payload = payload(&body);

        match path.split('/').collect::<Vec<_>>().as_slice() {
            ["", "directory"] => self.directory(),
            ["", "nonce"] => nonce_only(),
            ["", "new-account"] => self.new_account(&payload),
            ["", "new-order"] => self.new_order(&payload),
            ["", "authz", number] => self.authorization(index(number)),
            ["", "challenge", number] => self.ready(index(number)).await,
            ["", "order", number] => self.order(index(number)),
            ["", "order", number, "finalize"] => self.finalize(index(number)),
            ["", "order", number, "cert"] => self.certificate(index(number)),
            _ => problem(StatusCode::NOT_FOUND, "no such resource"),
        }
    }

    fn directory(&self) -> Response<Body> {
        ok(json!({
            "newNonce": "https://acme.test/nonce",
            "newAccount": "https://acme.test/new-account",
            "newOrder": "https://acme.test/new-order",
        }))
    }

    fn new_account(&self, payload: &Value) -> Response<Body> {
        let contact = payload["contact"]
            .as_array()
            .map(|contacts| {
                contacts
                    .iter()
                    .filter_map(|contact| contact.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let mut state = self.state.lock().unwrap();
        state.registrations.push(contact);
        let id = state.registrations.len();

        created(
            &format!("https://acme.test/account/{id}"),
            json!({"status": "valid"}),
        )
    }

    fn new_order(&self, payload: &Value) -> Response<Body> {
        let host = payload["identifiers"][0]["value"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let mut state = self.state.lock().unwrap();
        let number = state.orders.len();
        // A token a CA hands out is unguessable and used once. Only the second
        // matters here.
        let token = format!("token-{number}-for-{host}");
        state.orders.push(Order {
            host,
            token,
            status: "pending",
            certificate: None,
        });

        created(
            &format!("https://acme.test/order/{number}"),
            order_state(number, &state.orders[number]),
        )
    }

    fn authorization(&self, number: usize) -> Response<Body> {
        let state = self.state.lock().unwrap();
        let Some(order) = state.orders.get(number) else {
            return problem(StatusCode::NOT_FOUND, "no such authorization");
        };

        let challenge = if state.only_dns {
            json!({
                "type": "dns-01",
                "url": format!("https://acme.test/challenge/{number}"),
                "token": order.token,
                "status": "pending",
            })
        } else {
            json!({
                "type": "http-01",
                "url": format!("https://acme.test/challenge/{number}"),
                "token": order.token,
                "status": "pending",
            })
        };

        ok(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": order.host},
            "challenges": [challenge],
        }))
    }

    /// Spaceport says it is ready, so go and look — over HTTP, through the
    /// router the edge serves, exactly as a CA would.
    async fn ready(&self, number: usize) -> Response<Body> {
        let (token, host, refuse) = {
            let state = self.state.lock().unwrap();
            let Some(order) = state.orders.get(number) else {
                return problem(StatusCode::NOT_FOUND, "no such challenge");
            };

            (
                order.token.clone(),
                order.host.clone(),
                state.refuse_validation,
            )
        };

        let answered = self.fetch_challenge(&token).await;
        let expected = self.challenges.answer(&token);
        let accepted = !refuse && answered.is_some() && answered == expected;

        let mut state = self.state.lock().unwrap();
        if accepted {
            state.validated.push(host);
            state.orders[number].status = "ready";
        } else {
            state.orders[number].status = "invalid";
        }

        ok(json!({
            "type": "http-01",
            "url": format!("https://acme.test/challenge/{number}"),
            "token": token,
            "status": if accepted { "valid" } else { "invalid" },
        }))
    }

    /// `GET /.well-known/acme-challenge/{token}` against the real router.
    async fn fetch_challenge(&self, token: &str) -> Option<String> {
        let response = routes::router(self.challenges.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/acme-challenge/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() != StatusCode::OK {
            return None;
        }

        let body = response.into_body().collect().await.unwrap().to_bytes();

        Some(String::from_utf8(body.to_vec()).unwrap())
    }

    fn order(&self, number: usize) -> Response<Body> {
        let state = self.state.lock().unwrap();
        match state.orders.get(number) {
            Some(order) => ok(order_state(number, order)),
            None => problem(StatusCode::NOT_FOUND, "no such order"),
        }
    }

    /// Issue. The certificate is self-signed — nothing in the test verifies a
    /// chain, and what is being tested is that the right host's certificate
    /// comes back and is stored and served.
    fn finalize(&self, number: usize) -> Response<Body> {
        let mut state = self.state.lock().unwrap();
        let Some(order) = state.orders.get_mut(number) else {
            return problem(StatusCode::NOT_FOUND, "no such order");
        };

        let (chain, _) = certificate::self_signed(std::slice::from_ref(&order.host)).unwrap();
        order.certificate = Some(chain);
        order.status = "valid";

        ok(order_state(number, &state.orders[number]))
    }

    fn certificate(&self, number: usize) -> Response<Body> {
        let state = self.state.lock().unwrap();
        match state.orders.get(number).and_then(|o| o.certificate.clone()) {
            Some(chain) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/pem-certificate-chain")
                .header("replay-nonce", "nonce")
                .body(Body::from(chain))
                .unwrap(),
            None => problem(StatusCode::NOT_FOUND, "not issued"),
        }
    }
}

fn order_state(number: usize, order: &Order) -> Value {
    let mut state = json!({
        "status": order.status,
        "identifiers": [{"type": "dns", "value": order.host}],
        "authorizations": [format!("https://acme.test/authz/{number}")],
        "finalize": format!("https://acme.test/order/{number}/finalize"),
    });

    if order.certificate.is_some() {
        state["certificate"] = json!(format!("https://acme.test/order/{number}/cert"));
    }

    state
}

/// The JWS payload of a request, decoded. Unsigned and unverified: see the
/// module docs for why.
fn payload(body: &[u8]) -> Value {
    let Ok(jws) = serde_json::from_slice::<Value>(body) else {
        return Value::Null;
    };
    let Some(encoded) = jws["payload"].as_str() else {
        return Value::Null;
    };

    base64_url_decode(encoded)
        .and_then(|decoded| serde_json::from_slice(&decoded).ok())
        .unwrap_or(Value::Null)
}

/// Unpadded base64url, as JOSE uses it.
fn base64_url_decode(encoded: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let index: HashMap<u8, u32> = ALPHABET
        .iter()
        .enumerate()
        .map(|(value, &symbol)| (symbol, value as u32))
        .collect();

    let mut decoded = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;

    for symbol in encoded.bytes() {
        accumulator = (accumulator << 6) | index.get(&symbol).copied()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }

    Some(decoded)
}

fn index(number: &str) -> usize {
    number.parse().unwrap_or(usize::MAX)
}

/// Every response carries a nonce: the spec says so, and instant-acme fetches
/// one from `newNonce` if it is missing, which only makes the tests slower.
fn ok(body: Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("replay-nonce", "nonce")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn created(location: &str, body: Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::LOCATION, location)
        .header("replay-nonce", "nonce")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn nonce_only() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("replay-nonce", "nonce")
        .body(Body::empty())
        .unwrap()
}

fn problem(status: StatusCode, detail: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/problem+json")
        .header("replay-nonce", "nonce")
        .body(Body::from(
            json!({"type": "urn:ietf:params:acme:error:malformed", "detail": detail}).to_string(),
        ))
        .unwrap()
}

/// One instant-acme HTTP client, pointed at a [`FakeDirectory`].
struct FakeClient {
    directory: Arc<FakeDirectory>,
}

impl HttpClient for FakeClient {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let directory = self.directory.clone();

        Box::pin(async move { Ok(BytesResponse::from(directory.handle(request).await)) })
    }
}
