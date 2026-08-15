//! Getting the bytes of a commit out of GitHub.
//!
//! One commit, one tarball, and — the part that looks wrong until it is
//! explained — two requests to two different hosts. `GET
//! /repos/{owner}/{repo}/tarball/{ref}` does not answer with an archive. It
//! answers `302` to `codeload.github.com`, with a short-lived token in the
//! query string, and codeload refuses a request that carries the
//! `Authorization` header the API call was made with. There is no single
//! request that downloads a private repository's tarball; GitHub does not offer
//! one.
//!
//! So [`crate::connections::github::api::Client::archive_location`] makes the
//! authenticated call and reads the header, and this module makes the second
//! call. It will read as an exception to the rule that spaceport never follows a
//! redirect. It is the opposite: that rule exists because a client that follows
//! a `Location` is a client that replays its credentials to whoever wrote the
//! `Location`, and anybody who can answer as `api.github.com` for one response
//! can write one. Nothing here follows anything — a url arrives, spaceport
//! decides on its own terms whether that url is one it will fetch, and the
//! request it then makes carries no credential at all. The token in the query
//! string is the whole of the authorisation, it is GitHub's own, and it is good
//! for one archive for a few minutes.
//!
//! Two things make that decision safe rather than merely stated. The host is
//! pinned, so a `Location` that has been tampered with is a refusal and not an
//! arbitrary fetch spaceport performs on somebody's behalf. And the body is read
//! frame by frame against a limit, because the thing on the other end of this is
//! a file whose size spaceport did not choose.
//!
//! The seam is [`Archives`] rather than the github [`Transport`], deliberately.
//! That trait is `Request<Bytes> -> Response<Bytes>`: it buffers a whole
//! response into memory with nothing capping it, and its own documentation says
//! that streaming would matter for downloading a tarball and that downloading a
//! tarball is not something it does. Reusing it here would mean reading an
//! unbounded body into memory and checking its size afterwards, which is not a
//! limit. A trait shaped like the one thing this does — a url, a cap, some bytes
//! — is what lets the cap be part of the reading.
//!
//! [`Transport`]: crate::connections::github::api::Transport

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::{Method, Request, Uri, header};
use http_body_util::BodyExt;

/// The only host spaceport will download an archive from.
///
/// GitHub's download host: the API's tarball endpoint redirects here and
/// nowhere else. Pinning it is what turns "spaceport fetches the url GitHub
/// gave it" into something with a bound on it. Without this constant, a
/// `Location` from a compromised or spoofed API response — or from a bug that
/// let one be recorded — is a request spaceport makes to any host on the
/// internet, from inside an operator's network, on a schedule an attacker
/// controls. With it, the worst such a `Location` can do is fail.
///
/// Written out rather than configurable for the same reason the API host is:
/// nothing should be able to point this somewhere else by editing a file.
const DOWNLOAD_HOST: &str = "codeload.github.com";

/// What spaceport calls itself when downloading.
///
/// The same string the API client sends, because it is the same spaceport and
/// the first question about a misbehaving client is which one it is.
const USER_AGENT: &str = concat!("spaceport/", env!("CARGO_PKG_VERSION"));

/// Fetching an archive GitHub has said where to find.
#[async_trait]
pub trait Archives: Send + Sync {
    /// Fetch `url`, refusing anything past `limit` bytes as it arrives.
    async fn fetch(&self, url: &str, limit: u64) -> Result<Bytes>;
}

/// The downloader that actually goes out to the internet.
///
/// A client of its own rather than the github one's, because the two want
/// different things of a response: that one collects small JSON bodies whole,
/// and this one reads a large body under a cap. Sharing a connection pool
/// between them would save a handshake per build, which is nothing next to the
/// build it is part of.
///
/// The TLS configuration is deliberately identical to the API client's — the
/// `ring` provider, this host's own trust anchors, and no plaintext ever. An
/// archive fetched over plaintext is an archive anybody on the path may
/// replace, and the next thing that happens to it is that spaceport builds it
/// and runs it.
pub struct Downloads {
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<Bytes>,
    >,
}

impl Downloads {
    pub fn new() -> Result<Self> {
        // rustls needs a process-wide crypto provider, and a spaceport that
        // serves TLS or has talked to GitHub has already installed one. Losing
        // that race is not an error: both calls install the same provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .context(
                "reading this host's certificate authorities, which github is verified against",
            )?
            // Plaintext to codeload is an archive anybody on the path may
            // swap for one of their own.
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();

        Ok(Self {
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(connector),
        })
    }
}

#[async_trait]
impl Archives for Downloads {
    /// One request, no credential, no redirect followed.
    ///
    /// The headers are as few as GitHub will accept: a user agent, because
    /// GitHub requires one, and nothing else. No `Authorization` above all —
    /// codeload rejects a forwarded one, and a spaceport that sent an
    /// installation token to a host it read out of a header would have given
    /// the token away to whoever wrote the header.
    async fn fetch(&self, url: &str, limit: u64) -> Result<Bytes> {
        let uri = permitted(url)?;

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::USER_AGENT, USER_AGENT)
            .body(http_body_util::Full::new(Bytes::new()))
            .context("preparing the request for the archive")?;

        let response = self
            .client
            .request(request)
            .await
            .context("the archive could not be downloaded")?;

        let status = response.status();
        if status.is_redirection() {
            // hyper follows nothing and nothing here adds it. Codeload is the
            // end of the chain; a redirect from it is either GitHub changing
            // how this works or somebody pointing spaceport elsewhere, and
            // both want a person to look rather than a fetch to happen.
            bail!(
                "the archive's download location answered {status} and redirected somewhere else, which spaceport will not follow"
            );
        }
        if !status.is_success() {
            bail!(
                "the archive's download location answered {status} — the link github gave has probably expired, and the next pass will ask for a fresh one"
            );
        }

        // Checked before a single byte is read, and not relied upon: a
        // `Content-Length` is whatever the other end said, and the reading
        // below is what actually holds.
        if let Some(declared) = declared_length(response.headers())
            && declared > limit
        {
            bail!(
                "the archive says it is {declared} bytes, which is past the {limit} spaceport will download"
            );
        }

        within(response.into_body(), limit).await
    }
}

/// The url as a [`Uri`], if it is one spaceport will fetch at all.
///
/// A free function rather than a step inside [`Archives::fetch`] so that the
/// rule can be tested without a socket: this is the whole of what stands
/// between a `Location` header and an outbound request, and it deserves tests
/// that do not depend on anything being reachable.
fn permitted(url: &str) -> Result<Uri> {
    let uri: Uri = url.parse().with_context(|| {
        format!("github gave `{url}` as the archive's location, which is not a url")
    })?;

    if uri.scheme_str() != Some("https") {
        bail!(
            "the archive's location `{url}` is not https, and spaceport will not download over a connection anybody on the path may rewrite"
        );
    }

    // `host()` is the authority with any userinfo stripped, which is the point:
    // `https://codeload.github.com@elsewhere.example/…` has an authority that
    // begins with the pinned host and a host that is not it.
    let host = uri.host().unwrap_or_default();
    if !host.eq_ignore_ascii_case(DOWNLOAD_HOST) {
        bail!(
            "the archive's location `{url}` is on `{host}` rather than {DOWNLOAD_HOST}, and spaceport downloads from github's own host or from nowhere"
        );
    }

    Ok(uri)
}

/// Read a body whole, giving up the moment it passes `limit`.
///
/// Frame by frame, because a limit applied after collecting the body is not a
/// limit — by the time it could be checked, every byte the other end chose to
/// send is already in this process's memory, which is the thing the limit
/// exists to prevent. This refuses on the frame that crosses the line and drops
/// the connection with it.
///
/// Generic over the body rather than written against hyper's, so that the rule
/// can be tested against a stream constructed in this process. A cap that is
/// only exercised by downloading something large from the internet is a cap
/// nobody tests.
async fn within<B>(mut body: B, limit: u64) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut collected = BytesMut::new();
    let mut total: u64 = 0;

    while let Some(frame) = body.frame().await {
        let frame = frame.context("reading the archive")?;
        let Ok(chunk) = frame.into_data() else {
            // Trailers, which a tarball has nothing to say in.
            continue;
        };

        total += chunk.len() as u64;
        if total > limit {
            bail!(
                "the archive is larger than the {limit} bytes spaceport will download, so it was abandoned part way through"
            );
        }

        collected.extend_from_slice(&chunk);
    }

    Ok(collected.freeze())
}

/// How many bytes a response claims it is about to send, if it said.
fn declared_length(headers: &header::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A location on any host but GitHub's own is the one thing the pin is for:
    /// without it, a tampered-with `Location` is spaceport making a request to
    /// an attacker's host from inside the operator's network.
    #[test]
    fn refuses_a_location_that_is_not_on_githubs_download_host() {
        let error = format!(
            "{:#}",
            permitted("https://elsewhere.example/an-organisation/site.tar.gz").unwrap_err()
        );

        assert!(error.contains("elsewhere.example"), "{error}");
        assert!(error.contains("codeload.github.com"), "{error}");
    }

    /// `https://codeload.github.com@elsewhere.example/…` is a url whose
    /// authority begins with the pinned host and whose host is somebody else's.
    /// Comparing the authority rather than the host would fetch it.
    #[test]
    fn refuses_a_location_that_only_looks_like_the_download_host() {
        let error = format!(
            "{:#}",
            permitted("https://codeload.github.com@elsewhere.example/site.tar.gz").unwrap_err()
        );

        assert!(error.contains("elsewhere.example"), "{error}");
    }

    /// A plaintext download is an archive anybody on the path may replace, and
    /// the next thing spaceport does with it is build it and run it.
    #[test]
    fn refuses_a_location_that_is_not_https() {
        let error = format!(
            "{:#}",
            permitted("http://codeload.github.com/an-organisation/site.tar.gz").unwrap_err()
        );

        assert!(error.contains("not https"), "{error}");
    }

    #[test]
    fn refuses_a_location_that_is_not_a_url_at_all() {
        assert!(permitted("not a url").is_err());
        assert!(permitted("/an-organisation/site.tar.gz").is_err());
    }

    #[test]
    fn accepts_the_location_github_actually_gives_token_and_all() {
        let url =
            "https://codeload.github.com/an-organisation/site/legacy.tar.gz/d34db33f?token=ABCDEF";

        let uri = permitted(url).unwrap();

        assert_eq!(uri.to_string(), url);
    }

    #[tokio::test]
    async fn reads_a_body_that_fits() {
        let body = http_body_util::Full::new(Bytes::from_static(b"a tarball"));

        let bytes = within(body, 64).await.unwrap();

        assert_eq!(bytes, Bytes::from_static(b"a tarball"));
    }

    /// The cap has to bite while the body is arriving. A response that is
    /// collected first and measured afterwards has already spent the memory the
    /// cap exists to protect.
    #[tokio::test]
    async fn abandons_a_body_on_the_frame_that_passes_the_limit() {
        use http_body_util::StreamBody;
        use hyper::body::Frame;

        let frames = futures_util::stream::iter([
            Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"one "))),
            Ok(Frame::data(Bytes::from_static(b"two "))),
            // Never read: the frame before this one has already crossed the
            // line and taken the whole download with it.
            Ok(Frame::data(Bytes::from(vec![b'x'; 1024]))),
        ]);

        let error = format!(
            "{:#}",
            within(StreamBody::new(frames), 9).await.unwrap_err()
        );

        assert!(error.contains("larger than the 9 bytes"), "{error}");
    }

    /// Exactly the limit is not past the limit — a cap that refused the archive
    /// it was sized for would be a cap nobody could pick a number for.
    #[tokio::test]
    async fn allows_a_body_that_is_exactly_the_limit() {
        let body = http_body_util::Full::new(Bytes::from_static(b"123456789"));

        assert_eq!(within(body, 9).await.unwrap().len(), 9);
    }

    /// The check that costs nothing, kept honest: what a response claims about
    /// its own size is worth acting on before reading, and worth nothing after.
    #[test]
    fn reads_the_size_a_response_claims_for_itself() {
        let mut headers = header::HeaderMap::new();
        assert_eq!(declared_length(&headers), None);

        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("4096"),
        );
        assert_eq!(declared_length(&headers), Some(4096));

        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("lots"),
        );
        assert_eq!(declared_length(&headers), None);
    }

    /// The download refuses a bad url before it opens a socket, so this needs
    /// no network at all — which is the point of factoring the check out.
    #[tokio::test]
    async fn the_downloader_refuses_a_url_it_will_not_fetch_without_reaching_for_the_network() {
        let Ok(downloads) = Downloads::new() else {
            eprintln!("skipping: no certificate authorities on this host");
            return;
        };

        let error = format!(
            "{:#}",
            downloads
                .fetch("https://elsewhere.example/site.tar.gz", 1024)
                .await
                .unwrap_err()
        );

        assert!(error.contains("elsewhere.example"), "{error}");
    }
}
