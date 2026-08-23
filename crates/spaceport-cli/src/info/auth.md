# The auth contract to a hosted app

Spaceport terminates the user's session at its edge. An app whose manifest says `gating: edge` never sees a request spaceport has not authenticated, and every request that reaches it carries a short-lived signed JWT saying who is calling and what they may do.

The app's whole job is: verify that token, and authorize on its `roles`. It never sees a password, a session cookie of spaceport's, or an OAuth flow.

An app whose manifest says `gating: open` gets none of this: no JWT, no `SPACEPORT_*` variables, no cookies set on its domains, and its own `Authorization` headers pass through untouched. Everything below is about `gating: edge`.

## What the app receives

On every gated request that passes the gate:

```
Authorization: Bearer <JWT>
```

and in its environment, at launch:

| variable | meaning |
| --- | --- |
| `SPACEPORT_APP_ID` | the `aud` every token must carry |
| `SPACEPORT_ISSUER` | the `iss` every token must carry — `https://<edge.hostname>`, with the port beside it when it is not 443 |
| `SPACEPORT_JWKS_URL` | where the verifying keys are: `<issuer>/.well-known/jwks.json` |

The two URL variables are absent when the spaceport has no hostname configured — a deployment where a gated app cannot be signed into at all, and where the gate answers `503` rather than vouching for anyone. An app should fail to start on a missing variable rather than fall back to trusting the header.

An app manifest may not set any variable whose name starts with `SPACEPORT` (case-insensitively). That is what keeps an app from being pointed at somebody else's keys.

## The token

```json
{
  "header": {
    "alg": "EdDSA",
    "typ": "JWT",
    "kid": "20260816-001"
  },
  "payload": {
    "iss": "https://spaceport.example.com",
    "sub": "3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40",
    "aud": "knowledge-base",
    "iat": 1785333600,
    "exp": 1785333900,
    "jti": "019fae2c-cf00-7c40-9e1a-6f2d4b7a9c81",
    "roles": ["reader", "writer"]
  }
}
```

- `sub` — the user's stable id, a UUID, never reused. This is the identity to key the app's own rows on. A user's slug can be re-created after a drop and yields a *fresh* id, which is the point: the new user is not the old one. An operator can also bind somebody's IdP account to a user that already exists, before they have ever signed in (`spaceport auth user connect`), which is how a person spaceport already knows arrives under the `sub` the app already has rather than as a second one beside it.
- `aud` — the app id, exactly `SPACEPORT_APP_ID`.
- `roles` — the intersection of the user's entitlements with the roles the deployed manifest declares. Never empty: a user with no overlap gets a `403` from spaceport and the app hears nothing of the request.
- `exp` — five minutes after `iat`. The token is a per-request assertion, not a session.
- `jti` — fresh per token, for an app that wants replay detection.

Signature: Ed25519 (`alg: EdDSA`). Nothing else is ever issued and nothing else must ever be accepted.

## Verifying it

1. Take the bearer token from `Authorization`. No token means no access — never fall back to anything else.
2. Fetch the JWKS from `SPACEPORT_JWKS_URL`, cache it, and pick the key by the token header's `kid`. Refetch when a `kid` is unknown (that is a rotation), with a cooldown so an invalid token cannot make the app hammer the edge.
3. Verify the signature, and require `alg: EdDSA`. Reject `none` and any HMAC algorithm outright — take the algorithm from the app's configuration, not from the token.
4. Require `iss == SPACEPORT_ISSUER` and `aud == SPACEPORT_APP_ID`.
5. Check `exp` (and `nbf`/`iat` if the library does) with 60 seconds of leeway for clock skew.
6. Authorize on `roles`.

The signing key is Ed25519 and rotates every 90 days, or on demand when an operator rotates it. The JWKS carries the current key and keeps a retired one until every token it signed has expired; `kid` says which is which. An app that pins a key rather than reading the JWKS will break at the next rotation.

Node, with `jose`:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose'

const jwks = createRemoteJWKSet(new URL(process.env.SPACEPORT_JWKS_URL))

const { payload } = await jwtVerify(token, jwks, {
  issuer: process.env.SPACEPORT_ISSUER,
  audience: process.env.SPACEPORT_APP_ID,
  algorithms: ['EdDSA'],
  clockTolerance: 60,
})
```

Python, with `PyJWT`:

```python
import jwt

jwks = jwt.PyJWKClient(os.environ["SPACEPORT_JWKS_URL"], cache_keys=True)
key = jwks.get_signing_key_from_jwt(token).key

claims = jwt.decode(
    token,
    key,
    algorithms=["EdDSA"],
    issuer=os.environ["SPACEPORT_ISSUER"],
    audience=os.environ["SPACEPORT_APP_ID"],
    leeway=60,
)
```

## Roles

Roles are the app's own vocabulary, declared in its manifest (`auth.roles`) and granted against by an operator:

```
spaceport auth grant <user-id> writer@<app-id>
```

The app decides what `writer` means; spaceport only decides who holds it. Two consequences worth designing around:

- The names in the manifest are a published interface. Renaming a role in a deploy silently revokes it — entitlements name the old string, and the intersection is computed against the new manifest.
- A role the app understands but nobody was granted simply never appears. There is no implicit role, no "authenticated means reader", and no admin role in the token: spaceport's own admin is whoever can reach the operator socket, which is not something an app can see.

## What must not be trusted

- **Only the JWT.** Everything else in the request came from the client.
- Every request header starting with `X-Spaceport` is stripped by spaceport before the app sees it, on gated and open apps alike. There is no header saying who the user is — if the app is reading one, it is reading a forgery.
- On a gated app every `Authorization` header is stripped and replaced by spaceport's own (after the gate has read any API key out of it), and spaceport's session cookies are removed from the `Cookie` header. The app's own cookies pass through.
- Requests under `auth.public_path_prefixes` carry **no** token. Those paths are reachable signed out, by anyone. Do not put anything behind a public prefix that the app would only serve to a signed-in user.

## Revocation, and how stale a token can be

Spaceport caches a minted JWT for four minutes and mints tokens that live five, so a token in the app's hands is never more than about five minutes older than the entitlement check behind it. Every revocation lever — dropping a session or API key, revoking an entitlement, suspending or dropping a user, dropping a mapping rule, deploying a manifest whose roles changed — purges the cache in the same breath as the database write, so the practical window is a request in flight.

That budget is spent at the edge. It only stays true if the app does not extend it: **do not turn the token into a session of the app's own.** No cookie minted from it, no in-memory "user is logged in" that outlives `exp`, no cached authorization decision with a longer life than the token that justified it. Verify per request; it is a signature check against a cached key, not a network call.

## Signed-out clients, and SPAs

The app rarely sees these — spaceport answers them itself — but the app's *frontend* does:

- A top-level navigation (`GET`, `Sec-Fetch-Mode: navigate`, `Accept: text/html`) without a session is redirected into the sign-in exchange and comes back to the path it asked for.
- Anything else — a `fetch`, an XHR, a POST, a WebSocket upgrade — gets `401` with `WWW-Authenticate: Bearer` and an `X-Spaceport-Login` response header carrying the login URL. A redirect would be swallowed invisibly by whatever scripted the call, so this is the contract: on a `401` the app's frontend reads that header and drives a full-page navigation to it.
- A signed-in user with no role at this app gets `403` from spaceport, not a redirect. Signing in again will not help them; an operator has to grant something.
- Sign-out is `POST https://<SPACEPORT_ISSUER>/logout`, which drops the global session and every app session derived from it. `GET` on that URL renders a confirmation form and logs nobody out. A per-app "log out" link is a link there.

The app must not try to build a login of its own on these. It has no way to mint a session spaceport would honour.

## Cookies and CSRF

Spaceport sets `__Host-spaceport-app-session` on the app's own host and reads it at the edge; the app never sees it. For requests authenticated by that cookie, unsafe methods are checked at the edge before the app is reached: `Sec-Fetch-Site` must not be cross-site, or — where the browser sends none — `Origin` must match the app's host; a request with neither is refused. Requests authenticated by an API key are exempt, because a header a caller sets by hand is not a credential a browser attaches on its own.

That covers the spaceport cookie. Any cookie the *app* sets is the app's own to defend.

## WebSockets

Upgrades are tunnelled to the app. On a gated app the handshake is authenticated exactly like any other request and carries the JWT, so the app reads the identity from the handshake and holds it for the life of the socket. There is nothing to re-check afterwards and nothing to poll: spaceport tracks the tunnel against the credential that opened it and cuts it when that session is dropped, revoked or expires. Upgrades on open apps and under public prefixes tunnel untracked and unauthenticated.

## Machines calling a gated app

An operator mints an API key for a user, scoped to one role at one app:

```
spaceport auth user create ci-bot
spaceport auth session api-key ci-bot writer@<app-id> --expires 90d
```

The key grants exactly that role at exactly that app, whatever the user otherwise holds — no separate `grant` is needed for it.

The caller sends it as `Authorization: Bearer spk_…`. Spaceport validates it, strips it, and hands the app the same JWT shape it always gets — `sub` the owning user, `roles` the key's single role. The app cannot tell an API key from a browser session, and does not need to.

The full key is shown once, at mint. Only its prefix and last four characters can be listed afterwards. Dropping or suspending the owning user revokes it.

App-to-app calls are this and nothing else for now: first-class service identities are a later iteration, so an app calling another hosted app uses an API key minted for a technical user.

## Questions to settle with the app developer

1. Which role names does the app understand, and what does each permit? (They go in the manifest and never change casually.)
2. Where does the app currently get its user identity from, and can that be replaced by `sub` outright? What happens to existing rows keyed on the old identity?
3. Does the app need anything about the user beyond the id and the roles — an email, a display name? The token carries neither, deliberately, and spaceport has no endpoint the app can ask.
4. Does the app have a login, a signup or a password reset of its own? All three have to go behind edge gating, or the app is running two auth systems that disagree.
5. Which requests come from machines rather than browsers, and who owns the technical user each key is minted for?
6. Are there endpoints that must stay reachable signed out (health checks, webhook receivers, static assets on error pages)? Each one is a public prefix, and a public prefix gets no token at all.
7. Is the frontend an SPA? Then it needs the `401` + `X-Spaceport-Login` handling — and needs to stop treating a `401` as "show a login form".
8. Does anything hold state across requests that assumes a long-lived session — server-side sessions, sticky in-memory caches keyed by user? Those outlive revocation and have to be re-thought against a five-minute token.
