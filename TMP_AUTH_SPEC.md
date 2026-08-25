# Global user pool. 
This user pool provides stable user IDs to spaceport and the hosted applications. Human users come from SSO/IdPs (GitHub, Okta, Entra, ...) or via email/one-time code sign-in (same as the minted session below, which can be used for testing before SSO lands). SSO is implemented in a later iteration. Technical or internal users are created through the admin CLI.
User IDs are UUIDs and are never reused. Dropping a user cascades: all sessions (including derived app sessions and open WebSocket connections), API keys, entitlements and cached JWTs die with the user. A slug can be re-created after a drop, but yields a fresh user ID. A slug is a name and not an identity: it may be changed in place (`spaceport auth user rename`), and doing so moves the name only — the user ID, entitlements, sessions, API keys, cached JWTs and identity bindings are all untouched, and the person stays signed in. The new slug must be free, exactly as at creation. Suspending a user has the same immediate effect as dropping it (sessions, keys and cached JWTs are invalidated) but keeps the record and entitlements; resume restores access but does not resurrect sessions or keys.

Email/one-time-code sign-in: the login page on `edge.hostname` accepts an email address; if (and only if) it belongs to a known, non-suspended user, a single-use code is sent via the configured SMTP connection. Codes are 8 characters from an unambiguous alphabet, valid for 10 minutes, invalidated after 5 failed attempts; at most 5 codes per email per hour, and the response is identical whether or not the email is known.

Every login method authenticates by its own credential and never another's. A login asserts exactly one thing: that whoever is standing there controls *that* connection's credential *at the time of login* — the mailbox for email/one-time-code sign-in, the numeric account ID for GitHub, the IdP's stable subject for any other IdP. It asserts nothing about any other connection's credential, and nothing about who the person is. In particular an address an IdP reports as verified is a stored third-party claim about the email connection's credential, made at some past moment and never revalidated; it is never accepted in place of that credential, and an IdP login never writes one either — `--email` is set by an operator, deliberately, or not at all.

It follows that an IdP login resolves to an existing user only through a stored identity for (connection, external ID). A new user is created only when the login's attributes satisfy at least one of that connection's mapping rules, and a login matching no rule is refused without a user, session or entitlement being written for it. An IdP login never binds an identity onto a user that already holds a different one on that connection: joining two connections to one user is done by binding the second identity from a session already authenticated by the first, never by inferring the join from anything a login happens to carry.

A binding may also be *asserted* by an operator at the socket, which is a different act from a login inferring one and is allowed for the same reason `--email` is: the admin is deliberately stating who this account belongs to, under their own authority, and the auth event log records that they did. `spaceport auth user connect <slug|user-id> <connection>:<login>` — and `--connect` on `user create`, which is the same act folded into the creation — resolves the handle to the IdP's stable external ID *at that moment* and stores the identity against it, refusing if the IdP does not know the handle rather than storing a binding that would silently never match. The handle is recorded beside the external ID for the human reading an audit and is never what resolution keys on: handles are renameable and reusable, so a binding stored by handle would follow the name to whoever holds it next. An operator-asserted binding carries no attributes and no last login until the person actually signs in, and it grants nothing by itself — entitlements still come from a `grant` or from the mapping rules. The two refusals a login is held to hold here too: the connection's external ID may belong to only one user, and a user may hold only one identity per connection, so re-pointing one means `disconnect` first.

Because resolution keys on the stored identity and the mapping-rule gate applies only to *creation*, a user an operator has bound and granted signs in through that connection without any mapping rule matching them — which is how a single named person is let in without opening a rule that admits everyone their org contains.

All `spaceport auth` commands run over the operator interface (unix socket); whoever can reach the socket is the admin — there is no separate in-band admin role. Every mutating command is recorded in the auth event log.

- `spaceport auth user list [<pattern>]`
- `spaceport auth user create <slug> [--email <addr>] [--connect <connection>:<login>]`
- `spaceport auth user connect <slug|user-id> <connection>:<login>`
- `spaceport auth user disconnect <slug|user-id> <connection>`
- `spaceport auth user rename <slug|user-id> <slug>`
- `spaceport auth user suspend <slug|user-id>`
- `spaceport auth user resume <slug|user-id>`
- `spaceport auth user drop <slug|user-id>`

# Roles and access management
Users have entitlements, each of which connects a user, an app and a role (`Entitlement = (user_id, app_id, role)`). Entitlements are either mapped from SSO at login or manually granted by an admin. Mapped entitlements are tagged with the rule ID that produced them; every IdP login fully re-syncs the user's mapped entitlements (rules that no longer match remove their entitlements, new matches add them) — manual grants are untouched. Since a session forces an IdP roundtrip at least every `12h`, a user removed from the IdP loses mapped access within one session lifetime. This latency is accepted for now — `spaceport auth user suspend|drop` is the immediate-offboarding lever; periodic IdP reconciliation (as already done for GitHub repos) is a possible later iteration. Apps declare the roles they understand in their manifest. Only a user that has at least one entitlement for an understood role of an app is allowed to access that app. Entitlements for roles that an app doesn't understand produce a warning, but are stored nevertheless.

- `spaceport auth audit <user-id>`
  Shows the SSO connection, all entitlements this user has and where they are coming from as well as all apps they have access to.
- `spaceport auth log [<user-id>]`
  Prints the append-only auth event log: logins (and failed code attempts), logouts, session/API-key mints and drops, grants, revokes, mapping changes, user create/suspend/resume/drop — each with timestamp and origin (which IdP, or that it came through the operator CLI).
- `spaceport auth mapping list [<app-id>]`
  Prints the mapping including its *stable* rule ID.
- `spaceport auth mapping add <role>[,<role>...]@<app-id> --via <idp> --when <ruleN> ...`
  Adds a mapping for a specific IdP. The rules are `<attr>=<value>` (ie. `org=acme-corp`, `team=authors`) and attributes are IdP-specific. A rule matches when the attribute equals the value, or — for multi-valued attributes like group lists — contains it. Rules are `AND` across `--when` clauses; this is deliberately all the expressiveness there is (no `OR`, no negation) — `OR` is spelled "add another mapping". At least one `--when` is required. `--via` is verified against the configured connections; attribute names are not verifiable and a typo silently never matches, which is what `mapping test` is for. `admin` is never a mappable role.
- `spaceport auth mapping test <user-id>`
  Dry-run: re-evaluates all mappings against the attributes stored from the user's last IdP login and prints which rules match and which entitlements would result, without changing anything.
- `spaceport auth mapping drop <rule-id>`
- `spaceport auth grant <user-id> <role>@<app-id>`
- `spaceport auth revoke <user-id> [<role>@]<app-id>`
- `spaceport auth revoke <user-id> --all`
  Revokes an entitlement previously granted by `grant`; `--all` is required to revoke everything across apps. Refuses to revoke a mapped grant, printing the mapping instead.

App manifest `auth` section (`gating: edge`):
```yaml
auth:
  gating: edge                # `edge|open`
  public_path_prefixes:       # `/.well-known/acme-challenge/*` is handled before the app and stays public
                              # Matching these paths happens after canonicalization
                              # Prefixes match at segment boundaries: `/public` matches `/public` and `/public/x`, not `/publicfoo`
    - '/public'
    - '/css'
  roles: [ reader, writer ]   # constrained to [a-z][a-z0-9-]*, empty roles is invalid
```

App manifest `auth` section (`gating: open`):
```yaml
auth:
  gating: open
```

An absent `auth` block makes the manifest invalid. `auth` is internally typed on `gating`. With `gating: open`, spaceport never mints app sessions or JWTs for that app, sets no cookies on its domain, and passes `Authorization` headers through untouched; `X-Spaceport*` headers are still stripped.

# Sessions
Sessions are created in spaceport and held in database. When logging in on the web, the user gets an opaque session token in a HTTPS-only cookie on `edge.hostname`. This (global) session expires after `12h`, initially or when expired, it needs another roundtrip to the IdP. The roundtrip is silent when the IdP supports it and its own session is still valid (OIDC `prompt=none`, or the IdP just not prompting on a live SSO session): the user bounces through the IdP without interaction and gets a fresh `12h` session — so a session effectively slides for as long as the IdP session lives, and interactive login is only needed when the IdP demands it. App sessions are minted when the user reaches an app's domain without a session cookie (or an expired one) via a redirect exchange with `edge.hostname`. Redirect URLs are allowlisted to this app's domain. The redirect is protected agains replay by a one-time nonce and a short TTL. The exchange carries the originally requested URL; after minting the app session the user is redirected to its path+query on the app's domain (scheme and host are forced to the app's, never taken from the request). Per-app/-domain sessions are derived from the originating session, inherit its expiry and are dropped together. Session validity is checked in the database on every mint and purge; between purges the `4m` JWT cache below is the only staleness window on the hot path. API keys are created by an admin through CLI. API keys only grant a specific role for a specific app. API keys are prefixed with `spk_` and stored hashed; the full key is shown exactly once at mint, `list` shows only prefix and last four characters. Dropping the owning user revokes their API keys.
`https://<edge.hostname>/logout` (POST) drops the global session and all derived app sessions; a per-app logout is a redirect to that URL.
Note on request/redirect handling: Only top-level GET navigations (Sec-Fetch-Mode: navigate, Accept: text/html) redirect; everything else gets a `401` carrying `WWW-Authenticate: Bearer` and an `X-Spaceport-Login` response header with the login URL, so SPAs can detect expiry and bounce through the redirect exchange. Same for WebSocket upgrades — WS connections are tracked per session and terminated when their session is dropped, revoked or expires, so handshake auth never outlives revocation.

- `spaceport auth session list <user-id>`
  Lists sessions and API keys.
- `spaceport auth session api-key <user-id> <role>@<app-id> [--expires <duration>]`
  Mints an API key and prints that to the console. Default `duration` is `90d`.
- `spaceport auth session mint <user-id> [--expires <duration>]`
  Mints a session and prints the one-time code that can be used for 10 minutes. Default `duration` is `12h`.
- `spaceport auth session drop <user-id> [<session-id>|<key-id>]`
  Logs out the session or revokes the API key (or all sessions and keys of that user if the ID is omitted)

# Contract to the hosted apps
Spaceport terminates the session at the edge, checks its validity, the permissions of that user and mints a JWT that is handed down to the app as `Authorization: Bearer <JWT>`. The JWT contains the stable user ID (`sub`), the issuer (`iss`), the apps ID (`aud`) and a set of `roles` that this user is entitled for with this app. `roles` is the intersection of the user's entitlements with the roles the deployed manifest declares; an empty intersection is a `403` (after login, for navigations a plain "no access" page), never an empty-`roles` JWT. Requests authenticated by API key produce the same JWT shape with `sub` = the owning user and `roles` = the key's single role. The JWT is signed. For the app to be able to verify the signed JWT, the JWKS is provided at `https://<edge.hostname>/.well-known/jwks.json`. `SPACEPORT_APP_ID`, `SPACEPORT_ISSUER` and `SPACEPORT_JWKS_URL` env variables provide `aud`, `iss` names and the JWKS URL to the app (with `SPACEPORT_ISSUER` always being `https://<edge.hostname>`, the middleware can also compliantly derive the JWKS URL). 
Header stripping (all case insensitive): When `gating: edge`, spaceport strips all `Authorization` headers (after reading and validating potential API keys) and the session cookie. Any header that starts with `X-Spaceport` is always stripped.
Note on env variables: This also makes it illegal for an app manifest to define any env variable or secret that starts with `SPACEPORT` (case insensitive).
Note on the expiry and caching of the JWT: JWT have a short expiry of `5m` and are cached for `4m` to avoid extensive re-minting on the hot path. Cached JWTs for a user are purged on `spaceport auth session drop`, `spaceport auth revoke`, suspend/drop of the user or when manifest roles change on deploy. `spaceport auth mapping drop` deletes all entitlements derived from that rule, then purges affected cached JWTs. The cache is in-memory in the spaceport process (single edge), so purges are immediate.
Note on signing keys: the signing key is Ed25519, rotated every `90d`. The JWKS always contains the current key and keeps a retired key until every JWT signed with it has expired (`kid` disambiguates). Apps should verify with standard leeway of `60s` for clock skew.
Note on CSRF: Spaceport sets SameSite=Lax + __Host- prefix on the app cookie. For requests authenticated via the session cookie, unsafe methods are checked at the edge: if Sec-Fetch-Site is present it must not be cross-site; if it is absent (old Safari, WebViews), the Origin header must match the app's domain; if both are absent, the request is rejected. Requests authenticated via API key are exempt, as CSRF only applies to cookie-based authentication.

Out of scope for this iteration: app-to-app machine identity. Apps calling other hosted apps must use an API key minted for a technical user; first-class service identities are a later iteration.

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
