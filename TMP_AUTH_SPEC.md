# Global user pool. 
This user pool provides stable user IDs to spaceport and the hosted applications. Human users come from SSO/IdPs (GitHub, Okta, Entra, ...) or via email/one-time code sign-in (same as the minted session below, which can be used for testing before SSO lands). SSO is implemented in a later iteration. Technical or internal users are created through the admin CLI.

- `spaceport auth user list [<pattern>]`
- `spaceport auth user create <slug>`
- `spaceport auth user drop <slug|user-id>`

# Roles and access management
Users have entitlements, each of which connects a user, an app and a role (`Entitlement = (user_id, app_id, role)`). Entitlements are either mapped from SSO at login or manually granted by an admin. Apps declare the roles they understand in their manifest. Only a user that has at least one entitlement for an understood role of an app is allowed to access that app. Entitlements for roles that an app doesn't understand produce a warning, but are stored nevertheless.

- `spaceport auth audit <user-id>`
  Shows the SSO connection, all entitlements this user has and where they are coming from as well as all apps they have access to.
- `spaceport auth mapping list [<app-id>]`
  Prints the mapping including its *stable* rule ID.
- `spaceport auth mapping add <role>[,<role>...]@<app-id> --via <idp> --when <ruleN> ...`
  Adds a mapping for a specific IdP. The rules are `<attr>=<value>` (ie. `org=acme-corp`, `team=authors`) and attributes are IdP-specific. Rules are `AND` across `--when` clauses. At least one `--when` is required. `--via` is verified against the configured connections. `admin` is never a mappable role.
- `spaceport auth mapping drop <rule-id>`
- `spaceport auth grant <user-id> <role>@<app-id>`
- `spaceport auth revoke <user-id> [[<role>@]<app-id>]`
  Revokes an entitlement previously granted by `grant`. Refuses to revoke a mapped grant, printing the mapping instead.

App manifest `auth` section (`gating: edge`):
```yaml
auth:
  gating: edge                # `edge|open`
  public_path_prefixes:       # `/.well-known/acme-challenge/*` is handled before the app and stays public
                              # Matching these paths happens after canonicalization
    - '/public'
    - '/css'
  roles: [ reader, writer ]   # constrained to [a-z][a-z0-9-]*, empty roles is invalid
```

App manifest `auth` section (`gating: open`):
```yaml
auth:
  gating: open
```

An absent `auth` block makes the manifest invalid. `auth` is internally typed on `gating`. 

# Sessions
Sessions are created in spaceport and held in database. When logging in on the web, the user gets an opaque session token in a HTTPS-only cookie on `edge.hostname`. This (global) session expires after `12h`, initially or when expired, it needs another roundtrip to the IdP. App sessions are minted when the user reaches an app's domain without a session cookie (or an expired one) via a redirect exchange with `edge.hostname`. Redirect URLs are allowlisted to this app's domain. The redirect is protected agains replay by a one-time nonce and a short TTL. Per-app/-domain sessions are derived from the originating session and dropped together. API keys are created by an admin through CLI. API keys only grant a specific role for a specific app. API keys are prefixed with `spk_`.
Note on request/redirect handling: Only top-level GET navigations (Sec-Fetch-Mode: navigate, Accept: text/html) redirect; everything else 401. Same for WebSocket upgrades — and note a WS connection authenticated at handshake outlives any revocation.

- `spaceport auth session list <user-id>`
- `spaceport auth session api-key <user-id> <role>@<app-id> [--expires <duration>]`
  Mints an API key and prints that to the console. Default `duration` is `90d`.
- `spaceport auth session mint <user-id> [--expires <duration>]`
  Mints a session and prints the one-time code that can be used for 10 minutes. Default `duration` is `12h`.
- `spaceport auth session drop <user-id> [<session-id>]`
  Logs out the session (or all sessions of that user if `session-id` is omitted)

# Contract to the hosted apps
Spaceport terminates the session at the edge, checks its validity, the permissions of that user and mints a JWT that is handed down to the app as `Authorization: Bearer <JWT>`. The JWT contains the stable user ID (`sub`), the issuer (`iss`), the apps ID (`aud`) and a set of `roles` that this user is entitled for with this app. The JWT is signed. For the app to be able to verify the signed JWT, the JWKS is provided at `https://<edge.hostname>/.well-known/jwks.json`. `SPACEPORT_APP_ID`, `SPACEPORT_ISSUER` and `SPACEPORT_JWKS_URL` env variables provide `aud`, `iss` names and the JWKS URL to the app (with `SPACEPORT_ISSUER` always being `https://<edge.hostname>`, the middleware can also compliantly derive the JWKS URL). 
Header stripping (all case insensitive): When `gating: edge`, spaceport strips all `Authorization` headers (after reading and validating potential API keys) and the session cookie. Any header that starts with `X-Spaceport` is always stripped.
Note on env variables: This also makes it illegal for an app manifest to define any env variable or secret that starts with `SPACEPORT` (case insensitive).
Note on the expiry and caching of the JWT: JWT have a short expiry of `5m` and are cached for `4m` to avoid extensive re-minting on the hot path. Cached JWTs for a user are purged on `spaceport auth session drop`, `spaceport auth revoke` or when manifest roles change on deploy. `spaceport auth mapping drop` deletes all entitlements derived from that rule, then purges affected cached JWTs.
Note on CSRF: Spaceport sets SameSite=Lax + __Host- prefix on the app cookie. For requests authenticated via the session cookie, unsafe methods are rejected at the edge unless Sec-Fetch-Site is present and not cross-site; requests authenticated via API key are exempt, as CSRF only applies to cookie-based authentication.

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
