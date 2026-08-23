# The app manifest

A manifest is the whole of what spaceport knows about an app: where its image comes from, which hosts reach it, who is allowed through, and how the container runs. It is a YAML document the app's developer commits to the app's repository, and it never contains a credential — see `secrets` below.

The app's *id* is not in the document. It is what an operator names the app on the command line, so one manifest can be applied twice under two ids:

```
spaceport apps apply <app-id> <manifest.yaml>
```

Applying replaces a running app in place. `--suspended` records the app and claims its hosts — certificates included — without starting it, so `spaceport apps resume` serves immediately. An id is lowercase letters, digits and hyphens, not starting or ending with one, 63 characters at most.

Unknown keys are refused everywhere, on every block. A misspelled `pat:` is an error, never a silently ignored line.

## A complete manifest

```yaml
schema_version: 1

source:
  type: build            # build | image
  dockerfile: Dockerfile # default `Dockerfile`, relative to the checkout
  context: .             # default `.`, relative to the checkout

routing:
  hosts: [my-app.example.com, www.my-app.example.com]

auth:
  gating: edge           # edge | open — required, no default
  roles: [reader, writer]
  public_path_prefixes:
    - /public
    - /css

container:
  port: 8080
  health:
    readiness:
      type: http
      path: /healthz
      initial_delay: 0s
      interval: 1s
      timeout: 5s
      failure_threshold: 30
      success_threshold: 1
    liveness:
      type: http
      path: /healthz
      initial_delay: 10s
      interval: 10s
      timeout: 5s
      failure_threshold: 3
  volumes:
    - name: data
      mount: /var/lib/my-app/data
      read_only: false
  secrets:
    - DB_PASSWORD
  env:
    DATABASE_URL: postgres://user:{{DB_PASSWORD}}@db:5432/my-app
    ENVIRONMENT: production
```

## schema_version

`1`, and nothing else. It is the same schema version the spaceport config carries: one schema, one spaceport.

## source

Either a pre-built image, pulled as given:

```yaml
source:
  type: image
  image: strm/helloworld-http:latest
```

or an image built by spaceport from a checkout of the app's repository:

```yaml
source:
  type: build
  dockerfile: Dockerfile   # default
  context: .               # default
```

Both paths are inside the checkout and are kept there: an absolute path, or one that climbs out with `..`, is refused. A manifest may not name a path on the host — the host paths are spaceport's to choose.

Building needs the repository connected and tracked; see "Building from a repository" below.

## routing

```yaml
routing:
  hosts: [my-app.example.com]
```

At least one host, or nothing could ever reach the app. Each is a hostname without a port, at most 253 characters, labels at most 63, letters, digits, hyphens and dots; it is lowercased when it is read. A host is claimed exclusively — applying an app whose host another app already serves is refused, and so is claiming the host spaceport answers to as itself.

TLS is spaceport's: it terminates HTTPS and forwards plaintext HTTP/1.1 to the container over loopback. The app never sees a certificate and must not try to serve one.

## auth

Required, with no default, because either default would be wrong for somebody: `open` would silently publish an internal tool, `edge` would silently lock a public site's users out.

```yaml
auth:
  gating: edge
  roles: [reader, writer]        # at least one, no duplicates
  public_path_prefixes: [/css]   # optional
```

```yaml
auth:
  gating: open
```

With `gating: edge`, spaceport authenticates every request before the app sees it and hands the app a signed JWT. Roles are `[a-z][a-z0-9-]*`, 63 characters at most; entitlements are granted against exactly these names, and the JWT carries the intersection of what a user holds with what this manifest declares. `roles` may not be empty — an edge-gated app with no roles is one nobody could ever be entitled to.

`public_path_prefixes` are the paths that stay reachable signed out — a login page's CSS, a public feed. Each must start with `/`, must not end with `/`, must carry no query or fragment, no empty and no `.`/`..` segments, and must not be a bare `/` (that is `gating: open`). They match after canonicalization and at segment boundaries: `/public` covers `/public` and `/public/x`, never `/publicfoo`. A public path carries **no** JWT — it is reachable signed out, so a token that sometimes rode along would be a contract the app cannot rely on.

With `gating: open`, `roles` and `public_path_prefixes` are invalid keys, spaceport mints nothing for the app, sets no cookies on its domains, and passes `Authorization` through untouched.

The whole contract an edge-gated app is held to — the JWT, its claims, the env variables, the header stripping, the `401` shape — is `spaceport info auth`.

## container

Every part of it has a default; a manifest that says nothing here is complete.

### port

The port the app listens on *inside* the container. Optional when the image declares exactly one `EXPOSE`; required when it declares none or several. The manifest wins outright and is not checked against the image. `0` is refused.

### health

Two checks, sharing one shape.

`readiness` answers "may traffic go here yet?" — an apply waits for it before routing, and `initial_delay + interval × failure_threshold` is how long it waits before giving up. It defaults to a TCP connect to the routed port, which needs no cooperation from the app.

`liveness` answers "is it still working?" — the same numbers, but `failure_threshold` is how many checks in a row have to fail before spaceport restarts the app. It is **off unless the manifest asks for it**: a liveness check is a standing instruction to restart, and an app that never asked for one does not acquire it by being applied to a newer spaceport. A container that has *exited* is restarted either way.

| field | default | notes |
| --- | --- | --- |
| `type` | `tcp` | `tcp`, `http` or `none`. `none` means: route immediately / never restart. |
| `path` | — | required by `http`, refused for anything else |
| `interval` | `1s` | must not be zero, at most an hour |
| `initial_delay` | `0s` | at most an hour |
| `timeout` | `5s` | must not be zero, at most an hour |
| `failure_threshold` | `30` | at least 1, at most 3600 |
| `success_threshold` | `1` | at least 1, at most 3600 |

A probe `port` of its own is not supported: checks use the port traffic is routed to.

An `http` check passes on any non-error status. Keep the path cheap and dependency-free — a readiness path that talks to a database turns a slow database into an app that never comes up.

### volumes

```yaml
volumes:
  - name: data
    mount: /var/lib/my-app/data
    read_only: false     # default
```

The host path is spaceport's to choose: `<data-dir>/<app-id>/<volume-name>`. `name` is letters, digits, hyphens and underscores, 63 characters at most — it becomes one path segment. `mount` must be absolute and not `/`. No two volumes may share a name or a mount point.

Volumes survive restarts, redeploys and `spaceport apps destroy`.

The directory is created owned by the image's `USER` when that is a number. A `USER` given as a name cannot be resolved from outside the image, so the volume stays owned by root and spaceport says so at launch — an app that runs as a named non-root user should either use a numeric `USER` or `chown` at start.

Everything outside a volume is lost when the container is replaced, which happens on every apply and every deploy.

### secrets and env

`env` is the environment the container runs with. `secrets` declares the names of values that are *not* in the document; each is interpolated into an `env` value with `{{NAME}}`:

```yaml
secrets:
  - DB_PASSWORD
env:
  DATABASE_URL: postgres://user:{{DB_PASSWORD}}@db:5432/my-app
```

The two sides have to agree exactly: every `{{...}}` must name a declared secret, and every declared secret must be interpolated by some `env` value. Both directions are errors, because either one means an app comes up missing something it was promised. `{{` always opens a reference and there is no escape for a literal one.

Values are set by an operator, never in the manifest:

```
spaceport apps secret set <app-id> DB_PASSWORD -    # `-` reads from stdin
spaceport apps secret list <app-id>
```

Applying an app whose declared secrets are not all set leaves it **suspended and not serving** — including an app that was running before the apply — and names what is missing. Setting the last one starts it; setting a secret on a running app replaces its container with one carrying the new value. Values cannot be read back out of spaceport; an operator who lost one sets a new one.

Variable names are C identifiers: a letter or underscore, then letters, digits and underscores.

Names starting with `SPACEPORT` (case-insensitively) are refused in both `env` and `secrets`. They are spaceport's own channel to the app — see `spaceport info auth` — and an app that could shadow one could point its own token verification at somebody else's keys.

## What spaceport reserves

- `/.spaceport/*` on **every** host it serves, apps included. The sign-in callback lives there. An app cannot serve or shadow that prefix.
- `/.well-known/acme-challenge/*`, answered by spaceport for certificate issuance.
- Request headers starting with `X-Spaceport` — always stripped on the way to the app, whatever the gating, so a client cannot forge spaceport's voice.
- `SPACEPORT_*` environment variables.

What the app *does* receive: the original path and query byte for byte, the `Host` it was addressed as (restored for HTTP/2 requests, with the port beside it when it is not 443), and `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-For`. `X-Forwarded-For` is *replaced* with the address of the peer spaceport is talking to, not appended to — anything a client sent under that name is discarded.

WebSockets are tunnelled. On a gated app the handshake is authenticated like any other request, and the tunnel is cut when the session behind it is dropped, revoked or expires.

## Building from a repository

For `source.type: build`, an operator connects the repository once (`spaceport connect github`) and then tells spaceport which branch the app follows:

```
spaceport apps track <app-id> <owner>/<repo> --connection <slug> --branch main
spaceport apps deploy <app-id>
```

Tracking builds the branch's current head and every push after it. A build produces an image and nothing more — running it is `spaceport apps deploy`, a step an operator takes when they are ready for it, unless `--deploy` says otherwise.

The manifest for a tracked app comes **out of the commit being built**, at `spaceport.yaml` in the repository root unless `--manifest-path` says otherwise. So for a tracked app the document is versioned with the code it describes, and a monorepo holding several apps gives each one its own path. This is what tells apps that track the same repository and branch apart.

## Questions to settle with the app developer

Everything below has to be answered before a manifest can be written, and none of it can be guessed from the code with any confidence.

**Reachability**

1. Which hostnames should serve this app? Is one of them the canonical one, with the rest redirecting — and if so, does the *app* do that redirect, since spaceport does not?
2. Which port does the app listen on inside the container, and does the image `EXPOSE` exactly that one?

**Access**

3. `gating: edge` or `gating: open`? Anything without a good reason to be world-readable should be `edge`.
4. If edge-gated: which role names does the app understand, and what does each one mean in the app? These names are the contract — operators grant against them and the app authorizes on them.
5. Are there paths that must work signed out — health endpoints hit by something outside spaceport, static assets on a login screen, webhooks from a third party? Note that a webhook receiver behind `edge` gating cannot be reached by the sender at all; it needs a public prefix or an API key.
6. Does the app already have its own login? Two auth systems on one app is a decision, not an accident — usually the app's own should go.

**Running**

7. Does the app have a cheap readiness endpoint, and is it dependency-free? What is the app's realistic worst-case startup time (that sets `failure_threshold × interval`)?
8. Should spaceport restart the app when it stops working while still running — and if so, is the liveness path genuinely a liveness signal, not a deep dependency check that would restart the app whenever a database blinks?
9. What state must survive a redeploy, and at which absolute paths inside the container? Everything else is lost on every apply.
10. Which numeric UID does the container run as? (For volume ownership.)

**Configuration**

11. Which environment variables does the app read, and which of them are secrets? What are the non-secret values per environment?
12. Does anything the app reads from the environment start with `SPACEPORT`? It cannot; it has to be renamed.

**Delivery**

13. Pre-built image or built by spaceport from the repository? If built: which Dockerfile, which build context, which branch?
14. Does the app need to call another hosted app? That needs an API key minted for a technical user — see `spaceport info auth`.
