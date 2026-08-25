<p align="center"><img src="logo.png" alt="spaceport" width="160"></p>

# spaceport

A reverse proxy for small and internal apps.

One binary on one Linux host. It terminates TLS, routes hostnames to Docker containers it supervises, builds those containers from GitHub commits it tracks, and authenticates every request at the edge — so an app never sees a visitor spaceport has not identified. What the app gets instead of a session is a short-lived signed token saying who is calling and what they may do.

The unit of work is an **app**: an id, a manifest, and one or more hostnames. You hand spaceport a manifest, it claims the hosts, gets the certificates, runs the container, and puts an auth gate in front of it.

## Requirements

- Linux with systemd (for `spaceport setup`; `spaceport run` itself works anywhere)
- A reachable Docker daemon — spaceport talks to it the way the `docker` CLI would, honouring `DOCKER_HOST`, and refuses to start without it
- Ports 80 and 443, or whatever you point `edge.listen` at
- A hostname pointing at the machine, if you want real certificates or edge-gated apps

## Install

Download a release from [github.com/mtrense/spaceport/releases](https://github.com/mtrense/spaceport/releases) — `x86_64` and `aarch64`, glibc and fully static musl. Every artifact ships a `.sha256` and a build-provenance attestation; the checksum catches corruption, the attestation is the part worth verifying.

```sh
tar xzf spaceport-<version>-x86_64-unknown-linux-musl.tar.gz
sudo ./spaceport setup --operator /run/spaceport.sock
```

`setup` copies the binary to `/usr/local/bin/spaceport`, writes a reference config to `/etc/spaceport/spaceport.yaml` if the host has none, and installs, enables and starts `spaceport.service`. It never overwrites a config you have edited. Re-running it is the upgrade path; running it without `--operator` takes the operator socket away again.

Or build it yourself:

```sh
cargo build --release --locked --package spaceport-cli   # -> target/release/spaceport
scripts/cross-compile.sh                                 # all four Linux targets, via docker
```

## Configuration

One YAML file, `/etc/spaceport/spaceport.yaml` by default (`--config` elsewhere). `spaceport setup` leaves a fully commented copy behind; `examples/config.yaml` is the same thing pointed at a working directory for local runs.

```yaml
schema_version: 1
edge:
  hostname: spaceport.example.com     # spaceport's own host: login, JWKS, webhooks
  listen:
    http: 0.0.0.0:80
    https: 0.0.0.0:443
  tls:
    provider: acme                    # or self-signed, trusted by nothing
    acme:
      directory: staging              # staging | production | a directory URL
      contact: [mailto:ops@example.com]
      terms_of_service_agreed: true
state:
  directory: /var/lib/spaceport       # keys and records, owner-only
data:
  directory: /var/lib/spaceport/apps  # app volumes — this is what you back up
build:
  directory: /var/lib/spaceport/builds
  keep: 3
```

The three directories are separate on purpose: state holds signing keys and is owner-only, data is the only thing worth backing up, and builds is the only directory spaceport deletes from. Without `edge.hostname` there is no issuer and no JWKS, so edge-gated apps answer `503`.

Unknown keys are refused rather than ignored, which means downgrading a spaceport means downgrading its config with it. Check before restarting:

```sh
spaceport check config     # the file: hosts, listeners, TLS, directories
spaceport check state      # the store: schema version, apps, certificates
```

### Environment

| Variable | Applies to | Meaning |
| --- | --- | --- |
| `SPACEPORT_SERVER` | every client command | Operator socket path, default `/run/spaceport.sock`. Same as `-s`. |
| `SPACEPORT_TIMEOUT` | every client command | How long to wait for the server, default `30s`. |
| `SPACEPORT_STREAM` | `spaceport run` | What `spaceport stream` carries, default `spaceport=debug`. |
| `RUST_LOG` | `spaceport run` | The service's own log, default `spaceport=info,warn`. |
| `DOCKER_HOST` | `spaceport run` | Where the engine is. |
| `NO_COLOR` | all | Suppresses colour under `--color=auto`. |

Durations everywhere (`--expires`, timeouts, health probes) are a whole number and a unit: `ms`, `s`, `m`, `h`, `d`. No fractions, no `1h30m`.

## Running apps

An app is applied from a manifest. Everything a manifest can say — sources, hosts, gating, roles, ports, health probes, volumes, secrets, what spaceport reserves and what the container receives — is documented by the binary itself:

```sh
spaceport info manifest
```

That is the reference; this README will not repeat it. `examples/app-manifest.yaml` is the same contract as a commented YAML file, and `examples/echo.yaml` is a two-line one to try.

```sh
spaceport apps apply blog ./blog.yaml       # --suspended to claim hosts without serving
spaceport apps list                         # optional glob pattern
spaceport apps show blog --manifest
spaceport apps suspend blog --stop-container
spaceport apps resume blog
spaceport apps destroy blog                 # volumes under the data directory survive
```

### Secrets

Secrets never live in a config or a manifest. The manifest declares the names; you set the values, and they can be read back never — only listed.

```sh
spaceport apps secret set blog DB_PASSWORD -    # '-' reads stdin: use it for anything that matters
spaceport apps secret list blog
spaceport apps secret delete blog DB_PASSWORD   # refused while the manifest still declares it
```

An app whose declared secrets are not all set stays suspended and tells you which ones are missing.

### Building from GitHub

Register spaceport as a GitHub App once, then point apps at repositories. The manifest used for a build is the one that commit carried, so the app's shape is versioned with its code.

```sh
spaceport connect github --auto --org acme     # prints a link; open it, GitHub does the rest
spaceport connect list
spaceport connect show acme-spaceport
spaceport connect forget acme-spaceport
```

The link is good for 30 minutes. If you would rather create the App by hand, `--manual` takes the seven values off its settings page; the three secret ones also read from `SPACEPORT_GITHUB_CLIENT_SECRET`, `SPACEPORT_GITHUB_WEBHOOK_SECRET` and `SPACEPORT_GITHUB_PRIVATE_KEY` so they stay out of your shell history.

```sh
spaceport apps track blog acme/blog --connection acme-spaceport --branch main --deploy
spaceport apps deploy blog                     # newest finished build
spaceport apps deploy blog --revision a1b2c3d  # or an older one — this is the rollback
```

`--deploy` arms the tracking: every push to the branch builds and deploys. `--no-deploy` disarms it and leaves you to deploy by hand. `--manifest-path` handles monorepos.

## Users and access

Who may reach an edge-gated app is spaceport's business, not the app's. The app is told; it does not decide. What an app receives, how it verifies the token, and how a machine client authenticates is documented by the binary:

```sh
spaceport info auth
```

Hand that to whoever is writing the app. Below is only the operator's side.

**There is no admin role.** Whoever can reach the operator socket — mode `0600`, owned by root — is the admin. Administering another host is `ssh there spaceport …`; the socket is never exposed over TCP.

### The user pool

Users are global to a spaceport. A user has a slug you type and a UUID that is their real identity.

```sh
spaceport auth user create alice --email alice@example.com --connect acme-spaceport:alice-gh
spaceport auth user list 'a*'
spaceport auth user rename alice alicia    # a name change only — sessions, grants and identity survive
spaceport auth user suspend alice          # signs them out everywhere, immediately
spaceport auth user resume alice
spaceport auth user drop alice             # the audit log is the only record they existed
```

### Binding an identity

`--connect`, or later `user connect`, says *this GitHub account is that person*. The handle is resolved to the provider's stable id at that moment and stored against the id, so a later rename on their side changes nothing.

```sh
spaceport auth user connect alice acme-spaceport:alice-gh
spaceport auth user disconnect alice acme-spaceport
```

A binding grants nothing. It is what makes their first sign-in land on the user you already know instead of minting a stranger beside them. One identity per user per connection — re-pointing means disconnecting first.

### Grants

An entitlement is a user, an app, and a role the app declares.

```sh
spaceport auth grant alice writer@blog
spaceport auth revoke alice writer@blog    # or: revoke alice blog | revoke alice --all
spaceport auth audit alice                 # grants with their origin, and what she has reached
spaceport auth log                         # append-only, every change, every actor
```

Granting a role an app has not deployed yet is allowed with a warning — granting ahead of the deploy is the ordinary order of operations.

### Mapping SSO to grants

Instead of granting one by one, derive grants from what the identity provider says at login.

```sh
spaceport auth mapping add reader,writer@blog --via acme-spaceport --when org=acme --when team=authors
spaceport auth mapping list blog
spaceport auth mapping test alice          # dry run against her last login
spaceport auth mapping drop <rule-id>      # takes the entitlements it produced with it
```

Conditions are AND-ed; `OR` is spelled "add another mapping". Mapped grants cannot be revoked by hand — the next login would restore them; drop the rule instead.

### Sessions and keys

```sh
spaceport auth session list alice
spaceport auth session mint alice --expires 12h            # a one-time code they type into /login
spaceport auth session api-key ci-bot writer@blog --expires 90d
spaceport auth session drop alice                          # everything; add an id for just one
```

A minted code is good for ten minutes, one use, five wrong attempts. An API key is printed once, grants exactly one role at one app regardless of what its user is otherwise entitled to, and does not rotate itself.

The signing key behind the tokens apps receive rotates itself every 90 days; `spaceport auth key rotate` is the compromise lever, and `spaceport auth key list` shows what is current and what is still being honoured.

## Watching it

```sh
spaceport status                          # --json for machines
spaceport stream                          # -a <app> -c <category> -l <level> --history 20 --json
```

Categories are hierarchical: `-c app` selects `app.apply` and `app.reconcile` too.

## What spaceport serves itself

On every host it answers `/.spaceport/health`, `/.spaceport/callback` and `/.well-known/acme-challenge/*` before any app sees the request — an app cannot shadow them. On `edge.hostname` it additionally serves the login and logout pages, the SSO callbacks, `/.well-known/jwks.json`, and the GitHub setup and webhook endpoints.

## Development

```sh
spaceport run --config examples/config.yaml --operator ./.sp.sock
spaceport apps apply echo examples/echo.yaml
```

`examples/config.yaml` keeps its state, data and build directories inside the checkout. Tests, lints and the supply-chain policy: `cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets --all-features`, `cargo fmt --all --check`, `cargo deny check`, `cargo tarpaulin`.

[ARCHITECTURE.md](ARCHITECTURE.md) describes how the thing is put together and why.

## License

MIT — see [LICENSE](LICENSE).
