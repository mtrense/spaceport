# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-13

### Added
- Auth and SSO: user pool with an audit log of every change, grantable roles connecting users to apps, and manifests that declare whether the edge gates them
- Sign in with a one-time code and cookie, or through the GitHub App users came from, with rules that turn SSO logins into entitlements
- Gated apps receive each request with a signed JWT, and now also learn the caller's name; machines can call gated apps with an API key
- Operators can set the name a user answers to and say who a user is on GitHub
- WebSocket tunnelling through the edge, with signing-key rotation
- GitHub connections: `spaceport connect github` makes spaceport a GitHub App, with `--auto` registration from a manifest, webhooks on spaceport's own hostname, reconciliation on change events, healing of missed webhooks, and named repositories per connection
- Build and deploy from source: `spaceport apps track` says where code lives, builds run from pushed commits, `spaceport apps deploy` runs a built revision, and builds can deploy automatically where requested
- Apps get their own environment, volumes, and secrets kept out of the manifest
- A supervisor restarts apps that stop, and `spaceport apps suspend` takes an app out of service
- Spaceport gets an address of its own at the edge
- `spaceport status`, `spaceport stream`, and a systemd service installer for hosts
- CLI tells app developers what this spaceport expects of them, shows colour, and stops waiting on a spaceport that has stopped answering
- Organisation shown on each GitHub login button

### Fixed
- Restarting a built app that could not be restored at boot now resolves its image instead of failing every retry
- A refused fetch no longer sends the browser to an `/api/...` path after sign-in; it falls back to `/`
- A GitHub login now only proves what GitHub proved
- Operator: listing now includes apps that are not running, typed input is encoded before use as a parameter, and the socket gets its mode before it has a name
- A readiness wait that could flap forever now has a time limit, and health probes no longer add up to a panic
- Deployments no longer check the replaced container, wait on suspension, or race when several operations hit one app
- Builds start from the right revision when tracking starts, and no longer deny under the wrong stanza
- Event watchers are released on shutdown
- The echo example takes its port from the image
- Oversized durations are refused instead of wrapping around

### Changed
- The edge pins the host an app sees to the matched route
- Frontends that want their page back after login now set `next` themselves (documented in auth.md)

### Security
- Operator interface taken off the network entirely
- Archive unpacking refuses to follow links created by the archive
- Edge: every stage a client can drag out now has a time limit, and the pending-login map has its own size bound and is charged to whoever fills it
- Failed login codes are charged to the code they targeted, and unknown accounts matching no rule leave no rows behind
- Build failure reasons are limited to a sentence and exclude secrets
- Updated h2 to bound what a stream can queue, and rustls to 0.23.45 for RUSTSEC-2026-0285
