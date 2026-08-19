//! App manifests: what an operator hands spaceport to run an app.
//!
//! The manifest describes the app alone. Its id is not in here — that is what
//! the operator names it as, on the command line, so the same file can be
//! applied under two ids without editing.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};

use super::secrets::StoredSecret;
use crate::auth::Role;
use crate::config::SchemaVersion;
use crate::duration;

/// Longest a routing host may be, and its individual labels, per RFC 1035.
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Longest a volume name may be. It becomes one path segment on the host, and
/// 63 is the shortest limit any filesystem spaceport might run on imposes.
const MAX_VOLUME_NAME_LEN: usize = 63;

/// A parsed and validated app manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    /// Declares which schema the rest of the document is written against.
    /// Shares the config's version: one schema, one spaceport.
    pub schema_version: SchemaVersion,

    /// Where the app's image comes from.
    pub source: Source,

    /// Which traffic reaches the app.
    pub routing: Routing,

    /// Who may reach the app: behind spaceport's edge authentication, or open
    /// to anyone who can reach its hosts.
    ///
    /// Required, with no default on purpose. Either default would be wrong for
    /// somebody — defaulting to `open` silently publishes an internal tool,
    /// defaulting to `edge` silently locks a public site's users out — so the
    /// manifest has to say. This is also a compatibility decision: manifests
    /// recorded before this field existed no longer parse, and that lands in
    /// the paths that re-read stored manifests, which already leave such an
    /// app down with a warning naming the reason (see `reconcile` — "nothing
    /// here is fatal"). A running container keeps serving until then; the way
    /// back up is re-applying with an `auth` block, which is exactly the
    /// question the operator has to answer anyway.
    pub auth: Auth,

    /// How the app runs. Every part of it has a default, so a manifest that
    /// says nothing here is complete.
    #[serde(default)]
    pub container: Container,

    /// The document this was parsed from, kept verbatim.
    ///
    /// Private, and filled in by [`AppManifest::parse`] rather than by serde:
    /// it is not a field of the schema, it is the schema's own text. Spaceport
    /// stores this, not a re-serialization, so that what an operator applied is
    /// what a later spaceport reads back — including whatever this build's
    /// structs do not model.
    #[serde(skip)]
    source_text: String,
}

/// Where the app's image comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// A pre-built image, pulled as given.
    Image { image: String },

    /// An image built from a checkout of the app's repository.
    ///
    /// Both paths are inside that checkout and are kept there — see
    /// [`Source::validate`].
    Build {
        #[serde(default = "default_dockerfile")]
        dockerfile: PathBuf,
        #[serde(default = "default_context")]
        context: PathBuf,
    },
}

impl Source {
    /// What serde cannot express about where an image comes from: that a build
    /// stays inside the tree it was given.
    ///
    /// The principle is [`Volume`]'s, and these two paths were violating it by
    /// construction. A manifest may not name a host path — the host path is
    /// spaceport's to choose — and `context: /etc` or `dockerfile: ../../../x`
    /// is a manifest naming one. Both would be read by whatever unpacked the
    /// commit and by the engine after it, so the file that reaches the build is
    /// whatever the document asked for, from anywhere on the host.
    ///
    /// Refused here rather than where a build happens, because there is more
    /// than one place a build happens and only one place a manifest is
    /// accepted. This was unreachable for as long as every path bailed on
    /// `Source::Build`; building makes it reachable.
    fn validate(&self) -> Result<()> {
        let Self::Build {
            dockerfile,
            context,
        } = self
        else {
            return Ok(());
        };

        for (field, path) in [("dockerfile", dockerfile), ("context", context)] {
            if path.as_os_str().is_empty() {
                bail!("source.{field} must name a path inside the repository, not nothing");
            }
            if path.is_absolute() {
                bail!(
                    "source.{field} must be relative to the repository, not `{}`",
                    path.display()
                );
            }
            // Component-wise rather than by looking for `..` in the text: a
            // path is not a string, and `a..b` is a perfectly ordinary
            // directory name that a substring search would refuse.
            if path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
            {
                bail!(
                    "source.{field} must stay inside the repository, and `{}` climbs out of it",
                    path.display()
                );
            }
        }

        Ok(())
    }
}

impl fmt::Display for Source {
    /// One line, for listings: where the image comes from, and what from
    /// there.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image { image } => write!(f, "image {image}"),
            Self::Build {
                dockerfile,
                context,
            } => write!(f, "build {} in {}", dockerfile.display(), context.display()),
        }
    }
}

fn default_dockerfile() -> PathBuf {
    PathBuf::from("Dockerfile")
}

fn default_context() -> PathBuf {
    PathBuf::from(".")
}

/// Which traffic reaches the app.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    /// Hosts served by this app. At least one, or nothing could ever reach it.
    pub hosts: Vec<Host>,
}

/// Who may reach the app.
///
/// Internally tagged on `gating`, in the shape of [`Source`]: the two variants
/// share no fields, and `deny_unknown_fields` is what makes `roles` under
/// `gating: open` an error rather than a silently ignored key. Silently
/// ignoring it would hide a misconfiguration — an operator who wrote roles
/// down believed they were gating something.
///
/// Parsed and validated only, for now: nothing enforces gating yet. What is
/// accepted here is the contract later enforcement holds an app to, which is
/// exactly why it is strict already — a manifest admitted today must not be
/// refused by the spaceport that starts enforcing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gating", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Auth {
    /// Spaceport authenticates every request at its edge before the app sees
    /// it; only a user entitled to one of the declared roles gets through.
    Edge {
        /// Paths that stay reachable without a session — a login page's CSS,
        /// a public feed. Matched after canonicalization and at segment
        /// boundaries (`/public` matches `/public/x`, never `/publicfoo`);
        /// the matching itself is enforcement work and lives with it, later.
        #[serde(default)]
        public_path_prefixes: Vec<PathPrefix>,

        /// The roles this app understands. Entitlements are granted against
        /// these names, and the JWT an app receives carries the intersection.
        roles: Vec<Role>,
    },

    /// Anyone who can reach the app's hosts reaches the app. Spaceport mints
    /// no sessions for it, sets no cookies on its domains, and passes
    /// `Authorization` through untouched.
    ///
    /// A struct variant with no fields rather than a unit variant, because the
    /// derive skips unknown-field checks for unit variants: `gating: open`
    /// with a `roles:` key left over from an `edge` block would parse cleanly,
    /// and that leftover is precisely the misconfiguration worth catching.
    Open {},
}

impl Auth {
    /// What serde cannot express about gating: the rules that span the whole
    /// list rather than one element.
    fn validate(&self) -> Result<()> {
        let Self::Edge {
            public_path_prefixes,
            roles,
        } = self
        else {
            return Ok(());
        };

        // An edge-gated app with no roles is one nobody could ever be entitled
        // to: not gated, unreachable. `gating: open` is how to say "no roles".
        if roles.is_empty() {
            bail!(
                "auth.roles must declare at least one role: with `gating: edge`, access is granted per role, and an app with none could never be reached by anyone"
            );
        }

        let mut seen = HashSet::with_capacity(roles.len());
        for role in roles {
            if !seen.insert(role) {
                bail!("auth.roles names `{role}` twice");
            }
        }

        let mut seen = HashSet::with_capacity(public_path_prefixes.len());
        for prefix in public_path_prefixes {
            if !seen.insert(prefix) {
                bail!("auth.public_path_prefixes lists `{prefix}` twice");
            }
        }

        Ok(())
    }
}

/// Longest a public path prefix may be. Generous — a prefix is a piece of a
/// URL an operator wrote by hand — but bounded, because everything else a
/// manifest names is.
const MAX_PATH_PREFIX_LEN: usize = 1024;

/// A path prefix that stays public on an edge-gated app.
///
/// Held to the shape the matcher will rely on: absolute, no trailing slash, no
/// query or fragment, no empty and no `.`/`..` segments. Requests are
/// canonicalized before matching, so a prefix that only matches
/// un-canonicalized spellings — `/a/../b`, `/a//b` — would silently never
/// match, and one with a trailing slash would make `/public` itself private
/// while `/public/x` stayed open. Refusing those here means what is stored is
/// already the normal form, and the later milestone only adds the
/// segment-boundary matcher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathPrefix(String);

impl PathPrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this prefix covers `path`, which must already be
    /// [`canonical_path`]'s output.
    ///
    /// The boundary check is the whole point: `/public` covers `/public` and
    /// `/public/x` and never `/publicfoo`, because a prefix names a subtree of
    /// the URL space and `publicfoo` is a different segment that merely shares
    /// spelling. Taking the canonical form rather than the raw path is what
    /// makes the answer mean anything — a raw `/css/../secret` would match
    /// `/css` here while the app serves `/secret` there.
    pub fn matches(&self, canonical: &str) -> bool {
        canonical == self.0
            || (canonical.starts_with(&self.0)
                && canonical.as_bytes().get(self.0.len()) == Some(&b'/'))
    }
}

/// The one spelling of a request path that public-prefix matching compares
/// against: percent-decoded, dot segments resolved, empty segments dropped.
///
/// This exists because a path is an instruction the *app* will interpret, and
/// the gate must not read it more naively than the app will. `/css/%2e%2e/x`
/// is `/css/../x` to any framework that decodes before routing, so a matcher
/// that saw a `/css` prefix there would wave through a request the app treats
/// as `/x` — decoding first closes that dodge. Resolving `..` after decoding
/// closes the plain-text spelling of the same trick, and dropping empty
/// segments means `//public/x` cannot hide from a `/public` prefix it would
/// reach anyway. Everything that decodes into something unspeakable — a stray
/// `%`, bytes that are not UTF-8 — stays as it came or becomes a replacement
/// character, neither of which can equal an ASCII prefix segment: the failure
/// mode is always "not public", never "public by accident".
///
/// The request forwarded upstream is untouched; only the matching sees this
/// form. What the app is asked for is what the client sent, byte for byte.
pub fn canonical_path(raw: &str) -> String {
    // Percent-decode into bytes first: an encoded `/` becomes a real segment
    // boundary *before* segmentation, which is the conservative direction —
    // it can only split segments further, never glue two into a fake match.
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit() =>
            {
                let hex = std::str::from_utf8(&bytes[index + 1..=index + 2])
                    .expect("two ascii hex digits are utf-8");
                decoded.push(u8::from_str_radix(hex, 16).expect("two hex digits are a byte"));
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    let text = String::from_utf8_lossy(&decoded);

    let mut segments: Vec<&str> = Vec::new();
    for segment in text.split('/') {
        match segment {
            // Empty covers both the leading slash and `//`; `.` is "here".
            "" | "." => {}
            // `..` climbs, and climbing above the root stays at the root —
            // the same answer every filesystem and browser gives.
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }

    let mut canonical = String::with_capacity(text.len() + 1);
    for segment in segments {
        canonical.push('/');
        canonical.push_str(segment);
    }
    if canonical.is_empty() {
        canonical.push('/');
    }

    canonical
}

impl FromStr for PathPrefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if !s.starts_with('/') {
            bail!("public path prefix `{s}` must start with `/`");
        }
        // `/` is a prefix of every path, so this would be `gating: edge` with
        // every request exempted from it — a contradiction better said plainly.
        if s == "/" {
            bail!(
                "a public path prefix of `/` would make the whole app public — say `gating: open` instead"
            );
        }
        if s.len() > MAX_PATH_PREFIX_LEN {
            bail!("public path prefix `{s}` is longer than {MAX_PATH_PREFIX_LEN} characters");
        }
        // A query or fragment is not part of a path, and a prefix carrying one
        // would never match anything once the path alone is compared.
        if let Some(stray) = ['?', '#'].iter().find(|c| s.contains(**c)) {
            bail!("public path prefix `{s}` must not carry a `{stray}` — only a path is matched");
        }
        if s.ends_with('/') {
            bail!(
                "public path prefix `{s}` must not end with `/` — a prefix already covers everything below it"
            );
        }
        for segment in s[1..].split('/') {
            if segment.is_empty() {
                bail!("public path prefix `{s}` has an empty segment");
            }
            // Matching happens after canonicalization, which resolves these
            // away — a prefix spelled with them could never match a request.
            if segment == "." || segment == ".." {
                bail!("public path prefix `{s}` must not contain `.` or `..` segments");
            }
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for PathPrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for PathPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the app's container runs.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    /// The port the app listens on inside its container.
    ///
    /// Optional because an image that exposes exactly one port has already
    /// said. This is for the images that expose several, or none, or one they
    /// do not actually serve on.
    pub port: Option<u16>,

    /// How spaceport decides the app is working.
    #[serde(default)]
    pub health: Health,

    /// Directories the app keeps across restarts, redeploys and its own
    /// deletion.
    #[serde(default)]
    pub volumes: Vec<Volume>,

    /// Secrets the app's `env` may interpolate. What is declared here has to be
    /// set for the app before it can run: an apply whose secrets are not all
    /// set stages the app suspended and says which are missing — see `apply`.
    ///
    /// Declared as a list of bare names rather than name-and-value: the whole
    /// point is that the value is not in the document.
    #[serde(default)]
    pub secrets: Vec<VarName>,

    /// The environment the app runs with.
    ///
    /// A `BTreeMap`, so the environment a manifest describes has exactly one
    /// order. Docker takes it as a list, and a list that reshuffled between two
    /// reads of the same document would make an unchanged app look changed.
    #[serde(default)]
    pub env: BTreeMap<VarName, String>,

    /// The values behind [`Container::secrets`], once something has looked them
    /// up. Empty on a manifest that was only parsed — see
    /// [`AppManifest::with_secrets`], which is the only thing that fills it in.
    ///
    /// `#[serde(skip)]` because this is not a field of the schema and must
    /// never become one: a manifest is a document an operator commits, and the
    /// whole point of a secret is that it is not in it. Skipping it on the way
    /// in means a document that tried to set it is refused by
    /// `deny_unknown_fields`; there is no way out because [`Secret`] has no
    /// `Serialize`.
    ///
    /// [`Secret`]: crate::secret::Secret
    #[serde(skip)]
    pub resolved: BTreeMap<VarName, StoredSecret>,
}

/// A directory the app keeps.
///
/// The host path is not in here: it is spaceport's to choose, from the
/// configured data directory and the id the operator applied the app under.
/// A manifest that could name a host path could name any host path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    /// Names the volume within the app, and nothing else — it is the last
    /// segment of the host path, so it is kept to what is safe to put there.
    pub name: VolumeName,

    /// Where the app sees it, inside the container.
    pub mount: PathBuf,

    /// Whether the app may write to it. Off by default: a volume exists to be
    /// written to, and the read-only case is the one worth spelling out.
    #[serde(default)]
    pub read_only: bool,
}

/// The name of a volume, safe to use as one path segment.
///
/// Kept to letters, digits, hyphens and underscores, which is what makes it
/// safe: no separator, no `..`, no leading dot, nothing a shell or a path
/// walker reads as anything but a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VolumeName(String);

impl VolumeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VolumeName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a volume name must not be empty");
        }
        if s.len() > MAX_VOLUME_NAME_LEN {
            bail!("volume name `{s}` is longer than {MAX_VOLUME_NAME_LEN} characters");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("volume name `{s}` may only contain letters, digits, hyphens and underscores");
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for VolumeName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for VolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of an environment variable, and so also of a secret: a secret is
/// only ever delivered by being interpolated into one.
///
/// The C rules, because that is what the shell in the container will enforce
/// anyway — a name it cannot export is a name the app cannot read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarName(String);

impl VarName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VarName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("an environment variable name must not be empty");
        }
        let mut bytes = s.bytes();
        let first = bytes.next().expect("checked non-empty");
        if !(first.is_ascii_alphabetic() || first == b'_') {
            bail!("`{s}` must start with a letter or an underscore to be an environment variable");
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("`{s}` may only contain letters, digits and underscores");
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for VarName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lets a map keyed by `VarName` be looked up with a plain `&str`.
impl Borrow<str> for VarName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// One piece of an environment value, as written.
#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    /// Text that means itself.
    Text(&'a str),
    /// The name between a `{{` and the `}}` that closes it, trimmed.
    Reference(&'a str),
}

/// Split an environment value into the text it contains and the secrets it
/// interpolates, in the order they appear.
///
/// `{{` always opens a reference and there is no way to escape it. A literal
/// `{{` in an environment value is rare enough to wait for someone to want
/// one; inventing an escape now would be guessing at a syntax nobody has had
/// to write yet, and the guess would be permanent.
///
/// One scanner and not two: validation asks which secrets a value names and
/// rendering asks what to put where they were, and a second parser for the
/// second question could disagree with the first about what `{{ A }}` means —
/// which would be a value validated against one secret and rendered from
/// another.
fn pieces(value: &str) -> Result<Vec<Piece<'_>>> {
    let mut found = Vec::new();
    let mut rest = value;

    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            bail!("`{value}` opens a `{{{{` that is never closed");
        };
        found.push(Piece::Text(&rest[..open]));
        found.push(Piece::Reference(after[..close].trim()));
        rest = &after[close + 2..];
    }
    found.push(Piece::Text(rest));

    Ok(found)
}

/// The secrets an env value interpolates, in the order they appear.
fn placeholders(value: &str) -> Result<Vec<&str>> {
    Ok(pieces(value)?
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Reference(name) => Some(name),
            Piece::Text(_) => None,
        })
        .collect())
}

impl Container {
    /// The secrets this container declares that nothing has resolved.
    ///
    /// The question an apply asks before it starts anything: a container whose
    /// `DATABASE_URL` still says `{{DB_PASSWORD}}` would come up and fail
    /// against a database, which is a far worse way to be told a secret was
    /// never set. Reported and not acted on here — deciding what to do about a
    /// missing secret belongs to whoever is applying.
    pub fn missing_secrets(&self) -> Vec<&VarName> {
        self.secrets
            .iter()
            .filter(|secret| !self.resolved.contains_key(*secret))
            .collect()
    }

    /// The resolved secrets this container's manifest does not declare.
    ///
    /// Not an error and not this type's business to make one: an operator sets
    /// a secret before the manifest that reads it, or removes the last
    /// reference to one and leaves the value behind, and both are ordinary. It
    /// is worth being able to say so, which is what this is for.
    pub fn unused_secrets(&self) -> Vec<&VarName> {
        let declared: HashSet<&VarName> = self.secrets.iter().collect();

        self.resolved
            .keys()
            .filter(|name| !declared.contains(*name))
            .collect()
    }

    /// The environment to run this container with: every value as the manifest
    /// wrote it, with each `{{NAME}}` replaced by the secret it names.
    ///
    /// The one place a secret's plaintext is put into an env value, and it is
    /// on the way to the engine only. Nothing stores what comes back, and
    /// nothing hashes it.
    ///
    /// An unresolved placeholder is refused rather than passed through. It
    /// cannot be an operator's mistake by the time this runs — the manifest
    /// only parses if every reference is declared, and an apply refuses a
    /// manifest whose declared secrets are not all set — so it is spaceport
    /// having failed to resolve, and the two ways to be wrong here are to hand
    /// the app a literal `{{DB_PASSWORD}}` in a connection string, which it
    /// will report as a database problem, or to say so. This says so.
    pub fn environment(&self) -> Result<BTreeMap<VarName, String>> {
        let mut environment = BTreeMap::new();

        for (name, value) in &self.env {
            let mut rendered = String::with_capacity(value.len());
            for piece in pieces(value)? {
                match piece {
                    Piece::Text(text) => rendered.push_str(text),
                    Piece::Reference(reference) => {
                        let secret = self.resolved.get(reference).with_context(|| {
                            format!("`{name}` interpolates `{reference}`, which is not resolved")
                        })?;
                        rendered.push_str(secret.value.expose());
                    }
                }
            }
            environment.insert(name.clone(), rendered);
        }

        Ok(environment)
    }

    /// What serde cannot express about a container: the rules that span more
    /// than one field.
    fn validate(&self) -> Result<()> {
        if self.port == Some(0) {
            bail!("container.port must be a port an app can listen on, not 0");
        }

        let mut names = HashSet::with_capacity(self.volumes.len());
        let mut mounts = HashSet::with_capacity(self.volumes.len());
        for volume in &self.volumes {
            // Two volumes of one name would be one directory on the host, and
            // whichever mount won would depend on the order docker read them.
            if !names.insert(&volume.name) {
                bail!("container.volumes names `{}` twice", volume.name);
            }
            if !volume.mount.is_absolute() {
                bail!(
                    "volume `{}` must be mounted at an absolute path, not `{}`",
                    volume.name,
                    volume.mount.display()
                );
            }
            if volume.mount == Path::new("/") {
                bail!("volume `{}` must not be mounted over `/`", volume.name);
            }
            if !mounts.insert(&volume.mount) {
                bail!(
                    "container.volumes mounts two volumes at `{}`",
                    volume.mount.display()
                );
            }
        }

        let mut declared = HashSet::with_capacity(self.secrets.len());
        for secret in &self.secrets {
            if !declared.insert(secret) {
                bail!("container.secrets names `{secret}` twice");
            }
            if shadows_spaceport(secret) {
                bail!(
                    "container.secrets declares `{secret}`, and names starting with `SPACEPORT` are spaceport's own — it injects those variables itself, and an app must not be able to shadow one"
                );
            }
        }

        let mut used = HashSet::new();
        for (name, value) in &self.env {
            if shadows_spaceport(name) {
                bail!(
                    "container.env sets `{name}`, and names starting with `SPACEPORT` are spaceport's own — it injects those variables itself, and an app must not be able to shadow one"
                );
            }
            for reference in placeholders(value)? {
                let secret: VarName = reference
                    .parse()
                    .with_context(|| format!("`{name}` interpolates `{{{{{reference}}}}}`"))?;
                if !declared.contains(&secret) {
                    bail!(
                        "`{name}` interpolates `{secret}`, which container.secrets does not declare"
                    );
                }
                used.insert(secret);
            }
        }

        // A secret nothing reads is a typo on one side or the other, and both
        // ways round the app would come up missing something it was promised.
        for secret in &self.secrets {
            if !used.contains(secret) {
                bail!("container.secrets declares `{secret}`, which no env value interpolates");
            }
        }

        Ok(())
    }
}

/// Whether a variable name collides with the ones spaceport injects.
///
/// Spaceport hands every app `SPACEPORT_*` variables — `SPACEPORT_APP_ID`,
/// `SPACEPORT_ISSUER`, `SPACEPORT_JWKS_URL`, and whatever a later spaceport
/// adds — so a manifest must not be able to set one. Checked as a prefix and
/// case-insensitively: the docker engine's environment is case-sensitive, but
/// an app reading `getenv` results case-insensitively (or a manifest that
/// wins by spelling it `spaceport_issuer`) would still be shadowing.
fn shadows_spaceport(name: &VarName) -> bool {
    const RESERVED: &str = "SPACEPORT";

    name.as_str()
        .get(..RESERVED.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED))
}

/// How spaceport decides an app is working.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// What has to succeed before traffic is routed to a newly applied app.
    #[serde(default)]
    pub readiness: Probe,

    /// What has to keep succeeding for spaceport to leave the app alone.
    ///
    /// Optional, and off when it is not there — which is the one default in
    /// this file that is not simply the safe value. A liveness check is a
    /// standing instruction to restart the app, and an app that never asked for
    /// one must not acquire it by being applied to a newer spaceport. Saying
    /// `type: none` is the other way to say the same thing, for a manifest that
    /// wants to be explicit about it.
    ///
    /// A container that has exited is restarted either way: that is the engine
    /// reporting a fact, not spaceport forming an opinion. This is for the app
    /// that is still running and has stopped working, which is the only case
    /// nobody but the app itself can settle.
    pub liveness: Option<Probe>,
}

/// A check spaceport makes against a running app.
///
/// A single struct rather than a tagged enum per check kind, so that
/// `deny_unknown_fields` keeps working — a manifest that misspells `path` is
/// far more common than one that needs the extra type safety, and it is the
/// one worth catching.
///
/// The same fields answer both questions the manifest asks. Readiness is "may
/// traffic go here yet?", where `failure_threshold` is how long an apply waits
/// before giving up; liveness is "is it still working?", where the very same
/// number is how many checks in a row have to fail before spaceport restarts
/// it. One kind of check, two moments to ask it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// Which kind of check to make.
    #[serde(rename = "type", default)]
    pub kind: Check,

    /// The path to request. Required by `http`, meaningless otherwise.
    pub path: Option<String>,

    /// The port to check. Not supported yet — see [`Probe::validate`].
    pub port: Option<u16>,

    /// How long to wait before the first check. Containers that are going to
    /// answer at all usually answer quickly, so this is short by default and
    /// the retries do the rest of the waiting.
    #[serde(
        default = "default_initial_delay",
        deserialize_with = "duration::deserialize"
    )]
    pub initial_delay: Duration,

    /// How long to wait between checks.
    #[serde(
        default = "default_interval",
        deserialize_with = "duration::deserialize"
    )]
    pub interval: Duration,

    /// How long a single check may take before it counts as failed.
    #[serde(
        default = "default_timeout",
        deserialize_with = "duration::deserialize"
    )]
    pub timeout: Duration,

    /// How many checks in a row have to fail before the app is given up on.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// How many checks in a row have to pass before the app is routed to.
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

/// The kind of check to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    /// Connect to the app's port. The default: it needs no cooperation from
    /// the app, and an app that is not accepting connections is not ready by
    /// any definition.
    #[default]
    Tcp,
    /// Request a path and require a non-error status.
    Http,
    /// Ask nothing. For readiness, route to the app the moment its container
    /// starts; for liveness, never restart an app whose container is still
    /// running.
    None,
}

fn default_initial_delay() -> Duration {
    // None: a check costs a connection, and an app that is ready immediately
    // should be routed immediately rather than made to sit out a delay.
    Duration::ZERO
}

fn default_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_failure_threshold() -> u32 {
    30
}

fn default_success_threshold() -> u32 {
    1
}

/// The longest any single probe duration may be. See [`Probe::validate`].
const MAX_PROBE_DURATION: Duration = Duration::from_secs(60 * 60);

/// The most checks any probe threshold may count. See [`Probe::validate`].
const MAX_PROBE_THRESHOLD: u32 = 3600;

impl Default for Probe {
    fn default() -> Self {
        Self {
            kind: Check::default(),
            path: None,
            port: None,
            initial_delay: default_initial_delay(),
            interval: default_interval(),
            timeout: default_timeout(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

impl Probe {
    /// How long a wholly unresponsive app is given before an apply gives up.
    ///
    /// Saturates rather than overflowing: `Duration`'s `+` and `*` panic on
    /// overflow even in release, and a probe persisted into a build row before
    /// [`Probe::validate`] grew its ceilings is replayed through here on every
    /// apply — a panic would poison that app for good.
    pub fn budget(&self) -> Duration {
        self.interval
            .checked_mul(self.failure_threshold)
            .and_then(|checks| self.initial_delay.checked_add(checks))
            .unwrap_or(Duration::MAX)
    }

    /// `which` is the name the manifest gave this check — `readiness` or
    /// `liveness` — so that an operator with both is told which one is wrong.
    fn validate(&self, which: &str) -> Result<()> {
        match self.kind {
            Check::Http if self.path.is_none() => {
                bail!("a {which} check of type `http` needs a `path` to request");
            }
            Check::Http => {}
            _ if self.path.is_some() => {
                bail!(
                    "`path` only means something for a {which} check of type `http`, not `{}`",
                    self.kind.as_str()
                );
            }
            _ => {}
        }

        // Publishing a second host port to reach it is not implemented, and a
        // port that is never published would fail every check.
        if self.port.is_some() {
            bail!(
                "a {which} `port` of its own is not supported yet: the check uses the port traffic is routed to"
            );
        }

        if self.failure_threshold == 0 || self.success_threshold == 0 {
            bail!("{which} thresholds count checks, so they must be at least 1");
        }
        if self.interval.is_zero() {
            bail!("a {which} `interval` of zero would check without ever pausing");
        }
        if self.timeout.is_zero() {
            bail!("a {which} `timeout` of zero would fail every check");
        }

        // Ceilings, so that a manifest cannot hand [`Probe::budget`] numbers
        // whose product no longer fits a `Duration`. An hour is far past any
        // useful setting — the defaults are a 1s interval and a 5s timeout —
        // and 3600 checks is a hundred and twenty times the default threshold
        // of 30, so nothing an operator would plausibly write is newly refused.
        if self.initial_delay > MAX_PROBE_DURATION {
            bail!("a {which} `initial_delay` above an hour would stall every apply behind it");
        }
        if self.interval > MAX_PROBE_DURATION {
            bail!("a {which} `interval` above an hour would check too rarely to mean anything");
        }
        if self.timeout > MAX_PROBE_DURATION {
            bail!("a {which} `timeout` above an hour would hang a check rather than fail it");
        }
        if self.failure_threshold > MAX_PROBE_THRESHOLD
            || self.success_threshold > MAX_PROBE_THRESHOLD
        {
            bail!(
                "{which} thresholds above {MAX_PROBE_THRESHOLD} checks are more waiting than any app is worth"
            );
        }

        Ok(())
    }
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::None => "none",
        }
    }
}

/// A hostname an app answers to.
///
/// Lowercased on the way in, because `Host` headers are case-insensitive and
/// the routing table is a plain map: normalising once here means the edge
/// never has to think about it again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

impl Host {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a routing host must not be empty");
        }
        if s.len() > MAX_HOST_LEN {
            bail!("host `{s}` is longer than {MAX_HOST_LEN} characters");
        }
        // A port here would silently never match: the edge strips the port off
        // the request before looking a host up.
        if s.contains(':') {
            bail!("host `{s}` must name a host without a port");
        }

        let host = s.to_ascii_lowercase();
        for label in host.split('.') {
            check_label(&host, label)?;
        }

        Ok(Self(host))
    }
}

/// Validate one dot-separated label of `host`.
fn check_label(host: &str, label: &str) -> Result<()> {
    if label.is_empty() {
        bail!("host `{host}` has an empty label");
    }
    if label.len() > MAX_LABEL_LEN {
        bail!("label `{label}` in host `{host}` is longer than {MAX_LABEL_LEN} characters");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("host `{host}` may only contain letters, digits, hyphens and dots");
    }
    if label.starts_with('-') || label.ends_with('-') {
        bail!("label `{label}` in host `{host}` must not start or end with a hyphen");
    }

    Ok(())
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lets a routing table keyed by `Host` be looked up with a plain `&str`, so
/// the edge never allocates to find a request's app. Sound because `Host`
/// hashes and compares exactly as its inner string does.
impl Borrow<str> for Host {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AppManifest {
    /// Read, parse and validate the manifest at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading app manifest `{}`", path.display()))?;

        Self::parse(&raw).with_context(|| format!("invalid app manifest `{}`", path.display()))
    }

    /// Parse and validate a manifest document.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut manifest: Self = serde_norway::from_str(raw)?;
        manifest.validate()?;
        manifest.source_text = raw.to_owned();

        Ok(manifest)
    }

    /// The document this manifest was parsed from, byte for byte.
    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    /// This manifest as this spaceport can run it: the same document, with the
    /// image a build produced in place of the build that produced it.
    ///
    /// The copy's parsed source and its text disagree on purpose. The text is
    /// the document the repository holds — `type: build`, a Dockerfile and a
    /// context — and it is what an operator wrote and what a later spaceport
    /// reads back, so it is left exactly as it was. The parsed source is what
    /// this spaceport can run today: one image, resolved from one revision, on
    /// the way to the runtime and never on the way to the store. A resolved tag
    /// written down would be a fact about a single build frozen into the record
    /// of an app, and a restart would run it long after the revision it belonged
    /// to had been replaced.
    ///
    /// Validated as though it had been parsed, so an image a manifest would be
    /// refused for cannot arrive by this door instead.
    pub fn built_as(&self, image: &str) -> Result<Self> {
        let manifest = Self {
            source: Source::Image {
                image: image.to_owned(),
            },
            ..self.clone()
        };
        manifest.validate().context("resolving a built image")?;

        Ok(manifest)
    }

    /// This manifest with the values behind its secrets to hand.
    ///
    /// In the shape of [`AppManifest::built_as`], and for the same reason: what
    /// this spaceport can run right now is a copy on the way to the runtime,
    /// and the document is left as the operator wrote it.
    ///
    /// The values sit beside `env` rather than being substituted into it,
    /// because `env` is what the fingerprint is computed from and the
    /// fingerprint is written onto the container as a label anybody who can
    /// talk to the daemon can read. Keeping the `{{NAME}}` placeholders in the
    /// text means that text contains no secret and never will; the value is
    /// only ever put in its place by [`Container::environment`], on its way to
    /// the engine.
    ///
    /// Everything is taken, not only what `container.secrets` declares:
    /// resolving is a lookup of the app's secrets and deciding which of them
    /// this manifest wanted is [`Container::missing_secrets`] and
    /// [`Container::unused_secrets`]' question, asked by whoever cares about
    /// the answer.
    pub fn with_secrets(&self, secrets: BTreeMap<VarName, StoredSecret>) -> Self {
        Self {
            container: Container {
                resolved: secrets,
                ..self.container.clone()
            },
            ..self.clone()
        }
    }

    /// What serde cannot express: the rules that span more than one field.
    fn validate(&self) -> Result<()> {
        self.source.validate()?;

        if self.routing.hosts.is_empty() {
            bail!("routing.hosts must name at least one host");
        }

        let mut seen = HashSet::with_capacity(self.routing.hosts.len());
        for host in &self.routing.hosts {
            if !seen.insert(host) {
                bail!("routing.hosts lists `{host}` twice");
            }
        }

        self.auth.validate()?;

        self.container.validate()?;

        self.container.health.readiness.validate("readiness")?;
        // Nothing cross-checks the two: liveness starts only once readiness has
        // already passed, so a liveness check that gives up far sooner than an
        // apply would is the normal way to write one, not a mistake.
        if let Some(liveness) = &self.container.health.liveness {
            liveness.validate("liveness")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest with everything mandatory filled in, for tests to extend.
    const MINIMAL: &str = "
schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test, beta.test]
auth:
  gating: open
";

    fn hosts(manifest: &AppManifest) -> Vec<&str> {
        manifest.routing.hosts.iter().map(Host::as_str).collect()
    }

    /// The examples are documentation, and documentation that does not parse
    /// is worse than none. `app-manifest.yaml` is the one that matters most
    /// here: it is where every field spaceport understands is written down.
    #[test]
    fn the_shipped_examples_are_valid() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");

        for name in ["hello-app.yaml", "echo.yaml", "app-manifest.yaml"] {
            let raw = std::fs::read_to_string(examples.join(name)).unwrap();

            if let Err(err) = AppManifest::parse(&raw) {
                panic!("examples/{name}: {err:#}");
            }
        }
    }

    /// The state store keeps this text and nothing else, so a manifest that
    /// dropped a comment or normalized its quoting on the way through would
    /// give an operator back something they never wrote.
    #[test]
    fn keeps_the_document_it_was_parsed_from() {
        let raw = "# what this app is for\nschema_version: 1\nsource:\n  type: image\n  image: \"strm/helloworld-http:latest\"\nrouting:\n  hosts: [alpha.test]\nauth:\n  gating: open\n";

        let manifest = AppManifest::parse(raw).unwrap();

        assert_eq!(manifest.source_text(), raw);
        // And what it kept parses back to the same manifest.
        assert_eq!(
            AppManifest::parse(manifest.source_text()).unwrap(),
            manifest
        );
    }

    #[test]
    fn parses_an_image_source() {
        let manifest = AppManifest::parse(MINIMAL).unwrap();

        assert_eq!(
            manifest.source,
            Source::Image {
                image: "strm/helloworld-http:latest".into()
            }
        );
        assert_eq!(hosts(&manifest), ["alpha.test", "beta.test"]);
    }

    #[test]
    fn parses_a_build_source_with_defaults() {
        let raw = "
schema_version: 1
source:
  type: build
routing:
  hosts: [alpha.test]
auth:
  gating: open
";
        assert_eq!(
            AppManifest::parse(raw).unwrap().source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: ".".into(),
            }
        );
    }

    /// `MINIMAL` with a build source in place of its image one.
    fn with_build(fields: &str) -> String {
        let fields: String = fields.lines().map(|line| format!("  {line}\n")).collect();

        MINIMAL.replace(
            "source:\n  type: image\n  image: strm/helloworld-http:latest\n",
            &format!("source:\n  type: build\n{fields}"),
        )
    }

    /// The defaults are a build of the repository as it arrives, and they are
    /// what a manifest that says `type: build` and nothing else gets — so they
    /// have to survive the rules below.
    #[test]
    fn builds_the_repository_as_it_arrives_by_default() {
        let manifest = AppManifest::parse(&with_build("")).unwrap();

        assert_eq!(
            manifest.source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: ".".into(),
            }
        );
    }

    /// The host path is spaceport's to choose. A manifest that could name one
    /// could name any, and `/etc` is the same document asking to build the
    /// host's configuration.
    #[test]
    fn rejects_a_build_path_that_is_absolute() {
        for field in ["dockerfile: /etc/Dockerfile", "context: /etc"] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("must be relative"), "for `{field}`: {err}");
        }
    }

    /// The other way out of the checkout, and the one that does not look like
    /// a host path in the document.
    #[test]
    fn rejects_a_build_path_that_climbs_out_of_the_repository() {
        for field in [
            "dockerfile: ../../../x",
            "context: ..",
            "dockerfile: build/../../elsewhere/Dockerfile",
        ] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("climbs out"), "for `{field}`: {err}");
        }
    }

    /// An empty path is not the default: it is a field somebody meant to fill
    /// in, and it would be joined to the checkout to mean the checkout itself.
    #[test]
    fn rejects_a_build_path_that_is_empty() {
        for field in ["dockerfile: \"\"", "context: \"\""] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("not nothing"), "for `{field}`: {err}");
        }
    }

    /// A directory named `a..b` is an ordinary directory, and refusing it would
    /// be a substring search standing in for reading a path.
    #[test]
    fn accepts_a_build_path_with_dots_in_a_name() {
        let manifest = AppManifest::parse(&with_build("context: services/a..b")).unwrap();

        assert_eq!(
            manifest.source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: "services/a..b".into(),
            }
        );
    }

    /// What a build resolves to on the way to the runtime: the image, and the
    /// document the operator's repository still holds.
    #[test]
    fn runs_a_built_manifest_as_the_image_the_build_produced() {
        let manifest = AppManifest::parse(&with_build("")).unwrap();

        let built = manifest.built_as("spaceport/site:abc1234").unwrap();

        assert_eq!(
            built.source,
            Source::Image {
                image: "spaceport/site:abc1234".into()
            }
        );
        // The text is the repository's, and says what it always said.
        assert_eq!(built.source_text(), manifest.source_text());
        assert!(built.source_text().contains("type: build"));
        // And nothing else about the app moved with the source.
        assert_eq!(built.routing.hosts, manifest.routing.hosts);
        assert_eq!(built.container, manifest.container);
    }

    #[test]
    fn rejects_an_unknown_source_type() {
        let raw = MINIMAL.replace("type: image", "type: magic");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn rejects_a_source_field_from_another_variant() {
        let raw = MINIMAL.replace("  image: strm", "  dockerfile: Dockerfile\n  image: strm");
        assert!(AppManifest::parse(&raw).is_err());
    }

    #[test]
    fn rejects_a_missing_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1\n", "");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn rejects_a_future_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1", "schema_version: 2");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("unsupported schema version 2"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = AppManifest::parse(&format!("{MINIMAL}replicas: 3\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("replicas"), "{err}");
    }

    /// `secrets` is a container field, so at the root it is still a mistake —
    /// and one an operator who read the example half-way is likely to make.
    #[test]
    fn rejects_a_container_field_at_the_root() {
        let err = AppManifest::parse(&format!("{MINIMAL}secrets: [DB_PASSWORD]\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("secrets"), "{err}");
    }

    #[test]
    fn leaves_the_container_port_to_the_image_by_default() {
        assert_eq!(AppManifest::parse(MINIMAL).unwrap().container.port, None);
    }

    #[test]
    fn parses_a_container_port() {
        let raw = format!("{MINIMAL}container:\n  port: 8080\n");
        assert_eq!(AppManifest::parse(&raw).unwrap().container.port, Some(8080));
    }

    #[test]
    fn rejects_a_container_port_of_zero() {
        let raw = format!("{MINIMAL}container:\n  port: 0\n");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("not 0"), "{err}");
    }

    #[test]
    fn rejects_a_container_port_that_is_not_a_port() {
        let raw = format!("{MINIMAL}container:\n  port: 70000\n");
        assert!(AppManifest::parse(&raw).is_err());
    }

    #[test]
    fn rejects_an_unknown_container_field() {
        let raw = format!("{MINIMAL}container:\n  ports: 8080\n");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("ports"), "{err}");
    }

    /// `MINIMAL` with a container section, indented into place.
    fn with_container(fields: &str) -> String {
        let fields: String = fields.lines().map(|line| format!("  {line}\n")).collect();

        format!("{MINIMAL}container:\n{fields}")
    }

    #[test]
    fn runs_with_no_environment_and_no_volumes_by_default() {
        let container = AppManifest::parse(MINIMAL).unwrap().container;

        assert!(container.env.is_empty());
        assert!(container.volumes.is_empty());
        assert!(container.secrets.is_empty());
    }

    #[test]
    fn parses_an_environment() {
        let raw = with_container("env:\n  ENVIRONMENT: production\n  LOG_LEVEL: debug");
        let env = AppManifest::parse(&raw).unwrap().container.env;

        assert_eq!(env.len(), 2);
        assert_eq!(env["ENVIRONMENT"], "production");
        assert_eq!(env["LOG_LEVEL"], "debug");
    }

    #[test]
    fn rejects_an_environment_name_a_shell_could_not_export() {
        for name in ["1ST", "WITH-HYPHEN", "with space", ""] {
            let raw = with_container(&format!("env:\n  \"{name}\": x"));
            assert!(AppManifest::parse(&raw).is_err(), "accepted `{name}`");
        }
    }

    #[test]
    fn parses_a_volume() {
        let raw = with_container(
            "volumes:
  - name: data
    mount: /var/lib/my-app/data
  - name: cache
    mount: /var/cache/my-app
    read_only: true",
        );

        let volumes = AppManifest::parse(&raw).unwrap().container.volumes;

        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].name.as_str(), "data");
        assert_eq!(volumes[0].mount, Path::new("/var/lib/my-app/data"));
        // Off unless asked for: a volume exists to be written to.
        assert!(!volumes[0].read_only);
        assert!(volumes[1].read_only);
    }

    /// The name becomes one segment of a host path, so anything that could
    /// climb out of the app's own directory has to be refused here, before it
    /// is ever joined to one.
    #[test]
    fn rejects_a_volume_name_that_is_not_one_path_segment() {
        for name in ["..", "a/b", ".hidden", "", "with space", "\"a\\\\b\""] {
            let raw = with_container(&format!("volumes:\n  - name: {name}\n    mount: /data"));
            assert!(AppManifest::parse(&raw).is_err(), "accepted `{name}`");
        }
    }

    #[test]
    fn rejects_an_overlong_volume_name() {
        let name = "a".repeat(64);
        let raw = with_container(&format!("volumes:\n  - name: {name}\n    mount: /data"));
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("longer than 63"), "{err}");
    }

    #[test]
    fn rejects_a_relative_mount() {
        let raw = with_container("volumes:\n  - name: data\n    mount: var/lib/data");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("absolute path"), "{err}");
    }

    /// Mounting a volume over `/` would replace the image's whole filesystem
    /// with an empty directory.
    #[test]
    fn rejects_a_mount_over_the_root() {
        let raw = with_container("volumes:\n  - name: data\n    mount: /");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("over `/`"), "{err}");
    }

    /// Two volumes of one name are one host directory, and which mount won
    /// would come down to the order docker happened to read them in.
    #[test]
    fn rejects_two_volumes_of_the_same_name() {
        let raw = with_container(
            "volumes:
  - name: data
    mount: /one
  - name: data
    mount: /two",
        );
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn rejects_two_volumes_at_the_same_mount() {
        let raw = with_container(
            "volumes:
  - name: one
    mount: /data
  - name: two
    mount: /data",
        );
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("/data"), "{err}");
    }

    #[test]
    fn parses_a_secret_interpolated_into_the_environment() {
        let raw = with_container(
            "secrets:
  - DB_PASSWORD
env:
  DATABASE_URL: postgres://user:{{DB_PASSWORD}}@db:5432/my-app",
        );

        let container = AppManifest::parse(&raw).unwrap().container;

        assert_eq!(container.secrets[0].as_str(), "DB_PASSWORD");
        // Kept unresolved: the manifest is stored as written, and there is
        // nothing to resolve it with yet.
        assert_eq!(
            container.env["DATABASE_URL"],
            "postgres://user:{{DB_PASSWORD}}@db:5432/my-app"
        );
    }

    /// The typo that would otherwise reach the app as a literal `{{...}}` in
    /// a connection string, and be diagnosed as a database problem.
    #[test]
    fn rejects_a_reference_to_a_secret_nobody_declared() {
        let raw = with_container("env:\n  DATABASE_URL: \"pw={{DB_PASSWORD}}\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("DB_PASSWORD"), "{err}");
        assert!(err.contains("does not declare"), "{err}");
    }

    /// The same typo from the other side: the secret is declared, and it is
    /// the reference that is misspelt, so nothing would ever read it.
    #[test]
    fn rejects_a_declared_secret_nothing_interpolates() {
        let raw = with_container("secrets: [DB_PASSWORD]\nenv:\n  A: b");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("no env value interpolates"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_secret() {
        let raw =
            with_container("secrets: [DB_PASSWORD, DB_PASSWORD]\nenv:\n  A: \"{{DB_PASSWORD}}\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn rejects_an_unclosed_placeholder() {
        let raw = with_container("secrets: [DB_PASSWORD]\nenv:\n  A: \"{{DB_PASSWORD\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("never closed"), "{err}");
    }

    #[test]
    fn reads_a_secret_into_more_than_one_variable() {
        let raw = with_container(
            "secrets: [PW]
env:
  A: \"{{PW}}\"
  B: \"user:{{PW}}@host and again {{PW}}\"",
        );

        assert!(AppManifest::parse(&raw).is_ok());
    }

    /// A container declaring `PW` and reading it, with `resolved` filled in
    /// from the given names and values.
    fn with_secrets(secrets: &[(&str, &str)]) -> AppManifest {
        let raw = with_container("secrets: [PW]\nenv:\n  A: \"pw={{PW}}\"");
        let resolved = secrets
            .iter()
            .map(|(name, value)| {
                (
                    name.parse().unwrap(),
                    StoredSecret {
                        value: crate::secret::Secret::new(*value),
                        version: 1,
                    },
                )
            })
            .collect();

        AppManifest::parse(&raw).unwrap().with_secrets(resolved)
    }

    /// The values are not in the document and must not get into it: what an
    /// operator committed is what a later spaceport reads back, and a manifest
    /// carrying a resolved secret in its text would be a secret in the state
    /// database's copy of a repository's file.
    #[test]
    fn resolving_a_secret_leaves_the_document_and_its_environment_alone() {
        let manifest = with_secrets(&[("PW", "hunter2")]);

        assert_eq!(manifest.container.env["A"], "pw={{PW}}");
        assert!(!manifest.source_text().contains("hunter2"));
    }

    #[test]
    fn a_parsed_manifest_has_resolved_nothing() {
        let manifest = AppManifest::parse(MINIMAL).unwrap();

        assert!(manifest.container.resolved.is_empty());
    }

    /// `resolved` is not a field of the schema, so a document that names it is
    /// a document with an unknown field — and, more to the point, no way for a
    /// value to be smuggled in as though something had resolved it.
    #[test]
    fn rejects_a_document_that_tries_to_supply_a_resolved_secret() {
        let raw = with_container("resolved:\n  PW:\n    value: hunter2\n    version: 1");

        assert!(AppManifest::parse(&raw).is_err());
    }

    /// What an apply asks before it starts anything: an app whose password is
    /// missing would otherwise come up and fail against its database, which is
    /// a terrible way to be told a secret was never set.
    #[test]
    fn says_which_declared_secrets_nothing_has_resolved() {
        assert_eq!(
            with_secrets(&[]).container.missing_secrets(),
            [&"PW".parse::<VarName>().unwrap()]
        );
        assert!(
            with_secrets(&[("PW", "hunter2")])
                .container
                .missing_secrets()
                .is_empty()
        );
    }

    /// The other direction, and not an error: a secret set before the manifest
    /// that reads it, or left behind when the last reference went, is ordinary.
    #[test]
    fn says_which_resolved_secrets_nothing_declares() {
        let manifest = with_secrets(&[("PW", "hunter2"), ("LEFTOVER", "old")]);

        assert_eq!(
            manifest.container.unused_secrets(),
            [&"LEFTOVER".parse::<VarName>().unwrap()]
        );
        assert!(manifest.container.missing_secrets().is_empty());
    }

    /// `MINIMAL` with a readiness section, indented into place.
    fn with_readiness(fields: &str) -> String {
        let fields: String = fields
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect();

        format!("{MINIMAL}container:\n  health:\n    readiness:\n{fields}")
    }

    #[test]
    fn waits_for_a_tcp_connection_by_default() {
        let readiness = AppManifest::parse(MINIMAL)
            .unwrap()
            .container
            .health
            .readiness;

        assert_eq!(readiness, Probe::default());
        assert_eq!(readiness.kind, Check::Tcp);
        assert_eq!(readiness.budget(), Duration::from_secs(30));
    }

    #[test]
    fn parses_an_http_readiness_check() {
        let raw = with_readiness(
            "type: http
path: /healthz
interval: 500ms
timeout: 2s
initial_delay: 1m
failure_threshold: 6
success_threshold: 2",
        );

        let readiness = AppManifest::parse(&raw).unwrap().container.health.readiness;

        assert_eq!(readiness.kind, Check::Http);
        assert_eq!(readiness.path.as_deref(), Some("/healthz"));
        assert_eq!(readiness.interval, Duration::from_millis(500));
        assert_eq!(readiness.timeout, Duration::from_secs(2));
        assert_eq!(readiness.initial_delay, Duration::from_secs(60));
        assert_eq!(readiness.failure_threshold, 6);
        assert_eq!(readiness.success_threshold, 2);
    }

    #[test]
    fn keeps_the_defaults_for_whatever_a_check_leaves_out() {
        let raw = with_readiness("type: http\npath: /healthz");
        let readiness = AppManifest::parse(&raw).unwrap().container.health.readiness;

        assert_eq!(readiness.interval, Duration::from_secs(1));
        assert_eq!(readiness.failure_threshold, 30);
    }

    #[test]
    fn rejects_an_http_check_without_a_path() {
        let err = AppManifest::parse(&with_readiness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("needs a `path`"), "{err}");
    }

    #[test]
    fn rejects_a_path_on_a_check_that_cannot_use_one() {
        let err = AppManifest::parse(&with_readiness("type: tcp\npath: /healthz"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("only means something"), "{err}");
    }

    /// Reaching a port of its own would mean publishing a second host port,
    /// which nothing does yet — so it is refused rather than silently failing
    /// every check.
    #[test]
    fn rejects_a_readiness_port_of_its_own() {
        let err = AppManifest::parse(&with_readiness("port: 9000"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("not supported yet"), "{err}");
    }

    #[test]
    fn rejects_thresholds_that_count_nothing() {
        for field in ["failure_threshold: 0", "success_threshold: 0"] {
            let err = AppManifest::parse(&with_readiness(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("at least 1"), "{err}");
        }
    }

    #[test]
    fn rejects_a_pointless_interval_or_timeout() {
        assert!(AppManifest::parse(&with_readiness("interval: 0s")).is_err());
        assert!(AppManifest::parse(&with_readiness("timeout: 0s")).is_err());
    }

    /// The struct is built directly rather than parsed, so that the test still
    /// covers build rows persisted before validation grew its ceilings.
    #[test]
    fn saturates_a_budget_whose_checks_would_overflow() {
        let probe = Probe {
            interval: Duration::from_secs(u64::MAX),
            failure_threshold: 30,
            ..Probe::default()
        };

        assert_eq!(probe.budget(), Duration::MAX);
    }

    #[test]
    fn saturates_a_budget_whose_initial_delay_would_overflow() {
        let probe = Probe {
            initial_delay: Duration::MAX - Duration::from_secs(1),
            interval: Duration::from_secs(60),
            failure_threshold: 30,
            ..Probe::default()
        };

        assert_eq!(probe.budget(), Duration::MAX);
    }

    #[test]
    fn rejects_an_interval_no_apply_could_outlast() {
        let err = AppManifest::parse(&with_readiness("interval: 18446744073709551615s"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("readiness"), "{err}");
        assert!(err.contains("`interval`"), "{err}");
    }

    /// Guards the ceilings against being drawn tighter than the defaults.
    #[test]
    fn accepts_the_defaults_the_ceilings_have_to_leave_room_for() {
        let readiness = AppManifest::parse(MINIMAL)
            .unwrap()
            .container
            .health
            .readiness;

        assert_eq!(readiness, Probe::default());
    }

    #[test]
    fn rejects_a_duration_without_a_unit() {
        let err = AppManifest::parse(&with_readiness("interval: 30"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("duration"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_readiness_field() {
        let err = AppManifest::parse(&with_readiness("timeout_seconds: 3"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("timeout_seconds"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_check_type() {
        let err = AppManifest::parse(&with_readiness("type: ping"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("ping"), "{err}");
    }

    /// `MINIMAL` with a liveness section, indented into place.
    fn with_liveness(fields: &str) -> String {
        let fields: String = fields
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect();

        format!("{MINIMAL}container:\n  health:\n    liveness:\n{fields}")
    }

    /// The one default here that is not simply the safe value. Every app
    /// already applied was written without a liveness block, and if absence
    /// meant "watch it" they would all quietly acquire a standing instruction
    /// to restart on the next upgrade.
    #[test]
    fn watches_nothing_unless_a_manifest_asks_for_it() {
        let health = AppManifest::parse(MINIMAL).unwrap().container.health;

        assert_eq!(health.liveness, None);
        // And readiness is still there, so absent liveness is absence and not
        // a health section that failed to parse.
        assert_eq!(health.readiness, Probe::default());
    }

    #[test]
    fn parses_an_http_liveness_check() {
        let raw = with_liveness(
            "type: http
path: /livez
interval: 15s
timeout: 3s
initial_delay: 30s
failure_threshold: 4
success_threshold: 1",
        );

        let liveness = AppManifest::parse(&raw)
            .unwrap()
            .container
            .health
            .liveness
            .unwrap();

        assert_eq!(liveness.kind, Check::Http);
        assert_eq!(liveness.path.as_deref(), Some("/livez"));
        assert_eq!(liveness.interval, Duration::from_secs(15));
        assert_eq!(liveness.timeout, Duration::from_secs(3));
        assert_eq!(liveness.initial_delay, Duration::from_secs(30));
        assert_eq!(liveness.failure_threshold, 4);
        assert_eq!(liveness.success_threshold, 1);
    }

    /// An operator with both checks configured gets one error message, and it
    /// has to say which of the two they need to go and fix.
    #[test]
    fn says_liveness_when_it_is_the_liveness_check_that_is_wrong() {
        let err = AppManifest::parse(&with_liveness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("liveness"), "{err}");
        assert!(!err.contains("readiness"), "{err}");
    }

    /// The other half of the same worry: naming the check must not have turned
    /// every message into the liveness one.
    #[test]
    fn says_readiness_when_it_is_the_readiness_check_that_is_wrong() {
        let err = AppManifest::parse(&with_readiness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("readiness"), "{err}");
        assert!(!err.contains("liveness"), "{err}");
    }

    /// The two checks answer different questions and are written to different
    /// budgets — a slow apply and a twitchy restart are both reasonable — so
    /// neither may be allowed to inherit the other's settings.
    #[test]
    fn takes_the_two_checks_independently() {
        let raw = format!(
            "{MINIMAL}container:
  health:
    readiness:
      type: http
      path: /healthz
      interval: 500ms
      failure_threshold: 60
    liveness:
      type: tcp
      interval: 10s
      failure_threshold: 3
"
        );

        let health = AppManifest::parse(&raw).unwrap().container.health;
        let liveness = health.liveness.unwrap();

        assert_eq!(health.readiness.kind, Check::Http);
        assert_eq!(health.readiness.path.as_deref(), Some("/healthz"));
        assert_eq!(health.readiness.interval, Duration::from_millis(500));
        assert_eq!(health.readiness.failure_threshold, 60);

        assert_eq!(liveness.kind, Check::Tcp);
        assert_eq!(liveness.path, None);
        assert_eq!(liveness.interval, Duration::from_secs(10));
        assert_eq!(liveness.failure_threshold, 3);
    }

    #[test]
    fn rejects_a_liveness_interval_of_zero() {
        let err = AppManifest::parse(&with_liveness("interval: 0s"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("without ever pausing"), "{err}");
        assert!(err.contains("liveness"), "{err}");
    }

    #[test]
    fn rejects_a_manifest_without_hosts() {
        let raw = MINIMAL.replace("hosts: [alpha.test, beta.test]", "hosts: []");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("at least one host"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_host() {
        let raw = MINIMAL.replace("beta.test", "ALPHA.test");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn lowercases_hosts() {
        let raw = MINIMAL.replace("alpha.test", "ALPHA.Test");
        let manifest = AppManifest::parse(&raw).unwrap();

        assert_eq!(hosts(&manifest)[0], "alpha.test");
    }

    #[test]
    fn accepts_a_single_label_host() {
        assert_eq!("localhost".parse::<Host>().unwrap().as_str(), "localhost");
    }

    #[test]
    fn rejects_a_host_with_a_port() {
        let err = "alpha.test:8080".parse::<Host>().unwrap_err().to_string();
        assert!(err.contains("without a port"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_host() {
        for host in [
            "",
            "alpha..test",
            "alpha.test.",
            "al pha.test",
            "-alpha.test",
            "alpha-.test",
        ] {
            assert!(host.parse::<Host>().is_err(), "accepted `{host}`");
        }
    }

    #[test]
    fn rejects_an_overlong_label() {
        let host = format!("{}.test", "a".repeat(64));
        let err = host.parse::<Host>().unwrap_err().to_string();

        assert!(err.contains("longer than 63"), "{err}");
    }

    /// `MINIMAL` with its `auth` section replaced, indented into place.
    fn with_auth(fields: &str) -> String {
        let fields: String = fields.lines().map(|line| format!("  {line}\n")).collect();

        MINIMAL.replace("auth:\n  gating: open\n", &format!("auth:\n{fields}"))
    }

    /// Either default would be wrong for somebody — `open` publishes an
    /// internal tool, `edge` locks a public site's users out — so a manifest
    /// that does not say is refused rather than guessed at.
    #[test]
    fn rejects_a_manifest_without_an_auth_block() {
        let raw = MINIMAL.replace("auth:\n  gating: open\n", "");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("auth"), "{err}");
    }

    #[test]
    fn parses_open_gating() {
        assert_eq!(AppManifest::parse(MINIMAL).unwrap().auth, Auth::Open {});
    }

    #[test]
    fn parses_edge_gating_with_roles_and_public_prefixes() {
        let raw = with_auth(
            "gating: edge
public_path_prefixes:
  - '/public'
  - '/css/v2'
roles: [reader, writer]",
        );

        let auth = AppManifest::parse(&raw).unwrap().auth;
        let Auth::Edge {
            public_path_prefixes,
            roles,
        } = auth
        else {
            panic!("parsed `gating: edge` as {auth:?}");
        };

        assert_eq!(
            roles.iter().map(Role::as_str).collect::<Vec<_>>(),
            ["reader", "writer"]
        );
        assert_eq!(
            public_path_prefixes
                .iter()
                .map(PathPrefix::as_str)
                .collect::<Vec<_>>(),
            ["/public", "/css/v2"]
        );
    }

    /// Nothing public is the ordinary shape of a gated app, so the list must
    /// be optional — a manifest should not have to write `[]` to say it.
    #[test]
    fn an_edge_gated_app_is_wholly_private_by_default() {
        let auth = AppManifest::parse(&with_auth("gating: edge\nroles: [reader]"))
            .unwrap()
            .auth;

        assert!(matches!(
            auth,
            Auth::Edge { public_path_prefixes, .. } if public_path_prefixes.is_empty()
        ));
    }

    #[test]
    fn rejects_an_unknown_gating() {
        let err = AppManifest::parse(&with_auth("gating: perimeter"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("perimeter"), "{err}");
    }

    /// Roles under `gating: open` are meaningless, and a silently ignored key
    /// hides a misconfiguration: whoever wrote them down believed they were
    /// gating something.
    #[test]
    fn rejects_roles_under_open_gating() {
        let err = AppManifest::parse(&with_auth("gating: open\nroles: [reader]"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("roles"), "{err}");
    }

    /// The same worry for the other `edge` field.
    #[test]
    fn rejects_public_prefixes_under_open_gating() {
        let raw = with_auth("gating: open\npublic_path_prefixes: ['/public']");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("public_path_prefixes"), "{err}");
    }

    /// With `gating: edge`, access is granted per role, so an app with none
    /// declared could never be reached by anyone — `roles` is required, not
    /// defaulted to empty and caught later.
    #[test]
    fn rejects_edge_gating_without_roles() {
        let err = AppManifest::parse(&with_auth("gating: edge"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("roles"), "{err}");
    }

    /// Spelling the empty list out is the same mistake made explicitly.
    #[test]
    fn rejects_edge_gating_with_empty_roles() {
        let err = AppManifest::parse(&with_auth("gating: edge\nroles: []"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("at least one role"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_role() {
        let err = AppManifest::parse(&with_auth("gating: edge\nroles: [reader, reader]"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("twice"), "{err}");
    }

    /// The charset is [`Role`]'s and tested there; this is the seam — a bad
    /// role in a manifest has to surface as a manifest error.
    #[test]
    fn rejects_a_role_that_breaks_the_charset() {
        let err = AppManifest::parse(&with_auth("gating: edge\nroles: [Reader]"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("lowercase"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_public_prefix() {
        let raw = with_auth("gating: edge\nroles: [reader]\npublic_path_prefixes: ['/a', '/a']");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn accepts_a_normalized_public_prefix() {
        for prefix in ["/public", "/css/v2", "/a-b_c.d", "/.well-known/feed"] {
            assert_eq!(
                prefix.parse::<PathPrefix>().unwrap().as_str(),
                prefix,
                "refused `{prefix}`"
            );
        }
    }

    /// `/` is a prefix of every path: `gating: edge` with every request
    /// exempted from it. The message has to point at the honest spelling.
    #[test]
    fn rejects_a_public_prefix_of_the_whole_app() {
        let err = "/".parse::<PathPrefix>().unwrap_err().to_string();

        assert!(err.contains("gating: open"), "{err}");
    }

    /// The shapes the matcher could never match — relative, trailing slash,
    /// empty or dot segments, a query or fragment — refused before they are
    /// stored, so what is stored is already the normal form.
    #[test]
    fn rejects_a_public_prefix_that_is_not_a_normalized_path() {
        for prefix in [
            "",
            "public",
            "public/",
            "/public/",
            "/public//x",
            "//public",
            "/public/./x",
            "/public/..",
            "/../public",
            "/public?x=1",
            "/public#frag",
        ] {
            assert!(prefix.parse::<PathPrefix>().is_err(), "accepted `{prefix}`");
        }
    }

    #[test]
    fn rejects_an_overlong_public_prefix() {
        let prefix = format!("/{}", "a".repeat(MAX_PATH_PREFIX_LEN));
        let err = prefix.parse::<PathPrefix>().unwrap_err().to_string();

        assert!(err.contains("longer than"), "{err}");
    }

    /// Spaceport injects `SPACEPORT_*` variables into every app, and a
    /// manifest that could set one could shadow what the app's middleware
    /// trusts — `SPACEPORT_JWKS_URL` pointed at an attacker's keys is the
    /// concrete disaster. Case-insensitive because an app reading its
    /// environment leniently would still be fooled by `spaceport_jwks_url`.
    #[test]
    fn rejects_an_env_variable_that_shadows_spaceport() {
        for name in ["SPACEPORT_APP_ID", "spaceport_issuer", "SpacePortX"] {
            let raw = with_container(&format!("env:\n  {name}: x"));
            let err = AppManifest::parse(&raw).unwrap_err().to_string();

            assert!(err.contains("spaceport's own"), "for `{name}`: {err}");
        }
    }

    /// The same reservation from the secrets side: a secret is only ever
    /// delivered through an env variable of its own name.
    #[test]
    fn rejects_a_secret_that_shadows_spaceport() {
        let raw = with_container("secrets: [SPACEPORT_TOKEN]\nenv:\n  A: \"{{SPACEPORT_TOKEN}}\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("spaceport's own"), "{err}");
    }

    /// The reservation is a prefix rule, not a substring one: a name that
    /// merely contains or resembles the word is the app's own business.
    #[test]
    fn leaves_variables_that_merely_mention_spaceport_alone() {
        let raw = with_container("env:\n  MY_SPACEPORT_URL: x\n  SPACEPOR: y");
        assert!(AppManifest::parse(&raw).is_ok());
    }

    fn prefix(s: &str) -> PathPrefix {
        s.parse().unwrap()
    }

    /// The segment boundary is what separates a subtree from a lookalike:
    /// `/publicfoo` shares thirteen characters with `/public` and none of its
    /// meaning.
    #[test]
    fn a_prefix_matches_its_subtree_and_not_a_lookalike_segment() {
        let public = prefix("/public");

        assert!(public.matches("/public"));
        assert!(public.matches("/public/x"));
        assert!(public.matches("/public/x/y"));
        assert!(!public.matches("/publicfoo"));
        assert!(!public.matches("/pub"));
        assert!(!public.matches("/"));
        assert!(!public.matches("/x/public"));
    }

    #[test]
    fn canonicalization_leaves_a_plain_path_alone() {
        assert_eq!(canonical_path("/public/x"), "/public/x");
        assert_eq!(canonical_path("/"), "/");
        assert_eq!(canonical_path(""), "/");
    }

    /// The dodges: spellings of a private path that would slip past a naive
    /// prefix compare, and spellings of a public one that would hide from it.
    /// Both directions matter — the first is an information leak, the second
    /// only a nuisance, and canonicalization settles both the same way.
    #[test]
    fn canonicalization_resolves_dot_segments_and_empty_segments() {
        assert_eq!(canonical_path("/css/../secret"), "/secret");
        assert_eq!(canonical_path("/css/%2e%2e/secret"), "/secret");
        assert_eq!(canonical_path("//public/x"), "/public/x");
        assert_eq!(canonical_path("/public/./x"), "/public/x");
        assert_eq!(canonical_path("/a/b/../../public"), "/public");
        // Climbing above the root stays at the root.
        assert_eq!(canonical_path("/../../etc/passwd"), "/etc/passwd");
    }

    /// An encoded slash decodes into a real boundary before segmentation, so
    /// `%2f` can neither glue a fake match together nor smuggle a `..` past
    /// the resolver.
    #[test]
    fn canonicalization_decodes_an_encoded_slash_into_a_boundary() {
        assert_eq!(canonical_path("/secret%2f..%2fpublic/x"), "/public/x");
        assert_eq!(canonical_path("/css%2f..%2fsecret"), "/secret");
    }

    /// What cannot be decoded must fail towards "not public": a stray percent
    /// and non-UTF-8 bytes stay unmatchable rather than becoming a prefix.
    #[test]
    fn undecodable_paths_never_fake_a_match() {
        let public = prefix("/public");

        assert!(!public.matches(&canonical_path("/public%")));
        assert!(public.matches(&canonical_path("/public/%ff")));
        assert!(!public.matches(&canonical_path("/%ffpublic")));
    }
}
