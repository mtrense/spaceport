//! Handing an unpacked commit to the engine, and getting an image back.
//!
//! This is the last of the build module's four seams and the only one that
//! talks to a container engine. What crosses it is deliberately small: a
//! directory, the Dockerfile inside it, the tag to give the result, and the
//! labels to stamp on it. What comes back is a [`BuiltImage`] — spaceport's own
//! answer, not the engine's — because everything downstream of a build records
//! and reports an image rather than reading an engine's stream.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;

use crate::app::AppId;

/// How much of a sha spaceport writes down when it is naming something for a
/// person to read.
///
/// Seven, the same as `connections/github/push.rs` abbreviates a pushed head
/// to. The two are read side by side — the log line says a push moved a branch
/// to `0123456`, and the tag it produced says `0123456` — and a tag that
/// abbreviated differently would make the operator do the comparison by eye.
const ABBREVIATED_SHA: usize = 7;

/// Asks a container engine to build an image.
///
/// The trait is here for one concrete reason rather than an aspirational one.
/// Bollard supports the classic builder with no feature flag at all; turning on
/// its `buildkit` feature changes the *type* of `BuildInfo::aux` — the field a
/// built image's id arrives in — and additionally wants a gRPC session and a
/// considerably larger dependency tree. Neither the type change nor the session
/// is something the rest of spaceport should have an opinion about, so the
/// engine's stream is read in one place and what leaves it is [`BuiltImage`].
/// Moving to buildkit is then a change to the implementation and to nothing
/// else.
#[async_trait]
pub trait ImageBuilder: Send + Sync {
    async fn build(&self, request: &BuildRequest) -> Result<BuiltImage>;
}

/// What to build, and what to call it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// The unpacked tree that is the build context.
    pub context: PathBuf,

    /// The Dockerfile, as a path inside `context`.
    pub dockerfile: PathBuf,

    pub tag: String,

    pub labels: BTreeMap<String, String>,
}

/// What the engine made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltImage {
    pub tag: String,

    /// The engine's own id for it.
    pub id: String,

    /// The build log, as the engine emitted it.
    pub log: Vec<String>,
}

/// What spaceport calls the image it built for `app` from `revision`.
///
/// `spaceport/` so that an image spaceport built cannot be mistaken for one
/// pulled from a registry — the prefix is not a registry host, so nothing will
/// ever try to push or fetch it — and the abbreviated sha so that an operator
/// looking at `docker images` can see which commit each image is.
///
/// Both segments are already character-restricted by the types they come from:
/// an [`AppId`] is lowercase letters, digits and hyphens, and a revision is a
/// git object name, which is hex. So the tag cannot be malformed by what goes
/// into it — but that is a property of two validators in other files, and this
/// is the one place where a change to either would produce a tag the engine
/// rejects with a message about nothing in particular. It is asserted here
/// rather than assumed.
pub fn tag(app: &AppId, revision: &str) -> String {
    let short: String = revision
        .chars()
        .take(ABBREVIATED_SHA)
        .collect::<String>()
        .to_ascii_lowercase();

    assert!(
        !short.is_empty() && short.chars().all(|c| c.is_ascii_hexdigit()),
        "`{revision}` is not a git object name, so it cannot name an image"
    );
    assert!(
        app.as_str()
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "app id `{app}` is not what an image tag may contain"
    );

    format!("spaceport/{app}:{short}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_an_image_after_the_app_and_the_commit_it_came_from() {
        let app: AppId = "my-app".parse().unwrap();

        assert_eq!(
            tag(&app, "0123456789abcdef0123456789abcdef01234567"),
            "spaceport/my-app:0123456"
        );
    }

    /// The same seven digits a push writes down, so that the two lines an
    /// operator reads next to each other say the same thing.
    #[test]
    fn abbreviates_a_sha_the_way_a_push_does() {
        let app: AppId = "app".parse().unwrap();
        let tag = tag(&app, "0123456789abcdef0123456789abcdef01234567");

        assert_eq!(tag.split(':').next_back().unwrap().len(), 7);
    }

    /// A sha shorter than the abbreviation is still a name for one commit, and
    /// truncating is all the abbreviation ever does.
    #[test]
    fn names_an_image_from_an_already_short_sha() {
        let app: AppId = "app".parse().unwrap();

        assert_eq!(tag(&app, "abc123"), "spaceport/app:abc123");
    }

    #[test]
    fn refuses_a_revision_that_is_not_an_object_name() {
        let app: AppId = "app".parse().unwrap();

        for revision in ["", "not-a-sha", "HEAD"] {
            assert!(
                std::panic::catch_unwind(|| tag(&app, revision)).is_err(),
                "accepted `{revision}`"
            );
        }
    }
}
