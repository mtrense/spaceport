//! What a push GitHub delivered means for the apps that track the branch it
//! moved.
//!
//! A tracking says an app is built from a branch of a repository. A push says a
//! branch of a repository moved. This module is the join between the two, and
//! the whole of what it does is write down the head sha the branch moved to —
//! one row per app, and one line in the event stream so that an operator
//! watching `spaceport stream` sees the moment spaceport heard. Nothing builds
//! anything from this yet. No image is made, no container is replaced, and the
//! only observable effect of a push is a revision in `github_tracking` and the
//! event that says it was written.
//!
//! Branches only, and deliberately. `refs/tags/*` reaches this module and
//! leaves it untouched, because `spaceport apps track` binds exactly one branch
//! and a tag is not on a branch — a tag pointing at a commit says nothing about
//! whether that commit is the head of anything. Building from tags is a feature
//! with a flag of its own, and until an operator has asked for it, acting on a
//! tag would be spaceport deciding to deploy something nobody named.
//!
//! Deletions leave it untouched too. A branch that is gone has no new head, and
//! recording the sha a delete delivery carries would record `0000…` as the
//! revision an app was built from — a value no build could ever be taken at,
//! and one that would make the next real push to a recreated branch look like a
//! change from a commit that never existed.
//!
//! The head is taken from the fields GitHub uses to name the tip of the push,
//! and never by walking the commits. That is the requirement this module exists
//! to satisfy: a push of five commits is one event about one new head, not five
//! events, and expressing that as "read the tip GitHub named" rather than as a
//! loop with a break means there is no arithmetic to get wrong and no ordering
//! of the `commits` array to depend on.
//!
//! The rejected alternative to the per-tracking loop below was letting the
//! first failure end the delivery. A monorepo resolves to a tracking per app,
//! and one app whose row will not write is not a reason for the others to stay
//! on a revision that has moved — the same discipline [`super::reconcile`]
//! applies per connection.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::tracking::TrackingRepository;
use super::webhook::Payload;

/// What every branch ref begins with.
///
/// The suffix after it is the branch, slashes and all: `refs/heads/feature/x`
/// is the branch `feature/x`, and taking the last segment would make it `x` —
/// a name that matches a different tracking, or none.
const BRANCH_PREFIX: &str = "refs/heads/";

/// The lengths a sha GitHub sends can plausibly have — SHA-1 today, SHA-256
/// once GitHub finishes moving.
///
/// Used only to decide whether an all-zeros string is the absent sha. A short
/// run of zeros is somebody's truncated field or a fixture, and reading it as
/// "this ref is gone" would silently drop a real push.
const SHA_LENGTHS: [usize; 2] = [40, 64];

/// Take in one verified push, and record the head it moved a tracked branch to.
///
/// The whole [`Payload`] rather than the four values it would otherwise take,
/// which is why [`Payload`] is visible to this module at all. Four `&str`
/// arguments in a row is an order nothing checks, and it would also put the
/// decision about *which* fields a push is made of into [`super::webhook`] —
/// whose job is to establish that a delivery is genuine and to hand it on
/// unread. The knowledge that a push is a ref, a head and a deletion flag
/// belongs here, next to the checks that use it.
///
/// The `Err` case is the state store failing, and nothing else: a push that
/// matches no tracking, names no branch, or has already been seen is an
/// ordinary outcome and returns `Ok`.
pub(super) async fn handle(
    tracking: &TrackingRepository,
    github_app_id: i64,
    payload: &Payload,
) -> Result<()> {
    let Some(reference) = payload.reference.as_deref() else {
        warn!("a push named no ref");

        return Ok(());
    };

    let Some(branch) = reference.strip_prefix(BRANCH_PREFIX) else {
        debug!(reference, "a push was not to a branch");

        return Ok(());
    };

    if deletes_the_ref(payload) {
        debug!(reference, "a push deleted a branch");

        return Ok(());
    }

    let Some(repository) = payload.repository.as_deref() else {
        warn!(reference, "a push named no repository");

        return Ok(());
    };

    let tracked = tracking
        .for_push(github_app_id, repository, branch)
        .await
        .context("finding the apps a push is about")?;

    if tracked.is_empty() {
        debug!(repository, branch, "a push moved a branch nothing tracks");

        return Ok(());
    }

    let Some(revision) = head(payload) else {
        warn!(
            repository,
            branch, "a push to a tracked branch named no head"
        );

        return Ok(());
    };

    for tracked in tracked {
        // A delivery GitHub sent twice, arriving after the delivery id it
        // carries has been pruned out of the window, lands here rather than
        // being recognised earlier — and looks exactly like a push to the head
        // that is already recorded, because that is what it is.
        if tracked.revision.as_deref() == Some(revision) {
            debug!(
                app = %tracked.app,
                repository,
                branch,
                "a push landed on the revision this app is already at",
            );

            continue;
        }

        if let Err(error) = tracking.record_revision(&tracked.app, revision).await {
            warn!(
                app = %tracked.app,
                error = %format!("{error:#}"),
                "could not record the revision a push moved an app to",
            );

            continue;
        }

        let head = abbreviate(revision);
        info!(
            app = %tracked.app,
            repository,
            branch,
            revision,
            "the branch this app tracks moved to {head}",
        );
    }

    Ok(())
}

/// Whether this push is the ref going away.
///
/// The all-zeros sha is authoritative on its own, and is checked as well as the
/// flag rather than instead of it: it is what GitHub puts in `after` for a
/// delete, and a body that carried it without the flag would otherwise be read
/// as a branch moving to a commit nobody can fetch.
fn deletes_the_ref(payload: &Payload) -> bool {
    payload.deleted || payload.after.as_deref().is_some_and(is_the_absent_sha)
}

/// Whether `sha` is the value git spells "nothing is here".
fn is_the_absent_sha(sha: &str) -> bool {
    SHA_LENGTHS.contains(&sha.len()) && sha.bytes().all(|byte| byte == b'0')
}

/// The commit this push moved the branch to.
///
/// `after` first because it is the ref's new value and is present on every
/// push; `head_commit.id` is the same commit said another way, and is the
/// fallback for a body whose `after` is missing or empty rather than a second
/// opinion. Neither is the `commits` array: GitHub already names the tip, so
/// "act on the last commit of a push and not on each of them" is the shape of
/// this function rather than a loop somebody has to keep correct.
fn head(payload: &Payload) -> Option<&str> {
    present(payload.after.as_deref()).or_else(|| present(payload.head_commit.as_deref()))
}

/// `value` when it is text that says something.
fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

/// The first few digits of a sha, which is how a person says one out loud.
fn abbreviate(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::AppId;
    use crate::connections::github::tracking::Tracking;
    use crate::state::Db;

    const APP_ID: i64 = 42;
    const REPOSITORY: &str = "an-organisation/site";
    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
    const PREVIOUS: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const ABSENT: &str = "0000000000000000000000000000000000000000";

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    fn repository() -> TrackingRepository {
        TrackingRepository::new(Db::in_memory().unwrap())
    }

    /// An app tracking `branch` of [`REPOSITORY`] through the App `github_app_id`.
    async fn track(tracking: &TrackingRepository, id: &str, github_app_id: i64, branch: &str) {
        tracking
            .record(&Tracking {
                app: app(id),
                github_app_id,
                repository: REPOSITORY.to_owned(),
                branch: branch.to_owned(),
                manifest_path: "spaceport.yaml".to_owned(),
                tracked_at: String::new(),
                revision: None,
                revision_seen_at: None,
            })
            .await
            .unwrap();
    }

    /// A push body as GitHub sends one, read back through the same [`Payload`]
    /// the webhook builds — so that a field this module reads by the wrong
    /// pointer fails here rather than only in production.
    fn push(reference: &str, after: &str) -> Payload {
        Payload::read(
            format!(
                r#"{{"ref":"{reference}",
                     "after":"{after}",
                     "repository":{{"full_name":"{REPOSITORY}"}},
                     "head_commit":{{"id":"{after}"}}}}"#
            )
            .as_bytes(),
        )
    }

    async fn revision(tracking: &TrackingRepository, id: &str) -> Option<String> {
        tracking.by_app(&app(id)).await.unwrap().unwrap().revision
    }

    #[tokio::test]
    async fn ignores_a_push_to_a_branch_nobody_tracks() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;

        handle(&tracking, APP_ID, &push("refs/heads/release", HEAD))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await, None);
    }

    /// `track` binds a branch, and a tag is not on one. Acting on a tag would
    /// be spaceport deploying something no operator asked it to.
    #[tokio::test]
    async fn ignores_a_tag_push() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;

        handle(&tracking, APP_ID, &push("refs/tags/v1.0.0", HEAD))
            .await
            .unwrap();
        // And anything else that is not a branch either.
        handle(&tracking, APP_ID, &push("refs/pull/7/head", HEAD))
            .await
            .unwrap();
        handle(&tracking, APP_ID, &push("main", HEAD))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await, None);
    }

    /// A deleted branch has no new head. The flag and the all-zeros sha are
    /// checked separately because GitHub sends the sha whether or not the body
    /// this spaceport receives carries the flag.
    #[tokio::test]
    async fn ignores_a_branch_deletion() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;

        let mut flagged = push("refs/heads/main", HEAD);
        flagged.deleted = true;
        handle(&tracking, APP_ID, &flagged).await.unwrap();

        assert_eq!(revision(&tracking, "site").await, None);

        let zeroed = push("refs/heads/main", ABSENT);
        assert!(!zeroed.deleted, "the flag is not what this case tests");
        handle(&tracking, APP_ID, &zeroed).await.unwrap();

        assert_eq!(revision(&tracking, "site").await, None);
    }

    /// The reason this module exists: five commits in one push are one new
    /// head, and what is recorded is the tip GitHub named rather than anything
    /// walked out of the `commits` array.
    #[tokio::test]
    async fn acts_on_the_head_of_a_push_and_not_on_each_commit() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        let payload = Payload::read(
            format!(
                r#"{{"ref":"refs/heads/main",
                     "before":"{PREVIOUS}",
                     "after":"{HEAD}",
                     "repository":{{"full_name":"{REPOSITORY}"}},
                     "commits":[{{"id":"aaaaaaa"}},{{"id":"bbbbbbb"}},{{"id":"{HEAD}"}}],
                     "head_commit":{{"id":"{HEAD}"}}}}"#
            )
            .as_bytes(),
        );

        handle(&tracking, APP_ID, &payload).await.unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(HEAD));
    }

    /// GitHub retries, and a retry that arrives after the delivery window has
    /// been pruned reaches this far. The recorded revision is what makes it
    /// harmless.
    #[tokio::test]
    async fn ignores_a_push_that_lands_on_the_revision_already_seen() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        handle(&tracking, APP_ID, &push("refs/heads/main", HEAD))
            .await
            .unwrap();
        let seen_at = tracking
            .by_app(&app("site"))
            .await
            .unwrap()
            .unwrap()
            .revision_seen_at;

        handle(&tracking, APP_ID, &push("refs/heads/main", HEAD))
            .await
            .unwrap();

        let read = tracking.by_app(&app("site")).await.unwrap().unwrap();
        assert_eq!(read.revision.as_deref(), Some(HEAD));
        // Not rewritten, which is what says the second delivery did nothing.
        assert_eq!(read.revision_seen_at, seen_at);
    }

    /// A force push moves the head backwards or sideways. It is still a new
    /// head for this branch, and "new" here means different rather than later.
    #[tokio::test]
    async fn acts_on_a_force_push_that_moves_the_head() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        handle(&tracking, APP_ID, &push("refs/heads/main", HEAD))
            .await
            .unwrap();

        handle(&tracking, APP_ID, &push("refs/heads/main", PREVIOUS))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(PREVIOUS));
    }

    /// The branch is everything after `refs/heads/`, slashes included. Taking
    /// the last segment would make `feature/x` into `x`.
    #[tokio::test]
    async fn tracks_a_branch_whose_name_contains_a_slash() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "feature/x").await;

        handle(&tracking, APP_ID, &push("refs/heads/feature/x", HEAD))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(HEAD));
    }

    /// Two spaceport connections can both reach a repository of the same name,
    /// and a push through one of them is not news about the other's app.
    #[tokio::test]
    async fn a_push_on_one_connection_does_not_trigger_another_connections_tracking() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        track(&tracking, "other", 43, "main").await;

        handle(&tracking, APP_ID, &push("refs/heads/main", HEAD))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(HEAD));
        assert_eq!(revision(&tracking, "other").await, None);
    }

    /// A monorepo holds a manifest per app, and one commit moves all of them.
    #[tokio::test]
    async fn every_app_tracking_the_same_branch_hears_about_the_push() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        track(&tracking, "docs", APP_ID, "main").await;

        handle(&tracking, APP_ID, &push("refs/heads/main", HEAD))
            .await
            .unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(HEAD));
        assert_eq!(revision(&tracking, "docs").await.as_deref(), Some(HEAD));
    }

    /// A body whose `after` never arrived is still a push about a head, and
    /// `head_commit` is the same commit said another way.
    #[tokio::test]
    async fn falls_back_to_the_head_commit_when_a_push_names_no_after() {
        let tracking = repository();
        track(&tracking, "site", APP_ID, "main").await;
        let payload = Payload::read(
            format!(
                r#"{{"ref":"refs/heads/main",
                     "repository":{{"full_name":"{REPOSITORY}"}},
                     "head_commit":{{"id":"{HEAD}"}}}}"#
            )
            .as_bytes(),
        );

        handle(&tracking, APP_ID, &payload).await.unwrap();

        assert_eq!(revision(&tracking, "site").await.as_deref(), Some(HEAD));
    }

    #[test]
    fn only_a_sha_shaped_run_of_zeros_says_a_ref_is_gone() {
        assert!(is_the_absent_sha(ABSENT));
        assert!(is_the_absent_sha(&"0".repeat(64)));
        // Too short to be a sha, so it is somebody's truncated field rather
        // than git's word for nothing.
        assert!(!is_the_absent_sha("0000000"));
        assert!(!is_the_absent_sha(""));
        assert!(!is_the_absent_sha(HEAD));
    }

    #[test]
    fn abbreviates_a_sha_the_way_a_person_says_one() {
        assert_eq!(abbreviate(HEAD), "0123456");
        assert_eq!(abbreviate("abc"), "abc");
    }
}
