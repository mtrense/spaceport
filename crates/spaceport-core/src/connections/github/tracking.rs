//! Which repository an app is built from, and how far along it spaceport has
//! got.
//!
//! This is the first thing under `connections::github` that is not a cache.
//! Installations and the repositories they grant are GitHub's answer, thrown
//! away and refetched at will; a tracking is an operator's decision — *this*
//! app comes from *that* branch of *that* repository, and its manifest is at
//! *that* path — and losing one means the app stops being rebuilt with nothing
//! to say why. It is kept beside the cache rather than on the app because an
//! app that is not connected to any forge has nothing to say here, and a nulled
//! column on `apps` would be that absence spelled the long way.
//!
//! One tracking per app, keyed by spaceport's own [`AppId`]. An app is built
//! from one place, so re-tracking replaces rather than accumulates, and the
//! opposite direction is left open: a monorepo holding a manifest per app is
//! several trackings over the same repository, which the index rather than the
//! key has to serve.
//!
//! The revision is the one piece of state that is not the operator's. It is the
//! head sha spaceport last accepted for the tracked ref, written when a build
//! is taken and not when a push arrives — so the gap between it and what GitHub
//! reports is what "behind" means. It resets whenever the tracking moves.
//!
//! Nothing reads any of this yet. Deciding what a push means, and doing
//! anything about it, is a later step and lives nowhere.

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;

use crate::app::AppId;
use crate::state::Db;

/// One app, and the repository it is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracking {
    /// Spaceport's own id for the app — the name an operator chose, not
    /// anything GitHub knows.
    pub app: AppId,
    /// The numeric id of the GitHub App whose installation grants the
    /// repository. Named apart from [`Tracking::app`] all the way down to the
    /// column, because the two are different id-spaces that would otherwise
    /// both be called an app id.
    pub github_app_id: i64,
    /// `owner/name`, exactly as GitHub spells a full name.
    pub repository: String,
    pub branch: String,
    /// Where in the repository the app's manifest is, as a path from its root.
    pub manifest_path: String,
    /// When the tracking was recorded, RFC 3339.
    pub tracked_at: String,
    /// The head sha spaceport last accepted for this ref, if it has accepted
    /// one. `None` is an app pointed at a branch nothing has been taken from
    /// yet, which is not the same as one whose branch is empty.
    pub revision: Option<String>,
    /// When that revision was accepted, RFC 3339. Written and cleared with
    /// [`Tracking::revision`], never on its own.
    pub revision_seen_at: Option<String>,
}

/// The columns of `github_tracking`, in the order [`tracking_from`] reads them.
///
/// Written once so the `SELECT`s and the row mapping cannot drift apart.
const TRACKING_COLUMNS: &str = "spaceport_app, github_app_id, repository, branch, manifest_path, \
                                tracked_at, revision, revision_seen_at";

/// What an app is built from, in the vocabulary of tracking, pushing and
/// forgetting.
#[derive(Debug, Clone)]
pub struct TrackingRepository {
    db: Db,
}

impl TrackingRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Record that `tracking.app` is built from `tracking.repository`.
    ///
    /// Replaces whatever that app tracked before: an app is built from one
    /// place, and pointing it somewhere else is a `PUT`. `tracked_at` is
    /// stamped here rather than taken from the struct, so the recorded time is
    /// always the time the row was written.
    ///
    /// A re-track resets the revision to `None`, even when only the manifest
    /// path moved. The revision means "the last head sha spaceport accepted for
    /// this ref", and a sha carried over from the old ref was never on the new
    /// one — it would make a first build of the new branch look like a build
    /// that had already happened.
    pub async fn record(&self, tracking: &Tracking) -> Result<()> {
        let app = tracking.app.to_string();
        let github_app_id = tracking.github_app_id;
        let repository = tracking.repository.clone();
        let branch = tracking.branch.clone();
        let manifest_path = tracking.manifest_path.clone();
        let tracked_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO github_tracking (
                             spaceport_app, github_app_id, repository, branch,
                             manifest_path, tracked_at, revision, revision_seen_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)
                         ON CONFLICT(spaceport_app) DO UPDATE SET
                             github_app_id    = excluded.github_app_id,
                             repository       = excluded.repository,
                             branch           = excluded.branch,
                             manifest_path    = excluded.manifest_path,
                             tracked_at       = excluded.tracked_at,
                             revision         = NULL,
                             revision_seen_at = NULL",
                        rusqlite::params![
                            app,
                            github_app_id,
                            repository,
                            branch,
                            manifest_path,
                            tracked_at
                        ],
                    )
                    .context("recording the repository an app tracks")?;

                Ok(())
            })
            .await
    }

    /// What `app` is built from, if anything.
    pub async fn by_app(&self, app: &AppId) -> Result<Option<Tracking>> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "SELECT {TRACKING_COLUMNS} FROM github_tracking \
                             WHERE spaceport_app = ?1"
                        ),
                        [app],
                        tracking_from,
                    )
                    .optional()
                    .context("reading what an app tracks")
            })
            .await
    }

    /// Every tracking this spaceport holds, by app.
    ///
    /// Ordered so that a listing an operator reads twice reads the same twice.
    pub async fn all(&self) -> Result<Vec<Tracking>> {
        self.db
            .call(|connection| {
                let mut statement = connection
                    .prepare(&format!(
                        "SELECT {TRACKING_COLUMNS} FROM github_tracking ORDER BY spaceport_app"
                    ))
                    .context("preparing the tracking query")?;

                let rows = statement
                    .query_map([], tracking_from)
                    .context("reading what the apps track")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading what the apps track")?;

                Ok(rows)
            })
            .await
    }

    /// Every app a push to `branch` of `repository`, under the App
    /// `github_app_id`, is about.
    ///
    /// The question a delivery asks, and the reason the index over those three
    /// columns exists. Several rather than one, because a monorepo holds a
    /// manifest per app and one commit moves all of them; empty is the ordinary
    /// answer for a push to a repository nobody has tracked. Ordered by app, so
    /// that one push builds in the same order every time.
    pub async fn for_push(
        &self,
        github_app_id: i64,
        repository: &str,
        branch: &str,
    ) -> Result<Vec<Tracking>> {
        let repository = repository.to_owned();
        let branch = branch.to_owned();

        self.db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(&format!(
                        "SELECT {TRACKING_COLUMNS} FROM github_tracking
                         WHERE github_app_id = ?1 AND repository = ?2 AND branch = ?3
                         ORDER BY spaceport_app"
                    ))
                    .context("preparing the tracking query for a push")?;

                let rows = statement
                    .query_map(
                        rusqlite::params![github_app_id, repository, branch],
                        tracking_from,
                    )
                    .context("reading what a push is about")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading what a push is about")?;

                Ok(rows)
            })
            .await
    }

    /// Write down that `revision` is what spaceport has accepted for `app`.
    ///
    /// Silent about an app that tracks nothing: the caller got here from a
    /// tracking row, and a disconnect that raced it is a build that no longer
    /// matters rather than an error worth propagating.
    pub async fn record_revision(&self, app: &AppId, revision: &str) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let seen_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE github_tracking
                         SET revision = ?2, revision_seen_at = ?3
                         WHERE spaceport_app = ?1",
                        rusqlite::params![app, revision, seen_at],
                    )
                    .context("recording the revision an app was built from")?;

                Ok(())
            })
            .await
    }

    /// Stop tracking anything for `app`, and say whether it tracked something.
    pub async fn forget(&self, app: &AppId) -> Result<bool> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                let deleted = connection
                    .execute(
                        "DELETE FROM github_tracking WHERE spaceport_app = ?1",
                        [app],
                    )
                    .context("forgetting what an app tracks")?;

                Ok(deleted > 0)
            })
            .await
    }

    /// Stop tracking everything that reached GitHub through `github_app_id`,
    /// and say how much that was.
    ///
    /// A connection that is gone cannot grant a repository, so a tracking left
    /// behind is one nothing could ever act on. Forgetting a connection does
    /// this itself, in the transaction that forgets the connection — this is
    /// here for the callers that have a reason to drop the trackings without
    /// dropping the connection.
    pub async fn forget_connection(&self, github_app_id: i64) -> Result<usize> {
        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "DELETE FROM github_tracking WHERE github_app_id = ?1",
                        [github_app_id],
                    )
                    .context("forgetting what a connection's apps track")
            })
            .await
    }
}

/// One row of `github_tracking`, in the order [`TRACKING_COLUMNS`] names.
///
/// The app id goes back through `parse` rather than being taken as a string,
/// because a row that will not parse is a row this build cannot act on and the
/// honest place to find that out is where it is read.
fn tracking_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<Tracking> {
    let app: String = row.get(0)?;
    let app = app.parse::<AppId>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
    })?;

    Ok(Tracking {
        app,
        github_app_id: row.get(1)?,
        repository: row.get(2)?,
        branch: row.get(3)?,
        manifest_path: row.get(4)?,
        tracked_at: row.get(5)?,
        revision: row.get(6)?,
        revision_seen_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> TrackingRepository {
        TrackingRepository::new(Db::in_memory().unwrap())
    }

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    fn tracking(id: &str, github_app_id: i64, repository: &str, branch: &str) -> Tracking {
        Tracking {
            app: app(id),
            github_app_id,
            repository: repository.to_owned(),
            branch: branch.to_owned(),
            manifest_path: "spaceport.yaml".to_owned(),
            tracked_at: String::new(),
            revision: None,
            revision_seen_at: None,
        }
    }

    #[tokio::test]
    async fn tracks_nothing_to_begin_with() {
        let repository = repository();

        assert!(repository.all().await.unwrap().is_empty());
        assert!(repository.by_app(&app("site")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn records_and_reads_back_what_an_app_tracks() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();

        let read = repository.by_app(&app("site")).await.unwrap().unwrap();
        assert_eq!(read.github_app_id, 42);
        assert_eq!(read.repository, "an-organisation/site");
        assert_eq!(read.branch, "main");
        assert_eq!(read.manifest_path, "spaceport.yaml");
        assert_eq!(read.revision, None);
        // Stamped on the way in, whatever the struct said.
        assert!(read.tracked_at.ends_with('Z'), "{read:?}");
    }

    #[tokio::test]
    async fn re_tracking_an_app_replaces_what_it_tracked() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();
        repository
            .record(&tracking("site", 42, "an-organisation/other", "main"))
            .await
            .unwrap();

        let all = repository.all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].repository, "an-organisation/other");
    }

    /// The head sha belonged to the ref it was seen on. Carrying one across a
    /// re-track would make the first build of the new branch look like one that
    /// had already been done, and nothing would ever build it.
    #[tokio::test]
    async fn re_tracking_forgets_the_revision_that_was_never_on_the_new_ref() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();
        repository
            .record_revision(&app("site"), "0123456789abcdef")
            .await
            .unwrap();

        repository
            .record(&tracking("site", 42, "an-organisation/site", "release"))
            .await
            .unwrap();

        let read = repository.by_app(&app("site")).await.unwrap().unwrap();
        assert_eq!(read.revision, None);
        assert_eq!(read.revision_seen_at, None);
    }

    #[tokio::test]
    async fn records_the_revision_an_app_was_built_from() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();

        repository
            .record_revision(&app("site"), "0123456789abcdef")
            .await
            .unwrap();

        let read = repository.by_app(&app("site")).await.unwrap().unwrap();
        assert_eq!(read.revision.as_deref(), Some("0123456789abcdef"));
        assert!(
            read.revision_seen_at.as_deref().unwrap().ends_with('Z'),
            "{read:?}"
        );
    }

    #[tokio::test]
    async fn lists_trackings_in_app_order() {
        let repository = repository();
        for id in ["zulu", "alpha", "mike"] {
            repository
                .record(&tracking(id, 42, "an-organisation/mono", "main"))
                .await
                .unwrap();
        }

        let apps: Vec<String> = repository
            .all()
            .await
            .unwrap()
            .into_iter()
            .map(|tracking| tracking.app.to_string())
            .collect();
        assert_eq!(apps, ["alpha", "mike", "zulu"]);
    }

    /// One commit in a monorepo moves every app whose manifest lives in it, so
    /// a push resolves to several trackings and not one.
    #[tokio::test]
    async fn a_push_finds_every_app_that_tracks_the_ref() {
        let repository = repository();
        for id in ["zulu", "alpha"] {
            repository
                .record(&tracking(id, 42, "an-organisation/mono", "main"))
                .await
                .unwrap();
        }

        let found = repository
            .for_push(42, "an-organisation/mono", "main")
            .await
            .unwrap();

        let apps: Vec<String> = found
            .iter()
            .map(|tracking| tracking.app.to_string())
            .collect();
        assert_eq!(apps, ["alpha", "zulu"]);
    }

    /// All three columns of the index have to match. A push to another branch,
    /// another repository, or a repository of the same name under a different
    /// App is not this app's push — and the last of those is the one a lookup
    /// on name alone would get wrong.
    #[tokio::test]
    async fn a_push_finds_nothing_that_merely_looks_like_the_ref() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();

        for (app_id, name, branch) in [
            (43, "an-organisation/site", "main"),
            (42, "another-org/site", "main"),
            (42, "an-organisation/site", "release"),
        ] {
            assert!(
                repository
                    .for_push(app_id, name, branch)
                    .await
                    .unwrap()
                    .is_empty(),
                "{app_id} {name} {branch} matched"
            );
        }
    }

    #[tokio::test]
    async fn forgetting_a_tracking_says_whether_there_was_one() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();

        assert!(repository.forget(&app("site")).await.unwrap());
        assert!(!repository.forget(&app("site")).await.unwrap());
        assert!(repository.all().await.unwrap().is_empty());
    }

    /// A connection that is gone grants nothing, so what reached GitHub through
    /// it goes with it — and what reached GitHub through another App stays.
    #[tokio::test]
    async fn forgetting_a_connection_forgets_only_what_it_reached() {
        let repository = repository();
        repository
            .record(&tracking("site", 42, "an-organisation/site", "main"))
            .await
            .unwrap();
        repository
            .record(&tracking("docs", 42, "an-organisation/docs", "main"))
            .await
            .unwrap();
        repository
            .record(&tracking("other", 43, "another-org/site", "main"))
            .await
            .unwrap();

        assert_eq!(repository.forget_connection(42).await.unwrap(), 2);

        let all = repository.all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].app.as_str(), "other");
    }
}
