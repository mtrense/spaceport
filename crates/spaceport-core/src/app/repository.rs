//! What spaceport has been told to run, remembered across restarts.
//!
//! A record is intent, not observation: an app's id and the manifest that was
//! applied under it, kept **verbatim** — the exact document the operator sent,
//! not a re-serialization of what this build understood it to mean. A build
//! that adds a manifest field can then read back what an older one stored and
//! see the field; a re-serialized manifest would have dropped it on the way in
//! and nobody would ever know.
//!
//! Nothing about the container is in here. That is [`crate::app::store`]'s
//! business, and it lives only as long as the process does.

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use tracing::warn;

use super::AppId;
use crate::config::SCHEMA_VERSION;
use crate::state::Db;

/// One app spaceport should be running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRecord {
    pub id: AppId,
    /// The schema the stored manifest was written against.
    pub schema_version: u64,
    /// The manifest document, exactly as it was applied.
    pub manifest: String,
    /// When it was applied, RFC 3339.
    pub applied_at: String,
    /// Whether spaceport has been told not to run it for now.
    ///
    /// Still intent, and still this app's: a suspended record says the operator
    /// wants this manifest under this id and does not want it served yet.
    pub suspended: bool,

    /// The commit whose build this app runs, for a manifest that is built
    /// rather than pulled.
    ///
    /// The revision and not the image tag it resolved to, for the same reason
    /// the manifest is kept verbatim: this is intent. A restart re-resolves
    /// *this* revision and runs what was deployed, where a stored tag would run
    /// whatever a later build happened to move it to, and a stored "latest
    /// build" would silently deploy a commit nobody asked for. `None` for an
    /// app whose manifest names its image outright, which has no revision to
    /// remember.
    pub revision: Option<String>,
}

/// SQLite integers are signed, so a schema version goes in as an `i64`.
/// Versions are small; nothing real is lost here.
fn stored(version: u64) -> i64 {
    i64::try_from(version).unwrap_or(i64::MAX)
}

/// And comes back as one. A stored version that does not fit a `u64` is a
/// version this build could not read either way, so saying "newer than
/// anything" is the truthful answer.
fn read(version: i64) -> u64 {
    u64::try_from(version).unwrap_or(u64::MAX)
}

/// The apps table, in the vocabulary of applying and destroying apps.
#[derive(Debug, Clone)]
pub struct AppRepository {
    db: Db,
}

impl AppRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Remember that `manifest` is what the app named `id` should be running,
    /// which commit it was deployed from, and whether it should be running it
    /// yet.
    ///
    /// Replaces whatever was recorded under that id — an apply is a `PUT`, and
    /// so is this. `revision` goes the same way: an operator who applies a
    /// manifest of their own over a deployed one has replaced the app, and a
    /// revision left behind from the deploy before would outlive what it
    /// described.
    pub async fn record_applied(
        &self,
        id: &AppId,
        manifest: &str,
        revision: Option<&str>,
        suspended: bool,
    ) -> Result<()> {
        let id = id.to_string();
        let manifest = manifest.to_owned();
        let revision = revision.map(str::to_owned);
        let applied_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO apps
                             (id, schema_version, manifest, applied_at, suspended, revision)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(id) DO UPDATE SET
                             schema_version = excluded.schema_version,
                             manifest       = excluded.manifest,
                             applied_at     = excluded.applied_at,
                             suspended      = excluded.suspended,
                             revision       = excluded.revision",
                        rusqlite::params![
                            id,
                            stored(SCHEMA_VERSION),
                            manifest,
                            applied_at,
                            suspended,
                            revision
                        ],
                    )
                    .context("recording an applied app")?;

                Ok(())
            })
            .await
    }

    /// Write `record` back exactly as it was read, `applied_at` and all.
    ///
    /// For the one caller that has to undo a record rather than write one: an
    /// automatic deployment that failed *after* the applier had recorded what
    /// it was staging, which then rolls the app back to what it was running.
    /// [`AppRepository::record_applied`] would be wrong there twice over — it
    /// would say the app was applied at the moment of the rollback, and it is
    /// this record's own values that are going back, not new intent.
    ///
    /// Idempotent, and a no-op in every other sense: a rollback that had
    /// nothing to undo writes the same row it read.
    pub async fn put_back(&self, record: &AppRecord) -> Result<()> {
        let id = record.id.to_string();
        let schema_version = stored(record.schema_version);
        let manifest = record.manifest.clone();
        let applied_at = record.applied_at.clone();
        let suspended = record.suspended;
        let revision = record.revision.clone();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO apps
                             (id, schema_version, manifest, applied_at, suspended, revision)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(id) DO UPDATE SET
                             schema_version = excluded.schema_version,
                             manifest       = excluded.manifest,
                             applied_at     = excluded.applied_at,
                             suspended      = excluded.suspended,
                             revision       = excluded.revision",
                        rusqlite::params![
                            id,
                            schema_version,
                            manifest,
                            applied_at,
                            suspended,
                            revision
                        ],
                    )
                    .context("putting an app's record back")?;

                Ok(())
            })
            .await
    }

    /// Remember that the app named `id` is, or is no longer, suspended.
    ///
    /// Only the flag: the manifest and `applied_at` are left as they were,
    /// because suspending an app is not applying one. An operator who suspends
    /// and resumes should find the same record afterwards, still saying when
    /// they last applied it.
    ///
    /// Says whether there was a record to change, so suspending an app nothing
    /// was ever recorded for can be told from suspending one that was.
    pub async fn set_suspended(&self, id: &AppId, suspended: bool) -> Result<bool> {
        let id = id.to_string();

        self.db
            .call(move |connection| {
                let changed = connection
                    .execute(
                        "UPDATE apps SET suspended = ?2 WHERE id = ?1",
                        rusqlite::params![id, suspended],
                    )
                    .context("recording an app's suspension")?;

                Ok(changed > 0)
            })
            .await
    }

    /// Forget the app named `id` — it is no longer spaceport's to run.
    ///
    /// Says whether there was one, so a destroy can tell "stopped it" from
    /// "there was nothing recorded".
    pub async fn forget(&self, id: &AppId) -> Result<bool> {
        let id = id.to_string();

        self.db
            .call(move |connection| {
                let forgotten = connection
                    .execute("DELETE FROM apps WHERE id = ?1", [id])
                    .context("forgetting an app")?;

                Ok(forgotten > 0)
            })
            .await
    }

    /// The manifest recorded under `id`, if any.
    pub async fn recorded(&self, id: &AppId) -> Result<Option<AppRecord>> {
        let wanted = id.clone();
        let id = id.to_string();

        let row: Option<(i64, String, String, bool, Option<String>)> = self
            .db
            .call(move |connection| {
                connection
                    .query_row(
                        "SELECT schema_version, manifest, applied_at, suspended, revision
                         FROM apps WHERE id = ?1",
                        [id],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )
                    .optional()
                    .context("reading a recorded app")
            })
            .await?;

        Ok(row.map(
            |(schema_version, manifest, applied_at, suspended, revision)| AppRecord {
                id: wanted,
                schema_version: read(schema_version),
                manifest,
                applied_at,
                suspended,
                revision,
            },
        ))
    }

    /// Everything spaceport should be running, by id.
    ///
    /// Named for what these rows *are* — intent, not a listing of what happens
    /// to be up. What is actually running is [`crate::app::AppStore::apps`].
    ///
    /// A row whose id no longer parses is skipped with a warning rather than
    /// failing the read: one unreadable record must not cost every other app
    /// its restart.
    pub async fn desired(&self) -> Result<Vec<AppRecord>> {
        let rows: Vec<(String, i64, String, String, bool, Option<String>)> = self
            .db
            .call(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT id, schema_version, manifest, applied_at, suspended, revision
                         FROM apps ORDER BY id",
                    )
                    .context("preparing the desired-apps query")?;

                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    })
                    .context("reading the desired apps")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the desired apps")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(id, schema_version, manifest, applied_at, suspended, revision)| match id
                    .parse::<AppId>()
                {
                    Ok(id) => Some(AppRecord {
                        id,
                        schema_version: read(schema_version),
                        manifest,
                        applied_at,
                        suspended,
                        revision,
                    }),
                    Err(error) => {
                        warn!(app = id, %error, "skipping a recorded app whose id is not valid");
                        None
                    }
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> AppRepository {
        AppRepository::new(Db::in_memory().unwrap())
    }

    fn id(id: &str) -> AppId {
        id.parse().unwrap()
    }

    const MANIFEST: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
";

    #[tokio::test]
    async fn remembers_nothing_to_begin_with() {
        assert!(repository().desired().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn records_a_manifest_verbatim() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        let desired = repository.desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].id, id("hello"));
        // Byte for byte, comments and all — that is the whole point.
        assert_eq!(desired[0].manifest, MANIFEST);
        assert_eq!(desired[0].schema_version, SCHEMA_VERSION);
        assert!(desired[0].applied_at.ends_with('Z'), "{:?}", desired[0]);
    }

    #[tokio::test]
    async fn re_recording_replaces_the_manifest() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();
        let changed = MANIFEST.replace("alpha.test", "beta.test");
        repository
            .record_applied(&id("hello"), &changed, None, false)
            .await
            .unwrap();

        let desired = repository.desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].manifest, changed);
    }

    #[tokio::test]
    async fn forgets_an_app() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        assert!(repository.forget(&id("hello")).await.unwrap());
        assert!(repository.desired().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn forgetting_an_unknown_app_says_there_was_none() {
        assert!(!repository().forget(&id("ghost")).await.unwrap());
    }

    #[tokio::test]
    async fn reads_back_one_app() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        let record = repository.recorded(&id("hello")).await.unwrap().unwrap();
        assert_eq!(record.manifest, MANIFEST);
        assert!(repository.recorded(&id("ghost")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn lists_the_desired_apps_in_a_stable_order() {
        let repository = repository();
        for app in ["zulu", "alpha", "mike"] {
            repository
                .record_applied(&id(app), MANIFEST, None, false)
                .await
                .unwrap();
        }

        let ids: Vec<String> = repository
            .desired()
            .await
            .unwrap()
            .iter()
            .map(|record| record.id.to_string())
            .collect();
        assert_eq!(ids, ["alpha", "mike", "zulu"]);
    }

    #[tokio::test]
    async fn records_an_app_as_running_by_default() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        assert!(!repository.desired().await.unwrap()[0].suspended);
    }

    #[tokio::test]
    async fn records_an_app_that_was_applied_suspended() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, true)
            .await
            .unwrap();

        assert!(repository.desired().await.unwrap()[0].suspended);
        assert!(
            repository
                .recorded(&id("hello"))
                .await
                .unwrap()
                .unwrap()
                .suspended
        );
    }

    /// What a restart re-resolves: the commit, not the image its build was
    /// tagged with.
    #[tokio::test]
    async fn records_the_revision_an_app_was_deployed_from() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, Some("abc1234"), false)
            .await
            .unwrap();

        assert_eq!(
            repository.desired().await.unwrap()[0].revision.as_deref(),
            Some("abc1234")
        );
        assert_eq!(
            repository
                .recorded(&id("hello"))
                .await
                .unwrap()
                .unwrap()
                .revision
                .as_deref(),
            Some("abc1234")
        );
    }

    /// An operator who applies a manifest of their own over a deployed app has
    /// replaced it, and a revision from the deploy before would outlive the app
    /// it described.
    #[tokio::test]
    async fn re_recording_without_a_revision_forgets_the_one_before() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, Some("abc1234"), false)
            .await
            .unwrap();

        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        assert_eq!(repository.desired().await.unwrap()[0].revision, None);
    }

    #[tokio::test]
    async fn suspends_and_resumes_a_recorded_app() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();

        assert!(repository.set_suspended(&id("hello"), true).await.unwrap());
        assert!(repository.desired().await.unwrap()[0].suspended);

        assert!(repository.set_suspended(&id("hello"), false).await.unwrap());
        assert!(!repository.desired().await.unwrap()[0].suspended);
    }

    /// What a rollback is for: the record of a deployment that failed halfway
    /// through recording itself goes back to the app that is running again,
    /// down to the day it was applied.
    #[tokio::test]
    async fn puts_a_record_back_the_way_it_was() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, Some("abc1234"), false)
            .await
            .unwrap();
        let before = repository.recorded(&id("hello")).await.unwrap().unwrap();
        repository
            .record_applied(&id("hello"), "schema_version: 1\n", Some("def5678"), true)
            .await
            .unwrap();

        repository.put_back(&before).await.unwrap();

        assert_eq!(
            repository.recorded(&id("hello")).await.unwrap().unwrap(),
            before
        );
    }

    /// Suspending is not applying: the manifest and the day the operator
    /// applied it are still theirs, and come back unchanged.
    #[tokio::test]
    async fn suspending_leaves_the_manifest_and_applied_at_alone() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();
        let before = repository.recorded(&id("hello")).await.unwrap().unwrap();

        repository.set_suspended(&id("hello"), true).await.unwrap();

        let after = repository.recorded(&id("hello")).await.unwrap().unwrap();
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.applied_at, before.applied_at);
    }

    #[tokio::test]
    async fn suspending_an_unrecorded_app_says_there_was_none() {
        assert!(
            !repository()
                .set_suspended(&id("ghost"), true)
                .await
                .unwrap()
        );
    }

    /// A record written by some other tool, or by a future spaceport with
    /// looser ids, must not take the rest of the apps down with it.
    #[tokio::test]
    async fn skips_a_record_whose_id_is_not_valid() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST, None, false)
            .await
            .unwrap();
        repository
            .db
            .call(|connection| {
                connection
                    .execute(
                        "INSERT INTO apps (id, schema_version, manifest, applied_at)
                         VALUES ('Not An Id', 1, 'whatever', '2026-01-01T00:00:00Z')",
                        [],
                    )
                    .context("inserting a broken record")?;

                Ok(())
            })
            .await
            .unwrap();

        let desired = repository.desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].id, id("hello"));
    }
}
