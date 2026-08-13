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

    /// Remember that `manifest` is what the app named `id` should be running.
    ///
    /// Replaces whatever was recorded under that id — an apply is a `PUT`, and
    /// so is this.
    pub async fn record_applied(&self, id: &AppId, manifest: &str) -> Result<()> {
        let id = id.to_string();
        let manifest = manifest.to_owned();
        let applied_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO apps (id, schema_version, manifest, applied_at)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(id) DO UPDATE SET
                             schema_version = excluded.schema_version,
                             manifest       = excluded.manifest,
                             applied_at     = excluded.applied_at",
                        rusqlite::params![id, stored(SCHEMA_VERSION), manifest, applied_at],
                    )
                    .context("recording an applied app")?;

                Ok(())
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

        let row: Option<(i64, String, String)> = self
            .db
            .call(move |connection| {
                connection
                    .query_row(
                        "SELECT schema_version, manifest, applied_at FROM apps WHERE id = ?1",
                        [id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .context("reading a recorded app")
            })
            .await?;

        Ok(row.map(|(schema_version, manifest, applied_at)| AppRecord {
            id: wanted,
            schema_version: read(schema_version),
            manifest,
            applied_at,
        }))
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
        let rows: Vec<(String, i64, String, String)> = self
            .db
            .call(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT id, schema_version, manifest, applied_at FROM apps ORDER BY id",
                    )
                    .context("preparing the desired-apps query")?;

                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
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
                |(id, schema_version, manifest, applied_at)| match id.parse::<AppId>() {
                    Ok(id) => Some(AppRecord {
                        id,
                        schema_version: read(schema_version),
                        manifest,
                        applied_at,
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
            .record_applied(&id("hello"), MANIFEST)
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
            .record_applied(&id("hello"), MANIFEST)
            .await
            .unwrap();
        let changed = MANIFEST.replace("alpha.test", "beta.test");
        repository
            .record_applied(&id("hello"), &changed)
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
            .record_applied(&id("hello"), MANIFEST)
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
            .record_applied(&id("hello"), MANIFEST)
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
            repository.record_applied(&id(app), MANIFEST).await.unwrap();
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

    /// A record written by some other tool, or by a future spaceport with
    /// looser ids, must not take the rest of the apps down with it.
    #[tokio::test]
    async fn skips_a_record_whose_id_is_not_valid() {
        let repository = repository();
        repository
            .record_applied(&id("hello"), MANIFEST)
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
