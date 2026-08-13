//! Bringing a database up to the schema this build expects.
//!
//! One ordered, forward-only list, for every domain at once. There is one
//! `user_version` per database, so per-domain migration lists would be a
//! fiction the moment a certificate row referenced an app — and they will.
//!
//! Migrations are append-only: to change the schema, add a step, never edit one
//! that has shipped. A database whose version is *higher* than this build knows
//! about is refused rather than guessed at, the same rule config files and app
//! manifests follow.

use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use tracing::info;

/// Every schema step, in order. The database's `user_version` is the number of
/// these that have been applied.
const MIGRATIONS: &[&str] = &[
    // 1 — the apps an operator has asked spaceport to run.
    "CREATE TABLE apps (
        id             TEXT    PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        manifest       TEXT    NOT NULL,
        applied_at     TEXT    NOT NULL
    ) STRICT;",
];

/// The schema version this build writes.
pub const LATEST_VERSION: u32 = MIGRATIONS.len() as u32;

/// Bring `connection` up to [`LATEST_VERSION`], returning where it ended up.
pub fn migrate(connection: &Connection) -> Result<u32> {
    let current = schema_version(connection)?;

    if current > LATEST_VERSION {
        bail!(
            "the state database is at schema version {current}, which only a newer spaceport \
             understands — this one writes {LATEST_VERSION}"
        );
    }
    if current == LATEST_VERSION {
        return Ok(current);
    }

    for (index, migration) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let version = index as u32 + 1;

        // Each step commits with the version it produced, so an interrupted
        // run leaves the database at a version that was actually reached
        // rather than one that was half applied.
        connection
            .execute_batch(&format!(
                "BEGIN;\n{migration}\nPRAGMA user_version = {version};\nCOMMIT;"
            ))
            .with_context(|| format!("applying state schema migration {version}"))?;

        info!(version, "migrated the state database");
    }

    schema_version(connection)
}

/// How far this database has been migrated.
pub fn schema_version(connection: &Connection) -> Result<u32> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .context("reading the state schema version")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn migrates_a_fresh_database_to_the_latest_version() {
        let connection = empty();

        assert_eq!(migrate(&connection).unwrap(), LATEST_VERSION);
        assert_eq!(schema_version(&connection).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn migrating_twice_changes_nothing() {
        let connection = empty();
        migrate(&connection).unwrap();

        // The second run must not re-run a `CREATE TABLE` that would now fail.
        assert_eq!(migrate(&connection).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn refuses_a_database_from_a_later_build() {
        let connection = empty();
        connection
            .pragma_update(None, "user_version", LATEST_VERSION + 1)
            .unwrap();

        let err = migrate(&connection).unwrap_err().to_string();
        assert!(err.contains("newer spaceport"), "{err}");
    }

    #[test]
    fn the_first_migration_creates_the_apps_table() {
        let connection = empty();
        migrate(&connection).unwrap();

        let columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('apps') ORDER BY cid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        assert_eq!(columns, ["id", "schema_version", "manifest", "applied_at"]);
    }
}
