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
    // 2 — what an ACME CA has issued, and the account it was issued to.
    //
    // Accounts are keyed by directory URL, so moving a setup from staging to
    // production registers a new account rather than presenting a staging key
    // to a CA that has never heard of it — and moving back finds the old one
    // still there.
    //
    // Certificates are keyed by host, one order per host: a host that fails
    // its challenge then costs its own certificate rather than everybody's.
    //
    // There is no expiry column. When a certificate expires is written inside
    // the certificate, and a column saying so could only ever be a second
    // answer to a question that already has one.
    "CREATE TABLE acme_accounts (
        directory   TEXT PRIMARY KEY,
        credentials TEXT NOT NULL,
        created_at  TEXT NOT NULL
    ) STRICT;
    CREATE TABLE certificates (
        host        TEXT PRIMARY KEY,
        chain       TEXT NOT NULL,
        private_key TEXT NOT NULL,
        issued_at   TEXT NOT NULL
    ) STRICT;",
    // 3 — whether an app is suspended: recorded, still claiming its hosts, but
    // deliberately not served.
    //
    // A column on `apps` rather than a state machine, because that is what it
    // is: an app is one manifest under one id either way, and suspension says
    // only whether spaceport should be running it right now. Defaulting to 0
    // makes every app an older build recorded a running one, which is what it
    // was.
    //
    // Nothing here says whether the *container* was stopped. That is the
    // engine's to answer, and asking it is the only way to get an answer that
    // is still true after somebody used `docker` by hand.
    "ALTER TABLE apps ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0;",
    // 4 — the GitHub Apps a spaceport has registered for itself, and what it
    // has since learned about where they are installed.
    //
    // A connection is keyed by slug because that is the name an operator reads
    // on GitHub and types on the command line. `app_id` is unique as well,
    // because it is what a webhook header carries and what an installation
    // token is minted against — both are legitimate ways in, so both are
    // indexed rather than one being derived from the other at read time.
    //
    // The four secrets sit in plain columns, exactly as `acme_accounts`
    // .credentials does: the protection is a `0700` directory and a `0600`
    // file. Encrypting them here would only move the question to where the
    // key that decrypts them lives, and on a single host that key would end up
    // in the same directory.
    //
    // Installations and repositories are a cache of what GitHub says, not a
    // record of what an operator wants. Reconciliation discovers them,
    // refreshes them and drops them, and losing the lot costs exactly one
    // pass. They are written down anyway so that a spaceport which has just
    // restarted does not look like one that has never heard of anything.
    //
    // There is deliberately no foreign key from `github_installations.app_id`
    // to `github_apps.app_id`. Forgetting a connection deletes its rows
    // explicitly, which is the honest place for that knowledge, and a
    // constraint would turn a reconciliation interrupted half way into a
    // failed one rather than a stale one.
    //
    // `github_deliveries` exists for one purpose: a delivery GitHub sends
    // twice must be acted on once. Rows are pruned by age, so it is a window
    // on recent deliveries rather than a log of every one.
    "CREATE TABLE github_apps (
        slug           TEXT    PRIMARY KEY,
        app_id         INTEGER NOT NULL UNIQUE,
        name           TEXT    NOT NULL,
        owner          TEXT    NOT NULL,
        client_id      TEXT    NOT NULL,
        client_secret  TEXT    NOT NULL,
        webhook_secret TEXT    NOT NULL,
        private_key    TEXT    NOT NULL,
        connected_at   TEXT    NOT NULL
    ) STRICT;
    CREATE TABLE github_installations (
        app_id          INTEGER NOT NULL,
        installation_id INTEGER NOT NULL,
        account         TEXT    NOT NULL,
        account_type    TEXT    NOT NULL,
        seen_at         TEXT    NOT NULL,
        PRIMARY KEY (app_id, installation_id)
    ) STRICT;
    CREATE TABLE github_repositories (
        app_id          INTEGER NOT NULL,
        installation_id INTEGER NOT NULL,
        full_name       TEXT    NOT NULL,
        seen_at         TEXT    NOT NULL,
        PRIMARY KEY (app_id, installation_id, full_name)
    ) STRICT;
    CREATE TABLE github_deliveries (
        delivery_id TEXT    PRIMARY KEY,
        app_id      INTEGER NOT NULL,
        event       TEXT    NOT NULL,
        received_at TEXT    NOT NULL
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

    /// The columns of `table`, in declaration order.
    fn columns(connection: &Connection, table: &str) -> Vec<String> {
        connection
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
            ))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn the_first_migration_creates_the_apps_table() {
        let connection = empty();
        migrate(&connection).unwrap();

        assert_eq!(
            columns(&connection, "apps"),
            [
                "id",
                "schema_version",
                "manifest",
                "applied_at",
                "suspended"
            ]
        );
    }

    #[test]
    fn the_second_migration_creates_the_certificate_tables() {
        let connection = empty();
        migrate(&connection).unwrap();

        assert_eq!(
            columns(&connection, "acme_accounts"),
            ["directory", "credentials", "created_at"]
        );
        assert_eq!(
            columns(&connection, "certificates"),
            ["host", "chain", "private_key", "issued_at"]
        );
    }

    #[test]
    fn the_fourth_migration_creates_the_connection_tables() {
        let connection = empty();
        migrate(&connection).unwrap();

        assert_eq!(
            columns(&connection, "github_apps"),
            [
                "slug",
                "app_id",
                "name",
                "owner",
                "client_id",
                "client_secret",
                "webhook_secret",
                "private_key",
                "connected_at"
            ]
        );
        assert_eq!(
            columns(&connection, "github_installations"),
            [
                "app_id",
                "installation_id",
                "account",
                "account_type",
                "seen_at"
            ]
        );
        assert_eq!(
            columns(&connection, "github_repositories"),
            ["app_id", "installation_id", "full_name", "seen_at"]
        );
        assert_eq!(
            columns(&connection, "github_deliveries"),
            ["delivery_id", "app_id", "event", "received_at"]
        );
    }

    /// A database written by the previous build has only the apps table, and
    /// must gain the rest without losing what is in it.
    #[test]
    fn migrates_a_database_that_stopped_at_the_first_step() {
        let connection = empty();
        connection.execute_batch(MIGRATIONS[0]).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        connection
            .execute(
                "INSERT INTO apps VALUES ('hello', 1, 'schema_version: 1', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

        assert_eq!(migrate(&connection).unwrap(), LATEST_VERSION);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM apps", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(!columns(&connection, "certificates").is_empty());
        // An app recorded before suspension existed was a running one.
        assert_eq!(
            connection
                .query_row("SELECT suspended FROM apps WHERE id = 'hello'", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}
