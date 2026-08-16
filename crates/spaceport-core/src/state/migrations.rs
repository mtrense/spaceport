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
    // 5 — which repository an app is built from, and which commit of it was
    // last accepted.
    //
    // Two id-spaces meet in this one table and they are deliberately spelled
    // apart. Everywhere else under `github_*`, `app_id` means GitHub's numeric
    // App id; spaceport's own `AppId` is a text name an operator chose. Here
    // they would sit side by side as two columns called `app_id`, and the first
    // person to write a join would get a query that runs, returns nothing, and
    // looks correct. `spaceport_app` and `github_app_id` cannot be confused for
    // one another, and a `TEXT` column beside an `INTEGER` one will not compare
    // equal under `STRICT` even if somebody tries.
    //
    // The primary key is the spaceport app, so an app tracks at most one
    // repository and re-tracking is a `PUT` — the same shape as `apps`, where
    // the id an operator chose is the whole identity of the thing. The
    // converse is not constrained: many apps may be built from one repository,
    // a monorepo with a manifest per app being the ordinary case.
    //
    // `github_tracking_by_push` is the index a delivery reads. A push names an
    // App, a repository and a ref, and the question it asks is "which apps does
    // that move?" — so the index is on exactly those three columns, in that
    // order, and the App id comes first because it is what a delivery has
    // already been verified against.
    //
    // No foreign keys, for the reason step 4 gives: forgetting a connection
    // deletes these rows explicitly, and a constraint would make writing a
    // tracking row depend on a connection row that a concurrent disconnect may
    // have taken.
    //
    // `revision` is nullable because an app can be pointed at a branch before
    // anything has ever been built from it, and "no commit has been accepted
    // yet" is a different answer from "the commit is the empty string".
    "CREATE TABLE github_tracking (
        spaceport_app    TEXT    PRIMARY KEY,
        github_app_id    INTEGER NOT NULL,
        repository       TEXT    NOT NULL,
        branch           TEXT    NOT NULL,
        manifest_path    TEXT    NOT NULL,
        tracked_at       TEXT    NOT NULL,
        revision         TEXT,
        revision_seen_at TEXT
    ) STRICT;
    CREATE INDEX github_tracking_by_push ON github_tracking (github_app_id, repository, branch);",
    // 6 — the attempt to turn a revision into an image, and how it went.
    //
    // A tracking says where an app comes from and which commit was last
    // accepted; this is what happened when spaceport tried to build that
    // commit. It is written down rather than kept in the worker so that a build
    // is not done twice, so a failure has somewhere to say why, and so a
    // process that restarts can tell what it was in the middle of.
    //
    // The key is `(spaceport_app, revision)` and not a synthetic id, because
    // that pair *is* the identity of the work: one app builds one commit once,
    // and the image that comes out is the image for that commit. Asking for the
    // same revision again — a webhook GitHub sent twice, a reconciliation that
    // noticed the same head, an operator retrying — must land on the row that
    // already exists rather than pile a second attempt on top of it, and with
    // this key the insert is the check. A synthetic id would make every request
    // a new row and push the question "have we already built this?" into a
    // query that somebody has to remember to write.
    //
    // `state` is a text column and not a foreign key into a table of states,
    // for the reason `github_installations.account_type` keeps GitHub's own
    // word: a row must stay readable when the word in it is one this build has
    // never heard of. A database written by a newer spaceport, or by one whose
    // states were spelled differently, then still reads back as a row, and the
    // one function that maps rows is where the unknown word is met and named —
    // rather than a join that quietly returns nothing and a build that has
    // vanished from an operator's listing with nobody able to say why.
    //
    // `log` holds the tail of the build output, and is truncated by the writer
    // before it ever reaches this table. Storing the whole thing and cutting it
    // down in the query would mean the megabyte a noisy compiler printed is
    // already in the database, already in every backup and already in the page
    // cache of every read — the cheap place to lose it is the only place that
    // ever had it whole. `reason` is separate and short, because what an
    // operator needs first is one sentence, not the last hundred lines.
    //
    // `spaceport_app` is spaceport's own `AppId`, the name an operator chose,
    // and matches `github_tracking.spaceport_app` exactly. The neighbouring
    // tables spell GitHub's numeric App id `github_app_id`; the two are
    // different id-spaces and are kept spelled apart here for the same reason
    // step 5 gives. `connection` is the slug the revision was fetched through,
    // kept so that forgetting a connection can take its builds with it without
    // a join back through the tracking that forgetting has already deleted.
    //
    // No foreign keys, for the reason step 4 gives: the destroy and
    // connection-forget cascades are written by hand, and a constraint would
    // turn a build racing a disconnect into a failed write rather than a stale
    // row.
    //
    // `app_builds_by_state` is the index the worker reads: "the oldest thing
    // still pending" is a lookup on state and then on time, in that order. It
    // also serves the startup pass that looks for rows left `building` by a
    // process that died.
    "CREATE TABLE app_builds (
        spaceport_app TEXT    NOT NULL,
        revision      TEXT    NOT NULL,
        connection    TEXT    NOT NULL,
        repository    TEXT    NOT NULL,
        branch        TEXT    NOT NULL,
        manifest_path TEXT    NOT NULL,
        state         TEXT    NOT NULL,
        image_tag     TEXT,
        image_id      TEXT,
        reason        TEXT,
        log           TEXT,
        started_at    TEXT    NOT NULL,
        finished_at   TEXT,
        PRIMARY KEY (spaceport_app, revision)
    ) STRICT;
    CREATE INDEX app_builds_by_state ON app_builds (state, started_at);",
    // 7 — the manifest a build was made from, and the revision an app is
    // actually running.
    //
    // `app_builds.manifest` is the document as it was read out of the commit,
    // byte for byte, and not a re-serialisation of what parsing made of it. The
    // unpacked tree is swept once a few newer revisions exist, so the commit's
    // own copy is gone from this host long before an operator asks what it said;
    // and a re-serialisation would answer with this build's idea of the schema
    // rather than with what somebody wrote. Nullable, because a row written by
    // an earlier spaceport has none, and a build that failed before it got as
    // far as reading the manifest never had one.
    //
    // `apps.revision` is the deployed one — the revision whose build produced
    // the image the stored manifest is running. It is recorded rather than
    // re-derived, and that is the whole point of the column. Re-deriving it
    // would mean asking "which is the newest built revision of this app?" at
    // every restart, and answering that question a week later gives a different
    // revision from the one the operator deployed: a spaceport that restarted
    // overnight would come back running a commit nobody asked for, because
    // somebody merged in the meantime. What an operator deployed is a decision,
    // not a derivation, and a decision has to be written down to survive. NULL
    // means no build is involved at all — the manifest names its own image, and
    // there is no revision to remember.
    "ALTER TABLE app_builds ADD COLUMN manifest TEXT;
    ALTER TABLE apps ADD COLUMN revision TEXT;",
    // 8 — whether a successful build deploys itself, and what came of it when
    // one did.
    //
    // `github_tracking.automatic` is the switch, per tracking and off by
    // default, spelled exactly as `apps.suspended` is: an `INTEGER NOT NULL
    // DEFAULT`, because a boolean in this schema is a column with two values
    // and not a second table to join. Defaulting to 0 makes every tracking an
    // older build recorded one that deploys nothing, which is what it was —
    // and, unlike suspension, it is the answer an operator who has never asked
    // for automatic deployment would want anyway. It sits on the tracking and
    // not on `apps` because it is a property of where an app comes from: an app
    // that is built from nowhere has no build that could deploy itself, and a
    // column on `apps` would be that absence spelled the long way.
    //
    // The two columns on `app_builds` are the outcome of deploying a revision,
    // and they are on the build row because `(spaceport_app, revision)` is
    // already the key that outcome wants — the deployment of a revision is one
    // thing that happens at most once, exactly as the build of it is. A table
    // of its own would repeat that key and buy nothing; a column on `apps`
    // could only hold the last one and would forget which revision it was about
    // the moment the next commit arrived.
    //
    // Two columns and not three. `deployed_at` NULL means no automatic deploy
    // has concluded for this revision, which is what every row written before
    // this step says and what a freshly built one says. Non-NULL with
    // `deploy_reason` NULL is a deployment that worked; non-NULL with a reason
    // is one that did not, and the reason is why. That answers both halves of
    // "has this revision been deployed, and did it work?" without a state word
    // to parse, and it is what stops the worker attempting a doomed revision
    // every pass and taking the app down each time: a revision whose deployment
    // failed is written down as failed for ever, and the retry is the next
    // commit. A third column naming the revision would restate the key, and a
    // fourth naming a state would be a second answer to a question the two
    // NULLs already answer exactly once.
    //
    // `deploy_reason` is separate from `reason`, which is why the *build*
    // failed. A build that produced an image and a deployment that then refused
    // it are different sentences about the same revision, and one column would
    // make the second overwrite the first — leaving an operator reading `built`
    // beside a reason about a port collision.
    "ALTER TABLE github_tracking ADD COLUMN automatic INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE app_builds ADD COLUMN deployed_at TEXT;
    ALTER TABLE app_builds ADD COLUMN deploy_reason TEXT;",
    // 9 — the secrets an operator has set for an app, which its manifest names
    // but never contains.
    //
    // Keyed by `(spaceport_app, name)`, because that pair is the identity of a
    // secret: an app has one value for `DATABASE_URL`, and setting it again
    // replaces the one that was there. `spaceport_app` is spaceport's own
    // `AppId` and is spelled as step 5 spells it, so that nothing here can be
    // confused with GitHub's numeric app id in the neighbouring tables.
    //
    // `value` is a plain column, exactly as `github_apps.client_secret` and
    // `acme_accounts.credentials` are: the protection is a `0700` directory and
    // a `0600` file. Encrypting it here would only move the question to where
    // the key that decrypts it lives, and on a single host that key would end
    // up in the same directory.
    //
    // `version` is what makes a container notice. A container's spec is
    // fingerprinted to decide whether it has to be recreated, and the
    // fingerprint must change when a secret's value changes — but putting the
    // value, or a hash of it, into that fingerprint would mean the plaintext,
    // or something an attacker can test guesses against, ends up in a container
    // label that every `docker inspect` prints. A counter says "this is a
    // different value from the one before" and says nothing else about it,
    // which is the entire question the fingerprint has to answer. It starts at
    // 1 so that a row which exists has a version, and only a write that
    // actually changes the value moves it: setting a secret to what it already
    // was must not restart the app.
    //
    // `app_secret_versions` is where that counter is actually kept, one row per
    // app, and it exists because the counter cannot live in the rows it numbers:
    // deleting a secret takes its row away, and a counter derived from what is
    // left would hand the next value a number a container is already labelled
    // with — which is a container running the credential that was rotated away,
    // matching the app's spec and being adopted. It holds a number and an app
    // id and never a value, so the destroy cascade leaves it alone: what it
    // remembers is how many values an app has had, which is the one thing that
    // must survive the values themselves.
    //
    // No foreign key to `apps(id)`, for the reason step 4 gives and one more.
    // None of the per-app tables — `github_tracking`, `app_builds` — declares
    // one, the destroy cascade is written by hand where the knowledge belongs,
    // and a constraint would make setting a secret depend on the app already
    // having been applied. Setting the secrets first and then applying the
    // manifest that reads them is the ordinary way round, and the schema should
    // not forbid it.
    "CREATE TABLE app_secrets (
        spaceport_app TEXT    NOT NULL,
        name          TEXT    NOT NULL,
        value         TEXT    NOT NULL,
        version       INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (spaceport_app, name)
    ) STRICT;
    CREATE TABLE app_secret_versions (
        spaceport_app TEXT    NOT NULL PRIMARY KEY,
        latest        INTEGER NOT NULL
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
                "suspended",
                "revision"
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

    #[test]
    fn the_fifth_migration_creates_the_tracking_table() {
        let connection = empty();
        migrate(&connection).unwrap();

        assert_eq!(
            columns(&connection, "github_tracking"),
            [
                "spaceport_app",
                "github_app_id",
                "repository",
                "branch",
                "manifest_path",
                "tracked_at",
                "revision",
                "revision_seen_at",
                "automatic"
            ]
        );
    }

    #[test]
    fn the_sixth_migration_creates_the_builds_table() {
        let connection = empty();
        migrate(&connection).unwrap();

        assert_eq!(
            columns(&connection, "app_builds"),
            [
                "spaceport_app",
                "revision",
                "connection",
                "repository",
                "branch",
                "manifest_path",
                "state",
                "image_tag",
                "image_id",
                "reason",
                "log",
                "started_at",
                "finished_at",
                "manifest",
                "deployed_at",
                "deploy_reason"
            ]
        );
    }

    /// What the deployed revision is for: a restart re-resolves the revision an
    /// operator deployed, and a row from before the column says "no build is
    /// involved" rather than pointing at whatever has been built since.
    #[test]
    fn the_seventh_migration_records_the_manifest_and_the_deployed_revision() {
        let connection = empty();
        migrate(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO apps (id, schema_version, manifest, applied_at)
                 VALUES ('hello', 1, 'schema_version: 1', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

        assert_eq!(
            connection
                .query_row("SELECT revision FROM apps WHERE id = 'hello'", [], |row| {
                    row.get::<_, Option<String>>(0)
                })
                .unwrap(),
            None
        );
    }

    /// Nothing an earlier spaceport recorded asked to be deployed
    /// automatically, and nothing it built has been deployed by anything.
    #[test]
    fn the_eighth_migration_arms_nothing_and_deploys_nothing() {
        let connection = empty();
        migrate(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO github_tracking
                     (spaceport_app, github_app_id, repository, branch, manifest_path, tracked_at)
                 VALUES ('hello', 42, 'an-organisation/site', 'main', 'spaceport.yaml',
                         '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO app_builds
                     (spaceport_app, revision, connection, repository, branch, manifest_path,
                      state, started_at)
                 VALUES ('hello', 'abc', 'spaceport', 'an-organisation/site', 'main',
                         'spaceport.yaml', 'built', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

        assert_eq!(
            connection
                .query_row(
                    "SELECT automatic FROM github_tracking WHERE spaceport_app = 'hello'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT deployed_at, deploy_reason FROM app_builds WHERE revision = 'abc'",
                    [],
                    |row| Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?
                    ))
                )
                .unwrap(),
            (None, None)
        );
    }

    /// A secret that has just been set is at version 1, so that the fingerprint
    /// of a container reading it has something to change away from.
    #[test]
    fn the_ninth_migration_starts_a_secret_at_version_one() {
        let connection = empty();
        migrate(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO app_secrets (spaceport_app, name, value)
                 VALUES ('hello', 'DATABASE_URL', 'postgres://localhost')",
                [],
            )
            .unwrap();

        assert_eq!(
            columns(&connection, "app_secrets"),
            ["spaceport_app", "name", "value", "version"]
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT version FROM app_secrets WHERE spaceport_app = 'hello'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
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
