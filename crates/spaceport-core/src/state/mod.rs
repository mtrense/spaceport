//! Where spaceport keeps what it must not forget.
//!
//! Only *desired* state lives here — what an operator asked for, in the words
//! they asked for it. What that turned into on this host at this moment is
//! observed state: a container id, the port the engine published it on. None of
//! that is written down, because a published port is stale the instant the
//! engine republishes it, and a restart that trusted the stale one would route
//! traffic into nothing. Observed state is rediscovered at startup instead.
//!
//! One SQLite database holds all of it. Not because a handful of apps needs a
//! database, but because sessions and certificates are coming and those do —
//! and migrating a directory of files into a database later is a worse day than
//! writing the first migration now.
//!
//! Nothing outside this module talks to a [`Connection`]. Callers go through a
//! repository — [`crate::app::AppRepository`] and, in time, its siblings —
//! whose methods are named after what the caller is doing rather than after
//! what SQL it takes, so a call site reads as the domain event it is.

pub mod lock;
pub mod migrations;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tracing::debug;

pub use lock::StateLock;

/// Path used when the config names no state directory.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/spaceport";

/// The database file inside the state directory.
const DATABASE_FILE: &str = "spaceport.db";

/// Only the owner may read the state: it holds the keys and secrets spaceport
/// runs on.
#[cfg(unix)]
const STATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const DATABASE_MODE: u32 = 0o600;

/// Spaceport's database.
///
/// Cheap to clone — every clone is the same connection. Writes are rare enough
/// (an apply, a certificate renewal) that one connection behind a mutex is not
/// worth improving on, and it sidesteps the "one writer at a time" rule SQLite
/// would otherwise enforce by returning `SQLITE_BUSY` to somebody.
#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open the database in `directory`, creating and migrating it if needed.
    ///
    /// The directory is created too. WAL writes `-wal` and `-shm` files beside
    /// the database, so what has to be writable is the directory, not just the
    /// file.
    pub fn open(directory: &Path) -> Result<Self> {
        create_directory(directory)?;

        let path = database_path(directory);
        let connection = Connection::open(&path)
            .with_context(|| format!("opening the state database `{}`", path.display()))?;
        restrict(&path)?;

        Self::prepare(connection)
            .with_context(|| format!("preparing the state database `{}`", path.display()))
    }

    /// An empty database that lives only as long as this handle.
    ///
    /// This is what tests use: the real schema and the real migrations, with
    /// nothing to clean up afterwards.
    pub fn in_memory() -> Result<Self> {
        let connection =
            Connection::open_in_memory().context("opening an in-memory state database")?;

        Self::prepare(connection).context("preparing an in-memory state database")
    }

    /// The path the state database would live at inside `directory`.
    pub fn path_in(directory: &Path) -> PathBuf {
        database_path(directory)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        configure(&connection)?;
        let version = migrations::migrate(&connection)?;
        debug!(schema_version = version, "state database ready");

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Which migration the database has been brought up to.
    pub async fn schema_version(&self) -> Result<u32> {
        self.call(|connection| migrations::schema_version(connection))
            .await
    }

    /// Run `query` against the connection, off the async runtime's worker.
    ///
    /// Repositories are async so that call sites survive this getting slower,
    /// but SQLite is a blocking library and blocking a worker thread would
    /// stall the edge along with it.
    pub(crate) async fn call<T, F>(&self, query: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let connection = self.connection.clone();

        tokio::task::spawn_blocking(move || {
            // A poisoned lock means a query panicked mid-statement. Nothing
            // here can repair that, and carrying on against a connection in an
            // unknown state would be worse than stopping.
            let mut connection = connection.lock().expect("state database lock poisoned");

            query(&mut connection)
        })
        .await
        .context("the state database task panicked")?
    }
}

impl std::fmt::Debug for Db {
    /// A connection has nothing worth printing, and printing it must not be
    /// what forces a lock.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

fn database_path(directory: &Path) -> PathBuf {
    directory.join(DATABASE_FILE)
}

/// How every connection is set up, before any statement runs against it.
fn configure(connection: &Connection) -> Result<()> {
    // WAL so a reader never blocks on the writer; `NORMAL` because losing the
    // last transaction to a power cut costs one re-apply, and `FULL` costs an
    // fsync on every write forever.
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .context("enabling write-ahead logging")?;
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .context("setting the synchronous mode")?;
    // Off by default in SQLite, and a schema whose foreign keys are decoration
    // is worse than one without them.
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .context("enabling foreign keys")?;
    // Should never be hit — one process, one connection — but waiting beats
    // failing if a second one ever does show up.
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .context("setting the busy timeout")?;

    Ok(())
}

/// Create the state directory, if it is not already there.
///
/// [`Db::open`] does this itself; it is public because the lock has to be taken
/// on a directory that exists, and the lock has to be taken before the database
/// is opened.
pub fn create_directory(directory: &Path) -> Result<()> {
    if directory.is_dir() {
        return Ok(());
    }

    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating the state directory `{}`", directory.display()))?;
    restrict_dir(directory)?;

    Ok(())
}

/// Take the mode down to owner-only. Only on creation: an operator who has
/// deliberately widened it has said something, and silently undoing it at every
/// start would be spaceport arguing.
#[cfg(unix)]
fn restrict_dir(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(STATE_DIR_MODE))
        .with_context(|| format!("restricting access to `{}`", directory.display()))
}

#[cfg(not(unix))]
fn restrict_dir(_directory: &Path) -> Result<()> {
    Ok(())
}

/// The database is owner-only, every time: unlike the directory, nothing an
/// operator does with it is worth preserving over that.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(DATABASE_MODE))
        .with_context(|| format!("restricting access to `{}`", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

/// The moment a record is written, as RFC 3339 — a format that sorts, and that
/// says which zone it means.
pub(crate) fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        // The only way this fails is a format description that cannot render a
        // valid timestamp, which `Rfc3339` is not.
        .unwrap_or_else(|_| String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_in_memory_database_is_migrated() {
        let db = Db::in_memory().unwrap();

        assert_eq!(
            db.schema_version().await.unwrap(),
            migrations::LATEST_VERSION
        );
    }

    #[tokio::test]
    async fn opening_creates_the_state_directory() {
        let directory = temp_dir("creates");
        let db = Db::open(&directory).unwrap();

        assert!(Db::path_in(&directory).is_file());
        assert_eq!(
            db.schema_version().await.unwrap(),
            migrations::LATEST_VERSION
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn keeps_the_state_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temp_dir("modes");
        Db::open(&directory).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), STATE_DIR_MODE);
        assert_eq!(mode(&Db::path_in(&directory)), DATABASE_MODE);

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Re-opening is the ordinary case — every restart does it — and it must
    /// not try to migrate a database that is already current.
    #[tokio::test]
    async fn re_opening_an_existing_database_works() {
        let directory = temp_dir("reopen");
        drop(Db::open(&directory).unwrap());

        let db = Db::open(&directory).unwrap();
        assert_eq!(
            db.schema_version().await.unwrap(),
            migrations::LATEST_VERSION
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn refuses_a_database_from_a_later_spaceport() {
        let directory = temp_dir("from-the-future");
        std::fs::create_dir_all(&directory).unwrap();
        {
            let connection = Connection::open(database_path(&directory)).unwrap();
            connection
                .pragma_update(None, "user_version", migrations::LATEST_VERSION + 1)
                .unwrap();
        }

        let err = format!("{:#}", Db::open(&directory).unwrap_err());
        assert!(err.contains("newer spaceport"), "{err}");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// `2026-08-13T09:41:00.123456789Z` — UTC, and sorting as a string is
    /// sorting by time, which is what makes this worth storing as text.
    #[test]
    fn timestamps_are_rfc_3339_in_utc() {
        let stamped = now();

        assert!(stamped.ends_with('Z'), "{stamped}");
        assert_eq!(stamped.as_bytes()[4], b'-', "{stamped}");
        assert_eq!(stamped.as_bytes()[10], b'T', "{stamped}");
        assert!(stamped.len() >= 20, "{stamped}");
    }

    /// A directory of this test run's own, under the system temp dir.
    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("spaceport-test-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&directory);

        directory
    }
}
