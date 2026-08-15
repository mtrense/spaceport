//! What a spaceport remembers about the builds it has been asked for.
//!
//! A tracking says an app is built from a branch, and a push says which commit
//! that branch moved to. A [`Build`] is the next sentence: spaceport was asked
//! to turn *that* commit into an image, and here is how far it got. Three
//! things want that written down rather than held in the worker. A revision
//! asked for twice must be built once, so the request has to be able to find an
//! earlier one. A build that failed has to be able to tell an operator why,
//! minutes or days later, from a machine that has since restarted. And a
//! process that died half way through a build left work behind that nothing in
//! memory can know about — only a row saying `building` with nobody building it
//! can say so, which is why the state of a build lives in the database and not
//! in the worker that runs it.
//!
//! The queue is this table. There is no separate one: a `pending` row *is* a
//! request, a `building` row is a claim on it, and the terminal states are the
//! answer. That is what makes [`BuildRepository::request`] idempotent for free
//! — the primary key `(app, revision)` refuses a second row for work already
//! recorded — and it means the queue survives a restart without anything having
//! to be replayed into it.
//!
//! Nothing here builds anything. Fetching a commit, unpacking it and asking the
//! engine for an image live in this module's siblings; this one only writes
//! down what they were asked to do and what came back, so that the code which
//! talks to GitHub and Docker can be tested without a database and this can be
//! tested without either.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use rusqlite::OptionalExtension;

use crate::app::AppId;
use crate::state::Db;

/// How much of a build's output is kept.
///
/// Builds print as much as they like — a compiler with warnings on, a package
/// manager resolving a lock file — and none of that belongs in a file that is
/// backed up whole and read into memory a row at a time. The cut is made on the
/// way in rather than in the query, because a megabyte that reaches the table
/// is a megabyte in every backup from then on; the only place it can be lost
/// cheaply is the one place that ever had it whole.
///
/// Sixteen kilobytes is a few hundred lines: enough to hold the failing step
/// and what led to it, which is what an operator reads.
const LOG_LIMIT: usize = 16 * 1024;

/// What replaces the output that was dropped, so a reader can see that some
/// was.
const LOG_ELISION: &str = "[…earlier output dropped…]\n";

/// How far a build has got.
///
/// Stored as the word itself, not an index: a number would have to mean the
/// same thing in every build of spaceport for ever, and the state of a build is
/// read far more often by a person than by a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildState {
    /// Asked for, and waiting for a worker.
    Pending,
    /// Claimed by a worker, which may or may not still be alive.
    Building,
    /// An image exists for this revision.
    Built,
    /// It will not be built without something changing; `reason` says what.
    Failed,
}

impl fmt::Display for BuildState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Building => "building",
            Self::Built => "built",
            Self::Failed => "failed",
        })
    }
}

/// The other half of [`fmt::Display`], and the only place a stored word becomes
/// a state.
///
/// A word this build does not know is an error naming the word, rather than a
/// silently substituted default. The column is text precisely so that such a
/// row survives being written by another build — and the point of surviving is
/// that somebody can be told what it says, not that it can be guessed at.
impl FromStr for BuildState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "pending" => Self::Pending,
            "building" => Self::Building,
            "built" => Self::Built,
            "failed" => Self::Failed,
            other => bail!("`{other}` is not a build state this spaceport understands"),
        })
    }
}

/// One attempt to turn a revision of an app's repository into an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// Spaceport's own id for the app — the name an operator chose, not
    /// anything GitHub knows.
    pub app: AppId,
    /// The commit sha the image is built from.
    pub revision: String,
    /// The slug of the connection the revision is fetched through. Kept on the
    /// build itself so that forgetting a connection can take its builds with it
    /// without joining back through a tracking that the same disconnect has
    /// already deleted.
    pub connection: String,
    /// `owner/name`, exactly as GitHub spells a full name.
    pub repository: String,
    pub branch: String,
    /// Where in the repository the app's manifest is, as a path from its root.
    pub manifest_path: String,
    pub state: BuildState,
    /// What the image was tagged, once there is one.
    pub image_tag: Option<String>,
    /// The engine's own id for the image — the thing that is still true after
    /// somebody moved the tag.
    pub image_id: Option<String>,
    /// Why it failed, in one sentence, for an operator to read.
    pub reason: Option<String>,
    /// The tail of the build output, truncated to [`LOG_LIMIT`] on the way in.
    pub log: Option<String>,
    /// When the build was asked for, RFC 3339. The moment the queue orders by,
    /// which is why it is the request that stamps it and not the claim.
    pub started_at: String,
    /// When it reached a terminal state, RFC 3339.
    pub finished_at: Option<String>,
}

/// The columns of `app_builds`, in the order [`build_from`] reads them.
///
/// Written once so the `SELECT`s and the row mapping cannot drift apart.
const BUILD_COLUMNS: &str = "spaceport_app, revision, connection, repository, branch, \
                             manifest_path, state, image_tag, image_id, reason, log, \
                             started_at, finished_at";

/// The builds table, in the vocabulary of requesting, claiming and finishing.
#[derive(Debug, Clone)]
pub struct BuildRepository {
    db: Db,
}

impl BuildRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Record that `build` is wanted, and say whether that is news.
    ///
    /// The return value *is* the deduplication answer: `true` means nothing had
    /// asked for this revision of this app and a worker will get to it, `false`
    /// means it is already recorded — pending, being built, or long since built
    /// or failed — and the caller should do nothing. Because the insert and the
    /// check are one statement, two pushes racing each other cannot both be
    /// told they are first, exactly as a GitHub delivery is deduplicated.
    ///
    /// The row is always written as [`BuildState::Pending`]: the state on the
    /// struct describes a build that has been read back, never one that is
    /// being asked for. `started_at` is stamped here rather than taken from the
    /// struct, so the queue is ordered by when the request actually arrived.
    pub async fn request(&self, build: &Build) -> Result<bool> {
        let app = build.app.to_string();
        let revision = build.revision.clone();
        let slug = build.connection.clone();
        let repository = build.repository.clone();
        let branch = build.branch.clone();
        let manifest_path = build.manifest_path.clone();
        let started_at = crate::state::now();

        self.db
            .call(move |connection| {
                let inserted = connection
                    .execute(
                        "INSERT INTO app_builds (
                             spaceport_app, revision, connection, repository, branch,
                             manifest_path, state, image_tag, image_id, reason, log,
                             started_at, finished_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, NULL, NULL, ?7, NULL)
                         ON CONFLICT(spaceport_app, revision) DO NOTHING",
                        rusqlite::params![
                            app,
                            revision,
                            slug,
                            repository,
                            branch,
                            manifest_path,
                            started_at
                        ],
                    )
                    .context("recording a wanted build")?;

                Ok(inserted > 0)
            })
            .await
    }

    /// Take the oldest pending build, mark it as being built, and return it.
    ///
    /// One statement does both, and `RETURNING` gives back the row it moved, so
    /// there is no window between choosing a build and claiming it in which
    /// somebody else could choose the same one. SQLite completes the whole
    /// modification before it yields the first returned row, so the row this
    /// call returns is a row it has already taken — a second caller reaching
    /// the same statement finds it no longer `pending` and picks the next one.
    /// A transaction around a `SELECT` and an `UPDATE` would achieve the same
    /// thing and is what this would have to be on an engine without
    /// `RETURNING`; it is not needed here.
    ///
    /// Only one worker runs today, so none of that is load-bearing yet. It is
    /// written this way because the alternative — a claim that is only safe
    /// while there is exactly one caller — is the kind of assumption that is
    /// invisible until the day a second worker exists and two hosts build the
    /// same commit.
    pub async fn claim(&self) -> Result<Option<Build>> {
        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "UPDATE app_builds SET state = 'building'
                             WHERE rowid = (
                                 SELECT rowid FROM app_builds
                                 WHERE state = 'pending'
                                 ORDER BY started_at, revision
                                 LIMIT 1
                             )
                             RETURNING {BUILD_COLUMNS}"
                        ),
                        [],
                        build_from,
                    )
                    .optional()
                    .context("claiming the next pending build")
            })
            .await
    }

    /// Write down that the build of `revision` produced an image.
    ///
    /// Terminal: `finished_at` is stamped here, and nothing moves the row
    /// afterwards. The tag and the id are both kept because they answer
    /// different questions — the tag is what a container is asked to run, the
    /// id is what is still true after somebody has moved the tag.
    pub async fn succeeded(
        &self,
        app: &AppId,
        revision: &str,
        image_tag: &str,
        image_id: &str,
        log: &str,
    ) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let image_tag = image_tag.to_owned();
        let image_id = image_id.to_owned();
        let log = tail(log);
        let finished_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET state = 'built', image_tag = ?3, image_id = ?4,
                             reason = NULL, log = ?5, finished_at = ?6
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![app, revision, image_tag, image_id, log, finished_at],
                    )
                    .context("recording a finished build")?;

                Ok(())
            })
            .await
    }

    /// Write down that the build of `revision` will not produce an image, and
    /// why.
    ///
    /// `reason` is the one sentence an operator reads first — a clone that was
    /// refused, a manifest that would not parse, an engine that said no. The
    /// log is what they read second, and is truncated to the tail because the
    /// end of a build is where the failure is.
    pub async fn failed(&self, app: &AppId, revision: &str, reason: &str, log: &str) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let reason = reason.to_owned();
        let log = tail(log);
        let finished_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET state = 'failed', reason = ?3, log = ?4, finished_at = ?5
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![app, revision, reason, log, finished_at],
                    )
                    .context("recording a failed build")?;

                Ok(())
            })
            .await
    }

    /// Every build recorded for `app`, newest first.
    ///
    /// The order an operator wants: what happened last is what they came to
    /// look at. Ties on the timestamp fall back to the revision, so a listing
    /// read twice reads the same twice.
    pub async fn by_app(&self, app: &AppId) -> Result<Vec<Build>> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(&format!(
                        "SELECT {BUILD_COLUMNS} FROM app_builds
                         WHERE spaceport_app = ?1
                         ORDER BY started_at DESC, revision DESC"
                    ))
                    .context("preparing the builds query")?;

                let rows = statement
                    .query_map([app], build_from)
                    .context("reading the builds of an app")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the builds of an app")?;

                Ok(rows)
            })
            .await
    }

    /// The most recent build of `app`, whatever became of it.
    ///
    /// Deliberately not "the most recent successful build": what an operator
    /// asks when they say "how is it going?" includes the failure they are
    /// asking about. [`BuildRepository::built`] is the other question.
    pub async fn latest(&self, app: &AppId) -> Result<Option<Build>> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "SELECT {BUILD_COLUMNS} FROM app_builds
                             WHERE spaceport_app = ?1
                             ORDER BY started_at DESC, revision DESC
                             LIMIT 1"
                        ),
                        [app],
                        build_from,
                    )
                    .optional()
                    .context("reading the latest build of an app")
            })
            .await
    }

    /// The build of `revision` for `app`, if one was ever asked for.
    pub async fn get(&self, app: &AppId, revision: &str) -> Result<Option<Build>> {
        let app = app.to_string();
        let revision = revision.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "SELECT {BUILD_COLUMNS} FROM app_builds
                             WHERE spaceport_app = ?1 AND revision = ?2"
                        ),
                        rusqlite::params![app, revision],
                        build_from,
                    )
                    .optional()
                    .context("reading a build by revision")
            })
            .await
    }

    /// The successful build of `revision` for `app`, if there is one.
    ///
    /// This is what a deploy asks: it does not want to know that a build was
    /// attempted, it wants the image tag to run, and a pending, failed or
    /// abandoned row has no answer to give. Separate from
    /// [`BuildRepository::get`] so that a caller cannot forget to check the
    /// state and deploy the `image_tag` of a build that never finished.
    pub async fn built(&self, app: &AppId, revision: &str) -> Result<Option<Build>> {
        let app = app.to_string();
        let revision = revision.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "SELECT {BUILD_COLUMNS} FROM app_builds
                             WHERE spaceport_app = ?1 AND revision = ?2 AND state = 'built'"
                        ),
                        rusqlite::params![app, revision],
                        build_from,
                    )
                    .optional()
                    .context("reading the successful build of a revision")
            })
            .await
    }

    /// Return every build left `building` to `pending`, and say how many.
    ///
    /// Run at startup. A `building` row means a worker said it had this one —
    /// and a worker that was killed, or a host that lost power, says nothing
    /// further. Nothing in any process's memory can find that row afterwards,
    /// which is exactly why the claim was written to the database in the first
    /// place: it is the only record that outlives the process that made it, and
    /// so the only thing that can tell a fresh process what the last one was in
    /// the middle of.
    ///
    /// Requeued rather than failed, because being interrupted says nothing
    /// about whether the commit builds. `finished_at` is cleared with it, so a
    /// row that goes round again does not carry a finish from a run that never
    /// finished.
    pub async fn reset_interrupted(&self) -> Result<usize> {
        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds SET state = 'pending', finished_at = NULL
                         WHERE state = 'building'",
                        [],
                    )
                    .context("returning interrupted builds to the queue")
            })
            .await
    }

    /// Forget every build of `app`, and say how many there were.
    ///
    /// For the destroy cascade: an app that no longer exists has no builds, and
    /// a row left behind would keep a revision looking built long after the app
    /// it belonged to was gone.
    pub async fn forget(&self, app: &AppId) -> Result<usize> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                connection
                    .execute("DELETE FROM app_builds WHERE spaceport_app = ?1", [app])
                    .context("forgetting the builds of an app")
            })
            .await
    }

    /// Forget every build that was fetched through the connection `connection`,
    /// and say how many there were.
    ///
    /// A connection that is gone can no longer fetch a commit, so a pending
    /// build of one is work nothing could ever do. The slug is on the row for
    /// this: by the time a disconnect gets here the tracking that named the
    /// connection has already been deleted, and a join would find nothing.
    pub async fn forget_connection(&self, connection: &str) -> Result<usize> {
        let slug = connection.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .execute("DELETE FROM app_builds WHERE connection = ?1", [slug])
                    .context("forgetting the builds of a connection")
            })
            .await
    }
}

/// One row of `app_builds`, in the order [`BUILD_COLUMNS`] names.
///
/// The app id and the state both go back through `parse` rather than being
/// taken as strings, because a row this build cannot make sense of is worth
/// finding out about where it is read, with the word that caused it to hand.
fn build_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<Build> {
    let app: String = row.get(0)?;
    let app = app.parse::<AppId>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
    })?;
    let state: String = row.get(6)?;
    let state = state.parse::<BuildState>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, error.into())
    })?;

    Ok(Build {
        app,
        revision: row.get(1)?,
        connection: row.get(2)?,
        repository: row.get(3)?,
        branch: row.get(4)?,
        manifest_path: row.get(5)?,
        state,
        image_tag: row.get(7)?,
        image_id: row.get(8)?,
        reason: row.get(9)?,
        log: row.get(10)?,
        started_at: row.get(11)?,
        finished_at: row.get(12)?,
    })
}

/// The last [`LOG_LIMIT`] bytes of `log`, marked so a reader can see that there
/// was more.
///
/// The tail rather than the head: a build says what it is doing all the way
/// through and says what went wrong at the end, so the last screenful is worth
/// more than the first. An empty log is `None` rather than an empty string,
/// because "the build printed nothing" and "there is no log for this build" are
/// answers to different questions.
fn tail(log: &str) -> Option<String> {
    if log.is_empty() {
        return None;
    }
    if log.len() <= LOG_LIMIT {
        return Some(log.to_owned());
    }

    // Cutting at a byte offset can land inside a character, so the cut moves
    // forward to the next boundary — losing a few bytes rather than producing a
    // string that is not one.
    let mut start = log.len() - LOG_LIMIT;
    while !log.is_char_boundary(start) {
        start += 1;
    }

    Some(format!("{LOG_ELISION}{}", &log[start..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> BuildRepository {
        BuildRepository::new(Db::in_memory().unwrap())
    }

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    fn build(id: &str, revision: &str) -> Build {
        Build {
            app: app(id),
            revision: revision.to_owned(),
            connection: "spaceport".to_owned(),
            repository: "an-organisation/site".to_owned(),
            branch: "main".to_owned(),
            manifest_path: "spaceport.yaml".to_owned(),
            state: BuildState::Pending,
            image_tag: None,
            image_id: None,
            reason: None,
            log: None,
            started_at: String::new(),
            finished_at: None,
        }
    }

    /// The queue orders by `started_at`, and two requests made in the same
    /// test can land on the same instant. Where an order is what is under
    /// test, the timestamps are written by hand so the test is about the
    /// query and not about the clock.
    async fn requested_at(repository: &BuildRepository, id: &str, revision: &str, at: &str) {
        repository.request(&build(id, revision)).await.unwrap();

        let app = id.to_owned();
        let revision = revision.to_owned();
        let at = at.to_owned();
        repository
            .db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds SET started_at = ?3
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![app, revision, at],
                    )
                    .context("backdating a requested build")?;

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn knows_of_no_builds_to_begin_with() {
        let repository = repository();

        assert!(repository.by_app(&app("site")).await.unwrap().is_empty());
        assert!(repository.latest(&app("site")).await.unwrap().is_none());
        assert!(repository.get(&app("site"), "abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn records_and_reads_back_a_requested_build() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(read.state, BuildState::Pending);
        assert_eq!(read.repository, "an-organisation/site");
        assert_eq!(read.branch, "main");
        assert_eq!(read.manifest_path, "spaceport.yaml");
        assert_eq!(read.connection, "spaceport");
        assert_eq!(read.finished_at, None);
        // Stamped on the way in, whatever the struct said.
        assert!(read.started_at.ends_with('Z'), "{read:?}");
    }

    /// A webhook GitHub sends twice, or two pushes to the same head, must not
    /// become two builds of one commit — and the caller has to be able to tell
    /// which of the two it is.
    #[tokio::test]
    async fn requesting_the_same_revision_twice_is_news_only_once() {
        let repository = repository();

        assert!(repository.request(&build("site", "abc")).await.unwrap());
        assert!(!repository.request(&build("site", "abc")).await.unwrap());
        // Another revision, and the same revision of another app, are both new.
        assert!(repository.request(&build("site", "def")).await.unwrap());
        assert!(repository.request(&build("docs", "abc")).await.unwrap());
        assert_eq!(repository.by_app(&app("site")).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn claiming_takes_the_oldest_pending_build_and_marks_it_building() {
        let repository = repository();
        requested_at(&repository, "site", "newer", "2026-06-01T00:00:00Z").await;
        requested_at(&repository, "site", "older", "2026-01-01T00:00:00Z").await;

        let claimed = repository.claim().await.unwrap().unwrap();
        assert_eq!(claimed.revision, "older");
        assert_eq!(claimed.state, BuildState::Building);
        // And the row says so too, not just the value handed back.
        let read = repository
            .get(&app("site"), "older")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.state, BuildState::Building);
    }

    /// The whole point of claiming in one statement: whatever a second caller
    /// gets, it is not the build the first one is already doing.
    #[tokio::test]
    async fn a_second_claim_does_not_hand_out_the_same_build() {
        let repository = repository();
        requested_at(&repository, "site", "older", "2026-01-01T00:00:00Z").await;
        requested_at(&repository, "site", "newer", "2026-06-01T00:00:00Z").await;

        let first = repository.claim().await.unwrap().unwrap();
        let second = repository.claim().await.unwrap().unwrap();

        assert_eq!(first.revision, "older");
        assert_eq!(second.revision, "newer");
        assert!(repository.claim().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn claiming_an_empty_queue_finds_nothing() {
        let repository = repository();

        assert!(repository.claim().await.unwrap().is_none());

        // A build that is finished is not pending either.
        repository.request(&build("site", "abc")).await.unwrap();
        repository.claim().await.unwrap();
        repository
            .succeeded(&app("site"), "abc", "spaceport/site:abc", "sha256:1", "")
            .await
            .unwrap();

        assert!(repository.claim().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_successful_build_records_the_image_it_produced() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository.claim().await.unwrap();

        repository
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:0123",
                "step 1/2\nstep 2/2\n",
            )
            .await
            .unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(read.state, BuildState::Built);
        assert_eq!(read.image_tag.as_deref(), Some("spaceport/site:abc"));
        assert_eq!(read.image_id.as_deref(), Some("sha256:0123"));
        assert_eq!(read.reason, None);
        assert_eq!(read.log.as_deref(), Some("step 1/2\nstep 2/2\n"));
        assert!(read.finished_at.unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn a_failed_build_keeps_the_reason_an_operator_reads() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository.claim().await.unwrap();

        repository
            .failed(
                &app("site"),
                "abc",
                "the manifest names no image or build",
                "step 1/2\nerror\n",
            )
            .await
            .unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(read.state, BuildState::Failed);
        assert_eq!(
            read.reason.as_deref(),
            Some("the manifest names no image or build")
        );
        assert_eq!(read.log.as_deref(), Some("step 1/2\nerror\n"));
        assert_eq!(read.image_tag, None);
        assert!(read.finished_at.unwrap().ends_with('Z'));
    }

    /// What a restart is for: a row nothing is building any more goes back in
    /// the queue, and a row that reached an answer keeps it.
    #[tokio::test]
    async fn resetting_returns_interrupted_builds_and_leaves_finished_ones() {
        let repository = repository();
        requested_at(&repository, "site", "interrupted", "2026-01-01T00:00:00Z").await;
        requested_at(&repository, "site", "done", "2026-02-01T00:00:00Z").await;
        requested_at(&repository, "site", "waiting", "2026-03-01T00:00:00Z").await;
        repository.claim().await.unwrap();
        repository.claim().await.unwrap();
        repository
            .succeeded(&app("site"), "done", "spaceport/site:done", "sha256:1", "")
            .await
            .unwrap();

        assert_eq!(repository.reset_interrupted().await.unwrap(), 1);

        let interrupted = repository
            .get(&app("site"), "interrupted")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(interrupted.state, BuildState::Pending);
        assert_eq!(interrupted.finished_at, None);
        assert_eq!(
            repository
                .get(&app("site"), "done")
                .await
                .unwrap()
                .unwrap()
                .state,
            BuildState::Built
        );
        // The one that was never claimed is untouched, and still first in line.
        assert_eq!(
            repository.claim().await.unwrap().unwrap().revision,
            "interrupted"
        );
    }

    /// A deploy asks for an image, not for an attempt, so only a build that
    /// produced one may answer.
    #[tokio::test]
    async fn only_a_successful_build_answers_for_a_revision() {
        let repository = repository();
        repository.request(&build("site", "pending")).await.unwrap();
        repository.request(&build("site", "broken")).await.unwrap();
        repository.request(&build("site", "good")).await.unwrap();
        repository
            .failed(&app("site"), "broken", "the build refused", "")
            .await
            .unwrap();
        repository
            .succeeded(&app("site"), "good", "spaceport/site:good", "sha256:1", "")
            .await
            .unwrap();

        assert!(
            repository
                .built(&app("site"), "pending")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .built(&app("site"), "broken")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            repository
                .built(&app("site"), "good")
                .await
                .unwrap()
                .unwrap()
                .image_tag
                .as_deref(),
            Some("spaceport/site:good")
        );
        // Another app's successful build of the same revision is not this
        // app's.
        assert!(
            repository
                .built(&app("docs"), "good")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A build that printed a megabyte must not put a megabyte in the database,
    /// and what is kept is the end, where the failure is.
    #[tokio::test]
    async fn a_long_log_is_cut_down_to_its_tail() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        let noisy = format!("{}the last line\n", "chatter\n".repeat(LOG_LIMIT / 4));

        repository
            .failed(&app("site"), "abc", "the build refused", &noisy)
            .await
            .unwrap();

        let log = repository
            .get(&app("site"), "abc")
            .await
            .unwrap()
            .unwrap()
            .log
            .unwrap();
        assert!(log.len() <= LOG_LIMIT + LOG_ELISION.len(), "{}", log.len());
        assert!(log.starts_with(LOG_ELISION), "{}", &log[..40]);
        assert!(log.ends_with("the last line\n"));
    }

    /// A log that came back empty is no log, which is a different answer from
    /// an empty one.
    #[tokio::test]
    async fn a_build_that_printed_nothing_has_no_log() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository
            .succeeded(&app("site"), "abc", "spaceport/site:abc", "sha256:1", "")
            .await
            .unwrap();

        assert_eq!(
            repository
                .get(&app("site"), "abc")
                .await
                .unwrap()
                .unwrap()
                .log,
            None
        );
    }

    #[tokio::test]
    async fn lists_and_reports_the_builds_of_an_app_newest_first() {
        let repository = repository();
        requested_at(&repository, "site", "oldest", "2026-01-01T00:00:00Z").await;
        requested_at(&repository, "site", "newest", "2026-03-01T00:00:00Z").await;
        requested_at(&repository, "site", "middle", "2026-02-01T00:00:00Z").await;
        requested_at(&repository, "docs", "elsewhere", "2026-04-01T00:00:00Z").await;

        let revisions: Vec<String> = repository
            .by_app(&app("site"))
            .await
            .unwrap()
            .into_iter()
            .map(|build| build.revision)
            .collect();
        assert_eq!(revisions, ["newest", "middle", "oldest"]);
        assert_eq!(
            repository
                .latest(&app("site"))
                .await
                .unwrap()
                .unwrap()
                .revision,
            "newest"
        );
    }

    /// The destroy cascade: an app that is gone has no builds, and nobody
    /// else's go with it.
    #[tokio::test]
    async fn forgetting_an_app_takes_only_its_builds() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository.request(&build("site", "def")).await.unwrap();
        repository.request(&build("docs", "abc")).await.unwrap();

        assert_eq!(repository.forget(&app("site")).await.unwrap(), 2);

        assert!(repository.by_app(&app("site")).await.unwrap().is_empty());
        assert_eq!(repository.by_app(&app("docs")).await.unwrap().len(), 1);
    }

    /// The connection-forget cascade: a connection that is gone cannot fetch a
    /// commit, so its builds go — and another connection's stay.
    #[tokio::test]
    async fn forgetting_a_connection_takes_only_the_builds_it_fetched() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository
            .request(&Build {
                connection: "another".to_owned(),
                ..build("docs", "abc")
            })
            .await
            .unwrap();

        assert_eq!(repository.forget_connection("spaceport").await.unwrap(), 1);

        assert!(repository.by_app(&app("site")).await.unwrap().is_empty());
        assert_eq!(repository.by_app(&app("docs")).await.unwrap().len(), 1);
    }

    /// The column holds the word, so the word has to survive the trip.
    #[tokio::test]
    async fn a_state_round_trips_through_its_written_word() {
        for state in [
            BuildState::Pending,
            BuildState::Building,
            BuildState::Built,
            BuildState::Failed,
        ] {
            assert_eq!(state.to_string().parse::<BuildState>().unwrap(), state);
        }

        let error = "half-built".parse::<BuildState>().unwrap_err().to_string();
        assert!(error.contains("half-built"), "{error}");
    }
}
