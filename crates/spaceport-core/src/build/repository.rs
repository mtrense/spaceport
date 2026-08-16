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
//! What became of *deploying* a revision is written on the same row, for the
//! same reason and then one more. A deployment that ran itself off the back of
//! a successful build has to be attempted once and never again: a revision that
//! would not start is a revision that will not start on the next pass either,
//! and a worker with no memory of having tried would take the app down every
//! minute for ever. The memory has to outlive the worker, so it is a column and
//! not a field — and `(app, revision)` is already the key it wants, because a
//! revision is deployed at most once just as it is built at most once.
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

/// How much of the reason a deployment failed is kept.
///
/// A reason is meant to be one sentence, but the sentence is often an error
/// chain from somewhere further down — an engine that refused a port, with
/// everything that was being attempted around it — and nothing stops one of
/// those carrying a page of output that a program printed into a message. Cut
/// on the way in for the reason [`LOG_LIMIT`] is: the only cheap place to lose
/// it is the one place that ever had it whole.
///
/// Four kilobytes is far more than a sentence and far less than a log. Unlike a
/// log it is the *head* that is kept, because an error chain says what failed
/// first and elaborates afterwards — the opposite way round from a build, which
/// chatters first and fails at the end.
const REASON_LIMIT: usize = 4 * 1024;

/// What replaces the end of a reason that was too long, so a reader can see
/// that there was more.
const REASON_ELISION: &str = "…";

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
    /// The manifest document that was read out of the commit, exactly as it was
    /// written there.
    ///
    /// Kept on the row rather than re-read off disk, because by the time it is
    /// wanted there is nothing to re-read: the unpacked tree is swept once
    /// `keep` newer revisions exist, and a deploy of this revision days later
    /// still has to be able to say what the commit asked for. Storing what
    /// parsing made of it would answer with this build's idea of the schema
    /// instead of with the document, which is the one thing an operator can
    /// compare against their repository. `None` for a row an earlier spaceport
    /// wrote, and for a build that failed before it read one.
    pub manifest: Option<String>,
    /// When a deployment of this revision concluded, RFC 3339, whether it
    /// worked or not.
    ///
    /// `None` is a revision no deployment has ever finished for: one still
    /// queued, one that failed to build, one an operator has not deployed. It
    /// is what every row written before the column existed says, and it is what
    /// makes an automatic deployment attemptable exactly once — see
    /// [`Build::awaits_deployment`].
    pub deployed_at: Option<String>,
    /// Why the deployment failed, in one sentence, for an operator to read.
    ///
    /// `None` beside a `deployed_at` means it worked. Separate from
    /// [`Build::reason`], which is why the *build* failed: a revision that built
    /// an image and then could not be started has two different things to say
    /// about it, and one column would let the second erase the first.
    pub deploy_reason: Option<String>,
}

impl Build {
    /// Whether an automatic deployment should still attempt this revision.
    ///
    /// Two conditions, and the second is the one worth writing down. There has
    /// to be an image, so the build must have succeeded. And no deployment may
    /// have concluded for this revision *either way* — not because a second
    /// deployment of a working revision would be wrong, but because a second
    /// deployment of a broken one would be: a revision whose deployment failed
    /// is never retried, or the worker would take the app down again on every
    /// pass, for ever, for a commit that cannot come back. The retry is the next
    /// commit, which is a thing a person can push once they have seen why.
    pub fn awaits_deployment(&self) -> bool {
        self.state == BuildState::Built && self.deployed_at.is_none()
    }
}

/// The columns of `app_builds`, in the order [`build_from`] reads them.
///
/// Written once so the `SELECT`s and the row mapping cannot drift apart.
const BUILD_COLUMNS: &str = "spaceport_app, revision, connection, repository, branch, \
                             manifest_path, state, image_tag, image_id, reason, log, \
                             started_at, finished_at, manifest, deployed_at, deploy_reason";

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
    ///
    /// `manifest` is the document the commit carried, written down here because
    /// this is the only moment it is in hand — see [`Build::manifest`].
    pub async fn succeeded(
        &self,
        app: &AppId,
        revision: &str,
        image_tag: &str,
        image_id: &str,
        manifest: &str,
        log: &str,
    ) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let image_tag = image_tag.to_owned();
        let image_id = image_id.to_owned();
        let manifest = manifest.to_owned();
        let log = tail(log);
        let finished_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET state = 'built', image_tag = ?3, image_id = ?4,
                             reason = NULL, log = ?5, finished_at = ?6, manifest = ?7
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![
                            app,
                            revision,
                            image_tag,
                            image_id,
                            log,
                            finished_at,
                            manifest
                        ],
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

    /// Write down that this revision has been deployed and that it worked.
    ///
    /// Stamped whether the deployment was automatic or an operator's, because
    /// the question the row answers is "has anything already deployed this
    /// revision?", and an operator who deployed a commit by hand has answered it
    /// — a worker that came along afterwards and deployed it again would be
    /// restarting a running app for no reason.
    ///
    /// Terminal in the same sense [`BuildRepository::succeeded`] is: a revision
    /// is deployed once, and what happens to the app afterwards is the
    /// supervisor's business rather than this row's.
    pub async fn deployed(&self, app: &AppId, revision: &str) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let deployed_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET deployed_at = ?3, deploy_reason = NULL
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![app, revision, deployed_at],
                    )
                    .context("recording a deployed revision")?;

                Ok(())
            })
            .await
    }

    /// Write down that this revision was deployed, that it did not work, and
    /// why.
    ///
    /// The row that stops the loop. Without it the next pass would find the same
    /// newest built revision, deploy it again, and take the app down again —
    /// once a minute, for a commit that cannot be made to work by being tried
    /// harder. `reason` is the sentence an operator reads when they ask why
    /// production is still on the commit before: a manifest that would not
    /// apply, a container that would not start, a port already taken. It is cut
    /// to [`REASON_LIMIT`] because an error chain is only usually a sentence.
    pub async fn deploy_failed(&self, app: &AppId, revision: &str, reason: &str) -> Result<()> {
        let app = app.to_string();
        let revision = revision.to_owned();
        let reason = head(reason);
        let deployed_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET deployed_at = ?3, deploy_reason = ?4
                         WHERE spaceport_app = ?1 AND revision = ?2",
                        rusqlite::params![app, revision, deployed_at, reason],
                    )
                    .context("recording a failed deployment")?;

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

    /// The most recently finished successful build of `app`, if there is one.
    ///
    /// What an operator means by `spaceport apps deploy site` with no
    /// `--revision`: the newest thing that actually exists as an image.
    /// Deliberately not [`BuildRepository::latest`], which answers "how is it
    /// going?" and so includes the failure and the commit still in the queue —
    /// deploying either of those would point an app at an image nothing ever
    /// produced.
    ///
    /// Ordered by `finished_at` and not by `started_at`, because that is the
    /// order the images came into existence: a long build of an older commit
    /// can finish after a quick build of a newer one, and the deploy that
    /// follows should land on whichever image was ready last rather than on the
    /// one whose request was typed last. Ties fall back to the revision, so a
    /// deploy issued twice deploys the same thing twice.
    pub async fn latest_built(&self, app: &AppId) -> Result<Option<Build>> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!(
                            "SELECT {BUILD_COLUMNS} FROM app_builds
                             WHERE spaceport_app = ?1 AND state = 'built'
                             ORDER BY finished_at DESC, revision DESC
                             LIMIT 1"
                        ),
                        [app],
                        build_from,
                    )
                    .optional()
                    .context("reading the latest successful build of an app")
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
        manifest: row.get(13)?,
        deployed_at: row.get(14)?,
        deploy_reason: row.get(15)?,
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

/// The first [`REASON_LIMIT`] bytes of `reason`, marked so a reader can see
/// that there was more.
///
/// The head rather than the tail, which is the other way round from [`tail`]
/// and for the other reason: an error chain leads with what failed and follows
/// with the context it failed in, so the first sentence is the one that was
/// wanted. A `String` and never a `None`, however empty the reason is, because
/// a NULL in that column means the deployment worked — a failure that arrived
/// without anything to say must still read as a failure.
fn head(reason: &str) -> String {
    if reason.len() <= REASON_LIMIT {
        return reason.to_owned();
    }

    // Cutting at a byte offset can land inside a character, so the cut moves
    // back to the previous boundary — losing a few bytes rather than producing
    // a string that is not one.
    let mut end = REASON_LIMIT;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}{REASON_ELISION}", &reason[..end])
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
            manifest: None,
            deployed_at: None,
            deploy_reason: None,
        }
    }

    /// A manifest as one comes out of a commit.
    const MANIFEST: &str = "\
schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
routing:
  hosts: [site.example.com]
auth:
  gating: open
";

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
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:1",
                MANIFEST,
                "",
            )
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
                MANIFEST,
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

    /// The tree the document was read out of is swept a few revisions later, so
    /// the row is the only thing that can still say what the commit asked for.
    #[tokio::test]
    async fn a_successful_build_remembers_the_manifest_it_was_built_from() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository.claim().await.unwrap();

        repository
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:0123",
                MANIFEST,
                "",
            )
            .await
            .unwrap();

        // Byte for byte, and through every way of reading the row back.
        for read in [
            repository.get(&app("site"), "abc").await.unwrap().unwrap(),
            repository
                .built(&app("site"), "abc")
                .await
                .unwrap()
                .unwrap(),
            repository.latest(&app("site")).await.unwrap().unwrap(),
            repository
                .latest_built(&app("site"))
                .await
                .unwrap()
                .unwrap(),
            repository.by_app(&app("site")).await.unwrap().remove(0),
        ] {
            assert_eq!(read.manifest.as_deref(), Some(MANIFEST));
        }
    }

    /// A deploy with no revision named wants the newest image that exists, and
    /// a commit that is queued or broken is not one.
    #[tokio::test]
    async fn the_latest_built_revision_ignores_a_failed_or_pending_one() {
        let repository = repository();
        requested_at(&repository, "site", "built", "2026-01-01T00:00:00Z").await;
        requested_at(&repository, "site", "broken", "2026-02-01T00:00:00Z").await;
        requested_at(&repository, "site", "queued", "2026-03-01T00:00:00Z").await;
        repository
            .succeeded(
                &app("site"),
                "built",
                "spaceport/site:built",
                "sha256:1",
                MANIFEST,
                "",
            )
            .await
            .unwrap();
        repository
            .failed(&app("site"), "broken", "the build refused", "")
            .await
            .unwrap();

        // `latest` answers "how is it going?" and so sees the one still queued.
        assert_eq!(
            repository
                .latest(&app("site"))
                .await
                .unwrap()
                .unwrap()
                .revision,
            "queued"
        );
        assert_eq!(
            repository
                .latest_built(&app("site"))
                .await
                .unwrap()
                .unwrap()
                .revision,
            "built"
        );
        // An app nothing has ever been built for has no answer to give, and
        // another app's image is not this one's.
        assert!(
            repository
                .latest_built(&app("docs"))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A build recorded before this column existed says nothing about the
    /// manifest, which is a different answer from an empty document.
    #[tokio::test]
    async fn a_build_written_before_the_manifest_was_kept_reads_back_as_none() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        // Exactly the row an older spaceport left behind: built, with an image,
        // and no manifest.
        repository
            .db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET state = 'built', image_tag = 'spaceport/site:abc',
                             image_id = 'sha256:1', finished_at = '2026-01-01T00:00:00Z'
                         WHERE spaceport_app = 'site' AND revision = 'abc'",
                        [],
                    )
                    .context("writing a build as an older spaceport did")?;

                Ok(())
            })
            .await
            .unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(read.state, BuildState::Built);
        assert_eq!(read.manifest, None);
        assert_eq!(
            repository
                .latest_built(&app("site"))
                .await
                .unwrap()
                .unwrap()
                .manifest,
            None
        );
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

    /// A revision that has been deployed says so through every way of reading
    /// the row back, because the worker, the operator and a listing all ask
    /// different questions of the same fact.
    #[tokio::test]
    async fn a_deployed_revision_reads_back_as_deployed_everywhere() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:1",
                MANIFEST,
                "",
            )
            .await
            .unwrap();

        // Before anything deploys it, it is exactly what an automatic
        // deployment is looking for.
        assert!(
            repository
                .latest_built(&app("site"))
                .await
                .unwrap()
                .unwrap()
                .awaits_deployment()
        );

        repository.deployed(&app("site"), "abc").await.unwrap();

        for read in [
            repository.get(&app("site"), "abc").await.unwrap().unwrap(),
            repository
                .built(&app("site"), "abc")
                .await
                .unwrap()
                .unwrap(),
            repository.latest(&app("site")).await.unwrap().unwrap(),
            repository
                .latest_built(&app("site"))
                .await
                .unwrap()
                .unwrap(),
            repository.by_app(&app("site")).await.unwrap().remove(0),
        ] {
            assert!(read.deployed_at.as_deref().unwrap().ends_with('Z'));
            assert_eq!(read.deploy_reason, None);
            assert!(!read.awaits_deployment());
        }
    }

    /// The row that stops the loop: a revision that would not start is not
    /// tried again, and what it said is still there for an operator to read.
    #[tokio::test]
    async fn a_deployment_that_failed_keeps_its_reason_and_is_not_attempted_again() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        repository
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:1",
                MANIFEST,
                "",
            )
            .await
            .unwrap();

        repository
            .deploy_failed(&app("site"), "abc", "the container exited immediately")
            .await
            .unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(
            read.deploy_reason.as_deref(),
            Some("the container exited immediately")
        );
        assert!(read.deployed_at.as_deref().unwrap().ends_with('Z'));
        assert!(!read.awaits_deployment());
        // The build itself still says it produced an image, and why it failed
        // to deploy has not overwritten why it failed to build.
        assert_eq!(read.state, BuildState::Built);
        assert_eq!(read.reason, None);
    }

    /// A revision nothing has an image for is not one to deploy, whatever else
    /// is true of it.
    #[tokio::test]
    async fn only_a_built_revision_awaits_deployment() {
        let repository = repository();
        repository.request(&build("site", "pending")).await.unwrap();
        repository.request(&build("site", "broken")).await.unwrap();
        repository
            .failed(&app("site"), "broken", "the build refused", "")
            .await
            .unwrap();

        for revision in ["pending", "broken"] {
            assert!(
                !repository
                    .get(&app("site"), revision)
                    .await
                    .unwrap()
                    .unwrap()
                    .awaits_deployment(),
                "{revision}"
            );
        }
    }

    /// A reason that arrived as a page of error chain must not put a page in
    /// the database, and what is kept is the beginning, where the failure is
    /// named.
    #[tokio::test]
    async fn a_long_deployment_reason_is_cut_down_to_its_head() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        let chatty = format!("the first thing\n{}", "context\n".repeat(REASON_LIMIT / 4));

        repository
            .deploy_failed(&app("site"), "abc", &chatty)
            .await
            .unwrap();

        let reason = repository
            .get(&app("site"), "abc")
            .await
            .unwrap()
            .unwrap()
            .deploy_reason
            .unwrap();
        assert!(
            reason.len() <= REASON_LIMIT + REASON_ELISION.len(),
            "{}",
            reason.len()
        );
        assert!(reason.starts_with("the first thing\n"), "{}", &reason[..40]);
        assert!(reason.ends_with(REASON_ELISION));
    }

    /// A build recorded before these columns existed has never been deployed,
    /// which is what makes it one an automatic deployment may still act on
    /// rather than one it has to guess about.
    #[tokio::test]
    async fn a_build_written_before_deployments_were_recorded_reads_as_never_deployed() {
        let repository = repository();
        repository.request(&build("site", "abc")).await.unwrap();
        // Exactly the row an older spaceport left behind: built, with an image,
        // and nothing at all to say about deploying it.
        repository
            .db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE app_builds
                         SET state = 'built', image_tag = 'spaceport/site:abc',
                             image_id = 'sha256:1', finished_at = '2026-01-01T00:00:00Z'
                         WHERE spaceport_app = 'site' AND revision = 'abc'",
                        [],
                    )
                    .context("writing a build as an older spaceport did")?;

                Ok(())
            })
            .await
            .unwrap();

        let read = repository.get(&app("site"), "abc").await.unwrap().unwrap();
        assert_eq!(read.deployed_at, None);
        assert_eq!(read.deploy_reason, None);
        assert!(read.awaits_deployment());
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
            .succeeded(
                &app("site"),
                "done",
                "spaceport/site:done",
                "sha256:1",
                MANIFEST,
                "",
            )
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
            .succeeded(
                &app("site"),
                "good",
                "spaceport/site:good",
                "sha256:1",
                MANIFEST,
                "",
            )
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
            .succeeded(
                &app("site"),
                "abc",
                "spaceport/site:abc",
                "sha256:1",
                MANIFEST,
                "",
            )
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
