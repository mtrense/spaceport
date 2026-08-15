//! The loop that turns the revisions apps track into images.
//!
//! The four seams beside this one each do one thing and know nothing about the
//! others: [`super::archive`] fetches bytes, [`super::unpack`] writes a tree,
//! [`super::image`] asks the engine, and [`super::repository`] remembers. This
//! module is the only place they meet, and the whole of what it adds is order —
//! resolve the connection, ask GitHub where the tarball is, download it, unpack
//! it, read the manifest, hand the result to the engine, write down what came
//! back.
//!
//! It is shaped like [`crate::connections::github::reconcile::maintain`] and
//! for the same reason. A pass does not act on what woke it: every pass reads
//! the trackings out of the state store and asks for a build of each revision
//! it finds, whether or not anything said one had moved. That is what makes a
//! missed wake-up heal itself, and it costs nothing, because
//! [`BuildRepository::request`] is idempotent — a revision already asked for is
//! not asked for twice. Acting on what the loop was told would be believing a
//! webhook, which is the argument `reconcile.rs` makes about installations and
//! which is no weaker here.
//!
//! **One build at a time, deliberately.** A build reads a source tree off the
//! disk, hands hundreds of megabytes to a container engine, and then runs
//! somebody's compiler. A host running four small apps that all get a push
//! within the same minute should build them one after another rather than
//! discover how much memory four `cargo build`s want; the queue is what makes
//! that safe, since a build nobody got to is a row rather than a task. The pass
//! does drain the queue rather than taking one build per interval — a backlog
//! after a restart would otherwise take an interval per commit — and it checks
//! for shutdown between builds, so stopping a spaceport does not mean waiting
//! out a queue.
//!
//! Nothing here deploys anything, and it shoves something that does. The image
//! is built, tagged and recorded against the app and the revision it came from,
//! and the app goes on running whatever it was running; pointing it at the
//! fresh image is [`crate::app::deploy`]'s, and only for an app whose operator
//! armed it. The [`Worker::deploys`] nudge is the whole of what this loop has
//! to do with that — the shove says "go and look", never "deploy this", so a
//! shove that goes missing costs the interval that loop runs on and nothing
//! else, and the deployment itself waits on a container becoming ready
//! somewhere that is not holding the one build slot.
//!
//! A failure is written down and never propagated. There is nobody above this
//! loop to return an error to — a worker that gave up on a bad manifest would
//! be a spaceport that stops building every app because one of them is broken —
//! so each step's failure becomes a sentence on the build row, which is what an
//! operator reads minutes or days later from a machine that has since
//! restarted.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::archive::Archives;
use super::dir::BuildDir;
use super::image::{BuildRequest, ImageBuilder, tag};
use super::repository::{Build, BuildRepository, BuildState};
use super::unpack::{Limits, unpack};
use crate::app::AppId;
use crate::app::manifest::{AppManifest, Source};
use crate::connections::github::api::{Client, Transport};
use crate::connections::github::reconcile::Nudge;
use crate::connections::github::repository::ConnectionRepository;
use crate::connections::github::tracking::TrackingRepository;

/// The label every image spaceport built carries, so that an image of its
/// making can be told from one pulled off a registry.
///
/// The same string [`crate::runtime`] stamps on the containers it starts, and
/// spelled out again here rather than shared: that constant is private to the
/// docker runtime, and widening it would be editing another module for this
/// one's convenience.
const MANAGED_LABEL: &str = "spaceport.managed";

/// Which app the image was built for.
const APP_LABEL: &str = "spaceport.app";

/// Which commit it was built from.
///
/// The tag carries an abbreviated sha and this carries the whole one: the tag
/// is what a person reads, and the label is what answers "exactly which commit
/// is this" for a machine that has only the image.
const REVISION_LABEL: &str = "spaceport.revision";

/// How often a pass runs, and what one build is allowed to cost.
///
/// One struct rather than five constants, for the reason the reconciler's is
/// one: these are an argument about time and size that only makes sense read
/// together, and a test that had to sit out the real ones would take minutes to
/// find out what it already knows.
#[derive(Debug, Clone)]
pub struct Policy {
    /// How long between passes.
    ///
    /// This is the outer bound on how long a push whose wake-up went missing
    /// stays unbuilt, and five minutes is right because a pass over a spaceport
    /// with nothing to do is two queries against a local database and no
    /// network at all. The nudge is what makes an ordinary push build in
    /// seconds; this is what makes a push build at all when the process was
    /// restarting as the delivery arrived.
    pub interval: Duration,

    /// How long to let a wake-up settle before acting on it.
    ///
    /// A push to a monorepo moves every app whose manifest is in it, and a
    /// merge train pushes several times in a few seconds. Each of those is a
    /// nudge, and each would otherwise be a pass. The wait costs only itself,
    /// because a pass reads the whole of what is tracked either way — the later
    /// push of a burst is answered by the pass the earlier one started.
    ///
    /// Two seconds, the same as the reconciler's, so that the two loops behave
    /// alike where nothing argues for a difference.
    pub settle: Duration,

    /// The largest archive that will be downloaded, in bytes.
    ///
    /// The operator's number, from `build.max_archive_bytes`. It is here rather
    /// than read from the config at the download because this module is handed
    /// a policy and never a config: what a build may cost is a judgement about
    /// a host, and a test that wants a small one should be able to say so.
    pub max_archive_bytes: u64,

    /// What the archive is allowed to be once it is expanded.
    ///
    /// Deliberately not the download limit. Gzip over source code compresses
    /// several times over, so a tarball that is honestly under the download cap
    /// still expands to several times it, and a limit equal to the download
    /// would refuse ordinary repositories. It is also the only limit that
    /// stands between spaceport and an archive built to expand for ever, which
    /// is why it is a limit at all rather than a multiple worked out on the
    /// spot.
    pub unpacked: Limits,

    /// How many built revisions of each app to keep on disk, from
    /// `build.keep` — the operator's number, like the archive limit.
    pub keep: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            interval: Duration::minutes(5),
            settle: Duration::seconds(2),
            // The config's own default, restated so that a policy built by hand
            // is bounded rather than boundless.
            max_archive_bytes: 64 * 1024 * 1024,
            unpacked: Limits {
                total: 512 * 1024 * 1024,
                // A source tree with more files than this is not a small app's,
                // and this is the cheapest place to find out that something
                // else has been committed into the repository.
                entries: 20_000,
            },
            keep: super::dir::DEFAULT_REVISIONS_KEPT,
        }
    }
}

/// Everything one build needs, gathered once at startup.
///
/// A struct rather than eight arguments to [`maintain`], for the reason
/// [`crate::edge::Home`] is one: every field is held for the life of the
/// process, and the alternative is threading each of them through separately
/// and getting the order wrong. Public fields, because assembling it is the
/// daemon's job and there is nothing to enforce.
pub struct Worker {
    /// The queue, and the record of what became of everything in it.
    pub builds: BuildRepository,
    /// What each app is built from — read afresh every pass.
    pub trackings: Arc<TrackingRepository>,
    /// The connections a commit is fetched through, and what their
    /// installations grant.
    pub connections: Arc<ConnectionRepository>,
    /// How spaceport asks GitHub where a tarball is.
    pub github: Arc<dyn Transport>,
    /// How it then downloads one.
    pub archives: Arc<dyn Archives>,
    /// The engine that turns an unpacked commit into an image.
    pub images: Arc<dyn ImageBuilder>,
    /// Where a commit is unpacked.
    pub directory: BuildDir,
    /// Shoved once a build has been recorded as having succeeded, so that an
    /// armed app's commit is deployed in seconds rather than at the deploying
    /// loop's next interval.
    ///
    /// A [`Nudge`] of the same type this loop is woken by and emphatically not
    /// the same *instance* — the reasoning
    /// [`crate::connections::github::webhook`] makes about the reconciler's and
    /// the builder's holds again here. Waking
    /// the builder when a build has just finished would put every finished
    /// build back through the queue it came out of; waking the reconciler would
    /// make an image finishing into a GitHub round trip per connection. Three
    /// loops with three different costs per wake-up need three signals.
    pub deploys: Nudge,
}

/// Keep building the revisions this spaceport's apps track, until `shutdown` is
/// cancelled.
///
/// Wakes on three things — the interval, a [`Nudge`], and shutdown. The
/// interval is what makes a revision eventually built whatever went missing;
/// the nudge is what makes it built in seconds when a push did reach this
/// spaceport, which is nearly always. Nothing here treats the two differently
/// once it is awake: both run the same pass, because the pass is what reads the
/// trackings, and a wake-up that acted on what it was told would be believing a
/// webhook.
///
/// The queue is emptied before the loop is entered for the first time in one
/// respect only: [`BuildRepository::reset_interrupted`] runs once at startup. A
/// process that was killed mid-build left a `building` row behind, and nothing
/// in any process's memory can find it — the row is the only record that
/// outlived the worker that made it.
pub async fn maintain(
    worker: Arc<Worker>,
    policy: Policy,
    nudge: Nudge,
    shutdown: CancellationToken,
) {
    debug!(
        minutes = policy.interval.whole_minutes(),
        "building what the apps track"
    );

    match worker.builds.reset_interrupted().await {
        Ok(0) => {}
        // Worth a line: it says the last run of this spaceport was killed
        // rather than stopped, which is the sort of thing an operator finds out
        // about far too late otherwise.
        Ok(returned) => info!(
            builds = returned,
            "returned interrupted builds to the queue"
        ),
        Err(error) => warn!(
            error = %format!("{error:#}"),
            "could not return the interrupted builds to the queue",
        ),
    }

    let mut woken = nudge.changed();

    loop {
        // Everything learned up to this point is what this pass is about to go
        // and read for itself, so it is not also a reason to run again.
        // Anything that arrives from here on is — it may have been recorded
        // after this pass read the trackings.
        woken.mark_unchanged();

        pass(&worker, &policy, &shutdown).await;

        tokio::select! {
            () = shutdown.cancelled() => break,
            // `unsigned_abs` for the reason the other loops use it: a policy or
            // a clock that has done something strange should cost a busy loop
            // at worst rather than a panic.
            () = tokio::time::sleep(policy.interval.unsigned_abs()) => {}
            // A push moved a branch an app tracks.
            result = woken.changed() => {
                // Every sender has gone, so nothing can ever say so again. A
                // wake-up that can no longer happen is not worth a task.
                if result.is_err() {
                    break;
                }

                // Only on this arm: a burst is a property of what GitHub sends,
                // and the interval has nothing to settle. Interruptible,
                // because a settle that outlived a shutdown would be a shutdown
                // that waits for it.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(policy.settle.unsigned_abs()) => {}
                }
            }
        }
    }

    debug!("stopped building what the apps track");
}

/// One pass: ask for what is tracked, then build the queue empty.
///
/// The order is load-bearing. Requesting first means a revision recorded while
/// the last pass was running is in the queue before this one starts draining
/// it, so a push that arrived during a build is built by the pass that build
/// belongs to rather than by the next one.
async fn pass(worker: &Worker, policy: &Policy, shutdown: &CancellationToken) {
    request_what_is_tracked(worker).await;

    loop {
        // Between builds rather than only around the wait: a queue of ten
        // commits must not be ten builds a stopping spaceport sits through.
        if shutdown.is_cancelled() {
            break;
        }

        let claimed = match worker.builds.claim().await {
            Ok(Some(claimed)) => claimed,
            Ok(None) => break,
            // The state store, not the engine and not GitHub. Nothing in a pass
            // can be done without it, and claiming again immediately would not
            // make it readable.
            Err(error) => {
                warn!(error = %format!("{error:#}"), "could not take the next build off the queue");

                break;
            }
        };

        run(worker, policy, &claimed).await;
    }
}

/// Ask for a build of every revision an app tracks.
///
/// Every pass, for every tracking, whatever woke the loop — see the module
/// header. [`BuildRepository::request`] refuses a second row for a revision
/// already recorded, so the cost of running this when nothing has changed is
/// one insert per app that goes nowhere, and the benefit is that a revision
/// recorded while this spaceport was not listening is still built.
async fn request_what_is_tracked(worker: &Worker) {
    let trackings = match worker.trackings.all().await {
        Ok(trackings) => trackings,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not read what the apps track");

            return;
        }
    };

    for tracking in trackings {
        // An app pointed at a branch nothing has been taken from yet. There is
        // no commit to build, which is an ordinary state and not a failure.
        let Some(revision) = tracking.revision.clone() else {
            continue;
        };

        // The build row names the connection by slug rather than by GitHub's
        // numeric app id, so that forgetting a connection can take its builds
        // with it without joining back through a tracking the same disconnect
        // has already deleted.
        let connection = match worker.connections.by_app_id(tracking.github_app_id).await {
            Ok(Some(connection)) => connection,
            Ok(None) => {
                debug!(
                    app = %tracking.app,
                    github_app_id = tracking.github_app_id,
                    "an app tracks a repository through a connection that is gone",
                );

                continue;
            }
            Err(error) => {
                warn!(
                    app = %tracking.app,
                    error = %format!("{error:#}"),
                    "could not read the connection an app is built through",
                );

                continue;
            }
        };

        let build = Build {
            app: tracking.app.clone(),
            revision: revision.clone(),
            connection: connection.slug,
            repository: tracking.repository.clone(),
            branch: tracking.branch.clone(),
            manifest_path: tracking.manifest_path.clone(),
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
        };

        match worker.builds.request(&build).await {
            Ok(true) => info!(
                app = %tracking.app,
                revision = %revision,
                repository = %tracking.repository,
                "a build was asked for",
            ),
            // Already asked for, being built, or long since built. The ordinary
            // answer, and the reason this may run every pass.
            Ok(false) => {}
            Err(error) => warn!(
                app = %tracking.app,
                error = %format!("{error:#}"),
                "could not ask for a build",
            ),
        }
    }
}

/// Take one claimed build to a terminal state, whatever happens.
///
/// The one place a build's outcome is written down, so that no step can end
/// without the row ending with it: a `building` row nobody is building is
/// exactly what [`BuildRepository::reset_interrupted`] exists to clean up after
/// a crash, and it should not be produced by ordinary failure as well.
async fn run(worker: &Worker, policy: &Policy, build: &Build) {
    match produce(worker, policy, build).await {
        Ok(produced) => {
            match worker
                .builds
                .succeeded(
                    &build.app,
                    &build.revision,
                    &produced.tag,
                    &produced.id,
                    &produced.manifest,
                    &produced.log,
                )
                .await
            {
                // After the row and never before, and only when there is one:
                // the deploying loop reads the builds for itself, so a shove
                // that arrived first would send it to look at a revision that
                // is not recorded as built yet — and it would find the one
                // before it and believe it. The same order a push writes a
                // revision down in before waking this loop.
                Ok(()) => worker.deploys.nudge(),
                Err(error) => warn!(
                    app = %build.app,
                    error = %format!("{error:#}"),
                    "could not record a build that succeeded",
                ),
            }

            // After the record and not before: a sweep that fails must not cost
            // the image it was tidying up after. Old trees are worth exactly
            // what the commits they came from are, which is nothing — the
            // commit is still on GitHub.
            match worker
                .directory
                .sweep(&build.connection, &build.app, policy.keep)
            {
                Ok(0) => {}
                Ok(swept) => debug!(app = %build.app, swept, "removed builds that had aged out"),
                Err(error) => warn!(
                    app = %build.app,
                    error = %format!("{error:#}"),
                    "could not remove the builds that had aged out",
                ),
            }

            info!(
                app = %build.app,
                revision = %build.revision,
                image = %produced.tag,
                "built this app's revision",
            );
        }
        Err(failure) => {
            let reason = format!("{:#}", failure.error);

            if let Err(error) = worker
                .builds
                .failed(&build.app, &build.revision, &reason, &failure.log)
                .await
            {
                warn!(
                    app = %build.app,
                    error = %format!("{error:#}"),
                    "could not record a build that failed",
                );
            }

            warn!(
                app = %build.app,
                revision = %build.revision,
                %reason,
                "could not build this app's revision",
            );
        }
    }
}

/// The image one build resolved to, and what the engine said on the way.
struct Produced {
    tag: String,
    /// The engine's own id, and empty for an image spaceport did not build —
    /// see [`produce`].
    id: String,
    /// The manifest document as the commit carried it, passed on untouched.
    ///
    /// Filled in by [`produce`] rather than by [`resolve`], so that the two
    /// kinds of manifest cannot disagree about whether it was worth keeping:
    /// the revision that named a prebuilt image is exactly the one whose
    /// document a deploy has no other way of finding, since no unpacked tree of
    /// it will still be on this host by then.
    manifest: String,
    log: String,
}

/// Why a build did not produce an image, and whatever output there was.
///
/// The log is carried separately from the error because only one step has one:
/// the engine's output is the operator's second question after "why did it
/// fail", and every earlier step's whole answer is the sentence.
struct Failure {
    error: anyhow::Error,
    log: String,
}

impl From<anyhow::Error> for Failure {
    fn from(error: anyhow::Error) -> Self {
        Self {
            error,
            log: String::new(),
        }
    }
}

/// Fetch, unpack, read and build one revision.
///
/// Every `?` here is a build that fails with the sentence its context wrote —
/// this is where an operator's "why is my app not building" is answered, so
/// each one names the thing that would not work rather than the call that
/// returned an error.
async fn produce(worker: &Worker, policy: &Policy, build: &Build) -> Result<Produced, Failure> {
    let connection = worker
        .connections
        .by_slug(&build.connection)
        .await
        .with_context(|| format!("looking up the connection `{}`", build.connection))?
        .with_context(|| {
            format!(
                "the connection `{}` this app is built through is no longer connected",
                build.connection
            )
        })?;

    let (installation_id, full_name) = worker
        .connections
        .installation_for(connection.app_id, &build.repository)
        .await
        .with_context(|| format!("finding what grants `{}`", build.repository))?
        .with_context(|| {
            format!(
                "no installation of `{}` grants `{}` — either the app was removed from it, or spaceport's copy of what it reaches is older than the installation is",
                connection.slug, build.repository
            )
        })?;

    let client = Client::new(&connection, worker.github.clone())
        .with_context(|| format!("acting as the app `{}`", connection.slug))?;

    // GitHub's own sentence, unwrapped: `archive_location` already says which
    // repository at which revision it was asking about, and a context here
    // would only say it twice.
    let location = client
        .archive_location(installation_id, &full_name, &build.revision)
        .await?;
    let archive = worker
        .archives
        .fetch(&location, policy.max_archive_bytes)
        .await
        .with_context(|| format!("downloading the commit `{}`", build.revision))?;

    let tree = worker
        .directory
        .prepare(&build.connection, &build.app, &build.revision)
        .context("making somewhere to unpack the commit")?;
    let unpacked = unpack(&archive, &tree, &policy.unpacked)
        .with_context(|| format!("unpacking the commit `{}`", build.revision))?;
    debug!(
        app = %build.app,
        revision = %build.revision,
        entries = unpacked.entries,
        bytes = unpacked.bytes,
        "unpacked a commit",
    );

    // Checked again, though `spaceport apps track` checked it when the tracking
    // was recorded. That check was against a value on its way into a database;
    // this is the moment the same value becomes a path on this host, and a
    // string that has been through a database is a string that was last
    // validated by another version of this program.
    let manifest_path = inside(&tree, &build.manifest_path)?;
    let raw = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "reading the manifest `{}` out of the commit",
            build.manifest_path
        )
    })?;
    let manifest = AppManifest::parse(&raw)
        .with_context(|| format!("reading the manifest `{}`", build.manifest_path))?;

    let produced = resolve(worker, build, &tree, manifest.source).await?;

    // The document itself and not `manifest` re-serialised: what is written
    // down has to be what somebody wrote, so that an operator reading it back
    // is reading their own file rather than this build's idea of the schema.
    Ok(Produced {
        manifest: raw,
        ..produced
    })
}

/// What the revision's manifest says the image is.
///
/// The two arms are the same answer in two shapes, and that is the whole point.
/// The question a build answers is "which image does this revision resolve
/// to", and a manifest naming a prebuilt image has answered it without the
/// engine being asked anything — so it is recorded as a build that succeeded,
/// with that image as the tag, rather than skipped or refused. A deploy then
/// reads one thing from one place, whichever kind of manifest produced it.
///
/// What such a build has no answer for is the engine's id, because there is no
/// engine in it: the image is whatever the registry serves under that name at
/// the moment something pulls it, which is not a fact this host holds. The
/// column keeps that as nothing, which is the honest answer.
///
/// The dockerfile is taken as a path inside the context rather than inside the
/// repository, which is what every compose file an operator has ever written
/// means by the pair of fields. The rejected alternative was reading it from
/// the repository root and stripping the context off the front: it makes the
/// two spellings ambiguous where the context is the root, and it turns a
/// manifest that names a dockerfile outside its own context into a build that
/// the engine could not have performed anyway.
async fn resolve(
    worker: &Worker,
    build: &Build,
    tree: &Path,
    source: Source,
) -> Result<Produced, Failure> {
    let (dockerfile, context) = match source {
        Source::Image { image } => {
            debug!(
                app = %build.app,
                revision = %build.revision,
                %image,
                "the manifest of this revision names a prebuilt image",
            );

            return Ok(Produced {
                tag: image,
                id: String::new(),
                // Filled in by the caller, which is the only one holding the
                // document — see [`Produced::manifest`].
                manifest: String::new(),
                log: String::new(),
            });
        }
        Source::Build {
            dockerfile,
            context,
        } => (dockerfile, context),
    };

    // Both paths come out of a document in somebody's repository, and both were
    // checked when the manifest was parsed. They are checked again here for the
    // reason the manifest path is: this is where they become paths on this
    // host.
    let context = inside(tree, &context.to_string_lossy())?;
    let dockerfile = relative(&dockerfile)?;

    let request = BuildRequest {
        context,
        dockerfile,
        tag: tag(&build.app, &build.revision),
        labels: labels(&build.app, &build.revision),
    };

    let image = worker
        .images
        .build(&request)
        .await
        .map_err(|error| Failure {
            error: error.context(format!("building the image for `{}`", build.revision)),
            log: String::new(),
        })?;

    Ok(Produced {
        tag: image.tag,
        id: image.id,
        manifest: String::new(),
        log: image.log.join("\n"),
    })
}

/// What every image spaceport builds is stamped with.
///
/// Enough for an operator with nothing but `docker images` to answer the three
/// questions they will have: is this spaceport's, whose is it, and which commit
/// is it.
fn labels(app: &AppId, revision: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.to_owned(), "true".to_owned()),
        (APP_LABEL.to_owned(), app.to_string()),
        (REVISION_LABEL.to_owned(), revision.to_owned()),
    ])
}

/// `relative`, resolved under `tree`, if it stays there.
fn inside(tree: &Path, relative_path: &str) -> Result<PathBuf> {
    Ok(tree.join(relative(Path::new(relative_path))?))
}

/// `path`, if it is a path inside the tree it is named from.
///
/// Component-wise rather than by looking for `..` in the text: a path is not a
/// string, and `a..b` is an ordinary directory name a substring search would
/// refuse. The sentence names the offending path, because the operator who has
/// to fix it is looking at a manifest and not at this code.
fn relative(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("a path inside the repository was left empty");
    }
    if path.is_absolute() {
        bail!(
            "`{}` is an absolute path, and everything a build reads is named from the root of the repository",
            path.display()
        );
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!(
            "`{}` climbs out of the repository, and a build reads nothing outside the commit it is building",
            path.display()
        );
    }

    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytes::Bytes;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder as TarBuilder, EntryType, Header};

    use super::super::image::BuiltImage;
    use crate::connections::Secret;
    use crate::connections::github::api::testing::FakeGitHub;
    use crate::connections::github::key;
    use crate::connections::github::repository::{Connection, Installation};
    use crate::connections::github::tracking::Tracking;
    use crate::state::Db;

    const APP_ID: i64 = 42;
    const INSTALLATION: i64 = 7;
    const SLUG: &str = "spaceport-for-acme";
    const REPOSITORY: &str = "an-organisation/site";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";
    /// Where this GitHub says its tarballs are. On the pinned host, because the
    /// real downloader would refuse anything else and a fixture that could not
    /// be fetched in production is a fixture that says nothing.
    const LOCATION: &str = "https://codeload.github.com/an-organisation/site/legacy.tar.gz/0123456";
    const OTHER_LOCATION: &str =
        "https://codeload.github.com/an-organisation/site/legacy.tar.gz/89abcde";
    /// The directory GitHub wraps a commit in.
    const PREFIX: &str = "an-organisation-site-0123abc";

    const BUILT_MANIFEST: &str = "\
schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
routing:
  hosts: [site.example.com]
";

    const PREBUILT_MANIFEST: &str = "\
schema_version: 1
source:
  type: image
  image: ghcr.io/an-organisation/site:v1
routing:
  hosts: [site.example.com]
";

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    /// A directory of this test's own, under the system temp dir.
    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("spaceport-worker-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&directory);

        directory
    }

    /// A gzipped tarball shaped as GitHub's are: one wrapper directory, and the
    /// files under it.
    fn commit(files: &[(&str, &str)]) -> Bytes {
        let mut builder = TarBuilder::new(Vec::new());
        for (path, contents) in files {
            let path = format!("{PREFIX}/{path}");
            let mut header = Header::new_gnu();
            header.set_path(&path).unwrap();
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append(&header, contents.as_bytes()).unwrap();
        }
        let tar = builder.into_inner().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&tar).unwrap();

        Bytes::from(encoder.finish().unwrap())
    }

    /// An ordinary commit: a manifest and something to build.
    fn a_commit(manifest: &str) -> Bytes {
        commit(&[
            ("spaceport.yaml", manifest),
            ("Dockerfile", "FROM scratch\n"),
        ])
    }

    /// The archives spaceport is told to download, answered in this process.
    ///
    /// Keyed by url rather than by repository, because the url is the whole of
    /// what the worker knows by the time it gets here — which is also what says
    /// the location GitHub gave really is the one that was fetched.
    struct FakeArchives {
        by_url: Mutex<BTreeMap<String, Bytes>>,
        fetched: Mutex<Vec<String>>,
    }

    impl FakeArchives {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                by_url: Mutex::new(BTreeMap::new()),
                fetched: Mutex::new(Vec::new()),
            })
        }

        fn holds(&self, url: &str, archive: Bytes) {
            self.by_url.lock().unwrap().insert(url.to_owned(), archive);
        }

        fn fetches(&self) -> Vec<String> {
            self.fetched.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Archives for FakeArchives {
        async fn fetch(&self, url: &str, _limit: u64) -> Result<Bytes> {
            self.fetched.lock().unwrap().push(url.to_owned());

            match self.by_url.lock().unwrap().get(url) {
                Some(archive) => Ok(archive.clone()),
                None => bail!("the archive's download location answered 404"),
            }
        }
    }

    /// An engine that builds whatever it is given, or refuses everything.
    struct FakeEngine {
        requests: Mutex<Vec<BuildRequest>>,
        refuses: Mutex<bool>,
    }

    impl FakeEngine {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                refuses: Mutex::new(false),
            })
        }

        fn refuses_everything(&self) {
            *self.refuses.lock().unwrap() = true;
        }

        fn requests(&self) -> Vec<BuildRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ImageBuilder for FakeEngine {
        async fn build(&self, request: &BuildRequest) -> Result<BuiltImage> {
            self.requests.lock().unwrap().push(request.clone());

            if *self.refuses.lock().unwrap() {
                bail!("the engine could not read the dockerfile");
            }

            Ok(BuiltImage {
                tag: request.tag.clone(),
                id: format!("sha256:{}", request.tag.len()),
                log: vec!["step 1/1 : FROM scratch".to_owned()],
            })
        }
    }

    /// A connection as one is read back out of the state store, with the
    /// fixture key so a client can be built from it and can sign.
    fn connection() -> Connection {
        Connection {
            slug: SLUG.to_owned(),
            app_id: APP_ID,
            name: "Spaceport for Acme".to_owned(),
            owner: "an-organisation".to_owned(),
            client_id: "Iv1.0123456789abcdef".to_owned(),
            client_secret: Secret::new("a-client-secret"),
            webhook_secret: Secret::new("a-webhook-secret"),
            private_key: Secret::new(key::testing::PKCS1),
            connected_at: String::new(),
        }
    }

    /// A worker over an in-memory state store, with fakes for everything
    /// outside this process, and the temp root to take away afterwards.
    struct Fixture {
        worker: Arc<Worker>,
        archives: Arc<FakeArchives>,
        engine: Arc<FakeEngine>,
        /// The same signal the worker holds, so a test can ask whether an image
        /// finishing woke the loop that would run it.
        deploys: Nudge,
        root: PathBuf,
    }

    impl Fixture {
        /// A spaceport that has one connection, one installation granting
        /// [`REPOSITORY`], and a GitHub that says where its tarballs are.
        async fn new(name: &str) -> Self {
            let db = Db::in_memory().unwrap();
            let connections = ConnectionRepository::new(db.clone());
            connections.record(&connection()).await.unwrap();
            connections
                .record_installations(
                    APP_ID,
                    &[Installation {
                        installation_id: INSTALLATION,
                        account: "an-organisation".to_owned(),
                        account_type: "Organization".to_owned(),
                        repositories: vec![REPOSITORY.to_owned()],
                    }],
                )
                .await
                .unwrap();

            let github = FakeGitHub::new();
            github.archives_at(REPOSITORY, REVISION, LOCATION);
            github.archives_at(REPOSITORY, OTHER_REVISION, OTHER_LOCATION);

            let archives = FakeArchives::new();
            let engine = FakeEngine::new();
            let deploys = Nudge::new();
            let root = temp_dir(name);

            Self {
                worker: Arc::new(Worker {
                    builds: BuildRepository::new(db.clone()),
                    trackings: Arc::new(TrackingRepository::new(db.clone())),
                    connections: Arc::new(connections),
                    github: github.clone(),
                    archives: archives.clone(),
                    images: engine.clone(),
                    directory: BuildDir::new(root.join("builds")),
                    deploys: deploys.clone(),
                }),
                archives,
                engine,
                deploys,
                root,
            }
        }

        /// Track `id` against [`REPOSITORY`], at `revision` if there is one.
        ///
        /// The two writes `spaceport apps track` makes, in its order: the
        /// tracking row, and then the head of the branch it bound. A push
        /// writes the second of them too, so a tracking with a revision is the
        /// same row whichever put it there — and the case with no revision at
        /// all is the one that is now only reachable when a `record_revision`
        /// failed.
        async fn track(&self, id: &str, revision: Option<&str>) {
            self.worker
                .trackings
                .record(
                    &Tracking {
                        app: app(id),
                        github_app_id: APP_ID,
                        repository: REPOSITORY.to_owned(),
                        branch: "main".to_owned(),
                        manifest_path: "spaceport.yaml".to_owned(),
                        tracked_at: String::new(),
                        revision: None,
                        revision_seen_at: None,
                        automatic: false,
                    },
                    None,
                )
                .await
                .unwrap();

            if let Some(revision) = revision {
                self.worker
                    .trackings
                    .record_revision(&app(id), revision)
                    .await
                    .unwrap();
            }
        }

        async fn pass(&self) {
            pass(&self.worker, &Policy::default(), &CancellationToken::new()).await;
        }

        async fn build_of(&self, id: &str, revision: &str) -> Build {
            self.worker
                .builds
                .get(&app(id), revision)
                .await
                .unwrap()
                .unwrap()
        }

        /// The whole reason each test makes its own root: a build writes a
        /// source tree onto this host.
        fn clean_up(&self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// A tracking with a revision is what says a commit is wanted, and the pass
    /// reads that rather than being told it.
    ///
    /// Which is what makes `spaceport apps track` build anything: it records
    /// the head of the branch it bound, so this pass has work before any push
    /// has arrived — a repository whose last commit is older than the tracking
    /// would otherwise never be built at all.
    #[tokio::test]
    async fn a_tracked_revision_is_asked_for_as_a_build() {
        let fixture = Fixture::new("asks-for-a-build").await;
        fixture.track("site", Some(REVISION)).await;
        // Nothing to fetch, so the build fails — what is under test is that it
        // was asked for at all.
        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.connection, SLUG);
        assert_eq!(build.repository, REPOSITORY);
        assert_eq!(build.branch, "main");
        assert_eq!(build.manifest_path, "spaceport.yaml");

        fixture.clean_up();
    }

    /// An app pointed at a branch nothing has been taken from yet is not a
    /// build waiting to happen.
    #[tokio::test]
    async fn a_tracking_without_a_revision_asks_for_nothing() {
        let fixture = Fixture::new("no-revision").await;
        fixture.track("site", None).await;

        fixture.pass().await;

        assert!(
            fixture
                .worker
                .builds
                .by_app(&app("site"))
                .await
                .unwrap()
                .is_empty()
        );

        fixture.clean_up();
    }

    #[tokio::test]
    async fn a_pass_builds_a_revision_and_records_the_image() {
        let fixture = Fixture::new("builds-a-revision").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Built, "{:?}", build.reason);
        assert_eq!(build.image_tag.as_deref(), Some("spaceport/site:0123456"));
        assert!(build.image_id.unwrap().starts_with("sha256:"));
        assert!(build.log.unwrap().contains("FROM scratch"));
        // The document out of the commit, byte for byte — the tree it came from
        // is swept long before a deploy asks what it said.
        assert_eq!(build.manifest.as_deref(), Some(BUILT_MANIFEST));
        // The location GitHub gave is the one that was fetched, rather than a
        // url built out of what spaceport happens to know.
        assert_eq!(fixture.archives.fetches(), [LOCATION]);

        // And what the engine was asked for: the unpacked tree as the context,
        // the dockerfile inside it, and the labels that say whose image it is.
        let requests = fixture.engine.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].dockerfile, PathBuf::from("Dockerfile"));
        assert!(requests[0].context.join("Dockerfile").is_file());
        assert_eq!(requests[0].labels[MANAGED_LABEL], "true");
        assert_eq!(requests[0].labels[APP_LABEL], "site");
        assert_eq!(requests[0].labels[REVISION_LABEL], REVISION);

        fixture.clean_up();
    }

    /// The question a build answers is which image a revision resolves to, and
    /// a manifest naming a prebuilt image has answered it — without the engine
    /// being asked anything at all.
    #[tokio::test]
    async fn a_manifest_naming_a_prebuilt_image_succeeds_without_the_engine() {
        let fixture = Fixture::new("prebuilt-image").await;
        fixture.track("site", Some(REVISION)).await;
        fixture
            .archives
            .holds(LOCATION, a_commit(PREBUILT_MANIFEST));

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Built, "{:?}", build.reason);
        assert_eq!(
            build.image_tag.as_deref(),
            Some("ghcr.io/an-organisation/site:v1")
        );
        assert!(fixture.engine.requests().is_empty());
        // Never through the engine, and still the revision whose manifest a
        // deploy has nowhere else to read.
        assert_eq!(build.manifest.as_deref(), Some(PREBUILT_MANIFEST));

        fixture.clean_up();
    }

    /// An image that exists is the moment an armed app's commit can be run, and
    /// an operator watching a push should not wait out the deploying loop's
    /// interval to see it happen.
    #[tokio::test]
    async fn a_build_that_succeeded_wakes_the_deploying_loop() {
        let fixture = Fixture::new("wakes-the-deployer").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        let woken = fixture.deploys.changed();

        fixture.pass().await;

        assert!(woken.has_changed().unwrap());

        fixture.clean_up();
    }

    /// A build that produced no image is nothing to deploy, and the loop it
    /// would wake would read the same rows it read last time.
    #[tokio::test]
    async fn a_build_that_failed_wakes_the_deploying_loop_for_nothing() {
        let fixture = Fixture::new("does-not-wake-the-deployer").await;
        fixture.track("site", Some(REVISION)).await;
        let woken = fixture.deploys.changed();

        fixture.pass().await;

        assert_eq!(
            fixture.build_of("site", REVISION).await.state,
            BuildState::Failed
        );
        assert!(!woken.has_changed().unwrap());

        fixture.clean_up();
    }

    /// Spaceport's copy of what an installation reaches can be older than the
    /// installation is, and the sentence has to say so — this is the failure an
    /// operator hits the day they move a repository between organisations.
    #[tokio::test]
    async fn a_repository_no_installation_grants_fails_with_a_readable_reason() {
        let fixture = Fixture::new("ungranted-repository").await;
        fixture
            .worker
            .connections
            .record_installations(APP_ID, &[])
            .await
            .unwrap();
        fixture.track("site", Some(REVISION)).await;

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("no installation"), "{reason}");
        assert!(reason.contains(REPOSITORY), "{reason}");

        fixture.clean_up();
    }

    /// The link GitHub hands out is good for a few minutes, so a download that
    /// fails is an ordinary outcome and has to read like one.
    #[tokio::test]
    async fn an_archive_that_will_not_download_fails_the_build() {
        let fixture = Fixture::new("archive-refused").await;
        fixture.track("site", Some(REVISION)).await;

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("downloading the commit"), "{reason}");

        fixture.clean_up();
    }

    #[tokio::test]
    async fn a_commit_without_a_manifest_fails_the_build() {
        let fixture = Fixture::new("no-manifest").await;
        fixture.track("site", Some(REVISION)).await;
        fixture
            .archives
            .holds(LOCATION, commit(&[("README.md", "hello")]));

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("spaceport.yaml"), "{reason}");

        fixture.clean_up();
    }

    #[tokio::test]
    async fn a_manifest_that_will_not_parse_fails_the_build() {
        let fixture = Fixture::new("bad-manifest").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(
            LOCATION,
            commit(&[("spaceport.yaml", "schema_version: 1\nsource: nonsense\n")]),
        );

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("manifest"), "{reason}");

        fixture.clean_up();
    }

    /// A manifest may not name a file outside the commit, and this is the check
    /// that stands between a document in somebody's repository and this host's
    /// filesystem.
    #[tokio::test]
    async fn a_manifest_path_that_climbs_out_of_the_tree_fails_the_build() {
        let fixture = Fixture::new("escaping-manifest-path").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        // Written straight into the row, exactly as one that had been through a
        // database written by another version of this program would be.
        fixture
            .worker
            .trackings
            .record(
                &Tracking {
                    app: app("site"),
                    github_app_id: APP_ID,
                    repository: REPOSITORY.to_owned(),
                    branch: "main".to_owned(),
                    manifest_path: "../../../etc/spaceport/spaceport.yaml".to_owned(),
                    tracked_at: String::new(),
                    revision: None,
                    revision_seen_at: None,
                    automatic: false,
                },
                None,
            )
            .await
            .unwrap();
        fixture
            .worker
            .trackings
            .record_revision(&app("site"), REVISION)
            .await
            .unwrap();

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("climbs out of the repository"), "{reason}");

        fixture.clean_up();
    }

    #[tokio::test]
    async fn an_engine_that_refuses_fails_the_build() {
        let fixture = Fixture::new("engine-refuses").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        fixture.engine.refuses_everything();

        fixture.pass().await;

        let build = fixture.build_of("site", REVISION).await;
        assert_eq!(build.state, BuildState::Failed);
        let reason = build.reason.unwrap();
        assert!(reason.contains("building the image"), "{reason}");
        assert!(reason.contains("dockerfile"), "{reason}");

        fixture.clean_up();
    }

    /// One app whose commit will not build is not a reason for every other app
    /// on the host to stop being built — the same discipline the reconciler
    /// applies per connection.
    #[tokio::test]
    async fn a_build_that_failed_does_not_stop_the_next_one() {
        let fixture = Fixture::new("one-failure").await;
        fixture.track("broken", Some(REVISION)).await;
        fixture.track("site", Some(OTHER_REVISION)).await;
        fixture
            .archives
            .holds(OTHER_LOCATION, a_commit(BUILT_MANIFEST));

        fixture.pass().await;

        assert_eq!(
            fixture.build_of("broken", REVISION).await.state,
            BuildState::Failed
        );
        let built = fixture.build_of("site", OTHER_REVISION).await;
        assert_eq!(built.state, BuildState::Built, "{:?}", built.reason);

        fixture.clean_up();
    }

    /// A build claimed by a process that was then killed is a row nothing in
    /// memory can find. `maintain` returns it to the queue at startup, which is
    /// the only reason such a commit is ever built.
    #[tokio::test(start_paused = true)]
    async fn a_build_interrupted_by_a_restart_is_built_after_it() {
        let fixture = Fixture::new("interrupted").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        // The last run of this spaceport got as far as claiming it, and then
        // the host lost power: the row says `building` and nothing is.
        fixture
            .worker
            .builds
            .request(&build_row("site", REVISION))
            .await
            .unwrap();
        let claimed = fixture.worker.builds.claim().await.unwrap().unwrap();
        assert_eq!(claimed.state, BuildState::Building);

        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            fixture.worker.clone(),
            Policy::default(),
            Nudge::new(),
            shutdown.clone(),
        ));
        until_built(&fixture, "site", REVISION).await;
        shutdown.cancel();
        running.await.unwrap();

        assert_eq!(
            fixture.build_of("site", REVISION).await.state,
            BuildState::Built
        );

        fixture.clean_up();
    }

    /// A build as a pass would have asked for one.
    fn build_row(id: &str, revision: &str) -> Build {
        Build {
            app: app(id),
            revision: revision.to_owned(),
            connection: SLUG.to_owned(),
            repository: REPOSITORY.to_owned(),
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

    /// Give the loop enough turns to have acted on what it has been told,
    /// without moving the clock: a nudge wakes a task, and a task that has not
    /// been polled yet has not started settling on it.
    async fn let_the_loop_run() {
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
    }

    /// Let the loop run until it has built `revision`, without moving the
    /// clock: a test that slept would be a test that let the interval elapse
    /// behind its own back.
    async fn until_built(fixture: &Fixture, id: &str, revision: &str) {
        for _ in 0..10_000 {
            if fixture
                .worker
                .builds
                .built(&app(id), revision)
                .await
                .unwrap()
                .is_some()
            {
                return;
            }

            tokio::task::yield_now().await;
        }

        panic!("`{id}` was never built at `{revision}`");
    }

    /// The property that makes running a pass every five minutes free: a
    /// revision already answered for is not answered for again, so a second
    /// pass asks the engine nothing.
    #[tokio::test]
    async fn a_second_pass_does_not_build_the_same_revision_twice() {
        let fixture = Fixture::new("idempotent-pass").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));

        fixture.pass().await;
        fixture.pass().await;

        assert_eq!(fixture.engine.requests().len(), 1);
        assert_eq!(fixture.archives.fetches().len(), 1);
        assert_eq!(
            fixture
                .worker
                .builds
                .by_app(&app("site"))
                .await
                .unwrap()
                .len(),
            1
        );

        fixture.clean_up();
    }

    /// A push that reaches this spaceport must not wait out the interval, which
    /// is the whole reason the loop takes a nudge at all.
    #[tokio::test(start_paused = true)]
    async fn a_nudge_builds_a_revision_the_interval_would_have_left_for_minutes() {
        let fixture = Fixture::new("nudged").await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        let policy = Policy::default();
        let nudge = Nudge::new();
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            fixture.worker.clone(),
            policy.clone(),
            nudge.clone(),
            shutdown.clone(),
        ));
        // The first pass has nothing to do, and has to have finished before the
        // revision arrives — otherwise it is the pass under test.
        let_the_loop_run().await;
        fixture.track("site", Some(REVISION)).await;

        let woken = tokio::time::Instant::now();
        nudge.nudge();
        let_the_loop_run().await;
        tokio::time::advance(policy.settle.unsigned_abs()).await;
        until_built(&fixture, "site", REVISION).await;

        assert!(
            woken.elapsed() < policy.interval.unsigned_abs(),
            "the build waited out the interval"
        );
        shutdown.cancel();
        running.await.unwrap();

        fixture.clean_up();
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_stops_when_it_is_shut_down() {
        let fixture = Fixture::new("shuts-down").await;
        fixture.track("site", Some(REVISION)).await;
        fixture.archives.holds(LOCATION, a_commit(BUILT_MANIFEST));
        let shutdown = CancellationToken::new();

        let running = tokio::spawn(maintain(
            fixture.worker.clone(),
            Policy::default(),
            Nudge::new(),
            shutdown.clone(),
        ));
        until_built(&fixture, "site", REVISION).await;
        // Cancelled while the loop is sleeping off an interval that is minutes
        // away: without the select arm this would never return.
        shutdown.cancel();
        running.await.unwrap();

        fixture.clean_up();
    }

    #[test]
    fn refuses_a_path_that_does_not_stay_inside_the_commit() {
        let tree = Path::new("/var/lib/spaceport/builds/x");

        assert_eq!(
            inside(tree, "spaceport.yaml").unwrap(),
            tree.join("spaceport.yaml")
        );
        assert_eq!(
            inside(tree, "deploy/spaceport.yaml").unwrap(),
            tree.join("deploy/spaceport.yaml")
        );
        for bad in ["/etc/passwd", "../../etc/passwd", "deploy/../../..", ""] {
            assert!(inside(tree, bad).is_err(), "accepted `{bad}`");
        }
    }
}
