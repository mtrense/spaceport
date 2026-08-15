//! Where a commit is unpacked and built on the host.
//!
//! A build needs somewhere to put a tree of somebody else's source code, and it
//! needs that somewhere to be its own. The path is
//! `<build-dir>/<connection-slug>/<app-id>/<revision>/`: the connection says
//! which GitHub App the commit came through, the app says what is being built,
//! and the revision says which commit — three segments that together name one
//! attempt at one build and never collide with another.
//!
//! **This module deletes, and [`crate::app::data`] never does.** The two look
//! alike — a root, an app segment, a path builder, a `create` — and they are
//! opposites in the one respect that matters. A volume is the app's data and
//! outlives everything; a build tree is scratch space that is worth exactly as
//! much as the commit it can be rebuilt from. [`BuildDir::prepare`] throws away
//! what it finds and [`BuildDir::sweep`] throws away what has aged out. Reach
//! for the wrong one of the two modules and the thing that goes missing is
//! somebody's database.
//!
//! Mode `0o700`, where the data directory is `0o711`. The data directory is
//! traversable because an operator and a container both have business reaching
//! into it. Nobody has business reaching in here: this is an application's
//! source code, checked out of a private repository under credentials the host
//! holds, and the host's other users are not party to it. Not listable, not
//! traversable, spaceport's own.
//!
//! The safety of the three segments is *enforced* here, not assumed. An
//! [`AppId`] is already restricted to lowercase letters, digits and hyphens by
//! the type that carries it, but a connection slug is a `String` and a revision
//! is a string that arrived in a webhook payload — so both are checked against
//! the alphabet they are supposed to be drawn from before either reaches the
//! filesystem. A segment made only of hex digits, or only of GitHub's slug
//! characters, cannot be `..`, cannot contain a separator, and cannot name
//! anything outside the tree. A revision that does not conform is an error and
//! not something to sanitise: a payload that says something unexpected is a
//! payload to refuse, and quietly stripping characters out of a sha would build
//! a commit nobody asked for.
//!
//! Nothing here fetches, unpacks or builds. This module only decides where a
//! build's directory is, makes it, and takes it away again.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tracing::debug;

use crate::app::AppId;

/// Path used when the config names no build directory.
pub const DEFAULT_BUILD_DIR: &str = "/var/lib/spaceport/builds";

/// How many built revisions of an app to keep when the config says nothing.
///
/// Three: the one running, the one before it that a rollback would go back to,
/// and the one being built. Fewer leaves nothing to fall back on, and more
/// keeps whole source trees on disk that nothing will read again.
pub const DEFAULT_REVISIONS_KEPT: usize = 3;

/// Neither listable nor traversable by anyone but spaceport — see the module
/// header. An app's source code is not the host's business.
#[cfg(unix)]
const BUILD_DIR_MODE: u32 = 0o700;

/// Longest a revision may be. A sha-256 object id is 64 hex digits, and
/// nothing git names is longer.
const MAX_REVISION_LEN: usize = 64;

/// Shortest a revision may be. Git's own abbreviations start at four, and a
/// one-character "sha" is a sign the payload was read wrong rather than a
/// commit worth building.
const MIN_REVISION_LEN: usize = 4;

/// Longest a connection slug may be. GitHub caps an App's name well below this
/// and derives the slug from it; the bound is here so that a slug can never be
/// the reason a path exceeds what the host will take.
const MAX_SLUG_LEN: usize = 64;

/// The directory builds are unpacked and run under.
#[derive(Debug, Clone)]
pub struct BuildDir {
    root: PathBuf,
}

impl BuildDir {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the build directory, if it is not already there.
    pub fn create(&self) -> Result<()> {
        if self.root.is_dir() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating the build directory `{}`", self.root.display()))?;
        set_mode(&self.root, BUILD_DIR_MODE)?;

        Ok(())
    }

    /// Everything built for one app of one connection.
    ///
    /// Composition only — the checks live on the two methods that touch the
    /// disk, so that no caller can reach the filesystem with a segment that was
    /// never looked at.
    pub fn app(&self, connection: &str, app: &AppId) -> PathBuf {
        self.root.join(connection).join(app.as_str())
    }

    /// Where one revision of one app is unpacked. Composition only, as
    /// [`BuildDir::app`] is.
    pub fn revision(&self, connection: &str, app: &AppId, revision: &str) -> PathBuf {
        self.app(connection, app).join(revision)
    }

    /// Make an empty directory for `revision` and hand back its path.
    ///
    /// Anything already at that path goes first. This is the deliberate
    /// opposite of [`crate::app::data::DataDir::provision`], which leaves what
    /// it finds: a volume that is already there is the app's data and reusing
    /// it is the whole point, whereas a build tree that is already there is the
    /// wreckage of a build that died partway through unpacking. Building on top
    /// of it would mean building a commit that is half one tree and half
    /// another — which compiles often enough to be dangerous. A build is cheap
    /// to repeat and the archive is still where it came from, so the safe
    /// reading of an existing tree is that it is worthless.
    pub fn prepare(&self, connection: &str, app: &AppId, revision: &str) -> Result<PathBuf> {
        check_slug(connection)?;
        check_revision(revision)?;

        self.create()?;
        let connection_dir = self.root.join(connection);
        make_dir(&connection_dir)?;
        let app_dir = connection_dir.join(app.as_str());
        make_dir(&app_dir)?;

        let path = app_dir.join(revision);
        remove(&path)?;
        std::fs::create_dir(&path).with_context(|| {
            format!(
                "creating the build directory for `{app}` at `{}`",
                path.display()
            )
        })?;
        set_mode(&path, BUILD_DIR_MODE)?;

        Ok(path)
    }

    /// Keep the newest `keep` revisions of `app` and remove the rest, returning
    /// how many were removed.
    ///
    /// Newest by the directory's modification time, not by its name: a sha
    /// sorts lexicographically and lexicographic order over shas is noise, so
    /// sorting by name would keep an arbitrary three and delete the running
    /// one. `prepare` creates the directory, which sets its mtime, and that is
    /// the only ordering here that means anything.
    ///
    /// Only directories whose names are revisions are considered — a stranger
    /// in the tree is left where it is rather than swept up by a routine that
    /// was not asked to have an opinion about it. Symlinks are never followed
    /// and never removed, so a link planted in the tree cannot make this delete
    /// something outside it. Neither the app's directory nor the connection's
    /// is ever removed: they cost an inode, and an empty one is the normal
    /// state of an app between its first tracking and its first build.
    pub fn sweep(&self, connection: &str, app: &AppId, keep: usize) -> Result<usize> {
        check_slug(connection)?;

        let app_dir = self.app(connection, app);
        let entries = match std::fs::read_dir(&app_dir) {
            Ok(entries) => entries,
            // Nothing has been built for this app yet, which is not a failure
            // to sweep — it is nothing to sweep.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("listing the builds of `{app}` in `{}`", app_dir.display())
                });
            }
        };

        let mut revisions = Vec::new();
        for entry in entries {
            let entry =
                entry.with_context(|| format!("reading an entry of `{}`", app_dir.display()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if check_revision(name).is_err() {
                continue;
            }

            // `symlink_metadata`, so that a symlink is judged as a symlink
            // rather than as whatever it points at.
            let metadata = std::fs::symlink_metadata(entry.path())
                .with_context(|| format!("looking at `{}`", entry.path().display()))?;
            if !metadata.is_dir() {
                continue;
            }

            let modified = metadata
                .modified()
                .with_context(|| format!("reading the age of `{}`", entry.path().display()))?;
            revisions.push((modified, entry.path()));
        }

        // Newest first, and by name where two directories share a timestamp, so
        // that a sweep is the same sweep whichever order the directory was read
        // in.
        revisions.sort_by(|left, right| right.0.cmp(&left.0).then(right.1.cmp(&left.1)));

        let mut swept = 0;
        for (_, path) in revisions.into_iter().skip(keep) {
            std::fs::remove_dir_all(&path)
                .with_context(|| format!("removing the old build `{}`", path.display()))?;
            swept += 1;
        }

        if swept > 0 {
            debug!(app = %app, connection, swept, keep, "removed builds that had aged out");
        }

        Ok(swept)
    }
}

/// Create one level of the tree, owner-only, if it is not there yet.
fn make_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }

    std::fs::create_dir_all(path).with_context(|| format!("creating `{}`", path.display()))?;
    set_mode(path, BUILD_DIR_MODE)
}

/// Take away whatever is at `path`, directory or not.
///
/// A symlink is unlinked rather than followed: `remove_dir_all` on a link would
/// be a request to delete whatever it points at, and a build tree is the last
/// place to grant that.
fn remove(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("looking at `{}`", path.display()));
        }
    };

    if metadata.is_dir() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("clearing the build directory `{}`", path.display()))
    } else {
        std::fs::remove_file(path).with_context(|| format!("clearing `{}`", path.display()))
    }
}

/// Refuse a revision that is not a hex object id.
///
/// The revision arrives in a webhook payload, which is to say from the
/// internet. Hex digits and nothing else is what makes the segment safe, and
/// checking is cheaper than reasoning about what GitHub might one day put in
/// that field.
fn check_revision(revision: &str) -> Result<()> {
    if revision.len() < MIN_REVISION_LEN || revision.len() > MAX_REVISION_LEN {
        bail!(
            "`{revision}` is not a revision: a revision is between {MIN_REVISION_LEN} and {MAX_REVISION_LEN} hex digits"
        );
    }
    if !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("`{revision}` is not a revision: a revision is hex digits and nothing else");
    }

    Ok(())
}

/// Refuse a connection slug that is not one of GitHub's.
///
/// The same alphabet [`crate::connections::github::register`] accepts when a
/// connection is recorded, checked again here because this is the point where a
/// slug becomes a path segment and that is not a place to take a value on
/// trust.
fn check_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > MAX_SLUG_LEN {
        bail!(
            "`{slug}` is not a connection slug: a slug is between 1 and {MAX_SLUG_LEN} characters"
        );
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("`{slug}` is not a connection slug: a slug is lowercase letters, digits and hyphens");
    }

    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of `{}`", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test run's own, under the system temp dir. The same
    /// helper [`crate::state`] keeps for its own tests, copied rather than
    /// borrowed because that one lives in a private module of its own crate
    /// subtree.
    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("spaceport-test-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&directory);

        directory
    }

    const REVISION: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c";
    const OLDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn app() -> AppId {
        "my-app".parse().unwrap()
    }

    /// A build directory of this test's own, and the root it sits under so the
    /// test can take the whole thing away again.
    fn builds(name: &str) -> (PathBuf, BuildDir) {
        let root = temp_dir(name);
        let builds = BuildDir::new(root.join("builds"));
        builds.create().unwrap();

        (root, builds)
    }

    /// Give `path` a modification time, so that a sweep's ordering is the
    /// test's to decide rather than the filesystem's clock resolution.
    fn age(path: &Path, seconds: u64) {
        let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        let file = std::fs::File::open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap();
    }

    #[test]
    fn puts_a_revision_under_its_app_and_connection() {
        let builds = BuildDir::new(PathBuf::from("/var/lib/spaceport/builds"));

        assert_eq!(
            builds.app("spaceport-for-acme", &app()),
            Path::new("/var/lib/spaceport/builds/spaceport-for-acme/my-app")
        );
        assert_eq!(
            builds.revision("spaceport-for-acme", &app(), REVISION),
            Path::new("/var/lib/spaceport/builds/spaceport-for-acme/my-app").join(REVISION)
        );
    }

    #[test]
    fn creates_a_directory_for_a_revision() {
        let (root, builds) = builds("prepares-a-revision");

        let path = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();

        assert!(path.is_dir());
        assert_eq!(
            path,
            builds.revision("spaceport-for-acme", &app(), REVISION)
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Half a commit is worse than no commit: an unpack that died partway
    /// through leaves files that would otherwise be built as if they were the
    /// whole tree.
    #[test]
    fn clears_a_tree_a_previous_build_left_behind() {
        let (root, builds) = builds("clears-a-tree");

        let path = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();
        std::fs::write(path.join("half-a-commit.rs"), "fn main() {").unwrap();

        let again = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();

        assert_eq!(again, path);
        assert!(!path.join("half-a-commit.rs").exists());
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The revision comes off a webhook payload, so this is the check that
    /// stands between the internet and a path segment.
    #[test]
    fn refuses_a_revision_that_is_not_a_sha() {
        let (root, builds) = builds("refuses-a-revision");

        for bad in [
            "not-a-sha",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c/../../etc",
            "../../../etc/passwd",
            "..",
            "a/b",
            "",
            "ab",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c0f1e2d3c4b5a69788796a5b4c3",
        ] {
            let error = builds
                .prepare("spaceport-for-acme", &app(), bad)
                .unwrap_err()
                .to_string();

            assert!(error.contains("is not a revision"), "{bad}: {error}");
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_a_connection_slug_that_could_leave_the_tree() {
        let (root, builds) = builds("refuses-a-slug");

        for bad in ["..", "acme/../..", "acme/evil", "Acme", "acme_corp", ""] {
            let error = builds
                .prepare(bad, &app(), REVISION)
                .unwrap_err()
                .to_string();
            assert!(error.contains("is not a connection slug"), "{bad}: {error}");

            let error = builds.sweep(bad, &app(), 1).unwrap_err().to_string();
            assert!(error.contains("is not a connection slug"), "{bad}: {error}");
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sweeps_all_but_the_newest_revisions() {
        let (root, builds) = builds("sweeps-the-oldest");

        let mut paths = Vec::new();
        for (index, revision) in ["a1", "b2", "c3", "d4", "e5"].iter().enumerate() {
            let revision = format!("{revision}{}", "0".repeat(38));
            let path = builds
                .prepare("spaceport-for-acme", &app(), &revision)
                .unwrap();
            age(&path, 1_000 + index as u64 * 60);
            paths.push(path);
        }

        let swept = builds.sweep("spaceport-for-acme", &app(), 2).unwrap();

        assert_eq!(swept, 3);
        assert!(!paths[0].exists());
        assert!(!paths[1].exists());
        assert!(!paths[2].exists());
        assert!(paths[3].is_dir());
        assert!(paths[4].is_dir());
        // Never the app's own directory, nor the connection's.
        assert!(builds.app("spaceport-for-acme", &app()).is_dir());
        assert!(builds.root().join("spaceport-for-acme").is_dir());

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sweeps_nothing_when_fewer_than_the_limit_are_there() {
        let (root, builds) = builds("sweeps-nothing");

        builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();
        builds.prepare("spaceport-for-acme", &app(), OLDER).unwrap();

        assert_eq!(builds.sweep("spaceport-for-acme", &app(), 3).unwrap(), 0);
        assert!(
            builds
                .revision("spaceport-for-acme", &app(), REVISION)
                .is_dir()
        );
        assert!(
            builds
                .revision("spaceport-for-acme", &app(), OLDER)
                .is_dir()
        );
        // Nor is an app that has never been built a failure to sweep.
        let never: AppId = "never-built".parse().unwrap();
        assert_eq!(builds.sweep("spaceport-for-acme", &never, 3).unwrap(), 0);

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Apps share a connection directory, and a sweep of one app's builds is
    /// not a licence to touch another's.
    #[test]
    fn leaves_the_builds_of_other_apps_alone() {
        let (root, builds) = builds("leaves-other-apps");
        let other: AppId = "other-app".parse().unwrap();

        let mine = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();
        let theirs = builds.prepare("spaceport-for-acme", &other, OLDER).unwrap();
        age(&mine, 1_000);
        age(&theirs, 1_000);

        assert_eq!(builds.sweep("spaceport-for-acme", &app(), 0).unwrap(), 1);

        assert!(!mine.exists());
        assert!(theirs.is_dir());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A sweep decides by age, and shas do not sort by age. Sorting by name
    /// would keep whichever revisions happened to start with a high digit.
    #[test]
    fn keeps_the_newest_and_not_the_last_alphabetically() {
        let (root, builds) = builds("sweeps-by-age");

        let newest = format!("a{}", "0".repeat(39));
        let oldest = format!("f{}", "0".repeat(39));
        let newest = builds
            .prepare("spaceport-for-acme", &app(), &newest)
            .unwrap();
        let oldest = builds
            .prepare("spaceport-for-acme", &app(), &oldest)
            .unwrap();
        age(&newest, 2_000);
        age(&oldest, 1_000);

        assert_eq!(builds.sweep("spaceport-for-acme", &app(), 1).unwrap(), 1);

        assert!(newest.is_dir());
        assert!(!oldest.exists());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A symlink in the tree is a way to ask a delete to happen somewhere else.
    /// It is not followed, and it is not swept.
    #[cfg(unix)]
    #[test]
    fn never_follows_a_symlink_out_of_the_tree() {
        let (root, builds) = builds("never-follows-a-symlink");
        let outside = root.join("precious");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("data.db"), "rows").unwrap();

        let app_dir = builds.app("spaceport-for-acme", &app());
        builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();
        let link = app_dir.join(OLDER);
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        assert_eq!(builds.sweep("spaceport-for-acme", &app(), 0).unwrap(), 1);

        assert!(link.symlink_metadata().is_ok());
        assert_eq!(
            std::fs::read_to_string(outside.join("data.db")).unwrap(),
            "rows"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// `prepare` clears what it finds, and a symlink is one of the things it
    /// can find — unlinked, never followed.
    #[test]
    #[cfg(unix)]
    fn unlinks_rather_than_empties_a_symlink_in_the_way() {
        let (root, builds) = builds("unlinks-a-symlink");
        let outside = root.join("precious");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("data.db"), "rows").unwrap();

        let app_dir = builds.app("spaceport-for-acme", &app());
        std::fs::create_dir_all(&app_dir).unwrap();
        std::os::unix::fs::symlink(&outside, app_dir.join(REVISION)).unwrap();

        let path = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();

        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_to_string(outside.join("data.db")).unwrap(),
            "rows"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn keeps_an_apps_source_to_itself() {
        use std::os::unix::fs::PermissionsExt;

        let (root, builds) = builds("owner-only");
        let path = builds
            .prepare("spaceport-for-acme", &app(), REVISION)
            .unwrap();

        for directory in [
            builds.root(),
            &builds.app("spaceport-for-acme", &app()),
            &path,
        ] {
            let mode = std::fs::metadata(directory).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", directory.display());
        }

        std::fs::remove_dir_all(&root).unwrap();
    }
}
