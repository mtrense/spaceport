//! Where an app's volumes live on the host.
//!
//! A manifest names a volume; spaceport decides where it goes. The path is
//! `<data-dir>/<app-id>/<volume-name>`, and both of those segments are already
//! restricted to letters, digits and hyphens by the types that carry them, so
//! joining them cannot produce a path outside the data directory.
//!
//! Nothing here deletes. Volumes outlive the app that made them — destroying
//! an app takes down its container and leaves its data where an operator can
//! still get at it, which is the only version of this that is safe to get
//! wrong.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, warn};

use super::AppId;
use crate::app::manifest::{Volume, VolumeName};

/// Path used when the config names no data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/spaceport/apps";

/// Traversable but not listable: an app's data is reachable by anyone who
/// already knows which app they are looking for, and the directory does not
/// hand out the list of every app on the host to anyone who asks.
#[cfg(unix)]
const DATA_DIR_MODE: u32 = 0o711;

/// A volume's own directory, readable by the host's operator and writable by
/// whoever the container runs as — see [`DataDir::provision`].
#[cfg(unix)]
const VOLUME_DIR_MODE: u32 = 0o755;

/// The user a container's image says it runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

impl Owner {
    /// Read an image config's `User` field, if it says something spaceport can
    /// act on.
    ///
    /// Only numeric ids resolve. A name like `nobody` means whatever the
    /// image's own `/etc/passwd` says it means, and spaceport is not in a
    /// position to read that file — so it says nothing rather than guess at a
    /// uid and chown a directory to the wrong one.
    pub fn parse(user: &str) -> Option<Self> {
        let user = user.trim();
        if user.is_empty() {
            return None;
        }

        let (uid, gid) = match user.split_once(':') {
            Some((uid, gid)) => (uid, Some(gid)),
            None => (user, None),
        };

        let uid: u32 = uid.parse().ok()?;
        // A `User` of just `1000` leaves the group to the engine, which uses
        // the same number. Matching that is what makes the directory writable.
        let gid: u32 = match gid {
            Some(gid) => gid.parse().ok()?,
            None => uid,
        };

        Some(Self { uid, gid })
    }
}

/// The directory apps' volumes live under.
#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the data directory, if it is not already there.
    pub fn create(&self) -> Result<()> {
        if self.root.is_dir() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating the data directory `{}`", self.root.display()))?;
        set_mode(&self.root, DATA_DIR_MODE)?;

        Ok(())
    }

    /// Everything belonging to one app.
    pub fn app(&self, app: &AppId) -> PathBuf {
        self.root.join(app.as_str())
    }

    /// Where one volume of one app lives.
    pub fn volume(&self, app: &AppId, name: &VolumeName) -> PathBuf {
        self.app(app).join(name.as_str())
    }

    /// Make sure `volume` has a directory on the host, and hand back its path.
    ///
    /// `owner` is who the image runs as, when the image said so. The directory
    /// is created root-owned, so a container running as anyone else could not
    /// write to it — which is every container that follows the usual advice.
    /// Chowning it once, at creation, is what makes a volume a volume rather
    /// than a permission error.
    ///
    /// An existing directory is left alone, ownership included: it is the
    /// app's data by then, and an operator who moved it to another user has
    /// said something spaceport should not undo at every start.
    pub fn provision(&self, app: &AppId, volume: &Volume, owner: Option<Owner>) -> Result<PathBuf> {
        let path = self.volume(app, &volume.name);
        if path.is_dir() {
            return Ok(path);
        }

        std::fs::create_dir_all(&path).with_context(|| {
            format!(
                "creating volume `{}` for app `{app}` at `{}`",
                volume.name,
                path.display()
            )
        })?;
        set_mode(&path, VOLUME_DIR_MODE)?;

        match owner {
            Some(owner) => {
                chown(&path, owner)?;
                debug!(app = %app, volume = %volume.name, uid = owner.uid, gid = owner.gid, "created a volume");
            }
            // Worth a word every time: an app that cannot write to its own
            // volume fails in a way that looks like the app's fault.
            None => {
                debug!(app = %app, volume = %volume.name, "created a volume, owned by root");
            }
        }

        Ok(path)
    }

    /// Say so when a volume will not be writable by the app that asked for it.
    ///
    /// Split out from [`DataDir::provision`] because it is worth saying on
    /// every launch, not only the one that created the directory.
    pub fn warn_unresolved_owner(&self, app: &AppId, volumes: &[Volume], user: &str) {
        if volumes.iter().all(|volume| volume.read_only) {
            return;
        }

        warn!(
            app = %app,
            user,
            "the image runs as `{user}`, which spaceport cannot resolve to a uid, so this app's volumes stay owned by root — give the image a numeric `USER` if it cannot write to them"
        );
    }
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

#[cfg(unix)]
fn chown(path: &Path, owner: Owner) -> Result<()> {
    std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid)).with_context(|| {
        format!(
            "giving `{}` to uid {} gid {}",
            path.display(),
            owner.uid,
            owner.gid
        )
    })
}

#[cfg(not(unix))]
fn chown(_path: &Path, _owner: Owner) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("spaceport-{name}-{unique}"));
        std::fs::create_dir_all(&path).unwrap();

        path
    }

    fn app() -> AppId {
        "my-app".parse().unwrap()
    }

    fn volume(name: &str) -> Volume {
        Volume {
            name: name.parse().unwrap(),
            mount: PathBuf::from("/data"),
            read_only: false,
        }
    }

    #[test]
    fn puts_a_volume_under_its_app() {
        let data = DataDir::new(PathBuf::from("/var/lib/spaceport/apps"));

        assert_eq!(
            data.volume(&app(), &"cache".parse().unwrap()),
            Path::new("/var/lib/spaceport/apps/my-app/cache")
        );
    }

    #[test]
    fn creates_a_volume_directory() {
        let root = temp_dir("creates-a-volume");
        let data = DataDir::new(root.join("apps"));
        data.create().unwrap();

        let path = data.provision(&app(), &volume("data"), None).unwrap();

        assert!(path.is_dir());
        assert_eq!(path, root.join("apps/my-app/data"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Provisioning runs on every launch, so it has to be the same operation
    /// the second time — and it must not touch what the app has written.
    #[test]
    fn leaves_a_volume_that_is_already_there_alone() {
        let root = temp_dir("keeps-a-volume");
        let data = DataDir::new(root.join("apps"));
        data.create().unwrap();

        let path = data.provision(&app(), &volume("data"), None).unwrap();
        std::fs::write(path.join("app.db"), "rows").unwrap();

        let again = data.provision(&app(), &volume("data"), None).unwrap();

        assert_eq!(again, path);
        assert_eq!(
            std::fs::read_to_string(path.join("app.db")).unwrap(),
            "rows"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reads_the_users_an_image_can_state() {
        assert_eq!(
            Owner::parse("1000"),
            Some(Owner {
                uid: 1000,
                gid: 1000
            })
        );
        assert_eq!(
            Owner::parse("1000:2000"),
            Some(Owner {
                uid: 1000,
                gid: 2000
            })
        );
        assert_eq!(
            Owner::parse(" 65534 "),
            Some(Owner {
                uid: 65534,
                gid: 65534
            })
        );
    }

    /// A name is not a uid anywhere but inside the image, and chowning to a
    /// guess would be worse than leaving the directory root-owned and saying
    /// so.
    #[test]
    fn declines_to_guess_at_a_named_user() {
        assert_eq!(Owner::parse(""), None);
        assert_eq!(Owner::parse("nobody"), None);
        assert_eq!(Owner::parse("nobody:nogroup"), None);
        assert_eq!(Owner::parse("1000:nogroup"), None);
    }
}
