//! One spaceport per state directory.
//!
//! SQLite would keep two spaceports from corrupting the database, and would do
//! nothing at all about the part that matters: both of them would be starting,
//! stopping and reconciling the same labelled containers, each undoing the
//! other's work while writing perfectly valid rows about it.
//!
//! So the state directory carries an advisory lock, taken for as long as the
//! process runs. `flock` and not a pid file, because the kernel drops it when
//! the process dies — a spaceport that was killed leaves nothing to clean up
//! and nothing stale to mistake for a live instance.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The lock file inside the state directory.
const LOCK_FILE: &str = "spaceport.lock";

/// Proof that this process is the one running this state directory.
///
/// Held for the lifetime of the daemon: dropping it releases the lock, so it
/// belongs somewhere that lives as long as the process should.
#[derive(Debug)]
pub struct StateLock {
    path: PathBuf,
    /// Kept for its file descriptor, which is what actually holds the lock.
    _file: File,
}

impl StateLock {
    /// Take the lock on `directory`, or say who has it.
    pub fn acquire(directory: &Path) -> Result<Self> {
        let path = directory.join(LOCK_FILE);
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening the state lock `{}`", path.display()))?;

        take(&file, &path)?;

        Ok(Self { path, _file: file })
    }

    /// The file this lock is held on.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn take(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `flock` takes a file descriptor and a flag, and the descriptor is
    // valid for as long as the borrow of `file` lasts.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let error = std::io::Error::last_os_error();

        if error.kind() == std::io::ErrorKind::WouldBlock {
            bail!(
                "another spaceport is already running this state directory (`{}` is locked)",
                path.display()
            );
        }

        return Err(error).with_context(|| format!("locking `{}`", path.display()));
    }

    Ok(())
}

/// Nothing to do where there is no `flock`. Spaceport runs containers on a unix
/// host; this exists so the crate still builds elsewhere.
#[cfg(not(unix))]
fn take(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::temp_dir;

    #[test]
    fn locks_an_empty_state_directory() {
        let directory = temp_dir("lock");
        std::fs::create_dir_all(&directory).unwrap();

        let lock = StateLock::acquire(&directory).unwrap();
        assert!(lock.path().is_file());

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_directory_another_instance_holds() {
        let directory = temp_dir("lock-taken");
        std::fs::create_dir_all(&directory).unwrap();
        let held = StateLock::acquire(&directory).unwrap();

        let err = StateLock::acquire(&directory).unwrap_err().to_string();
        assert!(err.contains("already running"), "{err}");

        // And letting go hands it to the next one.
        drop(held);
        StateLock::acquire(&directory).unwrap();

        let _ = std::fs::remove_dir_all(&directory);
    }
}
