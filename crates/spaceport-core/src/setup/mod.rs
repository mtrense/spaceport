//! Turning the binary somebody just downloaded into a running system service.
//!
//! Three things have to be true before a host is serving: the binary is
//! somewhere that survives the download directory being cleaned out, there is a
//! config file where spaceport looks for one, and something starts it at boot.
//! `spaceport setup` does all three, and does them again — over the top of the
//! last run — whenever any of them has to change.
//!
//! Re-running is the ordinary case, not the exception: upgrading is `setup`
//! with a newer binary, and taking the operator socket away is `setup` without
//! `--operator`. So each step is written to be idempotent, and the one thing
//! never overwritten is a config file an operator has since edited.

pub mod systemd;

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::REFERENCE_CONFIG;
use crate::{Config, OperatorEndpoint};

/// Where the binary is installed, if it is not already somewhere on the host.
pub const BIN_DIR: &str = "/usr/local/bin";

/// The name the binary is installed under.
const BINARY_NAME: &str = "spaceport";

#[cfg(unix)]
const BINARY_MODE: u32 = 0o755;
#[cfg(unix)]
const CONFIG_MODE: u32 = 0o644;
#[cfg(unix)]
const UNIT_MODE: u32 = 0o644;

/// What an operator asked `spaceport setup` for.
#[derive(Debug, Clone)]
pub struct Setup {
    /// Where the config file goes, and where the service is told to read it.
    pub config: PathBuf,

    /// A config file to install at that path. Without one, a host that has no
    /// config yet gets the reference config and a host that has one keeps it.
    pub initial_config: Option<PathBuf>,

    /// The operator interface the service exposes. `None` installs a spaceport
    /// that serves but cannot be told to run anything — which is also how an
    /// existing socket is taken away again.
    pub operator: Option<OperatorEndpoint>,
}

/// The filesystem a setup writes into.
///
/// `/` and this executable on a real host; a temp directory and a stand-in
/// under test, which is the only reason this is a type rather than two
/// constants.
#[derive(Debug, Clone)]
struct Target {
    /// Prefix every absolute path is placed under.
    root: PathBuf,
    /// The binary to install.
    binary: PathBuf,
}

impl Target {
    /// This host, and the binary that is asking.
    fn system() -> Result<Self> {
        Ok(Self {
            root: PathBuf::from("/"),
            // Canonical, so the comparison against the installed path is not
            // fooled by `./spaceport` or a symlinked download.
            binary: std::env::current_exe()
                .context("finding the running binary")?
                .canonicalize()
                .context("resolving the running binary")?,
        })
    }
}

/// What a setup did, in the order it did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub binary: PathBuf,
    pub binary_outcome: BinaryOutcome,
    pub config: PathBuf,
    pub config_outcome: ConfigOutcome,
    pub unit: PathBuf,
}

/// What became of the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOutcome {
    /// Copied into the system bin directory.
    Installed,
    /// Already the installed one — an upgrade in place, or a second setup run.
    AlreadyInstalled,
}

/// What became of the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOutcome {
    /// The file `--initial-config` named was installed at the config path.
    Installed,
    /// There was no config, so the reference one was written.
    Created,
    /// There already was one, and nothing was said about replacing it.
    Kept,
}

/// Install spaceport on this host, and start it.
///
/// Everything up to the last step is idempotent; the last step restarts the
/// service, because a setup that left the old binary running would have
/// installed a new one nobody is using.
pub fn install(setup: &Setup) -> Result<Report> {
    if !cfg!(unix) {
        bail!("`spaceport setup` installs a systemd service, which needs a Linux host");
    }
    if !systemd::booted() {
        bail!(
            "this host was not booted by systemd, so there is nothing here to install a \
             service into"
        );
    }
    if !is_root() {
        bail!(
            "`spaceport setup` writes to {BIN_DIR} and {}, so it has to run as root",
            systemd::UNIT_DIR
        );
    }

    let report = place(setup, &Target::system()?)?;
    systemd::activate()?;

    Ok(report)
}

/// Everything a setup writes: the binary, the config, the unit file.
///
/// Split from [`install`] so what lands on disk can be tested without a
/// systemd, a root, or a host willing to have its `/usr/local/bin` written to.
fn place(setup: &Setup, target: &Target) -> Result<Report> {
    let (binary, binary_outcome) = place_binary(target)?;
    let config = under(&target.root, &setup.config);
    let config_outcome = place_config(setup, &config)?;

    // The unit names the paths the service will use at boot, not the ones this
    // run wrote to: a rooted target is a test's business and not systemd's.
    let unit_dir = under(&target.root, Path::new(systemd::UNIT_DIR));
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating `{}`", unit_dir.display()))?;

    let unit_path = unit_dir.join(systemd::UNIT_NAME);
    let installed_binary = Path::new(BIN_DIR).join(BINARY_NAME);
    write(
        &unit_path,
        systemd::unit(&installed_binary, &setup.config, setup.operator.as_ref()).as_bytes(),
        UNIT_MODE,
    )?;

    Ok(Report {
        binary,
        binary_outcome,
        config: setup.config.clone(),
        config_outcome,
        unit: Path::new(systemd::UNIT_DIR).join(systemd::UNIT_NAME),
    })
}

/// Copy the running binary into the system bin directory, unless it is already
/// the file that lives there.
fn place_binary(target: &Target) -> Result<(PathBuf, BinaryOutcome)> {
    let directory = under(&target.root, Path::new(BIN_DIR));
    let installed = directory.join(BINARY_NAME);

    if same_file(&target.binary, &installed) {
        return Ok((installed, BinaryOutcome::AlreadyInstalled));
    }

    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating `{}`", directory.display()))?;

    // Written beside the target and renamed over it: a running spaceport holds
    // its own binary open, and the kernel refuses to write into a file it is
    // executing. Replacing the directory entry it points at is allowed, and
    // leaves the running process on the old inode until it exits.
    let staged = directory.join(format!("{BINARY_NAME}.new"));
    std::fs::copy(&target.binary, &staged).with_context(|| {
        format!(
            "copying `{}` to `{}`",
            target.binary.display(),
            staged.display()
        )
    })?;
    set_mode(&staged, BINARY_MODE)?;
    std::fs::rename(&staged, &installed)
        .with_context(|| format!("installing `{}`", installed.display()))?;

    Ok((installed, BinaryOutcome::Installed))
}

/// Put a config file where the service will look for one.
fn place_config(setup: &Setup, path: &Path) -> Result<ConfigOutcome> {
    if let Some(directory) = path.parent() {
        std::fs::create_dir_all(directory)
            .with_context(|| format!("creating `{}`", directory.display()))?;
    }

    let Some(initial) = &setup.initial_config else {
        if path.exists() {
            return Ok(ConfigOutcome::Kept);
        }

        write(path, REFERENCE_CONFIG.as_bytes(), CONFIG_MODE)?;
        return Ok(ConfigOutcome::Created);
    };

    // Validated before it is installed, not after: the alternative is a service
    // that will not start and a config file that has already replaced the one
    // that worked.
    let raw = std::fs::read_to_string(initial)
        .with_context(|| format!("reading `{}`", initial.display()))?;
    Config::parse(&raw).with_context(|| format!("invalid config file `{}`", initial.display()))?;

    write(path, raw.as_bytes(), CONFIG_MODE)?;

    Ok(ConfigOutcome::Installed)
}

/// Whether two paths are the same file, for paths that may not exist.
fn same_file(one: &Path, other: &Path) -> bool {
    match (one.canonicalize(), other.canonicalize()) {
        (Ok(one), Ok(other)) => one == other,
        _ => false,
    }
}

/// Place `path` under `root`, which for the real filesystem is a no-op.
fn under(root: &Path, path: &Path) -> PathBuf {
    match path.strip_prefix("/") {
        Ok(relative) => root.join(relative),
        Err(_) => root.join(path),
    }
}

fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing `{}`", path.display()))?;
    set_mode(path, mode)
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
fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments, touches nothing, and always
    // succeeds.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let binary = match self.binary_outcome {
            BinaryOutcome::Installed => "installed",
            BinaryOutcome::AlreadyInstalled => "already installed",
        };
        writeln!(f, "{}: {binary}", self.binary.display())?;

        let config = match self.config_outcome {
            ConfigOutcome::Installed => "installed",
            ConfigOutcome::Created => "created, edit it before serving anything real",
            ConfigOutcome::Kept => "kept, already there",
        };
        writeln!(f, "{}: {config}", self.config.display())?;

        write!(f, "{}: written", self.unit.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test run's own, under the system temp dir.
    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("spaceport-test-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&directory);

        directory
    }

    /// A target rooted in a directory of this test's own, with a stand-in for
    /// the binary being installed.
    fn target(name: &str) -> Target {
        let root = temp_dir(name);
        let binary = root.join("download").join(BINARY_NAME);

        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"#!/bin/false\n").unwrap();

        Target { root, binary }
    }

    fn setup(config: &Path) -> Setup {
        Setup {
            config: config.to_path_buf(),
            initial_config: None,
            operator: Some("/run/spaceport.sock".parse().unwrap()),
        }
    }

    fn config_path() -> PathBuf {
        PathBuf::from(crate::config::DEFAULT_CONFIG_PATH)
    }

    #[test]
    fn installs_the_binary_the_config_and_the_unit() {
        let target = target("setup-installs");
        let report = place(&setup(&config_path()), &target).unwrap();

        assert_eq!(report.binary_outcome, BinaryOutcome::Installed);
        assert_eq!(report.config_outcome, ConfigOutcome::Created);

        let installed = target.root.join("usr/local/bin/spaceport");
        assert_eq!(std::fs::read(&installed).unwrap(), b"#!/bin/false\n");
        assert!(!installed.with_file_name("spaceport.new").exists());

        let config = target.root.join("etc/spaceport/spaceport.yaml");
        Config::parse(&std::fs::read_to_string(config).unwrap()).unwrap();

        let unit =
            std::fs::read_to_string(target.root.join("etc/systemd/system/spaceport.service"))
                .unwrap();
        // The unit names the paths on the host, never the rooted ones a test
        // wrote to.
        assert!(
            unit.contains("ExecStart=\"/usr/local/bin/spaceport\" run"),
            "{unit}"
        );
        assert!(
            unit.contains("--config \"/etc/spaceport/spaceport.yaml\""),
            "{unit}"
        );
        assert!(
            unit.contains("--operator \"unix:/run/spaceport.sock\""),
            "{unit}"
        );

        let _ = std::fs::remove_dir_all(&target.root);
    }

    /// The upgrade path: the binary being run is the one already installed.
    #[test]
    fn leaves_the_binary_alone_when_it_is_already_the_installed_one() {
        let mut target = target("setup-in-place");
        target.binary = target.root.join("usr/local/bin/spaceport");
        std::fs::create_dir_all(target.binary.parent().unwrap()).unwrap();
        std::fs::write(&target.binary, b"the running one\n").unwrap();

        let report = place(&setup(&config_path()), &target).unwrap();

        assert_eq!(report.binary_outcome, BinaryOutcome::AlreadyInstalled);
        assert_eq!(std::fs::read(&target.binary).unwrap(), b"the running one\n");

        let _ = std::fs::remove_dir_all(&target.root);
    }

    /// A config file is the one thing on a host an operator has written by
    /// hand. A second setup run must not be what loses it.
    #[test]
    fn keeps_a_config_that_is_already_there() {
        let target = target("setup-keeps-config");
        let config = config_path();
        let placed = target.root.join("etc/spaceport/spaceport.yaml");

        std::fs::create_dir_all(placed.parent().unwrap()).unwrap();
        std::fs::write(&placed, "schema_version: 1 # mine\n").unwrap();

        let report = place(&setup(&config), &target).unwrap();

        assert_eq!(report.config_outcome, ConfigOutcome::Kept);
        assert_eq!(
            std::fs::read_to_string(&placed).unwrap(),
            "schema_version: 1 # mine\n"
        );

        let _ = std::fs::remove_dir_all(&target.root);
    }

    #[test]
    fn installs_the_config_it_is_given_over_the_one_that_is_there() {
        let target = target("setup-initial-config");
        let initial = target.root.join("mine.yaml");
        let raw = "schema_version: 1\nedge:\n  listen:\n    http: 0.0.0.0:8080\n    \
                   https: 0.0.0.0:8443\n";
        std::fs::write(&initial, raw).unwrap();

        let placed = target.root.join("etc/spaceport/spaceport.yaml");
        std::fs::create_dir_all(placed.parent().unwrap()).unwrap();
        std::fs::write(&placed, REFERENCE_CONFIG).unwrap();

        let report = place(
            &Setup {
                initial_config: Some(initial),
                ..setup(&config_path())
            },
            &target,
        )
        .unwrap();

        assert_eq!(report.config_outcome, ConfigOutcome::Installed);
        assert_eq!(std::fs::read_to_string(&placed).unwrap(), raw);

        let _ = std::fs::remove_dir_all(&target.root);
    }

    /// Installing a config that will not parse buys a service that will not
    /// start, and destroys the config that would have worked on the way.
    #[test]
    fn refuses_an_initial_config_that_is_not_valid() {
        let target = target("setup-invalid-config");
        let initial = target.root.join("broken.yaml");
        std::fs::write(&initial, "schema_version: 99\n").unwrap();

        let placed = target.root.join("etc/spaceport/spaceport.yaml");
        std::fs::create_dir_all(placed.parent().unwrap()).unwrap();
        std::fs::write(&placed, REFERENCE_CONFIG).unwrap();

        let err = format!(
            "{:#}",
            place(
                &Setup {
                    initial_config: Some(initial),
                    ..setup(&config_path())
                },
                &target,
            )
            .unwrap_err()
        );

        assert!(err.contains("unsupported schema version 99"), "{err}");
        assert_eq!(std::fs::read_to_string(&placed).unwrap(), REFERENCE_CONFIG);

        let _ = std::fs::remove_dir_all(&target.root);
    }

    /// Re-running without `--operator` is how the socket is taken away, and the
    /// unit is rewritten rather than left as it was.
    #[test]
    fn a_second_run_rewrites_the_unit() {
        let target = target("setup-rewrites-unit");
        place(&setup(&config_path()), &target).unwrap();

        place(
            &Setup {
                operator: None,
                ..setup(&config_path())
            },
            &target,
        )
        .unwrap();

        let unit =
            std::fs::read_to_string(target.root.join("etc/systemd/system/spaceport.service"))
                .unwrap();
        assert!(!unit.contains("--operator"), "{unit}");

        let _ = std::fs::remove_dir_all(&target.root);
    }

    #[test]
    fn takes_the_config_path_it_is_given() {
        let target = target("setup-config-path");
        let report = place(&setup(Path::new("/srv/spaceport/config.yaml")), &target).unwrap();

        assert!(target.root.join("srv/spaceport/config.yaml").is_file());
        assert_eq!(report.config, PathBuf::from("/srv/spaceport/config.yaml"));

        let unit =
            std::fs::read_to_string(target.root.join("etc/systemd/system/spaceport.service"))
                .unwrap();
        assert!(
            unit.contains("--config \"/srv/spaceport/config.yaml\""),
            "{unit}"
        );

        let _ = std::fs::remove_dir_all(&target.root);
    }

    #[cfg(unix)]
    #[test]
    fn the_installed_binary_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let target = target("setup-modes");
        place(&setup(&config_path()), &target).unwrap();

        let mode = |path: PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(target.root.join("usr/local/bin/spaceport")),
            BINARY_MODE
        );
        assert_eq!(
            mode(target.root.join("etc/spaceport/spaceport.yaml")),
            CONFIG_MODE
        );

        let _ = std::fs::remove_dir_all(&target.root);
    }
}
