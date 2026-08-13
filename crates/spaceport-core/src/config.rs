//! Configuration loading and validation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Path used when no `--config` is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/spaceport/spaceport.toml";

/// A parsed and validated spaceport configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Path the configuration was loaded from, if any.
    pub source: Option<PathBuf>,
}

impl Config {
    /// Read and validate the configuration at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let _raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path.display()))?;

        // TODO: parse the config document and validate it.

        Ok(Self {
            source: Some(path.to_path_buf()),
        })
    }
}
