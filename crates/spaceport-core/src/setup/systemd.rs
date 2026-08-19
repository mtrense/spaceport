//! The unit file spaceport runs under, and the three commands that make it
//! take effect.
//!
//! systemd and nothing else: spaceport talks to a container engine over its
//! socket, binds 80 and 443, and hands out a unix socket under `/run`. That is
//! a Linux host, and on a Linux host running a daemon at boot means systemd.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::OperatorEndpoint;

/// The unit spaceport is installed as.
pub const UNIT_NAME: &str = "spaceport.service";

/// Where units an administrator installs — as opposed to units a package ships
/// — belong.
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// How many file descriptors the unit gives spaceport.
///
/// The edge admits up to [`crate::edge::MAX_CONNECTIONS`] connections at once
/// and each one may hold two descriptors — the client's socket, and the
/// upstream socket its requests are proxied through — so twice that number is
/// the ceiling connections alone can reach. The thousand on top is everything
/// that is not a connection: the two listeners, the operator socket, the engine
/// socket, the database and its journal, and the odd file.
///
/// Without this the cap in the edge would be decoration. Linux's default soft
/// limit is 1024 descriptors, so a process that never asks for more meets
/// `EMFILE` in `accept()` at a few hundred connections — an outage that looks
/// like a bug, since the connection table it was supposed to fill is barely
/// touched. `LimitNOFILE` is how a unit asks, and the hard limit on any modern
/// kernel is far above this, so the ask is granted.
pub(crate) const FILE_DESCRIPTOR_LIMIT: usize = crate::edge::MAX_CONNECTIONS * 2 + 1_000;

/// Whether this host was booted by systemd.
///
/// The directory is systemd's own marker for "I am the init system here", and
/// is absent in a container, under another init, and on macOS.
pub fn booted() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// The unit file for a spaceport at `binary`, reading `config`.
///
/// Regenerated on every setup rather than patched, so `--operator` disappearing
/// from the command line is what makes the socket disappear from the unit.
pub fn unit(binary: &Path, config: &Path, operator: Option<&OperatorEndpoint>) -> String {
    let mut command = format!("{} run --config {}", quote(binary), quote(config));
    if let Some(operator) = operator {
        command.push_str(&format!(" --operator {}", quote_str(&operator.to_string())));
    }

    format!(
        "\
# Written by `spaceport setup`. Edits are lost the next time it runs.
[Unit]
Description=spaceport, a reverse proxy for small and internal apps
Documentation=https://github.com/mtrense/spaceport
# `Wants` and not `Requires`: a host whose engine is socket-activated, or
# called something else, still gets a spaceport that starts and says what it
# could not reach.
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=exec
ExecStart={command}
# The edge binds 80 and 443 and the runtime talks to the engine's socket.
User=root
# The edge caps how many connections it will hold at once; this is what makes
# that cap the limit spaceport actually meets, rather than the default 1024
# descriptors it would otherwise run out of first.
LimitNOFILE={FILE_DESCRIPTOR_LIMIT}
Restart=on-failure
RestartSec=2s
# spaceport shuts down gracefully on SIGINT and is killed by SIGTERM, so stops
# and restarts drain in-flight requests rather than cutting them.
KillSignal=SIGINT
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
"
    )
}

/// Pick up the unit, start it at boot, and run the version just installed.
///
/// `restart` and not `reload-or-restart`: the binary underneath has changed,
/// and no amount of reloading gets a running process to become a new one.
pub fn activate() -> Result<()> {
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT_NAME])?;
    systemctl(&["restart", UNIT_NAME])
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("running `systemctl {}`", args.join(" ")))?;

    if !status.success() {
        bail!("`systemctl {}` failed: {status}", args.join(" "));
    }

    Ok(())
}

/// A path as systemd should read it back.
///
/// systemd splits `ExecStart` on whitespace and unescapes what it finds, so a
/// path that survives the round trip has to be quoted, and a quote or backslash
/// inside it escaped.
fn quote(path: &Path) -> String {
    quote_str(&path.display().to_string())
}

fn quote_str(raw: &str) -> String {
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn rendered(operator: Option<&str>) -> String {
        unit(
            Path::new("/usr/local/bin/spaceport"),
            Path::new("/etc/spaceport/spaceport.yaml"),
            operator.map(|raw| raw.parse().unwrap()).as_ref(),
        )
    }

    #[test]
    fn runs_the_installed_binary_against_the_installed_config() {
        let unit = rendered(None);

        assert!(
            unit.contains(
                "ExecStart=\"/usr/local/bin/spaceport\" run --config \
                 \"/etc/spaceport/spaceport.yaml\"\n"
            ),
            "{unit}"
        );
        assert!(unit.contains("WantedBy=multi-user.target"), "{unit}");
    }

    /// The whole point of re-rendering: a setup run without `--operator` is how
    /// an operator takes the socket away.
    #[test]
    fn exposes_the_operator_interface_only_when_asked_to() {
        assert!(!rendered(None).contains("--operator"), "{}", rendered(None));

        let unit = rendered(Some("/run/spaceport.sock"));
        assert!(
            unit.contains("--operator \"unix:/run/spaceport.sock\""),
            "{unit}"
        );
    }

    /// The edge's connection cap is only a cap if the process has the
    /// descriptors to reach it, and nothing but the unit asks for them.
    #[test]
    fn raises_the_descriptor_limit_to_match_the_connection_cap() {
        let unit = rendered(None);

        // The number spelled out rather than interpolated from the constant,
        // which would assert nothing: twice the ten thousand connections the
        // edge admits, plus room for everything that is not a connection. A
        // change to either number should have to be made here too.
        assert!(unit.contains("\nLimitNOFILE=21000\n"), "{unit}");
    }

    /// A restart that killed in-flight requests would be a setup that made
    /// spaceport worse than running it by hand.
    #[test]
    fn stops_spaceport_the_way_it_shuts_down_gracefully() {
        assert!(rendered(None).contains("KillSignal=SIGINT"));
    }

    #[test]
    fn escapes_a_path_systemd_would_otherwise_split() {
        let unit = unit(
            &PathBuf::from("/opt/space port/spaceport"),
            Path::new("/etc/spaceport/spaceport.yaml"),
            None,
        );

        assert!(
            unit.contains("ExecStart=\"/opt/space port/spaceport\" run"),
            "{unit}"
        );
    }
}
