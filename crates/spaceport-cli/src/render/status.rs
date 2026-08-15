//! Turning a status into the block an operator reads.
//!
//! One label per line in a fixed column, so the eye runs down the labels and
//! stops at the one it came for. Colour is spent only on trouble — an engine
//! that is not answering, an app that is not, a host with no certificate —
//! because a healthy spaceport should be a page of plain text with nothing on
//! it worth looking at twice.

use std::fmt::Write as _;

use spaceport_core::status::{Apps, CertificateStatus, Status};

use super::{BOLD, Colour, DIM, RED, YELLOW};

/// How wide the label column is, and so where every value starts.
const LABEL: usize = 9;

/// How many names a line will list before it starts counting instead.
const NAMES: usize = 5;

/// A whole status, as a block of lines.
pub fn status(status: &Status, colour: Colour) -> String {
    // Flush left and on its own, because it is the answer to "which spaceport
    // am I looking at?" and everything under it is detail.
    let mut out = format!(
        "{} {} — up {} {}\n\n",
        colour.paint(BOLD, "spaceport"),
        colour.paint(BOLD, &status.version),
        since(status.uptime_seconds),
        colour.paint(DIM, &format!("(since {})", stamp(status.started_at))),
    );

    let mut line = |label: &str, value: &str| {
        // A blank line is blank: painting a label column onto it would leave
        // escape codes wrapped around nothing.
        if label.is_empty() && value.is_empty() {
            out.push('\n');

            return;
        }

        let _ = writeln!(
            out,
            "{} {value}",
            colour.paint(DIM, &format!("{label:<LABEL$}"))
        );
    };

    line(
        "edge",
        &format!("http {}, https {}", status.edge.http, status.edge.https),
    );
    // Only when there is one. A spaceport that answers to no name of its own is
    // a normal spaceport, and a line saying so every time would read as a
    // setting somebody forgot rather than one they never needed.
    if let Some(hostname) = &status.edge.hostname {
        line("hostname", hostname);
    }
    line("hosts", &format!("{} routed", status.edge.routed_hosts));

    let directory = match &status.tls.directory {
        Some(directory) => format!("{} {directory}", status.tls.provider),
        // Worth saying outright rather than leaving as a bare word: an edge
        // nothing trusts is a thing to find out from a status, not from a
        // browser.
        None => format!(
            "{} — {}",
            status.tls.provider,
            colour.paint(YELLOW, "trusted by nothing"),
        ),
    };
    line("tls", &directory);
    for line_of in certificates(&status.certificates, colour) {
        line("", &line_of);
    }

    line("operator", &status.operator);
    line(
        "engine",
        &match status.engine.reachable {
            true => status.engine.description.clone(),
            false => colour.paint(RED, &status.engine.description),
        },
    );

    let state = match (&status.state.schema_version, &status.state.error) {
        (Some(version), _) => format!("{} — schema {version}", status.state.path),
        (None, error) => format!(
            "{} — {}",
            status.state.path,
            colour.paint(RED, error.as_deref().unwrap_or("unreadable")),
        ),
    };
    line("state", &state);
    line("config", &status.config);
    line("", "");

    // Only the first line is labelled; the ones under it continue it.
    for (at, line_of) in apps(&status.apps, colour).into_iter().enumerate() {
        line(if at == 0 { "apps" } else { "" }, &line_of);
    }

    // Only when there is one, the way the hostname line is: a spaceport that is
    // connected to nothing is an ordinary spaceport, and a `0 github apps` line
    // on every status would read as something missing.
    if status.connections > 0 {
        line("connect", &connections(status.connections));
    }

    let reconcile = &status.reconcile;
    line(
        "start",
        &format!(
            "{} restored, {} adopted, {} swept",
            reconcile.restored, reconcile.adopted, reconcile.swept
        ),
    );

    // The label column is written for every line, including the ones that only
    // continue the line above; trailing spaces are not part of what was said.
    out.lines()
        .map(str::trim_end)
        .collect::<Vec<&str>>()
        .join("\n")
        + "\n"
}

/// What is running, what answers, and what was asked for and is not there.
fn apps(apps: &Apps, colour: Colour) -> Vec<String> {
    let mut lines = vec![format!(
        "{} running, {} ready{}",
        apps.running,
        apps.ready,
        match apps.unreachable.is_empty() {
            true => String::new(),
            false => format!(
                ", {}",
                colour.paint(
                    RED,
                    &format!(
                        "{} unreachable ({})",
                        apps.unreachable.len(),
                        names(apps.unreachable.iter().map(|id| id.to_string())),
                    ),
                ),
            ),
        },
    )];

    if let Some(error) = &apps.error {
        lines.push(colour.paint(RED, &format!("the records could not be read: {error}")));

        return lines;
    }

    lines.push(format!(
        "{} recorded{}{}",
        apps.recorded,
        // Uncoloured, and named: a suspended app is doing what it was told to,
        // so it is worth listing and not worth warning about.
        match apps.suspended.is_empty() {
            true => String::new(),
            false => format!(
                ", {} suspended ({})",
                apps.suspended.len(),
                names(apps.suspended.iter().map(|id| id.to_string())),
            ),
        },
        match apps.down.is_empty() {
            true => String::new(),
            false => format!(
                ", {}",
                colour.paint(YELLOW, &format!("{} not running", apps.down.len()))
            ),
        },
    ));
    // One line each, because the reason is the part worth reading and it does
    // not fit in a list.
    for down in &apps.down {
        lines.push(format!(
            "  {}{}",
            down.id,
            match &down.reason {
                Some(reason) => format!(": {}", colour.paint(RED, reason)),
                None => String::new(),
            },
        ));
    }

    lines
}

/// How many GitHub Apps this spaceport is registered as, said in English.
///
/// Nothing is coloured: being connected to none, one or several is a decision
/// rather than a condition, so there is nothing here to warn about.
fn connections(held: usize) -> String {
    match held {
        1 => "1 github app".to_owned(),
        held => format!("{held} github apps"),
    }
}

/// What spaceport holds, and what it is missing.
fn certificates(certificates: &CertificateStatus, colour: Colour) -> Vec<String> {
    if let Some(error) = &certificates.error {
        return vec![colour.paint(RED, &format!("the certificates could not be read: {error}"))];
    }

    let mut lines = vec![match &certificates.next_renewal {
        Some(next) => format!(
            "{} held, next renewal {} ({})",
            certificates.held,
            ahead(next.in_seconds, colour),
            next.host,
        ),
        None => format!("{} held", certificates.held),
    }];

    if !certificates.uncertified.is_empty() {
        lines.push(colour.paint(
            YELLOW,
            &format!(
                "no certificate yet for {}",
                names(certificates.uncertified.iter().cloned()),
            ),
        ));
    }
    if !certificates.unreadable.is_empty() {
        lines.push(colour.paint(
            RED,
            &format!(
                "unreadable certificate for {}",
                names(certificates.unreadable.iter().cloned()),
            ),
        ));
    }

    lines
}

/// A few names, and a count once there are too many to read.
fn names(names: impl Iterator<Item = String>) -> String {
    let names: Vec<String> = names.collect();
    let shown = names.len().min(NAMES);
    let listed = names[..shown].join(", ");

    match names.len() - shown {
        0 => listed,
        rest => format!("{listed} and {rest} more"),
    }
}

/// A span as an operator would say it: the two largest units that matter, and
/// never more precision than the number deserves.
fn since(seconds: u64) -> String {
    let (days, hours) = (seconds / 86_400, (seconds % 86_400) / 3600);
    let (minutes, seconds) = ((seconds % 3600) / 60, seconds % 60);

    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m"),
        (0, _, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

/// How far off something is, or that it is already behind — which is the case
/// worth colouring.
fn ahead(seconds: i64, colour: Colour) -> String {
    match seconds > 0 {
        true => format!("in {}", since(seconds.unsigned_abs())),
        false => colour.paint(YELLOW, "overdue"),
    }
}

/// A moment, to the second and in UTC, because that is what the host thinks
/// and a status may well be read from another machine.
fn stamp(at: time::OffsetDateTime) -> String {
    let (date, time) = (at.date(), at.time());

    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::tests::strip;
    use spaceport_core::status::{Down, Edge, Engine, Reconcile, Renewal, State, Tls};
    use time::OffsetDateTime;

    fn example() -> Status {
        Status {
            version: "0.4.1".to_owned(),
            started_at: OffsetDateTime::from_unix_timestamp(1_770_000_000).unwrap(),
            uptime_seconds: 275_040,
            config: "/etc/spaceport/spaceport.yaml".to_owned(),
            state: State {
                path: "/var/lib/spaceport/state.db".to_owned(),
                schema_version: Some(3),
                error: None,
            },
            edge: Edge {
                hostname: None,
                http: "0.0.0.0:80".parse().unwrap(),
                https: "0.0.0.0:443".parse().unwrap(),
                routed_hosts: 7,
            },
            tls: Tls {
                provider: "acme".to_owned(),
                directory: Some("https://acme.test/directory".to_owned()),
            },
            operator: "unix:/run/spaceport.sock".to_owned(),
            engine: Engine {
                reachable: true,
                description: "docker 27.1.1 (api 1.46)".to_owned(),
            },
            apps: Apps {
                running: 5,
                ready: 4,
                unreachable: vec!["worker-2".parse().unwrap()],
                recorded: 6,
                suspended: vec!["staging".parse().unwrap()],
                down: vec![Down {
                    id: "batch".parse().unwrap(),
                    reason: Some("no image `x:1`".to_owned()),
                }],
                error: None,
            },
            certificates: CertificateStatus {
                held: 4,
                next_renewal: Some(Renewal {
                    host: "api.example.com".to_owned(),
                    at: OffsetDateTime::from_unix_timestamp(1_772_000_000).unwrap(),
                    expires_at: OffsetDateTime::from_unix_timestamp(1_773_000_000).unwrap(),
                    in_seconds: 1_814_400,
                }),
                uncertified: vec!["staging.example.com".to_owned()],
                unreadable: Vec::new(),
                error: None,
            },
            reconcile: Reconcile {
                restored: 5,
                adopted: 4,
                failed: 1,
                swept: 1,
            },
            connections: 2,
        }
    }

    #[test]
    fn says_what_this_instance_is_and_how_long_it_has_been_it() {
        let block = super::status(&example(), Colour::No);

        assert!(block.contains("spaceport 0.4.1 — up 3d 4h"), "{block}");
        assert!(block.contains("(since 2026-02-02"), "{block}");
    }

    #[test]
    fn lays_the_values_out_in_one_column() {
        let block = super::status(&example(), Colour::No);

        for label in ["edge", "tls", "operator", "engine", "state", "config"] {
            let line = block
                .lines()
                .find(|line| line.starts_with(label))
                .unwrap_or_else(|| panic!("no `{label}` line in\n{block}"));

            assert!(
                line[LABEL..].starts_with(' ') || line.len() == LABEL,
                "`{label}` does not reach the value column: {line:?}"
            );
        }
    }

    /// The counts say there is something wrong; the names say where to go.
    #[test]
    fn names_what_is_not_working() {
        let block = super::status(&example(), Colour::No);

        assert!(
            block.contains("5 running, 4 ready, 1 unreachable (worker-2)"),
            "{block}"
        );
        assert!(
            block.contains("6 recorded, 1 suspended (staging), 1 not running"),
            "{block}"
        );
        assert!(block.contains("batch: no image `x:1`"), "{block}");
        assert!(
            block.contains("no certificate yet for staging.example.com"),
            "{block}"
        );
    }

    #[test]
    fn colours_the_trouble_and_nothing_else() {
        let block = super::status(&example(), Colour::Yes);

        assert!(block.contains(&format!("{RED}1 unreachable")), "{block:?}");
        // The engine is answering, so it is not painted at all.
        assert!(
            !block.contains(&format!("{RED}docker")) && !block.contains(&format!("{YELLOW}docker")),
            "{block:?}"
        );
        assert_eq!(strip(&block), super::status(&example(), Colour::No));
    }

    #[test]
    fn says_when_the_engine_is_gone() {
        let mut status = example();
        status.engine = Engine {
            reachable: false,
            description: "the docker daemon did not answer".to_owned(),
        };

        let block = super::status(&status, Colour::Yes);
        assert!(
            block.contains(&format!("{RED}the docker daemon did not answer")),
            "{block:?}"
        );
    }

    /// A spaceport with nothing wrong with it has nothing coloured in it.
    #[test]
    fn leaves_a_healthy_instance_plain() {
        let mut status = example();
        status.apps = Apps {
            running: 2,
            ready: 2,
            recorded: 2,
            ..Apps::default()
        };
        status.certificates.uncertified.clear();

        let block = super::status(&status, Colour::Yes);
        assert!(!block.contains(RED), "{block:?}");
        assert!(!block.contains(YELLOW), "{block:?}");
    }

    /// A spaceport connected to nothing says nothing, the same way one with no
    /// hostname of its own does.
    #[test]
    fn says_how_many_github_apps_it_is_connected_as_and_only_when_there_are_any() {
        let block = super::status(&example(), Colour::No);
        assert!(block.contains("connect   2 github apps"), "{block}");

        let mut none = example();
        none.connections = 0;
        assert!(
            !super::status(&none, Colour::No).contains("github app"),
            "{block}"
        );

        let mut one = example();
        one.connections = 1;
        assert!(
            super::status(&one, Colour::No).contains("1 github app\n"),
            "{block}"
        );
    }

    #[test]
    fn writes_a_span_at_the_precision_it_deserves() {
        assert_eq!(since(45), "45s");
        assert_eq!(since(600), "10m");
        assert_eq!(since(3_600 * 4 + 720), "4h 12m");
        assert_eq!(since(275_040), "3d 4h");
    }

    #[test]
    fn calls_a_renewal_that_should_have_happened_overdue() {
        assert_eq!(ahead(-5, Colour::No), "overdue");
        assert_eq!(ahead(86_400 * 21, Colour::No), "in 21d 0h");
    }

    #[test]
    fn counts_names_it_would_rather_not_list() {
        let many = (1..=8).map(|n| format!("app-{n}"));

        assert_eq!(names(many), "app-1, app-2, app-3, app-4, app-5 and 3 more");
    }
}
