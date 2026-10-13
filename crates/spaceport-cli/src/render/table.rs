//! Turning the rows a listing sends into columns an operator reads.
//!
//! The layout is the one the server used to write and is not up for
//! reinvention: every column as wide as the widest thing in it, two spaces
//! between, nothing trailing. What is new is that a cell can be worth
//! noticing, and only one kind of cell ever is — the one saying something is
//! wrong. A listing of healthy apps is a page of plain text with a dim header
//! over it.
//!
//! Colour is applied after padding, never before: an escape code is not a
//! character on the screen, and a column measured with one in it is a column
//! that does not line up.
//!
//! The empty listings say their sentence here rather than at the far end,
//! because the sentence names the command the operator would type next and
//! only this side knows what they typed to get here.

use spaceport_core::app::{AppId, Pattern};
use spaceport_core::auth::UserId;
use spaceport_core::operator::wire;

use super::{BOLD, Colour, DIM, RED, YELLOW};

/// How wide the gutter between two columns is.
const GUTTER: &str = "  ";

/// One thing in one column, and whether it is the thing that went wrong.
///
/// The text and the colour are kept apart until the very end because the width
/// maths is over the text: a painted cell is longer than what it prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    text: String,
    colour: Option<&'static str>,
}

impl Cell {
    /// A cell in the terminal's own foreground, which is what almost every
    /// cell is: it is being read, not scanned past.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            colour: None,
        }
    }

    /// A cell worth spending the line's one colour on.
    pub fn painted(text: impl Into<String>, colour: &'static str) -> Self {
        Self {
            text: text.into(),
            colour: Some(colour),
        }
    }

    /// The same cell in `colour`, or as it was when there is nothing to say.
    fn maybe(text: impl Into<String>, colour: Option<&'static str>) -> Self {
        Self {
            text: text.into(),
            colour,
        }
    }

    /// What this occupies on the screen, which is what a column is measured
    /// in.
    fn width(&self) -> usize {
        self.text.chars().count()
    }

    /// The cell padded out to `width` and only then painted.
    fn write(&self, width: usize, colour: Colour) -> String {
        let padded = format!("{}{}", self.text, " ".repeat(width - self.width()));

        match self.colour {
            // Nothing is not painted: wrapping an empty cell would leave escape
            // codes around nothing and put something where the line ends.
            Some(_) if self.text.is_empty() => padded,
            Some(code) => colour.paint(code, &padded),
            None => padded,
        }
    }
}

/// A header row and its rows, each column as wide as the widest thing in it.
///
/// The headers recede: they are read once, to find which column to run the eye
/// down, and never again.
pub fn columns(headers: &[&str], rows: &[Vec<Cell>], colour: Colour) -> String {
    let header: Vec<Cell> = headers
        .iter()
        .map(|header| Cell::painted(*header, DIM))
        .collect();

    let mut widths: Vec<usize> = header.iter().map(Cell::width).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.width());
        }
    }

    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows) {
        let mut line = String::new();
        for (at, (cell, width)) in row.iter().zip(&widths).enumerate() {
            if at > 0 {
                line.push_str(GUTTER);
            }
            // The last column is not padded: trailing spaces would be the only
            // thing past the end of it.
            let width = match at + 1 == row.len() {
                true => cell.width(),
                false => *width,
            };
            line.push_str(&cell.write(width, colour));
        }

        // A row whose last cells are empty ends where its last cell with
        // something in it does. Nothing painted ends in a space — an empty cell
        // is never painted and a painted one closes with a reset — so this
        // cannot eat a colour code.
        out.push_str(line.trim_end());
        out.push('\n');
    }

    out
}

/// `spaceport apps list`.
pub fn apps(rows: &[wire::AppRow], pattern: Option<&Pattern>, colour: Colour) -> String {
    if rows.is_empty() {
        return match pattern {
            Some(pattern) => format!("no app matches `{pattern}`\n"),
            // Not "nothing is running": an empty listing means spaceport has no
            // app under any name at all, running or otherwise.
            None => "spaceport has no apps\n".to_owned(),
        };
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|app| {
            vec![
                Cell::painted(app.id.to_string(), BOLD),
                Cell::plain(app.source.clone()),
                Cell::maybe(app.state.as_str(), state_colour(&app.state)),
                Cell::plain(app.hosts.join(", ")),
            ]
        })
        .collect();

    columns(&["APP", "SOURCE", "STATUS", "HOSTS"], &rows, colour)
}

/// How much an app's state wants to be noticed.
///
/// Only the states there is something to go and do about are saturated. A
/// suspended app and one that was never started are doing what they were told
/// and are still not serving, which is worth seeing and not worth alarm; a
/// ready or tracked app is worth neither.
fn state_colour(state: &wire::AppState) -> Option<&'static str> {
    if state.is_trouble() {
        return Some(RED);
    }

    match state {
        wire::AppState::Suspended | wire::AppState::NotRunning => Some(YELLOW),
        _ => None,
    }
}

/// `spaceport connect list`.
///
/// Nothing is coloured: which GitHub Apps this spaceport is registered as is a
/// decision rather than a condition, the argument the status block's connection
/// line makes.
pub fn connections(rows: &[wire::ConnectionRow], colour: Colour) -> String {
    if rows.is_empty() {
        return "no github apps are connected — connect one with `spaceport connect github --manual`\n".to_owned();
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|connection| {
            vec![
                Cell::painted(connection.slug.clone(), BOLD),
                Cell::plain(connection.app_id.to_string()),
                Cell::plain(connection.owner.clone()),
                Cell::plain(connection.connected_at.clone()),
            ]
        })
        .collect();

    columns(&["SLUG", "APP ID", "OWNER", "CONNECTED"], &rows, colour)
}

/// `spaceport auth user list`.
pub fn users(rows: &[wire::UserRow], pattern: Option<&Pattern>, colour: Colour) -> String {
    if rows.is_empty() {
        return match pattern {
            Some(pattern) => format!("no user matches `{pattern}`\n"),
            None => {
                "no users exist — create one with `spaceport auth user create <slug>`\n".to_owned()
            }
        };
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|user| {
            vec![
                Cell::painted(user.slug.to_string(), BOLD),
                Cell::plain(user.id.to_string()),
                // Locked out is the one thing on the line worth a colour: an
                // active user is the ordinary case and says so by looking
                // ordinary.
                match user.suspended {
                    true => Cell::painted("suspended", YELLOW),
                    false => Cell::plain("active"),
                },
                Cell::plain(user.email.clone().unwrap_or_default()),
                Cell::plain(user.created_at.clone()),
            ]
        })
        .collect();

    columns(&["USER", "ID", "STATUS", "EMAIL", "CREATED"], &rows, colour)
}

/// `spaceport auth log`.
///
/// Structure only. Every line here is something that already happened, and a
/// record of the past is not a condition to act on.
pub fn log(rows: &[wire::LogRow], user: Option<&UserId>, colour: Colour) -> String {
    if rows.is_empty() {
        return match user {
            Some(user) => format!("nothing is recorded about `{user}`\n"),
            None => {
                "nothing has happened yet — every auth command that changes something lands here\n"
                    .to_owned()
            }
        };
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|entry| {
            vec![
                Cell::plain(entry.at.clone()),
                Cell::plain(entry.kind.clone()),
                Cell::plain(entry.user.clone().unwrap_or_default()),
                Cell::plain(entry.origin.clone()),
                Cell::plain(entry.detail.clone().unwrap_or_default()),
            ]
        })
        .collect();

    columns(&["AT", "KIND", "USER", "ORIGIN", "DETAIL"], &rows, colour)
}

/// `spaceport auth key list`.
///
/// Nothing is saturated. A retired key is not a fault: it stays in the JWKS
/// until the last JWT it signed has expired, which is the rotation working.
pub fn keys(rows: &[wire::SigningKeyRow], colour: Colour) -> String {
    if rows.is_empty() {
        return "no signing key yet — the first gated request or jwks read mints one\n".to_owned();
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|key| {
            vec![
                Cell::painted(key.kid.clone(), BOLD),
                Cell::plain(match key.current {
                    true => "current",
                    false => "retired",
                }),
                Cell::plain(key.created_at.clone()),
                Cell::plain(key.retired_at.clone().unwrap_or_default()),
            ]
        })
        .collect();

    columns(&["KID", "STATE", "CREATED", "RETIRED"], &rows, colour)
}

/// `spaceport auth mapping list`.
///
/// Structure only: a rule that exists is a rule somebody wrote.
pub fn mappings(rows: &[wire::MappingRow], app: Option<&AppId>, colour: Colour) -> String {
    if rows.is_empty() {
        return match app {
            Some(app) => {
                format!("no mappings exist for `{app}` — `spaceport auth mapping add` writes one\n")
            }
            None => {
                "no mappings exist — `spaceport auth mapping add` writes the first one\n".to_owned()
            }
        };
    }

    let rows: Vec<Vec<Cell>> = rows
        .iter()
        .map(|mapping| {
            vec![
                Cell::painted(mapping.rule_id.clone(), BOLD),
                Cell::plain(mapping.grants.clone()),
                Cell::plain(mapping.connection.clone()),
                Cell::plain(mapping.conditions.join(", ")),
                Cell::plain(mapping.created_at.clone()),
            ]
        })
        .collect();

    columns(&["RULE", "MAPS", "VIA", "WHEN", "CREATED"], &rows, colour)
}

/// What a derived session's id is written behind, and the only thing saying it
/// belongs to the row above.
const DERIVED: &str = "↳ ";

/// `spaceport auth session list`.
///
/// One table rather than two, told apart by its KIND column, and flat rather
/// than nested: a derived app session follows the session it came from, set in
/// by the one mark that says it dies with it.
///
/// Structure only. Everything here is a live credential doing what it was
/// minted to do; the question an operator brings is what to revoke, and no
/// column answers that on its own.
pub fn sessions(listed: &wire::Sessions, colour: Colour) -> String {
    if listed.is_empty() {
        // The slug the listing came back with, not whatever was typed to ask
        // for it: an operator who named the user by id gets a command to type
        // next, and it should be one that reads as the name of a person.
        let user = &listed.user;

        return format!(
            "`{user}` has no sessions or api keys — `spaceport auth session mint {user}` starts a session\n"
        );
    }

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    for session in &listed.sessions {
        rows.push(vec![
            Cell::plain("session"),
            Cell::plain(session.id.clone()),
            Cell::plain(""),
            Cell::plain(""),
            Cell::plain(session.created_at.clone()),
            Cell::plain(session.expires_at.clone()),
        ]);
        for derived in &session.derived {
            rows.push(vec![
                Cell::plain("app"),
                Cell::plain(format!("{DERIVED}{}", derived.app)),
                Cell::plain(""),
                Cell::plain(""),
                Cell::plain(derived.created_at.clone()),
                Cell::plain(derived.expires_at.clone()),
            ]);
        }
    }
    for key in &listed.keys {
        rows.push(vec![
            Cell::plain("key"),
            Cell::plain(key.id.clone()),
            Cell::plain(key.prefix_tail.clone()),
            Cell::plain(format!("{}@{}", key.role, key.app)),
            Cell::plain(key.created_at.clone()),
            Cell::plain(key.expires_at.clone()),
        ]);
    }

    columns(
        &["KIND", "ID", "KEY", "GRANTS", "CREATED", "EXPIRES"],
        &rows,
        colour,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::tests::strip;

    fn app(id: &str, state: wire::AppState) -> wire::AppRow {
        wire::AppRow {
            id: id.parse().unwrap(),
            source: "manifest".to_owned(),
            state,
            hosts: vec![format!("{id}.example.com")],
        }
    }

    fn listed() -> Vec<wire::AppRow> {
        vec![
            app("api", wire::AppState::Ready),
            app(
                "batch",
                wire::AppState::Down {
                    reason: Some("no image `x:1`".to_owned()),
                },
            ),
            app("staging", wire::AppState::Suspended),
        ]
    }

    fn user(slug: &str, suspended: bool) -> wire::UserRow {
        wire::UserRow {
            slug: slug.parse().unwrap(),
            id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
            suspended,
            email: None,
            created_at: "2026-02-02T00:00:00Z".to_owned(),
        }
    }

    fn connection() -> wire::ConnectionRow {
        wire::ConnectionRow {
            slug: "spaceport-dev".to_owned(),
            app_id: 12345,
            owner: "acme".to_owned(),
            connected_at: "2026-02-02T00:00:00Z".to_owned(),
        }
    }

    fn entry() -> wire::LogRow {
        wire::LogRow {
            at: "2026-02-02T00:00:00Z".to_owned(),
            kind: "user.create".to_owned(),
            user: Some("ada".to_owned()),
            origin: "cli".to_owned(),
            detail: None,
        }
    }

    fn mapping() -> wire::MappingRow {
        wire::MappingRow {
            rule_id: "r1".to_owned(),
            grants: "reader@wiki".to_owned(),
            connection: "github".to_owned(),
            conditions: vec!["org=acme".to_owned(), "team=ops".to_owned()],
            created_at: "2026-02-02T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn writes_the_header_in_caps_and_the_rows_under_it() {
        let table = apps(&listed(), None, Colour::No);
        let lines: Vec<&str> = table.lines().collect();

        assert!(lines[0].starts_with("APP"), "{table}");
        assert!(lines[1].starts_with("api"), "{table}");
        assert_eq!(lines.len(), 4, "{table}");
        assert!(table.ends_with('\n'), "{table:?}");
    }

    /// The layout the server used to write, down to the two spaces and the
    /// unpadded last column.
    #[test]
    fn pads_every_column_but_the_last_and_leaves_nothing_trailing() {
        let table = apps(&listed(), None, Colour::No);

        for line in table.lines() {
            assert_eq!(line, line.trim_end(), "{line:?}");
        }
        assert!(
            table.contains("staging  manifest  suspended  staging.example.com"),
            "{table}"
        );
    }

    #[test]
    fn writes_no_escape_codes_without_colour() {
        assert!(!apps(&listed(), None, Colour::No).contains('\x1b'));
        assert!(!users(&[user("ada", true)], None, Colour::No).contains('\x1b'));
    }

    /// Colour is added to a listing, never a word of it changed.
    #[test]
    fn says_the_same_thing_coloured_as_plain() {
        assert_eq!(
            strip(&apps(&listed(), None, Colour::Yes)),
            apps(&listed(), None, Colour::No),
        );

        let listed = &[user("ada", true), user("bob", false)];
        assert_eq!(
            strip(&users(listed, None, Colour::Yes)),
            users(listed, None, Colour::No),
        );
    }

    /// An escape code is not a character on the screen: a column that lines up
    /// plain has to line up coloured too, however long the cells are.
    #[test]
    fn lines_the_columns_up_whether_or_not_there_is_colour() {
        let rows = vec![
            app("a", wire::AppState::Ready),
            app("a-much-longer-name", wire::AppState::Unreachable),
        ];

        let starts = |colour| -> Vec<usize> {
            apps(&rows, None, colour)
                .lines()
                .skip(1)
                .map(|line| strip(line).find("manifest").expect("a source column"))
                .collect()
        };

        let plain = starts(Colour::No);
        assert_eq!(plain[0], plain[1], "plain columns do not line up");
        assert_eq!(starts(Colour::Yes), plain, "coloured columns moved");
    }

    /// A listing with nothing wrong in it has nothing saturated in it.
    #[test]
    fn leaves_a_healthy_listing_plain() {
        let healthy = vec![
            app("api", wire::AppState::Ready),
            app("wiki", wire::AppState::Tracked),
        ];
        let table = apps(&healthy, None, Colour::Yes);

        assert!(!table.contains(RED), "{table:?}");
        assert!(!table.contains(YELLOW), "{table:?}");
    }

    #[test]
    fn colours_the_state_by_whether_there_is_something_to_do_about_it() {
        let table = apps(&listed(), None, Colour::Yes);

        assert!(table.contains(&format!("{RED}down")), "{table:?}");
        assert!(table.contains(&format!("{YELLOW}suspended")), "{table:?}");
        // The healthy one is not painted at all.
        assert!(!table.contains(&format!("{RED}ready")), "{table:?}");
        assert!(!table.contains(&format!("{YELLOW}ready")), "{table:?}");
    }

    #[test]
    fn colours_a_suspended_user_and_leaves_an_active_one_alone() {
        let table = users(&[user("ada", true), user("bob", false)], None, Colour::Yes);

        assert!(table.contains(&format!("{YELLOW}suspended")), "{table:?}");
        assert!(!table.contains(&format!("{YELLOW}active")), "{table:?}");
    }

    /// Whether a key is the current one is a fact about rotation, not a fault.
    #[test]
    fn leaves_a_retired_key_uncoloured() {
        let table = keys(
            &[
                wire::SigningKeyRow {
                    kid: "k2".to_owned(),
                    current: true,
                    created_at: "2026-02-02T00:00:00Z".to_owned(),
                    retired_at: None,
                },
                wire::SigningKeyRow {
                    kid: "k1".to_owned(),
                    current: false,
                    created_at: "2025-11-04T00:00:00Z".to_owned(),
                    retired_at: Some("2026-02-02T00:00:00Z".to_owned()),
                },
            ],
            Colour::Yes,
        );

        assert!(!table.contains(RED) && !table.contains(YELLOW), "{table:?}");
        // A key still in service has no retired-at, and says so with nothing.
        assert!(
            strip(&table).contains("k2   current  2026-02-02T00:00:00Z\n"),
            "{table:?}"
        );
    }

    /// The indent is the whole of what says a derived session dies with the
    /// one above it, so the order it is written in is part of the answer.
    #[test]
    fn writes_a_derived_session_under_the_one_it_came_from() {
        let listed = wire::Sessions {
            user: "ada".parse().unwrap(),
            sessions: vec![wire::SessionRow {
                id: "s1".to_owned(),
                created_at: "2026-02-02T00:00:00Z".to_owned(),
                expires_at: "2026-02-03T00:00:00Z".to_owned(),
                derived: vec![wire::DerivedRow {
                    app: "wiki".to_owned(),
                    created_at: "2026-02-02T01:00:00Z".to_owned(),
                    expires_at: "2026-02-02T02:00:00Z".to_owned(),
                }],
            }],
            keys: vec![wire::ApiKeyRow {
                id: "k1".to_owned(),
                prefix_tail: "sp_…9f2".to_owned(),
                role: "reader".to_owned(),
                app: "wiki".to_owned(),
                created_at: "2026-02-02T00:00:00Z".to_owned(),
                expires_at: "2026-05-03T00:00:00Z".to_owned(),
            }],
        };

        let table = sessions(&listed, Colour::No);
        let kinds: Vec<&str> = table
            .lines()
            .skip(1)
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();

        assert_eq!(kinds, ["session", "app", "key"], "{table}");
        assert!(table.contains("↳ wiki"), "{table}");
        assert!(table.contains("reader@wiki"), "{table}");
        // KEY and GRANTS are the key's alone, and stay empty above it.
        assert!(
            table
                .lines()
                .nth(1)
                .unwrap()
                .ends_with("2026-02-03T00:00:00Z"),
            "{table}"
        );
    }

    /// A connection is a decision, not a condition: the slug is bold and the
    /// rest is written as it came, with no word of it changed by colour.
    #[test]
    fn writes_a_connection_under_its_header() {
        let rows = &[connection()];
        let table = connections(rows, Colour::No);

        assert_eq!(
            table,
            "SLUG           APP ID  OWNER  CONNECTED\n\
             spaceport-dev  12345   acme   2026-02-02T00:00:00Z\n",
        );
        assert_eq!(strip(&connections(rows, Colour::Yes)), table);
    }

    /// A log line with no detail ends where its origin does: an absent field is
    /// an empty cell, and an empty last cell leaves nothing trailing.
    #[test]
    fn writes_a_log_entry_under_its_header() {
        let rows = &[entry()];
        let table = log(rows, None, Colour::No);

        assert_eq!(
            table,
            "AT                    KIND         USER  ORIGIN  DETAIL\n\
             2026-02-02T00:00:00Z  user.create  ada   cli\n",
        );
        assert_eq!(strip(&log(rows, None, Colour::Yes)), table);
    }

    /// A rule's conditions are one cell, joined the way they would be typed.
    #[test]
    fn writes_a_mapping_under_its_header() {
        let rows = &[mapping()];
        let table = mappings(rows, None, Colour::No);

        assert_eq!(
            table,
            "RULE  MAPS         VIA     WHEN                CREATED\n\
             r1    reader@wiki  github  org=acme, team=ops  2026-02-02T00:00:00Z\n",
        );
        assert_eq!(strip(&mappings(rows, None, Colour::Yes)), table);
    }

    /// Every empty listing names the command that would end it — which is why
    /// the sentence is written here and not at the far end.
    #[test]
    fn says_what_to_type_when_there_is_nothing_to_list() {
        let pattern: Pattern = "web-*".parse().unwrap();
        let id: AppId = "wiki".parse().unwrap();
        let user: UserId = "00000000-0000-4000-8000-000000000001".parse().unwrap();

        assert_eq!(apps(&[], None, Colour::Yes), "spaceport has no apps\n");
        assert_eq!(
            apps(&[], Some(&pattern), Colour::Yes),
            "no app matches `web-*`\n"
        );
        assert_eq!(
            connections(&[], Colour::Yes),
            "no github apps are connected — connect one with `spaceport connect github --manual`\n"
        );
        assert_eq!(
            users(&[], None, Colour::Yes),
            "no users exist — create one with `spaceport auth user create <slug>`\n"
        );
        assert_eq!(
            users(&[], Some(&pattern), Colour::Yes),
            "no user matches `web-*`\n"
        );
        assert_eq!(
            log(&[], None, Colour::Yes),
            "nothing has happened yet — every auth command that changes something lands here\n"
        );
        assert_eq!(
            log(&[], Some(&user), Colour::Yes),
            format!("nothing is recorded about `{user}`\n")
        );
        assert_eq!(
            keys(&[], Colour::Yes),
            "no signing key yet — the first gated request or jwks read mints one\n"
        );
        assert_eq!(
            mappings(&[], None, Colour::Yes),
            "no mappings exist — `spaceport auth mapping add` writes the first one\n"
        );
        assert_eq!(
            mappings(&[], Some(&id), Colour::Yes),
            "no mappings exist for `wiki` — `spaceport auth mapping add` writes one\n"
        );
        assert_eq!(
            sessions(
                &wire::Sessions {
                    user: "ada".parse().unwrap(),
                    sessions: Vec::new(),
                    keys: Vec::new(),
                },
                Colour::Yes
            ),
            "`ada` has no sessions or api keys — `spaceport auth session mint ada` starts a session\n"
        );
    }
}
