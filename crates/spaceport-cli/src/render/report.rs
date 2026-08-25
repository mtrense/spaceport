//! Turning the two reports about a single thing into blocks an operator reads.
//!
//! A listing answers "which of these are there"; a report answers "what is this
//! one". So the layout is the other one the server used to write: labels in a
//! column, values against them, one line each — the same shape as
//! [`super::status`], for the same reason. The eye runs down the labels and
//! stops at the one it came for.
//!
//! The labels recede, the values keep the terminal's own foreground, and the
//! one saturated colour on the page is the thing that went wrong: a cache that
//! would not be read, an app installed nowhere, an entitlement that grants
//! nothing. A connection doing its job and a user whose roles all land is a
//! page of plain text.
//!
//! Colour is applied after padding, never before, for the reason it is in
//! [`super::table`]: an escape code is not a character on the screen, and a
//! label column measured with one in it is a column that does not line up.
//!
//! The sentences for the empty cases are written here rather than at the far
//! end, because they name the command an operator would type next and only this
//! side knows what they typed to get here.

use spaceport_core::app::AppId;
use spaceport_core::operator::wire;

use super::table::{Cell, columns};
use super::{Colour, DIM, RED, YELLOW};

/// What separates a label from its value, and the whole of the gutter.
const GUTTER: &str = "  ";

/// Where a GitHub App is installed from, which is a fixed string built from the
/// slug rather than anything the wire carries.
const INSTALL_URL: &str = "https://github.com/apps";

/// What the repositories under an installation are set in by, and the only
/// thing saying they belong to the account above them.
const UNDER: &str = "  ";

/// A block of labels and their values, each value starting at the same column.
///
/// A label of `""` continues the line above it: the value belongs to the stanza
/// it is written under, and repeating the label would read as a second one.
///
/// Values arrive painted, because only the caller knows which part of one is
/// the trouble — a value is last on its line and so is never padded, which is
/// what makes that safe.
fn report(fields: &[(&str, String)], colour: Colour) -> String {
    // Counted in characters and not in bytes, so a label somebody writes in
    // anything but ascii does not drag its value column left.
    let width = fields
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (label, value) in fields {
        let padded = format!("{label}{}", " ".repeat(width - label.chars().count()));

        // Nothing is not painted: a continuation's label column is blank, and
        // wrapping it would leave escape codes around whitespace.
        out.push_str(&match label.is_empty() {
            true => padded,
            false => colour.paint(DIM, &padded),
        });
        out.push_str(GUTTER);
        out.push_str(value);
        out.push('\n');
    }

    out
}

/// `spaceport connect show`.
pub fn connection(connection: &wire::Connection, colour: Colour) -> String {
    let mut fields = vec![
        ("app", connection.slug.clone()),
        ("name", connection.name.clone()),
        ("app id", connection.app_id.to_string()),
        ("owner", connection.owner.clone()),
        ("client id", connection.client_id.clone()),
        ("connected", connection.connected_at.clone()),
        // Written from nothing, because it says nothing that varies: the three
        // are set or the connection would not exist, so the wire does not carry
        // them and this side states them.
        (
            "secrets",
            "client secret, webhook secret, private key (not shown)".to_owned(),
        ),
    ];

    match &connection.installations {
        // Not a fault — a connected app nobody has installed is a registration
        // half done, and the value is the URL that finishes it.
        wire::Installations::Nowhere => fields.push((
            "installed",
            colour.paint(
                YELLOW,
                &format!(
                    "nowhere yet — install it at {INSTALL_URL}/{}/installations/new",
                    connection.slug
                ),
            ),
        )),
        wire::Installations::Somewhere { installations } => {
            for (at, installation) in installations.iter().enumerate() {
                fields.push((
                    // Only the first is labelled; the rest continue it.
                    if at == 0 { "installed" } else { "" },
                    format!(
                        "{} ({}), {}",
                        installation.account,
                        installation.account_type.to_lowercase(),
                        counted(installation.repositories.len()),
                    ),
                ));

                for repository in &installation.repositories {
                    fields.push(("", format!("{UNDER}{repository}")));
                }
            }
        }
        wire::Installations::Unreadable { error } => fields.push((
            "installed",
            colour.paint(RED, &format!("could not be read: {error}")),
        )),
    }

    match &connection.refreshed {
        wire::Refreshed::At { at } => fields.push(("refreshed", at.clone())),
        // Ordinary for a connection made seconds ago, so it says what is due
        // rather than warning about what has not happened.
        wire::Refreshed::Never => fields.push((
            "refreshed",
            "not yet — a pass is due within seconds of connecting, and hourly after that"
                .to_owned(),
        )),
        wire::Refreshed::Unreadable { error } => fields.push((
            "refreshed",
            colour.paint(RED, &format!("could not be read: {error}")),
        )),
    }

    report(&fields, colour)
}

/// How many repositories an installation reaches, said in English.
///
/// An installation with none is a real state and not an empty list printed as
/// nothing: somebody installed the app and granted it no repository, and "0
/// repositories" would read as a failure to look rather than as what was found.
fn counted(repositories: usize) -> String {
    match repositories {
        0 => "no repositories".to_owned(),
        1 => "1 repository".to_owned(),
        many => format!("{many} repositories"),
    }
}

/// What an identity's last login comes to, said in English.
///
/// A binding with no login behind it is a state somebody put the row in
/// deliberately — an operator asserted it with `auth user connect`, and the
/// person it names has not arrived yet — so it is said as that rather than as
/// an absent timestamp. "last login none" would read as a field this side
/// failed to fill in, and an operator who had just typed `connect` would go
/// looking for what went wrong with a row that is exactly as it should be.
///
/// Only the login half is written here: the connection, the handle and the
/// numeric id are printed by the caller either way, because the id is what the
/// binding is keyed by and a row nobody has signed in through is precisely the
/// one where an operator wants to check it against github.
fn signed_in(last_login_at: Option<&str>) -> String {
    match last_login_at {
        Some(at) => format!("last login {at}"),
        None => "bound by an operator — nobody has signed in through it yet".to_owned(),
    }
}

/// What an IdP says about this person, or `None` when it has said nothing.
///
/// `None` rather than a line of blanks, for [`signed_in`]'s reason pointed the
/// other way: a profile is written by a login and by nothing else, so an
/// identity without one is either a binding waiting for its person or an IdP
/// that holds no name and no verified address — neither of them a field this
/// side failed to fill in.
///
/// Each value is labelled and quoted — `name: "Ada Lovelace"` — rather than run
/// together into a sentence. Today there are two fields and prose would have
/// read well enough; the next connection kind is not obliged to stop at two,
/// and a line whose shape a reader has to know by heart is one they will
/// eventually misread. A field added later changes this list and nothing else.
/// The quotes are `Debug`'s, so a value containing a comma stays visibly one
/// value.
///
/// The address in particular is never printed bare. Bare is how the `email`
/// field above prints the *credential* — the address a one-time code goes to —
/// and this one is a third party's claim about a mailbox that signs nobody in.
/// Two addresses that look alike in one report are two an operator will
/// eventually treat as one.
///
/// The same spelling is in the daemon's own renderer, for the reason
/// [`signed_in`] is in both: this one answers `spaceport auth audit` and that
/// one answers `curl`, and two spellings of one fact would leave an operator
/// wondering which knows something.
fn asserted_profile(identity: &wire::IdentityRow) -> Option<String> {
    let said: Vec<String> = [
        ("name", &identity.profile_name),
        ("email", &identity.profile_email),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}: {value:?}")))
    .collect();

    match said.is_empty() {
        true => None,
        false => Some(said.join(", ")),
    }
}

/// `spaceport auth audit`: the report, and then what the user actually holds.
pub fn audit(audit: &wire::Audit, colour: Colour) -> String {
    let mut fields = vec![
        ("user", audit.user.to_string()),
        ("id", audit.id.to_string()),
        // Locked out is the one thing in the block worth a colour, the way it
        // is in the user listing: an active user is the ordinary case and says
        // so by looking ordinary.
        (
            "status",
            match audit.suspended {
                true => colour.paint(YELLOW, "suspended"),
                false => "active".to_owned(),
            },
        ),
    ];
    // Only when there is one: a user with no address on file is an ordinary
    // user, and an empty line would read as one somebody forgot to fill in.
    if let Some(email) = &audit.email {
        fields.push(("email", email.clone()));
    }

    match audit.sso.as_slice() {
        // No IdP has vouched for this user, which is a fact about how they sign
        // in rather than something wrong with them.
        [] => fields.push(("sso", "none — no IdP login recorded".to_owned())),
        linked => {
            // Labelled every time, not continued: each of these is a separate
            // account at a separate connection, and a blank label would read as
            // more detail about the one above.
            for identity in linked {
                fields.push((
                    "sso",
                    format!(
                        "`{}` as `{}` (id {}), {}",
                        identity.connection,
                        identity.external_login,
                        identity.external_id,
                        signed_in(identity.last_login_at.as_deref()),
                    ),
                ));
                // Attributed to the connection, always: a display name and an
                // address are what that IdP asserted at the last login, not
                // things spaceport knows about the person. The `email` field
                // above is the credential; this is somebody else's word.
                if let Some(profile) = asserted_profile(identity) {
                    fields.push((
                        "profile",
                        format!("`{}` says {profile}", identity.connection),
                    ));
                }
            }
        }
    }

    fields.push((
        "access",
        match audit.access.is_empty() {
            // Holding entitlements and reaching nothing is the misconfiguration
            // an audit exists to surface, so it is the one sentence here that
            // is coloured.
            true => colour.paint(
                YELLOW,
                "no app — no entitled role is declared by a deployed manifest",
            ),
            false => audit
                .access
                .iter()
                .map(AppId::to_string)
                .collect::<Vec<String>>()
                .join(", "),
        },
    ));

    let mut out = report(&fields, colour);

    if audit.entitlements.is_empty() {
        out.push_str(
            "\nno entitlements — `spaceport auth grant` is what hands out the first one\n",
        );

        return out;
    }

    let rows: Vec<Vec<Cell>> = audit
        .entitlements
        .iter()
        .map(|entitlement| {
            vec![
                Cell::plain(format!("{}@{}", entitlement.role, entitlement.app)),
                // Uncoloured, for the reason the signing key listing colours
                // nothing: where a grant came from is a fact about how it was
                // made, and by hand is no more a condition than by rule.
                Cell::plain(match &entitlement.mapped_rule {
                    Some(rule) => format!("mapped by rule `{rule}`"),
                    None => "manual".to_owned(),
                }),
                match entitlement.grants_access {
                    true => Cell::plain("yes"),
                    // Worth seeing and not worth alarm: the grant is stored and
                    // correct, and the app it names declares no such role.
                    false => Cell::painted("no — role not declared by the app", YELLOW),
                },
                Cell::plain(entitlement.granted_at.clone()),
            ]
        })
        .collect();

    out.push('\n');
    out.push_str(&columns(
        &["ENTITLEMENT", "ORIGIN", "ACCESS", "GRANTED"],
        &rows,
        colour,
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::tests::strip;

    fn connected() -> wire::Connection {
        wire::Connection {
            slug: "spaceport-ci".to_owned(),
            name: "Spaceport CI".to_owned(),
            app_id: 12345,
            owner: "acme".to_owned(),
            client_id: "Iv1.abc123".to_owned(),
            connected_at: "2026-02-02T00:00:00Z".to_owned(),
            installations: wire::Installations::Somewhere {
                installations: vec![wire::Installation {
                    account: "acme".to_owned(),
                    account_type: "Organization".to_owned(),
                    repositories: vec!["acme/blog".to_owned(), "acme/wiki".to_owned()],
                }],
            },
            refreshed: wire::Refreshed::At {
                at: "2026-02-02T01:00:00Z".to_owned(),
            },
        }
    }

    fn audited() -> wire::Audit {
        wire::Audit {
            user: "ada".parse().unwrap(),
            id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
            suspended: false,
            email: Some("ada@example.com".to_owned()),
            sso: vec![
                wire::IdentityRow {
                    connection: "spaceport-ci".to_owned(),
                    external_id: "4242".to_owned(),
                    external_login: "ada-gh".to_owned(),
                    last_login_at: Some("2026-02-02T00:00:00Z".to_owned()),
                    profile_name: Some("Ada Lovelace".to_owned()),
                    profile_email: Some("ada@ci.example".to_owned()),
                },
                // The other state a row can be in, in the same fixture: an
                // operator asserted this one and its owner has not arrived —
                // so no login has asserted a profile for it either.
                wire::IdentityRow {
                    connection: "spaceport-acme".to_owned(),
                    external_id: "1701".to_owned(),
                    external_login: "ada-acme".to_owned(),
                    last_login_at: None,
                    profile_name: None,
                    profile_email: None,
                },
            ],
            access: vec!["wiki".parse().unwrap()],
            entitlements: vec![
                wire::EntitlementRow {
                    role: "admin".parse().unwrap(),
                    app: "wiki".parse().unwrap(),
                    mapped_rule: None,
                    grants_access: true,
                    granted_at: "2026-02-02T00:00:00Z".to_owned(),
                },
                wire::EntitlementRow {
                    role: "reader".parse().unwrap(),
                    app: "blog".parse().unwrap(),
                    mapped_rule: Some("a1b2".to_owned()),
                    grants_access: false,
                    granted_at: "2026-02-03T00:00:00Z".to_owned(),
                },
            ],
        }
    }

    /// Transcribed from the prose path of `fn connection` in the operator
    /// server: this side is a second renderer of the same report, and a second
    /// renderer that says something else is a wrong one.
    const SHOWN: &str = "\
app        spaceport-ci
name       Spaceport CI
app id     12345
owner      acme
client id  Iv1.abc123
connected  2026-02-02T00:00:00Z
secrets    client secret, webhook secret, private key (not shown)
installed  acme (organization), 2 repositories
             acme/blog
             acme/wiki
refreshed  2026-02-02T01:00:00Z
";

    /// The same, transcribed from `fn audit_user`.
    const AUDITED: &str = "\
user     ada
id       00000000-0000-4000-8000-000000000001
status   active
email    ada@example.com
sso      `spaceport-ci` as `ada-gh` (id 4242), last login 2026-02-02T00:00:00Z
profile  `spaceport-ci` says name: \"Ada Lovelace\", email: \"ada@ci.example\"
sso      `spaceport-acme` as `ada-acme` (id 1701), bound by an operator — nobody has signed in through it yet
access   wiki

ENTITLEMENT  ORIGIN                 ACCESS                             GRANTED
admin@wiki   manual                 yes                                2026-02-02T00:00:00Z
reader@blog  mapped by rule `a1b2`  no — role not declared by the app  2026-02-03T00:00:00Z
";

    #[test]
    fn writes_what_the_server_wrote_for_a_connection() {
        assert_eq!(connection(&connected(), Colour::No), SHOWN);
    }

    #[test]
    fn writes_what_the_server_wrote_for_an_audit() {
        assert_eq!(audit(&audited(), Colour::No), AUDITED);
    }

    /// A report is coloured, never reworded.
    #[test]
    fn says_the_same_thing_coloured_as_plain() {
        assert_eq!(strip(&connection(&connected(), Colour::Yes)), SHOWN);
        assert_eq!(strip(&audit(&audited(), Colour::Yes)), AUDITED);
    }

    /// An escape code is not a character on the screen: the value column has to
    /// start in the same place whether or not the labels are painted.
    #[test]
    fn lines_the_values_up_whether_or_not_there_is_colour() {
        // `client id`, `connected`, `installed` and `refreshed` are the widest
        // labels a connection has, and the gutter follows them.
        const VALUE: usize = 9 + GUTTER.len();

        for colour in [Colour::No, Colour::Yes] {
            for line in connection(&connected(), colour).lines() {
                let line = strip(line);
                // A continuation has no label, and its value is set in under
                // the one above rather than against the column.
                if line.starts_with(' ') {
                    continue;
                }

                let (label, value) = line.split_at(VALUE);
                assert!(label.ends_with(GUTTER), "{line:?} under {colour:?}");
                assert!(!value.starts_with(' '), "{line:?} under {colour:?}");
            }
        }
    }

    /// A connection doing its job and a user whose roles all land have nothing
    /// saturated on the page.
    #[test]
    fn leaves_a_healthy_connection_and_audit_plain() {
        let block = connection(&connected(), Colour::Yes);
        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");

        let mut audited = audited();
        audited.entitlements.truncate(1);
        let block = audit(&audited, Colour::Yes);
        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");
    }

    /// Registered and installed nowhere is a registration half done, so the
    /// value is the URL that finishes it.
    #[test]
    fn says_where_to_install_an_app_installed_nowhere() {
        let mut shown = connected();
        shown.installations = wire::Installations::Nowhere;

        let block = connection(&shown, Colour::Yes);
        assert!(
            block.contains(&format!(
                "{YELLOW}nowhere yet — install it at https://github.com/apps/spaceport-ci/installations/new"
            )),
            "{block:?}"
        );
        assert!(!block.contains(RED), "{block:?}");
    }

    #[test]
    fn counts_the_repositories_an_installation_reaches_in_english() {
        assert_eq!(counted(0), "no repositories");
        assert_eq!(counted(1), "1 repository");
        assert_eq!(counted(9), "9 repositories");
    }

    /// A cache that would not be read is the one thing here to go and do
    /// something about.
    #[test]
    fn colours_a_cache_that_would_not_be_read() {
        let mut shown = connected();
        shown.installations = wire::Installations::Unreadable {
            error: "the database is locked".to_owned(),
        };
        shown.refreshed = wire::Refreshed::Unreadable {
            error: "the database is locked".to_owned(),
        };

        let block = connection(&shown, Colour::Yes);
        assert_eq!(
            block
                .matches(&format!("{RED}could not be read: the database is locked"))
                .count(),
            2,
            "{block:?}"
        );
        assert_eq!(strip(&block), connection(&shown, Colour::No));
    }

    /// No pass has run yet, which for a connection made seconds ago is
    /// ordinary — so it is said and not coloured.
    #[test]
    fn leaves_a_connection_nothing_has_refreshed_yet_plain() {
        let mut shown = connected();
        shown.refreshed = wire::Refreshed::Never;

        let block = connection(&shown, Colour::Yes);
        assert!(
            strip(&block).contains(
                "refreshed  not yet — a pass is due within seconds of connecting, and hourly after that\n"
            ),
            "{block:?}"
        );
        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");
    }

    /// The paragraph replaces the table entirely, and keeps the blank line the
    /// table would have been set off by.
    #[test]
    fn says_what_to_type_when_a_user_holds_nothing() {
        let mut audited = audited();
        audited.entitlements.clear();
        audited.access.clear();

        let block = audit(&audited, Colour::No);
        assert!(
            block.ends_with(
                "\nno entitlements — `spaceport auth grant` is what hands out the first one\n"
            ),
            "{block:?}"
        );
        assert!(!block.contains("ENTITLEMENT"), "{block:?}");
    }

    /// An entitlement that reaches nothing is what an audit exists to surface,
    /// and so is a user who holds several and reaches none.
    #[test]
    fn colours_a_grant_that_gets_nobody_anywhere() {
        let mut audited = audited();
        audited.access.clear();

        let block = audit(&audited, Colour::Yes);
        assert!(
            block.contains(&format!(
                "{YELLOW}no app — no entitled role is declared by a deployed manifest"
            )),
            "{block:?}"
        );
        assert!(
            block.contains(&format!("{YELLOW}no — role not declared by the app")),
            "{block:?}"
        );
        // Where a grant came from is a fact, not a fault.
        assert!(!block.contains(&format!("{YELLOW}manual")), "{block:?}");
        assert!(!block.contains(RED), "{block:?}");
    }

    #[test]
    fn colours_a_locked_out_user_the_way_the_listing_does() {
        let mut audited = audited();
        audited.suspended = true;

        let block = audit(&audited, Colour::Yes);
        assert!(block.contains(&format!("{YELLOW}suspended")), "{block:?}");
        assert!(!audit(&super::tests::audited(), Colour::Yes).contains(&format!("{YELLOW}active")));
    }

    /// A user with no address on file is an ordinary user, and says so with
    /// nothing rather than with an empty line.
    ///
    /// The address the *connection* claims is a different thing and stays: this
    /// user has no credential the email connection would sign them in by, and
    /// github says it holds an address for them anyway. Both facts are true at
    /// once, which is why the field is checked by its label rather than by the
    /// word appearing anywhere in the report.
    #[test]
    fn leaves_out_an_email_there_is_none_of() {
        let mut audited = audited();
        audited.email = None;

        let block = audit(&audited, Colour::No);
        assert!(
            !block.lines().any(|line| line.starts_with("email")),
            "{block:?}"
        );
        assert!(block.contains(r#"email: "ada@ci.example""#), "{block:?}");
    }

    /// The two states an identity row can be in, told apart in words: a login
    /// has a date, and a binding nobody has arrived through says who put it
    /// there. An operator who has just run `auth user connect` must not read
    /// their own successful command as a field that failed to fill in — and
    /// the numeric id, which is what the binding is keyed by, is printed either
    /// way, because a row with no login behind it is the one worth checking
    /// against github.
    #[test]
    fn says_a_binding_nobody_has_signed_in_through_is_a_binding() {
        let mut audited = audited();
        // The entitlement that reaches nothing is the only coloured thing in
        // the fixture, and this test is about what the sso lines are not.
        audited.entitlements.truncate(1);
        let block = audit(&audited, Colour::Yes);

        assert!(
            block.contains("`spaceport-ci` as `ada-gh` (id 4242), last login 2026-02-02T00:00:00Z"),
            "{block:?}",
        );
        assert!(
            block.contains(
                "`spaceport-acme` as `ada-acme` (id 1701), bound by an operator — nobody has \
                 signed in through it yet"
            ),
            "{block:?}",
        );
        // Neither is a fault: an assertion waiting on its owner is exactly what
        // an operator asked for.
        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");
    }

    /// An identity the operator has never heard of is not the same thing as an
    /// identity nobody has signed in through, and the report must not spell
    /// them the same way.
    #[test]
    fn keeps_no_identity_apart_from_an_unused_one() {
        let mut audited = audited();
        audited.sso.clear();

        let block = audit(&audited, Colour::No);
        assert!(
            block.contains("sso     none — no IdP login recorded"),
            "{block:?}"
        );
        assert!(!block.contains("bound by an operator"), "{block:?}");
    }
}
