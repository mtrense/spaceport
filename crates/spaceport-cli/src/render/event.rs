//! Turning an event into a line for a person to read.
//!
//! The one saturated colour is the level: an operator watching a stream is
//! looking for the line that went wrong. The message itself keeps the
//! terminal's own foreground, because it is the part being read.

use spaceport_core::events::{Event, Level};

use super::{BOLD, BOLD_RED, CYAN, Colour, DIM, GREEN, RED, YELLOW};

/// The field whose value is the reason the line is being read at all.
const ERROR_FIELD: &str = "error";

/// One event as a line.
///
/// The message is what the call site wrote; the fields after it are what it
/// wrote the message about, and they keep the shape they were recorded in.
pub fn line(event: &Event, colour: Colour) -> String {
    let time = event.at.time();
    let clock = format!(
        "{:02}:{:02}:{:02}",
        time.hour(),
        time.minute(),
        time.second()
    );

    let mut line = format!(
        "{} {} {}",
        colour.paint(DIM, &clock),
        colour.paint(
            level_colour(event.level),
            &format!("{:<5}", event.level.as_str().to_uppercase()),
        ),
        // `as_str`, not the category itself: a width applies to what `Display`
        // writes only if the impl honours it, and one that writes straight to
        // the formatter — as every id in spaceport does — silently does not.
        colour.paint(CYAN, &format!("{:<13}", event.category.as_str())),
    );

    if let Some(app) = &event.app {
        line.push(' ');
        line.push_str(&colour.paint(BOLD, &format!("{app}:")));
    }

    line.push(' ');
    line.push_str(&event.message);

    for (name, value) in &event.fields {
        let value = match name.as_str() {
            ERROR_FIELD => colour.paint(RED, value),
            _ => value.clone(),
        };

        line.push(' ');
        line.push_str(&colour.paint(DIM, &format!("{name}=")));
        line.push_str(&value);
    }

    line
}

/// How much a level wants to be noticed. The two quiet ones recede rather than
/// take a hue of their own: a stream carrying one line per request is mostly
/// them, and mostly them is exactly what should not be lit up.
fn level_colour(level: Level) -> &'static str {
    match level {
        Level::Error => BOLD_RED,
        Level::Warn => YELLOW,
        Level::Info => GREEN,
        Level::Debug | Level::Trace => DIM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::RESET;
    use crate::render::tests::strip;
    use spaceport_core::events::Event;

    fn event(level: Level, app: Option<&str>) -> Event {
        Event {
            app: app.map(|app| app.parse().unwrap()),
            ..Event::now(level, "app.apply", "app is ready")
        }
    }

    fn with_field(level: Level, name: &str, value: &str) -> Event {
        let mut event = event(level, Some("web-api"));
        event.fields.insert(name.to_owned(), value.to_owned());

        event
    }

    #[test]
    fn writes_the_level_the_category_the_app_and_the_message() {
        let line = line(&event(Level::Info, Some("web-api")), Colour::No);

        assert!(line.contains("INFO"), "{line}");
        assert!(line.contains("app.apply"), "{line}");
        assert!(line.contains("web-api:"), "{line}");
        assert!(line.ends_with("app is ready"), "{line}");
    }

    #[test]
    fn writes_the_fields_after_the_message() {
        let line = line(&with_field(Level::Info, "after", "1.2s"), Colour::No);

        assert!(line.ends_with("app is ready after=1.2s"), "{line}");
    }

    /// An event about no app in particular says so by leaving the column out
    /// rather than by making one up.
    #[test]
    fn leaves_out_an_app_that_is_not_there() {
        let line = line(&event(Level::Info, None), Colour::No);

        // The message follows the category directly, with nothing between.
        assert!(line.contains("app.apply     app is ready"), "{line}");
    }

    #[test]
    fn writes_no_escape_codes_without_colour() {
        let line = line(&with_field(Level::Error, "error", "it broke"), Colour::No);

        assert!(!line.contains('\x1b'), "{line:?}");
    }

    #[test]
    fn colours_the_level_by_how_much_it_matters() {
        let coloured = |level| line(&event(level, None), Colour::Yes);

        assert!(coloured(Level::Error).contains(BOLD_RED));
        assert!(coloured(Level::Warn).contains(YELLOW));
        assert!(coloured(Level::Info).contains(GREEN));
        // The noisy levels recede rather than taking a hue.
        assert!(!coloured(Level::Debug).contains(GREEN));
    }

    /// The message is the part being read, so nothing is wrapped around it.
    #[test]
    fn leaves_the_message_in_the_terminal_s_own_colour() {
        let line = line(&event(Level::Error, Some("web-api")), Colour::Yes);

        assert!(line.ends_with("app is ready"), "{line:?}");
    }

    /// The one field that is the reason the line is being looked at.
    #[test]
    fn colours_an_error_field_and_leaves_the_others_alone() {
        let error = line(&with_field(Level::Warn, "error", "it broke"), Colour::Yes);
        let plain = line(&with_field(Level::Warn, "after", "1.2s"), Colour::Yes);

        assert!(
            error.contains(&format!("{RED}it broke{RESET}")),
            "{error:?}"
        );
        assert!(plain.ends_with("1.2s"), "{plain:?}");
        assert!(!plain.contains(RED), "{plain:?}");
    }

    /// Colour codes are not characters on the screen, so they must not be
    /// counted as ones: two lines whose columns line up plain have to line up
    /// coloured as well.
    #[test]
    fn lines_the_columns_up_whether_or_not_there_is_colour() {
        let short = Event::now(Level::Info, "tls", "a client asked for no host by name");
        let long = Event::now(Level::Debug, "app.reconcile", "restored app");

        let width = |event, colour| {
            let line: String = line(event, colour);

            // Where the message starts, once the escape codes are taken back
            // out — which is what the terminal shows.
            strip(&line)
                .find("a client")
                .or(strip(&line).find("restored"))
        };

        assert_eq!(
            width(&short, Colour::No),
            width(&long, Colour::No),
            "plain columns do not line up"
        );
        assert_eq!(
            width(&short, Colour::Yes),
            width(&long, Colour::Yes),
            "coloured columns do not line up"
        );
        assert_eq!(width(&short, Colour::No), width(&short, Colour::Yes));
    }
}
