//! Turning what the operator interface sends into something to look at.
//!
//! Rendering lives here rather than on the server because it is the only part
//! of a response that depends on who is reading it: the same status is a laid
//! out, coloured block in a terminal and a line of JSON in a pipe.
//!
//! At most one saturated colour per line, and it is the thing that went wrong:
//! an operator reading either of these is looking for the bad line, not
//! admiring the palette. Everything structural — the timestamp, the field
//! names, the labels — recedes, and the values keep the terminal's own
//! foreground, because they are the part being read rather than the part being
//! scanned past.

mod event;
pub mod prose;
pub mod report;
mod status;
pub mod table;

use std::io::IsTerminal;

pub use event::line;
pub use status::status;

pub const RESET: &str = "\x1b[0m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RED: &str = "\x1b[31m";
pub const BOLD_RED: &str = "\x1b[1;31m";
pub const YELLOW: &str = "\x1b[33m";
pub const GREEN: &str = "\x1b[32m";
pub const CYAN: &str = "\x1b[36m";

/// Set by anything that would rather not be sent escape codes.
const NO_COLOUR_VAR: &str = "NO_COLOR";

/// Names the terminal that cannot show any of this.
const TERM_VAR: &str = "TERM";

/// What `TERM` says when there is nothing to colour for.
const DUMB_TERM: &str = "dumb";

/// What an operator asked for, before the terminal gets a say.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum When {
    /// Colour when a person is watching and nothing has asked us not to.
    #[default]
    Auto,
    /// Colour regardless — including into a pager, which is the case the
    /// terminal check gets wrong.
    Always,
    /// Never colour, whoever is reading.
    Never,
}

/// Whether these lines carry colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colour {
    Yes,
    No,
}

impl Colour {
    /// What an operator's `--color` comes down to here.
    ///
    /// Under `Auto` that is: not when `NO_COLOR` is set at all, not when the
    /// terminal says it is `dumb`, and not when the output is being piped into
    /// something that would only have to strip the escapes out again.
    pub fn resolve(when: When) -> Self {
        match when {
            When::Always => return Self::Yes,
            When::Never => return Self::No,
            When::Auto => {}
        }

        if std::env::var_os(NO_COLOUR_VAR).is_some() {
            return Self::No;
        }
        if std::env::var_os(TERM_VAR).is_some_and(|term| term == DUMB_TERM) {
            return Self::No;
        }

        match std::io::stdout().is_terminal() {
            true => Self::Yes,
            false => Self::No,
        }
    }

    /// `text` in `code`, or `text` as it was.
    ///
    /// Takes the text already padded to its column: a colour code is not a
    /// character on the screen, and padding after wrapping would count it as
    /// one and misalign every coloured line.
    pub fn paint(self, code: &str, text: &str) -> String {
        match self {
            Self::Yes => format!("{code}{text}{RESET}"),
            Self::No => text.to_owned(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn forcing_colour_beats_asking_the_terminal() {
        assert_eq!(Colour::resolve(When::Always), Colour::Yes);
    }

    #[test]
    fn refusing_colour_beats_asking_the_terminal() {
        assert_eq!(Colour::resolve(When::Never), Colour::No);
    }

    #[test]
    fn asking_the_terminal_is_what_an_operator_gets_by_default() {
        assert_eq!(When::default(), When::Auto);
    }

    /// What a terminal would not print, dropped the crude way: every escape
    /// here is `\x1b[` and then letters, digits and semicolons up to an `m`.
    pub fn strip(line: &str) -> String {
        let mut out = String::new();
        let mut rest = line;

        while let Some(at) = rest.find('\x1b') {
            out.push_str(&rest[..at]);
            match rest[at..].find('m') {
                Some(end) => rest = &rest[at + end + 1..],
                None => return out,
            }
        }
        out.push_str(rest);

        out
    }
}
