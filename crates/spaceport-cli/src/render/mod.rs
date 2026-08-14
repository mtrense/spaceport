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
mod status;

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

/// Whether these lines carry colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colour {
    Yes,
    No,
}

impl Colour {
    /// Colour when a person is watching, and not when the output is being
    /// piped into something that would only have to strip it out again.
    ///
    /// `forced` is `--pretty`, which is an operator saying they want it
    /// regardless — including into a pager, which is the case the terminal
    /// check gets wrong.
    pub fn detect(forced: bool) -> Self {
        if forced {
            return Self::Yes;
        }
        if std::env::var_os(NO_COLOUR_VAR).is_some() {
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
mod tests {
    use super::*;

    #[test]
    fn forcing_colour_beats_asking_the_terminal() {
        assert_eq!(Colour::detect(true), Colour::Yes);
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
