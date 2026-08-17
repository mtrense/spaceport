//! Colouring the prose an operator interface already wrote.
//!
//! Every command that changes something answers in sentences, and the sentences
//! are the server's: it knows what it did and this side does not. What this side
//! knows is who is reading. So nothing here is parsed and nothing is reworded —
//! the acknowledgement is printed as it arrived, with the marks it already
//! carries picked out in the terminal's own terms.
//!
//! The marks are the ones the server writes deliberately and always: a head line
//! flush left saying what happened, detail lines under it indented two spaces,
//! a `warning: ` prefix for the one thing not to scroll past, and a small set of
//! fixed failure clauses. Only a prefix or a literal decides a colour. Nothing
//! infers meaning from a word in the middle of a line, because half of what
//! arrives here is somebody else's build log and the words in it mean nothing to
//! us — a line reading `npm test failed` is output, not a fault.
//!
//! The doctrine of the rest of this module holds: the head line is the part
//! being read and keeps the terminal's own foreground, the detail under it
//! recedes, and the one saturated colour on the page is the thing that went
//! wrong.

use super::{Colour, DIM, RED, YELLOW};

/// What the server indents a detail line by, and so what says a line is one.
const INDENT: &str = "  ";

/// What it indents somebody else's output by, under a detail line introducing
/// it — the excerpt of a build log that failed is the only thing this deep.
const QUOTED: &str = "    ";

/// The prefix that makes a line the reason the block is being read.
const WARNING: &str = "warning: ";

/// The head of every failure clause the server writes: `could not be read: …`,
/// `could not be forgotten: …`, `could not verify …: …`.
const COULD_NOT: &str = "could not ";

/// The other one, which reads `… failed: …` and so carries its own leading
/// space to keep it from matching a word that merely ends in `failed`.
const FAILED: &str = " failed: ";

/// A block of server-written prose, with the marks it already carries picked
/// out.
///
/// Line endings and every byte between them are passed through: this adds
/// escape codes to an acknowledgement and never a character of text, so what an
/// operator reads is what the server said.
pub fn block(text: &str, colour: Colour) -> String {
    text.split_inclusive('\n')
        .map(|chunk| {
            let (body, ending) = split_ending(chunk);

            format!("{}{ending}", line(body, colour))
        })
        .collect()
}

/// One line of it, without its ending.
///
/// The precedence, where more than one rule could fire: quoted output beats a
/// warning beats a failure clause beats the indent.
///
/// Quoted output comes first because nothing inside it is ours to mark at all —
/// the marks this looks for are the server's, and a build log is free to write
/// the same words meaning something else entirely. After that, a warning is
/// written by the server as the thing an operator must not scroll past, and one
/// whose text happens to contain `could not be checked` is still that thing — a
/// line with two colours in it would be saying neither.
fn line(text: &str, colour: Colour) -> String {
    let trimmed = text.trim_start();

    // Nothing is not painted: wrapping a blank line would leave escape codes
    // around nothing, and a blank line between stanzas is part of the layout.
    if trimmed.is_empty() {
        return text.to_owned();
    }

    // Quoted output takes no mark of ours at all. A build log says `could not
    // open x` and `error: build failed: exit 1` in somebody else's voice, about
    // somebody else's trouble, and coloured as ours it would read as spaceport
    // reporting a fault it never had. It recedes, whatever it says.
    if text.starts_with(QUOTED) {
        return colour.paint(DIM, text);
    }

    if trimmed.starts_with(WARNING) {
        return colour.paint(YELLOW, text);
    }

    // From the clause to the end of the line, never from the start of it: the
    // half before it says which app, which repository, which host — the part
    // being read — and only the half after it is the trouble.
    if let Some(at) = clause(text) {
        let (before, clause) = text.split_at(at);

        return format!("{before}{}", colour.paint(RED, clause));
    }

    // Whole line including its indent, and nothing padded afterwards: an escape
    // code is not a character on the screen, and these blocks have detail lines
    // aligned in columns the server counted out in spaces.
    if text.starts_with(INDENT) {
        return colour.paint(DIM, text);
    }

    // The head line, and anything else the server wrote flush left.
    text.to_owned()
}

/// Where a failure clause starts, if the line has one.
///
/// Anchored on the literals, so the answer is either "here" or "nowhere" and
/// never a judgement about English. The earlier of the two when a line somehow
/// carries both, so the whole of the trouble is coloured rather than the tail of
/// it.
fn clause(text: &str) -> Option<usize> {
    let could_not = text.find(COULD_NOT);
    // Past the anchoring space, which belongs to the words before the clause.
    let failed = text.find(FAILED).map(|at| at + 1);

    could_not.into_iter().chain(failed).min()
}

/// A line split from the ending it was written with, so the ending can be put
/// back untouched rather than assumed.
fn split_ending(chunk: &str) -> (&str, &str) {
    let body = chunk.strip_suffix('\n').unwrap_or(chunk);
    let body = body.strip_suffix('\r').unwrap_or(body);

    (body, &chunk[body.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::RESET;
    use crate::render::tests::strip;

    /// `spaceport apps apply`, as the operator interface writes it.
    const APPLIED: &str = "app `blog` applied\n  container abc123def456\n  upstream  127.0.0.1:9001\n  routes    blog.example.com\n";

    /// `spaceport apps destroy`, where the store would not answer.
    const DESTROYED: &str = "app `blog` destroyed\n  container abc123def456\n  it still tracks acme/blog on main, which could not be forgotten: the database is locked\n";

    #[test]
    fn leaves_the_head_line_alone_and_lets_the_detail_recede() {
        let block = block(APPLIED, Colour::Yes);
        let lines: Vec<&str> = block.lines().collect();

        assert_eq!(lines[0], "app `blog` applied", "{block:?}");
        assert_eq!(
            lines[1],
            format!("{DIM}  container abc123def456{RESET}"),
            "{block:?}"
        );
        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");
    }

    /// An acknowledgement is coloured, never reworded.
    #[test]
    fn says_the_same_thing_coloured_as_plain() {
        for text in [APPLIED, DESTROYED] {
            assert_eq!(strip(&block(text, Colour::Yes)), text);
        }
    }

    /// Whatever arrives, an operator who asked for no colour gets exactly what
    /// the server sent — including the blank lines, the endings and anything
    /// this side would not have recognised.
    #[test]
    fn hands_back_what_it_was_given_when_there_is_no_colour() {
        for text in [
            APPLIED,
            DESTROYED,
            "",
            "\n",
            "\r\n\r\n",
            "no ending at all",
            "  warning: something\n\n    a log line\n",
            "\u{1b}[31malready coloured\u{1b}[0m\n",
        ] {
            assert_eq!(block(text, Colour::No), text, "{text:?}");
        }
    }

    #[test]
    fn colours_a_warning_over_the_whole_line() {
        let block = block(
            "mapping added: rule `a1b2`\n  warning: `wiki` declares no role `admin`\n",
            Colour::Yes,
        );

        assert!(
            block.contains(&format!(
                "{YELLOW}  warning: `wiki` declares no role `admin`{RESET}"
            )),
            "{block:?}"
        );
        assert!(!block.contains(DIM), "{block:?}");
    }

    /// A warning whose own words contain a failure clause is still a warning:
    /// two colours on one line would be saying neither.
    #[test]
    fn keeps_a_warning_yellow_even_when_it_says_something_could_not_be_checked() {
        let block = block(
            "  warning: whether `wiki` declares role `admin` could not be checked: no manifest\n",
            Colour::Yes,
        );

        assert!(block.starts_with(YELLOW), "{block:?}");
        assert!(!block.contains(RED), "{block:?}");
    }

    /// The half before the clause says which app and which repository, and is
    /// the part being read.
    #[test]
    fn colours_a_failure_clause_from_the_clause_and_not_from_the_start_of_the_line() {
        let block = block(DESTROYED, Colour::Yes);

        assert!(
            block.contains("  it still tracks acme/blog on main, which "),
            "{block:?}"
        );
        assert!(
            block.contains(&format!(
                "{RED}could not be forgotten: the database is locked{RESET}"
            )),
            "{block:?}"
        );
    }

    #[test]
    fn colours_a_could_not_be_read_clause_the_same_way() {
        let block = block(
            "  build     could not be read: the database is locked\n",
            Colour::Yes,
        );

        assert!(
            block.starts_with("  build     ")
                && block.contains(&format!("{RED}could not be read:")),
            "{block:?}"
        );
    }

    /// Half of what comes back is somebody else's build output, where the word
    /// is a word and not a mark.
    #[test]
    fn leaves_a_build_log_line_that_merely_says_failed_alone() {
        let excerpt = "  it printed\n    2 of 40 tests failed\n    make: *** [build] Error 1\n";
        let block = block(excerpt, Colour::Yes);

        assert!(!block.contains(RED), "{block:?}");
        assert_eq!(strip(&block), excerpt);
    }

    /// And the other half of it says exactly what our own failure clause says.
    /// A build log reporting its own trouble is not this spaceport reporting
    /// one, and the indent is what tells them apart.
    #[test]
    fn leaves_a_quoted_log_alone_even_when_it_writes_a_clause_of_its_own() {
        let excerpt =
            "  it printed\n    error: build failed: exit 1\n    could not open /src/main.rs\n";
        let block = block(excerpt, Colour::Yes);

        assert!(!block.contains(RED) && !block.contains(YELLOW), "{block:?}");
        assert_eq!(strip(&block), excerpt);
    }

    /// The clause carries its own colon, and that is what tells it from the
    /// word: `deploying x failed: y` is a fault, `2 tests failed` is a count.
    #[test]
    fn colours_a_failed_clause_from_the_word_rather_than_the_space_before_it() {
        let block = block("  deploying abc123 failed: no such image\n", Colour::Yes);

        assert!(
            block.contains(&format!(
                "  deploying abc123 {RED}failed: no such image{RESET}"
            )),
            "{block:?}"
        );
    }

    /// Deeper lines are detail under detail, and recede with the rest of it.
    #[test]
    fn dims_a_line_indented_further_the_same_as_one_indented_twice() {
        let block = block("app `wiki` shown\n    a deeper line\n", Colour::Yes);

        assert!(
            block.contains(&format!("{DIM}    a deeper line{RESET}")),
            "{block:?}"
        );
    }
}
