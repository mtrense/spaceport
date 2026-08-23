//! What somebody writing an app for a spaceport has to know, and `spaceport
//! info` prints.
//!
//! The audience is not the operator every other command answers to: it is the
//! developer of a hosted app, and increasingly the agent working for them,
//! neither of whom has this repository open. Which is the argument for putting
//! these documents in the binary rather than in a README — the spaceport an
//! app is being written against is the copy that answers, so the answer is the
//! one that build enforces, and there is no version of it a repository is
//! behind on.
//!
//! Markdown, because half of what reads this is an agent that was handed the
//! output whole and the other half is a person in a terminal, and markdown is
//! the one shape that serves both without either being given something the
//! other has to strip.
//!
//! Nothing here reaches the operator socket. `spaceport info` answers from a
//! binary on a laptop that has never seen the host, which is exactly where an
//! app developer stands.

use crate::render::{BOLD, Colour};

/// The manifest: every block, what it may hold, and what to ask the app's
/// developer before writing one.
pub const MANIFEST: &str = include_str!("manifest.md");

/// The contract an edge-gated app is held to: the JWT, how to verify it, and
/// what it must not be turned into.
pub const AUTH: &str = include_str!("auth.md");

/// What starts a heading line, and so what is picked out for a person
/// scanning for the section they came for.
const HEADING: &str = "#";

/// What opens and closes a fenced block. Everything between two of these is
/// somebody's YAML or somebody's code, where a `#` is a comment and not a
/// heading — the same rule [`crate::render::prose`] follows about a build log,
/// for the same reason.
const FENCE: &str = "```";

/// One of these documents, with its headings picked out.
///
/// The only mark added is bold on a heading: the document is already laid out
/// as markdown and stays valid markdown either way, so what an operator reads
/// coloured and what a pipe receives are the same text.
pub fn document(text: &str, colour: Colour) -> String {
    let mut fenced = false;

    text.split_inclusive('\n')
        .map(|chunk| {
            let (body, ending) = split_ending(chunk);

            if body.starts_with(FENCE) {
                fenced = !fenced;

                return chunk.to_owned();
            }
            if !fenced && body.starts_with(HEADING) {
                return format!("{}{ending}", colour.paint(BOLD, body));
            }

            chunk.to_owned()
        })
        .collect()
}

/// A line split from the ending it was written with, so the ending stays
/// outside whatever the line is painted with — an escape code wrapped around a
/// newline is a newline a pager has to think about.
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

    #[test]
    fn picks_a_heading_out() {
        let document = document("# A title\n\nprose\n", Colour::Yes);

        assert!(
            document.starts_with(&format!("{BOLD}# A title{RESET}\n")),
            "{document:?}"
        );
        assert!(document.ends_with("\nprose\n"), "{document:?}");
    }

    /// A `#` inside a fenced block is a YAML comment or a shell prompt, and
    /// the manifest document is full of both.
    #[test]
    fn leaves_a_comment_inside_a_fence_alone() {
        let document = document("```yaml\n# not a heading\n```\n# a heading\n", Colour::Yes);

        assert!(
            document.starts_with("```yaml\n# not a heading\n```\n"),
            "{document:?}"
        );
        assert!(
            document.contains(&format!("{BOLD}# a heading")),
            "{document:?}"
        );
    }

    /// Coloured or not, it says the same thing: what a person reads and what
    /// an agent is piped are one document.
    #[test]
    fn says_the_same_thing_coloured_as_plain() {
        for text in [MANIFEST, AUTH] {
            assert_eq!(strip(&document(text, Colour::Yes)), text);
            assert_eq!(document(text, Colour::No), text);
        }
    }

    /// Both documents are written for somebody who cannot ask a question back,
    /// so each carries the checklist that is the whole point of printing them.
    #[test]
    fn both_documents_end_in_questions_for_the_developer() {
        for text in [MANIFEST, AUTH] {
            assert!(text.contains("Questions to settle with the app developer"));
        }
    }
}
