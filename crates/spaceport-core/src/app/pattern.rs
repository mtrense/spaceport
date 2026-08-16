//! Picking apps, and the things that belong to them, out of a list by name.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};

use super::AppId;
use super::manifest::VarName;

/// A glob over names, as `spaceport apps list` takes one.
///
/// `*` matches any run of characters, including none; every other character
/// matches itself. Deliberately not a regex: the names it filters are lowercase
/// letters, digits and hyphens, or the C rules for an environment variable, and
/// `web-*` is the whole of what anyone wants to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    /// The literal pieces between the `*`s, in order. Always at least one, and
    /// empty pieces are where a `*` sat at an end or next to another.
    parts: Vec<String>,
}

impl Pattern {
    /// Whether `id` matches.
    pub fn matches(&self, id: &AppId) -> bool {
        self.matches_str(id.as_str())
    }

    /// Whether the secret or environment variable called `name` matches.
    ///
    /// The same glob, spelled as a second method rather than as a generic one:
    /// an id and a variable name are different alphabets, and a caller should
    /// have to say which of them it is filtering.
    pub fn matches_name(&self, name: &VarName) -> bool {
        self.matches_str(name.as_str())
    }

    /// Whether the user called `slug` matches.
    ///
    /// A third alphabet, spelled as a third method for the reason
    /// [`Pattern::matches_name`] is a second one: a caller should have to say
    /// what it is filtering.
    pub fn matches_slug(&self, slug: &crate::auth::UserSlug) -> bool {
        self.matches_str(slug.as_str())
    }

    /// The glob itself, over whatever the callers above have unwrapped.
    fn matches_str(&self, candidate: &str) -> bool {
        let mut parts = self.parts.iter();
        let first = parts.next().expect("a pattern has at least one part");

        // The leading and trailing pieces are anchored — only the ones in
        // between are free to slide.
        let Some(mut rest) = candidate.strip_prefix(first.as_str()) else {
            return false;
        };
        let Some(last) = parts.next_back() else {
            // No `*` at all, so the one piece had to be the whole name.
            return rest.is_empty();
        };

        for part in parts {
            match rest.find(part.as_str()) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }

        // The length check keeps the last piece from matching characters the
        // first one already consumed.
        rest.len() >= last.len() && rest.ends_with(last.as_str())
    }
}

impl FromStr for Pattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a pattern must not be empty — leave it out to list every app");
        }

        Ok(Self {
            raw: s.to_owned(),
            parts: s.split('*').map(str::to_owned).collect(),
        })
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, id: &str) -> bool {
        pattern
            .parse::<Pattern>()
            .unwrap()
            .matches(&id.parse().unwrap())
    }

    #[test]
    fn a_pattern_without_a_star_matches_that_id_alone() {
        assert!(matches("hello", "hello"));
        assert!(!matches("hello", "hello-world"));
        assert!(!matches("ello", "hello"));
    }

    #[test]
    fn a_trailing_star_matches_a_prefix() {
        assert!(matches("web-*", "web-api"));
        // A `*` matching nothing at all still matches.
        assert!(matches("web*", "web"));
        assert!(!matches("web-*", "api-web"));
    }

    #[test]
    fn a_leading_star_matches_a_suffix() {
        assert!(matches("*-api", "web-api"));
        assert!(!matches("*-api", "web-apis"));
    }

    #[test]
    fn a_star_on_both_ends_matches_anywhere() {
        assert!(matches("*api*", "web-api-2"));
        assert!(matches("*api*", "api"));
        assert!(!matches("*api*", "web"));
    }

    #[test]
    fn a_lone_star_matches_everything() {
        assert!(matches("*", "hello"));
    }

    #[test]
    fn stars_in_the_middle_match_in_order() {
        assert!(matches("a*b*c", "a-b-c"));
        assert!(matches("a*b*c", "abc"));
        assert!(!matches("a*b*c", "a-c-b"));
    }

    /// The pieces around a `*` may not overlap: `a*a` needs two of them.
    #[test]
    fn anchored_pieces_do_not_share_characters() {
        assert!(!matches("a*a", "a"));
        assert!(matches("a*a", "aa"));
    }

    /// The same glob, over the other alphabet: secret names are uppercase and
    /// hold underscores, and nothing in the matching may assume otherwise.
    #[test]
    fn matches_a_variable_name_by_the_same_rules() {
        let pattern = "DATABASE_*".parse::<Pattern>().unwrap();

        assert!(pattern.matches_name(&"DATABASE_URL".parse().unwrap()));
        assert!(!pattern.matches_name(&"REDIS_URL".parse().unwrap()));
    }

    #[test]
    fn rejects_an_empty_pattern() {
        assert!("".parse::<Pattern>().is_err());
    }

    #[test]
    fn shows_itself_as_it_was_written() {
        assert_eq!("web-*".parse::<Pattern>().unwrap().to_string(), "web-*");
    }
}
