//! Putting a value somebody else chose into a URI.
//!
//! One function, and it is here rather than beside either of its callers
//! because both the edge and the operator client build URIs out of strings a
//! person typed — and a rule about which characters may travel unescaped is
//! not a rule two modules should each keep their own version of.

/// `value` as one query-string value: everything but the unreserved characters
/// percent-encoded. Stricter than a URL needs and exactly as strict as never
/// having to reason about which delimiter survives where.
///
/// Safe for a path segment too, and for the same reason: what comes out holds
/// no `/`, no `?` and no `#`, so it cannot become more of a URI than the one
/// segment it was meant to be.
///
/// Over-encoding costs nothing at the far end. `%20` is read back as a space,
/// `%2B` as a `+` rather than as the space a form-encoded `+` would mean, and
/// `%2F` as the `/` a branch name is allowed to hold — so a value that goes
/// through this arrives as the value that went in, whatever it held.
pub(crate) fn query_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The characters the whole thing exists for: every one of them ends the
    /// value it is in, and every one of them has to come back out as itself.
    #[test]
    fn nothing_that_delimits_a_uri_survives_as_itself() {
        assert_eq!(query_encode("a&b"), "a%26b");
        assert_eq!(query_encode("a=b"), "a%3Db");
        assert_eq!(query_encode("a?b"), "a%3Fb");
        assert_eq!(query_encode("a#b"), "a%23b");
        assert_eq!(query_encode("a/b"), "a%2Fb");
        assert_eq!(query_encode("a b"), "a%20b");
    }

    /// A `+` is a space to a form-encoded reader and nothing else to anybody,
    /// which is exactly the sort of disagreement encoding it settles.
    #[test]
    fn a_plus_cannot_arrive_as_a_space() {
        assert_eq!(query_encode("a+b"), "a%2Bb");
    }

    /// A `%` the operator typed is a literal percent, not the start of an
    /// escape somebody else wrote.
    #[test]
    fn a_percent_is_escaped_rather_than_read_as_one() {
        assert_eq!(query_encode("100%"), "100%25");
        assert_eq!(query_encode("%26"), "%2526");
    }

    /// The unreserved set, which is what makes an ordinary value still look
    /// like itself in a log.
    #[test]
    fn leaves_alone_what_needs_no_escaping() {
        assert_eq!(
            query_encode("an-organisation.Site_1~2"),
            "an-organisation.Site_1~2"
        );
    }

    /// Bytes and not chars: anything outside ASCII is encoded one byte of its
    /// utf-8 at a time, which is what a reader on the other side expects.
    #[test]
    fn encodes_utf8_a_byte_at_a_time() {
        assert_eq!(query_encode("é"), "%C3%A9");
    }

    #[test]
    fn an_empty_value_encodes_to_an_empty_value() {
        assert_eq!(query_encode(""), "");
    }
}
