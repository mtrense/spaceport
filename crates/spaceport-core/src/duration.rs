//! Durations as written in a manifest: `10s`, `500ms`, `2m`.
//!
//! A bare number is refused. `timeout: 30` reads as thirty seconds to one
//! person and thirty milliseconds to the next, and the one who guessed wrong
//! finds out from a timeout that never fires.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, de};

/// Parse a duration of the form `<whole number><unit>`, where the unit is one
/// of `ms`, `s`, `m`, `h` or `d`.
///
/// `d` exists because the auth spec spells lifetimes in days — an API key
/// defaults to `90d` — and asking an operator to write `2160h` would be the
/// parser optimising for its own alphabet over the person typing.
pub fn parse(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let split = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (amount, unit) = raw.split_at(split);

    let amount: u64 = match amount.parse() {
        Ok(amount) => amount,
        Err(_) => bail!("`{raw}` is not a duration like `10s`, `500ms` or `2m`"),
    };

    // Checked, because a release build wraps silently rather than panicking,
    // and wrapping turns the largest duration someone can write into one of
    // the smallest — a `liveness` interval that reads as an hour and checks in
    // a tight loop instead. Refusing is the only answer that cannot be
    // mistaken for the number that was asked for.
    let seconds = |per_unit: u64| match amount.checked_mul(per_unit) {
        Some(seconds) => Ok(Duration::from_secs(seconds)),
        None => bail!("`{raw}` is a longer duration than there is any way to keep"),
    };

    match unit {
        "ms" => Ok(Duration::from_millis(amount)),
        "s" => Ok(Duration::from_secs(amount)),
        "m" => seconds(60),
        "h" => seconds(3600),
        "d" => seconds(24 * 3600),
        "" => bail!("duration `{raw}` needs a unit: `ms`, `s`, `m`, `h` or `d`"),
        unit => bail!("`{unit}` in `{raw}` is not a duration unit: use `ms`, `s`, `m`, `h` or `d`"),
    }
}

/// For `#[serde(deserialize_with = "crate::duration::deserialize")]`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let raw = String::deserialize(deserializer)?;

    parse(&raw).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_unit() {
        assert_eq!(parse("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse("90d").unwrap(), Duration::from_secs(90 * 24 * 3600));
    }

    #[test]
    fn parses_zero() {
        assert_eq!(parse("0s").unwrap(), Duration::ZERO);
    }

    #[test]
    fn refuses_a_bare_number() {
        let err = parse("30").unwrap_err().to_string();
        assert!(err.contains("needs a unit"), "{err}");
    }

    #[test]
    fn refuses_an_unknown_unit() {
        let err = parse("10 seconds").unwrap_err().to_string();
        assert!(err.contains("not a duration unit"), "{err}");
    }

    /// Every unit that multiplies, at the smallest amount that overflows it.
    /// The first of these used to wrap to 44 seconds, so an accepted value
    /// here would be a duration nobody wrote.
    #[test]
    fn refuses_a_duration_too_long_to_keep() {
        for raw in [
            "307445734561825861m",
            "5124095576030432h",
            "213503982334602d",
        ] {
            let err = parse(raw).unwrap_err().to_string();
            assert!(err.contains("longer duration"), "{raw}: {err}");
        }
    }

    /// The largest amount of each unit that still fits, so that the check
    /// above cannot be tightened into refusing durations that are fine.
    #[test]
    fn keeps_the_longest_duration_that_fits() {
        assert_eq!(
            parse("307445734561825860m").unwrap(),
            Duration::from_secs(307_445_734_561_825_860 * 60)
        );
        assert_eq!(
            parse("5124095576030430h").unwrap(),
            Duration::from_secs(5_124_095_576_030_430 * 3600)
        );
        assert_eq!(
            parse("213503982334601d").unwrap(),
            Duration::from_secs(213_503_982_334_601 * 24 * 3600)
        );
    }

    #[test]
    fn refuses_nonsense() {
        for raw in ["", "s", "-5s", "1.5s", "ms10"] {
            assert!(parse(raw).is_err(), "accepted `{raw}`");
        }
    }
}
