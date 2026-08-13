//! Durations as written in a manifest: `10s`, `500ms`, `2m`.
//!
//! A bare number is refused. `timeout: 30` reads as thirty seconds to one
//! person and thirty milliseconds to the next, and the one who guessed wrong
//! finds out from a timeout that never fires.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, de};

/// Parse a duration of the form `<whole number><unit>`, where the unit is one
/// of `ms`, `s`, `m` or `h`.
pub fn parse(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let split = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (amount, unit) = raw.split_at(split);

    let amount: u64 = match amount.parse() {
        Ok(amount) => amount,
        Err(_) => bail!("`{raw}` is not a duration like `10s`, `500ms` or `2m`"),
    };

    match unit {
        "ms" => Ok(Duration::from_millis(amount)),
        "s" => Ok(Duration::from_secs(amount)),
        "m" => Ok(Duration::from_secs(amount * 60)),
        "h" => Ok(Duration::from_secs(amount * 3600)),
        "" => bail!("duration `{raw}` needs a unit: `ms`, `s`, `m` or `h`"),
        unit => bail!("`{unit}` in `{raw}` is not a duration unit: use `ms`, `s`, `m` or `h`"),
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

    #[test]
    fn refuses_nonsense() {
        for raw in ["", "s", "-5s", "1.5s", "ms10"] {
            assert!(parse(raw).is_err(), "accepted `{raw}`");
        }
    }
}
