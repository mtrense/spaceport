//! The events spaceport emits, and who gets to watch them.
//!
//! Nothing here is a second logging system. Spaceport already says what it is
//! doing through `tracing`, with the fields that matter — the app, the
//! container, the host — attached to the call site rather than baked into a
//! sentence. This module captures those same events on their way past the
//! subscriber, gives each one a category derived from where it came from, and
//! hands them to whoever is watching over the operator interface.
//!
//! So a new event costs an `info!` and nothing else, and `spaceport stream`
//! shows it the moment it is written.

pub mod bus;
pub mod layer;

pub use bus::EventBus;
pub use layer::layer;

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::app::{AppId, Pattern};

/// Something spaceport did, as it goes past.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// When it happened, in UTC. A host's local offset is a rendering
    /// question, and the stream may well be read from another machine.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub level: Level,
    pub category: Category,
    /// The app it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppId>,
    pub message: String,
    /// Everything else the call site recorded, rendered as it was written.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl Event {
    /// An event about the stream itself, stamped now.
    ///
    /// For the few things the machinery has to say in its own voice — a client
    /// that fell behind, say — where there is no call site to capture.
    pub fn now(level: Level, category: &str, message: impl Into<String>) -> Self {
        Self {
            at: OffsetDateTime::now_utc(),
            level,
            category: Category::new(category),
            app: None,
            message: message.into(),
            fields: BTreeMap::new(),
        }
    }
}

/// How much it matters, mirroring `tracing`'s levels.
///
/// Ordered by severity rather than by verbosity, so `Error < Info`: an event
/// passes a `--level` filter when it sorts at or before what was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl From<tracing::Level> for Level {
    fn from(level: tracing::Level) -> Self {
        match level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            _ => Self::Trace,
        }
    }
}

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => bail!("`{s}` is not a level — one of error, warn, info, debug, trace"),
        })
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of thing an event is about.
///
/// Dotted and hierarchical, so `app` selects `app.apply` and `app.reconcile`
/// alike. Derived from the module the event was written in — see
/// [`Category::for_target`] — which keeps every existing call site categorised
/// without touching it, and can be overridden per call site by recording a
/// `category` field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Category(String);

/// Which module's events land under which category.
///
/// First match wins, so the specific entries come before the module they sit
/// in. Anything unmatched is `other`, which is a bug report rather than a
/// category: it means spaceport grew a module and nobody said where it belongs.
const CATEGORIES: &[(&str, &str)] = &[
    ("spaceport_core::app::apply", "app.apply"),
    ("spaceport_core::app::reconcile", "app.reconcile"),
    ("spaceport_core::app::health", "app.health"),
    ("spaceport_core::app::store", "route"),
    ("spaceport_core::app::repository", "state"),
    ("spaceport_core::runtime", "container"),
    // Every module of the build: fetching a commit, unpacking it, asking the
    // engine and remembering what came back are one story to the operator
    // watching a push turn into an image, and splitting them would make
    // `--category build` the wrong answer to "why is my app not building".
    ("spaceport_core::build", "build"),
    ("spaceport_core::edge::proxy", "request"),
    ("spaceport_core::edge::tls", "tls"),
    ("spaceport_core::acme::resolver", "tls"),
    ("spaceport_core::acme", "acme"),
    (
        "spaceport_core::connections::github::webhook",
        "connection.webhook",
    ),
    (
        "spaceport_core::connections::github::reconcile",
        "connection.reconcile",
    ),
    // Not under `connection`: what an app is built from is the app's business
    // rather than the connection's, and an operator watching a deployment wants
    // it without the registration and reconciliation traffic around it. Two
    // modules, one category — where a branch was recorded from and where it
    // moved to are the same story to the operator reading them, whatever it
    // took spaceport to hear about it.
    ("spaceport_core::connections::github::tracking", "tracking"),
    ("spaceport_core::connections::github::push", "tracking"),
    ("spaceport_core::connections", "connection"),
    ("spaceport_core::edge", "edge"),
    ("spaceport_core::operator", "operator"),
    ("spaceport_core::state", "state"),
    ("spaceport_core::setup", "system"),
    ("spaceport_core::config", "system"),
    // The streaming machinery talking about itself, so that a watcher which
    // fell behind hears about it in the same shape as everything else.
    ("spaceport_core::events", "stream"),
    // The binary is `spaceport`, whatever the crate around it is called, and
    // the target an event carries is the binary's.
    ("spaceport_cli", "system"),
    ("spaceport", "system"),
];

/// What an event whose module is in no category gets.
const UNCATEGORISED: &str = "other";

impl Category {
    /// The category for events written in `target`, which is the module path
    /// unless the call site said otherwise.
    pub fn for_target(target: &str) -> Self {
        for (module, category) in CATEGORIES {
            if target == *module || target.starts_with(&format!("{module}::")) {
                return Self::new(category);
            }
        }

        Self::new(UNCATEGORISED)
    }

    fn new(category: &str) -> Self {
        Self(category.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this category is `other`, or sits underneath it.
    pub fn within(&self, other: &Self) -> bool {
        self.0 == other.0
            || (self.0.starts_with(&other.0) && self.0.as_bytes()[other.0.len()] == b'.')
    }
}

impl FromStr for Category {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a category must not be empty — leave it out to see every event");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            bail!("category `{s}` may only contain lowercase letters, digits, dots and hyphens");
        }
        if s.starts_with('.') || s.ends_with('.') {
            bail!("category `{s}` must not start or end with a dot");
        }

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which events a watcher wants.
///
/// Applied where the events are rather than where they are read: a client
/// watching one app should not be sent the whole firehose to sift through.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// The apps of interest, as a glob. Events about no app at all are not
    /// about the app that was asked for, so a filter excludes them.
    pub app: Option<Pattern>,
    /// The category, matched hierarchically.
    pub category: Option<Category>,
    /// The least severe level worth seeing.
    pub level: Option<Level>,
}

impl EventFilter {
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(level) = self.level
            && event.level > level
        {
            return false;
        }
        if let Some(category) = &self.category
            && !event.category.within(category)
        {
            return false;
        }
        if let Some(pattern) = &self.app {
            let Some(app) = &event.app else {
                return false;
            };
            if !pattern.matches(app) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(category: &str, level: Level, app: Option<&str>) -> Event {
        Event {
            at: OffsetDateTime::now_utc(),
            level,
            category: Category::new(category),
            app: app.map(|app| app.parse().unwrap()),
            message: "something happened".to_owned(),
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn categorises_by_the_module_an_event_came_from() {
        assert_eq!(
            Category::for_target("spaceport_core::app::apply").as_str(),
            "app.apply"
        );
        assert_eq!(
            Category::for_target("spaceport_core::edge::proxy").as_str(),
            "request"
        );
        // The module itself, and anything nested under it.
        assert_eq!(
            Category::for_target("spaceport_core::acme::account").as_str(),
            "acme"
        );
        assert_eq!(
            Category::for_target("spaceport_core::acme").as_str(),
            "acme"
        );
    }

    /// A spaceport's own registration with a forge is its own kind of thing,
    /// and an operator watching one wants neither the app stream nor the whole
    /// firehose.
    #[test]
    fn categorises_what_a_connection_does() {
        assert_eq!(
            Category::for_target("spaceport_core::connections").as_str(),
            "connection"
        );
        assert_eq!(
            Category::for_target("spaceport_core::connections::github::repository").as_str(),
            "connection"
        );
    }

    /// What a forge says to a spaceport is worth watching on its own — an
    /// operator setting a connection up wants the deliveries and not the
    /// registration — while everything else under `connections` stays where it
    /// was, which is what the ordering of the two rows buys.
    #[test]
    fn categorises_a_webhook_delivery_under_the_connection_it_arrived_for() {
        assert_eq!(
            Category::for_target("spaceport_core::connections::github::webhook").as_str(),
            "connection.webhook"
        );
        assert_eq!(
            Category::for_target("spaceport_core::connections::github::register").as_str(),
            "connection"
        );
        assert!(
            Category::new("connection.webhook").within(&Category::new("connection")),
            "a webhook is still a connection event"
        );
    }

    /// The two halves of knowing what GitHub says are worth telling apart:
    /// `connection.webhook` is what arrived unasked and `connection.reconcile`
    /// is what spaceport went and asked for, and an operator wondering why a
    /// repository is not showing up wants to know which of the two found it.
    #[test]
    fn categorises_a_reconciliation_pass_apart_from_the_deliveries() {
        assert_eq!(
            Category::for_target("spaceport_core::connections::github::reconcile").as_str(),
            "connection.reconcile"
        );
        assert!(
            Category::new("connection.reconcile").within(&Category::new("connection")),
            "a reconciliation is still a connection event"
        );
        assert!(
            !Category::new("connection.reconcile").within(&Category::new("connection.webhook"))
        );
    }

    /// Turning a commit into an image is its own kind of thing: an operator
    /// watching a deployment wants the build without the container's events
    /// around it, and every module of the build answers to the same word.
    #[test]
    fn categorises_what_a_build_does() {
        assert_eq!(
            Category::for_target("spaceport_core::build::worker").as_str(),
            "build"
        );
        assert_eq!(
            Category::for_target("spaceport_core::build::dir").as_str(),
            "build"
        );
        // And it is not the runtime's, which the entry above it holds.
        assert_eq!(
            Category::for_target("spaceport_core::runtime::docker").as_str(),
            "container"
        );
    }

    /// The specific entries have to win over the module they sit in, or every
    /// acme event would be `acme` and none would be `tls`.
    #[test]
    fn the_more_specific_module_decides() {
        assert_eq!(
            Category::for_target("spaceport_core::acme::resolver").as_str(),
            "tls"
        );
        assert_eq!(
            Category::for_target("spaceport_core::edge::tls").as_str(),
            "tls"
        );
    }

    #[test]
    fn an_unknown_module_is_not_silently_dropped() {
        assert_eq!(Category::for_target("hyper::client").as_str(), "other");
    }

    /// What the command itself writes as it starts up, whose target is the
    /// binary rather than a module of the library.
    #[test]
    fn categorises_the_binarys_own_events() {
        assert_eq!(Category::for_target("spaceport").as_str(), "system");
        // And the entry for it does not swallow the library's.
        assert_eq!(
            Category::for_target("spaceport_core::edge").as_str(),
            "edge"
        );
    }

    #[test]
    fn a_category_selects_the_ones_below_it() {
        let app: Category = "app".parse().unwrap();

        assert!(Category::new("app").within(&app));
        assert!(Category::new("app.apply").within(&app));
        // Not a dot boundary: a different category that merely starts the same.
        assert!(!Category::new("apply").within(&app));
        assert!(!Category::new("route").within(&app));
    }

    #[test]
    fn rejects_a_category_nothing_could_be_filed_under() {
        assert!("".parse::<Category>().is_err());
        assert!("App".parse::<Category>().is_err());
        assert!("app.".parse::<Category>().is_err());
    }

    #[test]
    fn a_level_filter_keeps_what_is_at_least_as_severe() {
        let filter = EventFilter {
            level: Some(Level::Info),
            ..Default::default()
        };

        assert!(filter.matches(&event("app.apply", Level::Error, None)));
        assert!(filter.matches(&event("app.apply", Level::Info, None)));
        assert!(!filter.matches(&event("app.apply", Level::Debug, None)));
    }

    #[test]
    fn an_app_filter_excludes_events_about_no_app() {
        let filter = EventFilter {
            app: Some("web-*".parse().unwrap()),
            ..Default::default()
        };

        assert!(filter.matches(&event("app.apply", Level::Info, Some("web-api"))));
        assert!(!filter.matches(&event("app.apply", Level::Info, Some("worker"))));
        assert!(!filter.matches(&event("edge", Level::Info, None)));
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let filter = EventFilter::default();

        assert!(filter.matches(&event("app.apply", Level::Trace, None)));
        assert!(filter.matches(&event("acme", Level::Error, Some("web-api"))));
    }

    #[test]
    fn levels_are_ordered_by_severity() {
        assert!(Level::Error < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert_eq!("WARN".parse::<Level>().unwrap(), Level::Warn);
        assert!("shout".parse::<Level>().is_err());
    }
}
