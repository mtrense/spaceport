//! Where events go, and where watchers pick them up.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::broadcast;

use super::{Event, EventFilter, Level};

/// How far a watcher may fall behind before it starts losing events.
///
/// Generous, because the cost is a queue of pointers and the alternative is
/// telling an operator their stream has holes in it.
const CAPACITY: usize = 1024;

/// How many events are kept for a watcher that was not yet watching.
///
/// The first thing anyone does is start the stream *after* the interesting
/// thing happened, so a little history is most of what makes it useful.
const HISTORY: usize = 256;

/// The least severe level worth keeping history for.
///
/// Debug events are the ones there are a great many of — one per request, once
/// the edge starts saying so — and a ring buffer full of those would push out
/// the apply that failed a minute ago, which is what the history is for.
const HISTORIC: Level = Level::Info;

/// The one place events are published, and the one place they are read from.
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<Event>>,
    /// The last [`HISTORY`] events worth keeping. Guarded by a mutex that also
    /// orders publication against subscription — see [`EventBus::watch`].
    recent: Mutex<VecDeque<Arc<Event>>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            sender: broadcast::Sender::new(CAPACITY),
            recent: Mutex::new(VecDeque::with_capacity(HISTORY)),
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an event at `level` is worth building at all.
    ///
    /// Asked before the fields are collected, so that the events nobody has
    /// asked for — the per-request ones, on a spaceport with no watchers —
    /// cost a load and a comparison rather than a map full of strings.
    pub fn wants(&self, level: Level) -> bool {
        level <= HISTORIC || self.sender.receiver_count() > 0
    }

    /// Publish `event` to every watcher, and remember it if it is worth
    /// remembering.
    pub fn emit(&self, event: Event) {
        let event = Arc::new(event);
        let mut recent = self.lock();

        if event.level <= HISTORIC {
            if recent.len() == HISTORY {
                recent.pop_front();
            }
            recent.push_back(event.clone());
        }

        // Under the lock, so that a watcher subscribing between the two halves
        // of this cannot see the event twice or miss it. Sending never blocks:
        // a broadcast channel drops the oldest value rather than waiting on the
        // slowest reader, and an error only means nobody is listening.
        let _ = self.sender.send(event);
    }

    /// Start watching: the recent events matching `filter`, most recent
    /// `history` of them, and a receiver for everything after those.
    ///
    /// The two are taken together under the lock, so the seam between them
    /// neither repeats an event nor drops one.
    pub fn watch(
        &self,
        history: usize,
        filter: &EventFilter,
    ) -> (Vec<Arc<Event>>, broadcast::Receiver<Arc<Event>>) {
        let recent = self.lock();

        let matching: Vec<Arc<Event>> = recent
            .iter()
            .filter(|event| filter.matches(event))
            .cloned()
            .collect();
        let past = matching[matching.len().saturating_sub(history)..].to_vec();

        (past, self.sender.subscribe())
    }

    /// The events are what matters here, and a panic in one publisher is no
    /// reason to stop telling everyone else what is happening.
    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Arc<Event>>> {
        self.recent.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Category;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    fn event(level: Level, message: &str) -> Event {
        Event {
            at: OffsetDateTime::now_utc(),
            level,
            category: Category::for_target("spaceport_core::app::apply"),
            app: Some("web-api".parse().unwrap()),
            message: message.to_owned(),
            fields: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn a_watcher_gets_what_is_emitted_after_it_started() {
        let bus = EventBus::new();
        let (past, mut rx) = bus.watch(0, &EventFilter::default());
        assert!(past.is_empty());

        bus.emit(event(Level::Info, "app is ready"));

        assert_eq!(rx.recv().await.unwrap().message, "app is ready");
    }

    #[tokio::test]
    async fn a_watcher_gets_the_history_it_asked_for() {
        let bus = EventBus::new();
        bus.emit(event(Level::Info, "first"));
        bus.emit(event(Level::Info, "second"));
        bus.emit(event(Level::Info, "third"));

        let (past, _rx) = bus.watch(2, &EventFilter::default());

        let messages: Vec<&str> = past.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, ["second", "third"]);
    }

    #[tokio::test]
    async fn the_history_is_filtered_like_the_stream() {
        let bus = EventBus::new();
        bus.emit(event(Level::Warn, "kept"));
        bus.emit(event(Level::Info, "dropped by the filter"));

        let filter = EventFilter {
            level: Some(Level::Warn),
            ..Default::default()
        };
        let (past, _rx) = bus.watch(HISTORY, &filter);

        assert_eq!(past.len(), 1);
        assert_eq!(past[0].message, "kept");
    }

    /// A history that kept every request would hold nothing else by the time
    /// anyone looked at it.
    #[tokio::test]
    async fn the_noisy_levels_are_streamed_but_not_remembered() {
        let bus = EventBus::new();
        let (_past, mut rx) = bus.watch(0, &EventFilter::default());

        bus.emit(event(Level::Debug, "proxied"));

        assert_eq!(rx.recv().await.unwrap().message, "proxied");
        let (past, _) = bus.watch(HISTORY, &EventFilter::default());
        assert!(past.is_empty());
    }

    #[tokio::test]
    async fn the_history_does_not_grow_without_bound() {
        let bus = EventBus::new();
        for n in 0..HISTORY + 10 {
            bus.emit(event(Level::Info, &format!("event {n}")));
        }

        let (past, _rx) = bus.watch(usize::MAX, &EventFilter::default());

        assert_eq!(past.len(), HISTORY);
        assert_eq!(past[0].message, "event 10");
    }

    /// The one thing the noisy levels are allowed to cost when nobody is
    /// watching is this question.
    #[tokio::test]
    async fn debug_events_are_only_built_while_somebody_is_watching() {
        let bus = EventBus::new();
        assert!(!bus.wants(Level::Debug));
        assert!(bus.wants(Level::Info));

        let (_past, _rx) = bus.watch(0, &EventFilter::default());

        assert!(bus.wants(Level::Debug));
    }
}
