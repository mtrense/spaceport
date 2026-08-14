//! Capturing `tracing` events on their way past.
//!
//! Installed beside the layer that writes to stdout rather than instead of it,
//! and with a filter of its own: what an operator watching a stream wants to
//! see is not the same as what belongs in a service's log, and the stream can
//! afford to be the more talkative of the two.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use super::{Category, Event, EventBus, Level};

/// A layer that publishes everything it sees to `bus`.
pub fn layer(bus: Arc<EventBus>) -> EventLayer {
    EventLayer { bus }
}

#[derive(Debug)]
pub struct EventLayer {
    bus: Arc<EventBus>,
}

impl<S: tracing::Subscriber> Layer<S> for EventLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let metadata = event.metadata();
        let level = Level::from(*metadata.level());

        // Asked before the fields are collected: the fields are the expensive
        // part, and on a spaceport nobody is watching there is no one to
        // collect them for.
        if !self.bus.wants(level) {
            return;
        }

        let mut fields = Fields::default();
        event.record(&mut fields);

        self.bus.emit(fields.into_event(level, metadata.target()));
    }
}

/// The fields of one event, as they are recorded.
///
/// Everything ends up as the string the call site would have written, because
/// that is what a reader wants and because a field's type is not something the
/// far end of a stream can do anything with.
#[derive(Debug, Default)]
struct Fields {
    message: String,
    app: Option<String>,
    category: Option<String>,
    rest: BTreeMap<String, String>,
}

impl Fields {
    fn set(&mut self, field: &Field, value: String) {
        match field.name() {
            "message" => self.message = value,
            "app" => self.app = Some(value),
            "category" => self.category = Some(value),
            name => {
                self.rest.insert(name.to_owned(), value);
            }
        }
    }

    fn into_event(mut self, level: Level, target: &str) -> Event {
        // An explicit category wins, and a nonsensical one is not worth losing
        // the event over — it goes back to being where it came from.
        let category = self
            .category
            .take()
            .and_then(|category| category.parse().ok())
            .unwrap_or_else(|| Category::for_target(target));

        // An `app` field that is not an app id is some other kind of app —
        // `?container.app`, which may be absent — and stays a plain field
        // rather than becoming something `--app` would filter on.
        let app = match self.app.take() {
            Some(app) => match app.parse() {
                Ok(app) => Some(app),
                Err(_) => {
                    self.rest.insert("app".to_owned(), app);
                    None
                }
            },
            None => None,
        };

        Event {
            at: OffsetDateTime::now_utc(),
            level,
            category,
            app,
            message: self.message,
            fields: self.rest,
        }
    }
}

impl Visit for Fields {
    /// What `%value` and `?value` both arrive as: the call site already chose
    /// how it wanted to be read, and this is that choice rendered.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.set(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.set(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.set(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.set(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.set(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.set(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventFilter;
    use tokio::sync::broadcast;
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::SubscriberExt;

    /// A subscriber that only feeds the bus, installed for this thread alone.
    fn capture() -> (Arc<EventBus>, broadcast::Receiver<Arc<Event>>, DefaultGuard) {
        let bus = Arc::new(EventBus::new());
        let (_, rx) = bus.watch(0, &EventFilter::default());
        let subscriber = tracing_subscriber::registry().with(layer(bus.clone()));

        (bus, rx, tracing::subscriber::set_default(subscriber))
    }

    fn next(rx: &mut broadcast::Receiver<Arc<Event>>) -> Arc<Event> {
        rx.try_recv().expect("an event was published")
    }

    #[tokio::test]
    async fn captures_the_message_and_the_fields() {
        let (_bus, mut rx, _guard) = capture();

        tracing::info!(container = "abc123", "app is ready");

        let event = next(&mut rx);
        assert_eq!(event.message, "app is ready");
        assert_eq!(event.level, Level::Info);
        assert_eq!(event.fields["container"], "abc123");
    }

    /// `app = %id` is how nearly every call site names the app it is about,
    /// and it is what `--app` filters on.
    #[tokio::test]
    async fn lifts_the_app_out_of_the_fields() {
        let (_bus, mut rx, _guard) = capture();
        let id: crate::app::AppId = "web-api".parse().unwrap();

        tracing::info!(app = %id, "app is ready");

        let event = next(&mut rx);
        assert_eq!(event.app.as_ref().unwrap().as_str(), "web-api");
        assert!(!event.fields.contains_key("app"));
    }

    /// `app = ?maybe_an_app` is a different kind of field with the same name,
    /// and dropping it would lose what the call site was saying.
    #[tokio::test]
    async fn keeps_an_app_field_that_is_not_an_app_id() {
        let (_bus, mut rx, _guard) = capture();

        tracing::info!(app = ?Some("web-api"), "removed a container no app claims");

        let event = next(&mut rx);
        assert!(event.app.is_none());
        assert_eq!(event.fields["app"], r#"Some("web-api")"#);
    }

    #[tokio::test]
    async fn categorises_by_where_the_event_was_written() {
        let (_bus, mut rx, _guard) = capture();

        tracing::info!("something happened here");

        // This module, which is the streaming machinery itself.
        assert_eq!(next(&mut rx).category.as_str(), "stream");
    }

    #[tokio::test]
    async fn a_call_site_may_say_which_category_it_belongs_to() {
        let (_bus, mut rx, _guard) = capture();

        tracing::info!(category = "acme", "got a certificate");

        let event = next(&mut rx);
        assert_eq!(event.category.as_str(), "acme");
        assert!(!event.fields.contains_key("category"));
    }
}
