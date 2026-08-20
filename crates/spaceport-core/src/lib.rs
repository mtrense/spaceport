//! Core types and logic for spaceport, a reverse proxy for small and internal apps.

pub mod acme;
pub mod app;
pub mod auth;
pub mod build;
pub mod config;
pub mod connections;
pub mod duration;
pub mod edge;
pub mod events;
pub mod operator;
pub mod runtime;
pub mod secret;
pub mod setup;
pub mod state;
pub mod status;
pub(crate) mod uri;

pub use app::{AppId, AppManifest};
pub use config::Config;
pub use events::{Event, EventBus};
pub use operator::OperatorEndpoint;
pub use state::Db;
