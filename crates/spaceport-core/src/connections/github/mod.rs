//! A spaceport's connection to GitHub: the App it registered, and what that App
//! can see.
//!
//! A GitHub App is the shape this takes because it is the only one that fits.
//! A personal access token belongs to a person and leaves when they do; an
//! OAuth app acts as whoever authorised it. An App is an actor of its own,
//! installed on an organisation by somebody who has the right to, granting only
//! the repositories they chose — which is what an operator means when they say
//! a spaceport should be able to see their code.
//!
//! What lives here for now is the persistence — the connection an operator
//! registered, the installations reconciliation has discovered, and the recent
//! webhook deliveries that let a redelivery be recognised as one — together
//! with registering an App an operator created by hand, reading the key it
//! signs with, and the client that asks GitHub what the App is and mints the
//! tokens that act as its installations — and, beside registering an App by
//! hand, the App Manifest flow that has GitHub create one instead. Verifying
//! webhook signatures and serving the webhook route are each their own module,
//! and each arrives with the step that needs it.

pub mod api;
pub mod jwt;
pub mod key;
pub mod manifest;
pub mod register;
pub mod repository;

pub use api::{Client, Network, Transport};
pub use manifest::{Attempt, Attempts};
pub use register::{Registration, connect};
pub use repository::{Connection, ConnectionRepository, Installation};
