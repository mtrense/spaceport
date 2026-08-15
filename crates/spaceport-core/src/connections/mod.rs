//! What a spaceport has registered itself with, out on the internet.
//!
//! A connection is spaceport's own identity somewhere else: a GitHub App an
//! operator created for this spaceport, with the secrets that let it ask GitHub
//! questions and prove that a webhook really came from GitHub. It is the exact
//! opposite of an app in [`crate::app`], which is something spaceport runs on
//! this host — a connection is something spaceport *is*, elsewhere, and nothing
//! about it ever gets a container.
//!
//! A spaceport may hold several at once, one per organisation, because a GitHub
//! App belongs to exactly one owner and an operator whose work spans two
//! organisations needs two. So a connection is identified by the app's slug, the
//! name GitHub assigns and an operator reads back off the settings page.
//!
//! `connections` is plural and says nothing about GitHub; `github` is the only
//! thing under it. That is deliberate and it is not an oversight. One
//! implementation is not enough to know where the seam between "a forge" and
//! "GitHub" belongs — the shapes of an installation, a check run and a webhook
//! signature differ enough between forges that a `Forge` trait invented now
//! would be a trait shaped exactly like GitHub with the names filed off. The
//! module boundary is cheap and reserves the room; the trait can wait for a
//! second implementation to argue with.

pub mod github;
pub mod secret;

pub use secret::Secret;
