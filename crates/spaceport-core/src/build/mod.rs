//! Turning a commit into an image.
//!
//! A tracking says an app is built from a branch of a repository, and a push
//! records the revision that branch moved to. This module is what happens next:
//! the commit is fetched from GitHub, unpacked onto the host, its manifest is
//! read, and the engine is asked to build an image from it. The image is
//! tagged, recorded against the app and the revision it came from, and left
//! there. Nothing here deploys it — an app goes on running whatever it was
//! running, and pointing it at a fresh image is a later step.
//!
//! Four seams, in the order a build crosses them. [`archive`] gets the bytes of
//! a commit out of GitHub, which is two requests rather than one and
//! deliberately so. [`unpack`] turns those bytes into a directory, treating the
//! archive as hostile because an archive is a file format with a long history
//! of naming paths outside the directory it is being extracted into. [`dir`]
//! decides where that directory goes and, unlike everywhere else spaceport
//! writes to disk, deletes it again. [`image`] hands the result to the engine.
//!
//! The engine's builder is behind a trait for a reason that is concrete rather
//! than aspirational: the classic builder is what bollard supports without a
//! feature flag, and turning on the buildkit feature changes the *type* of the
//! field a built image's id arrives in. A seam that returns spaceport's own
//! answer is what makes that a change to one file.

pub mod archive;
pub mod dir;
pub mod image;
pub mod repository;
pub mod unpack;
pub mod worker;
