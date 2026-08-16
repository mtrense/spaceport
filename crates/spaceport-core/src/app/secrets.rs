//! The values an app's manifest names but never contains.
//!
//! A manifest declares which secrets a container needs and interpolates them
//! into its environment; it does not say what they are, because a manifest is a
//! document an operator commits to a repository. The values are set out of band
//! and live here, keyed by the app they belong to and the environment variable
//! they arrive as — which is the whole of a secret's identity, so setting one
//! twice replaces it rather than piling up a second row.
//!
//! Two things make this more than a key-value table.
//!
//! The first is that a value must be hard to print by accident, so nothing in
//! this module hands back a `String`. Values come in and go out as
//! [`Secret`]s, and [`SecretRepository::names`] — the query an operator's
//! listing runs — cannot return a value at all, because it never reads the
//! column.
//!
//! The second is `version`. A container is recreated when its spec changes, and
//! a secret whose value changed has to count as a change or the app would keep
//! running with the old one. Deciding that by comparing values would mean the
//! plaintext, or a hash somebody can test guesses against, ends up in the
//! fingerprint that is written onto the container as a label. A counter says
//! "not the value you saw last time" and nothing else, which is exactly the
//! question the fingerprint asks — so [`SecretRepository::set`] reports whether
//! anything actually changed, and only bumps the counter when it did. Setting a
//! secret to what it already was must not restart the app.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use tracing::warn;

use super::manifest::VarName;
use super::{AppId, Pattern};
use crate::secret::Secret;
use crate::state::Db;

/// What setting a secret did.
///
/// Three answers and not a `bool`, because the caller wants two different
/// things from them: an operator is told whether the secret is new or replaced,
/// and a redeploy is triggered by anything that is not [`Set::Unchanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Set {
    /// There was no value under that name before.
    Created,
    /// There was, and it was a different one.
    Changed,
    /// There was, and it was byte for byte this one.
    Unchanged,
}

/// A secret as it is stored, with the counter that says which value it is.
///
/// The version travels with the value because the one caller that needs both is
/// the one that renders a container's spec: it interpolates the value and
/// fingerprints the version, and a second query for the counter could answer
/// about a value that had changed in between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecret {
    pub value: Secret,
    /// Which value this is, as a number the app never hands out twice.
    ///
    /// Not a count of the values this *name* has had: it comes from one counter
    /// per app, so that deleting a secret and setting it again cannot land back
    /// on a number a container is already labelled with.
    pub version: u64,
}

/// SQLite integers are signed, so a version goes in and comes back as an `i64`.
/// A stored version that does not fit a `u64` is one nothing wrote on purpose;
/// saying "newer than anything" keeps it comparing as changed.
fn read(version: i64) -> u64 {
    u64::try_from(version).unwrap_or(u64::MAX)
}

/// The next version for `app`, counted in a table of its own.
///
/// One counter for the whole app rather than one per name, because what it has
/// to guarantee is that a number is never handed out twice — two names holding
/// the same number is nothing, since the fingerprint records a version *beside*
/// the name it belongs to. Kept apart from the values it numbers so that
/// deleting a secret cannot take the count with it: that is the whole reason
/// this is not `MAX(version) + 1` over the app's rows.
///
/// In the caller's transaction, so that two operators setting secrets of the
/// same app at once cannot be handed the same number.
fn next_version(transaction: &rusqlite::Transaction<'_>, app: &str) -> Result<i64> {
    transaction
        .execute(
            "INSERT INTO app_secret_versions (spaceport_app, latest) VALUES (?1, 1)
             ON CONFLICT(spaceport_app) DO UPDATE SET latest = latest + 1",
            rusqlite::params![app],
        )
        .context("counting an app's secrets on")?;

    transaction
        .query_row(
            "SELECT latest FROM app_secret_versions WHERE spaceport_app = ?1",
            rusqlite::params![app],
            |row| row.get(0),
        )
        .context("reading the version an app's secret was given")
}

/// The `app_secrets` table, in the vocabulary of setting and reading secrets.
#[derive(Debug, Clone)]
pub struct SecretRepository {
    db: Db,
}

impl SecretRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// The names of the secrets set for `app`, in order, optionally only those
    /// matching `pattern`.
    ///
    /// Names and never values: this is what an operator's listing runs, and the
    /// safest way for a listing not to print a secret is for the query behind it
    /// to have no way of knowing one. The filtering happens here rather than in
    /// SQL because the glob is spaceport's own — `LIKE` would need `*` rewritten
    /// into `%`, `%` and `_` escaped, and would then be a second implementation
    /// of [`Pattern`] that could disagree with the first.
    ///
    /// A row whose name no longer parses is skipped with a warning rather than
    /// failing the read, exactly as an unreadable app record is: one bad row
    /// must not cost an operator the listing of everything else.
    pub async fn names(&self, app: &AppId, pattern: Option<&Pattern>) -> Result<Vec<VarName>> {
        let app = app.to_string();

        let names: Vec<String> = self
            .db
            .call(move |connection| {
                let mut statement = connection
                    .prepare("SELECT name FROM app_secrets WHERE spaceport_app = ?1 ORDER BY name")
                    .context("preparing the app-secrets query")?;

                let names = statement
                    .query_map([app], |row| row.get(0))
                    .context("reading the secrets of an app")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the secrets of an app")?;

                Ok(names)
            })
            .await?;

        Ok(names
            .into_iter()
            .filter_map(|name| match name.parse::<VarName>() {
                Ok(name) => Some(name),
                Err(error) => {
                    warn!(secret = name, %error, "skipping a stored secret whose name is not valid");
                    None
                }
            })
            .filter(|name| pattern.is_none_or(|pattern| pattern.matches_name(name)))
            .collect())
    }

    /// Set the secret `name` of `app` to `value`, and say what that did.
    ///
    /// One transaction, because the answer is about the row as it was: reading
    /// the old value, deciding, and writing the new one have to be one step or
    /// two operators setting the same secret at once could both be told
    /// `Unchanged` while one of them wrote.
    ///
    /// `version` only moves when the value does. That is the point of the
    /// column — a container is recreated because its secrets changed, and
    /// re-setting a secret to what it already held is not a change to anything
    /// the app can observe.
    ///
    /// Whichever way it moves, it moves to a number the app has never used, and
    /// that number comes from `app_secret_versions` rather than from the row
    /// being written. The version's only job is to never name a value the
    /// fingerprint has already seen, and a counter kept in the row fails at
    /// exactly that the moment a secret is deleted: the row goes, the count
    /// goes with it, and the next value under that name is version 1 again —
    /// the number the container still running the credential that was just
    /// rotated away is labelled with, so it fingerprints as current and `adopt`
    /// keeps it. A counter that outlives the values it numbers cannot do that.
    pub async fn set(&self, app: &AppId, name: &VarName, value: &Secret) -> Result<Set> {
        let app = app.to_string();
        let name = name.to_string();
        let value = value.expose().to_owned();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to set an app secret")?;

                let stored: Option<String> = transaction
                    .query_row(
                        "SELECT value FROM app_secrets
                         WHERE spaceport_app = ?1 AND name = ?2",
                        rusqlite::params![app, name],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("reading the secret that is being replaced")?;

                let set = match stored {
                    Some(stored) if stored == value => Set::Unchanged,
                    Some(_) => {
                        let version = next_version(&transaction, &app)?;
                        transaction
                            .execute(
                                "UPDATE app_secrets SET value = ?3, version = ?4
                                 WHERE spaceport_app = ?1 AND name = ?2",
                                rusqlite::params![app, name, value, version],
                            )
                            .context("replacing an app secret")?;

                        Set::Changed
                    }
                    None => {
                        let version = next_version(&transaction, &app)?;
                        transaction
                            .execute(
                                "INSERT INTO app_secrets (spaceport_app, name, value, version)
                                 VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![app, name, value, version],
                            )
                            .context("setting an app secret")?;

                        Set::Created
                    }
                };

                transaction.commit().context("committing an app secret")?;

                Ok(set)
            })
            .await
    }

    /// Forget the secret `name` of `app`.
    ///
    /// Says whether there was one, so an operator who unsets a secret can be
    /// told the difference between having removed it and having spelled it
    /// wrong.
    pub async fn delete(&self, app: &AppId, name: &VarName) -> Result<bool> {
        let app = app.to_string();
        let name = name.to_string();

        self.db
            .call(move |connection| {
                let deleted = connection
                    .execute(
                        "DELETE FROM app_secrets WHERE spaceport_app = ?1 AND name = ?2",
                        rusqlite::params![app, name],
                    )
                    .context("deleting an app secret")?;

                Ok(deleted > 0)
            })
            .await
    }

    /// Everything stored for `app`, values and all.
    ///
    /// The one method that reads the value column, named for what it is for:
    /// resolving the placeholders in a manifest's environment just before the
    /// container is rendered. A `BTreeMap` so that the environment built from it
    /// has one order, for the reason `Container.env` is one — a map that
    /// reshuffled between two reads would make an unchanged app look changed.
    ///
    /// It returns every secret the app has and not the ones a manifest asks
    /// for, because deciding what is missing is the caller's question and it
    /// needs the whole set to answer it.
    pub async fn resolve(&self, app: &AppId) -> Result<BTreeMap<VarName, StoredSecret>> {
        let app = app.to_string();

        let rows: Vec<(String, String, i64)> = self
            .db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT name, value, version FROM app_secrets
                         WHERE spaceport_app = ?1 ORDER BY name",
                    )
                    .context("preparing the app-secret resolution query")?;

                let rows = statement
                    .query_map([app], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .context("resolving the secrets of an app")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("resolving the secrets of an app")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(name, value, version)| match name.parse::<VarName>() {
                Ok(name) => Some((
                    name,
                    StoredSecret {
                        value: Secret::new(value),
                        version: read(version),
                    },
                )),
                Err(error) => {
                    warn!(secret = name, %error, "skipping a stored secret whose name is not valid");
                    None
                }
            })
            .collect())
    }

    /// Forget every secret of `app` — it is no longer spaceport's to run.
    ///
    /// Part of the destroy cascade, written out by hand for the reason the
    /// schema gives for having no foreign key: deleting is the only moment the
    /// relationship has to hold. It says nothing about how many rows there
    /// were, because nobody destroying an app wants to be told a number and a
    /// count of secrets is not something to print on the way out.
    pub async fn forget(&self, app: &AppId) -> Result<()> {
        let app = app.to_string();

        self.db
            .call(move |connection| {
                connection
                    .execute("DELETE FROM app_secrets WHERE spaceport_app = ?1", [app])
                    .context("forgetting the secrets of an app")?;

                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> SecretRepository {
        SecretRepository::new(Db::in_memory().unwrap())
    }

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    fn name(name: &str) -> VarName {
        name.parse().unwrap()
    }

    fn pattern(pattern: &str) -> Pattern {
        pattern.parse().unwrap()
    }

    /// The version the first secret of an app carries, so the tests can say
    /// what they expect without repeating the number's meaning.
    const FIRST: u64 = 1;

    #[tokio::test]
    async fn knows_nothing_to_begin_with() {
        let repository = repository();

        assert!(
            repository
                .names(&app("hello"), None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(repository.resolve(&app("hello")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reads_back_a_secret_that_was_set() {
        let repository = repository();

        assert_eq!(
            repository
                .set(
                    &app("hello"),
                    &name("DATABASE_URL"),
                    &Secret::new("hunter2")
                )
                .await
                .unwrap(),
            Set::Created
        );

        let stored = repository.resolve(&app("hello")).await.unwrap();
        assert_eq!(
            stored[&name("DATABASE_URL")],
            StoredSecret {
                value: Secret::new("hunter2"),
                version: FIRST,
            }
        );
    }

    /// The whole reason `version` is a counter and not a hash: an operator who
    /// re-runs the same `set` — from a script, or after a lost terminal — must
    /// not have their app restarted for it.
    #[tokio::test]
    async fn setting_the_same_value_again_changes_nothing() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("same"))
            .await
            .unwrap();

        assert_eq!(
            repository
                .set(&app("hello"), &name("TOKEN"), &Secret::new("same"))
                .await
                .unwrap(),
            Set::Unchanged
        );

        let stored = repository.resolve(&app("hello")).await.unwrap();
        assert_eq!(stored[&name("TOKEN")].version, FIRST);
    }

    /// And the other half: a value that really is different has to be visible
    /// as different to a fingerprint that never sees the value.
    #[tokio::test]
    async fn changing_a_value_moves_the_version_on() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("before"))
            .await
            .unwrap();

        assert_eq!(
            repository
                .set(&app("hello"), &name("TOKEN"), &Secret::new("after"))
                .await
                .unwrap(),
            Set::Changed
        );

        let stored = repository.resolve(&app("hello")).await.unwrap();
        assert_eq!(stored[&name("TOKEN")].value, Secret::new("after"));
        assert_eq!(stored[&name("TOKEN")].version, FIRST + 1);
    }

    /// The rotation a per-name counter would lose. A secret deleted and set
    /// again is a *new* value, and a container still running the old one is
    /// labelled with the version it had — so a new row that could land on that
    /// number would fingerprint the same, and `adopt` would keep a container
    /// serving the credential somebody has just rotated away.
    ///
    /// The app keeps another secret across the delete, which is what the mark
    /// is counted from: the number is the app's high water and the app's rows
    /// are where it is kept, so an app whose every secret is deleted at once
    /// does start over. That is a hole nothing can fall into — a container's
    /// label carries a version only for the secrets its manifest declares, and
    /// deleting a declared secret is refused while any manifest declares it.
    #[tokio::test]
    async fn a_secret_set_again_after_a_delete_never_reuses_a_version() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("KEEP"), &Secret::new("kept"))
            .await
            .unwrap();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("before"))
            .await
            .unwrap();
        let before = repository.resolve(&app("hello")).await.unwrap()[&name("TOKEN")].version;

        repository
            .delete(&app("hello"), &name("TOKEN"))
            .await
            .unwrap();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("after"))
            .await
            .unwrap();

        let after = repository.resolve(&app("hello")).await.unwrap()[&name("TOKEN")].version;
        assert!(after > before, "{after} is not newer than {before}");
    }

    #[tokio::test]
    async fn lists_the_names_in_a_stable_order() {
        let repository = repository();
        for secret in ["ZULU", "ALPHA", "MIKE"] {
            repository
                .set(&app("hello"), &name(secret), &Secret::new("value"))
                .await
                .unwrap();
        }

        assert_eq!(
            repository.names(&app("hello"), None).await.unwrap(),
            [name("ALPHA"), name("MIKE"), name("ZULU")]
        );
    }

    #[tokio::test]
    async fn lists_only_the_names_a_pattern_asks_for() {
        let repository = repository();
        for secret in ["DATABASE_URL", "DATABASE_PASSWORD", "REDIS_URL"] {
            repository
                .set(&app("hello"), &name(secret), &Secret::new("value"))
                .await
                .unwrap();
        }

        assert_eq!(
            repository
                .names(&app("hello"), Some(&pattern("DATABASE_*")))
                .await
                .unwrap(),
            [name("DATABASE_PASSWORD"), name("DATABASE_URL")]
        );
        assert!(
            repository
                .names(&app("hello"), Some(&pattern("NOTHING_*")))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn deleting_says_whether_there_was_one() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("value"))
            .await
            .unwrap();

        assert!(
            repository
                .delete(&app("hello"), &name("TOKEN"))
                .await
                .unwrap()
        );
        assert!(
            !repository
                .delete(&app("hello"), &name("TOKEN"))
                .await
                .unwrap()
        );
        assert!(
            repository
                .names(&app("hello"), None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Destroying an app takes its secrets with it, and takes nothing else:
    /// the cascade is written by hand, so the test is the only thing keeping it
    /// aimed at one app.
    #[tokio::test]
    async fn forgetting_an_app_leaves_another_apps_secrets_alone() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("mine"))
            .await
            .unwrap();
        repository
            .set(&app("other"), &name("TOKEN"), &Secret::new("theirs"))
            .await
            .unwrap();

        repository.forget(&app("hello")).await.unwrap();

        assert!(
            repository
                .names(&app("hello"), None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            repository.names(&app("other"), None).await.unwrap(),
            [name("TOKEN")]
        );
    }

    /// Two apps naming a secret the same way is the ordinary case — every app
    /// that talks to a database has a `DATABASE_URL` — and one must never be
    /// served the other's value.
    #[tokio::test]
    async fn secrets_of_different_apps_do_not_collide() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("DATABASE_URL"), &Secret::new("mine"))
            .await
            .unwrap();

        assert_eq!(
            repository
                .set(&app("other"), &name("DATABASE_URL"), &Secret::new("theirs"))
                .await
                .unwrap(),
            Set::Created
        );

        assert_eq!(
            repository.resolve(&app("hello")).await.unwrap()[&name("DATABASE_URL")].value,
            Secret::new("mine")
        );
        assert_eq!(
            repository.resolve(&app("other")).await.unwrap()[&name("DATABASE_URL")].value,
            Secret::new("theirs")
        );
    }

    /// A name written by some other tool, or by a future spaceport with looser
    /// names, must not cost an operator the listing of the rest.
    #[tokio::test]
    async fn skips_a_stored_secret_whose_name_is_not_valid() {
        let repository = repository();
        repository
            .set(&app("hello"), &name("TOKEN"), &Secret::new("value"))
            .await
            .unwrap();
        repository
            .db
            .call(|connection| {
                connection
                    .execute(
                        "INSERT INTO app_secrets (spaceport_app, name, value)
                         VALUES ('hello', 'not a name', 'whatever')",
                        [],
                    )
                    .context("inserting a broken row")?;

                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(
            repository.names(&app("hello"), None).await.unwrap(),
            [name("TOKEN")]
        );
        assert_eq!(repository.resolve(&app("hello")).await.unwrap().len(), 1);
    }
}
