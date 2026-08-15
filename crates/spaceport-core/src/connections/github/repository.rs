//! What survives a restart of a spaceport's connections to GitHub.
//!
//! Two quite different kinds of thing live in these tables, and keeping them
//! apart is most of what this module is about. A [`Connection`] is intent and
//! is expensive to lose: it is a GitHub App an operator registered, with the
//! secrets that let this spaceport act as it, and a forgotten one means walking
//! the registration flow again. An [`Installation`] and its repositories are
//! the opposite — a cache of what GitHub last said, refreshed by reconciliation
//! and worth exactly one pass if it goes missing. They are written down only so
//! a spaceport that has just restarted can answer a question before its first
//! pass has finished.
//!
//! Deliveries are a third thing again: a window, not a log. A row exists so
//! that a webhook GitHub sends twice is acted on once, and is pruned by age
//! rather than kept.
//!
//! Nothing here talks to GitHub. Fetching installations, minting tokens and
//! verifying signatures live elsewhere; this module only writes down what those
//! came back with, so that the code which does talk to GitHub can be tested
//! without a database and this can be tested without a network.

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;

use crate::connections::Secret;
use crate::state::Db;

/// One GitHub App this spaceport has registered for itself.
///
/// The secrets are [`Secret`]s rather than `String`s so that printing a
/// connection — in a log line, in an operator's listing, in a panic — cannot
/// give them away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// The name GitHub assigned the app, and the one an operator types.
    pub slug: String,
    /// The numeric id a webhook header carries and a token is minted against.
    pub app_id: i64,
    pub name: String,
    /// The user or organisation the app belongs to.
    pub owner: String,
    pub client_id: String,
    pub client_secret: Secret,
    pub webhook_secret: Secret,
    pub private_key: Secret,
    /// When the connection was recorded, RFC 3339.
    pub connected_at: String,
}

/// One place a connection's app has been installed, with what it can see there.
///
/// Everything in here is GitHub's answer, not spaceport's: there is no id of
/// spaceport's own, because there is nothing an operator decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    pub installation_id: i64,
    /// The user or organisation that installed the app.
    pub account: String,
    /// `User` or `Organization`, as GitHub spells it — kept as GitHub's own
    /// word rather than an enum, because a new account kind must not make a
    /// stored row unreadable.
    pub account_type: String,
    /// The repositories the installation grants, as `owner/name`.
    pub repositories: Vec<String>,
}

/// The columns of `github_apps`, in the order [`connection_from`] reads them.
///
/// Written once so the `SELECT`s and the row mapping cannot drift apart.
const CONNECTION_COLUMNS: &str = "slug, app_id, name, owner, client_id, client_secret, \
                                  webhook_secret, private_key, connected_at";

/// The connection tables, in the vocabulary of connecting, reconciling and
/// forgetting.
///
/// Named for what it holds — connections — and *not* `GithubRepository`, which
/// would read as "a repository on GitHub" and collide in the mind with the
/// `github_repositories` table it also writes to. The module path
/// `connections::github` already says which forge this is about.
#[derive(Debug, Clone)]
pub struct ConnectionRepository {
    db: Db,
}

impl ConnectionRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Remember `connection` as a GitHub App this spaceport holds.
    ///
    /// Replaces whatever was recorded under that slug: re-registering an app is
    /// a `PUT`, and a slug an operator connects twice is one app, not two.
    /// `connected_at` is stamped here rather than taken from the struct, so the
    /// recorded time is always the time the row was written.
    pub async fn record(&self, connection: &Connection) -> Result<()> {
        let slug = connection.slug.clone();
        let app_id = connection.app_id;
        let name = connection.name.clone();
        let owner = connection.owner.clone();
        let client_id = connection.client_id.clone();
        let client_secret = connection.client_secret.expose().to_owned();
        let webhook_secret = connection.webhook_secret.expose().to_owned();
        let private_key = connection.private_key.expose().to_owned();
        let connected_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO github_apps (
                             slug, app_id, name, owner, client_id,
                             client_secret, webhook_secret, private_key, connected_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                         ON CONFLICT(slug) DO UPDATE SET
                             app_id         = excluded.app_id,
                             name           = excluded.name,
                             owner          = excluded.owner,
                             client_id      = excluded.client_id,
                             client_secret  = excluded.client_secret,
                             webhook_secret = excluded.webhook_secret,
                             private_key    = excluded.private_key,
                             connected_at   = excluded.connected_at",
                        rusqlite::params![
                            slug,
                            app_id,
                            name,
                            owner,
                            client_id,
                            client_secret,
                            webhook_secret,
                            private_key,
                            connected_at
                        ],
                    )
                    .context("recording a github connection")?;

                Ok(())
            })
            .await
    }

    /// Every connection this spaceport holds, by slug.
    ///
    /// Ordered so that a listing an operator reads twice reads the same twice.
    pub async fn all(&self) -> Result<Vec<Connection>> {
        self.db
            .call(|connection| {
                let mut statement = connection
                    .prepare(&format!(
                        "SELECT {CONNECTION_COLUMNS} FROM github_apps ORDER BY slug"
                    ))
                    .context("preparing the github connections query")?;

                let rows = statement
                    .query_map([], connection_from)
                    .context("reading the github connections")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the github connections")?;

                Ok(rows)
            })
            .await
    }

    /// The connection an operator knows by `slug`, if there is one.
    pub async fn by_slug(&self, slug: &str) -> Result<Option<Connection>> {
        let slug = slug.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!("SELECT {CONNECTION_COLUMNS} FROM github_apps WHERE slug = ?1"),
                        [slug],
                        connection_from,
                    )
                    .optional()
                    .context("reading a github connection by slug")
            })
            .await
    }

    /// The connection GitHub knows by `app_id`, if there is one.
    ///
    /// This is the webhook's way in: a delivery names its app only in the
    /// `X-GitHub-Hook-Installation-Target-ID` header, and resolving that to a
    /// row is how spaceport finds the secret that says whether the delivery is
    /// genuine.
    pub async fn by_app_id(&self, app_id: i64) -> Result<Option<Connection>> {
        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        &format!("SELECT {CONNECTION_COLUMNS} FROM github_apps WHERE app_id = ?1"),
                        [app_id],
                        connection_from,
                    )
                    .optional()
                    .context("reading a github connection by app id")
            })
            .await
    }

    /// Forget the connection named `slug`, and everything cached under it.
    ///
    /// Says whether there was one, so a disconnect can tell "removed it" from
    /// "there was nothing to remove".
    ///
    /// The cascade is written out here rather than declared as a foreign key on
    /// purpose. A declared `ON DELETE CASCADE` would also make every write to
    /// `github_installations` depend on the connection row still being there,
    /// which turns a reconciliation racing a disconnect into a failed pass
    /// instead of a stale one. Deleting is the only moment the relationship
    /// actually has to hold, so it is the only moment that enforces it — and
    /// one transaction means an interrupted disconnect leaves either everything
    /// or nothing.
    pub async fn forget(&self, slug: &str) -> Result<bool> {
        let slug = slug.to_owned();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to forget a github connection")?;

                let app_id: Option<i64> = transaction
                    .query_row(
                        "SELECT app_id FROM github_apps WHERE slug = ?1",
                        [&slug],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("looking up the connection to forget")?;

                let Some(app_id) = app_id else {
                    return Ok(false);
                };

                transaction
                    .execute("DELETE FROM github_apps WHERE slug = ?1", [&slug])
                    .context("forgetting a github connection")?;
                for table in [
                    "github_installations",
                    "github_repositories",
                    "github_deliveries",
                ] {
                    transaction
                        .execute(&format!("DELETE FROM {table} WHERE app_id = ?1"), [app_id])
                        .with_context(|| format!("forgetting the rows in `{table}`"))?;
                }

                // Spelled out separately because the column is not `app_id`:
                // `github_tracking` holds spaceport's own app id as well, and
                // names GitHub's `github_app_id` so the two cannot be mistaken
                // for one another. Written here rather than delegated to
                // `TrackingRepository`, so it is inside the one transaction
                // that makes a disconnect all-or-nothing.
                transaction
                    .execute(
                        "DELETE FROM github_tracking WHERE github_app_id = ?1",
                        [app_id],
                    )
                    .context("forgetting what the connection's apps tracked")?;

                transaction
                    .commit()
                    .context("committing a forgotten github connection")?;

                Ok(true)
            })
            .await
    }

    /// Write down what GitHub says the app `app_id` is installed on.
    ///
    /// A full replacement, not a merge: GitHub's list is the whole truth about
    /// where an app is installed, so an installation that is not in it has been
    /// removed and a repository that is not in it is no longer granted. That
    /// makes any row which survives a pass a row GitHub still reports, which is
    /// the only reading of this cache that is safe to act on.
    ///
    /// One transaction, so a pass that is interrupted leaves the previous
    /// answer intact rather than half of the new one.
    pub async fn record_installations(
        &self,
        app_id: i64,
        installations: &[Installation],
    ) -> Result<()> {
        let installations = installations.to_vec();
        let seen_at = crate::state::now();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to record github installations")?;

                for installation in &installations {
                    transaction
                        .execute(
                            "INSERT INTO github_installations (
                                 app_id, installation_id, account, account_type, seen_at
                             )
                             VALUES (?1, ?2, ?3, ?4, ?5)
                             ON CONFLICT(app_id, installation_id) DO UPDATE SET
                                 account      = excluded.account,
                                 account_type = excluded.account_type,
                                 seen_at      = excluded.seen_at",
                            rusqlite::params![
                                app_id,
                                installation.installation_id,
                                installation.account,
                                installation.account_type,
                                seen_at
                            ],
                        )
                        .context("recording a github installation")?;

                    for full_name in &installation.repositories {
                        transaction
                            .execute(
                                "INSERT INTO github_repositories (
                                     app_id, installation_id, full_name, seen_at
                                 )
                                 VALUES (?1, ?2, ?3, ?4)
                                 ON CONFLICT(app_id, installation_id, full_name) DO UPDATE SET
                                     seen_at = excluded.seen_at",
                                rusqlite::params![
                                    app_id,
                                    installation.installation_id,
                                    full_name,
                                    seen_at
                                ],
                            )
                            .context("recording a repository of a github installation")?;
                    }
                }

                let ids: Vec<i64> = installations
                    .iter()
                    .map(|installation| installation.installation_id)
                    .collect();

                // Installations GitHub no longer reports, and everything they
                // used to grant.
                for table in ["github_installations", "github_repositories"] {
                    let statement = format!(
                        "DELETE FROM {table} WHERE app_id = ?1 AND installation_id NOT IN ({})",
                        placeholders(ids.len(), 2)
                    );
                    transaction
                        .execute(
                            &statement,
                            rusqlite::params_from_iter(
                                std::iter::once(app_id).chain(ids.iter().copied()),
                            ),
                        )
                        .with_context(|| format!("dropping vanished rows from `{table}`"))?;
                }

                // And, for the installations that remain, the repositories they
                // no longer grant.
                for installation in &installations {
                    let statement = format!(
                        "DELETE FROM github_repositories
                         WHERE app_id = ?1 AND installation_id = ?2 AND full_name NOT IN ({})",
                        placeholders(installation.repositories.len(), 3)
                    );
                    let parameters = [
                        rusqlite::types::Value::from(app_id),
                        rusqlite::types::Value::from(installation.installation_id),
                    ]
                    .into_iter()
                    .chain(
                        installation
                            .repositories
                            .iter()
                            .map(|name| rusqlite::types::Value::from(name.clone())),
                    );
                    transaction
                        .execute(&statement, rusqlite::params_from_iter(parameters))
                        .context("dropping repositories an installation no longer grants")?;
                }

                transaction
                    .commit()
                    .context("committing the recorded github installations")?;

                Ok(())
            })
            .await
    }

    /// Where the app `app_id` is installed, as of the last reconciliation.
    ///
    /// Ordered by installation id, and each installation's repositories by
    /// name, so that a listing and a diff of two listings both mean something.
    pub async fn installations(&self, app_id: i64) -> Result<Vec<Installation>> {
        self.db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT installation_id, account, account_type
                         FROM github_installations
                         WHERE app_id = ?1
                         ORDER BY installation_id",
                    )
                    .context("preparing the github installations query")?;

                let rows = statement
                    .query_map([app_id], |row| {
                        Ok(Installation {
                            installation_id: row.get(0)?,
                            account: row.get(1)?,
                            account_type: row.get(2)?,
                            repositories: Vec::new(),
                        })
                    })
                    .context("reading the github installations")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the github installations")?;

                let mut statement = connection
                    .prepare(
                        "SELECT full_name FROM github_repositories
                         WHERE app_id = ?1 AND installation_id = ?2
                         ORDER BY full_name",
                    )
                    .context("preparing the github repositories query")?;

                rows.into_iter()
                    .map(|installation| {
                        let repositories = statement
                            .query_map(
                                rusqlite::params![app_id, installation.installation_id],
                                |row| row.get(0),
                            )
                            .context("reading the repositories of a github installation")?
                            .collect::<rusqlite::Result<Vec<String>>>()
                            .context("reading the repositories of a github installation")?;

                        Ok(Installation {
                            repositories,
                            ..installation
                        })
                    })
                    .collect()
            })
            .await
    }

    /// When a reconciliation pass last wrote down what GitHub said about
    /// `app_id`, if one ever has.
    ///
    /// The newest `seen_at` across the installations, because a pass stamps
    /// every row it writes with the same moment — so the maximum is when the
    /// pass ran, and `None` means no pass has succeeded yet. Reported rather
    /// than computed from the interval: what an operator wants to know when a
    /// repository is missing is whether the cache is stale, and only the rows
    /// can say that.
    pub async fn last_reconciled(&self, app_id: i64) -> Result<Option<String>> {
        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        "SELECT MAX(seen_at) FROM github_installations WHERE app_id = ?1",
                        [app_id],
                        |row| row.get(0),
                    )
                    .context("reading when a github connection was last reconciled")
            })
            .await
    }

    /// Write down that delivery `delivery_id` arrived, and say whether it is
    /// new.
    ///
    /// The return value *is* the deduplication answer: `true` means this
    /// delivery has not been seen and the caller should act on it, `false`
    /// means GitHub has sent it before and the caller should do nothing but
    /// answer `200`. Because the insert and the check are the same statement,
    /// two deliveries racing each other cannot both be told they are first.
    pub async fn record_delivery(
        &self,
        delivery_id: &str,
        app_id: i64,
        event: &str,
    ) -> Result<bool> {
        let delivery_id = delivery_id.to_owned();
        let event = event.to_owned();
        let received_at = crate::state::now();

        self.db
            .call(move |connection| {
                let inserted = connection
                    .execute(
                        "INSERT INTO github_deliveries (delivery_id, app_id, event, received_at)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(delivery_id) DO NOTHING",
                        rusqlite::params![delivery_id, app_id, event, received_at],
                    )
                    .context("recording a github delivery")?;

                Ok(inserted > 0)
            })
            .await
    }

    /// Drop every delivery received before `before`, and say how many.
    ///
    /// `before` is an RFC 3339 timestamp, and the comparison is a plain text
    /// one. That works — and is the reason nothing here parses a date — because
    /// [`crate::state::now`] writes a fixed-width UTC format, where sorting the
    /// strings is sorting the moments. A stamp written in some other zone or
    /// some other width would break that quietly, which is why nothing but
    /// `now()` writes these columns.
    pub async fn prune_deliveries(&self, before: &str) -> Result<usize> {
        let before = before.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "DELETE FROM github_deliveries WHERE received_at < ?1",
                        [before],
                    )
                    .context("pruning github deliveries")
            })
            .await
    }
}

/// One row of `github_apps`, in the order [`CONNECTION_COLUMNS`] names.
fn connection_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<Connection> {
    Ok(Connection {
        slug: row.get(0)?,
        app_id: row.get(1)?,
        name: row.get(2)?,
        owner: row.get(3)?,
        client_id: row.get(4)?,
        client_secret: Secret::new(row.get::<_, String>(5)?),
        webhook_secret: Secret::new(row.get::<_, String>(6)?),
        private_key: Secret::new(row.get::<_, String>(7)?),
        connected_at: row.get(8)?,
    })
}

/// `?4, ?5, ?6` — `count` numbered placeholders starting at `first`, for the
/// body of an `IN (…)`.
///
/// SQLite has no `IN ()`, and `x NOT IN (NULL)` is neither true nor false, so
/// an empty list is spelled as a subquery that selects nothing instead: `x NOT
/// IN (SELECT NULL WHERE 0)` is true for every row, which is what "GitHub
/// reports none of these, delete them all" has to mean.
fn placeholders(count: usize, first: usize) -> String {
    if count == 0 {
        return "SELECT NULL WHERE 0".to_owned();
    }

    (first..first + count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> ConnectionRepository {
        ConnectionRepository::new(Db::in_memory().unwrap())
    }

    fn connection(slug: &str, app_id: i64) -> Connection {
        Connection {
            slug: slug.to_owned(),
            app_id,
            name: "Spaceport".to_owned(),
            owner: "an-organisation".to_owned(),
            client_id: "Iv1.0123456789abcdef".to_owned(),
            client_secret: Secret::new("client-secret"),
            webhook_secret: Secret::new("webhook-secret"),
            private_key: Secret::new("-----BEGIN RSA PRIVATE KEY-----"),
            connected_at: String::new(),
        }
    }

    fn installation(installation_id: i64, repositories: &[&str]) -> Installation {
        Installation {
            installation_id,
            account: "an-organisation".to_owned(),
            account_type: "Organization".to_owned(),
            repositories: repositories
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }

    #[tokio::test]
    async fn holds_no_connections_to_begin_with() {
        let repository = repository();

        assert!(repository.all().await.unwrap().is_empty());
        assert!(repository.by_slug("spaceport").await.unwrap().is_none());
        assert!(repository.by_app_id(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn records_and_reads_back_a_connection() {
        let repository = repository();
        let recorded = connection("spaceport", 42);
        repository.record(&recorded).await.unwrap();

        let read = repository.by_slug("spaceport").await.unwrap().unwrap();
        assert_eq!(read.app_id, 42);
        assert_eq!(read.owner, recorded.owner);
        assert_eq!(read.client_secret, recorded.client_secret);
        assert_eq!(read.private_key, recorded.private_key);
        // Stamped on the way in, whatever the struct said.
        assert!(read.connected_at.ends_with('Z'), "{read:?}");
    }

    #[tokio::test]
    async fn re_recording_the_same_slug_replaces_it() {
        let repository = repository();
        repository
            .record(&connection("spaceport", 42))
            .await
            .unwrap();

        let renewed = Connection {
            webhook_secret: Secret::new("a-new-webhook-secret"),
            ..connection("spaceport", 42)
        };
        repository.record(&renewed).await.unwrap();

        let all = repository.all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].webhook_secret, Secret::new("a-new-webhook-secret"));
    }

    /// The webhook's lookup: a delivery names only the numeric app id, and
    /// that has to reach the secret which verifies it.
    #[tokio::test]
    async fn finds_a_connection_by_app_id() {
        let repository = repository();
        repository.record(&connection("alpha", 1)).await.unwrap();
        repository.record(&connection("beta", 2)).await.unwrap();

        let found = repository.by_app_id(2).await.unwrap().unwrap();
        assert_eq!(found.slug, "beta");
        assert!(repository.by_app_id(3).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn lists_connections_in_slug_order() {
        let repository = repository();
        for (index, slug) in ["zulu", "alpha", "mike"].iter().enumerate() {
            repository
                .record(&connection(slug, index as i64 + 1))
                .await
                .unwrap();
        }

        let slugs: Vec<String> = repository
            .all()
            .await
            .unwrap()
            .into_iter()
            .map(|connection| connection.slug)
            .collect();
        assert_eq!(slugs, ["alpha", "mike", "zulu"]);
    }

    #[tokio::test]
    async fn forgetting_a_connection_says_whether_there_was_one() {
        let repository = repository();
        repository
            .record(&connection("spaceport", 42))
            .await
            .unwrap();

        assert!(repository.forget("spaceport").await.unwrap());
        assert!(!repository.forget("spaceport").await.unwrap());
        assert!(repository.all().await.unwrap().is_empty());
    }

    /// Nothing declares the cascade, so this is the test that it happens.
    #[tokio::test]
    async fn forgetting_a_connection_takes_its_cache_with_it() {
        let repository = repository();
        repository
            .record(&connection("spaceport", 42))
            .await
            .unwrap();
        repository
            .record_installations(42, &[installation(7, &["an-organisation/site"])])
            .await
            .unwrap();
        repository
            .record_delivery("delivery-1", 42, "push")
            .await
            .unwrap();
        let tracking = crate::connections::github::TrackingRepository::new(repository.db.clone());
        tracking
            .record(&crate::connections::github::Tracking {
                app: "site".parse().unwrap(),
                github_app_id: 42,
                repository: "an-organisation/site".to_owned(),
                branch: "main".to_owned(),
                manifest_path: "spaceport.yaml".to_owned(),
                tracked_at: String::new(),
                revision: None,
                revision_seen_at: None,
            })
            .await
            .unwrap();

        repository.forget("spaceport").await.unwrap();

        assert!(repository.installations(42).await.unwrap().is_empty());
        assert!(tracking.all().await.unwrap().is_empty());
        // The delivery is gone too, so its id is new again.
        assert!(
            repository
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn records_the_installations_of_an_app() {
        let repository = repository();
        repository
            .record_installations(
                42,
                &[
                    installation(9, &["an-organisation/zulu", "an-organisation/alpha"]),
                    installation(7, &["an-organisation/site"]),
                ],
            )
            .await
            .unwrap();

        let installations = repository.installations(42).await.unwrap();
        assert_eq!(
            installations
                .iter()
                .map(|installation| installation.installation_id)
                .collect::<Vec<_>>(),
            [7, 9]
        );
        assert_eq!(installations[0].account, "an-organisation");
        assert_eq!(installations[0].account_type, "Organization");
        assert_eq!(
            installations[1].repositories,
            ["an-organisation/alpha", "an-organisation/zulu"]
        );
    }

    /// GitHub's list is the whole truth, so a pass replaces rather than merges:
    /// an installation that has gone is gone, and one that stayed keeps only
    /// the repositories the new list gives it.
    #[tokio::test]
    async fn recording_installations_replaces_the_previous_set() {
        let repository = repository();
        repository
            .record_installations(
                42,
                &[
                    installation(7, &["an-organisation/site", "an-organisation/old"]),
                    installation(9, &["an-organisation/other"]),
                ],
            )
            .await
            .unwrap();

        repository
            .record_installations(
                42,
                &[installation(
                    7,
                    &["an-organisation/site", "an-organisation/new"],
                )],
            )
            .await
            .unwrap();

        let installations = repository.installations(42).await.unwrap();
        assert_eq!(installations.len(), 1);
        assert_eq!(installations[0].installation_id, 7);
        assert_eq!(
            installations[0].repositories,
            ["an-organisation/new", "an-organisation/site"]
        );
    }

    /// An app GitHub reports no installations for keeps none, which the empty
    /// `IN ()` has to survive.
    #[tokio::test]
    async fn recording_no_installations_empties_the_cache() {
        let repository = repository();
        repository
            .record_installations(42, &[installation(7, &["an-organisation/site"])])
            .await
            .unwrap();

        repository.record_installations(42, &[]).await.unwrap();

        assert!(repository.installations(42).await.unwrap().is_empty());
    }

    /// One app's reconciliation must not touch another's rows, since the two
    /// share every table.
    #[tokio::test]
    async fn recording_installations_leaves_another_app_alone() {
        let repository = repository();
        repository
            .record_installations(42, &[installation(7, &["an-organisation/site"])])
            .await
            .unwrap();
        repository
            .record_installations(43, &[installation(8, &["another-org/site"])])
            .await
            .unwrap();

        repository.record_installations(42, &[]).await.unwrap();

        let other = repository.installations(43).await.unwrap();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].repositories, ["another-org/site"]);
    }

    /// An empty listing is not the same answer as a cache nothing has ever
    /// filled, and `spaceport connect show` has to be able to tell them apart.
    #[tokio::test]
    async fn says_when_an_app_was_last_reconciled_and_when_it_never_has_been() {
        let repository = repository();

        assert!(repository.last_reconciled(42).await.unwrap().is_none());

        repository
            .record_installations(42, &[installation(7, &["an-organisation/site"])])
            .await
            .unwrap();

        let reconciled = repository.last_reconciled(42).await.unwrap().unwrap();
        assert!(reconciled.ends_with('Z'), "{reconciled}");
        // Another app's pass is not this one's.
        assert!(repository.last_reconciled(43).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_delivery_is_new_only_the_first_time() {
        let repository = repository();

        assert!(
            repository
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap()
        );
        assert!(
            !repository
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap()
        );
        assert!(
            repository
                .record_delivery("delivery-2", 42, "push")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn pruning_drops_only_deliveries_older_than_the_cutoff() {
        let repository = repository();
        repository
            .db
            .call(|connection| {
                connection
                    .execute(
                        "INSERT INTO github_deliveries VALUES
                             ('old', 42, 'push', '2026-01-01T00:00:00Z'),
                             ('newer', 42, 'push', '2026-06-01T00:00:00Z')",
                        [],
                    )
                    .context("inserting deliveries to prune")?;

                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(
            repository
                .prune_deliveries("2026-03-01T00:00:00Z")
                .await
                .unwrap(),
            1
        );
        // The pruned one is unknown again; the kept one is still known.
        assert!(repository.record_delivery("old", 42, "push").await.unwrap());
        assert!(
            !repository
                .record_delivery("newer", 42, "push")
                .await
                .unwrap()
        );
    }
}
