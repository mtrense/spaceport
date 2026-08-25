//! Turning a GitHub App an operator has into a connection this spaceport holds.
//!
//! Registration is the one moment the secrets exist outside GitHub's settings
//! page and this spaceport's state store, so it is the moment to be strict: a
//! slug that is not a slug, an app id of zero, an empty webhook secret or a
//! private key that is not a key are all mistakes that are obvious now and
//! invisible in three weeks, when a webhook is quietly failing its signature
//! check and nothing says why.
//!
//! Both ways in end here. An operator who created the App by hand types back
//! what its settings page shows them; the manifest flow in [`super::manifest`]
//! has GitHub create it and hand the same values over at a callback. They
//! differ in where the [`Registration`] comes from and in nothing after that,
//! which is why the checking and the recording live in one place rather than
//! once per flow — a rule enforced on one path and not the other is a rule that
//! holds until somebody uses the other path.
//!
//! Registering also talks to GitHub, once, to ask it a single question: is this
//! really the app whose credentials these are? The local checks run first and a
//! malformed registration never gets that far, because a key that is not a key
//! should not cost a round trip. What the round trip settles is the mistake no
//! local check can see — an app id typed with two digits transposed is a
//! perfectly well-formed number that names somebody else's app or none at all.
//!
//! What is still left to reconciliation is everything about the world rather
//! than the credentials: who has installed the app, what they granted it,
//! whether a webhook is reaching this host. None of that is knowable at the
//! moment an operator is standing there, and refusing to record a connection
//! because nobody has installed it yet would refuse every first connection
//! there has ever been.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tracing::{info, warn};

use super::api::{Client, Transport};
use super::key;
use super::reconcile::Nudge;
use super::repository::{Connection, ConnectionRepository};
use crate::secret::Secret;

/// Everything GitHub tells an operator when they create an App by hand.
///
/// `deny_unknown_fields` because this arrives over the operator socket: a field
/// spelled wrong is a secret that silently did not get set, and the whole point
/// of registering is that the secrets are right.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub slug: String,
    pub app_id: i64,
    pub name: String,
    pub owner: String,
    pub client_id: String,
    pub client_secret: Secret,
    pub webhook_secret: Secret,
    pub private_key: Secret,
}

impl Registration {
    /// Everything about this registration that can be judged without asking
    /// GitHub anything.
    pub fn validate(&self) -> Result<()> {
        if self.slug.is_empty() {
            bail!("the app's slug is empty — it is the name in the app's url on github.com");
        }
        if !self.slug.chars().all(is_slug_character) {
            bail!(
                "`{}` is not a github app slug — a slug is lowercase letters, digits and hyphens, exactly as github wrote it",
                self.slug
            );
        }
        if self.app_id <= 0 {
            bail!(
                "an app id is a positive number, and `{}` is not — it is the `App ID` on the app's settings page",
                self.app_id
            );
        }
        if self.name.is_empty() {
            bail!("the app's name is empty — it is the display name on the app's settings page");
        }
        if self.owner.is_empty() {
            bail!("the app's owner is empty — it is the user or organisation the app belongs to");
        }
        if self.client_id.is_empty() {
            bail!("the client id is empty — it is the `Client ID` on the app's settings page");
        }
        if self.client_secret.expose().is_empty() {
            bail!(
                "the client secret is empty — generate one on the app's settings page and pass it as `--client-secret`"
            );
        }
        if self.webhook_secret.expose().is_empty() {
            bail!(
                "the webhook secret is empty — set one on the app's settings page and pass the same value as `--webhook-secret`"
            );
        }
        if self.private_key.expose().is_empty() {
            bail!(
                "the private key is empty — generate one on the app's settings page and pass the downloaded file as `--private-key`"
            );
        }

        key::validate(self.private_key.expose())
    }
}

/// What a slug may be made of, which is what GitHub generates from an app's
/// name — and what may go in a url path without being escaped.
fn is_slug_character(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
}

/// Check `registration` against GitHub and remember it as a connection of this
/// spaceport's.
///
/// Recording is an upsert on the slug, so connecting an app that is already
/// connected replaces its secrets rather than refusing. That is the supported
/// way to rotate one: generate a new secret on GitHub, run the same command
/// again, and the next request uses the new value.
///
/// Nothing is written unless GitHub answers `/app` with the app these
/// credentials belong to. A connection that is recorded and does not work is
/// worse than none at all: it looks connected in every listing, and the first
/// sign that it is not is a reconciliation pass failing hours later.
///
/// `nudge` is taken rather than left to the caller because there are two callers
/// — an operator registering an App by hand, and the manifest callback where
/// GitHub created one — and a connection whose reconciliation waited an hour
/// because one of them forgot is a bug nothing would ever point at.
pub async fn connect(
    repository: &ConnectionRepository,
    transport: Arc<dyn Transport>,
    registration: Registration,
    nudge: &Nudge,
) -> Result<Connection> {
    registration.validate()?;

    let connection = Connection {
        slug: registration.slug,
        app_id: registration.app_id,
        name: registration.name,
        owner: registration.owner,
        client_id: registration.client_id,
        client_secret: registration.client_secret,
        webhook_secret: registration.webhook_secret,
        private_key: registration.private_key,
        // Stamped by the repository on the way in, so this is only a
        // placeholder for the value that is about to be written.
        connected_at: String::new(),
    };

    let confirmed = Client::new(&connection, transport)?
        .app()
        .await
        .context("the credentials for this app were not accepted")?;

    // GitHub answers `/app` for whichever app signed the request, so an id that
    // disagrees means the key and the id in this registration belong to two
    // different apps — which no amount of reconciliation would ever untangle.
    if confirmed.id != connection.app_id {
        bail!(
            "the private key belongs to github app {}, and the app id given is {} — the key and the `App ID` were taken from two different apps' settings pages",
            confirmed.id,
            connection.app_id
        );
    }

    // Said and not refused: an App made by hand likely predates the manifest's
    // SSO permissions or diverges from them, and everything except SSO login
    // works without these two. Refusing would hold today's registration
    // hostage to a feature the operator may never turn on — but a mapping rule
    // that silently never matches, or a profile that arrives with no address in
    // it, is exactly the invisible-in-three-weeks mistake this module exists to
    // say out loud now.
    //
    // The two are not equally serious and the sentences say so: without
    // `members` nobody is mapped anything, whereas without `emails` people
    // still sign in and simply arrive without the address half of their
    // profile.
    for (permission, why) in [
        ("members", "`org=`/`team=` mapping rules will never match"),
        (
            "emails",
            "the profile an sso login records will carry no email address",
        ),
    ] {
        if confirmed.permissions.get(permission).map(String::as_str) != Some("read") {
            warn!(
                slug = %confirmed.slug,
                "this app does not hold `{permission}: read`, so {why} — request it on the app's settings page, where every account that installed the app must approve the change",
            );
        }
    }

    // The slug, the display name and the owner are all things an operator read
    // off a page and typed back, and GitHub is the only authority on all three.
    // Refusing over one would be refusing a registration whose secrets are
    // every one of them correct because a word is misspelled, so the spelling
    // is corrected instead — and said out loud, because the corrected slug is
    // what every later command has to be given.
    //
    // The secrets are never second-guessed this way. GitHub does not say what
    // they are, and a client secret that is wrong is wrong.
    let mistyped: Vec<&str> = [
        ("slug", &connection.slug, &confirmed.slug),
        ("name", &connection.name, &confirmed.name),
        ("owner", &connection.owner, &confirmed.owner),
    ]
    .into_iter()
    .filter(|(_, typed, confirmed)| typed != confirmed)
    .map(|(field, _, _)| field)
    .collect();

    let connection = if mistyped.is_empty() {
        connection
    } else {
        info!(
            fields = mistyped.join(", "),
            typed = %connection.slug,
            corrected = %confirmed.slug,
            "github spells this app differently, and github's spelling is the one that counts",
        );

        Connection {
            slug: confirmed.slug,
            name: confirmed.name,
            owner: confirmed.owner,
            ..connection
        }
    };

    repository.record(&connection).await?;

    info!(
        slug = %connection.slug,
        app_id = connection.app_id,
        owner = %connection.owner,
        "connected a github app",
    );

    // After recording, because a pass that ran before the row existed would
    // reconcile every connection but this one. An App connected a moment ago
    // usually has nothing installed yet and the pass finds nothing — but an
    // operator who created the App and installed it in the same visit to
    // github.com has, and an hour is a long time to say `not yet` about
    // something spaceport could have asked.
    nudge.nudge();

    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::github::api::testing::FakeGitHub;
    use crate::connections::github::key::testing;
    use crate::state::Db;
    use http::StatusCode;

    fn repository() -> ConnectionRepository {
        ConnectionRepository::new(Db::in_memory().unwrap())
    }

    /// A GitHub that answers as the app [`registration`] describes.
    fn github() -> Arc<FakeGitHub> {
        FakeGitHub::new()
    }

    /// `connect` against a GitHub that agrees with the registration, which is
    /// the case every test that is not about verification wants.
    async fn connect_to(
        repository: &ConnectionRepository,
        registration: Registration,
    ) -> Result<Connection> {
        connect(repository, github(), registration, &Nudge::new()).await
    }

    fn registration() -> Registration {
        Registration {
            // The fixture GitHub answers as app 42, `spaceport-for-acme`.
            slug: "spaceport-for-acme".to_owned(),
            app_id: 42,
            name: "Spaceport for Acme".to_owned(),
            owner: "an-organisation".to_owned(),
            client_id: "Iv1.0123456789abcdef".to_owned(),
            client_secret: Secret::new("a-client-secret"),
            webhook_secret: Secret::new("a-webhook-secret"),
            private_key: Secret::new(testing::PKCS1),
        }
    }

    /// The error a bad registration is refused with, for the tests that only
    /// care what it says.
    fn refused(registration: Registration) -> String {
        registration
            .validate()
            .expect_err("the registration should have been refused")
            .to_string()
    }

    #[tokio::test]
    async fn records_a_registration_and_reads_it_back() {
        let repository = repository();

        let connected = connect_to(&repository, registration()).await.unwrap();

        assert_eq!(connected.slug, "spaceport-for-acme");
        let read = repository
            .by_slug("spaceport-for-acme")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.app_id, 42);
        assert_eq!(read.owner, "an-organisation");
        assert_eq!(read.client_secret, Secret::new("a-client-secret"));
        assert!(read.connected_at.ends_with('Z'), "{read:?}");
    }

    /// An App is connected and installed in the same visit to github.com, so
    /// the reconciler has to hear about it now rather than within the hour —
    /// otherwise `spaceport connect show` says `not yet` for as long as an
    /// operator is willing to keep looking.
    #[tokio::test]
    async fn connecting_an_app_nudges_the_reconciler() {
        let repository = repository();
        let nudge = Nudge::new();
        let changed = nudge.changed();

        connect(&repository, github(), registration(), &nudge)
            .await
            .unwrap();

        assert!(changed.has_changed().unwrap());
    }

    /// Nothing was recorded, so there is nothing for a pass to find — and a
    /// mistyped key must not cost a round trip per connection on this host.
    #[tokio::test]
    async fn a_registration_that_was_refused_nudges_nothing() {
        let repository = repository();
        let nudge = Nudge::new();
        let changed = nudge.changed();

        connect(
            &repository,
            github(),
            Registration {
                private_key: Secret::new("hunter2"),
                ..registration()
            },
            &nudge,
        )
        .await
        .unwrap_err();

        assert!(!changed.has_changed().unwrap());
    }

    /// Rotating a secret is running the same command again, so the second
    /// registration has to win outright.
    #[tokio::test]
    async fn re_connecting_the_same_slug_replaces_the_secrets() {
        let repository = repository();
        connect_to(&repository, registration()).await.unwrap();

        connect_to(
            &repository,
            Registration {
                webhook_secret: Secret::new("a-rotated-webhook-secret"),
                private_key: Secret::new(testing::PKCS8),
                ..registration()
            },
        )
        .await
        .unwrap();

        let all = repository.all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            all[0].webhook_secret,
            Secret::new("a-rotated-webhook-secret")
        );
        assert_eq!(all[0].private_key, Secret::new(testing::PKCS8));
    }

    /// A registration that will not validate must leave nothing behind, or an
    /// operator would have half a connection and no way to tell.
    #[tokio::test]
    async fn a_refused_registration_records_nothing() {
        let repository = repository();

        let result = connect_to(
            &repository,
            Registration {
                private_key: Secret::new("hunter2"),
                ..registration()
            },
        )
        .await;

        assert!(result.is_err());
        assert!(repository.all().await.unwrap().is_empty());
    }

    /// The whole reason registering costs a round trip: nothing is written
    /// down until GitHub has answered as the app these credentials belong to.
    #[tokio::test]
    async fn asks_github_who_the_app_is_before_recording_it() {
        let repository = repository();
        let github = github();

        connect(&repository, github.clone(), registration(), &Nudge::new())
            .await
            .unwrap();

        let paths: Vec<String> = github
            .requests()
            .into_iter()
            .map(|request| request.path)
            .collect();
        assert_eq!(paths, ["/app"]);
    }

    /// An app id with two digits transposed passes every local check there is,
    /// and used to be recorded as happily as a correct one.
    #[tokio::test]
    async fn a_credential_github_rejects_records_nothing() {
        let repository = repository();
        let github = github();
        github.refuse_with(StatusCode::UNAUTHORIZED, "Bad credentials");

        let error = format!(
            "{:#}",
            connect(&repository, github, registration(), &Nudge::new())
                .await
                .unwrap_err()
        );

        assert!(error.contains("not accepted"), "{error}");
        assert!(
            error.contains("does not accept this app's credentials"),
            "{error}"
        );
        assert!(repository.all().await.unwrap().is_empty());
    }

    /// A slug is a word an operator read off a page and typed back, so getting
    /// it wrong is a spelling mistake rather than a wrong credential — and
    /// GitHub is the authority on the spelling.
    #[tokio::test]
    async fn a_mistyped_slug_is_corrected_to_the_one_github_uses() {
        let repository = repository();

        let connected = connect_to(
            &repository,
            Registration {
                slug: "spaceport-for-acmee".to_owned(),
                ..registration()
            },
        )
        .await
        .unwrap();

        assert_eq!(connected.slug, "spaceport-for-acme");
        assert!(
            repository
                .by_slug("spaceport-for-acmee")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .by_slug("spaceport-for-acme")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The display name and the owner are read off the same page as the slug
    /// and mistyped the same way, and GitHub answers for all three — so a
    /// listing shows what GitHub shows rather than what was typed.
    #[tokio::test]
    async fn a_mistyped_name_and_owner_are_corrected_too() {
        let repository = repository();

        let connected = connect_to(
            &repository,
            Registration {
                name: "Spaceport for Acmee".to_owned(),
                owner: "an-organistion".to_owned(),
                ..registration()
            },
        )
        .await
        .unwrap();

        assert_eq!(connected.name, "Spaceport for Acme");
        assert_eq!(connected.owner, "an-organisation");
    }

    /// An App created by hand likely predates the manifest's SSO permissions,
    /// and a registration whose secrets are every one of them correct must not
    /// be refused over a feature the operator may never turn on. The gap is a
    /// warning in the log, not a refusal — so the assertion here is that the
    /// connection lands.
    #[tokio::test]
    async fn connects_an_app_that_lacks_the_sso_permissions() {
        let repository = repository();
        let github = github();
        github.app_permissions(&[("metadata", "read"), ("contents", "read")]);

        connect(&repository, github, registration(), &Nudge::new())
            .await
            .unwrap();

        assert_eq!(repository.all().await.unwrap().len(), 1);
    }

    /// A key from one app's settings page and an id from another's: both are
    /// real, and together they are a connection that could never work.
    #[tokio::test]
    async fn refuses_a_key_and_an_app_id_that_belong_to_different_apps() {
        let repository = repository();
        let github = github();
        github.app_is(43, "some-other-app", "Some Other App", "an-organisation");

        let error = format!(
            "{:#}",
            connect(&repository, github, registration(), &Nudge::new())
                .await
                .unwrap_err()
        );

        assert!(error.contains("belongs to github app 43"), "{error}");
        assert!(repository.all().await.unwrap().is_empty());
    }

    #[test]
    fn accepts_what_github_actually_hands_out() {
        registration().validate().unwrap();
    }

    #[test]
    fn refuses_an_empty_slug() {
        let error = refused(Registration {
            slug: String::new(),
            ..registration()
        });

        assert!(error.contains("slug is empty"), "{error}");
    }

    #[test]
    fn refuses_a_slug_github_would_never_have_written() {
        let error = refused(Registration {
            slug: "Spaceport For Acme".to_owned(),
            ..registration()
        });

        assert!(
            error.contains("lowercase letters, digits and hyphens"),
            "{error}"
        );
    }

    #[test]
    fn refuses_an_app_id_that_is_not_positive() {
        let error = refused(Registration {
            app_id: 0,
            ..registration()
        });

        assert!(error.contains("positive number"), "{error}");
    }

    #[test]
    fn refuses_an_empty_name() {
        let error = refused(Registration {
            name: String::new(),
            ..registration()
        });

        assert!(error.contains("name is empty"), "{error}");
    }

    #[test]
    fn refuses_an_empty_owner() {
        let error = refused(Registration {
            owner: String::new(),
            ..registration()
        });

        assert!(error.contains("owner is empty"), "{error}");
    }

    #[test]
    fn refuses_an_empty_client_id() {
        let error = refused(Registration {
            client_id: String::new(),
            ..registration()
        });

        assert!(error.contains("client id is empty"), "{error}");
    }

    #[test]
    fn refuses_an_empty_client_secret() {
        let error = refused(Registration {
            client_secret: Secret::new(""),
            ..registration()
        });

        assert!(error.contains("client secret is empty"), "{error}");
    }

    #[test]
    fn refuses_an_empty_webhook_secret() {
        let error = refused(Registration {
            webhook_secret: Secret::new(""),
            ..registration()
        });

        assert!(error.contains("webhook secret is empty"), "{error}");
    }

    #[test]
    fn refuses_an_empty_private_key() {
        let error = refused(Registration {
            private_key: Secret::new(""),
            ..registration()
        });

        assert!(error.contains("private key is empty"), "{error}");
    }

    /// The one check that is not about a field being filled in: a key that is
    /// not a key fails at the first webhook otherwise.
    #[test]
    fn refuses_a_private_key_that_is_not_a_key() {
        let error = refused(Registration {
            private_key: Secret::new("hunter2"),
            ..registration()
        });

        assert!(error.contains("not pem"), "{error}");
    }

    /// A field spelled wrong is a secret that silently did not arrive.
    #[test]
    fn refuses_a_field_it_does_not_know() {
        let json = r#"{
            "slug": "spaceport-for-acme",
            "app_id": 1,
            "name": "Spaceport",
            "owner": "an-organisation",
            "client_id": "Iv1.0",
            "client_secret": "a",
            "webhook_secret": "b",
            "private_key": "c",
            "webhook_url": "https://example.test/hook"
        }"#;

        let error = serde_json::from_str::<Registration>(json).unwrap_err();

        assert!(error.to_string().contains("webhook_url"), "{error}");
    }
}
