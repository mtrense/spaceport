//! Turning a GitHub App an operator has into a connection this spaceport holds.
//!
//! Registration is the one moment the secrets exist outside GitHub's settings
//! page and this spaceport's state store, so it is the moment to be strict: a
//! slug that is not a slug, an app id of zero, an empty webhook secret or a
//! private key that is not a key are all mistakes that are obvious now and
//! invisible in three weeks, when a webhook is quietly failing its signature
//! check and nothing says why.
//!
//! Only the manual half lives here for now — an operator created the App by
//! hand on github.com and types back what the settings page shows them. The
//! other half, where spaceport hands GitHub an App manifest and GitHub creates
//! the App and hands the secrets back, arrives with the next step and lands in
//! this module beside it, because both flows end in the same place: a validated
//! [`Registration`] recorded as a [`Connection`].
//!
//! Nothing here talks to GitHub, and that limits what "valid" can mean.
//! Whether the app id is really this operator's app, whether the client secret
//! was rotated an hour ago, whether anybody has installed it — none of that can
//! be known without the network, and reconciliation is what finds it out. What
//! can be checked locally is checked locally, and the rest waits.

use anyhow::{Result, bail};
use serde::Deserialize;
use tracing::info;

use super::key;
use super::repository::{Connection, ConnectionRepository};
use crate::connections::Secret;

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

/// Check `registration` and remember it as a connection of this spaceport's.
///
/// Recording is an upsert on the slug, so connecting an app that is already
/// connected replaces its secrets rather than refusing. That is the supported
/// way to rotate one: generate a new secret on GitHub, run the same command
/// again, and the next request uses the new value.
pub async fn connect(
    repository: &ConnectionRepository,
    registration: Registration,
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

    repository.record(&connection).await?;

    info!(
        slug = %connection.slug,
        app_id = connection.app_id,
        owner = %connection.owner,
        "connected a github app",
    );

    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::github::key::testing;
    use crate::state::Db;

    fn repository() -> ConnectionRepository {
        ConnectionRepository::new(Db::in_memory().unwrap())
    }

    fn registration() -> Registration {
        Registration {
            slug: "spaceport-for-acme".to_owned(),
            app_id: 1_234_567,
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

        let connected = connect(&repository, registration()).await.unwrap();

        assert_eq!(connected.slug, "spaceport-for-acme");
        let read = repository
            .by_slug("spaceport-for-acme")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.app_id, 1_234_567);
        assert_eq!(read.owner, "an-organisation");
        assert_eq!(read.client_secret, Secret::new("a-client-secret"));
        assert!(read.connected_at.ends_with('Z'), "{read:?}");
    }

    /// Rotating a secret is running the same command again, so the second
    /// registration has to win outright.
    #[tokio::test]
    async fn re_connecting_the_same_slug_replaces_the_secrets() {
        let repository = repository();
        connect(&repository, registration()).await.unwrap();

        connect(
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

        let result = connect(
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
