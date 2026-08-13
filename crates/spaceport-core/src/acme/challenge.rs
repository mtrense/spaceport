//! The answers spaceport is currently prepared to give a CA.
//!
//! An `HTTP-01` challenge is a CA asking for a specific string at a specific
//! URL on port 80, and this is the map from one to the other. It lives only in
//! memory and only for the length of an order: a token is worthless the moment
//! the authorization it belongs to is settled, and a restart mid-order simply
//! orders again.
//!
//! Answers are handed out through a guard, so an order that fails — or panics —
//! takes its token with it rather than leaving spaceport answering a challenge
//! nobody is still waiting on.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The tokens spaceport will answer, and what it answers with.
#[derive(Debug, Default)]
pub struct Challenges {
    answers: RwLock<HashMap<String, String>>,
}

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer `token` with `key_authorization` until the returned guard drops.
    pub fn expect(self: &Arc<Self>, token: String, key_authorization: String) -> PendingChallenge {
        self.write().insert(token.clone(), key_authorization);

        PendingChallenge {
            challenges: self.clone(),
            token,
        }
    }

    /// What to answer a request for `token` with, if spaceport is expecting it.
    pub fn answer(&self, token: &str) -> Option<String> {
        self.read().get(token).cloned()
    }

    /// How many challenges are outstanding.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock means a panic happened between an insert and its
    /// removal. The map itself is a `HashMap<String, String>` and cannot be
    /// left half-written, so the answers are still worth reading — refusing
    /// them would mean a panicked order taking certificate renewal down with it
    /// until the next restart.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, String>> {
        self.answers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, String>> {
        self.answers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A challenge spaceport is answering. Stops answering when dropped.
#[derive(Debug)]
pub struct PendingChallenge {
    challenges: Arc<Challenges>,
    token: String,
}

impl Drop for PendingChallenge {
    fn drop(&mut self) {
        self.challenges.write().remove(&self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_a_challenge_it_is_expecting() {
        let challenges = Arc::new(Challenges::new());
        let _pending = challenges.expect("tok3n".to_owned(), "tok3n.thumbprint".to_owned());

        assert_eq!(
            challenges.answer("tok3n").as_deref(),
            Some("tok3n.thumbprint")
        );
    }

    #[test]
    fn knows_nothing_about_a_token_it_never_issued() {
        assert!(Arc::new(Challenges::new()).answer("tok3n").is_none());
    }

    /// The window in which spaceport answers a challenge is exactly the window
    /// in which the order is waiting on it.
    #[test]
    fn stops_answering_once_the_order_is_done_with_it() {
        let challenges = Arc::new(Challenges::new());
        {
            let _pending = challenges.expect("tok3n".to_owned(), "answer".to_owned());
            assert_eq!(challenges.len(), 1);
        }

        assert!(challenges.answer("tok3n").is_none());
        assert!(challenges.is_empty());
    }

    #[test]
    fn answers_several_hosts_challenges_at_once() {
        let challenges = Arc::new(Challenges::new());
        let _alpha = challenges.expect("alpha".to_owned(), "one".to_owned());
        let beta = challenges.expect("beta".to_owned(), "two".to_owned());

        assert_eq!(challenges.len(), 2);
        drop(beta);

        assert_eq!(challenges.answer("alpha").as_deref(), Some("one"));
        assert!(challenges.answer("beta").is_none());
    }
}
