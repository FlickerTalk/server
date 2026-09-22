//! Temporary TURN credentials (Plan §17) in coturn's REST scheme: the username is
//! `<expiry>:<random>` and the password is `base64(HMAC-SHA1(shared secret, username))`. coturn
//! checks them with the same secret (`use-auth-secret`), so nothing is stored anywhere. The random
//! part is never the `device_id`: the relay must not learn who is talking.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

/// What a client needs to use the relays: the URLs and one temporary user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TurnCredentials {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// Issues credentials signed with the secret shared with coturn.
#[derive(Clone)]
pub struct TurnIssuer {
    secret: Vec<u8>,
    urls: Vec<String>,
    ttl: Duration,
}

impl TurnIssuer {
    pub fn new(secret: Vec<u8>, urls: Vec<String>, ttl: Duration) -> Self {
        Self { secret, urls, ttl }
    }

    pub fn issue(&self, now: SystemTime) -> TurnCredentials {
        let expiry = (now + self.ttl).duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let random: String = rand::random::<[u8; 16]>().iter().map(|byte| format!("{byte:02x}")).collect();
        let username = format!("{expiry}:{random}");
        let credential = credential_for(&self.secret, &username);
        TurnCredentials { urls: self.urls.clone(), username, credential }
    }
}

/// coturn's REST password for `username`.
pub fn credential_for(secret: &[u8], username: &str) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(username.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn issuer() -> TurnIssuer {
        TurnIssuer::new(b"shared-secret".to_vec(), vec!["turn:turn.example:3478".to_owned()], Duration::from_secs(600))
    }

    // Vector computed with openssl, independently of this code:
    // printf %s "1700000600:4f1c" | openssl dgst -sha1 -hmac "shared-secret" -binary | base64
    #[test]
    fn signs_usernames_the_way_coturn_checks_them() {
        assert_eq!(credential_for(b"shared-secret", "1700000600:4f1c"), "alhaPdDl0BJWg8ikitukW1mb9t0=");
    }

    #[test]
    fn credentials_expire_after_the_configured_time() {
        let issued = issuer().issue(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let (expiry, _) = issued.username.split_once(':').expect("expiry:random");
        assert_eq!(expiry, "1700000600");
        assert_eq!(issued.credential, credential_for(b"shared-secret", &issued.username));
    }

    #[test]
    fn every_session_gets_a_different_random_user() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let (first, second) = (issuer().issue(now), issuer().issue(now));
        assert_ne!(first.username, second.username);
        let (_, random) = first.username.split_once(':').expect("expiry:random");
        assert_eq!(random.len(), 32, "128 random bits, hex encoded");
    }

    #[test]
    fn credentials_point_at_the_configured_relays() {
        let issued = issuer().issue(UNIX_EPOCH);
        assert_eq!(issued.urls, ["turn:turn.example:3478"]);
    }
}
