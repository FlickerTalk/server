//! Signed requests (Plan §7, §106). Every request to the router carries the device id, the time,
//! a random nonce and an Ed25519 signature, made with the device's identity key, over:
//!
//! ```text
//! FT1\n{METHOD}\n{PATH}\n{time in ms}\n{nonce}\n{hex BLAKE3 of the body}
//! ```
//!
//! The client builds exactly the same text (ft-push); both sides pin it with test vectors.
//! Replays are refused: a request is only valid for a few minutes and its nonce only once.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
pub use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// How far the request time may be from the router's clock.
pub const WINDOW_MS: i64 = 5 * 60 * 1000;

pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub time_ms: i64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

impl SignedRequest<'_> {
    pub fn canonical(&self) -> Vec<u8> {
        format!(
            "FT1\n{}\n{}\n{}\n{}\n{}",
            self.method,
            self.path,
            self.time_ms,
            self.nonce,
            blake3::hash(self.body).to_hex()
        )
        .into_bytes()
    }
}

/// `ft_` + base58(BLAKE3(public key)), as the client derives it (ft-identity).
pub fn device_id(public_key: &[u8; 32]) -> String {
    format!("ft_{}", bs58::encode(blake3::hash(public_key).as_bytes()).into_string())
}

pub fn decode_base64(text: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| anyhow!("invalid base64"))
}

pub fn verify(public_key: &[u8; 32], request: &SignedRequest<'_>, signature: &str) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| anyhow!("invalid public key"))?;
    let bytes: [u8; 64] = decode_base64(signature)?.try_into().map_err(|_| anyhow!("invalid signature"))?;
    key.verify_strict(&request.canonical(), &Signature::from_bytes(&bytes)).map_err(|_| anyhow!("invalid signature"))
}

/// Remembers the nonces seen in the last minutes, per device, to refuse replays.
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<(String, String), i64>>,
}

impl ReplayGuard {
    pub fn admit(&self, device: &str, nonce: &str, time_ms: i64, now_ms: i64) -> Result<()> {
        if (time_ms - now_ms).abs() > WINDOW_MS {
            bail!("the request time is too far from now");
        }
        let mut seen = self.seen.lock().expect("replay guard poisoned");
        seen.retain(|_, expiry| *expiry > now_ms);
        let key = (device.to_owned(), nonce.to_owned());
        if seen.contains_key(&key) {
            bail!("replayed request");
        }
        seen.insert(key, time_ms + WINDOW_MS);
        Ok(())
    }

    pub fn remembered(&self) -> usize {
        self.seen.lock().expect("replay guard poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn request() -> SignedRequest<'static> {
        SignedRequest { method: "POST", path: "/v1/mailbox/ft_x", time_ms: 1_700_000_000_000, nonce: "n1", body: b"blob" }
    }

    // Pinned on both sides: the app (ft-push) asserts the very same text.
    #[test]
    fn the_signed_text_is_pinned() {
        let expected = format!(
            "FT1\nPOST\n/v1/mailbox/ft_x\n1700000000000\nn1\n{}",
            blake3::hash(b"blob").to_hex()
        );
        assert_eq!(request().canonical(), expected.as_bytes());
    }

    // Pinned on both sides: ft_ + base58(BLAKE3(public key)).
    #[test]
    fn device_ids_derive_from_the_public_key() {
        let public = key().verifying_key().to_bytes();
        let expected = format!("ft_{}", bs58::encode(blake3::hash(&public).as_bytes()).into_string());
        assert_eq!(device_id(&public), expected);
    }

    #[test]
    fn a_valid_signature_is_accepted() {
        let signature = key().sign(&request().canonical());
        let signature = STANDARD_NO_PAD.encode(signature.to_bytes());
        assert!(verify(&key().verifying_key().to_bytes(), &request(), &signature).is_ok());
    }

    #[test]
    fn a_signature_over_other_bytes_is_refused() {
        let other = SignedRequest { body: b"another blob", ..request() };
        let signature = STANDARD_NO_PAD.encode(key().sign(&other.canonical()).to_bytes());
        assert!(verify(&key().verifying_key().to_bytes(), &request(), &signature).is_err());
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let mallory = SigningKey::from_bytes(&[7; 32]);
        let signature = STANDARD_NO_PAD.encode(mallory.sign(&request().canonical()).to_bytes());
        assert!(verify(&key().verifying_key().to_bytes(), &request(), &signature).is_err());
    }

    #[test]
    fn requests_are_only_valid_for_a_few_minutes() {
        let guard = ReplayGuard::default();
        let now = 1_700_000_000_000;
        assert!(guard.admit("ft_a", "n1", now - 60_000, now).is_ok());
        assert!(guard.admit("ft_a", "n2", now - 10 * 60_000, now).is_err(), "too old");
        assert!(guard.admit("ft_a", "n3", now + 10 * 60_000, now).is_err(), "from the future");
    }

    #[test]
    fn a_nonce_is_only_accepted_once_per_device() {
        let guard = ReplayGuard::default();
        let now = 1_700_000_000_000;
        assert!(guard.admit("ft_a", "n1", now, now).is_ok());
        assert!(guard.admit("ft_a", "n1", now, now).is_err(), "replayed");
        assert!(guard.admit("ft_b", "n1", now, now).is_ok(), "other device");
    }

    #[test]
    fn old_nonces_are_forgotten() {
        let guard = ReplayGuard::default();
        let now = 1_700_000_000_000;
        guard.admit("ft_a", "n1", now, now).expect("admitted");
        guard.admit("ft_a", "n2", now + 20 * 60_000, now + 20 * 60_000).expect("admitted later");
        assert_eq!(guard.remembered(), 1, "the expired nonce was dropped");
    }
}
