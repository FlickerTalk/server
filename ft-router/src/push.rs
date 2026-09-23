//! Push wake-ups (Plan §8–12, §106 M4): the router wakes a device that is not connected when a
//! signal or mail arrives for it, through FCM. The push carries nothing: no sender, no content,
//! only "wake up" (§12). The device then connects and fetches what waits for it.
//!
//! - `PushVault`: push tokens are stored encrypted (ChaCha20-Poly1305) with a master key that
//!   lives outside the database (a Swarm secret), so a copy of the database reveals no tokens.
//! - `Fcm`: FCM HTTP v1, authorised with a service account that may only send messages.
//! - `WakeLimiter`: at most one wake-up per device every few seconds.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};

/// The only provider for now; APNs comes with the iOS developer account.
pub const FCM: &str = "fcm";
/// The longest push token accepted.
pub const MAX_TOKEN: usize = 4096;
/// A device is woken at most this often.
pub const WAKE_EVERY: Duration = Duration::from_secs(10);

/// Encrypts push tokens for the database.
pub struct PushVault {
    cipher: ChaCha20Poly1305,
}

impl PushVault {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { cipher: ChaCha20Poly1305::new(key.into()) }
    }

    /// Nonce and ciphertext, together.
    pub fn seal(&self, token: &str) -> Vec<u8> {
        let nonce: [u8; 12] = rand::random();
        let mut sealed = nonce.to_vec();
        sealed.extend(self.cipher.encrypt(Nonce::from_slice(&nonce), token.as_bytes()).expect("encrypting in memory cannot fail"));
        sealed
    }

    pub fn open(&self, sealed: &[u8]) -> Result<String> {
        if sealed.len() < 12 {
            return Err(anyhow!("a sealed token is too short"));
        }
        let (nonce, ciphertext) = sealed.split_at(12);
        let token = self.cipher.decrypt(Nonce::from_slice(nonce), ciphertext).map_err(|_| anyhow!("a sealed token does not open"))?;
        String::from_utf8(token).context("a push token is not text")
    }
}

/// What came of a wake-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    Sent,
    /// The token is no longer valid (the app was removed): forget it.
    Unregistered,
    Failed,
}

#[async_trait]
pub trait Waker: Send + Sync {
    /// Wakes the device, saying which of its capabilities was used (0–7, app#9) and nothing else.
    async fn wake(&self, token: &str, slot: u8) -> Wake;
}

/// Lets a device be woken at most once every `every`.
pub struct WakeLimiter {
    every: Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl WakeLimiter {
    pub fn new(every: Duration) -> Self {
        Self { every, last: Mutex::default() }
    }

    /// Whether the device may be woken now; if so, the time is taken.
    pub fn allow(&self, device: &str) -> bool {
        let mut last = self.last.lock().expect("limiter poisoned");
        let now = Instant::now();
        last.retain(|_, at| now.duration_since(*at) < self.every);
        if last.contains_key(device) {
            return false;
        }
        last.insert(device.to_owned(), now);
        true
    }
}

/// Push, when configured: the vault for tokens, who wakes devices and how often.
pub struct Push {
    pub vault: PushVault,
    pub waker: std::sync::Arc<dyn Waker>,
    pub limiter: WakeLimiter,
}

/// The parts of a Google service account key the router uses.
#[derive(Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    pub project_id: String,
}

/// FCM HTTP v1.
pub struct Fcm {
    account: ServiceAccount,
    key: jsonwebtoken::EncodingKey,
    /// Where messages are sent (FCM's in production, a fake in tests).
    endpoint: String,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

impl Fcm {
    pub fn new(account: ServiceAccount) -> Result<Self> {
        Self::with_endpoint(account, "https://fcm.googleapis.com")
    }

    pub fn with_endpoint(account: ServiceAccount, endpoint: &str) -> Result<Self> {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(account.private_key.as_bytes()).context("the service account key is not valid")?;
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("no TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::Client::builder().use_preconfigured_tls(tls).timeout(Duration::from_secs(10)).build()?;
        Ok(Self { account, key, endpoint: endpoint.trim_end_matches('/').to_owned(), http, token: tokio::sync::Mutex::default() })
    }

    /// An OAuth access token, reused until shortly before it expires.
    async fn access_token(&self) -> Result<String> {
        let mut cached = self.token.lock().await;
        if let Some((token, until)) = cached.as_ref() {
            if Instant::now() < *until {
                return Ok(token.clone());
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let claims = Claims { iss: &self.account.client_email, scope: SCOPE, aud: &self.account.token_uri, iat: now, exp: now + 3600 };
        let assertion = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256), &claims, &self.key)?;
        #[derive(Deserialize)]
        struct Granted {
            access_token: String,
            expires_in: u64,
        }
        let granted: Granted = self
            .http
            .post(&self.account.token_uri)
            .form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = Instant::now() + Duration::from_secs(granted.expires_in.saturating_sub(60));
        *cached = Some((granted.access_token.clone(), until));
        Ok(granted.access_token)
    }
}

#[async_trait]
impl Waker for Fcm {
    async fn wake(&self, token: &str, slot: u8) -> Wake {
        let Ok(access) = self.access_token().await else { return Wake::Failed };
        // Data only, high priority, short-lived: the app wakes and fetches; nothing to read here.
        let message = serde_json::json!({
            "message": {
                "token": token,
                // Which capability was used: the phone stays quiet for a closed hidden session.
                "data": { "t": "wake", "s": slot.to_string() },
                "android": { "priority": "high", "ttl": "60s" }
            }
        });
        let url = format!("{}/v1/projects/{}/messages:send", self.endpoint, self.account.project_id);
        match self.http.post(url).bearer_auth(access).json(&message).send().await {
            Ok(response) if response.status().is_success() => Wake::Sent,
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::NOT_FOUND || body.contains("UNREGISTERED") {
                    Wake::Unregistered
                } else {
                    Wake::Failed
                }
            }
            Err(_) => Wake::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Form, Json, Router};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    #[test]
    fn push_tokens_are_stored_encrypted() {
        let vault = PushVault::new(&[7; 32]);
        let sealed = vault.seal("fcm-token-123");
        assert!(!sealed.windows(5).any(|window| window == b"fcm-t"), "no token in the clear");
        assert_ne!(vault.seal("fcm-token-123"), sealed, "a fresh nonce each time");
        assert_eq!(vault.open(&sealed).unwrap(), "fcm-token-123");
        assert!(PushVault::new(&[8; 32]).open(&sealed).is_err(), "another key cannot open it");
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vault.open(&tampered).is_err());
    }

    #[test]
    fn a_device_is_woken_at_most_once_in_a_while() {
        let limiter = WakeLimiter::new(Duration::from_millis(50));
        assert!(limiter.allow("ft_a"));
        assert!(!limiter.allow("ft_a"));
        assert!(limiter.allow("ft_b"), "each device on its own");
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.allow("ft_a"));
    }

    /// What the fake Google saw.
    #[derive(Default)]
    struct Seen {
        assertions: std::sync::Mutex<Vec<String>>,
        messages: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    }

    struct Google {
        seen: Arc<Seen>,
        public_pem: String,
    }

    async fn token(State(google): State<Arc<Google>>, Form(form): Form<HashMap<String, String>>) -> Json<serde_json::Value> {
        google.seen.assertions.lock().unwrap().push(form["assertion"].clone());
        assert_eq!(form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
        Json(serde_json::json!({ "access_token": "access-1", "expires_in": 3600, "token_type": "Bearer" }))
    }

    async fn send(State(google): State<Arc<Google>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> (StatusCode, String) {
        let bearer = headers["authorization"].to_str().unwrap().to_owned();
        let unregistered = body["message"]["token"] == "gone";
        google.seen.messages.lock().unwrap().push((bearer, body));
        if unregistered {
            (StatusCode::NOT_FOUND, r#"{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}"#.to_owned())
        } else {
            (StatusCode::OK, r#"{"name":"projects/p/messages/1"}"#.to_owned())
        }
    }

    async fn fake_google() -> (String, Arc<Google>, String) {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("a test key");
        let private_pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = key.to_public_key().to_public_key_pem(LineEnding::LF).unwrap();
        let google = Arc::new(Google { seen: Arc::default(), public_pem });
        let app = Router::new()
            .route("/token", post(token))
            .route("/v1/projects/{project}/messages:send", post(send))
            .with_state(google.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, google, private_pem)
    }

    fn account(base: &str, private_key: String) -> ServiceAccount {
        ServiceAccount {
            client_email: "ft-router-fcm@example.iam.gserviceaccount.com".to_owned(),
            private_key,
            token_uri: format!("{base}/token"),
            project_id: "flickertalk-test".to_owned(),
        }
    }

    // FCM HTTP v1: a signed service-account assertion buys an access token, reused while valid;
    // the message only says "wake" and which capability was used.
    #[tokio::test]
    async fn fcm_wakes_with_an_empty_message() {
        let (base, google, private_pem) = fake_google().await;
        let fcm = Fcm::with_endpoint(account(&base, private_pem), &base).unwrap();

        assert_eq!(fcm.wake("device-token", 0).await, Wake::Sent);
        assert_eq!(fcm.wake("device-token", 0).await, Wake::Sent);

        let assertions = google.seen.assertions.lock().unwrap().clone();
        assert_eq!(assertions.len(), 1, "the access token is reused");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[format!("{base}/token")]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &assertions[0],
            &jsonwebtoken::DecodingKey::from_rsa_pem(google.public_pem.as_bytes()).unwrap(),
            &validation,
        )
        .expect("signed with the service account key");
        assert_eq!(decoded.claims["scope"], SCOPE);

        let messages = google.seen.messages.lock().unwrap().clone();
        assert_eq!(messages[0].0, "Bearer access-1");
        assert_eq!(messages[0].1["message"]["token"], "device-token");
        // Besides "wake", only which of the eight capabilities was used (app#9): no sender, no content.
        assert_eq!(messages[0].1["message"]["data"], serde_json::json!({ "t": "wake", "s": "0" }));
        assert!(messages[0].1["message"].get("notification").is_none(), "nothing to show, nothing to read");
    }

    #[tokio::test]
    async fn fcm_tells_when_a_token_is_gone() {
        let (base, _, private_pem) = fake_google().await;
        let fcm = Fcm::with_endpoint(account(&base, private_pem), &base).unwrap();
        assert_eq!(fcm.wake("gone", 0).await, Wake::Unregistered);
    }
}
