//! A push carries only its kind and the slot used, never the sender or any content.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};

pub const FCM: &str = "fcm";
pub const APNS: &str = "apns";
pub const MAX_TOKEN: usize = 4096;
pub const WAKE_EVERY: Duration = Duration::from_secs(10);

pub struct PushVault {
    cipher: ChaCha20Poly1305,
}

impl PushVault {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { cipher: ChaCha20Poly1305::new(key.into()) }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    Sent,
    Unregistered,
    Failed,
}

#[async_trait]
pub trait Waker: Send + Sync {
    async fn wake(&self, token: &str, slot: u8) -> Wake;

    async fn ring(&self, token: &str, slot: u8) -> Wake {
        self.wake(token, slot).await
    }

    fn accepts(&self, token: &str) -> bool {
        !token.is_empty()
    }
}

pub fn silent(silent_slots: u8, slot: u8) -> bool {
    slot != 0 && 1u8.checked_shl(u32::from(slot)).is_some_and(|bit| silent_slots & bit != 0)
}

pub struct WakeLimiter {
    every: Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl WakeLimiter {
    pub fn new(every: Duration) -> Self {
        Self { every, last: Mutex::default() }
    }

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

pub const RING_FOR: Duration = Duration::from_secs(45);
pub const RING_EVERY: Duration = Duration::from_secs(10);

struct Ring {
    at: Instant,
    taken: bool,
}

/// The router can't tell a caller's retry from a new call, so after a ring the next one waits
/// until the phone has connected and `every` has passed, or until `ring_for` runs out.
pub struct RingLimiter {
    every: Duration,
    ring_for: Duration,
    last: Mutex<HashMap<(String, u8), Ring>>,
}

impl RingLimiter {
    pub fn new(every: Duration, ring_for: Duration) -> Self {
        Self { every, ring_for, last: Mutex::default() }
    }

    pub fn allow(&self, device: &str, slot: u8) -> bool {
        let mut last = self.last.lock().expect("limiter poisoned");
        let now = Instant::now();
        last.retain(|_, ring| !self.done(ring, now));
        let key = (device.to_owned(), slot);
        if last.contains_key(&key) {
            return false;
        }
        last.insert(key, Ring { at: now, taken: false });
        true
    }

    pub fn picked_up(&self, device: &str) {
        let mut last = self.last.lock().expect("limiter poisoned");
        for ((rung, _), ring) in last.iter_mut() {
            if rung == device {
                ring.taken = true;
            }
        }
    }

    fn done(&self, ring: &Ring, now: Instant) -> bool {
        let since = now.duration_since(ring.at);
        since >= self.ring_for || (ring.taken && since >= self.every)
    }
}

pub struct Push {
    pub vault: PushVault,
    pub wakers: HashMap<String, std::sync::Arc<dyn Waker>>,
    pub limiter: WakeLimiter,
    pub ring_limiter: RingLimiter,
}

impl Push {
    pub fn waker(&self, provider: &str) -> Option<&std::sync::Arc<dyn Waker>> {
        self.wakers.get(provider)
    }
}

#[derive(Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    pub project_id: String,
}

pub struct Fcm {
    account: ServiceAccount,
    key: jsonwebtoken::EncodingKey,
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
        self.send(token, "wake", slot, "60s").await
    }

    async fn ring(&self, token: &str, slot: u8) -> Wake {
        self.send(token, "call", slot, &format!("{}s", RING_FOR.as_secs())).await
    }
}

impl Fcm {
    async fn send(&self, token: &str, kind: &str, slot: u8, ttl: &str) -> Wake {
        let Ok(access) = self.access_token().await else { return Wake::Failed };
        let message = serde_json::json!({
            "message": {
                "token": token,
                "data": { "t": kind, "s": slot.to_string() },
                "android": { "priority": "high", "ttl": ttl }
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

/// Xcode builds register with the sandbox, App Store and TestFlight builds with production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsGateway {
    Production,
    Sandbox,
}

/// The app sends it as gateway:topic:token[:voip], tokens in hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApnsTarget<'a> {
    pub gateway: ApnsGateway,
    pub topic: &'a str,
    pub token: &'a str,
    pub voip: Option<&'a str>,
}

fn apns_hex(token: &str) -> bool {
    token.len().is_multiple_of(2) && (64..=200).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn apns_target<'a, S: AsRef<str>>(target: &'a str, topics: &[S]) -> Option<ApnsTarget<'a>> {
    let mut parts = target.split(':');
    let gateway = match parts.next()? {
        "production" => ApnsGateway::Production,
        "sandbox" => ApnsGateway::Sandbox,
        _ => return None,
    };
    let topic = parts.next()?;
    let token = parts.next()?;
    let voip = parts.next();
    if parts.next().is_some() || !apns_hex(token) || voip.is_some_and(|voip| !apns_hex(voip)) {
        return None;
    }
    topics.iter().any(|allowed| allowed.as_ref() == topic).then_some(ApnsTarget { gateway, topic, token, voip })
}

#[derive(Serialize)]
struct ApnsClaims<'a> {
    iss: &'a str,
    iat: u64,
}

pub struct Apns {
    team: String,
    key_id: String,
    key: jsonwebtoken::EncodingKey,
    topics: Vec<String>,
    production: String,
    sandbox: String,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

/// Apple wants the signed token renewed between 20 and 60 minutes.
const APNS_TOKEN_FOR: Duration = Duration::from_secs(50 * 60);
const APNS_KEEP_FOR: u64 = 24 * 60 * 60;

impl Apns {
    pub fn new(team: &str, key_id: &str, p8: &[u8], topics: &[&str]) -> Result<Self> {
        Self::with_endpoints(team, key_id, p8, topics, "https://api.push.apple.com", "https://api.sandbox.push.apple.com")
    }

    pub fn with_endpoints(team: &str, key_id: &str, p8: &[u8], topics: &[&str], production: &str, sandbox: &str) -> Result<Self> {
        let key = jsonwebtoken::EncodingKey::from_ec_pem(p8).context("the APNs key is not a valid .p8")?;
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("no TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Apple only speaks HTTP/2.
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let http = reqwest::Client::builder().use_preconfigured_tls(tls).http2_prior_knowledge().timeout(Duration::from_secs(10)).build()?;
        Ok(Self {
            team: team.to_owned(),
            key_id: key_id.to_owned(),
            key,
            topics: topics.iter().map(|topic| (*topic).to_owned()).collect(),
            production: production.trim_end_matches('/').to_owned(),
            sandbox: sandbox.trim_end_matches('/').to_owned(),
            http,
            token: tokio::sync::Mutex::default(),
        })
    }

    async fn bearer(&self) -> Result<String> {
        let mut cached = self.token.lock().await;
        if let Some((token, until)) = cached.as_ref() {
            if Instant::now() < *until {
                return Ok(token.clone());
            }
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let token = jsonwebtoken::encode(&header, &ApnsClaims { iss: &self.team, iat }, &self.key)?;
        *cached = Some((token.clone(), Instant::now() + APNS_TOKEN_FOR));
        Ok(token)
    }
}

struct ApnsPush<'a> {
    gateway: ApnsGateway,
    token: &'a str,
    topic: String,
    kind: &'static str,
    expiration: u64,
    collapse: Option<&'static str>,
    body: serde_json::Value,
}

impl Apns {
    async fn send(&self, push: ApnsPush<'_>) -> Wake {
        let Ok(bearer) = self.bearer().await else { return Wake::Failed };
        let base = match push.gateway {
            ApnsGateway::Production => &self.production,
            ApnsGateway::Sandbox => &self.sandbox,
        };
        let mut request = self
            .http
            .post(format!("{base}/3/device/{}", push.token))
            .header("authorization", format!("bearer {bearer}"))
            .header("apns-topic", push.topic)
            .header("apns-push-type", push.kind)
            .header("apns-priority", "10")
            .header("apns-expiration", push.expiration.to_string());
        if let Some(collapse) = push.collapse {
            request = request.header("apns-collapse-id", collapse);
        }
        let sent = request.json(&push.body).send().await;
        match sent {
            Ok(response) if response.status().is_success() => Wake::Sent,
            Ok(response) => {
                let status = response.status();
                let reason = response.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::GONE || reason.contains("BadDeviceToken") || reason.contains("DeviceTokenNotForTopic") {
                    Wake::Unregistered
                } else {
                    if reason.contains("ExpiredProviderToken") {
                        *self.token.lock().await = None;
                    }
                    Wake::Failed
                }
            }
            Err(_) => Wake::Failed,
        }
    }
}

#[async_trait]
impl Waker for Apns {
    async fn wake(&self, target: &str, slot: u8) -> Wake {
        let Some(target) = apns_target(target, &self.topics) else { return Wake::Unregistered };
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH).map(|now| now.as_secs() + APNS_KEEP_FOR).unwrap_or(0);
        // The phone translates the loc-key, so there's no text and no language on our side.
        // mutable-content is for the notification service extension, once the app has one.
        let body = serde_json::json!({
            "aps": { "alert": { "loc-key": "FT_PUSH_WAKE" }, "sound": "default", "mutable-content": 1 },
            "t": "wake",
            "s": slot,
        });
        let push = ApnsPush { gateway: target.gateway, token: target.token, topic: target.topic.to_owned(), kind: "alert", expiration, collapse: Some("ft-wake"), body };
        self.send(push).await
    }

    /// Apple wants every VoIP push to ring through CallKit, so PushKit is only used for calls.
    async fn ring(&self, target: &str, slot: u8) -> Wake {
        let Some(target) = apns_target(target, &self.topics) else { return Wake::Unregistered };
        let push = match target.voip {
            Some(voip) => ApnsPush {
                gateway: target.gateway,
                token: voip,
                topic: format!("{}.voip", target.topic),
                kind: "voip",
                expiration: 0,
                collapse: None,
                body: serde_json::json!({ "t": "call", "s": slot }),
            },
            None => ApnsPush {
                gateway: target.gateway,
                token: target.token,
                topic: target.topic.to_owned(),
                kind: "alert",
                expiration: 0,
                collapse: None,
                body: serde_json::json!({
                    "aps": { "alert": { "loc-key": "FT_INCOMING_CALL" }, "sound": "default" },
                    "t": "call",
                    "s": slot,
                }),
            },
        };
        self.send(push).await
    }

    fn accepts(&self, target: &str) -> bool {
        apns_target(target, &self.topics).is_some()
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
    fn a_slot_is_silent_only_when_its_bit_is_set_and_it_is_not_the_main_list() {
        assert!(silent(0b0000_1000, 3));
        assert!(!silent(0b0000_1000, 2), "only its own bit");
        assert!(!silent(0b1111_0111, 3));
        assert!(!silent(0, 7), "nothing is silent by default");
        assert!(silent(0b1000_0000, 7));
        assert!(!silent(0b1111_1111, 0), "the main list always rings");
        assert!(!silent(0b1111_1111, 8), "there are only eight slots");
        assert!(!silent(0b1111_1111, 200));
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

    #[test]
    fn a_ring_waits_for_the_phone_to_take_it_or_for_it_to_run_out() {
        let rings = RingLimiter::new(Duration::from_millis(40), Duration::from_millis(400));
        assert!(rings.allow("ft_a", 0));
        assert!(!rings.allow("ft_a", 0), "a retry of the same call");
        std::thread::sleep(Duration::from_millis(60));
        assert!(!rings.allow("ft_a", 0), "past the floor, but the phone never took the ring");
        rings.picked_up("ft_a");
        assert!(rings.allow("ft_a", 0), "it did now: the next call rings");
        assert!(!rings.allow("ft_a", 0));
        std::thread::sleep(Duration::from_millis(420));
        assert!(rings.allow("ft_a", 0), "a ring that ran out holds nothing back");
    }

    #[test]
    fn a_phone_that_took_its_ring_is_rung_again_only_after_the_floor() {
        let rings = RingLimiter::new(Duration::from_millis(80), Duration::from_secs(5));
        assert!(rings.allow("ft_a", 0));
        rings.picked_up("ft_a");
        assert!(!rings.allow("ft_a", 0), "a flood that the phone keeps answering");
        std::thread::sleep(Duration::from_millis(100));
        assert!(rings.allow("ft_a", 0));
    }

    #[test]
    fn each_device_and_slot_rings_on_its_own() {
        let rings = RingLimiter::new(Duration::ZERO, Duration::from_secs(5));
        assert!(rings.allow("ft_a", 0));
        assert!(rings.allow("ft_a", 5), "another slot");
        assert!(rings.allow("ft_b", 0), "another device");
        rings.picked_up("ft_b");
        assert!(!rings.allow("ft_a", 0), "ft_b connecting takes nothing of ft_a's");
        assert!(!rings.allow("ft_a", 5));
        assert!(rings.allow("ft_b", 0));
        rings.picked_up("ft_a");
        assert!(rings.allow("ft_a", 0) && rings.allow("ft_a", 5), "connecting takes the rings of every slot");
    }

    #[test]
    fn a_ring_holds_for_a_whole_call_and_the_floor_matches_the_wake_pace() {
        assert_eq!(RING_FOR, Duration::from_secs(45));
        assert_eq!(RING_EVERY, WAKE_EVERY);
    }

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
        assert_eq!(messages[0].1["message"]["data"], serde_json::json!({ "t": "wake", "s": "0" }));
        assert!(messages[0].1["message"].get("notification").is_none(), "nothing to show, nothing to read");
    }

    #[tokio::test]
    async fn fcm_rings_a_call_as_a_call() {
        let (base, google, private_pem) = fake_google().await;
        let fcm = Fcm::with_endpoint(account(&base, private_pem), &base).unwrap();

        assert_eq!(fcm.ring("device-token", 2).await, Wake::Sent);

        let messages = google.seen.messages.lock().unwrap().clone();
        let message = &messages[0].1["message"];
        assert_eq!(message["data"], serde_json::json!({ "t": "call", "s": "2" }));
        assert_eq!(message["android"], serde_json::json!({ "priority": "high", "ttl": "45s" }));
        assert!(message.get("notification").is_none(), "still nothing to read: who calls comes over P2P");
    }

    #[tokio::test]
    async fn fcm_tells_when_a_token_is_gone() {
        let (base, _, private_pem) = fake_google().await;
        let fcm = Fcm::with_endpoint(account(&base, private_pem), &base).unwrap();
        assert_eq!(fcm.wake("gone", 0).await, Wake::Unregistered);
    }

    type Request = (String, HashMap<String, String>, serde_json::Value);

    #[derive(Default)]
    struct Pushed {
        requests: std::sync::Mutex<Vec<Request>>,
    }

    async fn apple(
        State(pushed): State<Arc<Pushed>>,
        axum::extract::Path(token): axum::extract::Path<String>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, String) {
        let keep = ["authorization", "apns-topic", "apns-push-type", "apns-priority", "apns-expiration", "apns-collapse-id"];
        let seen = keep.iter().filter_map(|name| Some((name.to_string(), headers.get(*name)?.to_str().ok()?.to_owned()))).collect();
        pushed.requests.lock().unwrap().push((uri.path().to_owned(), seen, body));
        match token.as_str() {
            t if t.starts_with("dead") => (StatusCode::GONE, r#"{"reason":"Unregistered"}"#.to_owned()),
            t if t.starts_with("bad") => (StatusCode::BAD_REQUEST, r#"{"reason":"BadDeviceToken"}"#.to_owned()),
            t if t.starts_with("fa11") => (StatusCode::INTERNAL_SERVER_ERROR, r#"{"reason":"InternalServerError"}"#.to_owned()),
            _ => (StatusCode::OK, String::new()),
        }
    }

    async fn fake_apple() -> (String, String, Arc<Pushed>, Arc<Pushed>, String, String) {
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let private_pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = key.public_key().to_public_key_pem(LineEnding::LF).unwrap();
        let mut bases = vec![];
        let mut seen = vec![];
        for _ in 0..2 {
            let pushed = Arc::new(Pushed::default());
            let app = Router::new().route("/3/device/{token}", post(apple)).with_state(pushed.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            bases.push(format!("http://{}", listener.local_addr().unwrap()));
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            seen.push(pushed);
        }
        (bases[0].clone(), bases[1].clone(), seen[0].clone(), seen[1].clone(), private_pem, public_pem)
    }

    const TOPICS: &[&str] = &["com.flickertalk.app", "com.flickertalk.app.dev"];
    const DEVICE: &str = "9f3c1a0b2e4d6f8a9f3c1a0b2e4d6f8a9f3c1a0b2e4d6f8a9f3c1a0b2e4d6f8a";

    #[tokio::test]
    async fn apns_wakes_with_a_notification_that_says_nothing() {
        let (production, sandbox, at_production, at_sandbox, private_pem, public_pem) = fake_apple().await;
        let apns = Apns::with_endpoints("TEAMID1234", "KEYID56789", private_pem.as_bytes(), TOPICS, &production, &sandbox).unwrap();

        assert_eq!(apns.wake(&format!("production:com.flickertalk.app:{DEVICE}"), 3).await, Wake::Sent);
        assert_eq!(apns.wake(&format!("sandbox:com.flickertalk.app.dev:{DEVICE}"), 0).await, Wake::Sent);

        let sent = at_production.requests.lock().unwrap().clone();
        let (path, headers, body) = &sent[0];
        assert_eq!(path, &format!("/3/device/{DEVICE}"));
        assert_eq!(headers["apns-topic"], "com.flickertalk.app");
        assert_eq!(headers["apns-push-type"], "alert");
        assert_eq!(headers["apns-priority"], "10");
        assert_eq!(headers["apns-collapse-id"], "ft-wake", "one notification waits, not a pile");
        let expiration: u64 = headers["apns-expiration"].parse().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(expiration > now + 3600 && expiration <= now + 86_400 + 5, "kept a day if the phone is off");
        assert_eq!(body["aps"]["alert"], serde_json::json!({ "loc-key": "FT_PUSH_WAKE" }));
        assert_eq!(body["aps"]["mutable-content"], 1);
        assert_eq!((body["t"].as_str(), body["s"].as_u64()), (Some("wake"), Some(3)));
        let text = body.to_string();
        assert_eq!(body.as_object().unwrap().len(), 3, "aps, t and s, nothing else: {text}");

        let sandboxed = at_sandbox.requests.lock().unwrap().clone();
        assert_eq!(sandboxed[0].1["apns-topic"], "com.flickertalk.app.dev");

        let bearer = headers["authorization"].strip_prefix("bearer ").expect("a bearer token");
        assert_eq!(sandboxed[0].1["authorization"], headers["authorization"], "the token is reused");
        let header = jsonwebtoken::decode_header(bearer).unwrap();
        assert_eq!((header.alg, header.kid.as_deref()), (jsonwebtoken::Algorithm::ES256, Some("KEYID56789")));
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let claims = jsonwebtoken::decode::<serde_json::Value>(bearer, &jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap(), &validation)
            .expect("signed with the .p8 key")
            .claims;
        assert_eq!(claims["iss"], "TEAMID1234");
        assert!(claims["iat"].as_u64().unwrap() >= now - 5);
    }

    #[tokio::test]
    async fn apns_tells_when_a_token_is_gone_or_bad() {
        let (production, sandbox, _, _, private_pem, _) = fake_apple().await;
        let apns = Apns::with_endpoints("TEAMID1234", "KEYID56789", private_pem.as_bytes(), TOPICS, &production, &sandbox).unwrap();
        let target = |token: &str| format!("production:com.flickertalk.app:{token}");
        assert_eq!(apns.wake(&target(&format!("dead{}", &DEVICE[4..])), 0).await, Wake::Unregistered);
        assert_eq!(apns.wake(&target(&format!("bad0{}", &DEVICE[4..])), 0).await, Wake::Unregistered);
        assert_eq!(apns.wake(&target(&format!("fa11{}", &DEVICE[4..])), 0).await, Wake::Failed);
        assert_eq!(apns.wake("not a target", 0).await, Wake::Unregistered, "a target that does not parse is forgotten");
    }

    #[test]
    fn an_apns_target_names_the_gateway_one_of_our_apps_and_a_token() {
        assert_eq!(
            apns_target(&format!("production:com.flickertalk.app:{DEVICE}"), TOPICS),
            Some(ApnsTarget { gateway: ApnsGateway::Production, topic: "com.flickertalk.app", token: DEVICE, voip: None })
        );
        assert_eq!(apns_target(&format!("sandbox:com.flickertalk.app.dev:{DEVICE}"), TOPICS).map(|t| t.gateway), Some(ApnsGateway::Sandbox));
        let voip = "cd".repeat(32);
        assert_eq!(apns_target(&format!("production:com.flickertalk.app:{DEVICE}:{voip}"), TOPICS).and_then(|t| t.voip), Some(voip.as_str()));
        assert!(apns_target(&format!("production:com.flickertalk.app:{DEVICE}:nothex"), TOPICS).is_none());
        for wrong in [
            format!("staging:com.flickertalk.app:{DEVICE}"),
            format!("production:com.example.other:{DEVICE}"),
            "production:com.flickertalk.app:not-hex".to_owned(),
            "production:com.flickertalk.app:abcd".to_owned(),
            format!("production:com.flickertalk.app:{DEVICE}{}", "0".repeat(400)),
            DEVICE.to_owned(),
        ] {
            assert!(apns_target(&wrong, TOPICS).is_none(), "{wrong}");
        }
    }

    #[tokio::test]
    async fn apns_rings_a_call_through_pushkit_or_else_says_it() {
        let (production, sandbox, at_production, _, private_pem, _) = fake_apple().await;
        let apns = Apns::with_endpoints("TEAMID1234", "KEYID56789", private_pem.as_bytes(), TOPICS, &production, &sandbox).unwrap();
        let voip = "cd".repeat(32);

        assert_eq!(apns.ring(&format!("production:com.flickertalk.app:{DEVICE}:{voip}"), 2).await, Wake::Sent);
        assert_eq!(apns.ring(&format!("production:com.flickertalk.app:{DEVICE}"), 0).await, Wake::Sent);

        let sent = at_production.requests.lock().unwrap().clone();
        let (path, headers, body) = &sent[0];
        assert_eq!(path, &format!("/3/device/{voip}"), "to PushKit's token");
        assert_eq!(headers["apns-topic"], "com.flickertalk.app.voip");
        assert_eq!(headers["apns-push-type"], "voip");
        assert_eq!(headers["apns-priority"], "10");
        assert_eq!(headers["apns-expiration"], "0", "a call is now or never");
        assert_eq!(body, &serde_json::json!({ "t": "call", "s": 2 }));

        let (path, headers, body) = &sent[1];
        assert_eq!(path, &format!("/3/device/{DEVICE}"));
        assert_eq!(headers["apns-push-type"], "alert");
        assert_eq!(body["aps"]["alert"], serde_json::json!({ "loc-key": "FT_INCOMING_CALL" }));
        assert_eq!(headers["apns-expiration"], "0");
        assert_eq!((body["t"].as_str(), body["s"].as_u64()), (Some("call"), Some(0)));
    }
}
