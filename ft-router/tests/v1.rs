//! Router API v1 (Plan §7, §10, §13–19, §34, §106 M2) against a real PostgreSQL (the local test
//! database, one schema per test) and real sockets.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ft_router::auth::{device_id, SignedRequest};
use ft_router::db::Db;
use ft_router::turn::TurnIssuer;
use ft_router::push::{apns_target, PushVault, RingLimiter, Wake, WakeLimiter, Waker, APNS, FCM, RING_EVERY, RING_FOR};
use ft_router::limits::Limits;
use ft_router::{app, Config, Push};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Router {
    base: String,
    http: reqwest::Client,
    db: Arc<Db>,
}

async fn router() -> Router {
    router_with(None).await
}

async fn router_with(push: Option<Arc<Push>>) -> Router {
    router_configured(push, Limits::default()).await
}

async fn router_limited(limits: Limits) -> Router {
    router_configured(None, limits).await
}

async fn router_configured(push: Option<Arc<Push>>, limits: Limits) -> Router {
    let url = std::env::var("FT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/ft_router_test".to_owned());
    let db = Arc::new(Db::connect_isolated(&url).await.expect("test database"));
    let config = Config {
        stun: vec!["stun:turn.example:3478".to_owned()],
        turn: Some(TurnIssuer::new(b"secret".to_vec(), vec!["turn:turn.example:3478".to_owned()], Duration::from_secs(600))),
        db: Some(db.clone()),
        push,
        poc_relay: false,
        limits,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app(config)).await.expect("serves") });
    // The router's HTTP client is built without a default TLS provider (it picks ring itself).
    let _ = rustls::crypto::ring::default_provider().install_default();
    Router { base: format!("http://{address}"), http: reqwest::Client::new(), db }
}

/// Wakes nobody: records the tokens it was asked to wake. "gone" is an expired token.
#[derive(Default)]
struct FakeWaker {
    woken: std::sync::Mutex<Vec<String>>,
    slots: std::sync::Mutex<Vec<u8>>,
    /// Rung for a call rather than woken (2026-09-28).
    rung: std::sync::Mutex<Vec<String>>,
    rung_slots: std::sync::Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl Waker for FakeWaker {
    async fn wake(&self, token: &str, slot: u8) -> Wake {
        self.woken.lock().unwrap().push(token.to_owned());
        self.slots.lock().unwrap().push(slot);
        if token == "gone" {
            Wake::Unregistered
        } else {
            Wake::Sent
        }
    }
    async fn ring(&self, token: &str, slot: u8) -> Wake {
        self.rung.lock().unwrap().push(token.to_owned());
        self.rung_slots.lock().unwrap().push(slot);
        Wake::Sent
    }
}

impl FakeWaker {
    fn rung(&self) -> Vec<String> {
        self.rung.lock().unwrap().clone()
    }

    fn woken(&self) -> Vec<String> {
        self.woken.lock().unwrap().clone()
    }

    fn slots(&self) -> Vec<u8> {
        self.slots.lock().unwrap().clone()
    }

    fn rung_slots(&self) -> Vec<u8> {
        self.rung_slots.lock().unwrap().clone()
    }
}

/// FCM, fake, with the paces of production.
fn push_with(waker: Arc<FakeWaker>) -> Option<Arc<Push>> {
    push_ringing(waker, RING_EVERY, RING_FOR)
}

/// FCM, fake, waking at the pace of production and ringing at the pace given.
fn push_ringing(waker: Arc<FakeWaker>, ring_every: Duration, ring_for: Duration) -> Option<Arc<Push>> {
    let wakers = [(FCM.to_owned(), waker as Arc<dyn Waker>)].into_iter().collect();
    Some(Arc::new(Push {
        vault: PushVault::new(&[9; 32]),
        wakers,
        limiter: WakeLimiter::new(Duration::from_secs(10)),
        ring_limiter: RingLimiter::new(ring_every, ring_for),
    }))
}

/// Records what it was asked to wake, and only takes what an APNs target looks like.
#[derive(Default)]
struct FakeApns(FakeWaker);

#[async_trait::async_trait]
impl Waker for FakeApns {
    async fn wake(&self, token: &str, slot: u8) -> Wake {
        self.0.wake(token, slot).await
    }

    fn accepts(&self, token: &str) -> bool {
        apns_target(token, &["com.flickertalk.app"]).is_some()
    }
}

fn push_for_both(android: Arc<FakeWaker>, iphones: Arc<FakeApns>) -> Option<Arc<Push>> {
    let wakers = [(FCM.to_owned(), android as Arc<dyn Waker>), (APNS.to_owned(), iphones as Arc<dyn Waker>)].into_iter().collect();
    Some(Arc::new(Push {
        vault: PushVault::new(&[9; 32]),
        wakers,
        limiter: WakeLimiter::new(Duration::from_secs(10)),
        ring_limiter: RingLimiter::new(RING_EVERY, RING_FOR),
    }))
}

/// Waits a little for work the router does in the background.
async fn soon<F: Fn() -> bool>(condition: F) -> bool {
    for _ in 0..50 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

/// A test device: its identity key and route capability.
struct Device {
    key: SigningKey,
    capability: [u8; 32],
}

impl Device {
    fn new(seed: u8) -> Self {
        Self { key: SigningKey::from_bytes(&[seed; 32]), capability: [seed.wrapping_add(100); 32] }
    }

    fn id(&self) -> String {
        device_id(&self.key.verifying_key().to_bytes())
    }

    fn capability(&self) -> String {
        STANDARD_NO_PAD.encode(self.capability)
    }

    /// The signature headers for a request, as ft-push builds them.
    fn sign(&self, method: &str, path: &str, body: &[u8], nonce: &str) -> Vec<(&'static str, String)> {
        let time_ms = now_ms();
        let request = SignedRequest { method, path, time_ms, nonce, body };
        let signature = STANDARD_NO_PAD.encode(self.key.sign(&request.canonical()).to_bytes());
        vec![("ft-device", self.id()), ("ft-time", time_ms.to_string()), ("ft-nonce", nonce.to_owned()), ("ft-signature", signature)]
    }

    async fn request(&self, router: &Router, method: &str, path: &str, body: Vec<u8>) -> reqwest::Response {
        let nonce = format!("{}", uuid::Uuid::now_v7());
        let mut request = router.http.request(method.parse().unwrap(), format!("{}{path}", router.base)).body(body.clone());
        for (name, value) in self.sign(method, path, &body, &nonce) {
            request = request.header(name, value);
        }
        request.send().await.expect("the router answers")
    }

    async fn register(&self, router: &Router) -> reqwest::Response {
        let body = json!({
            "signing_key": STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes()),
            "capability_hash": STANDARD_NO_PAD.encode(blake3::hash(&self.capability).as_bytes()),
        });
        self.request(router, "POST", "/v1/device/register", serde_json::to_vec(&body).unwrap()).await
    }

    async fn connect(&self, router: &Router) -> Socket {
        let path = "/v1/connect";
        // A fresh nonce each time, as the app does: a device reconnects.
        let headers = self.sign("GET", path, b"", &uuid::Uuid::now_v7().to_string());
        let query: Vec<String> = headers.iter().map(|(name, value)| format!("{name}={}", urlencode(value))).collect();
        let url = format!("{}{path}?{}", router.base.replace("http", "ws"), query.join("&"));
        let (socket, _) = connect_async(url).await.expect("connects");
        socket
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn urlencode(value: &str) -> String {
    value.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}

async fn next_json(socket: &mut Socket) -> Value {
    loop {
        match timeout(Duration::from_secs(3), socket.next()).await.expect("a frame in time") {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(text.as_str()).expect("json"),
            Some(Ok(_)) => continue,
            other => panic!("socket closed: {other:?}"),
        }
    }
}

async fn deposit(router: &Router, to: &Device, capability: String, blob: Vec<u8>) -> reqwest::Response {
    router
        .http
        .post(format!("{}/v1/mailbox/{}", router.base, to.id()))
        .header("ft-capability", capability)
        .body(blob)
        .send()
        .await
        .expect("answers")
}

async fn signal(router: &Router, to: &Device, capability: String, bytes: Vec<u8>) -> reqwest::Response {
    router
        .http
        .post(format!("{}/v1/signal/{}", router.base, to.id()))
        .header("ft-capability", capability)
        .body(bytes)
        .send()
        .await
        .expect("answers")
}

#[tokio::test]
async fn a_device_registers_and_then_signs_its_requests() {
    let router = router().await;
    let alice = Device::new(1);
    assert_eq!(alice.register(&router).await.status(), 204);
    let turn = alice.request(&router, "GET", "/v1/turn-credentials", vec![]).await;
    assert_eq!(turn.status(), 200);
    let turn: Value = turn.json().await.unwrap();
    assert_eq!(turn["urls"], json!(["turn:turn.example:3478"]));
}

// The device id is the hash of the key: nobody can register someone else's id.
#[tokio::test]
async fn a_device_can_only_register_its_own_id() {
    let router = router().await;
    let (alice, mallory) = (Device::new(1), Device::new(2));
    let body = json!({
        "signing_key": STANDARD_NO_PAD.encode(mallory.key.verifying_key().to_bytes()),
        "capability_hash": STANDARD_NO_PAD.encode([0u8; 32]),
    });
    // Signed by Mallory, but claiming Alice's id in the header.
    let body = serde_json::to_vec(&body).unwrap();
    let mut request = router.http.post(format!("{}/v1/device/register", router.base)).body(body.clone());
    for (name, value) in mallory.sign("POST", "/v1/device/register", &body, "n") {
        request = request.header(name, if name == "ft-device" { alice.id() } else { value });
    }
    assert_eq!(request.send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn unsigned_forged_and_replayed_requests_are_refused() {
    let router = router().await;
    let alice = Device::new(1);
    alice.register(&router).await;

    let unsigned = router.http.get(format!("{}/v1/turn-credentials", router.base)).send().await.unwrap();
    assert_eq!(unsigned.status(), 401);

    let mut forged = router.http.get(format!("{}/v1/turn-credentials", router.base));
    for (name, value) in Device::new(9).sign("GET", "/v1/turn-credentials", b"", "n1") {
        forged = forged.header(name, if name == "ft-device" { alice.id() } else { value });
    }
    assert_eq!(forged.send().await.unwrap().status(), 401);

    let headers = alice.sign("GET", "/v1/turn-credentials", b"", "same-nonce");
    for expected in [200, 401] {
        let mut request = router.http.get(format!("{}/v1/turn-credentials", router.base));
        for (name, value) in &headers {
            request = request.header(*name, value);
        }
        assert_eq!(request.send().await.unwrap().status(), expected);
    }
}

// §19, §34: depositing needs the recipient's capability, not the sender's identity.
#[tokio::test]
async fn the_mailbox_takes_mail_only_with_the_recipients_capability() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;

    assert_eq!(deposit(&router, &bob, STANDARD_NO_PAD.encode([0u8; 32]), b"spam".to_vec()).await.status(), 403);
    assert_eq!(deposit(&router, &bob, bob.capability(), b"sealed one".to_vec()).await.status(), 201);
    assert_eq!(deposit(&router, &bob, bob.capability(), vec![0; 70 * 1024]).await.status(), 413);

    let listed: Value = bob.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    let blobs = listed.as_array().expect("a list");
    assert_eq!(blobs.len(), 1);
    assert_eq!(STANDARD_NO_PAD.decode(blobs[0]["blob"].as_str().unwrap()).unwrap(), b"sealed one");

    let id = blobs[0]["id"].as_str().unwrap();
    let path = format!("/v1/mailbox/{id}");
    assert_eq!(bob.request(&router, "DELETE", &path, vec![]).await.status(), 204);
    let listed: Value = bob.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    assert!(listed.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn nobody_reads_or_deletes_another_devices_mail() {
    let router = router().await;
    let (alice, bob) = (Device::new(1), Device::new(2));
    alice.register(&router).await;
    bob.register(&router).await;
    deposit(&router, &bob, bob.capability(), b"for bob".to_vec()).await;

    let seen: Value = alice.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    assert!(seen.as_array().unwrap().is_empty(), "alice only sees her own mailbox");

    let listed: Value = bob.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    let path = format!("/v1/mailbox/{}", listed[0]["id"].as_str().unwrap());
    assert_eq!(alice.request(&router, "DELETE", &path, vec![]).await.status(), 404);
}

#[tokio::test]
async fn a_connected_device_gets_a_welcome_signals_and_mail_notices() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    let mut socket = bob.connect(&router).await;

    let welcome = next_json(&mut socket).await;
    assert_eq!(welcome["kind"], "welcome");
    assert_eq!(welcome["stun"], json!(["stun:turn.example:3478"]));
    assert!(welcome["turn"]["username"].is_string());

    assert_eq!(signal(&router, &bob, bob.capability(), b"offer".to_vec()).await.status(), 202);
    let incoming = next_json(&mut socket).await;
    assert_eq!(incoming["kind"], "signal");
    assert_eq!(STANDARD_NO_PAD.decode(incoming["signal"].as_str().unwrap()).unwrap(), b"offer");

    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
}

#[tokio::test]
async fn signals_need_the_capability_and_an_online_recipient() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    assert_eq!(signal(&router, &bob, bob.capability(), b"offer".to_vec()).await.status(), 404, "bob is not connected");

    let _socket = bob.connect(&router).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(signal(&router, &bob, STANDARD_NO_PAD.encode([0u8; 32]), b"offer".to_vec()).await.status(), 403);
}

#[tokio::test]
async fn connecting_needs_a_valid_signature() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    let url = format!("{}/v1/connect?ft-device={}&ft-time=1&ft-nonce=x&ft-signature=AAAA", router.base.replace("http", "ws"), bob.id());
    assert!(connect_async(url).await.is_err());
}

#[tokio::test]
async fn a_device_can_forget_itself() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert_eq!(bob.request(&router, "DELETE", "/v1/device", vec![]).await.status(), 204);
    assert_eq!(deposit(&router, &bob, bob.capability(), b"again".to_vec()).await.status(), 403);
}

impl Device {
    async fn set_push(&self, router: &Router, token: &str) -> reqwest::Response {
        self.set_push_with(router, "fcm", token).await
    }

    async fn set_push_with(&self, router: &Router, provider: &str, token: &str) -> reqwest::Response {
        let body = serde_json::to_vec(&json!({ "provider": provider, "token": token })).unwrap();
        self.request(router, "PUT", "/v1/device/push", body).await
    }
}

// iPhones (2026-09-28): an iPhone leaves an APNs target and is woken through APNs, an Android
// phone through FCM; a target APNs could not use is refused, and so is a provider not set up.
#[tokio::test]
async fn an_iphone_is_woken_through_apns_and_an_android_phone_through_fcm() {
    let (android, iphones) = (Arc::new(FakeWaker::default()), Arc::new(FakeApns::default()));
    let router = router_with(push_for_both(android.clone(), iphones.clone())).await;
    let (alice, bob, carol) = (Device::new(1), Device::new(2), Device::new(3));
    for device in [&alice, &bob, &carol] {
        device.register(&router).await;
    }
    let target = format!("production:com.flickertalk.app:{}", "ab".repeat(32));
    assert_eq!(bob.set_push_with(&router, "apns", "production:com.example.other:abab").await.status(), 400);
    assert_eq!(bob.set_push_with(&router, "apns", &target).await.status(), 204);
    assert_eq!(carol.set_push(&router, "carol-fcm-token").await.status(), 204);
    assert_eq!(router.db.push_of(&bob.id()).await.unwrap().expect("stored").0, "apns");

    deposit(&router, &bob, bob.capability(), b"sealed for bob".to_vec()).await;
    deposit(&router, &carol, carol.capability(), b"sealed for carol".to_vec()).await;
    assert!(soon(|| iphones.0.woken() == [target.clone()]).await, "bob's iPhone through APNs");
    assert!(soon(|| android.woken() == ["carol-fcm-token"]).await, "carol's Android through FCM");

    // Without APNs set up, an iPhone's target is refused rather than kept for nothing.
    let router = router_with(push_with(Arc::default())).await;
    let dave = Device::new(4);
    dave.register(&router).await;
    assert_eq!(dave.set_push_with(&router, "apns", &target).await.status(), 400);
}

// §8–12: a device leaves where it can be woken, encrypted with a key that is not in the database.
#[tokio::test]
async fn a_device_leaves_its_push_token_encrypted_and_takes_it_back() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker)).await;
    let bob = Device::new(2);
    assert_eq!(bob.register(&router).await.status(), 204);
    assert_eq!(bob.set_push(&router, "bob-fcm-token").await.status(), 204);

    let (provider, sealed) = router.db.push_of(&bob.id()).await.unwrap().expect("stored");
    assert_eq!(provider, "fcm");
    assert!(!sealed.windows(7).any(|window| window == b"bob-fcm"), "never in the clear");
    assert_eq!(PushVault::new(&[9; 32]).open(&sealed).unwrap(), "bob-fcm-token");

    assert_eq!(bob.request(&router, "DELETE", "/v1/device/push", vec![]).await.status(), 204);
    assert!(router.db.push_of(&bob.id()).await.unwrap().is_none());
}

#[tokio::test]
async fn push_tokens_must_be_sensible() {
    let router = router_with(push_with(Arc::default())).await;
    let bob = Device::new(2);
    bob.register(&router).await;
    let other = serde_json::to_vec(&json!({ "provider": "carrier-pigeon", "token": "x" })).unwrap();
    assert_eq!(bob.request(&router, "PUT", "/v1/device/push", other).await.status(), 400);
    assert_eq!(bob.set_push(&router, &"x".repeat(5000)).await.status(), 413);
    let stranger = Device::new(3);
    assert_eq!(stranger.set_push(&router, "t").await.status(), 401, "only registered devices");
}

// §12: a device that is not connected is woken when a signal or mail arrives, with nothing in the
// push; then it connects and fetches.
#[tokio::test]
async fn an_offline_device_is_woken_when_signalled_or_written_to() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let (alice, bob) = (Device::new(1), Device::new(2));
    alice.register(&router).await;
    bob.register(&router).await;
    bob.set_push(&router, "bob-fcm-token").await;

    assert_eq!(signal(&router, &bob, bob.capability(), b"offer".to_vec()).await.status(), 404, "still not delivered");
    assert!(soon(|| waker.woken() == ["bob-fcm-token"]).await);

    // Once in a while at most: mail right after does not wake again.
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(waker.woken().len(), 1);
}

// A call (2026-09-28): the caller says so, and an offline device is rung rather than woken, so
// an iPhone rings through CallKit. The router learns that it is a call, and nothing else.
#[tokio::test]
async fn an_offline_device_is_rung_when_the_signal_is_a_call() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let (alice, bob) = (Device::new(1), Device::new(2));
    alice.register(&router).await;
    bob.register(&router).await;
    bob.set_push(&router, "bob-token").await;

    let answer = router
        .http
        .post(format!("{}/v1/signal/{}", router.base, bob.id()))
        .header("ft-capability", bob.capability())
        .header("ft-call", "1")
        .body(b"offer".to_vec())
        .send()
        .await
        .expect("answers");
    assert_eq!(answer.status(), 404, "still not delivered");
    assert!(soon(|| waker.rung() == ["bob-token"]).await);
    assert!(waker.woken().is_empty(), "rung, not woken");
}

#[tokio::test]
async fn a_connected_device_is_not_woken() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let (alice, bob) = (Device::new(1), Device::new(2));
    alice.register(&router).await;
    bob.register(&router).await;
    bob.set_push(&router, "bob-fcm-token").await;
    let mut socket = bob.connect(&router).await;
    next_json(&mut socket).await;

    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(waker.woken().is_empty());
}

// A token FCM no longer knows (the app was removed) is forgotten.
#[tokio::test]
async fn an_expired_push_token_is_forgotten() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register(&router).await;
    bob.set_push(&router, "gone").await;
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| !waker.woken().is_empty()).await);
    for _ in 0..50 {
        if router.db.push_of(&bob.id()).await.unwrap().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the expired token is still there");
}

fn limits(per_device: u32, per_recipient: u32, per_origin: u32) -> Limits {
    Limits { per_device, per_recipient, per_origin, window: Duration::from_secs(60) }
}

// §91: each device, recipient and origin gets a fair share; beyond it, 429 until the next minute.
#[tokio::test]
async fn a_device_that_asks_too_often_is_told_to_slow_down() {
    let router = router_limited(limits(4, 1000, 1000)).await;
    let bob = Device::new(2);
    bob.register(&router).await;
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(bob.request(&router, "GET", "/v1/mailbox", vec![]).await.status().as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429], "the registration counts too");
}

#[tokio::test]
async fn a_recipient_cannot_be_flooded() {
    let router = router_limited(limits(1000, 3, 1000)).await;
    let (bob, carol) = (Device::new(2), Device::new(3));
    bob.register(&router).await;
    carol.register(&router).await;
    for _ in 0..3 {
        assert_eq!(deposit(&router, &bob, bob.capability(), b"x".to_vec()).await.status(), 201);
    }
    assert_eq!(deposit(&router, &bob, bob.capability(), b"x".to_vec()).await.status(), 429);
    assert_eq!(signal(&router, &bob, bob.capability(), b"x".to_vec()).await.status(), 429, "signals count for the same recipient");
    assert_eq!(deposit(&router, &carol, carol.capability(), b"x".to_vec()).await.status(), 201, "others are not affected");
}

// The origin is the address the load balancer saw (the last X-Forwarded-For), hashed in memory.
#[tokio::test]
async fn one_origin_cannot_register_devices_without_end() {
    let router = router_limited(limits(1000, 1000, 2)).await;
    let register_from = |seed: u8, origin: &'static str| {
        let router = &router;
        async move {
            let device = Device::new(seed);
            let body = serde_json::to_vec(&json!({
                "signing_key": STANDARD_NO_PAD.encode(device.key.verifying_key().to_bytes()),
                "capability_hash": STANDARD_NO_PAD.encode(blake3::hash(&device.capability).as_bytes()),
            }))
            .unwrap();
            let nonce = format!("{}", uuid::Uuid::now_v7());
            let mut request = router.http.post(format!("{}/v1/device/register", router.base)).body(body.clone());
            for (name, value) in device.sign("POST", "/v1/device/register", &body, &nonce) {
                request = request.header(name, value);
            }
            request.header("x-forwarded-for", format!("6.6.6.6, {origin}")).send().await.unwrap().status().as_u16()
        }
    };
    assert_eq!(register_from(10, "203.0.113.7").await, 204);
    assert_eq!(register_from(11, "203.0.113.7").await, 204);
    assert_eq!(register_from(12, "203.0.113.7").await, 429);
    assert_eq!(register_from(13, "198.51.100.9").await, 204, "another origin is fine");
}

/// Hidden sessions, phase 2 (app#9): a device registers eight capabilities, always eight, so the
/// router cannot tell how many are real. Its own is the first.
fn eight(device: &Device) -> Vec<[u8; 32]> {
    (0..8u8).map(|slot| if slot == 0 { device.capability } else { [slot; 32] }).collect()
}

impl Device {
    async fn register_eight(&self, router: &Router) -> reqwest::Response {
        let hashes: Vec<String> =
            eight(self).iter().map(|capability| STANDARD_NO_PAD.encode(blake3::hash(capability).as_bytes())).collect();
        let body = json!({
            "signing_key": STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes()),
            "capability_hash": hashes[0],
            "capability_hashes": hashes,
        });
        self.request(router, "POST", "/v1/device/register", serde_json::to_vec(&body).unwrap()).await
    }
}

#[tokio::test]
async fn any_of_the_eight_capabilities_reaches_the_device() {
    let router = router().await;
    let bob = Device::new(2);
    assert_eq!(bob.register_eight(&router).await.status(), 204);
    for capability in eight(&bob) {
        let status = deposit(&router, &bob, STANDARD_NO_PAD.encode(capability), b"sealed".to_vec()).await.status();
        assert_eq!(status, 201);
    }
    assert_eq!(deposit(&router, &bob, STANDARD_NO_PAD.encode([99u8; 32]), b"x".to_vec()).await.status(), 403);
}

#[tokio::test]
async fn capabilities_come_eight_at_a_time_or_not_at_all() {
    let router = router().await;
    let bob = Device::new(2);
    let hash = STANDARD_NO_PAD.encode(blake3::hash(&bob.capability).as_bytes());
    let body = json!({
        "signing_key": STANDARD_NO_PAD.encode(bob.key.verifying_key().to_bytes()),
        "capability_hash": hash,
        "capability_hashes": [hash, hash],
    });
    let status = bob.request(&router, "POST", "/v1/device/register", serde_json::to_vec(&body).unwrap()).await.status();
    assert_eq!(status, 400);
}

// The wake says which capability was used, and nothing else: the phone knows what it means.
#[tokio::test]
async fn the_wake_up_says_which_capability_was_used() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-fcm-token").await;

    deposit(&router, &bob, STANDARD_NO_PAD.encode([3u8; 32]), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3]).await);
    // A quiet slot never holds back the main one: each has its own pace.
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3, 0]).await);
}

// An app from before registers one capability, as ever: it is the first.
#[tokio::test]
async fn a_single_capability_is_still_the_first() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register(&router).await;
    bob.set_push(&router, "bob-fcm-token").await;
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [0]).await);
}


/// Nothing more arrives on the socket for a while (pings aside).
async fn nothing_more(socket: &mut Socket) -> bool {
    loop {
        match timeout(Duration::from_millis(300), socket.next()).await {
            Err(_) => return true,
            Ok(Some(Ok(Message::Text(_)))) => return false,
            Ok(Some(Ok(_))) => continue,
            Ok(_) => return true,
        }
    }
}

async fn next_signal(socket: &mut Socket) -> Vec<u8> {
    let frame = next_json(socket).await;
    assert_eq!(frame["kind"], "signal");
    STANDARD_NO_PAD.decode(frame["signal"].as_str().unwrap()).unwrap()
}

// §15: a signal for a device that is not connected waits for it in memory, and is handed over,
// in order and once, as soon as it connects. The sender learns it waits, still with a 404: the
// apps from before 0.4 read a 404 as "not connected" and go on as they did.
#[tokio::test]
async fn a_signal_for_an_offline_device_waits_for_it_to_connect() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;

    for offer in [b"first".to_vec(), b"second".to_vec()] {
        let answer = signal(&router, &bob, bob.capability(), offer).await;
        assert_eq!(answer.status(), 404, "bob is not connected");
        assert_eq!(answer.headers().get("ft-retained").map(|value| value.to_str().unwrap()), Some("1"), "but it waits for him");
    }

    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome", "the welcome comes first");
    assert_eq!(next_signal(&mut socket).await, b"first");
    assert_eq!(next_signal(&mut socket).await, b"second");
    assert!(nothing_more(&mut socket).await);
    drop(socket);

    let mut again = bob.connect(&router).await;
    assert_eq!(next_json(&mut again).await["kind"], "welcome");
    assert!(nothing_more(&mut again).await, "never handed over twice");

    let live = signal(&router, &bob, bob.capability(), b"third".to_vec()).await;
    assert_eq!(live.status(), 202);
    assert!(live.headers().get("ft-retained").is_none(), "handed over at once, not held");
    assert_eq!(next_signal(&mut again).await, b"third");
}

// A call to a phone that is not connected still rings it, and the offer is there when it
// connects: the caller no longer has to send it again and again.
#[tokio::test]
async fn a_call_waits_for_the_phone_it_rings() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register(&router).await;
    bob.set_push(&router, "bob-token").await;

    let answer = router
        .http
        .post(format!("{}/v1/signal/{}", router.base, bob.id()))
        .header("ft-capability", bob.capability())
        .header("ft-call", "1")
        .body(b"call offer".to_vec())
        .send()
        .await
        .expect("answers");
    assert_eq!(answer.status(), 404);
    assert!(answer.headers().contains_key("ft-retained"));
    assert!(soon(|| waker.rung() == ["bob-token"]).await);

    let mut socket = bob.connect(&router).await;
    next_json(&mut socket).await;
    assert_eq!(next_signal(&mut socket).await, b"call offer");
}

// What the router refuses is never held: a stranger's signal, one too big, one over the limit.
#[tokio::test]
async fn a_refused_signal_is_not_held() {
    let router = router_limited(limits(1000, 3, 1000)).await;
    let bob = Device::new(2);
    bob.register(&router).await;

    let stranger = signal(&router, &bob, STANDARD_NO_PAD.encode([0u8; 32]), b"spam".to_vec()).await;
    assert_eq!(stranger.status(), 403);
    assert!(!stranger.headers().contains_key("ft-retained"));
    assert_eq!(signal(&router, &bob, bob.capability(), b"kept".to_vec()).await.status(), 404);
    let big = signal(&router, &bob, bob.capability(), vec![0; 17 * 1024]).await;
    assert_eq!(big.status(), 413);
    assert!(!big.headers().contains_key("ft-retained"));
    assert_eq!(signal(&router, &bob, bob.capability(), b"one more".to_vec()).await.status(), 404);
    let flood = signal(&router, &bob, bob.capability(), b"flood".to_vec()).await;
    assert_eq!(flood.status(), 429);
    assert!(!flood.headers().contains_key("ft-retained"));

    let mut socket = bob.connect(&router).await;
    next_json(&mut socket).await;
    assert_eq!(next_signal(&mut socket).await, b"kept");
    assert_eq!(next_signal(&mut socket).await, b"one more");
    assert!(nothing_more(&mut socket).await);
}

// A device that forgets itself leaves nothing waiting for it.
#[tokio::test]
async fn forgetting_a_device_drops_what_waits_for_it() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    signal(&router, &bob, bob.capability(), b"offer".to_vec()).await;
    assert_eq!(bob.request(&router, "DELETE", "/v1/device", vec![]).await.status(), 204);

    bob.register(&router).await;
    let mut socket = bob.connect(&router).await;
    next_json(&mut socket).await;
    assert!(nothing_more(&mut socket).await);
}

// ---- Silent slots (2026-10-01) ----
//
// A session the user has left is silent: the phone says which of its eight slots are (a bitmask,
// bit i = slot i) and the router sends no push for them, because an iPhone shows an APNs alert
// and rings a VoIP push whatever the app decides.

impl Device {
    /// Registers the eight capabilities with `silent_slots` as given, any JSON at all.
    async fn register_silent(&self, router: &Router, silent_slots: Value) -> reqwest::Response {
        let hashes: Vec<String> =
            eight(self).iter().map(|capability| STANDARD_NO_PAD.encode(blake3::hash(capability).as_bytes())).collect();
        let body = json!({
            "signing_key": STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes()),
            "capability_hash": hashes[0],
            "capability_hashes": hashes,
            "silent_slots": silent_slots,
        });
        self.request(router, "POST", "/v1/device/register", serde_json::to_vec(&body).unwrap()).await
    }
}

/// The capability of one of the eight slots, as a sender holds it.
fn slot_capability(device: &Device, slot: usize) -> String {
    STANDARD_NO_PAD.encode(eight(device)[slot])
}

// An app from before sends no mask: nothing is silent, as ever.
#[tokio::test]
async fn a_registration_without_silent_slots_leaves_nothing_silent() {
    let router = router().await;
    let bob = Device::new(2);
    assert_eq!(bob.register_eight(&router).await.status(), 204);
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0));
    assert_eq!(bob.register(&router).await.status(), 204, "nor with a single capability");
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0));
}

// The main list (bit 0) can never be silenced: the router clears its bit.
#[tokio::test]
async fn a_registration_carries_the_silent_slots_but_never_the_main_list() {
    let router = router().await;
    let bob = Device::new(2);
    assert_eq!(bob.register_silent(&router, json!(0b1000_0111)).await.status(), 204);
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0b1000_0110));
    let carol = Device::new(3);
    assert_eq!(carol.register_silent(&router, json!(255)).await.status(), 204);
    assert_eq!(router.db.silent_slots(&carol.id()).await.unwrap(), Some(0b1111_1110));
}

// Like any other malformed registration: 400, and nothing is stored.
#[tokio::test]
async fn malformed_silent_slots_are_refused() {
    let router = router().await;
    let bob = Device::new(2);
    for wrong in [json!(256), json!(-1), json!(1.5), json!(2.0), json!("6"), json!(null), json!(true), json!([1]), json!({})] {
        assert_eq!(bob.register_silent(&router, wrong.clone()).await.status(), 400, "{wrong}");
    }
    assert!(router.db.signing_key(&bob.id()).await.unwrap().is_none(), "never registered");
}

// Leaving a session and coming back to it: each registration replaces the mask, and one without
// the field clears it.
#[tokio::test]
async fn each_registration_replaces_the_silent_slots() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0b0000_1000));
    bob.register_silent(&router, json!(0)).await;
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0));
    bob.register_silent(&router, json!(0b0010_1000)).await;
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0b0010_1000));
    bob.register_eight(&router).await;
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0), "absent is 0");
}

/// FCM and APNs, both fake, waking and ringing at the pace given: `Duration::ZERO` lets every push
/// through.
fn push_paced(android: Arc<FakeWaker>, iphones: Arc<FakeApns>, every: Duration) -> Option<Arc<Push>> {
    let wakers = [(FCM.to_owned(), android as Arc<dyn Waker>), (APNS.to_owned(), iphones as Arc<dyn Waker>)].into_iter().collect();
    Some(Arc::new(Push { vault: PushVault::new(&[9; 32]), wakers, limiter: WakeLimiter::new(every), ring_limiter: RingLimiter::new(every, every) }))
}

fn iphone_target(seed: u8) -> String {
    format!("production:com.flickertalk.app:{}", format!("{seed:02x}").repeat(32))
}

/// What a sender sees of an answer: the status and every header but the date.
async fn seen(response: reqwest::Response) -> (u16, std::collections::BTreeMap<String, String>) {
    let headers = response
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() != "date")
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
        .collect();
    (response.status().as_u16(), headers)
}

async fn call(router: &Router, to: &Device, capability: String, bytes: Vec<u8>) -> reqwest::Response {
    router
        .http
        .post(format!("{}/v1/signal/{}", router.base, to.id()))
        .header("ft-capability", capability)
        .header("ft-call", "1")
        .body(bytes)
        .send()
        .await
        .expect("answers")
}

/// Mail, a signal and a call through `slot`, as a sender sees each answer.
async fn write_signal_and_call(router: &Router, to: &Device, slot: usize) -> Vec<(u16, std::collections::BTreeMap<String, String>)> {
    vec![
        seen(deposit(router, to, slot_capability(to, slot), b"sealed".to_vec()).await).await,
        seen(signal(router, to, slot_capability(to, slot), b"offer".to_vec()).await).await,
        seen(call(router, to, slot_capability(to, slot), b"call offer".to_vec()).await).await,
    ]
}

// A silent slot gets no push at all, on FCM or APNs, for mail, a signal or a call; and the sender
// gets exactly the answers it gets when the push goes out: the mail is kept, the signal and the
// call wait for the phone, as ever.
#[tokio::test]
async fn a_silent_slot_gets_no_push_and_the_sender_cannot_tell() {
    let (android, iphones) = (Arc::new(FakeWaker::default()), Arc::new(FakeApns::default()));
    let router = router_with(push_paced(android.clone(), iphones.clone(), Duration::ZERO)).await;
    // Bob (Android) and Carol (iPhone) left the session in slot 3; Dave and Erin did not.
    let (bob, carol, dave, erin) = (Device::new(2), Device::new(3), Device::new(4), Device::new(5));
    for (device, silent) in [(&bob, 0b0000_1000), (&carol, 0b0000_1000), (&dave, 0), (&erin, 0)] {
        assert_eq!(device.register_silent(&router, json!(silent)).await.status(), 204);
    }
    bob.set_push(&router, "bob-fcm-token").await;
    dave.set_push(&router, "dave-fcm-token").await;
    assert_eq!(carol.set_push_with(&router, "apns", &iphone_target(0xc0)).await.status(), 204);
    assert_eq!(erin.set_push_with(&router, "apns", &iphone_target(0xe0)).await.status(), 204);

    let to_bob = write_signal_and_call(&router, &bob, 3).await;
    let to_carol = write_signal_and_call(&router, &carol, 3).await;
    let to_dave = write_signal_and_call(&router, &dave, 3).await;
    let to_erin = write_signal_and_call(&router, &erin, 3).await;

    assert_eq!(to_bob, to_dave, "an Android phone: the same answers, push or no push");
    assert_eq!(to_carol, to_erin, "an iPhone: the same answers, push or no push");
    assert_eq!(to_bob.iter().map(|(status, _)| *status).collect::<Vec<_>>(), [201, 404, 404]);
    assert_eq!(to_bob[1].1.get("ft-retained").map(String::as_str), Some("1"));
    assert_eq!(to_bob[2].1.get("ft-retained").map(String::as_str), Some("1"));

    // The pushes for Dave and Erin went out; none for Bob or Carol.
    assert!(soon(|| android.woken().len() == 2 && android.rung().len() == 1 && iphones.0.woken().len() == 3).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(android.woken(), ["dave-fcm-token", "dave-fcm-token"]);
    assert_eq!(android.rung(), ["dave-fcm-token"]);
    assert_eq!(iphones.0.woken(), [iphone_target(0xe0), iphone_target(0xe0), iphone_target(0xe0)], "Erin's wakes and call");

    // What came for the silent slot (2026-10-01, the router makes a left session unreachable): the
    // mail is kept but withheld from the phone, and the signals never reach it.
    let listed: Value = bob.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    assert!(listed.as_array().unwrap().is_empty(), "withheld while the slot is silent");
    let mut socket = carol.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert!(nothing_more(&mut socket).await, "no signal waited for the silent slot");
}

// Only the slots the phone named are silent: a spare slot without its bit still wakes and rings,
// and the main list always does, even when the phone sets every bit.
#[tokio::test]
async fn other_slots_and_the_main_list_still_wake_and_ring() {
    let android = Arc::new(FakeWaker::default());
    let router = router_with(push_paced(android.clone(), Arc::default(), Duration::ZERO)).await;
    let (bob, carol) = (Device::new(2), Device::new(3));
    bob.register_silent(&router, json!(0b0000_1000)).await;
    carol.register_silent(&router, json!(255)).await;
    bob.set_push(&router, "bob-fcm-token").await;
    carol.set_push(&router, "carol-fcm-token").await;

    deposit(&router, &bob, slot_capability(&bob, 5), b"sealed".to_vec()).await;
    assert!(soon(|| android.slots() == [5]).await, "slot 5 is not silent");
    call(&router, &bob, slot_capability(&bob, 6), b"call offer".to_vec()).await;
    assert!(soon(|| android.rung_slots() == [6]).await, "nor is slot 6");

    deposit(&router, &carol, carol.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| android.slots() == [5, 0]).await, "the main list wakes");
    call(&router, &carol, carol.capability(), b"call offer".to_vec()).await;
    assert!(soon(|| android.rung_slots() == [6, 0]).await, "and rings");
    deposit(&router, &carol, slot_capability(&carol, 7), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(android.slots(), [5, 0], "but every other slot of hers is silent");
}

// Leaving a session silences it, coming back to it lets it ring again, and leaving again
// silences it again: the latest registration decides.
#[tokio::test]
async fn coming_back_to_a_session_lets_it_ring_again() {
    let android = Arc::new(FakeWaker::default());
    let router = router_with(push_paced(android.clone(), Arc::default(), Duration::ZERO)).await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    bob.set_push(&router, "bob-fcm-token").await;

    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(android.woken().is_empty(), "silent");

    bob.register_silent(&router, json!(0)).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    assert!(soon(|| android.slots() == [3]).await, "back in the session: it wakes");
    call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await;
    assert!(soon(|| android.rung_slots() == [3]).await, "and rings");

    bob.register_silent(&router, json!(0b0000_1000)).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((android.slots(), android.rung_slots()), (vec![3], vec![3]), "left again: silent again");
}

// Each capability keeps its own pace (app#9), silent or not: a silent slot never holds back the
// main list or another slot, and the pace of a slot is taken the same way whether its push goes
// out or not, so nothing about it depends on the mask.
#[tokio::test]
async fn a_silent_slot_keeps_its_own_pace_and_holds_back_no_other() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    bob.set_push(&router, "bob-fcm-token").await;

    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [0]).await);
    deposit(&router, &bob, slot_capability(&bob, 5), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [0, 5]).await);

    // Back in slot 3 within the pace: its last push was skipped, not sent, yet the pace was taken
    // all the same, exactly as for a push that went out.
    bob.register_silent(&router, json!(0)).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.slots(), [0, 5]);
}

// ---- Rings and wakes, each at its own pace (0.5.1) ----
//
// Found on real phones (2026-10-01): a message woke a closed iPhone, and the same caller's call
// about ten seconds later sent no push at all, because a wake and a ring shared one pace. A call's
// push is now or never: a ring is never held back by a wake, nor a wake by a ring. A ring has a
// pace of its own, against a flood and against a caller's retry ringing the phone twice: after a
// ring, the next one waits until the phone has connected (it took the call's signal) and the floor
// has passed, or until the ring has run out.

/// The phone wakes, connects, takes the one signal that waited for it and goes back to sleep.
async fn take_and_sleep(router: &Router, device: &Device) {
    let mut socket = device.connect(router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    next_signal(&mut socket).await;
    socket.close(None).await.expect("closes");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// What the phones showed: mail and a message's offer wake the phone, and a call right after rings
// it all the same.
#[tokio::test]
async fn a_call_rings_right_after_a_wake() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;

    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    signal(&router, &bob, bob.capability(), b"offer".to_vec()).await;
    assert!(soon(|| waker.woken() == ["bob-token"]).await);
    assert_eq!(call(&router, &bob, bob.capability(), b"call offer".to_vec()).await.status(), 404);
    assert!(soon(|| waker.rung() == ["bob-token"]).await, "the call rings within the wake's pace");
    assert_eq!(waker.woken(), ["bob-token"], "and the wake's pace still holds for wakes");
}

// A message right after a ring still wakes the phone: it is something else to fetch, and the
// ring took nothing of the wake's pace. Each kind then keeps its own pace.
#[tokio::test]
async fn a_wake_goes_out_right_after_a_ring_and_each_keeps_its_own_pace() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;

    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung() == ["bob-token"]).await);
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.woken() == ["bob-token"]).await, "woken right after the ring");

    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((waker.woken().len(), waker.rung().len()), (1, 1), "neither again so soon");
}

// A caller that sends its call again while the phone has not yet answered the ring (it has not
// connected) rings it no more: on an iPhone each VoIP push is a call for CallKit. Once the ring
// has run out, a call rings again. The caller gets the same answer either way.
#[tokio::test]
async fn a_retry_of_the_same_call_rings_once() {
    let waker = Arc::new(FakeWaker::default());
    // No floor at all: only the ring that the phone has not taken holds the retries back.
    let router = router_with(push_ringing(waker.clone(), Duration::ZERO, Duration::from_millis(1500))).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;

    let started = std::time::Instant::now();
    let first = seen(call(&router, &bob, bob.capability(), b"call offer".to_vec()).await).await;
    for _ in 0..4 {
        let retry = seen(call(&router, &bob, bob.capability(), b"call offer".to_vec()).await).await;
        assert_eq!(retry, first, "the caller cannot tell a held ring from one that went out");
    }
    assert!(soon(|| waker.rung() == ["bob-token"]).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.rung().len(), 1, "rung once");

    tokio::time::sleep(Duration::from_millis(1700).saturating_sub(started.elapsed())).await;
    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung().len() == 2).await, "the ring ran out: the next call rings");
}

// Two calls in a row: the phone took the first (it connected and got its signal), so the second
// is a new call and rings, once the floor has passed.
#[tokio::test]
async fn a_second_call_rings_once_the_phone_took_the_first() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_ringing(waker.clone(), Duration::from_secs(1), Duration::from_secs(30))).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;

    let started = std::time::Instant::now();
    call(&router, &bob, bob.capability(), b"first call".to_vec()).await;
    assert!(soon(|| waker.rung().len() == 1).await);
    take_and_sleep(&router, &bob).await;

    tokio::time::sleep(Duration::from_millis(1200).saturating_sub(started.elapsed())).await;
    assert_eq!(call(&router, &bob, bob.capability(), b"second call".to_vec()).await.status(), 404);
    assert!(soon(|| waker.rung().len() == 2).await, "the second call rings");
}

// A flood stays bounded: without the phone connecting, a ring at most per ring; with the phone
// connecting after each ring, still no more than one ring per floor.
#[tokio::test]
async fn a_flood_of_calls_rings_no_more_often_than_its_pace() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;
    for _ in 0..30 {
        assert_eq!(call(&router, &bob, bob.capability(), b"flood".to_vec()).await.status(), 404);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.rung().len(), 1, "production paces: one ring");

    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_ringing(waker.clone(), Duration::from_secs(3), Duration::from_secs(30))).await;
    let carol = Device::new(3);
    carol.register_eight(&router).await;
    carol.set_push(&router, "carol-token").await;
    let started = std::time::Instant::now();
    for _ in 0..5 {
        assert_eq!(call(&router, &carol, carol.capability(), b"flood".to_vec()).await.status(), 404);
        take_and_sleep(&router, &carol).await;
    }
    assert!(started.elapsed() < Duration::from_secs(3), "all within the floor");
    assert_eq!(waker.rung().len(), 1, "the phone took every ring, and still one per floor");
}

// The main list and a spare slot ring on their own: a ring held back on one holds back no other,
// and neither holds back a wake.
#[tokio::test]
async fn the_main_list_and_a_spare_slot_ring_on_their_own() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-token").await;

    call(&router, &bob, slot_capability(&bob, 5), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung_slots() == [5]).await);
    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung_slots() == [5, 0]).await, "slot 5 holds back nothing of the main list");
    call(&router, &bob, slot_capability(&bob, 5), b"call offer".to_vec()).await;
    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    deposit(&router, &bob, slot_capability(&bob, 5), b"sealed".to_vec()).await;
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [5, 0]).await, "both wake");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.rung_slots(), [5, 0], "neither rings twice");
}

// A silent slot gets no ring, yet its ring pace is taken just as when the ring goes out; it holds
// back no other slot, and no wake.
#[tokio::test]
async fn a_silent_slot_keeps_its_own_ring_pace_and_holds_back_no_other() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    bob.set_push(&router, "bob-token").await;

    call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await;
    call(&router, &bob, bob.capability(), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung_slots() == [0]).await);
    call(&router, &bob, slot_capability(&bob, 5), b"call offer".to_vec()).await;
    assert!(soon(|| waker.rung_slots() == [0, 5]).await);

    // Back in slot 3 while its skipped ring would still be ringing: held back, as a ring that went
    // out would be. A wake for it goes out: the ring took nothing of the wake's pace.
    bob.register_silent(&router, json!(0)).await;
    call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3]).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.rung_slots(), [0, 5]);
}

// ---- A left session is unreachable (2026-10-01) ----
//
// The owner's decision: a session the user has left looks the same from outside whether the app is
// open or closed, and the router enforces it. A signal through a silent slot never reaches the
// device, connected or not: it is not forwarded, not held for its next connection, and nothing is
// pushed. The sender gets the answer of a phone that is not connected, so it cannot tell a left
// session from a phone that is off.

// The phone is connected, yet a signal or a call through its silent slot does not reach the
// socket, and the sender's answer is, header by header, that of a phone that is not connected.
#[tokio::test]
async fn a_signal_through_a_silent_slot_never_reaches_a_connected_device() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    // Bob left the session in slot 3 and has the app open; Dave left nothing and is not connected.
    let (bob, dave) = (Device::new(2), Device::new(4));
    bob.register_silent(&router, json!(0b0000_1000)).await;
    dave.register_silent(&router, json!(0)).await;
    bob.set_push(&router, "bob-token").await;
    dave.set_push(&router, "dave-token").await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");

    let to_bob = seen(signal(&router, &bob, slot_capability(&bob, 3), b"offer".to_vec()).await).await;
    let to_dave = seen(signal(&router, &dave, slot_capability(&dave, 3), b"offer".to_vec()).await).await;
    assert_eq!(to_bob, to_dave, "a signal: the answer of a phone that is not connected");
    assert_eq!(to_bob.0, 404);
    assert_eq!(to_bob.1.get("ft-retained").map(String::as_str), Some("1"));

    let call_bob = seen(call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await).await;
    let call_dave = seen(call(&router, &dave, slot_capability(&dave, 3), b"call offer".to_vec()).await).await;
    assert_eq!(call_bob, call_dave, "a call: the same");
    assert_eq!(call_bob, to_bob);

    assert!(nothing_more(&mut socket).await, "nothing reached Bob's socket");
    assert!(soon(|| waker.woken() == ["dave-token"] && waker.rung() == ["dave-token"]).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((waker.woken(), waker.rung()), (vec!["dave-token".to_owned()], vec!["dave-token".to_owned()]), "nothing pushed to Bob");
}

// What was sent through a silent slot is gone for good: not handed over when the phone connects,
// nor once it comes back to the session, even within the minute a signal could have waited. A
// sender that still wants through sends again (the app retries on its own).
#[tokio::test]
async fn nothing_sent_through_a_silent_slot_is_handed_over_later() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;

    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"offer".to_vec()).await.status(), 404);
    assert_eq!(call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await.status(), 404);
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert!(nothing_more(&mut socket).await, "not handed over when it connects");
    socket.close(None).await.expect("closes");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"another offer".to_vec()).await.status(), 404);
    bob.register_silent(&router, json!(0)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert!(nothing_more(&mut socket).await, "nor once the slot is no longer silent");

    // Back in the session, what is sent now arrives.
    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"new offer".to_vec()).await.status(), 202);
    assert_eq!(next_signal(&mut socket).await, b"new offer");
}

// Only the silent slot is cut off: the main list and the other slots of the same phone get their
// signals as ever, connected or not.
#[tokio::test]
async fn the_other_slots_of_a_device_still_get_their_signals() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");

    assert_eq!(signal(&router, &bob, slot_capability(&bob, 5), b"to five".to_vec()).await.status(), 202);
    assert_eq!(next_signal(&mut socket).await, b"to five");
    assert_eq!(call(&router, &bob, bob.capability(), b"to the main list".to_vec()).await.status(), 202);
    assert_eq!(next_signal(&mut socket).await, b"to the main list");
    socket.close(None).await.expect("closes");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"dropped".to_vec()).await.status(), 404);
    assert_eq!(signal(&router, &bob, slot_capability(&bob, 5), b"kept".to_vec()).await.status(), 404);
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert_eq!(next_signal(&mut socket).await, b"kept");
    assert!(nothing_more(&mut socket).await);
}

// An app that sends no mask sees no change: every slot reaches it.
#[tokio::test]
async fn without_silent_slots_every_slot_gets_its_signals() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    for slot in 0..8u8 {
        assert_eq!(signal(&router, &bob, slot_capability(&bob, slot.into()), vec![slot]).await.status(), 202);
        assert_eq!(next_signal(&mut socket).await, [slot]);
    }
}
