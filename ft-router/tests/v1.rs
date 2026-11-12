use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ft_router::auth::{device_id, SignedRequest};
use ft_router::bans::Bans;
use ft_router::db::Db;
use ft_router::turn::TurnIssuer;
use ft_router::push::{apns_target, PushVault, RingLimiter, Wake, WakeLimiter, Waker, APNS, FCM, RING_EVERY, RING_FOR};
use ft_router::limits::{FeedbackLimits, Limits};
use ft_router::mail::Mailer;
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
    router_built(push, None, limits).await
}

async fn router_mailing(mail: Option<Arc<Mailer>>, limits: Limits) -> Router {
    router_built(None, mail, limits).await
}

async fn router_built(push: Option<Arc<Push>>, mail: Option<Arc<Mailer>>, limits: Limits) -> Router {
    router_on(fresh_db().await, push, mail, limits, Bans::default()).await
}

async fn fresh_db() -> Arc<Db> {
    let url = std::env::var("FT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/ft_router_test".to_owned());
    Arc::new(Db::connect_isolated(&url).await.expect("test database"))
}

async fn router_banning(db: Arc<Db>, bans: Bans, push: Option<Arc<Push>>) -> Router {
    router_on(db, push, None, Limits::default(), bans).await
}

async fn router_on(db: Arc<Db>, push: Option<Arc<Push>>, mail: Option<Arc<Mailer>>, limits: Limits, bans: Bans) -> Router {
    let config = Config {
        stun: vec!["stun:turn.example:3478".to_owned()],
        turn: Some(TurnIssuer::new(b"secret".to_vec(), vec!["turn:turn.example:3478".to_owned()], Duration::from_secs(600))),
        db: Some(db.clone()),
        push,
        mail,
        poc_relay: false,
        limits,
        bans: Arc::new(bans),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app(config)).await.expect("serves") });
    let _ = rustls::crypto::ring::default_provider().install_default();
    Router { base: format!("http://{address}"), http: reqwest::Client::new(), db }
}

#[derive(Default)]
struct FakeWaker {
    woken: std::sync::Mutex<Vec<String>>,
    slots: std::sync::Mutex<Vec<u8>>,
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

fn push_with(waker: Arc<FakeWaker>) -> Option<Arc<Push>> {
    push_ringing(waker, RING_EVERY, RING_FOR)
}

fn push_ringing(waker: Arc<FakeWaker>, ring_every: Duration, ring_for: Duration) -> Option<Arc<Push>> {
    let wakers = [(FCM.to_owned(), waker as Arc<dyn Waker>)].into_iter().collect();
    Some(Arc::new(Push {
        vault: PushVault::new(&[9; 32]),
        wakers,
        limiter: WakeLimiter::new(Duration::from_secs(10)),
        ring_limiter: RingLimiter::new(ring_every, ring_for),
    }))
}

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

async fn soon<F: Fn() -> bool>(condition: F) -> bool {
    for _ in 0..50 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

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
        let (socket, _) = connect_async(self.connect_url(router)).await.expect("connects");
        socket
    }

    async fn connect_status(&self, router: &Router) -> u16 {
        match connect_async(self.connect_url(router)).await {
            Ok(_) => 101,
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status().as_u16(),
            Err(other) => panic!("cannot reach the router: {other}"),
        }
    }

    fn connect_url(&self, router: &Router) -> String {
        let path = "/v1/connect";
        let headers = self.sign("GET", path, b"", &uuid::Uuid::now_v7().to_string());
        let query: Vec<String> = headers.iter().map(|(name, value)| format!("{name}={}", urlencode(value))).collect();
        format!("{}{path}?{}", router.base.replace("http", "ws"), query.join("&"))
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

#[tokio::test]
async fn a_device_can_only_register_its_own_id() {
    let router = router().await;
    let (alice, mallory) = (Device::new(1), Device::new(2));
    let body = json!({
        "signing_key": STANDARD_NO_PAD.encode(mallory.key.verifying_key().to_bytes()),
        "capability_hash": STANDARD_NO_PAD.encode([0u8; 32]),
    });
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

    let router = router_with(push_with(Arc::default())).await;
    let dave = Device::new(4);
    dave.register(&router).await;
    assert_eq!(dave.set_push_with(&router, "apns", &target).await.status(), 400);
}

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

    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(waker.woken().len(), 1);
}

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
    Limits { per_device, per_recipient, per_origin, window: Duration::from_secs(60), ..Limits::default() }
}

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

#[tokio::test]
async fn the_wake_up_says_which_capability_was_used() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let bob = Device::new(2);
    bob.register_eight(&router).await;
    bob.set_push(&router, "bob-fcm-token").await;

    deposit(&router, &bob, STANDARD_NO_PAD.encode([3u8; 32]), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3]).await);
    deposit(&router, &bob, bob.capability(), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3, 0]).await);
}

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

impl Device {
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

fn slot_capability(device: &Device, slot: usize) -> String {
    STANDARD_NO_PAD.encode(eight(device)[slot])
}

#[tokio::test]
async fn a_registration_without_silent_slots_leaves_nothing_silent() {
    let router = router().await;
    let bob = Device::new(2);
    assert_eq!(bob.register_eight(&router).await.status(), 204);
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0));
    assert_eq!(bob.register(&router).await.status(), 204, "nor with a single capability");
    assert_eq!(router.db.silent_slots(&bob.id()).await.unwrap(), Some(0));
}

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

#[tokio::test]
async fn malformed_silent_slots_are_refused() {
    let router = router().await;
    let bob = Device::new(2);
    for wrong in [json!(256), json!(-1), json!(1.5), json!(2.0), json!("6"), json!(null), json!(true), json!([1]), json!({})] {
        assert_eq!(bob.register_silent(&router, wrong.clone()).await.status(), 400, "{wrong}");
    }
    assert!(router.db.signing_key(&bob.id()).await.unwrap().is_none(), "never registered");
}

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

fn push_paced(android: Arc<FakeWaker>, iphones: Arc<FakeApns>, every: Duration) -> Option<Arc<Push>> {
    let wakers = [(FCM.to_owned(), android as Arc<dyn Waker>), (APNS.to_owned(), iphones as Arc<dyn Waker>)].into_iter().collect();
    Some(Arc::new(Push { vault: PushVault::new(&[9; 32]), wakers, limiter: WakeLimiter::new(every), ring_limiter: RingLimiter::new(every, every) }))
}

fn iphone_target(seed: u8) -> String {
    format!("production:com.flickertalk.app:{}", format!("{seed:02x}").repeat(32))
}

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

async fn write_signal_and_call(router: &Router, to: &Device, slot: usize) -> Vec<(u16, std::collections::BTreeMap<String, String>)> {
    vec![
        seen(deposit(router, to, slot_capability(to, slot), b"sealed".to_vec()).await).await,
        seen(signal(router, to, slot_capability(to, slot), b"offer".to_vec()).await).await,
        seen(call(router, to, slot_capability(to, slot), b"call offer".to_vec()).await).await,
    ]
}

#[tokio::test]
async fn a_silent_slot_gets_no_push_and_the_sender_cannot_tell() {
    let (android, iphones) = (Arc::new(FakeWaker::default()), Arc::new(FakeApns::default()));
    let router = router_with(push_paced(android.clone(), iphones.clone(), Duration::ZERO)).await;
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

    assert!(soon(|| android.woken().len() == 2 && android.rung().len() == 1 && iphones.0.woken().len() == 3).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(android.woken(), ["dave-fcm-token", "dave-fcm-token"]);
    assert_eq!(android.rung(), ["dave-fcm-token"]);
    assert_eq!(iphones.0.woken(), [iphone_target(0xe0), iphone_target(0xe0), iphone_target(0xe0)], "Erin's wakes and call");

    let listed: Value = bob.request(&router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    assert!(listed.as_array().unwrap().is_empty(), "withheld while the slot is silent");
    let mut socket = carol.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert!(nothing_more(&mut socket).await, "no signal waited for the silent slot");
}

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

    bob.register_silent(&router, json!(0)).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.slots(), [0, 5]);
}

async fn take_and_sleep(router: &Router, device: &Device) {
    let mut socket = device.connect(router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    next_signal(&mut socket).await;
    socket.close(None).await.expect("closes");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

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

#[tokio::test]
async fn a_retry_of_the_same_call_rings_once() {
    let waker = Arc::new(FakeWaker::default());
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

    bob.register_silent(&router, json!(0)).await;
    call(&router, &bob, slot_capability(&bob, 3), b"call offer".to_vec()).await;
    deposit(&router, &bob, slot_capability(&bob, 3), b"sealed".to_vec()).await;
    assert!(soon(|| waker.slots() == [3]).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(waker.rung_slots(), [0, 5]);
}

#[tokio::test]
async fn a_signal_through_a_silent_slot_never_reaches_a_connected_device() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
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

    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"new offer".to_vec()).await.status(), 202);
    assert_eq!(next_signal(&mut socket).await, b"new offer");
}

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

async fn collected(router: &Router, device: &Device) -> Vec<(String, Vec<u8>)> {
    let listed: Value = device.request(router, "GET", "/v1/mailbox", vec![]).await.json().await.unwrap();
    listed
        .as_array()
        .expect("a list")
        .iter()
        .map(|blob| (blob["id"].as_str().unwrap().to_owned(), STANDARD_NO_PAD.decode(blob["blob"].as_str().unwrap()).unwrap()))
        .collect()
}

fn blobs(collected: &[(String, Vec<u8>)]) -> Vec<&[u8]> {
    collected.iter().map(|(_, blob)| blob.as_slice()).collect()
}

#[tokio::test]
async fn mail_through_a_silent_slot_is_kept_without_a_word_to_the_device() {
    let waker = Arc::new(FakeWaker::default());
    let router = router_with(push_with(waker.clone())).await;
    let (bob, dave) = (Device::new(2), Device::new(4));
    bob.register_silent(&router, json!(0b0000_1000)).await;
    dave.register_silent(&router, json!(0)).await;
    bob.set_push(&router, "bob-token").await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");

    let to_bob = seen(deposit(&router, &bob, slot_capability(&bob, 3), b"left".to_vec()).await).await;
    let to_dave = seen(deposit(&router, &dave, slot_capability(&dave, 3), b"sealed".to_vec()).await).await;
    assert_eq!(to_bob, to_dave, "the sender cannot tell");
    assert_eq!(to_bob.0, 201);

    assert!(nothing_more(&mut socket).await, "no notice");
    assert!(collected(&router, &bob).await.is_empty(), "not collectable");
    assert!(waker.woken().is_empty(), "no push");
}

#[tokio::test]
async fn opening_the_session_again_hands_its_mail_over_with_a_notice() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");

    deposit(&router, &bob, slot_capability(&bob, 3), b"left".to_vec()).await;
    bob.register_silent(&router, json!(0b0000_1000)).await;
    bob.register_silent(&router, json!(0b0010_1000)).await;
    assert!(nothing_more(&mut socket).await, "still silent: nothing to say");

    bob.register_silent(&router, json!(0b0010_0000)).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail", "slot 3 is open again");
    assert_eq!(blobs(&collected(&router, &bob).await), [b"left".as_slice()]);

    bob.register_silent(&router, json!(0b0000_1000)).await;
    assert!(collected(&router, &bob).await.is_empty(), "left again before acknowledging: withheld again");
    bob.register_silent(&router, json!(0)).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
    let again = collected(&router, &bob).await;
    assert_eq!(blobs(&again), [b"left".as_slice()]);
    assert_eq!(bob.request(&router, "DELETE", &format!("/v1/mailbox/{}", again[0].0), vec![]).await.status(), 204);

    bob.register_silent(&router, json!(0b0000_1000)).await;
    bob.register_silent(&router, json!(0)).await;
    assert!(nothing_more(&mut socket).await);
}

#[tokio::test]
async fn mail_through_the_other_slots_is_collected_as_usual_meanwhile() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0b0000_1000)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");

    deposit(&router, &bob, bob.capability(), b"main".to_vec()).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
    deposit(&router, &bob, slot_capability(&bob, 3), b"left".to_vec()).await;
    deposit(&router, &bob, slot_capability(&bob, 5), b"five".to_vec()).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
    assert!(nothing_more(&mut socket).await, "one notice each, none for slot 3");

    let now = collected(&router, &bob).await;
    assert_eq!(blobs(&now), [b"main".as_slice(), b"five"]);
    for (id, _) in &now {
        assert_eq!(bob.request(&router, "DELETE", &format!("/v1/mailbox/{id}"), vec![]).await.status(), 204);
    }
    assert!(collected(&router, &bob).await.is_empty());

    bob.register_silent(&router, json!(0)).await;
    assert_eq!(next_json(&mut socket).await["kind"], "mail");
    assert_eq!(blobs(&collected(&router, &bob).await), [b"left".as_slice()]);
}

#[tokio::test]
async fn a_full_session_answers_like_a_full_mailbox_and_holds_back_no_other() {
    use ft_router::db::MAX_BLOBS_PER_SESSION;
    let router = router_limited(limits(100_000, 100_000, 100_000)).await;
    let (bob, dave) = (Device::new(2), Device::new(4));
    bob.register_silent(&router, json!(0b0000_1000)).await;
    dave.register_silent(&router, json!(0)).await;
    for _ in 0..MAX_BLOBS_PER_SESSION {
        assert_eq!(deposit(&router, &bob, slot_capability(&bob, 3), b"again".to_vec()).await.status(), 201);
        assert_eq!(deposit(&router, &dave, slot_capability(&dave, 3), b"again".to_vec()).await.status(), 201);
    }
    let to_bob = seen(deposit(&router, &bob, slot_capability(&bob, 3), b"one more".to_vec()).await).await;
    let to_dave = seen(deposit(&router, &dave, slot_capability(&dave, 3), b"one more".to_vec()).await).await;
    assert_eq!(to_bob, to_dave, "the sender cannot tell");
    assert_eq!(to_bob.0, 507);

    assert_eq!(deposit(&router, &bob, bob.capability(), b"main".to_vec()).await.status(), 201, "the main list");
    assert_eq!(deposit(&router, &bob, slot_capability(&bob, 5), b"five".to_vec()).await.status(), 201, "another session");
    assert_eq!(blobs(&collected(&router, &bob).await), [b"main".as_slice(), b"five"]);
}

#[tokio::test]
async fn a_retained_signal_is_dropped_if_its_session_was_left_before_the_hand_over() {
    let router = router().await;
    let bob = Device::new(2);
    bob.register_silent(&router, json!(0)).await;
    assert_eq!(signal(&router, &bob, slot_capability(&bob, 3), b"to three".to_vec()).await.status(), 404);
    assert_eq!(signal(&router, &bob, slot_capability(&bob, 5), b"to five".to_vec()).await.status(), 404);
    assert_eq!(call(&router, &bob, bob.capability(), b"to the main list".to_vec()).await.status(), 404);

    bob.register_silent(&router, json!(0b0000_1000)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert_eq!(next_signal(&mut socket).await, b"to five");
    assert_eq!(next_signal(&mut socket).await, b"to the main list");
    assert!(nothing_more(&mut socket).await, "not the one through slot 3");
    socket.close(None).await.expect("closes");
    tokio::time::sleep(Duration::from_millis(100)).await;

    bob.register_silent(&router, json!(0)).await;
    let mut socket = bob.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert!(nothing_more(&mut socket).await);
}

#[derive(Clone, Debug)]
struct Sent {
    recipients: Vec<String>,
    data: String,
}

impl Sent {
    fn headers(&self) -> Vec<(String, String)> {
        let (headers, _) = self.data.split_once("\r\n\r\n").expect("headers and body");
        headers
            .split("\r\n")
            .filter(|line| !line.starts_with([' ', '\t']))
            .map(|line| {
                let (name, value) = line.split_once(':').expect("a header");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect()
    }

    fn header(&self, name: &str) -> Vec<String> {
        self.headers().into_iter().filter(|(found, _)| found == name).map(|(_, value)| value).collect()
    }

    fn text(&self) -> String {
        assert_eq!(self.header("content-transfer-encoding"), ["base64"]);
        let (_, body) = self.data.split_once("\r\n\r\n").expect("headers and body");
        let body: String = body.split_whitespace().collect();
        let bytes = base64::engine::general_purpose::STANDARD.decode(body).expect("base64");
        String::from_utf8(bytes).expect("UTF-8").replace("\r\n", "\n")
    }
}

struct FakeSmtp {
    port: u16,
    sent: Arc<std::sync::Mutex<Vec<Sent>>>,
    up: Arc<std::sync::atomic::AtomicBool>,
    hold: Arc<std::sync::atomic::AtomicBool>,
    held: Arc<std::sync::Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>>,
}

impl FakeSmtp {
    async fn start() -> Self {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("address").port();
        let sent: Arc<std::sync::Mutex<Vec<Sent>>> = Arc::default();
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hold = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held: Arc<std::sync::Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>> = Arc::default();
        let (keep, running, holding, waiting) = (sent.clone(), up.clone(), hold.clone(), held.clone());
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (keep, running, holding, waiting) = (keep.clone(), running.clone(), holding.clone(), waiting.clone());
                tokio::spawn(async move {
                    let (read, mut write) = socket.into_split();
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = write.write_all(b"421 down\r\n").await;
                        return;
                    }
                    let mut lines = BufReader::new(read).lines();
                    let _ = write.write_all(b"220 fake\r\n").await;
                    let mut recipients = Vec::new();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let command = line.to_ascii_uppercase();
                        let answer: &[u8] = if command.starts_with("RCPT TO:") {
                            recipients.push(line[8..].to_owned());
                            b"250 ok\r\n"
                        } else if command == "DATA" {
                            let _ = write.write_all(b"354 go on\r\n").await;
                            let mut data = Vec::new();
                            while let Ok(Some(line)) = lines.next_line().await {
                                if line == "." {
                                    break;
                                }
                                data.push(line.strip_prefix('.').map(str::to_owned).unwrap_or(line));
                            }
                            if holding.load(std::sync::atomic::Ordering::SeqCst) {
                                let (decide, decision) = tokio::sync::oneshot::channel();
                                waiting.lock().unwrap().push(decide);
                                if !decision.await.unwrap_or(false) {
                                    let _ = write.write_all(b"554 refused\r\n").await;
                                    recipients.clear();
                                    continue;
                                }
                            }
                            keep.lock().unwrap().push(Sent { recipients: std::mem::take(&mut recipients), data: data.join("\r\n") });
                            b"250 queued\r\n"
                        } else if command == "QUIT" {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            return;
                        } else {
                            b"250 ok\r\n"
                        };
                        if write.write_all(answer).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { port, sent, up, hold, held }
    }

    fn mailer(&self) -> Option<Arc<Mailer>> {
        Some(Arc::new(Mailer::plaintext_loopback(self.port, "info@flickertalk.com", "info@flickertalk.com").expect("a mailer")))
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    fn switch(&self, up: bool) {
        self.up.store(up, std::sync::atomic::Ordering::SeqCst);
    }

    fn hold(&self, hold: bool) {
        self.hold.store(hold, std::sync::atomic::Ordering::SeqCst);
    }

    fn held(&self) -> usize {
        self.held.lock().unwrap().len()
    }

    fn release(&self, taken: bool) {
        for decide in self.held.lock().unwrap().drain(..) {
            let _ = decide.send(taken);
        }
    }
}

fn suggestion(text: &str, app: &str, platform: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "text": text, "app": app, "platform": platform })).unwrap()
}

impl Device {
    async fn suggest(&self, router: &Router, body: Vec<u8>) -> u16 {
        self.request(router, "POST", "/v1/feedback", body).await.status().as_u16()
    }
}

async fn mailing_router() -> (Router, FakeSmtp, Device) {
    let smtp = FakeSmtp::start().await;
    let router = router_mailing(smtp.mailer(), Limits::default()).await;
    let alice = Device::new(1);
    assert_eq!(alice.register(&router).await.status(), 204);
    (router, smtp, alice)
}

#[tokio::test]
async fn a_suggestion_arrives_by_mail_with_the_app_version_and_platform() {
    let (router, smtp, alice) = mailing_router().await;
    assert_eq!(alice.suggest(&router, suggestion("  Dark mode, please.\n", "1.3.0", "android")).await, 204);
    let sent = smtp.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].recipients, ["<info@flickertalk.com>"]);
    assert_eq!(sent[0].header("subject"), ["FlickerTalk suggestion (android 1.3.0)"]);
    assert_eq!(sent[0].header("from"), ["info@flickertalk.com"]);
    assert_eq!(sent[0].header("to"), ["info@flickertalk.com"]);
    assert_eq!(sent[0].text(), "Dark mode, please.", "without the blanks around it");
}

#[tokio::test]
async fn a_suggestion_mail_never_carries_the_device_id() {
    let (router, smtp, alice) = mailing_router().await;
    assert_eq!(alice.suggest(&router, suggestion("Stickers", "1.3.0", "ios")).await, 204);
    let sent = &smtp.sent()[0];
    let id = alice.id();
    assert!(!sent.data.contains(&id), "not in any header nor in the raw body");
    assert!(!sent.text().contains(&id));
    assert!(!sent.data.contains(&id["ft_".len()..]), "not even without its prefix");
    assert!(!sent.data.contains(&STANDARD_NO_PAD.encode(alice.key.verifying_key().to_bytes())), "nor its key");
}

#[tokio::test]
async fn an_unsigned_suggestion_is_refused_and_sends_nothing() {
    let (router, smtp, alice) = mailing_router().await;
    let unsigned = router.http.post(format!("{}/v1/feedback", router.base)).body(suggestion("hi", "1.3.0", "android")).send().await;
    assert_eq!(unsigned.unwrap().status(), 401);
    let mut forged = router.http.post(format!("{}/v1/feedback", router.base)).body(suggestion("spam", "1.3.0", "android"));
    for (name, value) in alice.sign("POST", "/v1/feedback", &suggestion("hi", "1.3.0", "android"), "n-1") {
        forged = forged.header(name, value);
    }
    assert_eq!(forged.send().await.unwrap().status(), 401);
    assert_eq!(Device::new(9).suggest(&router, suggestion("hi", "1.3.0", "android")).await, 401, "a device never registered");
    assert!(smtp.sent().is_empty());
}

#[tokio::test]
async fn a_device_sends_three_suggestions_a_day_and_another_can_still_send() {
    let (router, smtp, alice) = mailing_router().await;
    let bob = Device::new(2);
    bob.register(&router).await;
    let mut statuses = Vec::new();
    for n in 0..4 {
        statuses.push(alice.suggest(&router, suggestion(&format!("idea {n}"), "1.3.0", "android")).await);
    }
    assert_eq!(statuses, [204, 204, 204, 429]);
    assert_eq!(bob.suggest(&router, suggestion("mine", "1.3.0", "ios")).await, 204);
    assert_eq!(smtp.sent().len(), 4, "the refused one was not mailed");
}

#[tokio::test]
async fn above_the_total_cap_suggestions_are_refused() {
    let smtp = FakeSmtp::start().await;
    let feedback = FeedbackLimits { per_device: 3, total: 2, window: Duration::from_secs(60) };
    let router = router_mailing(smtp.mailer(), Limits { feedback, ..Limits::default() }).await;
    let (alice, bob, carol) = (Device::new(1), Device::new(2), Device::new(3));
    for device in [&alice, &bob, &carol] {
        device.register(&router).await;
    }
    assert_eq!(alice.suggest(&router, suggestion("one", "1.3.0", "android")).await, 204);
    assert_eq!(bob.suggest(&router, suggestion("two", "1.3.0", "android")).await, 204);
    assert_eq!(carol.suggest(&router, suggestion("three", "1.3.0", "android")).await, 429);
    assert_eq!(alice.suggest(&router, suggestion("four", "1.3.0", "android")).await, 429);
    assert_eq!(smtp.sent().len(), 2);
}

#[tokio::test]
async fn a_malformed_suggestion_is_refused_and_spends_nothing() {
    let (router, smtp, alice) = mailing_router().await;
    let refused = [
        suggestion("", "1.3.0", "android"),
        suggestion(" \n\t ", "1.3.0", "android"),
        suggestion(&"a".repeat(2001), "1.3.0", "android"),
        suggestion(&"👋".repeat(2001), "1.3.0", "android"),
        suggestion("hi", "1.3.0", "symbian"),
        suggestion("hi", "1.3.0", "Android"),
        suggestion("hi", "1.3.0\r\nBcc: a@b.c", "android"),
        suggestion("hi", "1.3.0 beta", "android"),
        suggestion("hi", "", "android"),
        suggestion("hi", "1..3", "android"),
        suggestion("hi", "1.2.3.4.5", "android"),
        suggestion("hi", "12345678.12345678", "android"),
        b"{\"text\": \"hi\", \"app\": \"1.3.0\"".to_vec(),
        serde_json::to_vec(&json!({ "text": "hi", "platform": "android" })).unwrap(),
        serde_json::to_vec(&json!({ "text": 7, "app": "1.3.0", "platform": "android" })).unwrap(),
    ];
    for body in refused {
        let shown = String::from_utf8_lossy(&body).chars().take(60).collect::<String>();
        assert_eq!(alice.suggest(&router, body).await, 400, "{shown}");
    }
    assert!(smtp.sent().is_empty());
    for app in ["1", "1.3", "10.20.30.4000"] {
        assert_eq!(alice.suggest(&router, suggestion("still mine", app, "ios")).await, 204, "{app}");
    }
    assert_eq!(alice.suggest(&router, suggestion("one more", "1.3.0", "ios")).await, 429, "the refused ones cost nothing");
    let platforms = ["android", "ios", "macos", "windows", "linux"];
    for (seed, platform) in (10..).zip(platforms) {
        let device = Device::new(seed);
        device.register(&router).await;
        assert_eq!(device.suggest(&router, suggestion("hi", "1.3.0", platform)).await, 204, "{platform}");
    }
}

#[tokio::test]
async fn while_the_mail_server_is_down_suggestions_fail_and_spend_nothing() {
    let (router, smtp, alice) = mailing_router().await;
    smtp.switch(false);
    for _ in 0..3 {
        assert_eq!(alice.suggest(&router, suggestion("hello?", "1.3.0", "android")).await, 503);
    }
    smtp.switch(true);
    for _ in 0..3 {
        assert_eq!(alice.suggest(&router, suggestion("hello", "1.3.0", "android")).await, 204);
    }
    assert_eq!(alice.suggest(&router, suggestion("hello", "1.3.0", "android")).await, 429);
    assert_eq!(smtp.sent().len(), 3);
}

#[tokio::test]
async fn without_mail_settings_suggestions_are_unavailable() {
    let router = router_mailing(None, Limits::default()).await;
    let alice = Device::new(1);
    alice.register(&router).await;
    assert_eq!(alice.suggest(&router, suggestion("hi", "1.3.0", "android")).await, 503);
    assert_eq!(alice.request(&router, "GET", "/v1/mailbox", vec![]).await.status(), 200, "the rest is unchanged");
}

#[tokio::test]
async fn long_texts_in_any_script_arrive_intact() {
    let (router, smtp, alice) = mailing_router().await;
    let letters = ['👋', 'م', 'ر', '\n', 'é', '中', 'ж'];
    let text: String = (0..2000).map(|i| letters[i % letters.len()]).collect();
    assert_eq!(text.chars().count(), 2000);
    assert!(text.len() > 4000, "far more bytes than characters");
    assert!(!text.ends_with('\n'));
    assert_eq!(alice.suggest(&router, suggestion(&format!("\n  {text}  \n"), "1.3.0", "android")).await, 204);
    assert_eq!(smtp.sent()[0].text(), text);
}

#[tokio::test]
async fn a_text_that_looks_like_mail_headers_stays_in_the_body() {
    let (router, smtp, alice) = mailing_router().await;
    let text = "Hello\r\nSubject: x\r\nBcc: a@b.c\r\n\r\n.\r\nRCPT TO:<b@c.d>\r\nafter the dot";
    assert_eq!(alice.suggest(&router, suggestion(text, "1.3.0", "android")).await, 204);
    let sent = smtp.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].recipients, ["<info@flickertalk.com>"]);
    assert_eq!(sent[0].header("subject"), ["FlickerTalk suggestion (android 1.3.0)"]);
    assert!(sent[0].header("bcc").is_empty());
    assert_eq!(sent[0].text(), text.replace("\r\n", "\n"));
}

#[tokio::test]
async fn a_suggestion_refused_while_another_is_in_flight_leaves_no_trace() {
    let (router, smtp, alice) = mailing_router().await;
    for n in 0..2 {
        assert_eq!(alice.suggest(&router, suggestion(&format!("idea {n}"), "1.3.0", "android")).await, 204);
    }
    smtp.hold(true);
    let in_flight = {
        let (base, http) = (router.base.clone(), router.http.clone());
        let body = suggestion("A", "1.3.0", "android");
        let mut request = http.post(format!("{base}/v1/feedback")).body(body.clone());
        for (name, value) in alice.sign("POST", "/v1/feedback", &body, "in-flight") {
            request = request.header(name, value);
        }
        tokio::spawn(async move { request.send().await.expect("answers").status().as_u16() })
    };
    assert!(soon(|| smtp.held() == 1).await, "A reached the mail server");
    assert_eq!(alice.suggest(&router, suggestion("B", "1.3.0", "android")).await, 429);
    smtp.release(false);
    assert_eq!(in_flight.await.unwrap(), 503);
    smtp.hold(false);
    assert_eq!(alice.suggest(&router, suggestion("C", "1.3.0", "android")).await, 204, "two delivered, one to go");
    assert_eq!(alice.suggest(&router, suggestion("D", "1.3.0", "android")).await, 429);
    assert_eq!(smtp.sent().len(), 3);
}

#[tokio::test]
async fn a_suggestion_body_over_32_kib_is_refused_and_spends_nothing() {
    let (router, smtp, alice) = mailing_router().await;
    let oversized = suggestion(&"a".repeat(32 * 1024), "1.3.0", "android");
    assert_eq!(alice.suggest(&router, oversized).await, 413);
    assert!(smtp.sent().is_empty());

    let text = "👋".repeat(2000);
    let escaped: String = text.encode_utf16().map(|unit| format!("\\u{unit:04x}")).collect();
    let body = format!(r#"{{"text":"{escaped}","app":"1.3.0","platform":"android"}}"#).into_bytes();
    assert!(body.len() > 24_000 && body.len() <= 32 * 1024);
    assert_eq!(alice.suggest(&router, body).await, 204);
    assert_eq!(smtp.sent()[0].text(), text);
    for _ in 0..2 {
        assert_eq!(alice.suggest(&router, suggestion("more", "1.3.0", "android")).await, 204);
    }
    assert_eq!(alice.suggest(&router, suggestion("more", "1.3.0", "android")).await, 429, "the 413 cost nothing");
}

async fn eventually<F, Fut>(condition: F) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..50 {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition().await
}

async fn closed(socket: &mut Socket) -> bool {
    loop {
        match timeout(Duration::from_secs(3), socket.next()).await {
            Err(_) => return false,
            Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

fn ban_file(text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ft-banned-{}", uuid::Uuid::now_v7()));
    std::fs::write(&path, text).expect("writes");
    path
}

impl Device {
    async fn register_in(&self, db: &Db) {
        db.register(&self.id(), &self.key.verifying_key().to_bytes(), blake3::hash(&self.capability).as_bytes(), 0)
            .await
            .expect("registers");
    }
}

#[tokio::test]
async fn a_banned_device_cannot_register() {
    let (alice, mallory) = (Device::new(1), Device::new(66));
    let router = router_banning(fresh_db().await, Bans::listed([mallory.id()]), None).await;
    assert_eq!(mallory.register(&router).await.status(), 403);
    assert!(router.db.signing_key(&mallory.id()).await.unwrap().is_none(), "nothing of it is kept");
    assert_eq!(alice.register(&router).await.status(), 204);
}

#[tokio::test]
async fn a_banned_device_and_its_mail_are_deleted_when_the_router_starts() {
    let before = router().await;
    let (alice, mallory) = (Device::new(1), Device::new(66));
    alice.register(&before).await;
    mallory.register(&before).await;
    assert_eq!(deposit(&before, &alice, alice.capability(), b"for alice".to_vec()).await.status(), 201);
    assert_eq!(deposit(&before, &mallory, mallory.capability(), b"for mallory".to_vec()).await.status(), 201);

    let after = router_banning(before.db.clone(), Bans::listed([mallory.id()]), None).await;
    let db = after.db.clone();
    assert!(eventually(|| async { db.signing_key(&mallory.id()).await.unwrap().is_none() }).await, "registration deleted");
    assert!(db.collect(&mallory.id()).await.unwrap().is_empty(), "its mail too");
    assert!(db.signing_key(&alice.id()).await.unwrap().is_some());
    assert_eq!(blobs(&collected(&after, &alice).await), [b"for alice".as_slice()]);
}

#[tokio::test]
async fn a_banned_device_is_refused_as_caller_and_as_target() {
    let waker = Arc::new(FakeWaker::default());
    let mallory = Device::new(66);
    let db = fresh_db().await;
    mallory.register_in(&db).await;
    let router = router_banning(db.clone(), Bans::listed([mallory.id()]), push_with(waker.clone())).await;
    assert!(eventually(|| async { db.signing_key(&mallory.id()).await.unwrap().is_none() }).await);
    mallory.register_in(&db).await;
    let sealed = PushVault::new(&[9; 32]).seal("mallory-token");
    assert!(db.set_push(&mallory.id(), FCM, &sealed).await.unwrap());

    assert_eq!(mallory.connect_status(&router).await, 403);
    assert_eq!(mallory.register(&router).await.status(), 403);
    let push = serde_json::to_vec(&json!({ "provider": "fcm", "token": "other" })).unwrap();
    let acknowledge = format!("/v1/mailbox/{}", uuid::Uuid::now_v7());
    for (method, path, body) in [
        ("GET", "/v1/mailbox", vec![]),
        ("DELETE", acknowledge.as_str(), vec![]),
        ("GET", "/v1/turn-credentials", vec![]),
        ("PUT", "/v1/device/push", push),
        ("DELETE", "/v1/device/push", vec![]),
        ("DELETE", "/v1/device", vec![]),
        ("POST", "/v1/feedback", suggestion("hello", "1.7.1", "ios")),
    ] {
        assert_eq!(mallory.request(&router, method, path, body).await.status(), 403, "{method} {path}");
    }

    assert_eq!(signal(&router, &mallory, mallory.capability(), b"offer".to_vec()).await.status(), 403);
    assert_eq!(call(&router, &mallory, mallory.capability(), b"call".to_vec()).await.status(), 403);
    assert_eq!(deposit(&router, &mallory, mallory.capability(), b"sealed".to_vec()).await.status(), 403);
    assert!(db.collect(&mallory.id()).await.unwrap().is_empty(), "nothing dropped into its mailbox");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(waker.woken().is_empty() && waker.rung().is_empty(), "nobody woke or rang it");
}

#[tokio::test]
async fn a_device_banned_while_connected_is_cut_off_until_the_ban_is_lifted() {
    let file = ban_file("# nobody yet\n");
    let bans = Bans::from_file(&file, Duration::from_millis(50)).expect("reads");
    let router = router_banning(fresh_db().await, bans, None).await;
    let (alice, mallory) = (Device::new(1), Device::new(66));
    assert_eq!(alice.register(&router).await.status(), 204);
    assert_eq!(mallory.register(&router).await.status(), 204);
    let mut socket = mallory.connect(&router).await;
    assert_eq!(next_json(&mut socket).await["kind"], "welcome");
    assert_eq!(deposit(&router, &mallory, mallory.capability(), b"sealed".to_vec()).await.status(), 201);

    std::fs::write(&file, format!("# report of 2026-10-28\n{}\n", mallory.id())).unwrap();
    assert!(closed(&mut socket).await, "its socket is closed");
    let db = router.db.clone();
    assert!(eventually(|| async { db.signing_key(&mallory.id()).await.unwrap().is_none() }).await);
    assert!(db.collect(&mallory.id()).await.unwrap().is_empty());
    assert_eq!(mallory.register(&router).await.status(), 403);
    assert_eq!(signal(&router, &mallory, mallory.capability(), b"offer".to_vec()).await.status(), 403);
    assert_eq!(alice.request(&router, "GET", "/v1/turn-credentials", vec![]).await.status(), 200, "alice goes on");

    std::fs::write(&file, "").unwrap();
    assert!(eventually(|| async { mallory.register(&router).await.status() == 204 }).await, "lifted");
    std::fs::remove_file(&file).unwrap();
}
