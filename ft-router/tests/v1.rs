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
use ft_router::{app, Config};
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
}

async fn router() -> Router {
    let url = std::env::var("FT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/ft_router_test".to_owned());
    let db = Db::connect_isolated(&url).await.expect("test database");
    let config = Config {
        stun: vec!["stun:turn.example:3478".to_owned()],
        turn: Some(TurnIssuer::new(b"secret".to_vec(), vec!["turn:turn.example:3478".to_owned()], Duration::from_secs(600))),
        db: Some(Arc::new(db)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app(config)).await.expect("serves") });
    Router { base: format!("http://{address}"), http: reqwest::Client::new() }
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
        let headers = self.sign("GET", path, b"", "connect-nonce");
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
