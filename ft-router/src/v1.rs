//! Router API v1 (Plan §7, §10, §13–19, §34, §106 M2).
//!
//! - `POST /v1/device/register`: signed with the key being registered; stores that key and the
//!   hash of the route capability. The app registers on every start. Since 0.5.0 it may carry
//!   `silent_slots` (0–255, bit i = slot i): no push goes out for those slots, sessions the user
//!   has left; slot 0, the main list, always gets them. Each registration replaces the mask. Since
//!   0.6.0 a silent slot is unreachable, not only quiet (see below); a registration that clears a
//!   bit makes that slot's withheld mail collectable and tells a connected device.
//! - `GET /v1/connect`: signed WebSocket. The router sends a welcome (STUN and a temporary TURN
//!   user), the signals addressed to the device and a notice when mail arrives.
//! - `POST /v1/signal/{to}`: needs the recipient's capability. `202` when the recipient is
//!   connected and the signal went to its socket. When it is not connected, `404` as before, now
//!   with `ft-retained: 1` (0.4.0): the router woke it (or rang it, with `ft-call: 1`; neither for a
//!   silent slot, with the same answer) and holds the signal in memory for up to 55 s, to hand it over, in order and once, right after the welcome
//!   of its next `/v1/connect` (see `waiting.rs`: eight per recipient and 32 MiB in all, the oldest
//!   dropped first). The status stays `404` on purpose: apps before 0.4 read `202` as "connected"
//!   and would wait for a data channel before falling back to the mailbox; with `404` they go on as
//!   they did, and a sender that knows the header keeps its offer open and waits for the answer.
//!   A signal through a silent slot (0.6.0) never reaches the device, connected or not: it is
//!   neither forwarded nor held, and the sender gets the same `404` with `ft-retained: 1`.
//! - `POST /v1/mailbox/{to}`: needs the recipient's capability, not the sender's identity: the
//!   router does not learn who writes to whom through the mailbox. Each blob keeps the slot it
//!   came through (0.6.0): mail through a silent slot is kept, with the same answer, but neither
//!   announced nor collectable until a registration clears that slot's bit.
//! - `GET /v1/mailbox`, `DELETE /v1/mailbox/{id}`: signed by the owner.
//! - `GET /v1/turn-credentials`, `DELETE /v1/device`: signed.
//! - `PUT /v1/device/push`, `DELETE /v1/device/push`: signed; where the device can be woken, kept
//!   encrypted (§8). A device that is not connected is woken when a signal or mail arrives for it,
//!   with nothing in the push (§12).
//!
//! Requests are limited per device, per recipient and per origin (`limits.rs`, §91): 429 beyond.
//!
//! Nothing is logged (§71). Connections and the signals waiting for a device live in memory only
//! (never in the database, on disk or in a log), so signalling needs a single replica until it is
//! shared between replicas (§106).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Weak;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

use crate::auth::{self, decode_base64, ReplayGuard, SignedRequest, STANDARD_NO_PAD};
use crate::db::{Db, Route, MAX_BLOB};
use crate::limits::{Limiters, Limits};
use crate::push::{Push, Wake, MAX_TOKEN};
use crate::turn::TurnIssuer;
use crate::waiting::{Retention, Waiting, SWEEP_EVERY};

/// How long a blob waits in a mailbox (§19, provisional).
pub const MAILBOX_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Signals are small: a session description with its candidates, encrypted.
const MAX_SIGNAL: usize = 16 * 1024;
/// Keeps idle connections open through the load balancer (its HTTP timeout is 300 s).
const KEEPALIVE: Duration = Duration::from_secs(60);

pub struct Hub {
    db: Arc<Db>,
    guard: ReplayGuard,
    online: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
    /// Signals for devices that are not connected (§15). Held and handed over under the lock of
    /// `online`, so a device gets them before anything sent to it once it is connected.
    waiting: Waiting,
    stun: Vec<String>,
    turn: Option<TurnIssuer>,
    push: Option<Arc<Push>>,
    limiters: Limiters,
}

impl Hub {
    pub fn new(db: Arc<Db>, stun: Vec<String>, turn: Option<TurnIssuer>, push: Option<Arc<Push>>, limits: Limits) -> Self {
        Self {
            db,
            guard: ReplayGuard::default(),
            online: Mutex::default(),
            waiting: Waiting::new(Retention::default()),
            stun,
            turn,
            push,
            limiters: Limiters::new(limits),
        }
    }

    /// One more request from this origin; 429 once it is over its share.
    fn limit_origin(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if self.limiters.origin.allow(&self.limiters.origin(headers)) {
            Ok(())
        } else {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }

    fn limit_recipient(&self, to: &str) -> Result<(), StatusCode> {
        if self.limiters.recipient.allow(to) {
            Ok(())
        } else {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

pub fn routes(hub: Arc<Hub>) -> Router {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(sweep(Arc::downgrade(&hub)));
    }
    Router::new()
        .route("/v1/device/register", post(register))
        .route("/v1/device", delete(forget))
        .route("/v1/device/push", put(set_push).delete(clear_push))
        .route("/v1/connect", get(connect))
        .route("/v1/signal/{to}", post(signal))
        .route("/v1/mailbox", get(collect))
        .route("/v1/mailbox/{target}", post(deposit).delete(acknowledge))
        .route("/v1/turn-credentials", get(turn_credentials))
        .with_state(hub)
}

/// Frees the signals that waited too long, while the hub lives.
async fn sweep(hub: Weak<Hub>) {
    let mut every = tokio::time::interval(SWEEP_EVERY);
    loop {
        every.tick().await;
        let Some(hub) = hub.upgrade() else { return };
        hub.waiting.sweep(Instant::now());
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

struct Signature {
    device: String,
    time_ms: i64,
    nonce: String,
    signature: String,
}

impl Signature {
    fn from_pairs(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        Some(Self {
            device: get("ft-device")?,
            time_ms: get("ft-time")?.parse().ok()?,
            nonce: get("ft-nonce")?,
            signature: get("ft-signature")?,
        })
    }

    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        Self::from_pairs(|name| headers.get(name)?.to_str().ok().map(str::to_owned))
    }
}

/// Checks a signed request and returns the device that made it. `key` is given only when the
/// request registers that very key; otherwise it comes from the registry.
async fn authenticate(
    hub: &Hub,
    method: &str,
    path: &str,
    signature: Option<Signature>,
    body: &[u8],
    key: Option<[u8; 32]>,
) -> Result<String, StatusCode> {
    let signature = signature.ok_or(StatusCode::UNAUTHORIZED)?;
    let key = match key {
        Some(key) if auth::device_id(&key) == signature.device => key,
        Some(_) => return Err(StatusCode::UNAUTHORIZED),
        None => hub
            .db
            .signing_key(&signature.device)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?,
    };
    let request = SignedRequest { method, path, time_ms: signature.time_ms, nonce: &signature.nonce, body };
    auth::verify(&key, &request, &signature.signature).map_err(|_| StatusCode::UNAUTHORIZED)?;
    hub.guard
        .admit(&signature.device, &signature.nonce, signature.time_ms, now_ms())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !hub.limiters.device.allow(&signature.device) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(signature.device)
}

/// The recipient's route capability must come with anything addressed to it (§34). Returns which
/// of its capabilities it was (app#9), and whether that slot is silent (2026-10-01).
async fn check_capability(hub: &Hub, to: &str, headers: &HeaderMap) -> Result<Route, StatusCode> {
    let capability = headers.get("ft-capability").and_then(|value| value.to_str().ok()).ok_or(StatusCode::FORBIDDEN)?;
    let capability: [u8; 32] = decode_base64(capability)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    match hub.db.route(to, &capability).await {
        Ok(Some(route)) => Ok(route),
        Ok(None) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn key32(text: &str) -> Result<[u8; 32], StatusCode> {
    decode_base64(text).ok().and_then(|bytes| bytes.try_into().ok()).ok_or(StatusCode::BAD_REQUEST)
}

#[derive(Deserialize)]
struct Registration {
    signing_key: String,
    capability_hash: String,
    /// Eight capabilities, always eight (app#9); apps from before send only the one above.
    #[serde(default)]
    capability_hashes: Option<Vec<String>>,
    /// Which slots are silent (2026-10-01): bit i set means slot i, a session the user has left,
    /// gets no push. An integer 0–255, anything else is refused; absent (apps from before) is 0.
    #[serde(default)]
    silent_slots: u8,
}

async fn register(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, StatusCode> {
    hub.limit_origin(&headers)?;
    let registration: Registration = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = key32(&registration.signing_key)?;
    let hash = key32(&registration.capability_hash)?;
    let eight = match &registration.capability_hashes {
        Some(hashes) if hashes.len() == 8 => {
            let hashes: Vec<[u8; 32]> = hashes.iter().map(|hash| key32(hash)).collect::<Result<_, _>>()?;
            Some(<[[u8; 32]; 8]>::try_from(hashes).map_err(|_| StatusCode::BAD_REQUEST)?)
        }
        Some(_) => return Err(StatusCode::BAD_REQUEST),
        None => None,
    };
    let device =
        authenticate(&hub, "POST", "/v1/device/register", Signature::from_headers(&headers), &body, Some(key)).await?;
    // The main list always rings: its bit is never kept.
    let silent_slots = registration.silent_slots & !1;
    let before = hub.db.register(&device, &key, &hash, silent_slots).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(eight) = eight {
        hub.db.set_capabilities(&device, &eight).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    // Sessions opened again (2026-10-01): the mail withheld for them is collectable now, and a
    // connected phone hears of it as of any mail. A notice missed here costs nothing: the app
    // collects whenever it connects.
    let opened = before & !silent_slots;
    if opened != 0 && matches!(hub.db.mail_through(&device, opened).await, Ok(true)) {
        notify(&hub, &device, json!({ "kind": "mail" })).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn forget(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Result<StatusCode, StatusCode> {
    let device = authenticate(&hub, "DELETE", "/v1/device", Signature::from_headers(&headers), b"", None).await?;
    hub.db.forget(&device).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut online = hub.online.lock().await;
    online.remove(&device);
    hub.waiting.take(&device, Instant::now());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PushTarget {
    provider: String,
    token: String,
}

async fn set_push(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, StatusCode> {
    let device = authenticate(&hub, "PUT", "/v1/device/push", Signature::from_headers(&headers), &body, None).await?;
    let target: PushTarget = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if target.token.len() > MAX_TOKEN {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let push = hub.push.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    // FCM for Android, APNs for iPhones (2026-09-28); only a token its provider could use is kept.
    let waker = push.waker(&target.provider).ok_or(StatusCode::BAD_REQUEST)?;
    if !waker.accepts(&target.token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sealed = push.vault.seal(&target.token);
    match hub.db.set_push(&device, &target.provider, &sealed).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(StatusCode::UNAUTHORIZED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn clear_push(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Result<StatusCode, StatusCode> {
    let device = authenticate(&hub, "DELETE", "/v1/device/push", Signature::from_headers(&headers), b"", None).await?;
    hub.db.clear_push(&device).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Wakes a device that is not connected, in the background and at most once in a while. A token
/// the provider no longer knows is forgotten.
fn wake(hub: &Arc<Hub>, device: &str, slot: u8) {
    wake_as(hub, device, slot, false);
}

/// Wakes the device, or rings it when the signal is a call. Nothing goes out for a slot the device
/// said is silent (2026-10-01), a session the user has left; that is decided in the background,
/// after the pace is taken, so the sender's answer, its timing and the pace are the same whether
/// the push goes out or not.
fn wake_as(hub: &Arc<Hub>, device: &str, slot: u8, call: bool) {
    let Some(push) = hub.push.clone() else { return };
    // Each capability has its own pace: a quiet one never holds back the device's own (app#9).
    // Rings and wakes have theirs too (0.5.1): a call is now or never, so a wake never holds it
    // back, and a ring never holds back the mail that comes after it.
    let paced = if call { push.ring_limiter.allow(device, slot) } else { push.limiter.allow(&format!("{device}/{slot}")) };
    if !paced {
        return;
    }
    let (hub, device) = (hub.clone(), device.to_owned());
    tokio::spawn(async move {
        let Ok(Some((provider, sealed))) = hub.db.push_for(&device, slot).await else { return };
        let Some(waker) = push.waker(&provider) else { return };
        let Ok(token) = push.vault.open(&sealed) else { return };
        let woke = if call { waker.ring(&token, slot).await } else { waker.wake(&token, slot).await };
        if woke == Wake::Unregistered {
            let _ = hub.db.clear_push(&device).await;
        }
    });
}

async fn connect(
    State(hub): State<Arc<Hub>>,
    Query(query): Query<HashMap<String, String>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let signature = Signature::from_pairs(|name| query.get(name).cloned());
    match authenticate(&hub, "GET", "/v1/connect", signature, b"", None).await {
        Ok(device) => upgrade.on_upgrade(move |socket| serve(hub, device, socket)),
        Err(status) => status.into_response(),
    }
}

async fn serve(hub: Arc<Hub>, device: String, mut socket: WebSocket) {
    let (outbox, mut pending) = mpsc::unbounded_channel::<String>();
    {
        // A newer connection of the same device replaces the older one. What waited for the
        // device goes first, in order: signals sent from now on queue behind it.
        let mut online = hub.online.lock().await;
        online.insert(device.clone(), outbox.clone());
        // It takes the signals its rings were for: the next call is a new one (0.5.1).
        if let Some(push) = &hub.push {
            push.ring_limiter.picked_up(&device);
        }
        for signal in hub.waiting.take(&device, Instant::now()) {
            let _ = outbox.send(signal_frame(&signal));
        }
    }

    let turn = hub.turn.as_ref().map(|issuer| issuer.issue(SystemTime::now()));
    let welcome = json!({ "kind": "welcome", "stun": hub.stun, "turn": turn }).to_string();
    let mut alive = socket.send(Message::Text(welcome.into())).await.is_ok();
    let mut keepalive = tokio::time::interval(KEEPALIVE);

    while alive {
        tokio::select! {
            Some(text) = pending.recv() => alive = socket.send(Message::Text(text.into())).await.is_ok(),
            incoming = socket.recv() => alive = matches!(incoming, Some(Ok(message)) if !matches!(message, Message::Close(_))),
            _ = keepalive.tick() => alive = socket.send(Message::Ping(Bytes::new())).await.is_ok(),
        }
    }

    // From here a signal for this device cannot reach the socket: sending to it fails, so the
    // signal waits for the next connection instead of vanishing in this queue.
    pending.close();
    let mut online = hub.online.lock().await;
    if online.get(&device).is_some_and(|current| current.same_channel(&outbox)) {
        online.remove(&device);
    }
}

async fn notify(hub: &Hub, device: &str, message: Value) -> bool {
    let online = hub.online.lock().await.get(device).cloned();
    online.is_some_and(|outbox| outbox.send(message.to_string()).is_ok())
}

/// A signal as the socket carries it.
fn signal_frame(signal: &[u8]) -> String {
    json!({ "kind": "signal", "signal": STANDARD_NO_PAD.encode(signal) }).to_string()
}

async fn signal(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    // Everything that refuses a signal comes before holding it: the limits and the size bound
    // what a sender can make the router keep.
    if let Err(status) = hub.limit_origin(&headers) {
        return status.into_response();
    }
    let route = match check_capability(&hub, &to, &headers).await {
        Ok(route) => route,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = hub.limit_recipient(&to) {
        return status.into_response();
    }
    if body.len() > MAX_SIGNAL {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    // A silent slot is a session the user has left (2026-10-01): its signal never reaches the
    // device, connected or not. It is not held either, so nothing sent while the session was left
    // is handed over once the user comes back to it; a sender that still wants through sends again,
    // as it does for a phone that stayed off. The sender gets the answer of a phone that is not
    // connected, and the push path below is taken the same way (it sends nothing for a silent slot).
    if !route.silent {
        let online = hub.online.lock().await;
        if online.get(&to).is_some_and(|outbox| outbox.send(signal_frame(&body)).is_ok()) {
            return StatusCode::ACCEPTED.into_response();
        }
        hub.waiting.hold(&to, body.to_vec(), Instant::now());
    }
    // The caller says a signal is a call (2026-09-28): an iPhone rings through CallKit. That it
    // is a call is all the router learns; not who, nor voice or video.
    let call = headers.get("ft-call").is_some_and(|value| value == "1");
    wake_as(&hub, &to, route.slot, call);
    (StatusCode::NOT_FOUND, [("ft-retained", "1")]).into_response()
}

async fn deposit(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if let Err(status) = hub.limit_origin(&headers) {
        return status;
    }
    let route = match check_capability(&hub, &to, &headers).await {
        Ok(route) => route,
        Err(status) => return status,
    };
    if let Err(status) = hub.limit_recipient(&to) {
        return status;
    }
    if body.len() > MAX_BLOB {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    match hub.db.deposit(&to, route.slot, &body, MAILBOX_TTL).await {
        Ok(_) => {
            // Mail through a silent slot (2026-10-01) is kept but withheld: the phone hears nothing
            // of it, open or closed, and the push path is taken as for a phone that is not
            // connected (it sends nothing for a silent slot). The sender's answer is the same.
            if route.silent || !notify(&hub, &to, json!({ "kind": "mail" })).await {
                wake(&hub, &to, route.slot);
            }
            StatusCode::CREATED
        }
        Err(_) => StatusCode::INSUFFICIENT_STORAGE,
    }
}

async fn collect(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    let device = authenticate(&hub, "GET", "/v1/mailbox", Signature::from_headers(&headers), b"", None).await?;
    let blobs = hub.db.collect(&device).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let listed = blobs
        .into_iter()
        .map(|(id, blob)| json!({ "id": id.to_string(), "blob": STANDARD_NO_PAD.encode(blob) }))
        .collect();
    Ok(Json(Value::Array(listed)))
}

async fn acknowledge(State(hub): State<Arc<Hub>>, Path(id): Path<String>, headers: HeaderMap) -> Result<StatusCode, StatusCode> {
    let path = format!("/v1/mailbox/{id}");
    let device = authenticate(&hub, "DELETE", &path, Signature::from_headers(&headers), b"", None).await?;
    let id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    match hub.db.acknowledge(&device, id).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn turn_credentials(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    authenticate(&hub, "GET", "/v1/turn-credentials", Signature::from_headers(&headers), b"", None).await?;
    let issuer = hub.turn.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::to_value(issuer.issue(SystemTime::now())).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_read_from_headers() {
        let mut headers = HeaderMap::new();
        for (name, value) in [("ft-device", "ft_a"), ("ft-time", "12"), ("ft-nonce", "n"), ("ft-signature", "s")] {
            headers.insert(name, value.parse().unwrap());
        }
        let signature = Signature::from_headers(&headers).expect("complete");
        assert_eq!((signature.device.as_str(), signature.time_ms), ("ft_a", 12));
        headers.remove("ft-nonce");
        assert!(Signature::from_headers(&headers).is_none());
    }

    #[test]
    fn mail_waits_a_week_at_most() {
        assert_eq!(MAILBOX_TTL, Duration::from_secs(604_800));
    }
}
