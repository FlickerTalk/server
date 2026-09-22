//! Router API v1 (Plan §7, §10, §13–19, §34, §106 M2).
//!
//! - `POST /v1/device/register`: signed with the key being registered; stores that key and the
//!   hash of the route capability. The app registers on every start.
//! - `GET /v1/connect`: signed WebSocket. The router sends a welcome (STUN and a temporary TURN
//!   user), the signals addressed to the device and a notice when mail arrives.
//! - `POST /v1/signal/{to}`: needs the recipient's capability; 404 when it is not connected.
//! - `POST /v1/mailbox/{to}`: needs the recipient's capability, not the sender's identity: the
//!   router does not learn who writes to whom through the mailbox.
//! - `GET /v1/mailbox`, `DELETE /v1/mailbox/{id}`: signed by the owner.
//! - `GET /v1/turn-credentials`, `DELETE /v1/device`: signed.
//! - `PUT /v1/device/push`, `DELETE /v1/device/push`: signed; where the device can be woken, kept
//!   encrypted (§8). A device that is not connected is woken when a signal or mail arrives for it,
//!   with nothing in the push (§12).
//!
//! Nothing is logged (§71). Connections live in memory, so signalling needs a single replica
//! until it is shared through PostgreSQL (§106).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use crate::db::{Db, MAX_BLOB};
use crate::push::{Push, Wake, FCM, MAX_TOKEN};
use crate::turn::TurnIssuer;

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
    stun: Vec<String>,
    turn: Option<TurnIssuer>,
    push: Option<Arc<Push>>,
}

impl Hub {
    pub fn new(db: Arc<Db>, stun: Vec<String>, turn: Option<TurnIssuer>, push: Option<Arc<Push>>) -> Self {
        Self { db, guard: ReplayGuard::default(), online: Mutex::default(), stun, turn, push }
    }
}

pub fn routes(hub: Arc<Hub>) -> Router {
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
    Ok(signature.device)
}

/// The recipient's route capability must come with anything addressed to it (§34).
async fn check_capability(hub: &Hub, to: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
    let capability = headers.get("ft-capability").and_then(|value| value.to_str().ok()).ok_or(StatusCode::FORBIDDEN)?;
    let capability: [u8; 32] = decode_base64(capability)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    match hub.db.capability_matches(to, &capability).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(StatusCode::FORBIDDEN),
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
}

async fn register(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, StatusCode> {
    let registration: Registration = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = key32(&registration.signing_key)?;
    let hash = key32(&registration.capability_hash)?;
    let device =
        authenticate(&hub, "POST", "/v1/device/register", Signature::from_headers(&headers), &body, Some(key)).await?;
    hub.db.register(&device, &key, &hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn forget(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Result<StatusCode, StatusCode> {
    let device = authenticate(&hub, "DELETE", "/v1/device", Signature::from_headers(&headers), b"", None).await?;
    hub.db.forget(&device).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    hub.online.lock().await.remove(&device);
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
    if target.provider != FCM || target.token.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if target.token.len() > MAX_TOKEN {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let push = hub.push.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
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
fn wake(hub: &Arc<Hub>, device: &str) {
    let Some(push) = hub.push.clone() else { return };
    if !push.limiter.allow(device) {
        return;
    }
    let (hub, device) = (hub.clone(), device.to_owned());
    tokio::spawn(async move {
        let Ok(Some((_, sealed))) = hub.db.push_of(&device).await else { return };
        let Ok(token) = push.vault.open(&sealed) else { return };
        if push.waker.wake(&token).await == Wake::Unregistered {
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
    // A newer connection of the same device replaces the older one.
    hub.online.lock().await.insert(device.clone(), outbox.clone());

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

    let mut online = hub.online.lock().await;
    if online.get(&device).is_some_and(|current| current.same_channel(&outbox)) {
        online.remove(&device);
    }
}

async fn notify(hub: &Hub, device: &str, message: Value) -> bool {
    let online = hub.online.lock().await.get(device).cloned();
    online.is_some_and(|outbox| outbox.send(message.to_string()).is_ok())
}

async fn signal(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if let Err(status) = check_capability(&hub, &to, &headers).await {
        return status;
    }
    if body.len() > MAX_SIGNAL {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let message = json!({ "kind": "signal", "signal": STANDARD_NO_PAD.encode(&body) });
    if notify(&hub, &to, message).await {
        StatusCode::ACCEPTED
    } else {
        wake(&hub, &to);
        StatusCode::NOT_FOUND
    }
}

async fn deposit(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if let Err(status) = check_capability(&hub, &to, &headers).await {
        return status;
    }
    if body.len() > MAX_BLOB {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    match hub.db.deposit(&to, &body, MAILBOX_TTL).await {
        Ok(_) => {
            if !notify(&hub, &to, json!({ "kind": "mail" })).await {
                wake(&hub, &to);
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
