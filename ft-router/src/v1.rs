//! Connections and held signals live in this process only, so signalling needs a single replica.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Weak;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

use crate::auth::{self, decode_base64, ReplayGuard, SignedRequest, STANDARD_NO_PAD};
use crate::bans::Bans;
use crate::db::{CallRule, Db, Route, MAX_BLOB};
use crate::limits::{Limiters, Limits};
use crate::mail::Mailer;
use crate::push::{silent, Push, Wake, MAX_TOKEN};
use crate::turn::TurnIssuer;
use crate::waiting::{Retention, Waiting, SWEEP_EVERY};

pub const MAILBOX_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_SIGNAL: usize = 16 * 1024;
/// Pings under the load balancer's 300 s HTTP timeout.
const KEEPALIVE: Duration = Duration::from_secs(60);

pub struct Hub {
    db: Arc<Db>,
    guard: ReplayGuard,
    online: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
    /// Held and handed over under the online lock, so held signals go out before newer ones.
    waiting: Waiting,
    stun: Vec<String>,
    turn: Option<TurnIssuer>,
    push: Option<Arc<Push>>,
    mail: Option<Arc<Mailer>>,
    limiters: Limiters,
    bans: Arc<Bans>,
}

impl Hub {
    pub fn new(
        db: Arc<Db>,
        stun: Vec<String>,
        turn: Option<TurnIssuer>,
        push: Option<Arc<Push>>,
        mail: Option<Arc<Mailer>>,
        limits: Limits,
        bans: Arc<Bans>,
    ) -> Self {
        Self {
            db,
            guard: ReplayGuard::default(),
            online: Mutex::default(),
            waiting: Waiting::new(Retention::default()),
            stun,
            turn,
            push,
            mail,
            limiters: Limiters::new(limits),
            bans,
        }
    }

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
        runtime.spawn(enforce_bans(Arc::downgrade(&hub)));
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
        .route("/v1/feedback", post(feedback).layer(DefaultBodyLimit::max(MAX_SUGGESTION_BODY)))
        .with_state(hub)
}

async fn sweep(hub: Weak<Hub>) {
    let mut every = tokio::time::interval(SWEEP_EVERY);
    loop {
        every.tick().await;
        let Some(hub) = hub.upgrade() else { return };
        hub.waiting.sweep(Instant::now());
    }
}

async fn enforce_bans(weak: Weak<Hub>) {
    let mut pending = true;
    loop {
        let Some(hub) = weak.upgrade() else { return };
        if pending {
            pending = eject_banned(&hub).await.is_err();
        }
        let every = hub.bans.every().unwrap_or(crate::bans::RELOAD_EVERY);
        drop(hub);
        tokio::time::sleep(every).await;
        let Some(hub) = weak.upgrade() else { return };
        match hub.bans.reload() {
            Ok(changed) => pending |= changed,
            Err(error) => eprintln!("the ban list could not be read again, the last one read stays: {error:#}"),
        }
    }
}

async fn eject_banned(hub: &Hub) -> anyhow::Result<()> {
    let mut result = Ok(());
    for device in hub.bans.devices() {
        {
            let mut online = hub.online.lock().await;
            online.remove(&device);
            hub.waiting.take(&device, Instant::now());
        }
        if let Err(error) = hub.db.forget(&device).await {
            result = Err(error);
        }
    }
    result
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

    fn present(headers: &HeaderMap) -> bool {
        ["ft-device", "ft-time", "ft-nonce", "ft-signature"].into_iter().any(|name| headers.contains_key(name))
    }
}

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
    // Checked after the signature so an unsigned request can't find out a device is banned.
    if hub.bans.is_banned(&signature.device) {
        return Err(StatusCode::FORBIDDEN);
    }
    hub.guard
        .admit(&signature.device, &signature.nonce, signature.time_ms, now_ms())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !hub.limiters.device.allow(&signature.device) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(signature.device)
}

/// A banned recipient gets the same 403, after the same lookup, as a wrong capability.
async fn check_capability(hub: &Hub, to: &str, headers: &HeaderMap) -> Result<(Route, [u8; 32]), StatusCode> {
    let capability = headers.get("ft-capability").and_then(|value| value.to_str().ok()).ok_or(StatusCode::FORBIDDEN)?;
    let capability: [u8; 32] = decode_base64(capability)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    match hub.db.route(to, &capability).await {
        Ok(Some(route)) if !hub.bans.is_banned(to) => Ok((route, capability)),
        Ok(_) => Err(StatusCode::FORBIDDEN),
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
    #[serde(default)]
    capability_hashes: Option<Vec<String>>,
    #[serde(default)]
    silent_slots: u8,
    #[serde(default)]
    call_rules: Option<Vec<ListedCallRule>>,
}

const MAX_CALL_RULES: usize = 1024;

#[derive(Deserialize)]
struct ListedCallRule {
    caller: String,
    rule: String,
}

fn call_rules(listed: &[ListedCallRule]) -> Result<Vec<([u8; 32], CallRule)>, StatusCode> {
    if listed.len() > MAX_CALL_RULES {
        return Err(StatusCode::BAD_REQUEST);
    }
    listed
        .iter()
        .map(|entry| {
            let rule = match entry.rule.as_str() {
                "quiet" => CallRule::Quiet,
                "none" => CallRule::NoPush,
                _ => return Err(StatusCode::BAD_REQUEST),
            };
            Ok((key32(&entry.caller)?, rule))
        })
        .collect()
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
    let call_rules = registration.call_rules.as_deref().map(call_rules).transpose()?;
    let device =
        authenticate(&hub, "POST", "/v1/device/register", Signature::from_headers(&headers), &body, Some(key)).await?;
    // bit 0 is the main list, which always rings
    let silent_slots = registration.silent_slots & !1;
    let before = hub.db.register(&device, &key, &hash, silent_slots).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(eight) = eight {
        hub.db.set_capabilities(&device, &eight).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    if let Some(call_rules) = call_rules {
        hub.db.set_call_rules(&device, &call_rules).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
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

#[derive(Clone, Copy)]
enum Nudge {
    Wake,
    Ring,
    QuietRing,
}

fn wake(hub: &Arc<Hub>, device: &str, slot: u8) {
    wake_as(hub, device, slot, Nudge::Wake);
}

/// Silent slots are checked in the background, after the pace is taken, so the sender sees the
/// same answer and timing whether a push goes out or not.
fn wake_as(hub: &Arc<Hub>, device: &str, slot: u8, nudge: Nudge) {
    let Some(push) = hub.push.clone() else { return };
    let paced = match nudge {
        Nudge::Ring => push.ring_limiter.allow(device, slot),
        Nudge::Wake | Nudge::QuietRing => push.limiter.allow(&format!("{device}/{slot}")),
    };
    if !paced {
        return;
    }
    let (hub, device) = (hub.clone(), device.to_owned());
    tokio::spawn(async move {
        let Ok(Some((provider, sealed))) = hub.db.push_for(&device, slot).await else { return };
        let Some(waker) = push.waker(&provider) else { return };
        let Ok(token) = push.vault.open(&sealed) else { return };
        let woke = match nudge {
            Nudge::Wake => waker.wake(&token, slot).await,
            Nudge::Ring => waker.ring(&token, slot).await,
            Nudge::QuietRing => waker.ring_quietly(&token, slot).await,
        };
        if woke == Wake::Unregistered {
            let _ = hub.db.clear_push(&device).await;
        }
    });
}

/// The rule is looked up in the background, so the caller gets the same answer and timing whatever it is.
fn ring_as_ruled(hub: &Arc<Hub>, device: &str, slot: u8, caller: [u8; 32]) {
    if hub.push.is_none() {
        return;
    }
    let (hub, device) = (hub.clone(), device.to_owned());
    tokio::spawn(async move {
        match hub.db.call_rule(&device, &caller).await {
            Ok(None) => wake_as(&hub, &device, slot, Nudge::Ring),
            Ok(Some(CallRule::Quiet)) => wake_as(&hub, &device, slot, Nudge::QuietRing),
            Ok(Some(CallRule::NoPush)) | Err(_) => {}
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
    let mut bans = hub.bans.subscribe();
    if hub.bans.is_banned(&device) {
        return;
    }
    let (outbox, mut pending) = mpsc::unbounded_channel::<String>();
    {
        // If the mask can't be read, only the main list's signals go out.
        let silent_slots = match hub.db.silent_slots(&device).await {
            Ok(Some(mask)) => mask,
            _ => !1,
        };
        let mut online = hub.online.lock().await;
        online.insert(device.clone(), outbox.clone());
        if let Some(push) = &hub.push {
            push.ring_limiter.picked_up(&device);
        }
        for (slot, signal) in hub.waiting.take(&device, Instant::now()) {
            if !silent(silent_slots, slot) {
                let _ = outbox.send(signal_frame(&signal));
            }
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
            Ok(()) = bans.changed() => alive = !hub.bans.is_banned(&device),
        }
    }

    // Close first so later signals fail to send and get held for the next connection.
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

fn signal_frame(signal: &[u8]) -> String {
    json!({ "kind": "signal", "signal": STANDARD_NO_PAD.encode(signal) }).to_string()
}

async fn signal(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(status) = hub.limit_origin(&headers) {
        return status.into_response();
    }
    let (route, capability) = match check_capability(&hub, &to, &headers).await {
        Ok(checked) => checked,
        Err(status) => return status.into_response(),
    };
    let call = headers.get("ft-call").is_some_and(|value| value == "1");
    let caller = if call && Signature::present(&headers) {
        let path = format!("/v1/signal/{to}");
        match authenticate(&hub, "POST", &path, Signature::from_headers(&headers), &body, None).await {
            Ok(caller) => Some(caller),
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    if let Err(status) = hub.limit_recipient(&to) {
        return status.into_response();
    }
    if body.len() > MAX_SIGNAL {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    // Signals through a silent slot are dropped, with the same answer as for an offline phone.
    if !route.silent {
        let online = hub.online.lock().await;
        if online.get(&to).is_some_and(|outbox| outbox.send(signal_frame(&body)).is_ok()) {
            return StatusCode::ACCEPTED.into_response();
        }
        hub.waiting.hold(&to, route.slot, body.to_vec(), Instant::now());
    }
    // Only a signed call tells the router who calls, and that must never be stored or logged.
    match caller {
        Some(caller) => ring_as_ruled(&hub, &to, route.slot, auth::caller_tag(&capability, &caller)),
        None => wake_as(&hub, &to, route.slot, if call { Nudge::Ring } else { Nudge::Wake }),
    }
    // Apps before 0.4 read 202 as "connected" and never fall back to the mailbox, hence 404.
    (StatusCode::NOT_FOUND, [("ft-retained", "1")]).into_response()
}

/// Deliberately takes no sender identity. The router must not learn who writes to whom.
async fn deposit(State(hub): State<Arc<Hub>>, Path(to): Path<String>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if let Err(status) = hub.limit_origin(&headers) {
        return status;
    }
    let (route, _) = match check_capability(&hub, &to, &headers).await {
        Ok(checked) => checked,
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
            // Silent-slot mail is kept but not announced, and the sender gets the same answer.
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

const PLATFORMS: [&str; 5] = ["android", "ios", "macos", "windows", "linux"];
/// characters, after trimming
const MAX_SUGGESTION: usize = 2000;
/// 2000 characters at 12 bytes each (an emoji as two \uXXXX escapes) still fit.
const MAX_SUGGESTION_BODY: usize = 32 * 1024;
const ALL_SUGGESTIONS: &str = "all";

#[derive(Deserialize)]
struct Suggestion {
    text: String,
    app: String,
    platform: String,
}

impl Suggestion {
    /// Version and platform end up in the subject, so only digits, dots and known platforms pass.
    fn mail(&self) -> Option<(String, &str)> {
        let text = self.text.trim();
        let characters = text.chars().count();
        let well_formed = (1..=MAX_SUGGESTION).contains(&characters)
            && app_version(&self.app)
            && PLATFORMS.contains(&self.platform.as_str());
        well_formed.then(|| (format!("FlickerTalk suggestion ({} {})", self.platform, self.app), text))
    }
}

fn app_version(version: &str) -> bool {
    version.len() <= 16
        && version.split('.').count() <= 4
        && version.split('.').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Never store or log the text, and never put the device id in the mail.
async fn feedback(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, StatusCode> {
    let device = authenticate(&hub, "POST", "/v1/feedback", Signature::from_headers(&headers), &body, None).await?;
    let suggestion: Suggestion = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let (subject, text) = suggestion.mail().ok_or(StatusCode::BAD_REQUEST)?;
    let mail = hub.mail.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let limiters = &hub.limiters;
    if !limiters.feedback_device.take(&device) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if !limiters.feedback_total.take(ALL_SUGGESTIONS) {
        limiters.feedback_device.refund(&device);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if mail.send(&subject, text).await.is_err() {
        limiters.feedback_device.refund(&device);
        limiters.feedback_total.refund(ALL_SUGGESTIONS);
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(StatusCode::NO_CONTENT)
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
