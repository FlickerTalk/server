//! FlickerTalk router (Plan §8–19).
//!
//! For now it only holds the PoC 0 signalling relay (§87): two peers join a room over a WebSocket
//! and the relay forwards their text messages to each other. In the real design signalling travels
//! through push (§13); this relay is temporary and exists to test WebRTC between devices.
//!
//! Nothing is stored or logged: rooms live in memory and disappear with their last peer (§71).
//!
//! Every peer first gets a welcome with the ICE servers to use: our STUN and, if configured, a
//! temporary TURN user for that session only (§16–17).

pub mod auth;
pub mod db;
pub mod turn;
pub mod push;

pub use push::Push;
pub mod v1;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};

use crate::db::Db;
use crate::turn::TurnIssuer;

/// Sent to a newcomer when someone is already in the room.
pub const PEER_PRESENT: &str = r#"{"kind":"peer_present"}"#;
/// Sent to the peers already in a room when someone joins.
pub const PEER_JOINED: &str = r#"{"kind":"peer_joined"}"#;
/// Sent to the remaining peers when someone leaves.
pub const PEER_LEFT: &str = r#"{"kind":"peer_left"}"#;

type Outbox = mpsc::UnboundedSender<String>;

/// The ICE servers handed to every peer and, for API v1, the database.
#[derive(Clone, Default)]
pub struct Config {
    pub stun: Vec<String>,
    pub turn: Option<TurnIssuer>,
    /// Without a database only the PoC relay and the health check are served.
    pub db: Option<Arc<Db>>,
    /// Without it, devices that are not connected are never woken.
    pub push: Option<Arc<Push>>,
}

#[derive(Clone, Default)]
struct Rooms {
    peers: Arc<Mutex<HashMap<String, HashMap<u64, Outbox>>>>,
    next_id: Arc<AtomicU64>,
    config: Arc<Config>,
}

pub fn app(config: Config) -> Router {
    let v1 = config
        .db
        .clone()
        .map(|db| v1::routes(Arc::new(v1::Hub::new(db, config.stun.clone(), config.turn.clone(), config.push.clone()))));
    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/poc/rooms/{room}", get(join))
        .with_state(Rooms { config: Arc::new(config), ..Rooms::default() });
    match v1 {
        Some(v1) => router.merge(v1),
        None => router,
    }
}

async fn join(socket: WebSocketUpgrade, Path(room): Path<String>, State(rooms): State<Rooms>) -> Response {
    socket.on_upgrade(move |socket| relay(socket, room, rooms))
}

fn welcome(config: &Config) -> String {
    let turn = config.turn.as_ref().map(|issuer| issuer.issue(SystemTime::now()));
    serde_json::json!({ "kind": "welcome", "stun": config.stun, "turn": turn }).to_string()
}

async fn relay(socket: WebSocket, room: String, rooms: Rooms) {
    let id = rooms.next_id.fetch_add(1, Ordering::Relaxed);
    let (outbox, mut pending) = mpsc::unbounded_channel::<String>();
    let _ = outbox.send(welcome(&rooms.config));

    {
        let mut all = rooms.peers.lock().await;
        let peers = all.entry(room.clone()).or_default();
        if !peers.is_empty() {
            let _ = outbox.send(PEER_PRESENT.to_owned());
            broadcast(peers, id, PEER_JOINED);
        }
        peers.insert(id, outbox);
    }

    let (mut sink, mut stream) = socket.split();
    let writer = tokio::spawn(async move {
        while let Some(text) = pending.recv().await {
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(message)) = stream.next().await {
        if let Message::Text(text) = message {
            if let Some(peers) = rooms.peers.lock().await.get(&room) {
                broadcast(peers, id, text.as_str());
            }
        }
    }

    let mut all = rooms.peers.lock().await;
    if let Some(peers) = all.get_mut(&room) {
        peers.remove(&id);
        broadcast(peers, id, PEER_LEFT);
        if peers.is_empty() {
            all.remove(&room);
        }
    }
    writer.abort();
}

/// Sends `text` to every peer of the room except `from`.
fn broadcast(peers: &HashMap<u64, Outbox>, from: u64, text: &str) {
    for (id, outbox) in peers {
        if *id != from {
            let _ = outbox.send(text.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broadcast_skips_the_sender() {
        let (to_sender, mut sender_inbox) = mpsc::unbounded_channel();
        let (to_other, mut other_inbox) = mpsc::unbounded_channel();
        let peers = HashMap::from([(1, to_sender), (2, to_other)]);

        broadcast(&peers, 1, "hi");

        assert_eq!(other_inbox.try_recv().ok().as_deref(), Some("hi"));
        assert!(sender_inbox.try_recv().is_err());
    }
}
