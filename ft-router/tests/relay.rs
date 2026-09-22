//! PoC 0 signalling relay (Plan §87): forwards text between the peers of a room, in memory only.

use std::time::Duration;

use ft_router::turn::TurnIssuer;
use ft_router::Config;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_relay_with(config: Config) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move { axum::serve(listener, ft_router::app(config)).await.expect("serves") });
    format!("ws://{address}")
}

async fn start_relay() -> String {
    start_relay_with(Config { poc_relay: true, ..Config::default() }).await
}

async fn join_raw(base: &str, room: &str) -> Client {
    connect_async(format!("{base}/poc/rooms/{room}")).await.expect("joins the room").0
}

/// Joins and consumes the welcome, which always comes first.
async fn join(base: &str, room: &str) -> Client {
    let mut client = join_raw(base, room).await;
    let welcome = next_text(&mut client).await.expect("a welcome arrives");
    assert!(welcome.contains(r#""kind":"welcome""#), "the first message is the welcome: {welcome}");
    client
}

async fn welcome_of(client: &mut Client) -> serde_json::Value {
    serde_json::from_str(&next_text(client).await.expect("a welcome arrives")).expect("the welcome is JSON")
}

/// Status code of a plain HTTP GET, without pulling in an HTTP client.
async fn status_of(base: &str, path: &str) -> u16 {
    let address = base.trim_start_matches("ws://");
    let mut stream = TcpStream::connect(address).await.expect("connects");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("sends the request");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("reads the response");
    response.split_whitespace().nth(1).and_then(|code| code.parse().ok()).expect("a status line")
}

/// Body of a plain HTTP GET.
async fn body_of(base: &str, path: &str) -> String {
    let address = base.trim_start_matches("ws://");
    let mut stream = TcpStream::connect(address).await.expect("connects");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("sends the request");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("reads the response");
    response.split_once("\r\n\r\n").map(|(_, body)| body.to_owned()).expect("a body")
}

// The load balancer's health check (Plan §75).
#[tokio::test]
async fn answers_the_health_check() {
    let base = start_relay().await;
    assert_eq!(status_of(&base, "/health").await, 200);
}

// A deploy waits until the new version answers (the old one serves during the rolling update).
#[tokio::test]
async fn tells_which_version_is_running() {
    let base = start_relay().await;
    assert_eq!(body_of(&base, "/version").await, env!("CARGO_PKG_VERSION"));
}

// Plan §16–17: our STUN first, and a temporary TURN user for this session only.
#[tokio::test]
async fn welcomes_each_peer_with_the_stun_servers_and_a_temporary_turn_user() {
    let config = Config {
        stun: vec!["stun:turn.example:3478".to_owned()],
        turn: Some(TurnIssuer::new(
            b"shared-secret".to_vec(),
            vec!["turn:turn.example:3478".to_owned()],
            Duration::from_secs(600),
        )),
        poc_relay: true,
        ..Config::default()
    };
    let base = start_relay_with(config).await;
    let mut first = join_raw(&base, "r1").await;
    let mut second = join_raw(&base, "r1").await;

    let (one, two) = (welcome_of(&mut first).await, welcome_of(&mut second).await);

    assert_eq!(one["kind"], "welcome");
    assert_eq!(one["stun"], serde_json::json!(["stun:turn.example:3478"]));
    assert_eq!(one["turn"]["urls"], serde_json::json!(["turn:turn.example:3478"]));
    assert!(!one["turn"]["credential"].as_str().unwrap_or_default().is_empty());
    assert_ne!(one["turn"]["username"], two["turn"]["username"], "one user per session");
}

#[tokio::test]
async fn welcomes_without_turn_when_no_relay_is_configured() {
    let base = start_relay().await;
    let mut peer = join_raw(&base, "r1").await;
    assert_eq!(welcome_of(&mut peer).await["turn"], serde_json::Value::Null);
}

async fn next_text(client: &mut Client) -> Option<String> {
    match timeout(Duration::from_millis(500), client.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => Some(text.to_string()),
        _ => None,
    }
}

#[tokio::test]
async fn tells_each_peer_that_the_other_one_is_there() {
    let base = start_relay().await;
    let mut first = join(&base, "r1").await;
    let mut second = join(&base, "r1").await;

    assert_eq!(next_text(&mut first).await.as_deref(), Some(r#"{"kind":"peer_joined"}"#));
    assert_eq!(next_text(&mut second).await.as_deref(), Some(r#"{"kind":"peer_present"}"#));
}

#[tokio::test]
async fn relays_messages_to_the_other_peer_only() {
    let base = start_relay().await;
    let mut first = join(&base, "r1").await;
    let mut second = join(&base, "r1").await;
    next_text(&mut first).await;
    next_text(&mut second).await;

    first.send(Message::Text("hello".into())).await.expect("sends");

    assert_eq!(next_text(&mut second).await.as_deref(), Some("hello"));
    assert_eq!(next_text(&mut first).await, None, "a peer does not get its own messages back");
}

#[tokio::test]
async fn keeps_rooms_apart() {
    let base = start_relay().await;
    let mut first = join(&base, "r1").await;
    let mut stranger = join(&base, "r2").await;

    first.send(Message::Text("hello".into())).await.expect("sends");

    assert_eq!(next_text(&mut stranger).await, None);
}

// The PoC relay forwards anything between whoever joins a room: an open relay. Off unless asked.
#[tokio::test]
async fn the_poc_relay_is_off_by_default() {
    let base = start_relay_with(Config::default()).await;
    assert!(tokio_tungstenite::connect_async(format!("{base}/poc/rooms/demo")).await.is_err());
}
