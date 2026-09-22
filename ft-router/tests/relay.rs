//! PoC 0 signalling relay (Plan §87): forwards text between the peers of a room, in memory only.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move { axum::serve(listener, ft_router::app()).await.expect("serves") });
    format!("ws://{address}")
}

async fn join(base: &str, room: &str) -> Client {
    connect_async(format!("{base}/poc/rooms/{room}")).await.expect("joins the room").0
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
