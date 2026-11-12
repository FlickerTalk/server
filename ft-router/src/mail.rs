use std::time::Duration;

use lettre::message::header::{ContentTransferEncoding, ContentType};
use lettre::message::{Mailbox, Message, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_PORT: u16 = 587;

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Mailbox,
    timeout: Duration,
}

impl Mailer {
    /// Always STARTTLS. A server that doesn't upgrade never gets the password or the mail.
    pub fn starttls(host: &str, port: u16, user: &str, password: &str, to: &str) -> anyhow::Result<Self> {
        let from: Mailbox = user.parse()?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?
            .port(port)
            .hello_name(ClientId::Domain(from.email.domain().to_owned()))
            .credentials(Credentials::new(user.to_owned(), password.to_owned()))
            .timeout(Some(SEND_TIMEOUT))
            .build();
        Ok(Self { transport, from, to: to.parse()?, timeout: SEND_TIMEOUT })
    }

    /// Tests only. Hardwired to 127.0.0.1, no setting reaches it.
    #[doc(hidden)]
    pub fn plaintext_loopback(port: u16, from: &str, to: &str) -> anyhow::Result<Self> {
        let transport =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1").port(port).timeout(Some(SEND_TIMEOUT)).build();
        Ok(Self { transport, from: from.parse()?, to: to.parse()?, timeout: SEND_TIMEOUT })
    }

    pub async fn send(&self, subject: &str, text: &str) -> anyhow::Result<()> {
        let mail = message(self.from.clone(), self.to.clone(), subject, text)?;
        tokio::time::timeout(self.timeout, self.transport.send(mail)).await??;
        Ok(())
    }
}

/// The body is base64 so the text can't add a header or end the mail early with a lone dot.
fn message(from: Mailbox, to: Mailbox, subject: &str, text: &str) -> anyhow::Result<Message> {
    let body = SinglePart::builder()
        .header(ContentType::TEXT_PLAIN)
        .header(ContentTransferEncoding::Base64)
        .body(text.to_owned());
    // Mail without a Message-ID looks like spam. Random so it says nothing about the sender.
    let id = format!("<{:032x}@{}>", rand::random::<u128>(), from.email.domain());
    Ok(Message::builder().from(from).to(to).subject(subject).message_id(Some(id)).singlepart(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn header_names(mail: &str) -> Vec<String> {
        let (headers, _) = mail.split_once("\r\n\r\n").expect("headers and body");
        headers
            .split("\r\n")
            .filter(|line| !line.starts_with([' ', '\t']))
            .map(|line| line.split_once(':').expect("a header").0.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn the_mail_carries_the_subject_and_the_text_and_nothing_else() {
        let text = "Dark mode, please.\r\nSubject: x\n.\nمرحبا 👋";
        let info: Mailbox = "info@flickertalk.com".parse().unwrap();
        let mail = message(info.clone(), info, "FlickerTalk suggestion (ios 1.3.0)", text).unwrap();
        let mail = String::from_utf8(mail.formatted()).unwrap();
        let mut names = header_names(&mail);
        names.sort();
        assert_eq!(
            names,
            ["content-transfer-encoding", "content-type", "date", "from", "message-id", "mime-version", "subject", "to"]
        );
        assert!(mail.contains("\r\nSubject: FlickerTalk suggestion (ios 1.3.0)\r\n"));
        assert!(mail.to_ascii_lowercase().contains("content-type: text/plain; charset=utf-8"));
        let (_, body) = mail.split_once("\r\n\r\n").unwrap();
        let body: String = body.split_whitespace().collect();
        let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(body).unwrap()).unwrap();
        assert_eq!(decoded, "Dark mode, please.\r\nSubject: x\r\n.\r\nمرحبا 👋");
    }

    async fn server_without_tls() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let heard = Arc::new(Mutex::new(Vec::new()));
        let log = heard.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (read, mut write) = socket.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 fake\r\n").await.unwrap();
                while let Ok(Some(line)) = lines.next_line().await {
                    log.lock().unwrap().push(line.clone());
                    let answer: &[u8] = if line.starts_with("EHLO") { b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n" } else { b"250 ok\r\n" };
                    if write.write_all(answer).await.is_err() {
                        break;
                    }
                }
            }
        });
        (port, heard)
    }

    #[tokio::test]
    async fn the_production_mailer_says_nothing_without_tls() {
        let (port, heard) = server_without_tls().await;
        let mailer = Mailer::starttls("127.0.0.1", port, "info@flickertalk.com", "hunter2", "info@flickertalk.com").unwrap();
        assert!(mailer.send("FlickerTalk suggestion (android 1.3.0)", "hello").await.is_err());
        let heard = heard.lock().unwrap().clone();
        assert_eq!(heard.first().map(String::as_str), Some("EHLO flickertalk.com"), "our domain, not the container's name");
        assert!(heard.iter().all(|line| line.starts_with("EHLO") || line.starts_with("QUIT")), "{heard:?}");
    }

    #[tokio::test]
    async fn a_mail_server_that_never_answers_is_given_up_on() {
        assert_eq!(SEND_TIMEOUT, Duration::from_secs(10));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let mut mailer = Mailer::plaintext_loopback(port, "info@flickertalk.com", "info@flickertalk.com").unwrap();
        mailer.timeout = Duration::from_millis(200);
        let started = std::time::Instant::now();
        assert!(mailer.send("FlickerTalk suggestion (android 1.3.0)", "hello").await.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
