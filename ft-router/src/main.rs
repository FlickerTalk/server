use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ft_router::db::Db;
use ft_router::push::{Apns, Fcm, PushVault, RingLimiter, ServiceAccount, Waker, WakeLimiter, APNS, FCM, RING_EVERY, RING_FOR, WAKE_EVERY};
use ft_router::turn::TurnIssuer;
use ft_router::{Config, Push};
use tokio::net::TcpListener;

const DEFAULT_ADDRESS: &str = "0.0.0.0:8787";

/// TURN users last a few minutes (Plan §17).
const TURN_TTL: Duration = Duration::from_secs(10 * 60);

/// Where to listen: `FT_ROUTER_ADDR` if set, else every interface on port 8787.
fn listen_address(configured: Option<String>) -> String {
    configured.filter(|address| !address.is_empty()).unwrap_or_else(|| DEFAULT_ADDRESS.to_owned())
}

fn server_list(urls: Option<String>) -> Vec<String> {
    urls.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Our STUN and TURN servers, comma-separated, and the secret shared with coturn. Without the
/// secret no TURN user is issued.
fn config_from(stun: Option<String>, turn: Option<String>, secret: Option<Vec<u8>>) -> Config {
    let turn = secret.map(|secret| {
        let secret = secret.trim_ascii_end().to_vec();
        TurnIssuer::new(secret, server_list(turn), TURN_TTL)
    });
    Config { stun: server_list(stun), turn, ..Config::default() }
}

/// `FT_DATABASE_URL`, or the contents of the file named by `FT_DATABASE_URL_FILE`.
fn database_url(variable: Option<String>, file: Option<Vec<u8>>) -> Option<String> {
    variable.or_else(|| file.map(|bytes| String::from_utf8_lossy(bytes.trim_ascii_end()).into_owned()))
}

/// What APNs needs (2026-09-28): the team's .p8 key (a Swarm secret), its id, the team id and
/// the apps it may push to.
struct ApnsSetup {
    key: Vec<u8>,
    key_id: String,
    team: String,
    topics: Vec<String>,
}

/// The apps an iPhone may register for: ours, the App Store one and the development one.
fn topics_from(variable: Option<String>) -> Vec<String> {
    let listed = variable.unwrap_or_else(|| "com.flickertalk.app,com.flickertalk.app.dev".to_owned());
    listed.split(',').map(str::trim).filter(|topic| !topic.is_empty()).map(str::to_owned).collect()
}

/// Push wake-ups (§8–12): the master key that encrypts push tokens (base64 of 32 bytes), and who
/// wakes each kind of phone: FCM with its service account key, APNs with the team's .p8 key.
/// Without the master key, or without either provider, devices are never woken.
fn push_from(key: Option<Vec<u8>>, service_account: Option<Vec<u8>>, apns: Option<ApnsSetup>) -> anyhow::Result<Option<Push>> {
    let Some(key) = key else { return Ok(None) };
    let key: [u8; 32] = BASE64
        .decode(key.trim_ascii())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the push key must be 32 bytes in base64"))?;
    let mut wakers: std::collections::HashMap<String, Arc<dyn Waker>> = Default::default();
    if let Some(account) = service_account {
        let account: ServiceAccount = serde_json::from_slice(&account)?;
        wakers.insert(FCM.to_owned(), Arc::new(Fcm::new(account)?));
    }
    if let Some(apns) = apns {
        let topics: Vec<&str> = apns.topics.iter().map(String::as_str).collect();
        wakers.insert(APNS.to_owned(), Arc::new(Apns::new(&apns.team, &apns.key_id, &apns.key, &topics)?));
    }
    if wakers.is_empty() {
        return Ok(None);
    }
    Ok(Some(Push {
        vault: PushVault::new(&key),
        wakers,
        limiter: WakeLimiter::new(WAKE_EVERY),
        ring_limiter: RingLimiter::new(RING_EVERY, RING_FOR),
    }))
}

/// Expired mail is deleted every hour (§19).
const PURGE_EVERY: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let variable = |name: &str| std::env::var(name).ok();
    let secret = variable("FT_TURN_SECRET_FILE").map(std::fs::read).transpose()?;
    let mut config = config_from(variable("FT_STUN_URLS"), variable("FT_TURN_URLS"), secret);
    let url_file = variable("FT_DATABASE_URL_FILE").map(std::fs::read).transpose()?;
    if let Some(url) = database_url(variable("FT_DATABASE_URL"), url_file) {
        let db = Arc::new(Db::connect(&url).await?);
        let purging = db.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(PURGE_EVERY);
            loop {
                every.tick().await;
                let _ = purging.purge_expired().await;
            }
        });
        config.db = Some(db);
    }

    config.poc_relay = variable("FT_POC_RELAY").as_deref() == Some("1");
    let push_key = variable("FT_PUSH_KEY_FILE").map(std::fs::read).transpose()?;
    let service_account = variable("FT_FCM_SERVICE_ACCOUNT_FILE").map(std::fs::read).transpose()?;
    let apns = match (variable("FT_APNS_KEY_FILE"), variable("FT_APNS_KEY_ID"), variable("FT_APNS_TEAM_ID")) {
        (Some(file), Some(key_id), Some(team)) => {
            Some(ApnsSetup { key: std::fs::read(file)?, key_id, team, topics: topics_from(variable("FT_APNS_TOPICS")) })
        }
        _ => None,
    };
    config.push = push_from(push_key, service_account, apns)?.map(Arc::new);

    let listener = TcpListener::bind(listen_address(variable("FT_ROUTER_ADDR"))).await?;
    axum::serve(listener, ft_router::app(config)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use ft_router::turn::credential_for;

    use super::*;

    fn service_account() -> Vec<u8> {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        serde_json::to_vec(&serde_json::json!({
            "type": "service_account",
            "client_email": "ft-router-fcm@example.iam.gserviceaccount.com",
            "private_key": key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": "flickertalk-test"
        }))
        .unwrap()
    }

    // Push needs both secrets: the master key (base64, 32 bytes) and the service account.
    #[test]
    fn push_is_on_only_with_its_key_and_service_account() {
        let key = b"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\n".to_vec();
        assert!(push_from(Some(key.clone()), Some(service_account()), None).unwrap().is_some());
        assert!(push_from(None, Some(service_account()), None).unwrap().is_none());
        assert!(push_from(Some(key), None, None).unwrap().is_none());
        assert!(push_from(Some(b"short".to_vec()), Some(service_account()), None).is_err(), "a wrong key is an error, not silence");
    }

    fn apns_setup() -> ApnsSetup {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        ApnsSetup {
            key: key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes().to_vec(),
            key_id: "KEYID56789".to_owned(),
            team: "TEAMID1234".to_owned(),
            topics: topics_from(None),
        }
    }

    // iPhones (2026-09-28): with the .p8 key, its id and the team, APNs wakes them; Android and
    // iPhones each only with their own provider's secret.
    #[test]
    fn push_wakes_iphones_with_the_apns_key_and_android_with_fcm() {
        let key = b"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\n".to_vec();
        let both = push_from(Some(key.clone()), Some(service_account()), Some(apns_setup())).unwrap().expect("on");
        assert!(both.waker(FCM).is_some() && both.waker(APNS).is_some());
        let iphones = push_from(Some(key.clone()), None, Some(apns_setup())).unwrap().expect("on with APNs alone");
        assert!(iphones.waker(FCM).is_none() && iphones.waker(APNS).is_some());
        let broken = ApnsSetup { key: b"not a key".to_vec(), ..apns_setup() };
        assert!(push_from(Some(key), None, Some(broken)).is_err(), "a wrong .p8 is an error, not silence");
        assert_eq!(topics_from(None), ["com.flickertalk.app", "com.flickertalk.app.dev"]);
        assert_eq!(topics_from(Some("com.flickertalk.app".to_owned())), ["com.flickertalk.app"]);
    }

    #[test]
    fn without_a_turn_secret_only_stun_is_offered() {
        let config = config_from(Some("stun:a:3478".to_owned()), Some("turn:a:3478".to_owned()), None);
        assert_eq!(config.stun, ["stun:a:3478"]);
        assert!(config.turn.is_none());
    }

    #[test]
    fn server_lists_are_comma_separated() {
        let config = config_from(Some("stun:a:3478, stun:b:3478".to_owned()), None, None);
        assert_eq!(config.stun, ["stun:a:3478", "stun:b:3478"]);
        assert!(config_from(None, None, None).stun.is_empty());
    }

    // The URL carries the database password, so in the cluster it comes from a Swarm secret file.
    #[test]
    fn the_database_url_comes_from_the_environment_or_a_secret_file() {
        assert_eq!(database_url(Some("postgres://a".to_owned()), None).as_deref(), Some("postgres://a"));
        assert_eq!(database_url(None, Some(b"postgres://b\n".to_vec())).as_deref(), Some("postgres://b"));
        assert_eq!(database_url(None, None), None);
    }

    // Swarm secrets are files; the trailing newline is not part of the secret.
    #[test]
    fn turn_users_are_signed_with_the_secret_file_contents() {
        let config = config_from(None, Some("turn:a:3478".to_owned()), Some(b"abc\n".to_vec()));
        let issued = config.turn.expect("TURN is configured").issue(SystemTime::now());
        assert_eq!(issued.urls, ["turn:a:3478"]);
        assert_eq!(issued.credential, credential_for(b"abc", &issued.username));
    }

    #[test]
    fn listens_on_port_8787_unless_told_otherwise() {
        assert_eq!(listen_address(None), "0.0.0.0:8787");
        assert_eq!(listen_address(Some(String::new())), "0.0.0.0:8787");
        assert_eq!(listen_address(Some("127.0.0.1:9000".to_owned())), "127.0.0.1:9000");
    }
}
