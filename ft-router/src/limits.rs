//! Rate limits (Plan §7, §34, §91): each device, each recipient and each origin gets a fair share
//! of requests per window; beyond it, 429 until the next one. Everything lives in memory and is
//! never logged. Origins are the address the load balancer saw, hashed with a salt made at start,
//! so not even memory holds an IP (§71).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Signed requests per device.
    pub per_device: u32,
    /// Signals and mail per recipient.
    pub per_recipient: u32,
    /// Registrations, signals and mail per origin.
    pub per_origin: u32,
    pub window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { per_device: 600, per_recipient: 240, per_origin: 1200, window: Duration::from_secs(60) }
    }
}

/// Counts requests per key in fixed windows.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    counts: Mutex<HashMap<String, (Instant, u32)>>,
}

/// Above this many keys, finished windows are swept away.
const SWEEP_ABOVE: usize = 10_000;

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self { limit, window, counts: Mutex::default() }
    }

    /// Counts one request; `false` once the key is over its limit in this window.
    pub fn allow(&self, key: &str) -> bool {
        let mut counts = self.counts.lock().expect("limiter poisoned");
        let now = Instant::now();
        if counts.len() > SWEEP_ABOVE {
            counts.retain(|_, (started, _)| now.duration_since(*started) < self.window);
        }
        let entry = counts.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}

/// The three limits, and the salt that hides origins.
pub struct Limiters {
    pub device: RateLimiter,
    pub recipient: RateLimiter,
    pub origin: RateLimiter,
    salt: [u8; 32],
}

impl Limiters {
    pub fn new(limits: Limits) -> Self {
        Self {
            device: RateLimiter::new(limits.per_device, limits.window),
            recipient: RateLimiter::new(limits.per_recipient, limits.window),
            origin: RateLimiter::new(limits.per_origin, limits.window),
            salt: rand::random(),
        }
    }

    /// Where a request comes from: the last address in `X-Forwarded-For` (the one our load
    /// balancer added; earlier ones come from the client and prove nothing), hashed.
    pub fn origin(&self, headers: &HeaderMap) -> String {
        let seen = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .map(str::trim)
            .unwrap_or("direct");
        blake3::keyed_hash(&self.salt, seen.as_bytes()).to_hex()[..32].to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_cut_off_at_its_limit_until_the_window_ends() {
        let limiter = RateLimiter::new(2, Duration::from_millis(60));
        assert!(limiter.allow("a"));
        assert!(limiter.allow("a"));
        assert!(!limiter.allow("a"));
        assert!(limiter.allow("b"), "each key on its own");
        std::thread::sleep(Duration::from_millis(70));
        assert!(limiter.allow("a"), "a new window");
    }

    #[test]
    fn the_origin_is_the_address_the_load_balancer_added_and_never_kept_in_the_clear() {
        let limiters = Limiters::new(Limits::default());
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.9.9.9, 203.0.113.7".parse().unwrap());
        let origin = limiters.origin(&headers);
        assert!(!origin.contains("203.0.113"));
        headers.insert("x-forwarded-for", "1.1.1.1, 203.0.113.7".parse().unwrap());
        assert_eq!(limiters.origin(&headers), origin, "what the client adds does not count");
        assert_ne!(Limiters::new(Limits::default()).origin(&headers), origin, "a new salt at each start");
    }
}
