//! Signals waiting for a recipient that is not connected (Plan §15).
//!
//! A signal addressed to a device without an open `/v1/connect` is held here, in memory only,
//! and handed over in order when that device connects. Nothing here is ever written to the
//! database, to disk or to a log, and the router never looks inside a signal: it is opaque bytes.
//!
//! - A signal waits `ttl` at most; after that it is never delivered, and the sweeper frees it.
//! - A recipient keeps `per_recipient` signals at most, and all of them together `total_bytes`;
//!   beyond either, the oldest are dropped first, so the newest (the retry its sender still waits
//!   for) survive.
//! - Taking a recipient's signals removes them: a signal is handed over at most once.
//! - Each signal remembers the slot it came through (2026-10-01): at hand-over, what came through
//!   a slot that is silent by then is dropped instead of delivered.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long, how many and how much the router holds.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub ttl: Duration,
    pub per_recipient: usize,
    pub total_bytes: usize,
}

impl Default for Retention {
    fn default() -> Self {
        // 55 s, so that with the sweeper a signal is gone within the minute the design allows. A
        // phone woken by a push connects within seconds; a call rings for 40 s.
        //
        // Eight per recipient: what opens a connection is one offer (a call's own offer travels
        // inside the data channel), but a sender that retries adds one per attempt, a few
        // contacts may write at once, and an answer can wait for a caller whose socket blinked.
        // At 16 KiB a signal, that is 128 KiB per recipient at worst.
        //
        // 32 MiB for all, bookkeeping included: two thousand full-size signals, far more than a
        // minute of real traffic.
        Self { ttl: Duration::from_secs(55), per_recipient: 8, total_bytes: 32 << 20 }
    }
}

/// How often expired signals are freed.
pub const SWEEP_EVERY: Duration = Duration::from_secs(5);

struct Held {
    to: String,
    /// Which of the recipient's slots it came through (2026-10-01).
    slot: u8,
    at: Instant,
    signal: Vec<u8>,
}

/// What one held signal costs besides its bytes and its recipient's id, roughly.
const BOOKKEEPING: usize = 64;

impl Held {
    /// Its share of `total_bytes`: tiny signals are not free.
    fn cost(&self) -> usize {
        self.signal.len() + self.to.len() + BOOKKEEPING
    }
}

/// The signals waiting, oldest first, and how many bytes they add up to.
pub struct Waiting {
    retention: Retention,
    held: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    held: VecDeque<Held>,
    bytes: usize,
}

impl Queue {
    fn remove(&mut self, index: usize) -> Option<Held> {
        let held = self.held.remove(index)?;
        self.bytes -= held.cost();
        Some(held)
    }

    /// Everything is in arrival order, so what has expired is at the front.
    fn expire(&mut self, ttl: Duration, now: Instant) {
        while self.held.front().is_some_and(|held| now.saturating_duration_since(held.at) >= ttl) {
            self.remove(0);
        }
    }
}

impl Waiting {
    pub fn new(retention: Retention) -> Self {
        Self { retention, held: Mutex::default() }
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.held.lock().expect("waiting signals poisoned")
    }

    /// Holds a signal for `to` until it connects, dropping the oldest beyond the caps.
    pub fn hold(&self, to: &str, slot: u8, signal: Vec<u8>, now: Instant) {
        let mut queue = self.queue();
        queue.expire(self.retention.ttl, now);
        let mut theirs = queue.held.iter().filter(|held| held.to == to).count();
        while theirs >= self.retention.per_recipient {
            let Some(oldest) = queue.held.iter().position(|held| held.to == to) else { break };
            queue.remove(oldest);
            theirs -= 1;
        }
        let held = Held { to: to.to_owned(), slot, at: now, signal };
        queue.bytes += held.cost();
        queue.held.push_back(held);
        while queue.bytes > self.retention.total_bytes {
            queue.remove(0);
        }
    }

    /// Removes and returns what waits for `to`, oldest first, each with the slot it came through.
    pub fn take(&self, to: &str, now: Instant) -> Vec<(u8, Vec<u8>)> {
        let mut queue = self.queue();
        queue.expire(self.retention.ttl, now);
        let (theirs, others): (VecDeque<Held>, VecDeque<Held>) = queue.held.drain(..).partition(|held| held.to == to);
        queue.held = others;
        queue.bytes -= theirs.iter().map(Held::cost).sum::<usize>();
        theirs.into_iter().map(|held| (held.slot, held.signal)).collect()
    }

    /// Frees what has waited too long.
    pub fn sweep(&self, now: Instant) {
        self.queue().expire(self.retention.ttl, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(per_recipient: usize, total_bytes: usize) -> Waiting {
        Waiting::new(Retention { ttl: Duration::from_secs(55), per_recipient, total_bytes })
    }

    /// The signals alone, without their slots.
    fn signals(taken: Vec<(u8, Vec<u8>)>) -> Vec<Vec<u8>> {
        taken.into_iter().map(|(_, signal)| signal).collect()
    }

    // A held signal remembers the slot it came through (2026-10-01), so that at hand-over the
    // router can drop what came through a session the user has left since.
    #[test]
    fn a_held_signal_remembers_its_slot() {
        let waiting = small(8, 1 << 20);
        let now = Instant::now();
        waiting.hold("ft_bob", 3, b"through three".to_vec(), now);
        waiting.hold("ft_bob", 0, b"through the main list".to_vec(), now);
        assert_eq!(waiting.take("ft_bob", now), [(3, b"through three".to_vec()), (0, b"through the main list".to_vec())]);
    }

    impl Waiting {
        fn count(&self) -> usize {
            self.queue().held.len()
        }
    }

    #[test]
    fn signals_are_handed_over_in_order_and_only_once() {
        let waiting = small(8, 1 << 20);
        let now = Instant::now();
        waiting.hold("ft_bob", 0, b"first".to_vec(), now);
        waiting.hold("ft_bob", 0, b"second".to_vec(), now);
        assert_eq!(signals(waiting.take("ft_bob", now)), [b"first".to_vec(), b"second".to_vec()]);
        assert!(signals(waiting.take("ft_bob", now)).is_empty(), "never twice");
        assert_eq!(waiting.count(), 0);
    }

    #[test]
    fn each_recipient_gets_only_its_own() {
        let waiting = small(8, 1 << 20);
        let now = Instant::now();
        waiting.hold("ft_bob", 0, b"for bob".to_vec(), now);
        waiting.hold("ft_carol", 0, b"for carol".to_vec(), now);
        assert_eq!(signals(waiting.take("ft_bob", now)), [b"for bob".to_vec()]);
        assert_eq!(signals(waiting.take("ft_carol", now)), [b"for carol".to_vec()]);
    }

    // A controllable clock: no test waits a real minute.
    #[test]
    fn a_signal_is_never_handed_over_after_its_time() {
        let waiting = small(8, 1 << 20);
        let start = Instant::now();
        waiting.hold("ft_bob", 0, b"old".to_vec(), start);
        waiting.hold("ft_bob", 0, b"newer".to_vec(), start + Duration::from_secs(10));
        let later = start + Duration::from_secs(55);
        assert_eq!(signals(waiting.take("ft_bob", later)), [b"newer".to_vec()]);
    }

    #[test]
    fn the_sweeper_frees_what_waited_too_long() {
        let waiting = small(8, 1 << 20);
        let start = Instant::now();
        waiting.hold("ft_bob", 0, b"old".to_vec(), start);
        waiting.hold("ft_carol", 0, b"recent".to_vec(), start + Duration::from_secs(30));
        waiting.sweep(start + Duration::from_secs(54));
        assert_eq!(waiting.count(), 2, "not yet");
        waiting.sweep(start + Duration::from_secs(56));
        assert_eq!(waiting.count(), 1, "only the recent one is left");
    }

    // A retry loop fills its recipient's share: the oldest go, the newest (the one its sender
    // still waits for) stays.
    #[test]
    fn a_recipient_holds_a_few_and_the_oldest_go_first() {
        let waiting = small(3, 1 << 20);
        let now = Instant::now();
        for retry in 0..5u8 {
            waiting.hold("ft_bob", 0, vec![retry], now);
        }
        waiting.hold("ft_carol", 0, b"untouched".to_vec(), now);
        assert_eq!(signals(waiting.take("ft_bob", now)), [vec![2], vec![3], vec![4]]);
        assert_eq!(signals(waiting.take("ft_carol", now)), [b"untouched".to_vec()]);
    }

    // Tiny signals are not free: each one costs its bookkeeping too, so the cap bounds how many.
    #[test]
    fn even_empty_signals_count_against_the_total() {
        let waiting = small(8, 2 * 100);
        let now = Instant::now();
        for recipient in ["ft_a", "ft_b", "ft_c", "ft_d"] {
            waiting.hold(recipient, 0, Vec::new(), now);
        }
        assert!(waiting.count() <= 2);
    }

    #[test]
    fn all_together_hold_a_bounded_amount_and_the_oldest_go_first() {
        // Room for two of these, not three.
        let waiting = small(8, 2 * (4 + "ft_bob".len() + BOOKKEEPING) + 1);
        let now = Instant::now();
        waiting.hold("ft_bob", 0, vec![1; 4], now);
        waiting.hold("ft_eve", 0, vec![2; 4], now);
        waiting.hold("ft_ivy", 0, vec![3; 4], now);
        assert!(signals(waiting.take("ft_bob", now)).is_empty(), "the oldest of all went");
        assert_eq!(signals(waiting.take("ft_eve", now)), [vec![2; 4]]);
        assert_eq!(signals(waiting.take("ft_ivy", now)), [vec![3; 4]]);
    }

    // The design (§15): in memory for a minute at most, swept included; a few per recipient.
    #[test]
    fn a_signal_is_gone_within_a_minute() {
        let retention = Retention::default();
        assert!(retention.ttl + SWEEP_EVERY <= Duration::from_secs(60));
        assert!(retention.ttl >= Duration::from_secs(30), "long enough for a phone to wake");
        assert_eq!(retention.per_recipient, 8);
        assert_eq!(retention.total_bytes, 32 << 20);
    }
}
