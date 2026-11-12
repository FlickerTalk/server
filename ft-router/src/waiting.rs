//! Memory only. Held signals never go to the database, the disk or a log.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub ttl: Duration,
    pub per_recipient: usize,
    pub total_bytes: usize,
}

impl Default for Retention {
    fn default() -> Self {
        // 55 s plus the sweep interval stays under a minute
        Self { ttl: Duration::from_secs(55), per_recipient: 8, total_bytes: 32 << 20 }
    }
}

pub const SWEEP_EVERY: Duration = Duration::from_secs(5);

struct Held {
    to: String,
    slot: u8,
    at: Instant,
    signal: Vec<u8>,
}

const BOOKKEEPING: usize = 64;

impl Held {
    fn cost(&self) -> usize {
        self.signal.len() + self.to.len() + BOOKKEEPING
    }
}

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

    pub fn take(&self, to: &str, now: Instant) -> Vec<(u8, Vec<u8>)> {
        let mut queue = self.queue();
        queue.expire(self.retention.ttl, now);
        let (theirs, others): (VecDeque<Held>, VecDeque<Held>) = queue.held.drain(..).partition(|held| held.to == to);
        queue.held = others;
        queue.bytes -= theirs.iter().map(Held::cost).sum::<usize>();
        theirs.into_iter().map(|held| (held.slot, held.signal)).collect()
    }

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

    fn signals(taken: Vec<(u8, Vec<u8>)>) -> Vec<Vec<u8>> {
        taken.into_iter().map(|(_, signal)| signal).collect()
    }

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
        let waiting = small(8, 2 * (4 + "ft_bob".len() + BOOKKEEPING) + 1);
        let now = Instant::now();
        waiting.hold("ft_bob", 0, vec![1; 4], now);
        waiting.hold("ft_eve", 0, vec![2; 4], now);
        waiting.hold("ft_ivy", 0, vec![3; 4], now);
        assert!(signals(waiting.take("ft_bob", now)).is_empty(), "the oldest of all went");
        assert_eq!(signals(waiting.take("ft_eve", now)), [vec![2; 4]]);
        assert_eq!(signals(waiting.take("ft_ivy", now)), [vec![3; 4]]);
    }

    #[test]
    fn a_signal_is_gone_within_a_minute() {
        let retention = Retention::default();
        assert!(retention.ttl + SWEEP_EVERY <= Duration::from_secs(60));
        assert!(retention.ttl >= Duration::from_secs(30), "long enough for a phone to wake");
        assert_eq!(retention.per_recipient, 8);
        assert_eq!(retention.total_bytes, 32 << 20);
    }
}
