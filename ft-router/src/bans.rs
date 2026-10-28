//! Banned devices (0.8.0, 2026-10-28; App Review Guideline 1.2): the device ids the operator has
//! cut off after an abuse report. Their requests are refused, nothing can be signalled or mailed
//! to them, and their registration and the mail waiting for them are deleted.
//!
//! The list is a file, one `ft_…` device id per line, with `#` comments and blank lines; in the
//! cluster it is a Swarm secret (`FT_BANNED_DEVICES_FILE`). It is read at start, where a missing
//! or malformed file is an error so that a typo is noticed, and read again every minute; a file
//! that breaks later keeps the list that was read last. It lives in memory, never in the database.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::watch;

/// How often the list is read again from its file.
pub const RELOAD_EVERY: Duration = Duration::from_secs(60);

pub struct Bans {
    banned: RwLock<HashSet<String>>,
    file: Option<PathBuf>,
    every: Duration,
    changed: watch::Sender<()>,
}

impl Default for Bans {
    fn default() -> Self {
        Self::listed([])
    }
}

impl Bans {
    /// A fixed list, never read again.
    pub fn listed(ids: impl IntoIterator<Item = String>) -> Self {
        Self::new(ids.into_iter().collect(), None, RELOAD_EVERY)
    }

    /// The list in `file`, read now (a missing or malformed file is an error) and again every
    /// `every`.
    pub fn from_file(file: impl Into<PathBuf>, every: Duration) -> Result<Self> {
        let file = file.into();
        let banned = read(&file)?;
        Ok(Self::new(banned, Some(file), every))
    }

    fn new(banned: HashSet<String>, file: Option<PathBuf>, every: Duration) -> Self {
        Self { banned: RwLock::new(banned), file, every, changed: watch::Sender::new(()) }
    }

    /// A hash lookup, the same work whichever the device.
    pub fn is_banned(&self, device: &str) -> bool {
        self.banned.read().expect("ban list poisoned").contains(device)
    }

    /// Every device on the list.
    pub fn devices(&self) -> Vec<String> {
        self.banned.read().expect("ban list poisoned").iter().cloned().collect()
    }

    /// How often to read the list again; never without a file.
    pub fn every(&self) -> Option<Duration> {
        self.file.as_ref().map(|_| self.every)
    }

    /// Reads the file again: `true` if the list changed. A file that cannot be read or is
    /// malformed is an error, and the list read last stays.
    pub fn reload(&self) -> Result<bool> {
        let Some(file) = &self.file else { return Ok(false) };
        let banned = read(file)?;
        let mut current = self.banned.write().expect("ban list poisoned");
        if *current == banned {
            return Ok(false);
        }
        *current = banned;
        drop(current);
        self.changed.send_replace(());
        Ok(true)
    }

    /// Hears of every change of the list.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }
}

fn read(file: &std::path::Path) -> Result<HashSet<String>> {
    parse(&std::fs::read_to_string(file).context("cannot read the ban list")?)
}

/// The device ids in a ban list. The error names the line of a malformed entry, never its text.
pub fn parse(text: &str) -> Result<HashSet<String>> {
    let mut banned = HashSet::new();
    for (number, line) in text.lines().enumerate() {
        let entry = line.split('#').next().unwrap_or_default().trim();
        if entry.is_empty() {
            continue;
        }
        if !device_id(entry) {
            bail!("line {} of the ban list is not a device id", number + 1);
        }
        banned.insert(entry.to_owned());
    }
    Ok(banned)
}

/// `ft_` and the base58 of a 32-byte hash, as `auth::device_id` makes them.
fn device_id(text: &str) -> bool {
    text.strip_prefix("ft_")
        .and_then(|hash| bs58::decode(hash).into_vec().ok())
        .is_some_and(|hash| hash.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> String {
        crate::auth::device_id(&[seed; 32])
    }

    /// A file of its own in the temporary directory.
    fn file_with(text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ft-bans-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, text).expect("writes");
        path
    }

    #[test]
    fn the_list_is_one_device_id_per_line_with_comments_and_blank_lines() {
        let text = format!("# reports of 2026-10-28\n\n{}\n  {}  # report 2\n\t\n", id(1), id(2));
        let banned = parse(&text).expect("well formed");
        assert_eq!(banned, HashSet::from([id(1), id(2)]));
        assert!(parse("").expect("empty").is_empty());
        assert!(parse("# nobody yet\n").expect("only a comment").is_empty());
    }

    // The operator must notice a typo, and the error must not carry what was typed.
    #[test]
    fn a_line_that_is_not_a_device_id_is_an_error_naming_only_its_line() {
        for wrong in ["ft_notbase58!", "ft_abc", "xx_4GbW2", &id(1)[3..], &format!("{} {}", id(1), id(2))] {
            let error = parse(&format!("{}\n{wrong}\n", id(3))).expect_err(wrong).to_string();
            assert!(error.contains("line 2"), "{error}");
            assert!(!error.contains(wrong), "{error}");
        }
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let missing = std::env::temp_dir().join(format!("ft-bans-missing-{}", uuid::Uuid::now_v7()));
        assert!(Bans::from_file(missing, RELOAD_EVERY).is_err());
    }

    #[test]
    fn a_fixed_list_is_never_read_again() {
        let bans = Bans::listed([id(1)]);
        assert!(bans.is_banned(&id(1)));
        assert!(!bans.is_banned(&id(2)));
        assert_eq!(bans.every(), None);
        assert!(!Bans::default().is_banned(&id(1)));
    }

    #[test]
    fn reading_again_finds_changes_and_keeps_the_list_when_the_file_breaks() {
        let path = file_with(&format!("{}\n", id(1)));
        let bans = Bans::from_file(&path, Duration::from_secs(5)).expect("reads");
        assert_eq!(bans.every(), Some(Duration::from_secs(5)));
        assert_eq!(bans.devices(), [id(1)]);
        let mut changes = bans.subscribe();

        assert!(!bans.reload().expect("same file"), "nothing changed");
        assert!(!changes.has_changed().unwrap(), "and nobody hears of it");

        std::fs::write(&path, format!("{}\n{}\n", id(1), id(2))).unwrap();
        assert!(bans.reload().expect("a new id"));
        assert!(bans.is_banned(&id(2)));
        assert!(changes.has_changed().unwrap(), "a change is announced");
        changes.mark_unchanged();

        std::fs::write(&path, "ft_typo\n").unwrap();
        assert!(bans.reload().is_err());
        assert!(bans.is_banned(&id(1)) && bans.is_banned(&id(2)), "a broken file keeps the last list");
        std::fs::remove_file(&path).unwrap();
        assert!(bans.reload().is_err());
        assert!(bans.is_banned(&id(2)), "so does a missing one");
        assert!(!changes.has_changed().unwrap());

        std::fs::write(&path, format!("{}\n", id(2))).unwrap();
        assert!(bans.reload().expect("lifted"));
        assert!(!bans.is_banned(&id(1)), "a ban is lifted by taking the id off the list");
        std::fs::remove_file(&path).unwrap();
    }
}
