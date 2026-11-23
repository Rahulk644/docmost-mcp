//! Rotation state of refresh-token families, kept durable across restarts.
//!
//! Refresh tokens are sealed and held by clients (see `oauth`). What has to
//! survive a restart is the server's side of rotation: for each family (one
//! authorization), the generation that may be redeemed next, whether the
//! family was revoked, and when it expires. That is all this file holds. No
//! Docmost session, refresh token, or hash of either is written.
//!
//! The file is a journal of JSON lines, one family's full state per line; the
//! last line for a family wins. Every change is appended and synced before
//! the caller acts on it, so a response never depends on state a crash could
//! lose. Each operation takes an exclusive advisory lock on the file and first
//! applies whatever other processes appended since, so processes sharing the
//! file (the old and new process during a rolling restart, say) see one
//! sequence of states and a generation can be redeemed only once across all of
//! them. The journal is compacted to the live families at startup and whenever
//! it grows well past them: written in full under a temporary name, synced,
//! and renamed over the journal. Other processes notice the replaced file once
//! they hold its lock and re-read it.
//!
//! A trailing partial line is the remains of an append that never finished
//! syncing, which nothing depended on, and is dropped. Any other unreadable
//! line is an error, so refreshes fail closed rather than forgetting a
//! revocation.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::key_file;

/// The journal is compacted once it holds this many records more than twice
/// the live families.
const COMPACTION_SLACK: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyState {
    /// The generation of the one token in this family that may be redeemed.
    pub current: u64,
    pub revoked: bool,
    pub expires_at: DateTime<Utc>,
}

/// The answer to a check or a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The token is current (check), or the change is now durable.
    Accepted,
    /// No such family: never issued here, expired, revoked (and dropped), or its
    /// state was lost.
    Unknown,
    /// The family is revoked but not yet dropped; the next operation drops it
    /// and reports `Unknown`. Both are refused alike.
    Revoked,
    /// The token's generation was already redeemed; the family is now
    /// revoked (durably).
    Reused,
    /// No room for another family.
    Full,
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    #[serde(rename = "f")]
    family: String,
    #[serde(rename = "g")]
    current: u64,
    #[serde(rename = "r", default)]
    revoked: bool,
    #[serde(rename = "e", with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
}

impl Record {
    fn new(family: &str, state: FamilyState) -> Self {
        Self {
            family: family.to_string(),
            current: state.current,
            revoked: state.revoked,
            expires_at: state.expires_at,
        }
    }
}

type Families = HashMap<String, FamilyState>;

pub struct FamilyStore {
    families: Families,
    /// None keeps the state in memory only (tests).
    journal: Option<Journal>,
    capacity: usize,
}

impl FamilyStore {
    pub fn in_memory(capacity: usize) -> Self {
        Self {
            families: HashMap::new(),
            journal: None,
            capacity,
        }
    }

    /// Opens (creating if needed, mode 0600 in a 0700 directory) the journal
    /// at `path`, loads it and compacts it.
    pub fn open(path: &Path, capacity: usize) -> anyhow::Result<Self> {
        if let Some(dir) = key_file::parent_dir(path) {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;
        }
        let mut journal = Journal {
            file: Journal::open_file(path)
                .with_context(|| format!("Failed to open {}", path.display()))?,
            path: path.to_path_buf(),
            offset: 0,
            records: 0,
        };
        let mut families = HashMap::new();
        journal
            .lock(&mut families)
            .with_context(|| format!("Failed to load {}", path.display()))?;
        let now = Utc::now();
        families.retain(|_, state| keep(state, now));
        let compacted = journal.compact(&families);
        journal.unlock();
        compacted.with_context(|| format!("Failed to compact {}", path.display()))?;
        Ok(Self {
            families,
            journal: Some(journal),
            capacity,
        })
    }

    /// Whether `generation` is the family's redeemable token. Presenting a
    /// spent generation revokes the family before this returns.
    pub fn check(&mut self, family: &str, generation: u64) -> io::Result<Outcome> {
        self.transact(|families| match families.get(family) {
            None => (Outcome::Unknown, None),
            Some(state) if state.revoked => (Outcome::Revoked, None),
            Some(state) if state.current != generation => (
                Outcome::Reused,
                Some(Record::new(
                    family,
                    FamilyState {
                        revoked: true,
                        ..*state
                    },
                )),
            ),
            Some(_) => (Outcome::Accepted, None),
        })
    }

    /// Records a new family whose first token (generation 1) has been sealed.
    pub fn start(&mut self, family: &str, expires_at: DateTime<Utc>) -> io::Result<Outcome> {
        let capacity = self.capacity;
        self.transact(|families| {
            if families.contains_key(family) {
                // Family ids are 128 random bits; a collision is not a new family.
                (Outcome::Reused, None)
            } else if families.len() >= capacity {
                (Outcome::Full, None)
            } else {
                let state = FamilyState {
                    current: 1,
                    revoked: false,
                    expires_at,
                };
                (Outcome::Accepted, Some(Record::new(family, state)))
            }
        })
    }

    /// Spends `generation` and makes `generation + 1` (already sealed, valid
    /// until `expires_at`) the redeemable token, if `generation` is still the
    /// current one. This is the single-use point: of any number of
    /// concurrent redemptions of one token, across every process sharing the
    /// journal, at most one is accepted. Any other outcome changes nothing
    /// except that `Reused` revokes the family.
    pub fn rotate(
        &mut self,
        family: &str,
        generation: u64,
        expires_at: DateTime<Utc>,
    ) -> io::Result<Outcome> {
        self.transact(|families| match families.get(family) {
            None => (Outcome::Unknown, None),
            Some(state) if state.revoked => (Outcome::Revoked, None),
            Some(state) if state.current != generation => (
                Outcome::Reused,
                Some(Record::new(
                    family,
                    FamilyState {
                        revoked: true,
                        ..*state
                    },
                )),
            ),
            Some(state) => (
                Outcome::Accepted,
                Some(Record::new(
                    family,
                    FamilyState {
                        current: generation + 1,
                        revoked: false,
                        expires_at: expires_at.max(state.expires_at),
                    },
                )),
            ),
        })
    }

    #[cfg(test)]
    pub fn get(&mut self, family: &str) -> io::Result<Option<FamilyState>> {
        self.transact(|families| (families.get(family).copied(), None))
    }

    /// Brings the state up to date (under the journal lock), lets `decide`
    /// choose an outcome and at most one change, makes the change durable,
    /// and only then applies it in memory. If writing fails, nothing changes.
    fn transact<T>(
        &mut self,
        decide: impl FnOnce(&Families) -> (T, Option<Record>),
    ) -> io::Result<T> {
        let Self {
            families, journal, ..
        } = self;
        if let Some(journal) = journal {
            journal.lock(families)?;
        }
        let result = (|| {
            let now = Utc::now();
            families.retain(|_, state| keep(state, now));
            let (outcome, change) = decide(families);
            if let Some(record) = change {
                if let Some(journal) = journal.as_mut() {
                    journal.append(&record)?;
                }
                apply(families, record);
                if let Some(journal) = journal.as_mut()
                    && let Err(error) = journal.compact_if_large(families)
                {
                    // The change itself is durable; compaction can wait.
                    tracing::warn!("Failed to compact {}: {error:#}", journal.path.display());
                }
            }
            Ok(outcome)
        })();
        if let Some(journal) = journal {
            journal.unlock();
        }
        result
    }
}

/// Whether a family still needs a slot. A revoked family is refused exactly as
/// an unknown one is, so it is dropped (and left out of compaction) at once
/// instead of counting toward the capacity until it expires; otherwise
/// authorizing a few thousand times would lock everyone else out.
fn keep(state: &FamilyState, now: DateTime<Utc>) -> bool {
    !state.revoked && state.expires_at > now
}

fn apply(families: &mut Families, record: Record) {
    families.insert(
        record.family,
        FamilyState {
            current: record.current,
            revoked: record.revoked,
            expires_at: record.expires_at,
        },
    );
}

struct Journal {
    path: PathBuf,
    file: File,
    /// Bytes of `file` already applied to the in-memory state.
    offset: u64,
    /// Records in `file`, for deciding when to compact.
    records: usize,
}

impl Journal {
    fn open_file(path: &Path) -> io::Result<File> {
        let mut options = fs::OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path)
    }

    /// Takes the exclusive lock on the journal now at `path` and applies the
    /// records appended since `offset`. If the file was replaced (compacted
    /// by another process, or deleted), switches to the new one and replays
    /// it from the start.
    fn lock(&mut self, families: &mut Families) -> io::Result<()> {
        loop {
            self.file.lock()?;
            match self.is_current() {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    self.unlock();
                    return Err(error);
                }
            }
            self.unlock();
            self.file = Self::open_file(&self.path)?;
            self.offset = 0;
            self.records = 0;
            families.clear();
        }
        self.read_tail(families).inspect_err(|_| self.unlock())
    }

    fn unlock(&self) {
        let _ = self.file.unlock();
    }

    /// Whether the open file is still the one at `path`. Off Unix there is no
    /// stable file id in std, so this is always true there; compaction (the
    /// only thing this process does that replaces the file) is disabled to
    /// match, and sharing the journal across processes is supported on Unix
    /// only.
    fn is_current(&self) -> io::Result<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let open = self.file.metadata()?;
            match fs::metadata(&self.path) {
                Ok(named) => Ok(named.dev() == open.dev() && named.ino() == open.ino()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }
        #[cfg(not(unix))]
        Ok(true)
    }

    /// Whether the file still holds what was applied: it is at least
    /// `offset` long and a record ends there. A journal truncated or rewritten
    /// in place (same inode) fails this, and must be replayed from the start
    /// rather than trusting state read from the old contents.
    fn ends_where_applied(&self) -> io::Result<bool> {
        if self.offset == 0 {
            return Ok(true);
        }
        if self.file.metadata()?.len() < self.offset {
            return Ok(false);
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(self.offset - 1))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)?;
        Ok(last[0] == b'\n')
    }

    fn read_tail(&mut self, families: &mut Families) -> io::Result<()> {
        if !self.ends_where_applied()? {
            self.offset = 0;
            self.records = 0;
            families.clear();
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(self.offset))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let complete = tail
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        for line in tail[..complete]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: Record = serde_json::from_slice(line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} holds an unreadable record: {error}",
                        self.path.display()
                    ),
                )
            })?;
            apply(families, record);
            self.records += 1;
        }
        self.offset += complete as u64;
        if complete < tail.len() {
            // We hold the lock, so no writer is mid-append: this is an append
            // that crashed before it was synced, and nothing depended on it.
            self.file.set_len(self.offset)?;
            self.file.sync_data()?;
        }
        Ok(())
    }

    fn append(&mut self, record: &Record) -> io::Result<()> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let mut file = &self.file;
        match file.write_all(&line).and_then(|()| file.sync_data()) {
            Ok(()) => {
                self.offset += line.len() as u64;
                self.records += 1;
                Ok(())
            }
            Err(error) => {
                // Keep the journal line-aligned; the change did not happen.
                let _ = self.file.set_len(self.offset);
                Err(error)
            }
        }
    }

    fn compact_if_large(&mut self, families: &Families) -> io::Result<()> {
        if self.records > 2 * families.len() + COMPACTION_SLACK {
            self.compact(families)
        } else {
            Ok(())
        }
    }

    /// Off Unix, other processes could not tell the file was replaced (see
    /// is_current), so the journal is never compacted there.
    #[cfg(not(unix))]
    fn compact(&mut self, _: &Families) -> io::Result<()> {
        Ok(())
    }

    /// Replaces the journal with one record per live family. Called with the
    /// lock held; on success the lock is held on the new file instead.
    #[cfg(unix)]
    fn compact(&mut self, families: &Families) -> io::Result<()> {
        let mut contents = Vec::new();
        for (family, state) in families {
            serde_json::to_writer(&mut contents, &Record::new(family, *state))?;
            contents.push(b'\n');
        }
        let temp = key_file::temp_path(&self.path).map_err(io::Error::other)?;
        let written =
            key_file::write_synced(&temp, &contents).and_then(|()| fs::rename(&temp, &self.path));
        if let Err(error) = written {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        key_file::sync_dir(&self.path).map_err(io::Error::other)?;
        // Lock the new file before letting go of the old one, so whoever
        // locks the new file next sees every change made so far.
        let file = Self::open_file(&self.path)?;
        file.lock()?;
        self.unlock();
        self.file = file;
        self.offset = contents.len() as u64;
        self.records = families.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn later() -> DateTime<Utc> {
        DateTime::from_timestamp((Utc::now() + Duration::hours(1)).timestamp(), 0).unwrap()
    }

    #[test]
    fn rotation_and_revocation_survive_reopening() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state/families.jsonl");
        let mut store = FamilyStore::open(&path, 16)?;
        assert_eq!(store.start("a", later())?, Outcome::Accepted);
        assert_eq!(store.start("b", later())?, Outcome::Accepted);
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Accepted);
        assert_eq!(store.rotate("a", 2, later())?, Outcome::Accepted);
        assert_eq!(store.check("b", 1)?, Outcome::Accepted);
        assert_eq!(store.check("b", 2)?, Outcome::Reused);
        drop(store);

        let mut store = FamilyStore::open(&path, 16)?;
        assert_eq!(store.check("a", 3)?, Outcome::Accepted);
        assert_eq!(store.get("a")?.unwrap().current, 3);
        assert_eq!(store.check("b", 1)?, Outcome::Unknown);
        assert_eq!(store.rotate("b", 1, later())?, Outcome::Unknown);
        assert_eq!(store.check("c", 1)?, Outcome::Unknown);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[test]
    fn a_spent_generation_revokes_and_a_failed_check_changes_nothing() -> anyhow::Result<()> {
        let mut store = FamilyStore::in_memory(16);
        store.start("a", later())?;
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Accepted);
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Reused);
        assert_eq!(store.check("a", 2)?, Outcome::Unknown);
        assert_eq!(store.rotate("missing", 1, later())?, Outcome::Unknown);
        Ok(())
    }

    #[test]
    fn revoked_families_do_not_count_toward_capacity() -> anyhow::Result<()> {
        let mut store = FamilyStore::in_memory(2);
        store.start("a", later())?;
        store.start("b", later())?;
        assert_eq!(store.start("c", later())?, Outcome::Full);
        // Reusing a spent token revokes the family; its slot is free again.
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Accepted);
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Reused);
        assert_eq!(store.start("c", later())?, Outcome::Accepted);
        // A revoked family is refused like an unknown one.
        assert_eq!(store.check("a", 2)?, Outcome::Unknown);
        assert_eq!(store.start("d", later())?, Outcome::Full);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn revoked_families_are_dropped_from_the_journal_on_open() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("families.jsonl");
        let mut store = FamilyStore::open(&path, 16)?;
        store.start("a", later())?;
        store.start("b", later())?;
        assert_eq!(store.check("a", 2)?, Outcome::Reused);
        drop(store);
        let mut store = FamilyStore::open(&path, 16)?;
        assert_eq!(fs::read_to_string(&path)?.lines().count(), 1);
        assert_eq!(store.check("a", 1)?, Outcome::Unknown);
        assert_eq!(store.check("b", 1)?, Outcome::Accepted);
        Ok(())
    }

    #[test]
    fn capacity_counts_live_families_only() -> anyhow::Result<()> {
        let mut store = FamilyStore::in_memory(1);
        assert_eq!(
            store.start("old", Utc::now() - Duration::seconds(1))?,
            Outcome::Accepted
        );
        assert_eq!(store.start("a", later())?, Outcome::Accepted);
        assert_eq!(store.start("b", later())?, Outcome::Full);
        Ok(())
    }

    #[test]
    fn a_torn_final_line_is_dropped_and_other_damage_is_an_error() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("families.jsonl");
        let mut store = FamilyStore::open(&path, 16)?;
        store.start("a", later())?;
        drop(store);

        // A crash partway through an append.
        let mut file = fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(br#"{"f":"a","g":7"#)?;
        drop(file);
        let mut store = FamilyStore::open(&path, 16)?;
        assert_eq!(store.check("a", 1)?, Outcome::Accepted);
        assert_eq!(store.rotate("a", 1, later())?, Outcome::Accepted);
        drop(store);
        assert_eq!(
            FamilyStore::open(&path, 16)?.check("a", 2)?,
            Outcome::Accepted
        );

        fs::write(&path, "not json\n")?;
        assert!(FamilyStore::open(&path, 16).is_err());
        Ok(())
    }

    #[cfg(unix)] // Compaction is disabled elsewhere (see Journal::compact).
    #[test]
    fn compaction_keeps_live_state_and_drops_expired_families() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("families.jsonl");
        let mut store = FamilyStore::open(&path, 16)?;
        store.start("expired", Utc::now() + Duration::seconds(1))?;
        store.start("a", later())?;
        for generation in 1..=(COMPACTION_SLACK as u64 + 10) {
            assert_eq!(store.rotate("a", generation, later())?, Outcome::Accepted);
        }
        let lines = fs::read_to_string(&path)?.lines().count();
        assert!(
            lines < COMPACTION_SLACK,
            "compacted while running ({lines} lines)"
        );
        std::thread::sleep(std::time::Duration::from_millis(2_100));
        drop(store);

        let mut store = FamilyStore::open(&path, 16)?;
        assert_eq!(fs::read_to_string(&path)?.lines().count(), 1);
        assert_eq!(
            store.check("a", COMPACTION_SLACK as u64 + 11)?,
            Outcome::Accepted
        );
        assert_eq!(store.check("expired", 1)?, Outcome::Unknown);
        let names: Vec<_> = fs::read_dir(dir.path())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<_>>()?;
        assert_eq!(names.len(), 1, "temporary files left behind: {names:?}");
        Ok(())
    }

    /// Two processes sharing the journal (a rolling restart): each sees the
    /// other's changes, including across a compaction that replaces the file.
    #[test]
    fn processes_sharing_the_journal_see_one_history() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("families.jsonl");
        let mut old = FamilyStore::open(&path, 16)?;
        old.start("a", later())?;
        let mut new = FamilyStore::open(&path, 16)?; // compacts: replaces the file
        assert_eq!(old.rotate("a", 1, later())?, Outcome::Accepted);
        // The new process cannot redeem the generation the old one spent.
        assert_eq!(new.rotate("a", 1, later())?, Outcome::Reused);
        assert_eq!(old.check("a", 2)?, Outcome::Unknown);
        Ok(())
    }

    /// A journal truncated in place (same inode, so not detected as replaced)
    /// must not leave another process trusting what it read before: that
    /// would let it accept a generation the truncated history had spent.
    #[test]
    fn a_journal_truncated_in_place_is_replayed_not_trusted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("families.jsonl");
        let mut first = FamilyStore::open(&path, 16)?;
        let mut second = FamilyStore::open(&path, 16)?;
        first.start("a", later())?;
        assert_eq!(first.rotate("a", 1, later())?, Outcome::Accepted);
        assert_eq!(second.check("a", 2)?, Outcome::Accepted);

        // `: > families.jsonl`, then a record for another family that ends
        // short of where `second` had read to.
        fs::OpenOptions::new().write(true).open(&path)?.set_len(0)?;
        first.start("b", later())?;
        assert!(fs::metadata(&path)?.len() > 0);

        // `second` replays the truncated journal: "a" is gone (refused, fail
        // closed), not still at generation 2 from before the truncation.
        assert_eq!(second.rotate("a", 2, later())?, Outcome::Unknown);
        assert_eq!(second.check("b", 1)?, Outcome::Accepted);
        Ok(())
    }

    /// Many redemptions of one generation at once, from separate stores on
    /// one journal: exactly one is accepted.
    #[test]
    fn concurrent_rotation_accepts_exactly_one() -> anyhow::Result<()> {
        const RACERS: usize = 8;
        for round in 0..20 {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("families.jsonl");
            FamilyStore::open(&path, 16)?.start("a", later())?;
            let barrier = std::sync::Barrier::new(RACERS);
            let outcomes: Vec<Outcome> = std::thread::scope(|scope| {
                let racers: Vec<_> = (0..RACERS)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut store = FamilyStore::open(&path, 16)?;
                            barrier.wait();
                            Ok(store.rotate("a", 1, later())?)
                        })
                    })
                    .collect();
                racers
                    .into_iter()
                    .map(|racer| racer.join().expect("racer panicked"))
                    .collect::<anyhow::Result<_>>()
            })?;
            let accepted = outcomes
                .iter()
                .filter(|outcome| **outcome == Outcome::Accepted)
                .count();
            assert_eq!(accepted, 1, "round {round}: {outcomes:?}");
            assert!(
                outcomes.iter().all(|outcome| matches!(
                    outcome,
                    Outcome::Accepted | Outcome::Reused | Outcome::Unknown
                )),
                "round {round}: {outcomes:?}"
            );
        }
        Ok(())
    }
}
