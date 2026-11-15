//! 32-byte secret keys kept in files, shared by every process that points at
//! the same path (replicas on one volume, or the old and new process during a
//! rolling restart).
//!
//! A key is published atomically: it is written in full to a uniquely named
//! temporary file in the same directory, synced, and then hard-linked to its
//! final name. `link` never replaces an existing name, so when several
//! processes start against an empty directory exactly one key wins, and the
//! others read the winner's. A reader can only ever see a complete key.

use std::{
    fs, io,
    io::Write as _,
    path::{Path, PathBuf},
};

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use anyhow::{Context as _, Result, anyhow};

pub const KEY_BYTES: usize = 32;

pub fn random_key() -> [u8; KEY_BYTES] {
    let mut key = [0_u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    key
}

/// Reads the key at `path`, creating it (file mode 0600, directory 0700) if
/// it does not exist yet. A file of any other length is an error rather than
/// being silently replaced.
pub fn load_or_create_key(path: &Path) -> Result<[u8; KEY_BYTES]> {
    if let Some(key) = read_key(path)? {
        return Ok(key);
    }
    if let Some(dir) = parent_dir(path) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    publish_key(path, &random_key())
}

/// Publishes `key` at `path` unless a key is already there, and returns the
/// key that is published at `path` afterwards (ours, or the one that won).
fn publish_key(path: &Path, key: &[u8; KEY_BYTES]) -> Result<[u8; KEY_BYTES]> {
    let temp = temp_path(path)?;
    let result = write_synced(&temp, key)
        .with_context(|| format!("Failed to write {}", temp.display()))
        .and_then(|()| match fs::hard_link(&temp, path) {
            Ok(()) => {
                sync_dir(path)?;
                Ok(*key)
            }
            // Another process published first: use theirs, which is complete
            // because it, too, was linked only after being synced.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(path)?
                .ok_or_else(|| anyhow!("{} vanished while it was being created", path.display())),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "Failed to publish {} (the filesystem must support hard links)",
                    path.display()
                )
            }),
        });
    // The temporary name is never needed again, whoever won.
    let _ = fs::remove_file(&temp);
    result
}

/// None when there is no file at `path`.
fn read_key(path: &Path) -> Result<Option<[u8; KEY_BYTES]>> {
    match fs::read(path) {
        Ok(bytes) => bytes.try_into().map(Some).map_err(|bytes: Vec<u8>| {
            anyhow!(
                "{} must hold exactly {KEY_BYTES} bytes (found {}); delete it to generate a new key",
                path.display(),
                bytes.len()
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to read {}", path.display())),
    }
}

pub(crate) fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent().filter(|dir| !dir.as_os_str().is_empty())
}

/// `.<name>.<random>.tmp` beside `path`, so the final link stays on one
/// filesystem and concurrent writers never share a temporary file.
pub(crate) fn temp_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{suffix}.tmp"));
    Ok(path.with_file_name(temp_name))
}

pub(crate) fn write_synced(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Makes the new directory entry durable, so a crash cannot lose a key that
/// clients have already been handed values derived from.
pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(dir) = parent_dir(path) {
        fs::File::open(dir)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("Failed to sync {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn key_persists_and_wrong_length_is_an_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state/test.key");
        let first = load_or_create_key(&path)?;
        assert_eq!(load_or_create_key(&path)?, first);
        assert_eq!(fs::read(&path)?, first);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            let parent = fs::metadata(path.parent().unwrap())?;
            assert_eq!(parent.permissions().mode() & 0o777, 0o700);
        }

        fs::write(&path, b"short")?;
        assert!(load_or_create_key(&path).is_err());
        assert_eq!(fs::read(&path)?, b"short", "a bad key is never replaced");
        Ok(())
    }

    #[test]
    fn publishing_never_replaces_an_existing_key() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.key");
        let winner = [1_u8; KEY_BYTES];
        assert_eq!(publish_key(&path, &winner)?, winner);
        // A process that lost the race gets the winner's key back.
        assert_eq!(publish_key(&path, &[2_u8; KEY_BYTES])?, winner);
        assert_eq!(fs::read(&path)?, winner);
        assert_eq!(entries(dir.path())?, vec!["test.key".to_string()]);
        Ok(())
    }

    /// Replicas starting together against an empty directory (which does not
    /// exist yet either) all load the same, complete key.
    #[test]
    fn concurrent_first_start_agrees_on_one_complete_key() -> Result<()> {
        const STARTERS: usize = 8;
        for round in 0..50 {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("state/test.key");
            let barrier = Barrier::new(STARTERS);
            let keys: Vec<Result<[u8; KEY_BYTES]>> = std::thread::scope(|scope| {
                let starters: Vec<_> = (0..STARTERS)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            load_or_create_key(&path)
                        })
                    })
                    .collect();
                starters
                    .into_iter()
                    .map(|starter| starter.join().expect("starter panicked"))
                    .collect()
            });
            let keys = keys
                .into_iter()
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("round {round}: a starter failed"))?;
            assert!(
                keys.iter().all(|key| *key == keys[0]),
                "round {round}: starters disagree on the key"
            );
            assert_eq!(fs::read(&path)?, keys[0], "round {round}");
            assert_eq!(
                entries(path.parent().unwrap())?,
                vec!["test.key".to_string()],
                "round {round}: temporary files left behind"
            );
        }
        Ok(())
    }

    fn entries(dir: &Path) -> Result<Vec<String>> {
        let mut names = fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }
}
