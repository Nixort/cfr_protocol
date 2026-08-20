// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

use super::{
    Error, PersistenceOptions, Result, VersionKind, HARD_MAX_STATE_BYTES, HARD_MAX_WAL_BYTES,
};
use cfr_crypto::{ct_eq, hash};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const STORE_FORMAT_VERSION: u32 = 1;

const SNAPSHOT_FILE: &str = "snapshot";
const SNAPSHOT_TEMP: &str = "snapshot.tmp";
const WAL_FILE: &str = "wal";
const WAL_TEMP: &str = "wal.tmp";
const LOCK_FILE: &str = "lock";

const SNAPSHOT_MAGIC: [u8; 8] = *b"CFRSNAP\0";
const WAL_MAGIC: [u8; 8] = *b"CFRWAL\0\0";
const RECORD_MAGIC: [u8; 8] = *b"CFRREC\0\0";
const COMMIT_MARKER: [u8; 8] = *b"CFRCMIT\0";

const WAL_HEADER_LEN: usize = 12;
const RECORD_PREFIX_LEN: usize = 8 + 8 + 8 + 32;
const RECORD_OVERHEAD: usize = RECORD_PREFIX_LEN + COMMIT_MARKER.len();
const SNAPSHOT_PREFIX_LEN: usize = 8 + 4 + 8 + 8 + 32;
const SNAPSHOT_OVERHEAD: usize = SNAPSHOT_PREFIX_LEN + COMMIT_MARKER.len();

#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) sequence: u64,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum SnapshotStatus {
    Valid(Record),
    Missing,
    Corrupt,
}

#[derive(Debug)]
pub(crate) struct Recovery {
    pub(crate) snapshot: SnapshotStatus,
    pub(crate) wal: Vec<Record>,
}

pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
    wal: File,
    #[cfg(test)]
    fault: Option<Fault>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    BeforeWrite,
    BeforeSync,
}

fn snapshot_checksum(sequence: u64, payload: &[u8]) -> [u8; 32] {
    hash(
        b"cfr/persistence/snapshot-checksum",
        &[&sequence.to_be_bytes(), payload],
    )
}

fn record_checksum(sequence: u64, payload: &[u8]) -> [u8; 32] {
    hash(
        b"cfr/persistence/wal-checksum",
        &[&sequence.to_be_bytes(), payload],
    )
}

fn encode_snapshot(sequence: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let length = u64::try_from(payload.len())
        .map_err(|_| Error::LimitExceeded("snapshot payload length exceeds u64"))?;
    let capacity = payload
        .len()
        .checked_add(SNAPSHOT_OVERHEAD)
        .ok_or(Error::LimitExceeded("snapshot size overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&STORE_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&snapshot_checksum(sequence, payload));
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&COMMIT_MARKER);
    Ok(bytes)
}

fn encode_record(sequence: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let length = u64::try_from(payload.len())
        .map_err(|_| Error::LimitExceeded("WAL payload length exceeds u64"))?;
    let capacity = payload
        .len()
        .checked_add(RECORD_OVERHEAD)
        .ok_or(Error::LimitExceeded("WAL record size overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&RECORD_MAGIC);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&record_checksum(sequence, payload));
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&COMMIT_MARKER);
    Ok(bytes)
}

fn wal_header() -> [u8; WAL_HEADER_LEN] {
    let mut header = [0u8; WAL_HEADER_LEN];
    header[..8].copy_from_slice(&WAL_MAGIC);
    header[8..].copy_from_slice(&STORE_FORMAT_VERSION.to_be_bytes());
    header
}

fn be_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn be_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

fn parse_snapshot(bytes: &[u8]) -> Result<SnapshotStatus> {
    if bytes.len() < SNAPSHOT_PREFIX_LEN || bytes.get(..8) != Some(&SNAPSHOT_MAGIC) {
        return Ok(SnapshotStatus::Corrupt);
    }
    let version = be_u32(&bytes[8..12]).ok_or(Error::Corrupt("snapshot version is truncated"))?;
    if version != STORE_FORMAT_VERSION {
        return Err(Error::UnsupportedVersion {
            kind: VersionKind::StoreEnvelope,
            found: version,
        });
    }
    let Some(sequence) = be_u64(&bytes[12..20]) else {
        return Ok(SnapshotStatus::Corrupt);
    };
    let Some(length_u64) = be_u64(&bytes[20..28]) else {
        return Ok(SnapshotStatus::Corrupt);
    };
    let Ok(length) = usize::try_from(length_u64) else {
        return Ok(SnapshotStatus::Corrupt);
    };
    if sequence == 0 || length > HARD_MAX_STATE_BYTES {
        return Ok(SnapshotStatus::Corrupt);
    }
    let Some(expected) = SNAPSHOT_OVERHEAD.checked_add(length) else {
        return Ok(SnapshotStatus::Corrupt);
    };
    if bytes.len() != expected || bytes[expected - 8..] != COMMIT_MARKER {
        return Ok(SnapshotStatus::Corrupt);
    }
    let payload = &bytes[SNAPSHOT_PREFIX_LEN..SNAPSHOT_PREFIX_LEN + length];
    let checksum = &bytes[28..60];
    if !ct_eq(checksum, &snapshot_checksum(sequence, payload)) {
        return Ok(SnapshotStatus::Corrupt);
    }
    Ok(SnapshotStatus::Valid(Record {
        sequence,
        payload: payload.to_vec(),
    }))
}

fn validate_wal_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < WAL_HEADER_LEN || bytes.get(..8) != Some(&WAL_MAGIC) {
        return Err(Error::Corrupt("WAL header is malformed"));
    }
    let version = be_u32(&bytes[8..12]).ok_or(Error::Corrupt("WAL version is truncated"))?;
    if version != STORE_FORMAT_VERSION {
        return Err(Error::UnsupportedVersion {
            kind: VersionKind::StoreEnvelope,
            found: version,
        });
    }
    Ok(())
}

fn parse_record(bytes: &[u8], start: usize) -> Result<Option<(Record, usize)>> {
    let remaining = bytes.len() - start;
    if remaining < RECORD_PREFIX_LEN {
        return Ok(None);
    }
    if bytes[start..start + 8] != RECORD_MAGIC {
        return Err(Error::Corrupt("WAL record magic is invalid"));
    }
    let sequence =
        be_u64(&bytes[start + 8..start + 16]).ok_or(Error::Corrupt("WAL sequence is truncated"))?;
    let length_u64 =
        be_u64(&bytes[start + 16..start + 24]).ok_or(Error::Corrupt("WAL length is truncated"))?;
    let length = usize::try_from(length_u64)
        .map_err(|_| Error::Corrupt("WAL record length exceeds platform width"))?;
    if sequence == 0 || length > HARD_MAX_STATE_BYTES {
        return Err(Error::Corrupt("WAL record bounds are invalid"));
    }
    let total = RECORD_OVERHEAD
        .checked_add(length)
        .ok_or(Error::Corrupt("WAL record length overflows"))?;
    if remaining < total {
        return Ok(None);
    }
    let payload_start = start + RECORD_PREFIX_LEN;
    let payload_end = payload_start + length;
    if bytes[payload_end..payload_end + 8] != COMMIT_MARKER {
        return Err(Error::Corrupt("WAL commit marker is invalid"));
    }
    let payload = &bytes[payload_start..payload_end];
    let checksum = &bytes[start + 24..start + 56];
    if !ct_eq(checksum, &record_checksum(sequence, payload)) {
        return Err(Error::Corrupt("WAL record checksum is invalid"));
    }
    Ok(Some((
        Record {
            sequence,
            payload: payload.to_vec(),
        },
        start + total,
    )))
}

fn scan_wal(bytes: &[u8]) -> Result<(Vec<Record>, usize)> {
    validate_wal_header(bytes)?;
    let mut records = Vec::new();
    let mut position = WAL_HEADER_LEN;
    let mut previous: Option<u64> = None;
    while position < bytes.len() {
        let Some((record, next)) = parse_record(bytes, position)? else {
            break;
        };
        if let Some(previous_sequence) = previous {
            let expected = previous_sequence
                .checked_add(1)
                .ok_or(Error::Corrupt("WAL sequence overflowed"))?;
            if record.sequence != expected {
                return Err(Error::Corrupt("WAL sequence is not consecutive"));
            }
        }
        previous = Some(record.sequence);
        records.push(record);
        position = next;
    }
    Ok((records, position))
}

#[cfg(unix)]
fn secure_directory_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn secure_directory_builder() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

fn secure_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

#[cfg(unix)]
fn validate_mode(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Corrupt("state path type or permissions are unsafe"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_mode(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(Error::Corrupt("state path has the wrong type"));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

fn write_atomic(directory: &Path, temporary: &str, committed: &str, bytes: &[u8]) -> Result<()> {
    let temporary_path = directory.join(temporary);
    let committed_path = directory.join(committed);
    let mut options = secure_open_options();
    options.create(true).truncate(true);
    let mut file = options.open(&temporary_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary_path, &committed_path)?;
    sync_directory(directory)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    validate_mode(path, false)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > limit {
        return Err(Error::Corrupt("persisted file exceeds hard limit"));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| Error::Corrupt("persisted file length exceeds platform width"))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn acquire_lock(directory: &Path) -> Result<File> {
    let path = directory.join(LOCK_FILE);
    let mut options = secure_open_options();
    options.create(true);
    let file = options.open(&path)?;
    validate_mode(&path, false)?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(Error::Locked),
        Err(error) => Err(Error::Io(error)),
    }
}

impl Store {
    pub(crate) fn create(path: &Path, sequence: u64, payload: &[u8]) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        secure_directory_builder().create(path)?;
        validate_mode(path, true)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        let lock = acquire_lock(path)?;
        let snapshot = encode_snapshot(sequence, payload)?;
        write_atomic(path, SNAPSHOT_TEMP, SNAPSHOT_FILE, &snapshot)?;
        write_atomic(path, WAL_TEMP, WAL_FILE, &wal_header())?;
        let wal_path = path.join(WAL_FILE);
        let wal = secure_open_options().open(&wal_path)?;
        Ok(Self {
            directory: path.to_path_buf(),
            _lock: lock,
            wal,
            #[cfg(test)]
            fault: None,
        })
    }

    pub(crate) fn open(path: &Path) -> Result<(Self, Recovery)> {
        match fs::symlink_metadata(path) {
            Ok(_) => validate_mode(path, true)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound);
            }
            Err(error) => return Err(Error::Io(error)),
        }
        let lock = acquire_lock(path)?;
        let wal_path = path.join(WAL_FILE);
        let wal_bytes = read_bounded(&wal_path, HARD_MAX_WAL_BYTES)?;
        let (records, valid_length) = scan_wal(&wal_bytes)?;
        let wal = secure_open_options().open(&wal_path)?;
        if valid_length != wal_bytes.len() {
            wal.set_len(
                u64::try_from(valid_length)
                    .map_err(|_| Error::Corrupt("valid WAL length exceeds u64"))?,
            )?;
            wal.sync_data()?;
        }
        let snapshot_path = path.join(SNAPSHOT_FILE);
        let snapshot = match read_bounded(
            &snapshot_path,
            u64::try_from(HARD_MAX_STATE_BYTES + SNAPSHOT_OVERHEAD)
                .map_err(|_| Error::Corrupt("snapshot hard limit exceeds u64"))?,
        ) {
            Ok(bytes) => parse_snapshot(&bytes)?,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                SnapshotStatus::Missing
            }
            Err(Error::Corrupt(_)) => SnapshotStatus::Corrupt,
            Err(error) => return Err(error),
        };
        Ok((
            Self {
                directory: path.to_path_buf(),
                _lock: lock,
                wal,
                #[cfg(test)]
                fault: None,
            },
            Recovery {
                snapshot,
                wal: records,
            },
        ))
    }

    pub(crate) fn validate_runtime_limits(&self, options: &PersistenceOptions) -> Result<()> {
        if self.wal.metadata()?.len() > options.max_wal_bytes {
            return Err(Error::Corrupt("WAL exceeds its persisted limit"));
        }
        Ok(())
    }

    pub(crate) fn append(
        &mut self,
        current_sequence: u64,
        current_payload: &[u8],
        candidate_sequence: u64,
        candidate_payload: &[u8],
        options: PersistenceOptions,
    ) -> Result<()> {
        if current_sequence.checked_add(1) != Some(candidate_sequence) {
            return Err(Error::Corrupt("candidate sequence is not consecutive"));
        }
        if candidate_payload.len() > options.max_record_bytes
            || candidate_payload.len() > HARD_MAX_STATE_BYTES
        {
            return Err(Error::LimitExceeded("WAL record exceeds configured limit"));
        }
        let record = encode_record(candidate_sequence, candidate_payload)?;
        let mut wal_length = self.wal.metadata()?.len();
        let record_length = u64::try_from(record.len())
            .map_err(|_| Error::LimitExceeded("WAL record length exceeds u64"))?;
        let projected = wal_length
            .checked_add(record_length)
            .ok_or(Error::LimitExceeded("WAL length overflow"))?;
        if projected > options.checkpoint_threshold || projected > options.max_wal_bytes {
            self.checkpoint(current_sequence, current_payload)?;
            wal_length = u64::try_from(WAL_HEADER_LEN)
                .map_err(|_| Error::LimitExceeded("WAL header length exceeds u64"))?;
        }
        let projected = wal_length
            .checked_add(record_length)
            .ok_or(Error::LimitExceeded("WAL length overflow"))?;
        if projected > options.max_wal_bytes {
            return Err(Error::LimitExceeded(
                "one WAL record cannot fit configured limit",
            ));
        }
        self.append_durable(wal_length, &record)
    }

    pub(crate) fn checkpoint(&mut self, sequence: u64, payload: &[u8]) -> Result<()> {
        if payload.len() > HARD_MAX_STATE_BYTES {
            return Err(Error::LimitExceeded("snapshot exceeds hard limit"));
        }
        let snapshot = encode_snapshot(sequence, payload)?;
        write_atomic(&self.directory, SNAPSHOT_TEMP, SNAPSHOT_FILE, &snapshot)?;
        write_atomic(&self.directory, WAL_TEMP, WAL_FILE, &wal_header())?;
        self.wal = secure_open_options().open(self.directory.join(WAL_FILE))?;
        Ok(())
    }

    fn append_durable(&mut self, original_length: u64, record: &[u8]) -> Result<()> {
        #[cfg(test)]
        if self.take_fault(Fault::BeforeWrite) {
            return Err(Error::Io(std::io::Error::other("injected write failure")));
        }
        self.wal.seek(SeekFrom::End(0))?;
        if let Err(error) = self.wal.write_all(record) {
            return self.rollback_append(original_length, error);
        }
        #[cfg(test)]
        if self.take_fault(Fault::BeforeSync) {
            return self.rollback_append(
                original_length,
                std::io::Error::other("injected sync failure"),
            );
        }
        if let Err(error) = self.wal.sync_data() {
            return self.rollback_append(original_length, error);
        }
        Ok(())
    }

    fn rollback_append(&mut self, original_length: u64, original: std::io::Error) -> Result<()> {
        self.wal.set_len(original_length)?;
        self.wal.sync_data()?;
        self.wal.seek(SeekFrom::End(0))?;
        Err(Error::Io(original))
    }

    #[cfg(test)]
    fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    #[cfg(test)]
    fn take_fault(&mut self, expected: Fault) -> bool {
        if self.fault == Some(expected) {
            self.fault = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self(
                std::env::temp_dir()
                    .join(format!("cfr-persistence-store-{}-{id}", std::process::id())),
            )
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn options() -> PersistenceOptions {
        PersistenceOptions::default()
    }

    #[test]
    fn snapshot_and_wal_recover_latest_record() {
        let directory = TestDirectory::new();
        let mut store = Store::create(&directory.0, 1, b"one").unwrap();
        store.append(1, b"one", 2, b"two", options()).unwrap();
        drop(store);

        let (_store, recovery) = Store::open(&directory.0).unwrap();
        assert!(matches!(recovery.snapshot, SnapshotStatus::Valid(_)));
        assert_eq!(recovery.wal.len(), 1);
        assert_eq!(recovery.wal[0].sequence, 2);
        assert_eq!(recovery.wal[0].payload, b"two");
    }

    #[test]
    fn incomplete_final_tail_is_truncated() {
        let directory = TestDirectory::new();
        let mut store = Store::create(&directory.0, 1, b"one").unwrap();
        store.append(1, b"one", 2, b"two", options()).unwrap();
        drop(store);
        let wal_path = directory.0.join(WAL_FILE);
        let valid_length = fs::metadata(&wal_path).unwrap().len();
        let mut wal = OpenOptions::new().append(true).open(&wal_path).unwrap();
        wal.write_all(&RECORD_MAGIC[..5]).unwrap();
        wal.sync_all().unwrap();
        drop(wal);

        let (_store, recovery) = Store::open(&directory.0).unwrap();
        assert_eq!(recovery.wal.len(), 1);
        assert_eq!(fs::metadata(wal_path).unwrap().len(), valid_length);
    }

    #[test]
    fn complete_bad_checksum_fails_closed() {
        let directory = TestDirectory::new();
        let mut store = Store::create(&directory.0, 1, b"one").unwrap();
        store.append(1, b"one", 2, b"two", options()).unwrap();
        drop(store);
        let path = directory.0.join(WAL_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[WAL_HEADER_LEN + 24] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(Store::open(&directory.0), Err(Error::Corrupt(_))));
    }

    #[test]
    fn corrupt_snapshot_is_reported_alongside_valid_wal() {
        let directory = TestDirectory::new();
        let mut store = Store::create(&directory.0, 1, b"one").unwrap();
        store.append(1, b"one", 2, b"two", options()).unwrap();
        drop(store);
        let path = directory.0.join(SNAPSHOT_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[28] ^= 1;
        fs::write(path, bytes).unwrap();

        let (_store, recovery) = Store::open(&directory.0).unwrap();
        assert!(matches!(recovery.snapshot, SnapshotStatus::Corrupt));
        assert_eq!(recovery.wal.len(), 1);
    }

    #[test]
    fn lock_is_exclusive_until_store_drop() {
        let directory = TestDirectory::new();
        let first = Store::create(&directory.0, 1, b"one").unwrap();
        assert!(matches!(Store::open(&directory.0), Err(Error::Locked)));
        drop(first);
        assert!(Store::open(&directory.0).is_ok());
    }

    #[test]
    fn injected_write_and_sync_failures_leave_previous_state() {
        for fault in [Fault::BeforeWrite, Fault::BeforeSync] {
            let directory = TestDirectory::new();
            let mut store = Store::create(&directory.0, 1, b"one").unwrap();
            store.inject(fault);
            assert!(matches!(
                store.append(1, b"one", 2, b"two", options()),
                Err(Error::Io(_))
            ));
            drop(store);
            let (_store, recovery) = Store::open(&directory.0).unwrap();
            assert!(recovery.wal.is_empty());
            assert!(matches!(
                recovery.snapshot,
                SnapshotStatus::Valid(Record { sequence: 1, .. })
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn created_paths_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let _store = Store::create(&directory.0, 1, b"one").unwrap();
        assert_eq!(
            fs::metadata(&directory.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [LOCK_FILE, SNAPSHOT_FILE, WAL_FILE] {
            assert_eq!(
                fs::metadata(directory.0.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
