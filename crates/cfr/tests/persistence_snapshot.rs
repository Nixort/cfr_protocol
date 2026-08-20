// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Filesystem corruption, version, and WAL-compaction acceptance tests.

#![allow(missing_docs)]

use cfr::layers::crypto::hash;
use cfr::persistence::{
    Error, PersistenceOptions, PersistentConference, VersionKind,
    CURRENT_PERSISTENCE_SCHEMA_VERSION,
};
use cfr::Policy;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SNAPSHOT_PREFIX: usize = 60;
const WAL_HEADER: usize = 12;
const RECORD_PREFIX: usize = 56;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "cfr-persistence-snapshot-{label}-{}-{id}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn snapshot(&self) -> PathBuf {
        self.0.join("snapshot")
    }

    fn wal(&self) -> PathBuf {
        self.0.join("wal")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy() -> Policy {
    Policy::leaderless(2)
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

fn write_synced(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn rewrite_snapshot_checksum(bytes: &mut [u8]) {
    let sequence_bytes: [u8; 8] = bytes[12..20].try_into().unwrap();
    let length = usize::try_from(read_u64(&bytes[20..28])).unwrap();
    let payload = &bytes[SNAPSHOT_PREFIX..SNAPSHOT_PREFIX + length];
    let checksum = hash(
        b"cfr/persistence/snapshot-checksum",
        &[&sequence_bytes, payload],
    );
    bytes[28..60].copy_from_slice(&checksum);
}

#[test]
fn valid_wal_newer_than_snapshot_restores_latest_state() {
    let directory = TestDirectory::new("newer-wal");
    let mut conference = PersistentConference::create(directory.path(), policy()).unwrap();
    let identity = conference.identity();
    conference.tick().unwrap();
    conference.rekey().unwrap();
    let latest_sequence = conference.sequence();
    let latest_version = conference.version();
    drop(conference);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.identity(), identity);
    assert_eq!(reopened.sequence(), latest_sequence);
    assert_eq!(reopened.version(), latest_version);
}

#[test]
fn incomplete_final_wal_record_is_removed_without_losing_valid_state() {
    let directory = TestDirectory::new("tail");
    let mut conference = PersistentConference::create(directory.path(), policy()).unwrap();
    conference.tick().unwrap();
    let sequence = conference.sequence();
    let identity = conference.identity();
    drop(conference);

    let wal_path = directory.wal();
    let valid_length = fs::metadata(&wal_path).unwrap().len();
    let mut wal = OpenOptions::new().append(true).open(&wal_path).unwrap();
    wal.write_all(b"CFRREC\0\0").unwrap();
    wal.write_all(&(sequence + 1).to_be_bytes()).unwrap();
    wal.write_all(&100u64.to_be_bytes()).unwrap();
    wal.write_all(&[0xA5; 32]).unwrap();
    wal.write_all(b"partial").unwrap();
    wal.sync_all().unwrap();
    drop(wal);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.sequence(), sequence);
    assert_eq!(reopened.identity(), identity);
    assert_eq!(fs::metadata(wal_path).unwrap().len(), valid_length);
}

#[test]
fn complete_wal_checksum_or_marker_corruption_fails_closed() {
    for corrupt_marker in [false, true] {
        let directory = TestDirectory::new(if corrupt_marker { "marker" } else { "checksum" });
        let mut conference = PersistentConference::create(directory.path(), policy()).unwrap();
        conference.tick().unwrap();
        drop(conference);

        let wal_path = directory.wal();
        let mut bytes = fs::read(&wal_path).unwrap();
        let payload_length =
            usize::try_from(read_u64(&bytes[WAL_HEADER + 16..WAL_HEADER + 24])).unwrap();
        if corrupt_marker {
            bytes[WAL_HEADER + RECORD_PREFIX + payload_length] ^= 1;
        } else {
            bytes[WAL_HEADER + 24] ^= 1;
        }
        write_synced(&wal_path, &bytes);
        let before = fs::read(&wal_path).unwrap();
        assert!(matches!(
            PersistentConference::open(directory.path()),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(fs::read(wal_path).unwrap(), before);
    }
}

#[test]
fn corrupt_snapshot_falls_back_to_newer_full_state_wal() {
    let directory = TestDirectory::new("snapshot-fallback");
    let mut conference = PersistentConference::create(directory.path(), policy()).unwrap();
    let identity = conference.identity();
    conference.tick().unwrap();
    let sequence = conference.sequence();
    drop(conference);

    let snapshot_path = directory.snapshot();
    let mut snapshot = fs::read(&snapshot_path).unwrap();
    snapshot[28] ^= 1;
    write_synced(&snapshot_path, &snapshot);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.identity(), identity);
    assert_eq!(reopened.sequence(), sequence);
}

#[test]
fn corrupt_snapshot_without_wal_state_fails_closed() {
    let directory = TestDirectory::new("snapshot-only-corrupt");
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    drop(conference);
    let snapshot_path = directory.snapshot();
    let mut snapshot = fs::read(&snapshot_path).unwrap();
    snapshot[28] ^= 1;
    write_synced(&snapshot_path, &snapshot);
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn unknown_snapshot_and_wal_envelope_versions_are_explicit() {
    let snapshot_directory = TestDirectory::new("snapshot-version");
    let conference = PersistentConference::create(snapshot_directory.path(), policy()).unwrap();
    drop(conference);
    let path = snapshot_directory.snapshot();
    let mut snapshot = fs::read(&path).unwrap();
    snapshot[8..12].copy_from_slice(&99u32.to_be_bytes());
    write_synced(&path, &snapshot);
    assert!(matches!(
        PersistentConference::open(snapshot_directory.path()),
        Err(Error::UnsupportedVersion {
            kind: VersionKind::StoreEnvelope,
            found: 99
        })
    ));

    let wal_directory = TestDirectory::new("wal-version");
    let conference = PersistentConference::create(wal_directory.path(), policy()).unwrap();
    drop(conference);
    let path = wal_directory.wal();
    let mut wal = fs::read(&path).unwrap();
    wal[8..12].copy_from_slice(&77u32.to_be_bytes());
    write_synced(&path, &wal);
    assert!(matches!(
        PersistentConference::open(wal_directory.path()),
        Err(Error::UnsupportedVersion {
            kind: VersionKind::StoreEnvelope,
            found: 77
        })
    ));
}

#[test]
fn unknown_logical_schema_is_explicit_and_not_autodetected() {
    assert_eq!(CURRENT_PERSISTENCE_SCHEMA_VERSION, 1);
    let directory = TestDirectory::new("schema-version");
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    drop(conference);
    let path = directory.snapshot();
    let mut snapshot = fs::read(&path).unwrap();
    assert_eq!(snapshot[SNAPSHOT_PREFIX], 2, "schema is a TLV integer");
    snapshot[SNAPSHOT_PREFIX + 1..SNAPSHOT_PREFIX + 9].copy_from_slice(&99u64.to_be_bytes());
    rewrite_snapshot_checksum(&mut snapshot);
    write_synced(&path, &snapshot);
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::UnsupportedVersion {
            kind: VersionKind::PersistenceSchema,
            found: 99
        })
    ));
}

#[test]
fn small_checkpoint_threshold_compacts_before_each_crossing() {
    let directory = TestDirectory::new("wal-limit");
    let options = PersistenceOptions {
        checkpoint_threshold: 1,
        max_wal_bytes: 256 * 1024,
        ..PersistenceOptions::default()
    };
    let mut conference =
        PersistentConference::create_with_options(directory.path(), policy(), options).unwrap();
    conference.tick().unwrap();
    conference.tick().unwrap();
    conference.rekey().unwrap();
    let sequence = conference.sequence();
    let identity = conference.identity();
    assert!(fs::metadata(directory.wal()).unwrap().len() <= options.max_wal_bytes);
    drop(conference);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.sequence(), sequence);
    assert_eq!(reopened.identity(), identity);
    assert!(fs::metadata(directory.wal()).unwrap().len() <= options.max_wal_bytes);
}

#[test]
fn snapshot_with_trailing_bytes_is_not_accepted() {
    let directory = TestDirectory::new("snapshot-trailing");
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    drop(conference);
    let path = directory.snapshot();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"trailing").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn state_directory_cannot_be_recreated_over_existing_data() {
    let directory = TestDirectory::new("already-exists");
    fs::create_dir(directory.path()).unwrap();
    assert!(matches!(
        PersistentConference::create(directory.path(), policy()),
        Err(Error::AlreadyExists)
    ));
    assert!(fs::metadata(directory.path()).unwrap().is_dir());
}

#[test]
fn missing_wal_in_existing_state_is_corruption_not_absence() {
    let directory = TestDirectory::new("missing-wal");
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    drop(conference);
    fs::remove_file(directory.wal()).unwrap();
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::Corrupt("WAL file is missing"))
    ));
}

#[test]
fn single_component_relative_state_path_is_supported() {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = TestDirectory(PathBuf::from(format!(
        "cfr-relative-persistence-{}-{id}",
        std::process::id()
    )));
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    let identity = conference.identity();
    drop(conference);
    assert_eq!(
        PersistentConference::open(directory.path())
            .unwrap()
            .identity(),
        identity
    );
}
