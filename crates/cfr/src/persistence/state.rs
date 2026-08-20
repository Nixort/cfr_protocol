// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

use super::store::{Record, Recovery, SnapshotStatus};
use super::{
    DeliveryKey, Error, InboundId, OutboundId, PendingDelivery, PersistenceOptions, Recipient,
    Result, VersionKind, CURRENT_PERSISTENCE_SCHEMA_VERSION, HARD_MAX_STATE_BYTES,
};
use crate::{Conference, Message};
use cfr_core::codec::{Reader, Writer};
use cfr_crypto::hash;
use std::collections::{BTreeMap, VecDeque};

type InboundDigests = BTreeMap<InboundId, [u8; 32]>;
type InboundOrder = VecDeque<InboundId>;

pub(crate) struct LogicalState {
    pub(crate) sequence: u64,
    pub(crate) conference: Conference,
    pub(crate) options: PersistenceOptions,
    pub(crate) inbound: InboundDigests,
    inbound_order: InboundOrder,
    pub(crate) outbox: BTreeMap<OutboundId, PendingDelivery>,
    next_outbound_id: u64,
}

pub(crate) fn inbound_digest(payload: &[u8]) -> [u8; 32] {
    hash(b"cfr/persistence/inbound", &[payload])
}

fn delivery_key(
    conference: &Conference,
    id: OutboundId,
    recipient: Recipient,
    payload: &[u8],
) -> DeliveryKey {
    let id_bytes = id.0.to_be_bytes();
    let everyone = [0u8];
    let peer = [1u8];
    let digest = match recipient {
        Recipient::Everyone => hash(
            b"cfr/persistence/delivery",
            &[
                &conference.session_id(),
                conference.identity().as_bytes(),
                &id_bytes,
                &everyone,
                payload,
            ],
        ),
        Recipient::Peer(identity) => hash(
            b"cfr/persistence/delivery",
            &[
                &conference.session_id(),
                conference.identity().as_bytes(),
                &id_bytes,
                &peer,
                identity.as_bytes(),
                payload,
            ],
        ),
    };
    DeliveryKey(digest)
}

fn usize_to_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::LimitExceeded("integer exceeds persisted width"))
}

fn read_usize(reader: &mut Reader<'_>) -> Result<usize> {
    usize::try_from(reader.u64().map_err(corrupt_codec)?)
        .map_err(|_| Error::Corrupt("integer exceeds platform width"))
}

fn corrupt_codec(_: cfr_core::Error) -> Error {
    Error::Corrupt("logical state encoding is malformed")
}

fn read_options(reader: &mut Reader<'_>) -> Result<PersistenceOptions> {
    let options = PersistenceOptions {
        inbound_window: read_usize(reader)?,
        max_outbox_entries: read_usize(reader)?,
        max_state_bytes: read_usize(reader)?,
        max_record_bytes: read_usize(reader)?,
        max_wal_bytes: reader.u64().map_err(corrupt_codec)?,
        checkpoint_threshold: reader.u64().map_err(corrupt_codec)?,
    };
    options
        .validate()
        .map_err(|_| Error::Corrupt("persisted resource limits are invalid"))
}

fn write_options(writer: &mut Writer, options: PersistenceOptions) -> Result<()> {
    writer
        .u64(usize_to_u64(options.inbound_window)?)
        .u64(usize_to_u64(options.max_outbox_entries)?)
        .u64(usize_to_u64(options.max_state_bytes)?)
        .u64(usize_to_u64(options.max_record_bytes)?)
        .u64(options.max_wal_bytes)
        .u64(options.checkpoint_threshold);
    Ok(())
}

fn read_recipient(reader: &mut Reader<'_>) -> Result<Recipient> {
    match reader.u32().map_err(corrupt_codec)? {
        0 => Ok(Recipient::Everyone),
        1 => Ok(Recipient::Peer(crate::SigPublic::from_bytes(
            reader.array::<32>().map_err(corrupt_codec)?,
        ))),
        _ => Err(Error::Corrupt("outbox recipient tag is invalid")),
    }
}

fn write_recipient(writer: &mut Writer, recipient: Recipient) {
    match recipient {
        Recipient::Everyone => {
            writer.u32(0);
        }
        Recipient::Peer(identity) => {
            writer.u32(1).bytes(identity.as_bytes());
        }
    }
}

impl LogicalState {
    pub(crate) fn new(
        conference: Conference,
        messages: Vec<Message>,
        options: PersistenceOptions,
    ) -> Result<Self> {
        let mut state = Self {
            sequence: 1,
            conference,
            options,
            inbound: BTreeMap::new(),
            inbound_order: VecDeque::new(),
            outbox: BTreeMap::new(),
            next_outbound_id: 1,
        };
        state.enqueue(messages)?;
        Ok(state)
    }

    pub(crate) fn enqueue(&mut self, messages: Vec<Message>) -> Result<Vec<OutboundId>> {
        let available = self
            .options
            .max_outbox_entries
            .checked_sub(self.outbox.len())
            .ok_or(Error::Corrupt("outbox exceeds its persisted limit"))?;
        if messages.len() > available {
            return Err(Error::LimitExceeded("durable outbox is full"));
        }
        let count = u64::try_from(messages.len())
            .map_err(|_| Error::LimitExceeded("too many outbound messages"))?;
        self.next_outbound_id
            .checked_add(count)
            .ok_or(Error::LimitExceeded("outbound identifier exhausted"))?;

        let mut ids = Vec::with_capacity(messages.len());
        for message in messages {
            let id = OutboundId(self.next_outbound_id);
            self.next_outbound_id += 1;
            let delivery = PendingDelivery {
                id,
                delivery_key: delivery_key(&self.conference, id, message.to, &message.payload),
                recipient: message.to,
                payload: message.payload,
            };
            self.outbox.insert(id, delivery);
            ids.push(id);
        }
        Ok(ids)
    }

    pub(crate) fn record_inbound(&mut self, id: InboundId, digest: [u8; 32]) {
        self.inbound.insert(id, digest);
        self.inbound_order.push_back(id);
        while self.inbound_order.len() > self.options.inbound_window {
            if let Some(expired) = self.inbound_order.pop_front() {
                self.inbound.remove(&expired);
            }
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let conference = self.conference.export_persistence_state()?;
        let inbound: Vec<(InboundId, [u8; 32])> = self
            .inbound_order
            .iter()
            .map(|id| {
                self.inbound
                    .get(id)
                    .copied()
                    .map(|digest| (*id, digest))
                    .ok_or(Error::Corrupt("inbound eviction order is inconsistent"))
            })
            .collect::<Result<_>>()?;
        if inbound.len() != self.inbound.len() {
            return Err(Error::Corrupt("inbound eviction order is inconsistent"));
        }

        let mut writer = Writer::new();
        writer
            .u32(CURRENT_PERSISTENCE_SCHEMA_VERSION)
            .u64(self.sequence);
        write_options(&mut writer, self.options)?;
        writer.bytes(&conference);
        writer.list(&inbound, |writer, (id, digest)| {
            writer.bytes(id.as_bytes()).bytes(digest);
        });
        let outbox: Vec<_> = self.outbox.values().collect();
        writer.list(&outbox, |writer, delivery| {
            writer
                .u64(delivery.id.0)
                .bytes(delivery.delivery_key.as_bytes());
            write_recipient(writer, delivery.recipient);
            writer.bytes(&delivery.payload);
        });
        writer.u64(self.next_outbound_id);
        let bytes = writer.finish();
        if bytes.len() > self.options.max_state_bytes || bytes.len() > HARD_MAX_STATE_BYTES {
            return Err(Error::LimitExceeded(
                "logical state exceeds configured limit",
            ));
        }
        if bytes.len() > self.options.max_record_bytes {
            return Err(Error::LimitExceeded("WAL record exceeds configured limit"));
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8], envelope_sequence: u64) -> Result<Self> {
        if bytes.len() > HARD_MAX_STATE_BYTES {
            return Err(Error::Corrupt("logical state exceeds hard limit"));
        }
        let mut reader = Reader::new(bytes);
        let schema = reader.u32().map_err(corrupt_codec)?;
        if schema != CURRENT_PERSISTENCE_SCHEMA_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: VersionKind::PersistenceSchema,
                found: schema,
            });
        }
        let sequence = reader.u64().map_err(corrupt_codec)?;
        if sequence == 0 || sequence != envelope_sequence {
            return Err(Error::Corrupt("logical and envelope sequences differ"));
        }
        let options = read_options(&mut reader)?;
        if bytes.len() > options.max_state_bytes || bytes.len() > options.max_record_bytes {
            return Err(Error::Corrupt("logical state exceeds persisted limits"));
        }
        let conference_bytes = reader.bytes().map_err(corrupt_codec)?;
        let conference = Conference::import_persistence_state(conference_bytes)
            .map_err(|_| Error::Corrupt("conference state failed validation"))?;
        let (inbound, inbound_order) = Self::read_inbound(&mut reader, options)?;
        let outbox = Self::read_outbox(&mut reader, &conference, options)?;
        let next_outbound_id = reader.u64().map_err(corrupt_codec)?;
        reader.finish().map_err(corrupt_codec)?;
        if next_outbound_id == 0
            || outbox
                .keys()
                .next_back()
                .is_some_and(|last| last.0 >= next_outbound_id)
        {
            return Err(Error::Corrupt("next outbound identifier is invalid"));
        }
        let state = Self {
            sequence,
            conference,
            options,
            inbound,
            inbound_order,
            outbox,
            next_outbound_id,
        };
        let canonical = state
            .encode()
            .map_err(|_| Error::Corrupt("logical state is not re-encodable"))?;
        if canonical != bytes {
            return Err(Error::Corrupt("logical state encoding is non-canonical"));
        }
        Ok(state)
    }

    fn read_inbound(
        reader: &mut Reader<'_>,
        options: PersistenceOptions,
    ) -> Result<(InboundDigests, InboundOrder)> {
        let entries: Vec<(InboundId, [u8; 32])> = reader
            .list(|reader| Ok((InboundId(reader.array::<32>()?), reader.array::<32>()?)))
            .map_err(corrupt_codec)?;
        if entries.len() > options.inbound_window {
            return Err(Error::Corrupt("inbound window exceeds persisted limit"));
        }
        let mut inbound = BTreeMap::new();
        let mut order = VecDeque::with_capacity(entries.len());
        for (id, digest) in entries {
            if inbound.insert(id, digest).is_some() {
                return Err(Error::Corrupt("inbound window contains a duplicate ID"));
            }
            order.push_back(id);
        }
        Ok((inbound, order))
    }

    fn read_outbox(
        reader: &mut Reader<'_>,
        conference: &Conference,
        options: PersistenceOptions,
    ) -> Result<BTreeMap<OutboundId, PendingDelivery>> {
        let entries: Vec<PendingDelivery> = reader
            .list(|reader| {
                Ok(PendingDelivery {
                    id: OutboundId(reader.u64()?),
                    delivery_key: DeliveryKey(reader.array::<32>()?),
                    recipient: read_recipient(reader)
                        .map_err(|_| cfr_core::Error::Encoding("invalid persisted recipient"))?,
                    payload: reader.bytes()?.to_vec(),
                })
            })
            .map_err(corrupt_codec)?;
        if entries.len() > options.max_outbox_entries {
            return Err(Error::Corrupt("outbox exceeds persisted limit"));
        }
        let mut outbox = BTreeMap::new();
        let mut previous = None;
        for delivery in entries {
            if delivery.id.0 == 0
                || previous.is_some_and(|id: OutboundId| id >= delivery.id)
                || delivery.delivery_key
                    != delivery_key(
                        conference,
                        delivery.id,
                        delivery.recipient,
                        &delivery.payload,
                    )
            {
                return Err(Error::Corrupt("outbox delivery binding is invalid"));
            }
            previous = Some(delivery.id);
            outbox.insert(delivery.id, delivery);
        }
        Ok(outbox)
    }

    pub(crate) fn recover(recovery: Recovery) -> Result<Self> {
        let snapshot = match recovery.snapshot {
            SnapshotStatus::Valid(record) => match Self::decode(&record.payload, record.sequence) {
                Ok(state) => Some((state, record)),
                Err(Error::UnsupportedVersion { kind, found }) => {
                    return Err(Error::UnsupportedVersion { kind, found });
                }
                Err(_) => None,
            },
            SnapshotStatus::Missing | SnapshotStatus::Corrupt => None,
        };

        let mut wal_states = Vec::with_capacity(recovery.wal.len());
        for record in recovery.wal {
            wal_states.push((Self::decode(&record.payload, record.sequence)?, record));
        }
        Self::select_recovered(snapshot, wal_states)
    }

    fn select_recovered(
        snapshot: Option<(Self, Record)>,
        wal: Vec<(Self, Record)>,
    ) -> Result<Self> {
        let Some((mut selected, snapshot_record)) = snapshot else {
            return wal
                .into_iter()
                .last()
                .map(|(state, _)| state)
                .ok_or(Error::Corrupt("no valid complete persisted state"));
        };
        let mut selected_sequence = selected.sequence;
        for (state, record) in wal {
            if state.sequence < selected_sequence {
                continue;
            }
            if state.sequence == selected_sequence {
                if state.sequence == snapshot_record.sequence
                    && record.payload != snapshot_record.payload
                {
                    return Err(Error::Corrupt("snapshot and WAL disagree at one sequence"));
                }
                continue;
            }
            if state.sequence != selected_sequence + 1 {
                return Err(Error::Corrupt("WAL sequence has a gap after snapshot"));
            }
            selected = state;
            selected_sequence = selected.sequence;
        }
        Ok(selected)
    }
}
