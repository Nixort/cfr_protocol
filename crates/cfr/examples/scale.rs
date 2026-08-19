// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Reproducible CFR scale benchmark.
use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use cfr::layers::core::Message as CoreMessage;
use cfr::{Codec, Conference, Joining, Message, Policy, Recipient};
use cfr_crypto::SigPublic;

const DEFAULT_PARTICIPANTS: usize = 100;
const DEFAULT_MEDIA_ROUNDS: u32 = 200;
const FRAME_BYTES: usize = 40_000;
const MIN_PARTICIPANTS: usize = 8;

#[derive(Debug, Clone, Copy)]
struct BenchConfig {
    participants: usize,
    media_rounds: u32,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            participants: DEFAULT_PARTICIPANTS,
            media_rounds: DEFAULT_MEDIA_ROUNDS,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Traffic {
    messages: usize,
    upload_bytes: usize,
    per_recipient_bytes: usize,
}

impl Traffic {
    fn record(&mut self, message: &Message) {
        self.messages += 1;
        self.upload_bytes += message.payload.len();
        if message.to == Recipient::Everyone {
            self.per_recipient_bytes += message.payload.len();
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Measurement {
    operation: &'static str,
    traffic: Traffic,
    elapsed: Duration,
}

impl Measurement {
    fn csv_row(self, participants: usize) {
        println!(
            "{},{},{},{},{},{:.3}",
            self.operation,
            participants,
            self.traffic.messages,
            self.traffic.upload_bytes,
            self.traffic.per_recipient_bytes,
            self.elapsed.as_secs_f64() * 1_000.0,
        );
    }
}

struct Net {
    peers: BTreeMap<SigPublic, Conference>,
    queue: VecDeque<(SigPublic, Vec<u8>)>,
    traffic: Traffic,
}

impl Net {
    fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            queue: VecDeque::new(),
            traffic: Traffic::default(),
        }
    }

    fn reset_traffic(&mut self) {
        self.traffic = Traffic::default();
    }

    fn peer(&self, id: &SigPublic) -> Result<&Conference, String> {
        self.peers
            .get(id)
            .ok_or_else(|| "benchmark invariant failed: peer is absent".to_owned())
    }

    fn peer_mut(&mut self, id: &SigPublic) -> Result<&mut Conference, String> {
        self.peers
            .get_mut(id)
            .ok_or_else(|| "benchmark invariant failed: peer is absent".to_owned())
    }

    fn send(&mut self, from: SigPublic, outbound: Vec<Message>, count_traffic: bool) {
        for message in outbound {
            if count_traffic {
                self.traffic.record(&message);
            }
            let recipients: Vec<SigPublic> = match message.to {
                Recipient::Everyone => self
                    .peers
                    .keys()
                    .filter(|identity| **identity != from)
                    .copied()
                    .collect(),
                Recipient::Peer(identity) => vec![identity],
            };
            for recipient in recipients {
                if self.peers.contains_key(&recipient) {
                    self.queue.push_back((recipient, message.payload.clone()));
                }
            }
        }
    }

    fn settle(&mut self, count_traffic: bool) -> Result<(), String> {
        while let Some((recipient, payload)) = self.queue.pop_front() {
            let outbound = self
                .peer_mut(&recipient)?
                .handle(&payload)
                .map_err(|error| format!("benchmark delivery to {recipient:?} failed: {error:?}"))?
                .1;
            self.send(recipient, outbound, count_traffic);
        }
        Ok(())
    }

    fn measured<F>(&mut self, operation: &'static str, action: F) -> Result<Measurement, String>
    where
        F: FnOnce(&mut Self) -> Result<(), String>,
    {
        self.reset_traffic();
        let started = Instant::now();
        action(self)?;
        Ok(Measurement {
            operation,
            traffic: self.traffic,
            elapsed: started.elapsed(),
        })
    }

    fn assert_agreement(&self, expected_members: usize) -> Result<(), String> {
        let Some((_, first)) = self.peers.first_key_value() else {
            return Err("benchmark invariant failed: conference is empty".to_owned());
        };
        let version = first.version();
        for (identity, peer) in &self.peers {
            if !peer.ready() {
                return Err(format!(
                    "benchmark invariant failed: {identity:?} lacks the group key"
                ));
            }
            if peer.members().len() != expected_members {
                return Err(format!(
                    "benchmark invariant failed: {identity:?} sees {} members, expected {expected_members}",
                    peer.members().len()
                ));
            }
            if peer.version() != version {
                return Err("benchmark invariant failed: participants diverged".to_owned());
            }
        }
        Ok(())
    }
}

fn parse_args() -> Result<BenchConfig, String> {
    let mut config = BenchConfig::default();
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--participants" => {
                config.participants = value
                    .parse()
                    .map_err(|_| format!("invalid participant count: {value}"))?;
            }
            "--rounds" => {
                config.media_rounds = value
                    .parse()
                    .map_err(|_| format!("invalid media round count: {value}"))?;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if config.participants < MIN_PARTICIPANTS {
        return Err(format!(
            "--participants must be at least {MIN_PARTICIPANTS} for the selected scenarios"
        ));
    }
    if config.media_rounds == 0 {
        return Err("--rounds must be positive".to_owned());
    }
    Ok(config)
}

fn conference_error(context: &str, error: impl core::fmt::Debug) -> String {
    format!("{context}: {error:?}")
}

struct PreparedConference {
    net: Net,
    identities: Vec<SigPublic>,
    join: Measurement,
    build_elapsed: Duration,
    welcome_bytes: usize,
}

fn build_conference(participants: usize) -> Result<PreparedConference, String> {
    let policy = || Policy::leaderless(2);
    let mut net = Net::new();
    let (founder, outbound) =
        Conference::create(policy()).map_err(|error| conference_error("create", error))?;
    let founder_id = founder.identity();
    net.peers.insert(founder_id, founder);
    net.send(founder_id, outbound, false);
    net.settle(false)?;

    let build_started = Instant::now();
    let mut join = None;
    let mut welcome_bytes = 0;
    for participant_index in 1..participants {
        let joining =
            Joining::new(policy()).map_err(|error| conference_error("join identity", error))?;
        let package = joining.key_package();
        let identity = joining.identity();

        net.reset_traffic();
        let outbound = net
            .peer_mut(&founder_id)?
            .invite(&package)
            .map_err(|error| conference_error("invite", error))?;
        let welcome = outbound
            .iter()
            .find(|message| message.to == Recipient::Peer(identity))
            .ok_or_else(|| "benchmark invariant failed: invitation has no welcome".to_owned())?
            .payload
            .clone();
        welcome_bytes = welcome.len();
        let (participant, participant_outbound) = joining
            .accept(&welcome)
            .map_err(|error| conference_error("accept welcome", error))?;
        net.peers.insert(identity, participant);
        // The joiner already consumed the welcome locally to become a
        // participant. Count that direct message in the measured traffic, but
        // do not enqueue it a second time: an existing participant correctly
        // rejects a duplicate welcome.
        net.traffic.record(
            outbound
                .iter()
                .find(|message| message.to == Recipient::Peer(identity))
                .expect("welcome selected above"),
        );
        let remaining_outbound: Vec<Message> = outbound
            .into_iter()
            .filter(|message| message.to != Recipient::Peer(identity))
            .collect();
        net.send(founder_id, remaining_outbound, true);
        net.send(identity, participant_outbound, true);
        net.settle(true)?;
        if participant_index + 1 == participants {
            join = Some(Measurement {
                operation: "join",
                traffic: net.traffic,
                elapsed: Duration::ZERO,
            });
        }
    }
    net.assert_agreement(participants)?;
    let identities = net.peers.keys().copied().collect();
    Ok(PreparedConference {
        net,
        identities,
        join: join.ok_or_else(|| "benchmark invariant failed: no join measurement".to_owned())?,
        build_elapsed: build_started.elapsed(),
        welcome_bytes,
    })
}

fn measure_rotation(
    net: &mut Net,
    identities: &[SigPublic],
    participants: usize,
) -> Result<Measurement, String> {
    let initial_version = net.peer(&identities[0])?.version();
    net.measured("rotation", |network| {
        let outbound = network
            .peer_mut(&identities[7])?
            .rekey()
            .map_err(|error| conference_error("rotate contribution", error))?;
        network.send(identities[7], outbound, true);
        network.settle(true)?;
        network.assert_agreement(participants)?;
        if network.peer(&identities[0])?.version() == initial_version {
            return Err(
                "benchmark invariant failed: rotation did not change the version".to_owned(),
            );
        }
        Ok(())
    })
}

fn measure_eviction(net: &mut Net, identities: &[SigPublic]) -> Result<Measurement, String> {
    let victim = *identities
        .last()
        .ok_or_else(|| "benchmark invariant failed: conference is empty".to_owned())?;
    net.measured("eviction_quorum_2", |network| {
        for evictor in [identities[0], identities[1]] {
            let outbound = network
                .peer_mut(&evictor)?
                .evict(&victim)
                .map_err(|error| conference_error("evict", error))?;
            network.send(evictor, outbound, true);
            network.settle(true)?;
        }
        if network.peer(&identities[0])?.members().contains(&victim) {
            return Err(
                "benchmark invariant failed: quorum eviction did not take effect".to_owned(),
            );
        }
        Ok(())
    })
}

fn measure_healing(net: &mut Net, identities: &[SigPublic]) -> Result<Measurement, String> {
    net.measured("heal", |network| {
        let outbound = network
            .peer_mut(&identities[3])?
            .heal()
            .map_err(|error| conference_error("heal", error))?;
        network.send(identities[3], outbound, true);
        network.settle(true)
    })
}

fn measure_media(
    net: &mut Net,
    identities: &[SigPublic],
    rounds: u32,
) -> Result<(Measurement, usize), String> {
    let frame: Vec<u8> = (0..FRAME_BYTES)
        .map(|index| u8::try_from(index % 251).expect("reduced byte is in range"))
        .collect();
    let mut sealed = Vec::new();
    let started = Instant::now();
    for _ in 0..rounds {
        sealed = net
            .peer_mut(&identities[0])?
            .protect(Codec::H264, &frame, false)
            .map_err(|error| conference_error("protect media", error))?;
    }
    let opened = net
        .peer_mut(&identities[1])?
        .open(&sealed)
        .map_err(|error| conference_error("open media", error))?;
    if opened.1 != frame {
        return Err("benchmark invariant failed: media round trip changed the frame".to_owned());
    }
    Ok((
        Measurement {
            operation: "media_protect",
            traffic: Traffic::default(),
            elapsed: started.elapsed() / rounds,
        },
        sealed.len() - frame.len(),
    ))
}

fn run(config: BenchConfig) -> Result<(), String> {
    let mut prepared = build_conference(config.participants)?;
    let rotation = measure_rotation(&mut prepared.net, &prepared.identities, config.participants)?;
    let eviction = measure_eviction(&mut prepared.net, &prepared.identities)?;
    let healing = measure_healing(&mut prepared.net, &prepared.identities)?;
    let (media, frame_overhead) =
        measure_media(&mut prepared.net, &prepared.identities, config.media_rounds)?;

    let state_bytes = prepared.net.peer(&prepared.identities[0])?.state_bytes();
    let history_len = prepared.net.peer(&prepared.identities[0])?.history_len();
    let sync = prepared.net.peer_mut(&prepared.identities[0])?.resync();
    let sync_message = sync
        .iter()
        .find(|message| message.to == Recipient::Everyone)
        .ok_or_else(|| "benchmark invariant failed: resync emitted no Sync message".to_owned())?;
    let CoreMessage::Sync { heads, .. } = CoreMessage::from_wire(&sync_message.payload)
        .map_err(|error| conference_error("parse sync summary", error))?
    else {
        return Err("benchmark invariant failed: resync emitted a non-Sync message".to_owned());
    };
    println!(
        "# cfr-bench,participants={},media_rounds={},build_ms={:.3},state_bytes={},history_operations={},sync_summary_bytes={},sync_heads={},frame_bytes={},frame_overhead_bytes={},join_welcome_bytes={}",
        config.participants,
        config.media_rounds,
        prepared.build_elapsed.as_secs_f64() * 1_000.0,
        state_bytes,
        history_len,
        sync_message.payload.len(),
        heads.len(),
        FRAME_BYTES,
        frame_overhead,
        prepared.welcome_bytes,
    );
    println!("operation,participants,messages,upload_bytes,per_recipient_bytes,elapsed_ms");
    rotation.csv_row(config.participants);
    prepared.join.csv_row(config.participants);
    eviction.csv_row(config.participants);
    healing.csv_row(config.participants);
    media.csv_row(config.participants);
    Ok(())
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cfr-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
