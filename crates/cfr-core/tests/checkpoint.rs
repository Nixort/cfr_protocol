// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.

//! End-to-end validation of the CFR signed checkpoint workflow.

use cfr_core::{
    CheckpointCertificate, Event, Participant, Policy, ProtocolProfile, REINIT_RECOMMENDED_AT,
};

fn founder() -> Participant {
    Participant::create(Policy::leaderless(2))
        .expect("conference creation")
        .0
}

#[test]
fn unanimous_checkpoint_is_delivered_as_an_offer_without_history_mutation() {
    let mut participant = founder();
    let history_before = participant.history_len();
    let record = participant
        .prepare_checkpoint([9; 32], 1, ProtocolProfile::DecentralizedMerkle)
        .expect("valid record");
    let approval = participant
        .approve_checkpoint(&record)
        .expect("local state matches record");
    let mut certificate = CheckpointCertificate::new(record);
    certificate.add_signature(approval).expect("valid approval");

    let offer = participant
        .offer_checkpoint(&certificate)
        .expect("valid unanimous certificate");
    let (events, outbound) = participant
        .handle(&offer.payload)
        .expect("checkpoint offer");

    assert!(outbound.is_empty());
    assert_eq!(participant.history_len(), history_before);
    assert_eq!(events, vec![Event::CheckpointOffered(certificate)]);
}

#[test]
fn checkpoint_for_another_causal_state_cannot_be_approved() {
    let participant = founder();
    let mut record = participant
        .prepare_checkpoint([9; 32], 1, ProtocolProfile::CentralizedSequenced)
        .expect("valid record");
    record.membership_root[0] ^= 1;
    assert!(participant.approve_checkpoint(&record).is_err());
}

#[test]
fn reinitialization_is_not_recommended_before_the_active_history_budget() {
    let participant = founder();
    assert!(participant.history_len() < REINIT_RECOMMENDED_AT);
    assert!(!participant.reinitialization_recommended());
}
