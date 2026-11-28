// SPDX-License-Identifier: Apache-2.0
//! Olm (vodozemac) through the exported API, as the app uses it.

use corekit::*;

const KEY: [u8; 32] = [7; 32];
/// Largest blob the app uses (N2 design: four sizes, 1 400 bytes max).
const BLOB_MAX: usize = 1400;

/// A started conversation: Alice opened it with one of Bob's one-time keys.
fn pair() -> (
    std::sync::Arc<OlmAccount>,
    std::sync::Arc<OlmAccount>,
    std::sync::Arc<OlmSession>,
) {
    let alice = OlmAccount::new();
    let bob = OlmAccount::new();
    bob.generate_one_time_keys(1).unwrap();
    let otk = bob.one_time_keys().unwrap().remove(0);
    bob.mark_keys_as_published().unwrap();
    let a = alice
        .create_outbound_session(bob.identity_key().unwrap(), otk)
        .unwrap();
    (alice, bob, a)
}

#[test]
fn conversation_both_ways() {
    let (alice, bob, a) = pair();
    let first = a.encrypt(b"salut".to_vec()).unwrap();
    assert_eq!(first.msg_type, 0, "first message is a pre-key message");
    let inbound = bob
        .create_inbound_session(alice.identity_key().unwrap(), first.body)
        .unwrap();
    assert_eq!(inbound.plaintext, b"salut");
    let b = inbound.session;
    assert_eq!(a.session_id().unwrap(), b.session_id().unwrap());

    let reply = b.encrypt(b"bien recu".to_vec()).unwrap();
    assert_eq!(reply.msg_type, 1);
    assert_eq!(a.decrypt(reply.msg_type, reply.body).unwrap(), b"bien recu");
    // Alice has heard back: her messages are normal ones now.
    let next = a.encrypt(b"top".to_vec()).unwrap();
    assert_eq!(next.msg_type, 1);
    assert_eq!(b.decrypt(next.msg_type, next.body).unwrap(), b"top");
}

#[test]
fn a_1000_byte_text_fits_a_blob() {
    let (alice, bob, a) = pair();
    let text = vec![b'x'; 1000];
    let first = a.encrypt(text.clone()).unwrap();
    let pre_key_len = first.body.len();
    assert!(pre_key_len <= BLOB_MAX, "pre-key: {pre_key_len}");
    let b = bob
        .create_inbound_session(alice.identity_key().unwrap(), first.body)
        .unwrap()
        .session;
    let normal = b.encrypt(text).unwrap();
    assert_eq!(normal.msg_type, 1);
    assert!(
        normal.body.len() <= BLOB_MAX,
        "normal: {}",
        normal.body.len()
    );
    println!("pre-key {pre_key_len} B, normal {} B", normal.body.len());
}

#[test]
fn out_of_order_ok_replay_and_forgery_refused() {
    let (alice, bob, a) = pair();
    let m0 = a.encrypt(b"0".to_vec()).unwrap();
    let b = bob
        .create_inbound_session(alice.identity_key().unwrap(), m0.body)
        .unwrap()
        .session;
    let r = b.encrypt(b"r".to_vec()).unwrap();
    a.decrypt(r.msg_type, r.body).unwrap();
    let m1 = a.encrypt(b"1".to_vec()).unwrap();
    let m2 = a.encrypt(b"2".to_vec()).unwrap();
    assert_eq!(b.decrypt(m2.msg_type, m2.body.clone()).unwrap(), b"2");
    assert_eq!(b.decrypt(m1.msg_type, m1.body).unwrap(), b"1");
    assert!(b.decrypt(m2.msg_type, m2.body.clone()).is_err(), "replay");
    let m3 = a.encrypt(b"3".to_vec()).unwrap();
    let mut forged = m3.body.clone();
    let mid = forged.len() / 2;
    forged[mid] ^= 1;
    assert!(b.decrypt(m3.msg_type, forged).is_err(), "forgery");
    assert_eq!(b.decrypt(m3.msg_type, m3.body).unwrap(), b"3");
}

#[test]
fn one_time_key_works_once() {
    let (alice, bob, a) = pair();
    let first = a.encrypt(b"hi".to_vec()).unwrap();
    bob.create_inbound_session(alice.identity_key().unwrap(), first.body.clone())
        .unwrap();
    assert!(bob
        .create_inbound_session(alice.identity_key().unwrap(), first.body)
        .is_err());
}

#[test]
fn wrong_sender_identity_refused() {
    let (_alice, bob, a) = pair();
    let mallory = OlmAccount::new();
    let first = a.encrypt(b"hi".to_vec()).unwrap();
    assert!(bob
        .create_inbound_session(mallory.identity_key().unwrap(), first.body)
        .is_err());
}

#[test]
fn pickles_round_trip_and_need_the_key() {
    let (alice, bob, a) = pair();
    let first = a.encrypt(b"avant".to_vec()).unwrap();

    // Bob restarts before reading: account restored from its pickle.
    let bob_p = bob.pickle(KEY.to_vec()).unwrap();
    assert!(OlmAccount::from_pickle(bob_p.clone(), vec![8; 32]).is_err());
    assert!(OlmAccount::from_pickle(bob_p.clone(), vec![7; 31]).is_err());
    let bob2 = OlmAccount::from_pickle(bob_p, KEY.to_vec()).unwrap();
    assert_eq!(bob2.identity_key().unwrap(), bob.identity_key().unwrap());
    let b = bob2
        .create_inbound_session(alice.identity_key().unwrap(), first.body)
        .unwrap()
        .session;

    // Alice restarts: session restored, the ratchet goes on.
    let a2 = OlmSession::from_pickle(a.pickle(KEY.to_vec()).unwrap(), KEY.to_vec()).unwrap();
    let r = b.encrypt(b"apres".to_vec()).unwrap();
    assert_eq!(a2.decrypt(r.msg_type, r.body).unwrap(), b"apres");
    assert!(OlmSession::from_pickle(b"garbage".to_vec(), KEY.to_vec()).is_err());
}

#[test]
fn bad_arguments_refused() {
    let alice = OlmAccount::new();
    assert!(alice.generate_one_time_keys(0).is_err());
    assert!(alice.generate_one_time_keys(51).is_err());
    assert!(alice
        .create_outbound_session(vec![1; 31], vec![2; 32])
        .is_err());
    assert!(alice
        .create_inbound_session(vec![1; 32], vec![0xff; 10])
        .is_err());
    alice.generate_one_time_keys(5).unwrap();
    assert_eq!(alice.one_time_keys().unwrap().len(), 5);
    alice.mark_keys_as_published().unwrap();
    assert!(alice.one_time_keys().unwrap().is_empty());
}
