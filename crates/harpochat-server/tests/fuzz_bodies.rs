// SPDX-License-Identifier: Apache-2.0
//! Stable-toolchain run of the fuzzing bodies (`harpochat_server::fuzzing`):
//! random inputs, then thousands of mutations of valid inputs (bit flips,
//! truncations, extensions, splices) so that parsing goes past the first
//! check. Long runs use cargo-fuzz (`fuzz/`, CI).

use harpochat_core::envelope::{self, Message};
use harpochat_core::invite::{encode_token, NodeInvite};
use harpochat_core::keys::SigningKey;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::signed::Signed;
use harpochat_core::sphinx::{self, Hop, LOCAL_DELIVERY};
use harpochat_server::config::Config;
use harpochat_server::fuzzing::{self, BODIES, NOW};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(5) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 => v.truncate(rng.below(v.len() + 1)),
            3 => {
                let extra = rng.below(64);
                v.extend(rng.bytes(extra));
            }
            _ if v.len() > 2 => {
                // Splice: duplicate a random slice somewhere else.
                let a = rng.below(v.len());
                let b = a + rng.below(v.len() - a);
                let chunk = v[a..b].to_vec();
                let at = rng.below(v.len());
                v.splice(at..at, chunk);
            }
            _ => {}
        }
    }
    v
}

fn seeds() -> Vec<Vec<u8>> {
    let k = MailboxKeys::derive(&[3; 32], harpochat_core::mailbox::epoch_of(NOW));
    let put = Message::Put {
        mailbox_id: k.mailbox_id(),
        write_auth: sign_put(&k, b"blob", [1; 16]),
        blob: b"blob".to_vec(),
    };
    let fetch = Message::Fetch {
        mailbox_id: k.mailbox_id(),
        read_auth: sign_read(&k, ReadOp::Fetch, &[0, 0, 0, 8], NOW, [2; 16]),
        max: 8,
        surbs: vec![vec![9; sphinx::surb_len()]],
    };
    let sponsor = SigningKey::generate();
    let token = encode_token(&Signed::sign(
        &sponsor,
        &NodeInvite {
            v: 1,
            sponsor_id: sponsor.public(),
            sponsor_endpoints: vec!["wss://127.0.0.1:4430".into()],
            secret: [5; 32],
            expires: NOW + 3600,
        },
    ));
    let hop = Hop {
        id_pub: [1; 32],
        sphinx_pub: harpochat_core::keys::X25519Secret::generate().public(),
    };
    let packet = sphinx::build_forward(
        &envelope::encode(&put),
        &[hop],
        LOCAL_DELIVERY,
        &[0],
        SizeClass::Small,
        None,
    )
    .unwrap();
    vec![
        LinkFrame {
            kind: FrameKind::Sphinx,
            body: vec![1, 2, 3],
        }
        .encode(SizeClass::Small)
        .unwrap(),
        envelope::encode(&put),
        envelope::encode(&fetch),
        envelope::encode(&Message::Loop),
        packet,
        token.into_bytes(),
        Config::default().to_toml().into_bytes(),
        Vec::new(),
    ]
}

#[test]
fn fuzz_bodies_never_panic() {
    let seeds = seeds();
    let mut rng = Rng(0x00C0_FFEE_1234_5678);
    for (name, body) in BODIES {
        for _ in 0..300 {
            let len = rng.below(3000);
            body(&rng.bytes(len));
        }
        for seed in &seeds {
            body(seed);
            for _ in 0..150 {
                body(&mutate(seed, &mut rng));
            }
        }
        eprintln!("{name}: ok");
    }
}

#[test]
fn valid_inputs_go_deep() {
    // The envelope body checks round-trips; a valid PUT must reach the
    // service without panicking and the valid token must parse.
    let s = seeds();
    fuzzing::envelope(&s[1]);
    fuzzing::mailbox_service(&s[1]);
    fuzzing::token(&s[5]);
    fuzzing::config(&s[6]);
}
