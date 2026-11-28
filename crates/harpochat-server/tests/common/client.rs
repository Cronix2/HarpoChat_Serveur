// SPDX-License-Identifier: Apache-2.0
//! Minimal phone-like test client: anonymous Noise link, inbox, Sphinx
//! packets through a single node (M1).

use std::net::SocketAddr;
use std::time::Duration;

use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::{random_bytes, X25519Secret};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::sphinx::{self, Hop, LOCAL_DELIVERY};
use harpochat_server::net::{self, LinkReader, LinkWriter, NetError};

/// Next frame that is not link padding; `None` on timeout.
pub async fn recv_skipping_padding(
    reader: &mut LinkReader,
    within: Duration,
) -> Option<Result<(SizeClass, LinkFrame), NetError>> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, reader.recv()).await {
            Err(_) => return None,
            Ok(Ok((_, f))) if f.kind == FrameKind::Padding => continue,
            Ok(r) => return Some(r),
        }
    }
}

pub struct Client {
    pub reader: LinkReader,
    pub writer: LinkWriter,
    pub inbox: [u8; 32],
    pub node: Hop,
}

impl Client {
    pub async fn connect(addr: SocketAddr, node: Hop) -> Result<Self, NetError> {
        let (reader, mut writer, _) =
            net::connect(addr, &X25519Secret::generate(), None, Some(node.id_pub)).await?;
        let inbox = random_bytes();
        writer
            .send(
                &LinkFrame {
                    kind: FrameKind::RegisterInbox,
                    body: inbox.to_vec(),
                },
                SizeClass::Small,
            )
            .await?;
        Ok(Self {
            reader,
            writer,
            inbox,
            node,
        })
    }

    /// Next non-padding frame; `None` on timeout or closed link.
    pub async fn recv_real(&mut self, within: Duration) -> Option<(SizeClass, LinkFrame)> {
        recv_skipping_padding(&mut self.reader, within).await?.ok()
    }

    pub async fn send_message(&mut self, msg: &Message) -> Result<(), NetError> {
        let packet = sphinx::build_forward(
            &envelope::encode(msg),
            &[self.node],
            LOCAL_DELIVERY,
            &[0],
            SizeClass::Small,
            None,
        )
        .expect("packet");
        self.writer
            .send(
                &LinkFrame {
                    kind: FrameKind::Sphinx,
                    body: packet,
                },
                SizeClass::Small,
            )
            .await
    }

    pub async fn put(&mut self, k: &MailboxKeys, blob: &[u8]) -> Result<(), NetError> {
        self.send_message(&Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(k, blob, random_bytes()),
            blob: blob.to_vec(),
        })
        .await
    }

    /// FETCH with one SURB, wait for the reply, return the decoded message.
    pub async fn fetch(&mut self, k: &MailboxKeys, now: u64) -> Option<Message> {
        let surb_id = random_bytes();
        let (surb, rec) = sphinx::create_surb(&[self.node], self.inbox, surb_id, &[0]).ok()?;
        let unsigned = Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, ReadOp::Fetch, b"", now, [0; 16]),
            max: 64,
            surbs: vec![surb.clone()],
        };
        let (op, bound) = envelope::read_bound(&unsigned)?;
        self.send_message(&Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, op, &bound, now, random_bytes()),
            max: 64,
            surbs: vec![surb],
        })
        .await
        .ok()?;
        // The phone downlink is a Poisson stream (1 packet/s on average): the
        // reply waits an exponential time for its slot, so leave a margin.
        let (_, frame) = self.recv_real(Duration::from_secs(15)).await?;
        assert_eq!(frame.kind, FrameKind::Deliver);
        assert_eq!(frame.body[..16], surb_id);
        let plain = sphinx::recover_reply(&rec, &frame.body[16..]).ok()?;
        envelope::decode(&plain).ok()
    }

    pub async fn ack(&mut self, k: &MailboxKeys, ids: Vec<[u8; 16]>, now: u64) {
        let unsigned = Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, ReadOp::Ack, b"", now, [0; 16]),
            blob_ids: ids.clone(),
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        self.send_message(&Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, op, &bound, now, random_bytes()),
            blob_ids: ids,
        })
        .await
        .unwrap();
    }
}
