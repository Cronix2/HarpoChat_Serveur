// SPDX-License-Identifier: Apache-2.0
//! Sphinx façade (spec §6), over the `sphinx-packet` crate (Nym).
//!
//! * Packet sizes are fixed per [`SizeClass`]: a Sphinx packet exactly fills
//!   the body of a link frame.
//! * Node addresses are [`node_address`] of the node identity (design §5.7).
//! * Forward packets end at a mailbox node with destination
//!   [`LOCAL_DELIVERY`]; the mailbox reads them with [`open_forward_payload`].
//! * Replies use **single-seed SURBs** (sphinx-packet version 260): the
//!   sender of the reply cannot precompute per-hop payloads, and no hop —
//!   not even the final gateway — can read the reply. Only the SURB creator,
//!   holding the [`SurbRecovery`], can ([`recover_reply`]). A SURB route ends
//!   at the phone's gateway, with the phone's inbox token as destination
//!   (design §5.3).
//! * [`process`] returns the packet's replay tag: mixes must drop packets
//!   whose tag they already saw under the same Sphinx key (design §5.5).

use sphinx_packet::header::delays::Delay;
use sphinx_packet::header::HEADER_SIZE;
use sphinx_packet::packet::ProcessedPacketData;
use sphinx_packet::payload::{Payload, PAYLOAD_OVERHEAD_SIZE};
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::surb::{SURBMaterial, SurbReplyRecovery, SURB};
use sphinx_packet::version::SINGLE_SEED_SURB_VERSION;
use sphinx_packet::{SphinxPacket, SphinxPacketBuilder};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::descriptor::{node_address, NodeDescriptor};
use crate::envelope::{self, Message, MAX_SURBS};
use crate::keys::X25519Secret;
use crate::link::SizeClass;
use crate::mailbox::{sign_read, MailboxKeys, ReadOp};
use crate::{CoreError, Result};

/// Size of a Sphinx header (constant, sized for [`MAX_HOPS`]).
pub const HEADER_LEN: usize = HEADER_SIZE;
/// Longest route a packet can take.
pub const MAX_HOPS: usize = sphinx_packet::constants::MAX_PATH_LENGTH;
/// Minimum number of distinct nodes on a path (spec §6.1).
pub const MIN_DISTINCT_NODES: usize = 3;
/// Destination address meaning "deliver to the final node's mailbox service".
pub const LOCAL_DELIVERY: [u8; 32] = [0; 32];
/// Largest per-hop delay accepted when building a packet or SURB (one minute).
pub const MAX_DELAY_MS: u64 = 60_000;
const SURB_ID_LEN: usize = 16;
const PAYLOAD_KEY_SEED_LEN: usize = 16;

/// Length of a Sphinx packet of this class (fills a link frame body).
pub const fn packet_len(c: SizeClass) -> usize {
    c.max_body_len()
}

/// Length of the Sphinx payload of this class.
pub const fn payload_len(c: SizeClass) -> usize {
    packet_len(c) - HEADER_LEN
}

/// Largest plaintext message (an encoded envelope) of this class.
pub const fn max_message_len(c: SizeClass) -> usize {
    payload_len(c) - PAYLOAD_OVERHEAD_SIZE
}

/// Serialized length of a single-seed SURB: header, first hop, one seed.
pub const fn surb_len() -> usize {
    HEADER_LEN + 32 + PAYLOAD_KEY_SEED_LEN
}

/// One hop of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    /// Node identity (its Sphinx address is derived from it).
    pub id_pub: [u8; 32],
    /// Node's current Sphinx key.
    pub sphinx_pub: [u8; 32],
}

impl From<&NodeDescriptor> for Hop {
    fn from(d: &NodeDescriptor) -> Self {
        Hop {
            id_pub: d.id_pub,
            sphinx_pub: d.sphinx_pub,
        }
    }
}

/// Outcome of processing one Sphinx layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processed {
    /// Forward `packet` to `next_hop` after `delay_ms`.
    Forward {
        /// Sphinx address of the next node (or a phone inbox token at a gateway).
        next_hop: [u8; 32],
        /// Delay chosen by the sender for this hop.
        delay_ms: u64,
        /// Packet for the next hop (same length).
        packet: Vec<u8>,
    },
    /// This node is the final hop.
    Final {
        /// [`LOCAL_DELIVERY`] or a phone inbox token.
        destination: [u8; 32],
        /// SURB identifier (zeros for forward packets).
        surb_id: [u8; 16],
        /// Raw final payload: [`open_forward_payload`] or [`recover_reply`].
        payload: Vec<u8>,
    },
}

/// Recovery material of a SURB, kept by its creator only (RAM only).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SurbRecovery(Vec<u8>);

impl SurbRecovery {
    /// Serialize (for in-memory storage by the creator).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Restore from [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SurbReplyRecovery::from_bytes(bytes).map_err(|_| CoreError::Malformed)?;
        Ok(Self(bytes.to_vec()))
    }
}

impl core::fmt::Debug for SurbRecovery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SurbRecovery(<redacted>)")
    }
}

fn route_nodes(route: &[Hop]) -> Vec<Node> {
    route
        .iter()
        .map(|h| {
            Node::new(
                NodeAddressBytes::from_bytes(node_address(&h.id_pub)),
                x25519_dalek::PublicKey::from(h.sphinx_pub),
            )
        })
        .collect()
}

fn check_route(route: &[Hop], delays_ms: &[u64]) -> Result<()> {
    if route.is_empty()
        || route.len() > MAX_HOPS
        || delays_ms.len() != route.len()
        || delays_ms.iter().any(|d| *d > MAX_DELAY_MS)
    {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

fn delays(delays_ms: &[u64]) -> Vec<Delay> {
    delays_ms
        .iter()
        .map(|ms| Delay::new_from_millis(*ms))
        .collect()
}

/// Build a forward packet carrying `message` along `route` to `destination`.
/// `initial_secret` fixes the sender's ephemeral key (test vectors only).
pub fn build_forward(
    message: &[u8],
    route: &[Hop],
    destination: [u8; 32],
    delays_ms: &[u64],
    class: SizeClass,
    initial_secret: Option<[u8; 32]>,
) -> Result<Vec<u8>> {
    build(
        message,
        route,
        destination,
        [0; SURB_ID_LEN],
        delays_ms,
        class,
        initial_secret,
    )
}

/// Like [`build_forward`], with a 16-byte identifier handed to the final
/// node with the payload. A phone's own loops use it: route
/// `gateway → … → gateway`, destination its inbox token; the gateway then
/// delivers `id ‖ payload` (`Deliver`), and the phone recognises the id.
pub fn build_forward_tagged(
    message: &[u8],
    route: &[Hop],
    destination: [u8; 32],
    id: [u8; 16],
    delays_ms: &[u64],
    class: SizeClass,
) -> Result<Vec<u8>> {
    build(message, route, destination, id, delays_ms, class, None)
}

fn build(
    message: &[u8],
    route: &[Hop],
    destination: [u8; 32],
    id: [u8; SURB_ID_LEN],
    delays_ms: &[u64],
    class: SizeClass,
    initial_secret: Option<[u8; 32]>,
) -> Result<Vec<u8>> {
    check_route(route, delays_ms)?;
    if message.len() > max_message_len(class) {
        return Err(CoreError::TooLarge);
    }
    let dest = Destination::new(DestinationAddressBytes::from_bytes(destination), id);
    let secret = initial_secret.map(x25519_dalek::StaticSecret::from);
    let mut builder = SphinxPacketBuilder::new().with_payload_size(payload_len(class));
    if let Some(s) = secret.as_ref() {
        builder = builder.with_initial_secret(s);
    }
    let packet = builder
        .build_packet(message, &route_nodes(route), &dest, &delays(delays_ms))
        .map_err(|_| CoreError::Sphinx)?;
    Ok(packet.to_bytes())
}

/// Process one layer with this node's Sphinx secret. Returns the replay tag
/// and the outcome.
pub fn process(packet: &[u8], sphinx_secret: &X25519Secret) -> Result<([u8; 32], Processed)> {
    if packet.len() != packet_len(SizeClass::Small) && packet.len() != packet_len(SizeClass::Large)
    {
        return Err(CoreError::Malformed);
    }
    let packet = SphinxPacket::from_bytes(packet).map_err(|_| CoreError::Sphinx)?;
    let sk = sphinx_secret.to_dalek();
    let expanded = packet.header.compute_expanded_shared_secret(&sk);
    let tag = *expanded.replay_tag();
    let processed = packet
        .process_with_expanded_secret(&expanded)
        .map_err(|_| CoreError::Sphinx)?;
    let out = match processed.data {
        ProcessedPacketData::ForwardHop {
            next_hop_packet,
            next_hop_address,
            delay,
        } => Processed::Forward {
            next_hop: next_hop_address.to_bytes(),
            delay_ms: delay.to_nanos() / 1_000_000,
            packet: next_hop_packet.to_bytes(),
        },
        ProcessedPacketData::FinalHop {
            destination,
            identifier,
            payload,
        } => Processed::Final {
            destination: destination.as_bytes(),
            surb_id: identifier,
            payload: payload.into_bytes(),
        },
    };
    Ok((tag, out))
}

/// Recover the plaintext of a forward packet at its final node.
pub fn open_forward_payload(payload: &[u8]) -> Result<Vec<u8>> {
    Payload::from_bytes(payload)
        .and_then(Payload::recover_plaintext)
        .map_err(|_| CoreError::Sphinx)
}

/// Create a single-seed SURB along `route` (usually mix(es) then the
/// gateway), delivering to `destination` (the phone's inbox token).
pub fn create_surb(
    route: &[Hop],
    destination: [u8; 32],
    surb_id: [u8; 16],
    delays_ms: &[u64],
) -> Result<(Vec<u8>, SurbRecovery)> {
    check_route(route, delays_ms)?;
    let dest = Destination::new(DestinationAddressBytes::from_bytes(destination), surb_id);
    let (surb, recovery) = SURBMaterial::new(
        route_nodes(route),
        delays(delays_ms),
        dest,
        SINGLE_SEED_SURB_VERSION,
    )
    .construct_recoverable_SURB()
    .map_err(|_| CoreError::Sphinx)?;
    Ok((surb.to_bytes(), SurbRecovery(recovery.to_bytes())))
}

/// Use a SURB to send `message`. Returns the packet and the first-hop address.
pub fn use_surb(surb: &[u8], message: &[u8], class: SizeClass) -> Result<(Vec<u8>, [u8; 32])> {
    if surb.len() != surb_len() {
        return Err(CoreError::Malformed);
    }
    if message.len() > max_message_len(class) {
        return Err(CoreError::TooLarge);
    }
    let surb = SURB::from_bytes(surb).map_err(|_| CoreError::Malformed)?;
    let (packet, first) = surb
        .use_surb(message, payload_len(class))
        .map_err(|_| CoreError::Sphinx)?;
    Ok((packet.to_bytes(), first.to_bytes()))
}

/// Recover a reply sent through one of our SURBs.
pub fn recover_reply(recovery: &SurbRecovery, payload: &[u8]) -> Result<Vec<u8>> {
    let rec = SurbReplyRecovery::from_bytes(&recovery.0).map_err(|_| CoreError::Malformed)?;
    let payload = Payload::from_bytes(payload).map_err(|_| CoreError::Sphinx)?;
    rec.recover_plaintext(payload)
        .map_err(|_| CoreError::Sphinx)
}

/// Largest number of SURBs a SUBSCRIBE can carry in one packet of this class.
/// When a client needs more, it sends several SUBSCRIBE packets.
pub fn max_surbs_per_subscribe(class: SizeClass) -> usize {
    let keys = MailboxKeys::derive(&[0; 32], 0);
    let fits = |n: usize| {
        let msg = Message::Subscribe {
            mailbox_id: keys.mailbox_id(),
            read_auth: sign_read(&keys, ReadOp::Subscribe, b"", u64::MAX, [0; 16]),
            surbs: vec![vec![0; surb_len()]; n],
            until: u64::MAX,
        };
        envelope::encode(&msg).len() <= max_message_len(class)
    };
    (0..=MAX_SURBS).take_while(|n| fits(*n)).last().unwrap_or(0)
}
