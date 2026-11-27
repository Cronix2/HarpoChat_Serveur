// SPDX-License-Identifier: Apache-2.0
//! # harpochat-core-ffi
//!
//! Kotlin bindings (via uniffi) of `harpochat-core` for the Android app.
//! Everything here is a thin, typed wrapper: no network, no file, no clock.
//! The app owns the WebSocket and moves bytes in and out of these functions.
//!
//! Byte arrays cross the boundary as `Vec<u8>` (`ByteArray` in Kotlin);
//! fixed-size inputs are length-checked and rejected with
//! [`FfiError::InvalidArgument`].
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::{Arc, Mutex};

use harpochat_core::bootstrap::Bootstrap;
use harpochat_core::descriptor::Role;
use harpochat_core::directory::verify_directory as core_verify_directory;
use harpochat_core::envelope::{self, Message, StoredBlob};
use harpochat_core::keys::{random_bytes as core_random, X25519Secret};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{self, sign_put, sign_read, MailboxKeys};
use harpochat_core::noise::{Handshake, Transport};
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, sphinx, CoreError};

uniffi::setup_scaffolding!();

/// Errors returned to Kotlin.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Input could not be parsed.
    #[error("malformed")]
    Malformed,
    /// Input exceeds a size limit.
    #[error("too large")]
    TooLarge,
    /// Unknown format version.
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Signature, MAC or AEAD failure.
    #[error("bad signature")]
    BadSignature,
    /// Expired object.
    #[error("expired")]
    Expired,
    /// Object not valid yet.
    #[error("not yet valid")]
    NotYetValid,
    /// Not authorised.
    #[error("unauthorized")]
    Unauthorized,
    /// Not anchored to a trusted root.
    #[error("untrusted")]
    Untrusted,
    /// Sphinx failure.
    #[error("sphinx")]
    Sphinx,
    /// Wrong argument length or state (e.g. handshake used twice).
    #[error("invalid argument")]
    InvalidArgument,
}

impl From<CoreError> for FfiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Malformed => FfiError::Malformed,
            CoreError::TooLarge => FfiError::TooLarge,
            CoreError::UnsupportedVersion => FfiError::UnsupportedVersion,
            CoreError::BadSignature => FfiError::BadSignature,
            CoreError::Expired => FfiError::Expired,
            CoreError::NotYetValid => FfiError::NotYetValid,
            CoreError::Unauthorized => FfiError::Unauthorized,
            CoreError::Untrusted => FfiError::Untrusted,
            CoreError::Sphinx => FfiError::Sphinx,
        }
    }
}

type FfiResult<T> = Result<T, FfiError>;

fn fixed<const N: usize>(v: &[u8]) -> FfiResult<[u8; N]> {
    v.try_into().map_err(|_| FfiError::InvalidArgument)
}

// ---------------------------------------------------------------------------
// Sizes and constants
// ---------------------------------------------------------------------------

/// Packet size class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSizeClass {
    /// 2 048-byte Noise messages.
    Small,
    /// 32 768-byte Noise messages.
    Large,
}

impl From<FfiSizeClass> for SizeClass {
    fn from(c: FfiSizeClass) -> Self {
        match c {
            FfiSizeClass::Small => SizeClass::Small,
            FfiSizeClass::Large => SizeClass::Large,
        }
    }
}

impl From<SizeClass> for FfiSizeClass {
    fn from(c: SizeClass) -> Self {
        match c {
            SizeClass::Small => FfiSizeClass::Small,
            SizeClass::Large => FfiSizeClass::Large,
        }
    }
}

/// Fixed sizes of one class.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSizes {
    /// Noise message on the wire.
    pub noise_ciphertext: u32,
    /// Link frame before Noise.
    pub link_plaintext: u32,
    /// Sphinx packet.
    pub sphinx_packet: u32,
    /// Largest encoded envelope.
    pub max_message: u32,
    /// SURBs one SUBSCRIBE can carry.
    pub max_surbs_per_subscribe: u32,
}

/// Sizes of a class.
#[uniffi::export]
pub fn sizes(size_class: FfiSizeClass) -> FfiSizes {
    let c: SizeClass = size_class.into();
    FfiSizes {
        noise_ciphertext: c.ciphertext_len() as u32,
        link_plaintext: c.plaintext_len() as u32,
        sphinx_packet: sphinx::packet_len(c) as u32,
        max_message: sphinx::max_message_len(c) as u32,
        max_surbs_per_subscribe: sphinx::max_surbs_per_subscribe(c) as u32,
    }
}

/// Version of the core compiled into this library.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// OS randomness (inbox tokens, SURB ids, pair secrets).
#[uniffi::export]
pub fn random_bytes(len: u32) -> FfiResult<Vec<u8>> {
    if len > 1024 {
        return Err(FfiError::InvalidArgument);
    }
    let mut out = Vec::with_capacity(len as usize);
    while out.len() < len as usize {
        out.extend_from_slice(&core_random::<32>());
    }
    out.truncate(len as usize);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Mailboxes and messages
// ---------------------------------------------------------------------------

/// Epoch (UTC day) of a unix time.
#[uniffi::export]
pub fn epoch_of(now_unix_secs: u64) -> u32 {
    mailbox::epoch_of(now_unix_secs)
}

/// Epochs to poll on reconnection (7, newest first).
#[uniffi::export]
pub fn epochs_to_poll(now_unix_secs: u64) -> Vec<u32> {
    mailbox::epochs_to_poll(now_unix_secs)
}

/// Per-epoch keys of one directional mailbox.
#[derive(Debug, uniffi::Object)]
pub struct FfiMailboxKeys(MailboxKeys);

#[uniffi::export]
impl FfiMailboxKeys {
    /// Derive from a 32-byte directional pair secret and an epoch.
    #[uniffi::constructor]
    pub fn derive(pair_secret: Vec<u8>, epoch: u32) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Self(MailboxKeys::derive(
            &fixed(&pair_secret)?,
            epoch,
        ))))
    }

    /// Mailbox identifier (32 bytes).
    pub fn mailbox_id(&self) -> Vec<u8> {
        self.0.mailbox_id().to_vec()
    }

    /// Epoch of these keys.
    pub fn epoch(&self) -> u32 {
        self.0.epoch
    }

    /// Write public key (32 bytes).
    pub fn write_pub(&self) -> Vec<u8> {
        self.0.write.public().to_vec()
    }

    /// Read public key (32 bytes).
    pub fn read_pub(&self) -> Vec<u8> {
        self.0.read.public().to_vec()
    }
}

/// Encoded PUT envelope (fresh random nonce).
#[uniffi::export]
pub fn build_put(keys: &FfiMailboxKeys, blob: Vec<u8>) -> FfiResult<Vec<u8>> {
    let msg = Message::Put {
        mailbox_id: keys.0.mailbox_id(),
        write_auth: sign_put(&keys.0, &blob, core_random()),
        blob,
    };
    encode_checked(&msg)
}

fn encode_checked(msg: &Message) -> FfiResult<Vec<u8>> {
    let bytes = envelope::encode(msg);
    if bytes.len() > sphinx::max_message_len(SizeClass::Large) {
        return Err(FfiError::TooLarge);
    }
    Ok(bytes)
}

fn signed_read(keys: &MailboxKeys, unsigned: Message, now: u64) -> FfiResult<Message> {
    let (op, bound) = envelope::read_bound(&unsigned).ok_or(FfiError::InvalidArgument)?;
    let auth = sign_read(keys, op, &bound, now, core_random());
    Ok(match unsigned {
        Message::Fetch {
            mailbox_id,
            max,
            surbs,
            ..
        } => Message::Fetch {
            mailbox_id,
            read_auth: auth,
            max,
            surbs,
        },
        Message::Ack {
            mailbox_id,
            blob_ids,
            ..
        } => Message::Ack {
            mailbox_id,
            read_auth: auth,
            blob_ids,
        },
        Message::Subscribe {
            mailbox_id,
            surbs,
            until,
            ..
        } => Message::Subscribe {
            mailbox_id,
            read_auth: auth,
            surbs,
            until,
        },
        _ => return Err(FfiError::InvalidArgument),
    })
}

fn placeholder_auth(keys: &MailboxKeys) -> harpochat_core::mailbox::ReadAuth {
    sign_read(
        keys,
        harpochat_core::mailbox::ReadOp::Fetch,
        b"",
        0,
        [0; 16],
    )
}

/// Encoded FETCH envelope: replies come back through `surbs`.
#[uniffi::export]
pub fn build_fetch(
    keys: &FfiMailboxKeys,
    max: u16,
    surbs: Vec<Vec<u8>>,
    now_unix_secs: u64,
) -> FfiResult<Vec<u8>> {
    let unsigned = Message::Fetch {
        mailbox_id: keys.0.mailbox_id(),
        read_auth: placeholder_auth(&keys.0),
        max,
        surbs,
    };
    encode_checked(&signed_read(&keys.0, unsigned, now_unix_secs)?)
}

/// Encoded ACK envelope deleting `blob_ids` (16 bytes each).
#[uniffi::export]
pub fn build_ack(
    keys: &FfiMailboxKeys,
    blob_ids: Vec<Vec<u8>>,
    now_unix_secs: u64,
) -> FfiResult<Vec<u8>> {
    let ids = blob_ids
        .iter()
        .map(|i| fixed::<16>(i))
        .collect::<FfiResult<Vec<_>>>()?;
    let unsigned = Message::Ack {
        mailbox_id: keys.0.mailbox_id(),
        read_auth: placeholder_auth(&keys.0),
        blob_ids: ids,
    };
    encode_checked(&signed_read(&keys.0, unsigned, now_unix_secs)?)
}

/// Encoded SUBSCRIBE envelope (real-time delivery, spec §7.5).
#[uniffi::export]
pub fn build_subscribe(
    keys: &FfiMailboxKeys,
    surbs: Vec<Vec<u8>>,
    until_unix_secs: u64,
    now_unix_secs: u64,
) -> FfiResult<Vec<u8>> {
    let unsigned = Message::Subscribe {
        mailbox_id: keys.0.mailbox_id(),
        read_auth: placeholder_auth(&keys.0),
        surbs,
        until: until_unix_secs,
    };
    encode_checked(&signed_read(&keys.0, unsigned, now_unix_secs)?)
}

/// Encoded DROP cover message.
#[uniffi::export]
pub fn build_drop() -> Vec<u8> {
    envelope::encode(&Message::Drop)
}

/// Encoded LOOP cover message.
#[uniffi::export]
pub fn build_loop() -> Vec<u8> {
    envelope::encode(&Message::Loop)
}

/// A blob returned by a mailbox.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBlob {
    /// Identifier, for ACK (16 bytes).
    pub id: Vec<u8>,
    /// End-to-end encrypted content.
    pub blob: Vec<u8>,
}

impl From<StoredBlob> for FfiBlob {
    fn from(b: StoredBlob) -> Self {
        FfiBlob {
            id: b.id.to_vec(),
            blob: b.blob,
        }
    }
}

/// Messages a phone can receive (anything else decodes as `Other`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMessage {
    /// Answer to FETCH.
    FetchResponse {
        /// Blobs.
        blobs: Vec<FfiBlob>,
        /// More are waiting.
        more: bool,
    },
    /// Real-time push.
    Push {
        /// Source mailbox.
        mailbox_id: Vec<u8>,
        /// Blobs.
        blobs: Vec<FfiBlob>,
    },
    /// Mail is waiting.
    Notify {
        /// Mailbox.
        mailbox_id: Vec<u8>,
        /// Pending blobs.
        pending: u16,
    },
    /// A LOOP cover message came back.
    Loop,
    /// Valid envelope not meant for a phone.
    Other {
        /// Spec §8 type code.
        type_code: u8,
    },
}

/// Decode an envelope (e.g. the result of `recover_reply`).
#[uniffi::export]
pub fn decode_message(bytes: Vec<u8>) -> FfiResult<FfiMessage> {
    Ok(match envelope::decode(&bytes)? {
        Message::FetchResponse { blobs, more } => FfiMessage::FetchResponse {
            blobs: blobs.into_iter().map(Into::into).collect(),
            more,
        },
        Message::Push { mailbox_id, blobs } => FfiMessage::Push {
            mailbox_id: mailbox_id.to_vec(),
            blobs: blobs.into_iter().map(Into::into).collect(),
        },
        Message::Notify {
            mailbox_id,
            pending,
        } => FfiMessage::Notify {
            mailbox_id: mailbox_id.to_vec(),
            pending,
        },
        Message::Loop => FfiMessage::Loop,
        other => FfiMessage::Other {
            type_code: other.type_code(),
        },
    })
}

// ---------------------------------------------------------------------------
// Sphinx
// ---------------------------------------------------------------------------

/// One hop of a route.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHop {
    /// Node identity (32 bytes).
    pub id_pub: Vec<u8>,
    /// Node's current Sphinx key (32 bytes).
    pub sphinx_pub: Vec<u8>,
}

fn hops(route: &[FfiHop]) -> FfiResult<Vec<sphinx::Hop>> {
    route
        .iter()
        .map(|h| {
            Ok(sphinx::Hop {
                id_pub: fixed(&h.id_pub)?,
                sphinx_pub: fixed(&h.sphinx_pub)?,
            })
        })
        .collect()
}

/// Destination meaning "the final node's mailbox".
#[uniffi::export]
pub fn local_delivery() -> Vec<u8> {
    sphinx::LOCAL_DELIVERY.to_vec()
}

/// Build a forward Sphinx packet (route: gateway → mix(es) → mailbox).
#[uniffi::export]
pub fn build_forward(
    message: Vec<u8>,
    route: Vec<FfiHop>,
    destination: Vec<u8>,
    delays_ms: Vec<u64>,
    size_class: FfiSizeClass,
) -> FfiResult<Vec<u8>> {
    Ok(sphinx::build_forward(
        &message,
        &hops(&route)?,
        fixed(&destination)?,
        &delays_ms,
        size_class.into(),
        None,
    )?)
}

/// A SURB and the recovery material its creator keeps (in RAM only).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSurb {
    /// SURB to put in FETCH / SUBSCRIBE.
    pub surb: Vec<u8>,
    /// Secret recovery material, never sent.
    pub recovery: Vec<u8>,
}

/// Create a single-seed SURB along `route` (mix(es) → gateway) to the
/// phone's inbox token `destination`; `surb_id` is 16 bytes.
#[uniffi::export]
pub fn create_surb(
    route: Vec<FfiHop>,
    destination: Vec<u8>,
    surb_id: Vec<u8>,
    delays_ms: Vec<u64>,
) -> FfiResult<FfiSurb> {
    let (surb, rec) = sphinx::create_surb(
        &hops(&route)?,
        fixed(&destination)?,
        fixed(&surb_id)?,
        &delays_ms,
    )?;
    Ok(FfiSurb {
        surb,
        recovery: rec.to_bytes(),
    })
}

/// Recover a reply delivered in a `Deliver` frame.
#[uniffi::export]
pub fn recover_reply(recovery: Vec<u8>, payload: Vec<u8>) -> FfiResult<Vec<u8>> {
    let rec = sphinx::SurbRecovery::from_bytes(&recovery)?;
    Ok(sphinx::recover_reply(&rec, &payload)?)
}

// ---------------------------------------------------------------------------
// Noise (phone side: anonymous initiator)
// ---------------------------------------------------------------------------

/// Noise transport after a successful handshake.
#[derive(Debug, uniffi::Object)]
pub struct FfiTransport(Mutex<Transport>);

#[uniffi::export]
impl FfiTransport {
    /// Encrypt a link frame (exactly a class `link_plaintext` long).
    pub fn encrypt(&self, frame: Vec<u8>) -> FfiResult<Vec<u8>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| FfiError::InvalidArgument)?
            .encrypt(&frame)?)
    }

    /// Decrypt a WebSocket binary message (exactly a class `noise_ciphertext` long).
    pub fn decrypt(&self, message: Vec<u8>) -> FfiResult<Vec<u8>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| FfiError::InvalidArgument)?
            .decrypt(&message)?)
    }
}

/// Outcome of a finished handshake.
#[derive(Debug, uniffi::Record)]
pub struct FfiSession {
    /// Encrypt/decrypt link frames.
    pub transport: Arc<FfiTransport>,
    /// Identity the node proved; compare with the expected `id_pub`.
    pub peer_node_id: Option<Vec<u8>>,
}

/// Noise XX handshake as an anonymous initiator (fresh static key).
#[derive(Debug, uniffi::Object)]
pub struct FfiHandshake(Mutex<Option<Handshake>>);

#[uniffi::export]
impl FfiHandshake {
    /// Start a handshake: write message 1, read 2, write 3, then `finish`.
    #[uniffi::constructor]
    pub fn initiator() -> FfiResult<Arc<Self>> {
        let hs = Handshake::initiator(&X25519Secret::generate(), None)?;
        Ok(Arc::new(Self(Mutex::new(Some(hs)))))
    }

    /// Next message to send.
    pub fn write_message(&self) -> FfiResult<Vec<u8>> {
        let mut g = self.0.lock().map_err(|_| FfiError::InvalidArgument)?;
        Ok(g.as_mut()
            .ok_or(FfiError::InvalidArgument)?
            .write_message()?)
    }

    /// Feed the node's message.
    pub fn read_message(&self, message: Vec<u8>) -> FfiResult<()> {
        let mut g = self.0.lock().map_err(|_| FfiError::InvalidArgument)?;
        Ok(g.as_mut()
            .ok_or(FfiError::InvalidArgument)?
            .read_message(&message)?)
    }

    /// Complete the handshake (once).
    pub fn finish(&self) -> FfiResult<FfiSession> {
        let hs = self
            .0
            .lock()
            .map_err(|_| FfiError::InvalidArgument)?
            .take()
            .ok_or(FfiError::InvalidArgument)?;
        let (t, peer) = hs.into_transport()?;
        Ok(FfiSession {
            transport: Arc::new(FfiTransport(Mutex::new(t))),
            peer_node_id: peer.node_id.map(|i| i.to_vec()),
        })
    }
}

// ---------------------------------------------------------------------------
// Link frames
// ---------------------------------------------------------------------------

/// Link frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFrameKind {
    /// Cover traffic.
    Padding,
    /// Sphinx packet.
    Sphinx,
    /// Directory request.
    DirectoryReq,
    /// Signed directory.
    Directory,
    /// Inbox token registration.
    RegisterInbox,
    /// Node join request (nodes only).
    JoinRequest,
    /// Node join response (nodes only).
    JoinResponse,
    /// Gossip (nodes only).
    Gossip,
    /// SURB reply for this phone: `surb_id[16] || payload`.
    Deliver,
}

impl From<FfiFrameKind> for FrameKind {
    fn from(k: FfiFrameKind) -> Self {
        match k {
            FfiFrameKind::Padding => FrameKind::Padding,
            FfiFrameKind::Sphinx => FrameKind::Sphinx,
            FfiFrameKind::DirectoryReq => FrameKind::DirectoryReq,
            FfiFrameKind::Directory => FrameKind::Directory,
            FfiFrameKind::RegisterInbox => FrameKind::RegisterInbox,
            FfiFrameKind::JoinRequest => FrameKind::JoinRequest,
            FfiFrameKind::JoinResponse => FrameKind::JoinResponse,
            FfiFrameKind::Gossip => FrameKind::Gossip,
            FfiFrameKind::Deliver => FrameKind::Deliver,
        }
    }
}

impl From<FrameKind> for FfiFrameKind {
    fn from(k: FrameKind) -> Self {
        match k {
            FrameKind::Padding => FfiFrameKind::Padding,
            FrameKind::Sphinx => FfiFrameKind::Sphinx,
            FrameKind::DirectoryReq => FfiFrameKind::DirectoryReq,
            FrameKind::Directory => FfiFrameKind::Directory,
            FrameKind::RegisterInbox => FfiFrameKind::RegisterInbox,
            FrameKind::JoinRequest => FfiFrameKind::JoinRequest,
            FrameKind::JoinResponse => FfiFrameKind::JoinResponse,
            FrameKind::Gossip => FfiFrameKind::Gossip,
            FrameKind::Deliver => FfiFrameKind::Deliver,
        }
    }
}

/// A decoded link frame.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFrame {
    /// Size class it arrived in.
    pub size_class: FfiSizeClass,
    /// Kind.
    pub kind: FfiFrameKind,
    /// Body.
    pub body: Vec<u8>,
}

/// Encode a frame to its fixed class size (then `FfiTransport.encrypt`).
#[uniffi::export]
pub fn encode_frame(
    kind: FfiFrameKind,
    body: Vec<u8>,
    size_class: FfiSizeClass,
) -> FfiResult<Vec<u8>> {
    Ok(LinkFrame {
        kind: kind.into(),
        body,
    }
    .encode(size_class.into())?)
}

/// Decode a frame (after `FfiTransport.decrypt`).
#[uniffi::export]
pub fn decode_frame(bytes: Vec<u8>) -> FfiResult<FfiFrame> {
    let (class, f) = LinkFrame::decode(&bytes)?;
    Ok(FfiFrame {
        size_class: class.into(),
        kind: f.kind.into(),
        body: f.body,
    })
}

// ---------------------------------------------------------------------------
// Bootstrap and directory
// ---------------------------------------------------------------------------

/// A root node from the bootstrap block.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRoot {
    /// Identity (trust anchor).
    pub id_pub: Vec<u8>,
    /// `wss://` endpoints.
    pub endpoints: Vec<String>,
}

/// Decode the bootstrap block embedded in the APK.
#[uniffi::export]
pub fn decode_bootstrap(bytes: Vec<u8>) -> FfiResult<Vec<FfiRoot>> {
    Ok(Bootstrap::decode(&bytes)?
        .roots
        .into_iter()
        .map(|r| FfiRoot {
            id_pub: r.id_pub.to_vec(),
            endpoints: r.endpoints,
        })
        .collect())
}

/// A verified node.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNode {
    /// Identity.
    pub id_pub: Vec<u8>,
    /// Noise static key.
    pub noise_pub: Vec<u8>,
    /// Current Sphinx key.
    pub sphinx_pub: Vec<u8>,
    /// Roles: "gateway", "mix", "mailbox".
    pub roles: Vec<String>,
    /// `wss://` endpoints.
    pub endpoints: Vec<String>,
    /// Mix layer.
    pub layer: u8,
    /// Expiry (unix seconds).
    pub valid_until: u64,
    /// Direct sponsor (none for roots), for path diversity.
    pub sponsor: Option<Vec<u8>>,
}

fn role_name(r: &Role) -> String {
    match r {
        Role::Gateway => "gateway",
        Role::Mix => "mix",
        Role::Mailbox => "mailbox",
    }
    .to_string()
}

/// Verify a `Directory` frame body against the trusted roots.
#[uniffi::export]
pub fn verify_directory(
    signed_directory: Vec<u8>,
    roots: Vec<Vec<u8>>,
    now_unix_secs: u64,
) -> FfiResult<Vec<FfiNode>> {
    let roots = roots
        .iter()
        .map(|r| fixed::<32>(r))
        .collect::<FfiResult<Vec<_>>>()?;
    let d: Signed<harpochat_core::directory::Directory> =
        cbor::from_slice(&signed_directory, 1 << 20)?;
    Ok(core_verify_directory(&d, &roots, now_unix_secs)?
        .into_iter()
        .map(|n| {
            let d = n.descriptor;
            FfiNode {
                id_pub: d.id_pub.to_vec(),
                noise_pub: d.noise_pub.to_vec(),
                sphinx_pub: d.sphinx_pub.to_vec(),
                roles: d.roles.iter().map(role_name).collect(),
                endpoints: d.endpoints,
                layer: d.layer,
                valid_until: d.valid_until,
                sponsor: n.sponsor.map(|s| s.to_vec()),
            }
        })
        .collect())
}

/// Nodes present with the same identity and Sphinx key in every view.
#[uniffi::export]
pub fn intersect_directories(views: Vec<Vec<FfiNode>>) -> Vec<FfiNode> {
    let Some((first, rest)) = views.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|n| {
            rest.iter().all(|v| {
                v.iter()
                    .any(|m| m.id_pub == n.id_pub && m.sphinx_pub == n.sphinx_pub)
            })
        })
        .cloned()
        .collect()
}
