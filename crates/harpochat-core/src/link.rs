// SPDX-License-Identifier: Apache-2.0
//! Fixed-size link frames carried inside a Noise session (design §5.2).
//!
//! Every frame on a link has the plaintext size of its class (Noise adds a
//! 16-byte tag): control traffic is indistinguishable from data and from
//! link padding. Layout: `kind: u8 || body_len: u16 BE || body || zeros`.
//! `DIRECTORY_REQ` / `DIRECTORY` live here rather than in Sphinx payloads
//! (design deviation E1): at bootstrap the client knows no topology yet.

use crate::{CoreError, Result};

/// Noise AEAD tag length.
pub const NOISE_TAG_LEN: usize = 16;
/// `kind: u8 || body_len: u16 BE`.
pub const LINK_HEADER_LEN: usize = 3;

/// The two fixed packet size classes (spec §13, design §5.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SizeClass {
    /// 2 048-byte Noise messages (text messages, control).
    Small,
    /// 32 768-byte Noise messages (media chunks, directories).
    Large,
}

impl SizeClass {
    /// Size of the encrypted Noise message on the wire.
    pub const fn ciphertext_len(self) -> usize {
        match self {
            SizeClass::Small => 2048,
            SizeClass::Large => 32768,
        }
    }

    /// Size of the frame before Noise encryption.
    pub const fn plaintext_len(self) -> usize {
        self.ciphertext_len() - NOISE_TAG_LEN
    }

    /// Largest body a frame of this class can carry.
    pub const fn max_body_len(self) -> usize {
        self.plaintext_len() - LINK_HEADER_LEN
    }

    fn from_plaintext_len(len: usize) -> Option<Self> {
        [SizeClass::Small, SizeClass::Large]
            .into_iter()
            .find(|c| c.plaintext_len() == len)
    }
}

/// What a link frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Link cover traffic.
    Padding = 0x00,
    /// A Sphinx packet.
    Sphinx = 0x01,
    /// Directory request (also used at bootstrap).
    DirectoryReq = 0x02,
    /// Signed directory.
    Directory = 0x03,
    /// Phone → gateway: 32-byte inbox token (design §5.3).
    RegisterInbox = 0x04,
    /// New node → sponsor.
    JoinRequest = 0x05,
    /// Sponsor → new node: vouch or uniform refusal.
    JoinResponse = 0x06,
    /// Descriptors and revocations.
    Gossip = 0x07,
}

impl FrameKind {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => FrameKind::Padding,
            0x01 => FrameKind::Sphinx,
            0x02 => FrameKind::DirectoryReq,
            0x03 => FrameKind::Directory,
            0x04 => FrameKind::RegisterInbox,
            0x05 => FrameKind::JoinRequest,
            0x06 => FrameKind::JoinResponse,
            0x07 => FrameKind::Gossip,
            _ => return None,
        })
    }
}

/// One link frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFrame {
    /// Kind.
    pub kind: FrameKind,
    /// Body (format depends on the kind).
    pub body: Vec<u8>,
}

impl LinkFrame {
    /// Encode to exactly `class.plaintext_len()` bytes.
    pub fn encode(&self, class: SizeClass) -> Result<Vec<u8>> {
        if self.body.len() > class.max_body_len() {
            return Err(CoreError::TooLarge);
        }
        let len = u16::try_from(self.body.len()).map_err(|_| CoreError::TooLarge)?;
        let mut out = Vec::with_capacity(class.plaintext_len());
        out.push(self.kind as u8);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.body);
        out.resize(class.plaintext_len(), 0);
        Ok(out)
    }

    /// Decode a decrypted frame; its length selects the class.
    pub fn decode(bytes: &[u8]) -> Result<(SizeClass, LinkFrame)> {
        let class = SizeClass::from_plaintext_len(bytes.len()).ok_or(CoreError::Malformed)?;
        let kind = FrameKind::from_u8(bytes[0]).ok_or(CoreError::Malformed)?;
        let len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if len > class.max_body_len() {
            return Err(CoreError::Malformed);
        }
        let end = LINK_HEADER_LEN + len;
        if bytes[end..].iter().any(|b| *b != 0) {
            return Err(CoreError::Malformed);
        }
        Ok((
            class,
            LinkFrame {
                kind,
                body: bytes[LINK_HEADER_LEN..end].to_vec(),
            },
        ))
    }

    /// An empty `Padding` frame of the given class.
    pub fn padding(class: SizeClass) -> Vec<u8> {
        LinkFrame {
            kind: FrameKind::Padding,
            body: Vec::new(),
        }
        .encode(class)
        .expect("empty body always fits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use proptest::prelude::*;

    #[test]
    fn class_sizes() {
        assert_eq!(SizeClass::Small.ciphertext_len(), 2048);
        assert_eq!(SizeClass::Small.plaintext_len(), 2032);
        assert_eq!(SizeClass::Large.ciphertext_len(), 32768);
        assert_eq!(SizeClass::Large.plaintext_len(), 32752);
    }

    #[test]
    fn frame_lengths_are_fixed() {
        let max = SizeClass::Small.plaintext_len() - LINK_HEADER_LEN;
        for len in [0usize, 1, max] {
            let f = LinkFrame {
                kind: FrameKind::Sphinx,
                body: vec![7; len],
            };
            let bytes = f.encode(SizeClass::Small).unwrap();
            assert_eq!(bytes.len(), 2032);
            assert_eq!(LinkFrame::decode(&bytes), Ok((SizeClass::Small, f)));
        }
    }

    #[test]
    fn large_frame_roundtrip() {
        let f = LinkFrame {
            kind: FrameKind::Directory,
            body: vec![1; 20_000],
        };
        let bytes = f.encode(SizeClass::Large).unwrap();
        assert_eq!(bytes.len(), 32752);
        assert_eq!(LinkFrame::decode(&bytes), Ok((SizeClass::Large, f)));
    }

    #[test]
    fn frame_body_too_large() {
        let f = LinkFrame {
            kind: FrameKind::Sphinx,
            body: vec![0; 2030],
        };
        assert_eq!(f.encode(SizeClass::Small), Err(CoreError::TooLarge));
    }

    #[test]
    fn frame_rejects_nonzero_padding() {
        let mut bytes = LinkFrame::padding(SizeClass::Small);
        *bytes.last_mut().unwrap() = 1;
        assert_eq!(LinkFrame::decode(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn frame_rejects_unknown_kind() {
        let mut bytes = LinkFrame::padding(SizeClass::Small);
        bytes[0] = 0x08;
        assert_eq!(LinkFrame::decode(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn frame_rejects_body_len_overflow() {
        let mut bytes = LinkFrame::padding(SizeClass::Small);
        bytes[1] = 0x07;
        bytes[2] = 0xF0; // 2032 > capacity
        assert_eq!(LinkFrame::decode(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn frame_rejects_odd_length() {
        assert_eq!(LinkFrame::decode(&[0; 2031]), Err(CoreError::Malformed));
        assert_eq!(LinkFrame::decode(&[]), Err(CoreError::Malformed));
    }

    #[test]
    fn padding_frame_decodes() {
        let (class, f) = LinkFrame::decode(&LinkFrame::padding(SizeClass::Large)).unwrap();
        assert_eq!(class, SizeClass::Large);
        assert_eq!(f.kind, FrameKind::Padding);
        assert!(f.body.is_empty());
    }

    #[test]
    fn kind_codes() {
        let all = [
            (FrameKind::Padding, 0x00),
            (FrameKind::Sphinx, 0x01),
            (FrameKind::DirectoryReq, 0x02),
            (FrameKind::Directory, 0x03),
            (FrameKind::RegisterInbox, 0x04),
            (FrameKind::JoinRequest, 0x05),
            (FrameKind::JoinResponse, 0x06),
            (FrameKind::Gossip, 0x07),
        ];
        for (k, code) in all {
            assert_eq!(k as u8, code);
        }
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 2032..=2032)) {
            let _ = LinkFrame::decode(&bytes);
        }
    }
}
