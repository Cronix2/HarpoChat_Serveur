// SPDX-License-Identifier: Apache-2.0
//! Strict CBOR (RFC 8949) helpers.
//!
//! Every decoder of the core goes through [`from_slice`], which enforces an
//! input size bound and rejects trailing bytes. Struct definitions use
//! `#[serde(deny_unknown_fields)]` and encode fixed byte arrays as CBOR byte
//! strings (`#[serde(with = "serde_bytes")]`), never as integer arrays.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{CoreError, Result};

/// Maximum CBOR nesting accepted by decoders (our formats nest < 8 deep).
const RECURSION_LIMIT: usize = 32;

/// Encode a value. Our types only contain encodable data, so this cannot fail.
pub fn to_vec<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding is infallible");
    out
}

/// Decode exactly one value from `bytes`.
///
/// `TooLarge` if `bytes.len() > max_len`; `Malformed` on any decode error,
/// unknown field, or trailing bytes.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8], max_len: usize) -> Result<T> {
    if bytes.len() > max_len {
        return Err(CoreError::TooLarge);
    }
    let mut reader = bytes;
    let v = ciborium::de::from_reader_with_recursion_limit(&mut reader, RECURSION_LIMIT)
        .map_err(|_| CoreError::Malformed)?;
    if !reader.is_empty() {
        return Err(CoreError::Malformed);
    }
    Ok(v)
}

/// `#[serde(with)]` helper: `Vec<Vec<u8>>` as an array of byte strings.
pub mod vec_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};

    /// Serialize.
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let items: Vec<&Bytes> = v.iter().map(|b| Bytes::new(b)).collect();
        items.serialize(s)
    }

    /// Deserialize.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let items: Vec<ByteBuf> = Vec::deserialize(d)?;
        Ok(items.into_iter().map(ByteBuf::into_vec).collect())
    }
}

/// `#[serde(with)]` helper: `Vec<[u8; N]>` as an array of byte strings.
pub mod vec_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteArray;

    /// Serialize.
    pub fn serialize<S: Serializer, const N: usize>(
        v: &[[u8; N]],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let items: Vec<ByteArray<N>> = v.iter().map(|a| ByteArray::new(*a)).collect();
        items.serialize(s)
    }

    /// Deserialize.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        let items: Vec<ByteArray<N>> = Vec::deserialize(d)?;
        Ok(items.into_iter().map(ByteArray::into_array).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct WithArray {
        #[serde(with = "serde_bytes")]
        k: [u8; 32],
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Lists {
        #[serde(with = "crate::cbor::vec_bytes")]
        a: Vec<Vec<u8>>,
        #[serde(with = "crate::cbor::vec_array")]
        b: Vec<[u8; 16]>,
    }

    #[test]
    fn roundtrip() {
        let v = WithArray { k: [9; 32] };
        let bytes = to_vec(&v);
        assert_eq!(from_slice::<WithArray>(&bytes, 1024), Ok(v));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = to_vec(&WithArray { k: [9; 32] });
        bytes.push(0);
        assert_eq!(
            from_slice::<WithArray>(&bytes, 1024),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn oversize_rejected() {
        assert_eq!(from_slice::<u8>(&[0; 10], 5), Err(CoreError::TooLarge));
    }

    #[test]
    fn unknown_field_rejected() {
        #[derive(Serialize)]
        struct Extra {
            #[serde(with = "serde_bytes")]
            k: [u8; 32],
            x: u8,
        }
        let bytes = to_vec(&Extra { k: [1; 32], x: 1 });
        assert_eq!(
            from_slice::<WithArray>(&bytes, 1024),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn byte_array_encodes_as_bstr() {
        let bytes = to_vec(&WithArray { k: [9; 32] });
        // map(1), text "k", then bstr header 0x58 0x20 (32 bytes).
        assert!(bytes.windows(2).any(|w| w == [0x58, 0x20]));
        assert!(
            bytes.len() < 40,
            "integer-array encoding would be ~70 bytes"
        );
    }

    #[test]
    fn list_helpers_roundtrip_and_use_bstr() {
        let v = Lists {
            a: vec![vec![1, 2, 3], vec![]],
            b: vec![[7; 16]],
        };
        let bytes = to_vec(&v);
        assert!(bytes.windows(2).any(|w| w == [0x50, 7])); // bstr(16) of 7s
        assert_eq!(from_slice::<Lists>(&bytes, 1024), Ok(v));
    }

    #[test]
    fn wrong_array_length_rejected() {
        #[derive(Serialize)]
        struct Short {
            #[serde(with = "serde_bytes")]
            k: [u8; 31],
        }
        let bytes = to_vec(&Short { k: [1; 31] });
        assert_eq!(
            from_slice::<WithArray>(&bytes, 1024),
            Err(CoreError::Malformed)
        );
    }
}
