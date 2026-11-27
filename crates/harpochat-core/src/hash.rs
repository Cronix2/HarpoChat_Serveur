// SPDX-License-Identifier: Apache-2.0
//! BLAKE2b-256 helpers. `H(x)` in the design documents is [`h`].

use blake2::{Blake2b256, Digest};

/// BLAKE2b-256 over the concatenation of `parts`.
pub fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// BLAKE2b-256 over `len(label) as u8 || label || parts…`.
pub fn h_domain(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(crate::domain::prefix(label));
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_domain_differs_by_label() {
        assert_ne!(h_domain("a", &[b"bc"]), h_domain("ab", &[b"c"]));
    }

    #[test]
    fn h_is_concatenation() {
        assert_eq!(h(&[b"ab", b"c"]), h(&[b"abc"]));
    }
}
