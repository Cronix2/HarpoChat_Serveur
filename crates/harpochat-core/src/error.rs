// SPDX-License-Identifier: Apache-2.0
//! Error type shared by every module of the core.
//!
//! Variants are deliberately coarse: a server must answer uniformly
//! (spec §8, "pas d'oracle d'erreur"), so no variant carries detail that
//! could be reflected to a remote peer.

/// All failures of the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// Input could not be parsed, or violates a structural rule.
    #[error("malformed input")]
    Malformed,
    /// Input exceeds a size or count limit.
    #[error("input too large")]
    TooLarge,
    /// Unknown or unsupported format version.
    #[error("unsupported version")]
    UnsupportedVersion,
    /// A signature or MAC does not verify.
    #[error("bad signature")]
    BadSignature,
    /// The object is past its validity window.
    #[error("expired")]
    Expired,
    /// The object is not valid yet (clock skew window exceeded).
    #[error("not yet valid")]
    NotYetValid,
    /// Valid object, but not authorised for this resource.
    #[error("unauthorized")]
    Unauthorized,
    /// Not anchored to a trusted root, or revoked.
    #[error("untrusted")]
    Untrusted,
    /// Sphinx packet processing failed.
    #[error("sphinx failure")]
    Sphinx,
}

/// Result alias for the core.
pub type Result<T> = core::result::Result<T, CoreError>;
