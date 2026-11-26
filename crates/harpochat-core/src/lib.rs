// SPDX-License-Identifier: Apache-2.0
//! # harpochat-core
//!
//! Shared protocol core of HarpoChat, compiled into both `harpochat-server`
//! and the Android app. It holds every wire format of the mesh and nothing
//! else: no network, no files, no clock (time is always a parameter), no
//! `unsafe`.
//!
//! Contract: `docs/SERVER_SPEC.md`. Design: `docs/superpowers/specs/2026-11-26-harpochat-core-design.md`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cbor;
pub mod domain;
mod error;
pub mod hash;
pub mod keys;
pub mod signed;

pub use error::{CoreError, Result};
