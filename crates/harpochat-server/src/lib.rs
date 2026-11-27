// SPDX-License-Identifier: Apache-2.0
//! `harpochat-server`: one binary, three roles (gateway, mix, mailbox).
//!
//! Persistent state is limited to the configuration file and the node key
//! file (spec §4.1); everything else lives in RAM and dies with the process.
#![deny(missing_docs)]

pub mod cli;
pub mod config;
pub mod keystore;
pub mod net;
pub mod node;
pub mod peers;
pub mod router;
pub mod server;
pub mod service;
pub mod store;
