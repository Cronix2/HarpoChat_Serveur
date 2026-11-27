// SPDX-License-Identifier: Apache-2.0
//! Log audit (spec §10): the real binary, at debug level, serving a phone
//! that registers, PUTs, FETCHes and then misbehaves, writes nothing that
//! identifies the phone, its mailbox or its traffic.

#[allow(dead_code)] // helpers shared with the milestone tests
mod common;

use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::client::Client;
use common::mesh::{directory_at, now};
use harpochat_core::keys::random_bytes;
use harpochat_core::mailbox::{epoch_of, MailboxKeys};
use harpochat_core::path::Candidate;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_reveal_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let bin = env!("CARGO_BIN_EXE_harpochat-server");
    let init = Command::new(bin)
        .arg("--dir")
        .arg(tmp.path())
        .args(["init", "--root", "--endpoint", &format!("wss://{listen}")])
        .output()
        .unwrap();
    assert!(init.status.success());
    let cfg = tmp.path().join("harpochat-server.toml");
    let text = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace("0.0.0.0:443", &listen);
    std::fs::write(&cfg, text).unwrap();

    let mut child = Command::new(bin)
        .arg("--dir")
        .arg(tmp.path())
        .arg("run")
        .env("HARPOCHAT_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let addr: SocketAddr = listen.parse().unwrap();
    let id = harpochat_server::keystore::load(tmp.path())
        .unwrap()
        .identity
        .public();
    let mut nodes = None;
    for _ in 0..50 {
        nodes = directory_at(addr, id, &[id]).await;
        if nodes.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let hop = Candidate::from(&nodes.expect("node up")[0]).hop;

    // A phone: inbox, PUT, FETCH; then a malformed frame (error path).
    let k = MailboxKeys::derive(&random_bytes(), epoch_of(now()));
    let secret_blob = b"TRES-SECRET-CONTENU";
    let mut c = Client::connect(addr, hop).await.unwrap();
    let inbox = c.inbox;
    c.put(&k, secret_blob).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(c.fetch(&k, now()).await.is_some());
    c.writer.send_raw(vec![0; 100]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    child.kill().unwrap();
    let mut logs = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .unwrap();
    let _ = child.wait();

    assert!(logs.contains("démarré"), "{logs}");
    assert!(!logs.contains('\u{1b}'), "no ANSI codes in a pipe");
    // The only address in the logs is the node's own listening socket.
    assert_eq!(
        logs.matches("127.0.0.1").count(),
        logs.matches(&listen).count(),
        "{logs}"
    );
    for secret in [
        hex::encode(inbox),
        hex::encode(k.mailbox_id()),
        hex::encode(&k.mailbox_id()[..8]),
        String::from_utf8_lossy(secret_blob).into_owned(),
    ] {
        assert!(!logs.contains(&secret), "leaked {secret}: {logs}");
    }
}
