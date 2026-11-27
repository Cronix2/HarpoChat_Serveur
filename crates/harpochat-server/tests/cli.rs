// SPDX-License-Identifier: Apache-2.0
//! Black-box tests of the `harpochat-server` binary.

use std::path::Path;
use std::process::{Command, Output};

use harpochat_core::bootstrap::RootEntry;

fn bin(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_harpochat-server"))
        .arg("--dir")
        .arg(dir)
        .args(args)
        .env_remove("HARPOCHAT_HOME")
        .output()
        .expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn all_output(o: &Output) -> String {
    format!("{}{}", stdout(o), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn init_creates_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let o = bin(
        &dir,
        &["init", "--root", "--endpoint", "wss://root.example:443"],
    );
    assert!(o.status.success(), "{}", all_output(&o));
    assert!(dir.join("node.key").is_file());
    assert!(dir.join("harpochat-server.toml").is_file());
    let id = harpochat_server::keystore::load(&dir)
        .unwrap()
        .identity
        .public();
    assert!(stdout(&o).contains(&hex::encode(id)));
}

#[test]
fn init_refuses_to_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(bin(tmp.path(), &["init", "--root"]).status.success());
    let before = std::fs::read(tmp.path().join("node.key")).unwrap();
    let o = bin(tmp.path(), &["init", "--root"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
    assert_eq!(std::fs::read(tmp.path().join("node.key")).unwrap(), before);
}

#[test]
fn init_root_prints_bootstrap_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let o = bin(
        tmp.path(),
        &["init", "--root", "--endpoint", "wss://root.example:443"],
    );
    assert!(o.status.success());
    let out = stdout(&o);
    let line = out
        .lines()
        .find_map(|l| l.strip_prefix("bootstrap-entry: "))
        .expect("bootstrap-entry line");
    let bytes = hex::decode(line.trim()).unwrap();
    let entry: RootEntry = harpochat_core::cbor::from_slice(&bytes, 4096).unwrap();
    let id = harpochat_server::keystore::load(tmp.path())
        .unwrap()
        .identity
        .public();
    assert_eq!(entry.id_pub, id);
    assert_eq!(entry.endpoints, vec!["wss://root.example:443".to_string()]);
}

#[test]
fn init_dir_is_file_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("f");
    std::fs::write(&file, b"x").unwrap();
    let o = bin(&file, &["init", "--root"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
}

#[test]
fn init_bad_endpoint_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("n");
    let o = bin(&dir, &["init", "--endpoint", "http://x"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
    assert!(!dir.join("node.key").exists());
}

#[test]
fn run_check_ok_after_init_root() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(bin(
        tmp.path(),
        &["init", "--root", "--endpoint", "wss://r.example"]
    )
    .status
    .success());
    let o = bin(tmp.path(), &["run", "--check"]);
    assert!(o.status.success(), "{}", all_output(&o));
    assert!(stdout(&o).starts_with("ok:"), "{}", stdout(&o));
}

#[test]
fn run_check_missing_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let o = bin(tmp.path(), &["run", "--check"]);
    assert_eq!(o.status.code(), Some(1), "{}", all_output(&o));
}

#[test]
fn run_check_non_root_without_roots() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(bin(tmp.path(), &["init"]).status.success());
    let o = bin(tmp.path(), &["run", "--check"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
    assert!(all_output(&o).contains("roots"));
}

#[test]
fn run_check_output_has_no_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let init = bin(
        tmp.path(),
        &["init", "--root", "--endpoint", "wss://r.example"],
    );
    let o = bin(tmp.path(), &["run", "--check"]);
    let keys = harpochat_server::keystore::load(tmp.path()).unwrap();
    let seed = hex::encode(*keys.identity.seed());
    let noise = hex::encode(*keys.noise.to_bytes());
    for out in [all_output(&init), all_output(&o)] {
        assert!(!out.contains(&seed) && !out.contains(&noise));
    }
}

#[test]
fn version_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let o = bin(tmp.path(), &["--version"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn invite_node_prints_a_token() {
    let tmp = tempfile::tempdir().unwrap();
    let init = bin(
        tmp.path(),
        &["init", "--root", "--endpoint", "wss://root.example:443"],
    );
    assert!(init.status.success(), "{}", all_output(&init));
    let o = bin(tmp.path(), &["invite-node", "--hours", "2"]);
    assert!(o.status.success(), "{}", all_output(&o));
    let token = stdout(&o).trim().to_string();
    assert!(token.starts_with("hcn1-"), "{token}");
    let invite = harpochat_core::invite::decode_token(&token, 0).unwrap();
    assert_eq!(invite.sponsor_endpoints, vec!["wss://root.example:443"]);
    // More than 48 h is refused.
    let o = bin(tmp.path(), &["invite-node", "--hours", "49"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
}

#[test]
fn unsponsored_node_cannot_invite() {
    let tmp = tempfile::tempdir().unwrap();
    // A root without any public endpoint cannot be reached by a new node.
    assert!(bin(tmp.path(), &["init", "--root"]).status.success());
    let o = bin(tmp.path(), &["invite-node"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
    assert!(all_output(&o).contains("adresse publique"));
}

#[test]
fn join_with_bad_token_fails_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("new");
    let o = bin(&dir, &["join", "hcn1-NOTATOKEN"]);
    assert_eq!(o.status.code(), Some(2), "{}", all_output(&o));
    assert!(!dir.exists(), "nothing written");
}

#[test]
fn revoke_writes_config() {
    let tmp = tempfile::tempdir().unwrap();
    let init = bin(
        tmp.path(),
        &["init", "--root", "--endpoint", "wss://root.example:443"],
    );
    assert!(init.status.success());
    let o = bin(tmp.path(), &["revoke", &"ab".repeat(32)]);
    assert!(o.status.success(), "{}", all_output(&o));
    let text = std::fs::read_to_string(tmp.path().join("harpochat-server.toml")).unwrap();
    let c = harpochat_server::config::Config::parse(&text).unwrap();
    let r = c.revocation_list().unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].verify().unwrap().node_id, [0xAB; 32]);
    // The node still starts with its revocation.
    let check = bin(tmp.path(), &["run", "--check"]);
    assert!(check.status.success(), "{}", all_output(&check));
    let bad = bin(tmp.path(), &["revoke", "xyz"]);
    assert_eq!(bad.status.code(), Some(2));
}
