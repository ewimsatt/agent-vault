#![allow(deprecated)]

use std::fs;
use std::sync::Mutex;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

static HOME_LOCK: Mutex<()> = Mutex::new(());

fn setup() -> (TempDir, Command) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();

    git2::Repository::init(&root).unwrap();

    let fake_home = root.join("fakehome");
    fs::create_dir_all(&fake_home).unwrap();
    unsafe {
        std::env::set_var("HOME", &fake_home);
    }

    let mut cmd = Command::cargo_bin("agent-vault").unwrap();
    cmd.current_dir(&root);
    cmd.env("HOME", &fake_home);

    (tmp, cmd)
}

fn cmd_in(tmp: &TempDir) -> Command {
    let root = tmp.path().to_path_buf();
    let fake_home = root.join("fakehome");

    let mut cmd = Command::cargo_bin("agent-vault").unwrap();
    cmd.current_dir(&root);
    cmd.env("HOME", &fake_home);
    cmd
}

#[test]
fn test_cli_help() {
    let _lock = HOME_LOCK.lock().unwrap();
    Command::cargo_bin("agent-vault")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Zero-trust credential manager"));
}

#[test]
fn test_cli_init() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();

    cmd.arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("Vault initialized"))
        .stderr(predicate::str::contains("owner key"));

    assert!(tmp.path().join(".agent-vault/config.yaml").exists());
}

#[test]
fn test_cli_init_twice_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already initialized"));
}

#[test]
fn test_cli_add_agent() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "my-bot"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Agent 'my-bot' created"))
        .stderr(predicate::str::contains("agent-vault grant"));
}

#[test]
fn test_cli_list_agents() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "bot1"])
        .assert()
        .success();

    cmd_in(&tmp)
        .arg("list-agents")
        .assert()
        .success()
        .stdout(predicate::str::contains("bot1"))
        .stdout(predicate::str::contains("no groups"));
}

#[test]
fn test_cli_set_get() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["set", "stripe/api-key", "sk_test_123"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Secret 'stripe/api-key' set"));

    cmd_in(&tmp)
        .args(["get", "stripe/api-key"])
        .assert()
        .success()
        .stdout(predicate::str::is_match("sk_test_123").unwrap());
}

#[test]
fn test_cli_set_from_file() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    let secret_file = tmp.path().join("secret.txt");
    fs::write(&secret_file, "file-secret-value").unwrap();

    cmd_in(&tmp)
        .args([
            "set",
            "creds/token",
            "--from-file",
            secret_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["get", "creds/token"])
        .assert()
        .success()
        .stdout(predicate::str::contains("file-secret-value"));
}

#[test]
fn test_cli_list_secrets() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["set", "stripe/api-key", "sk_123"])
        .assert()
        .success();

    cmd_in(&tmp)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe/api-key"))
        .stdout(predicate::str::contains("group=stripe"));
}

#[test]
fn test_cli_grant_revoke() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "bot1"])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["set", "stripe/api-key", "sk_123"])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["grant", "bot1", "stripe"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Granted 'bot1' access"))
        .stderr(predicate::str::contains("Re-encrypted"));

    // Agent can now decrypt
    let agent_key = tmp
        .path()
        .join("fakehome/.agent-vault/agents/bot1.key");
    cmd_in(&tmp)
        .args(["get", "stripe/api-key", "--key", agent_key.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_123"));

    cmd_in(&tmp)
        .args(["revoke", "bot1", "stripe"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Revoked"))
        .stderr(predicate::str::contains("WARNING"));

    // Agent can no longer decrypt
    cmd_in(&tmp)
        .args(["get", "stripe/api-key", "--key", agent_key.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_cli_remove_agent() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "bot1"])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["set", "stripe/api-key", "sk_123"])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["grant", "bot1", "stripe"])
        .assert()
        .success();

    cmd_in(&tmp)
        .args(["remove-agent", "bot1"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Agent 'bot1' removed"))
        .stderr(predicate::str::contains("WARNING"));

    cmd_in(&tmp)
        .arg("list-agents")
        .assert()
        .success()
        .stdout(predicate::str::contains("No agents"));
}

#[test]
fn test_cli_check() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "bot1"])
        .assert()
        .success();

    cmd_in(&tmp)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("bot1").and(predicate::str::contains("no group")));
}

#[test]
fn test_cli_restore_agent() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (tmp, mut cmd) = setup();
    cmd.arg("init").assert().success();

    cmd_in(&tmp)
        .args(["add-agent", "bot1"])
        .assert()
        .success();

    let restore_path = tmp.path().join("restored.key");
    cmd_in(&tmp)
        .args([
            "restore-agent",
            "bot1",
            "--to",
            restore_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("restored"));

    assert!(restore_path.exists());
}

#[test]
fn test_cli_no_vault_errors() {
    let _lock = HOME_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    git2::Repository::init(tmp.path()).unwrap();

    Command::cargo_bin("agent-vault")
        .unwrap()
        .current_dir(tmp.path())
        .arg("list-agents")
        .assert()
        .failure()
        .stderr(predicate::str::contains("vault not found"));
}
