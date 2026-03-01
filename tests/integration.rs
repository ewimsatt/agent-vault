use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use secrecy::ExposeSecret;
use tempfile::TempDir;

use agent_vault::core::vault::{CheckIssue, Vault};

// Global mutex to serialize tests that modify HOME env var.
static HOME_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set up a temporary git repo with isolated HOME.
fn setup_git_repo() -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();

    // Initialize a git repo so vault init can commit
    git2::Repository::init(&root).unwrap();

    // Override HOME so we don't pollute the real ~/.agent-vault/
    let fake_home = root.join("fakehome");
    fs::create_dir_all(&fake_home).unwrap();
    unsafe {
        std::env::set_var("HOME", &fake_home);
    }

    (tmp, root)
}

// ---- Basic flow tests ----

#[test]
fn test_full_flow_init_add_agent_set_get() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();

    let vault = Vault::init(&root).unwrap();

    assert!(root.join(".agent-vault/config.yaml").exists());
    assert!(root.join(".agent-vault/owner.pub").exists());
    assert!(root.join(".agent-vault/manifest.yaml").exists());
    assert!(root.join(".agent-vault/.gitignore").exists());

    let owner_key_path = agent_vault::core::paths::owner_key_path();
    assert!(owner_key_path.exists());

    let agent_key_path = vault.add_agent("test-agent").unwrap();
    assert!(agent_key_path.exists());
    assert!(root
        .join(".agent-vault/agents/test-agent/public.key")
        .exists());
    assert!(root
        .join(".agent-vault/agents/test-agent/private.key.escrow")
        .exists());

    vault
        .set_secret("stripe/api-key", "sk_test_123", "stripe", None, None)
        .unwrap();

    let plaintext = vault
        .get_secret("stripe/api-key", &owner_key_path)
        .unwrap();
    assert_eq!(plaintext.expose_secret(), "sk_test_123");

    // Agent can NOT decrypt (not granted)
    let result = vault.get_secret("stripe/api-key", &agent_key_path);
    assert!(result.is_err());

    let agents = vault.list_agents().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].0, "test-agent");
    assert!(agents[0].1.is_empty());

    let secrets = vault.list_secrets(None).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "stripe/api-key");
}

#[test]
fn test_init_twice_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();

    Vault::init(&root).unwrap();
    assert!(Vault::init(&root).is_err());
}

#[test]
fn test_add_duplicate_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.add_agent("bot1").unwrap();
    assert!(vault.add_agent("bot1").is_err());
}

#[test]
fn test_get_nonexistent_secret() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let key_path = agent_vault::core::paths::owner_key_path();
    assert!(vault.get_secret("nope/nothing", &key_path).is_err());
}

#[test]
fn test_multiple_secrets() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.set_secret("stripe/webhook-secret", "whsec_456", "stripe", None, None).unwrap();
    vault.set_secret("postgres/conn-string", "postgres://...", "postgres", None, None).unwrap();

    assert_eq!(vault.list_secrets(None).unwrap().len(), 3);
    assert_eq!(vault.list_secrets(Some("stripe")).unwrap().len(), 2);

    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault.get_secret("stripe/api-key", &owner_key).unwrap().expose_secret(),
        "sk_123"
    );
    assert_eq!(
        vault.get_secret("postgres/conn-string", &owner_key).unwrap().expose_secret(),
        "postgres://..."
    );
}

// ---- Grant / Revoke tests ----

#[test]
fn test_grant_enables_agent_access() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let agent_key = vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();

    // Before grant: agent can't decrypt
    assert!(vault.get_secret("stripe/api-key", &agent_key).is_err());

    // Grant access
    let secrets = vault.grant_agent("bot1", "stripe").unwrap();
    assert_eq!(secrets, vec!["stripe/api-key"]);

    // After grant: agent can decrypt
    let plaintext = vault.get_secret("stripe/api-key", &agent_key).unwrap();
    assert_eq!(plaintext.expose_secret(), "sk_123");

    // Owner can still decrypt
    let owner_key = agent_vault::core::paths::owner_key_path();
    let plaintext = vault.get_secret("stripe/api-key", &owner_key).unwrap();
    assert_eq!(plaintext.expose_secret(), "sk_123");

    // Agent shows group membership
    let agents = vault.list_agents().unwrap();
    assert_eq!(agents[0].1, vec!["stripe"]);
}

#[test]
fn test_revoke_removes_agent_access() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let agent_key = vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.grant_agent("bot1", "stripe").unwrap();

    // Agent can decrypt
    assert_eq!(
        vault.get_secret("stripe/api-key", &agent_key).unwrap().expose_secret(),
        "sk_123"
    );

    // Revoke access
    let secrets = vault.revoke_agent("bot1", "stripe").unwrap();
    assert_eq!(secrets, vec!["stripe/api-key"]);

    // Agent can no longer decrypt
    assert!(vault.get_secret("stripe/api-key", &agent_key).is_err());

    // Owner can still decrypt
    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault.get_secret("stripe/api-key", &owner_key).unwrap().expose_secret(),
        "sk_123"
    );
}

#[test]
fn test_grant_nonexistent_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    assert!(vault.grant_agent("ghost", "stripe").is_err());
}

#[test]
fn test_grant_nonexistent_group_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.add_agent("bot1").unwrap();
    assert!(vault.grant_agent("bot1", "nonexistent").is_err());
}

#[test]
fn test_multi_agent_grant_revoke() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let key1 = vault.add_agent("bot1").unwrap();
    let key2 = vault.add_agent("bot2").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();

    // Grant both
    vault.grant_agent("bot1", "stripe").unwrap();
    vault.grant_agent("bot2", "stripe").unwrap();

    // Both can decrypt
    assert_eq!(vault.get_secret("stripe/api-key", &key1).unwrap().expose_secret(), "sk_123");
    assert_eq!(vault.get_secret("stripe/api-key", &key2).unwrap().expose_secret(), "sk_123");

    // Revoke bot1
    vault.revoke_agent("bot1", "stripe").unwrap();

    // bot1 can't, bot2 still can
    assert!(vault.get_secret("stripe/api-key", &key1).is_err());
    assert_eq!(vault.get_secret("stripe/api-key", &key2).unwrap().expose_secret(), "sk_123");
}

// ---- Remove agent tests ----

#[test]
fn test_remove_agent() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let agent_key = vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.grant_agent("bot1", "stripe").unwrap();

    // Agent can decrypt
    assert_eq!(
        vault.get_secret("stripe/api-key", &agent_key).unwrap().expose_secret(),
        "sk_123"
    );

    // Remove agent
    let groups = vault.remove_agent("bot1").unwrap();
    assert_eq!(groups, vec!["stripe"]);

    // Agent dir removed from repo
    assert!(!root.join(".agent-vault/agents/bot1").exists());

    // Agent can no longer decrypt
    assert!(vault.get_secret("stripe/api-key", &agent_key).is_err());

    // Owner can still decrypt
    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault.get_secret("stripe/api-key", &owner_key).unwrap().expose_secret(),
        "sk_123"
    );

    // Agent no longer listed
    assert!(vault.list_agents().unwrap().is_empty());
}

#[test]
fn test_remove_nonexistent_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    assert!(vault.remove_agent("ghost").is_err());
}

// ---- Recovery tests ----

#[test]
fn test_restore_agent_from_escrow() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let original_key_path = vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.grant_agent("bot1", "stripe").unwrap();

    // Read original key content
    let original_key = fs::read_to_string(&original_key_path).unwrap();

    // Restore to a different path
    let restore_path = root.join("restored.key");
    vault.restore_agent("bot1", &restore_path).unwrap();

    // Restored key matches original
    let restored_key = fs::read_to_string(&restore_path).unwrap();
    assert_eq!(original_key.trim(), restored_key.trim());

    // Can decrypt with restored key
    assert_eq!(
        vault.get_secret("stripe/api-key", &restore_path).unwrap().expose_secret(),
        "sk_123"
    );
}

#[test]
fn test_recover_agent_new_keypair() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let original_key_path = vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.grant_agent("bot1", "stripe").unwrap();

    // Read original key
    let original_key = fs::read_to_string(&original_key_path).unwrap();

    // Recover with new keypair
    let new_key_path = vault.recover_agent("bot1").unwrap();

    // Key changed
    let new_key = fs::read_to_string(&new_key_path).unwrap();
    assert_ne!(original_key.trim(), new_key.trim());

    // Can still decrypt with new key
    assert_eq!(
        vault.get_secret("stripe/api-key", &new_key_path).unwrap().expose_secret(),
        "sk_123"
    );

    // Old key no longer works
    // Write old key to a temp file for testing
    let old_key_file = root.join("old.key");
    fs::write(&old_key_file, &original_key).unwrap();
    assert!(vault.get_secret("stripe/api-key", &old_key_file).is_err());

    // Owner can still decrypt
    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault.get_secret("stripe/api-key", &owner_key).unwrap().expose_secret(),
        "sk_123"
    );
}

#[test]
fn test_recover_nonexistent_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    assert!(vault.recover_agent("ghost").is_err());
}

// ---- Check tests ----

#[test]
fn test_check_healthy_vault() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.add_agent("bot1").unwrap();
    vault.set_secret("stripe/api-key", "sk_123", "stripe", None, None).unwrap();
    vault.grant_agent("bot1", "stripe").unwrap();

    let issues = vault.check().unwrap();
    // No errors expected (maybe warnings about no expiry)
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, CheckIssue::Error(_)))
        .collect();
    assert!(errors.is_empty());
}

#[test]
fn test_check_agent_no_access() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.add_agent("bot1").unwrap();

    let issues = vault.check().unwrap();
    let has_no_access_warning = issues.iter().any(|i| match i {
        CheckIssue::Warning(msg) => msg.contains("bot1") && msg.contains("no group access"),
        _ => false,
    });
    assert!(has_no_access_warning);
}

// ---- --agents flag tests ----

#[test]
fn test_set_with_extra_agents() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let agent_key = vault.add_agent("bot1").unwrap();

    // Set secret with extra_agents (no group grant needed)
    vault
        .set_secret(
            "stripe/api-key",
            "sk_123",
            "stripe",
            None,
            Some(&["bot1".to_string()]),
        )
        .unwrap();

    // Agent can decrypt even without group grant
    let plaintext = vault.get_secret("stripe/api-key", &agent_key).unwrap();
    assert_eq!(plaintext.expose_secret(), "sk_123");

    // Owner can also decrypt
    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault
            .get_secret("stripe/api-key", &owner_key)
            .unwrap()
            .expose_secret(),
        "sk_123"
    );

    // Metadata lists the agent
    let secrets = vault.list_secrets(None).unwrap();
    assert!(secrets[0].authorized_agents.contains(&"bot1".to_string()));
}

#[test]
fn test_set_with_nonexistent_extra_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let result = vault.set_secret(
        "stripe/api-key",
        "sk_123",
        "stripe",
        None,
        Some(&["ghost".to_string()]),
    );
    assert!(result.is_err());
}
