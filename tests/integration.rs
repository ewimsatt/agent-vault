use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use secrecy::ExposeSecret;
use tempfile::TempDir;

use agent_vault::core::vault::Vault;

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
    unsafe { std::env::set_var("HOME", &fake_home); }

    (tmp, root)
}

#[test]
fn test_full_flow_init_add_agent_set_get() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();

    // 1. Init
    let vault = Vault::init(&root).unwrap();

    // Verify structure created
    assert!(root.join(".agent-vault/config.yaml").exists());
    assert!(root.join(".agent-vault/owner.pub").exists());
    assert!(root.join(".agent-vault/manifest.yaml").exists());
    assert!(root.join(".agent-vault/.gitignore").exists());

    // Verify owner key saved
    let owner_key_path = agent_vault::core::paths::owner_key_path();
    assert!(owner_key_path.exists());

    // 2. Add agent
    let agent_key_path = vault.add_agent("test-agent").unwrap();
    assert!(agent_key_path.exists());
    assert!(root
        .join(".agent-vault/agents/test-agent/public.key")
        .exists());
    assert!(root
        .join(".agent-vault/agents/test-agent/private.key.escrow")
        .exists());

    // 3. Set secret (no agents granted yet, only owner can decrypt)
    vault
        .set_secret("stripe/api-key", "sk_test_123", "stripe")
        .unwrap();
    assert!(root
        .join(".agent-vault/secrets/stripe/api-key.enc")
        .exists());
    assert!(root
        .join(".agent-vault/secrets/stripe/api-key.meta")
        .exists());

    // 4. Get secret as owner
    let plaintext = vault
        .get_secret("stripe/api-key", &owner_key_path)
        .unwrap();
    assert_eq!(plaintext.expose_secret(), "sk_test_123");

    // 5. Agent can NOT decrypt (not granted to stripe group)
    let result = vault.get_secret("stripe/api-key", &agent_key_path);
    assert!(result.is_err());

    // 6. List agents
    let agents = vault.list_agents().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].0, "test-agent");
    assert!(agents[0].1.is_empty()); // no groups yet

    // 7. List secrets
    let secrets = vault.list_secrets(None).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "stripe/api-key");
    assert_eq!(secrets[0].group, "stripe");
}

#[test]
fn test_init_twice_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();

    Vault::init(&root).unwrap();
    let result = Vault::init(&root);
    assert!(result.is_err());
}

#[test]
fn test_add_duplicate_agent_fails() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault.add_agent("bot1").unwrap();
    let result = vault.add_agent("bot1");
    assert!(result.is_err());
}

#[test]
fn test_get_nonexistent_secret() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    let key_path = agent_vault::core::paths::owner_key_path();
    let result = vault.get_secret("nope/nothing", &key_path);
    assert!(result.is_err());
}

#[test]
fn test_multiple_secrets() {
    let _lock = HOME_LOCK.lock().unwrap();
    let (_tmp, root) = setup_git_repo();
    let vault = Vault::init(&root).unwrap();

    vault
        .set_secret("stripe/api-key", "sk_123", "stripe")
        .unwrap();
    vault
        .set_secret("stripe/webhook-secret", "whsec_456", "stripe")
        .unwrap();
    vault
        .set_secret("postgres/conn-string", "postgres://...", "postgres")
        .unwrap();

    let all = vault.list_secrets(None).unwrap();
    assert_eq!(all.len(), 3);

    let stripe_only = vault.list_secrets(Some("stripe")).unwrap();
    assert_eq!(stripe_only.len(), 2);

    let owner_key = agent_vault::core::paths::owner_key_path();
    assert_eq!(
        vault
            .get_secret("stripe/api-key", &owner_key)
            .unwrap()
            .expose_secret(),
        "sk_123"
    );
    assert_eq!(
        vault
            .get_secret("postgres/conn-string", &owner_key)
            .unwrap()
            .expose_secret(),
        "postgres://..."
    );
}
