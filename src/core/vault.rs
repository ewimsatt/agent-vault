use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::core::{config::Config, crypto, git, keys, manifest::Manifest, metadata::SecretMetadata, paths};
use crate::error::VaultError;

pub struct Vault {
    pub paths: paths::VaultPaths,
}

impl Vault {
    /// Open a vault rooted at the given directory.
    pub fn open(root: &Path) -> Result<Self, VaultError> {
        let vault = Self {
            paths: paths::VaultPaths::new(root),
        };
        if !vault.paths.vault_dir().exists() {
            return Err(VaultError::NotInitialized);
        }
        Ok(vault)
    }

    /// Initialize a new vault in the given directory.
    pub fn init(root: &Path) -> Result<Self, VaultError> {
        let vault_paths = paths::VaultPaths::new(root);

        if vault_paths.vault_dir().exists() {
            return Err(VaultError::AlreadyInitialized(
                vault_paths.vault_dir().display().to_string(),
            ));
        }

        // Create directory structure
        std::fs::create_dir_all(vault_paths.agents_dir())?;
        std::fs::create_dir_all(vault_paths.secrets_dir())?;

        // Generate owner keypair
        let (owner_secret, owner_public) = crypto::generate_keypair();

        // Save owner private key to ~/.agent-vault/owner.key
        let owner_key_path = paths::owner_key_path();
        keys::save_private_key(&owner_key_path, &owner_secret)?;

        // Save owner public key to .agent-vault/owner.pub
        keys::save_public_key(&vault_paths.owner_pub_file(), &owner_public)?;

        // Write config
        let config = Config::new();
        config.save(&vault_paths.config_file())?;

        // Write initial manifest
        let owner_name = whoami();
        let manifest = Manifest::new(&owner_name);
        manifest.save(&vault_paths.manifest_file())?;

        // Write .gitignore
        std::fs::write(vault_paths.gitignore_file(), git::gitignore_content())?;

        // Git operations
        let repo = git::open_repo(root)?;
        git::install_pre_commit_hook(&repo)?;

        let files_to_commit = vec![
            vault_paths.config_file(),
            vault_paths.owner_pub_file(),
            vault_paths.manifest_file(),
            vault_paths.gitignore_file(),
        ];
        git::commit_files(&repo, &files_to_commit, "agent-vault: initialize vault")?;

        Ok(Self {
            paths: vault_paths,
        })
    }

    /// Add a new agent to the vault.
    pub fn add_agent(&self, name: &str) -> Result<PathBuf, VaultError> {
        let agent_dir = self.paths.agent_dir(name);
        if agent_dir.exists() {
            return Err(VaultError::AgentExists(name.to_string()));
        }

        // Generate agent keypair
        let (agent_secret, agent_public) = crypto::generate_keypair();

        // Save agent private key locally
        let agent_key_path = paths::agent_key_path(name);
        keys::save_private_key(&agent_key_path, &agent_secret)?;

        // Save agent public key to repo
        std::fs::create_dir_all(&agent_dir)?;
        keys::save_public_key(&self.paths.agent_pub_file(name), &agent_public)?;

        // Create escrow
        let owner_pub = keys::load_public_key(&self.paths.owner_pub_file())?;
        keys::create_escrow(
            &agent_secret,
            &owner_pub,
            &self.paths.agent_escrow_file(name),
        )?;

        // Update manifest
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        manifest.add_agent(name)?;
        manifest.save(&self.paths.manifest_file())?;

        // Commit
        let repo = git::open_repo(self.paths.root())?;
        let files = vec![
            self.paths.agent_pub_file(name),
            self.paths.agent_escrow_file(name),
            self.paths.manifest_file(),
        ];
        git::commit_files(
            &repo,
            &files,
            &format!("agent-vault: add agent '{name}'"),
        )?;

        Ok(agent_key_path)
    }

    /// Set (create or update) a secret.
    pub fn set_secret(
        &self,
        secret_path: &str,
        value: &str,
        group: &str,
    ) -> Result<(), VaultError> {
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;

        // Ensure group exists and secret is registered
        manifest.add_secret_to_group(group, secret_path);

        // Collect recipients: owner + all authorized agents
        let mut recipients = vec![];

        let owner_pub_str = keys::load_public_key(&self.paths.owner_pub_file())?;
        let owner_recipient = crypto::parse_recipient(&owner_pub_str)?;
        recipients.push(owner_recipient);

        let authorized = manifest.agents_in_group(group);
        for agent_name in &authorized {
            let pub_path = self.paths.agent_pub_file(agent_name);
            if pub_path.exists() {
                let pub_str = keys::load_public_key(&pub_path)?;
                let recipient = crypto::parse_recipient(&pub_str)?;
                recipients.push(recipient);
            }
        }

        // Encrypt
        let ciphertext = crypto::encrypt(value.as_bytes(), &recipients)?;

        // Write .enc file
        let enc_path = self.paths.secret_enc_file(secret_path);
        if let Some(parent) = enc_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&enc_path, &ciphertext)?;

        // Write .meta file
        let meta = SecretMetadata::new(secret_path, group, authorized.clone());
        let meta_path = self.paths.secret_meta_file(secret_path);
        meta.save(&meta_path)?;

        // Save updated manifest
        manifest.save(&self.paths.manifest_file())?;

        // Commit
        let repo = git::open_repo(self.paths.root())?;
        let files = vec![enc_path, meta_path, self.paths.manifest_file()];
        git::commit_files(
            &repo,
            &files,
            &format!("agent-vault: set secret '{secret_path}'"),
        )?;

        Ok(())
    }

    /// Get (decrypt) a secret using the provided identity key.
    pub fn get_secret(&self, secret_path: &str, key_path: &Path) -> Result<SecretString, VaultError> {
        let enc_path = self.paths.secret_enc_file(secret_path);
        if !enc_path.exists() {
            return Err(VaultError::SecretNotFound(secret_path.to_string()));
        }

        let private_key = keys::load_private_key(key_path)?;
        let identity = crypto::parse_identity(private_key.expose_secret())?;

        let ciphertext = std::fs::read(&enc_path)?;
        crypto::decrypt(&ciphertext, &identity)
    }

    /// List all agents in the vault.
    pub fn list_agents(&self) -> Result<Vec<(String, Vec<String>)>, VaultError> {
        let manifest = Manifest::load(&self.paths.manifest_file())?;
        let result = manifest
            .agents
            .iter()
            .map(|a| (a.name.clone(), a.groups.clone()))
            .collect();
        Ok(result)
    }

    /// List all secrets, optionally filtered by group.
    pub fn list_secrets(&self, group_filter: Option<&str>) -> Result<Vec<SecretMetadata>, VaultError> {
        let secrets_dir = self.paths.secrets_dir();
        if !secrets_dir.exists() {
            return Ok(vec![]);
        }

        let mut results = vec![];
        for group_entry in std::fs::read_dir(&secrets_dir)? {
            let group_entry = group_entry?;
            if !group_entry.file_type()?.is_dir() {
                continue;
            }
            let group_name = group_entry.file_name().to_string_lossy().to_string();
            if let Some(filter) = group_filter {
                if group_name != filter {
                    continue;
                }
            }
            for file_entry in std::fs::read_dir(group_entry.path())? {
                let file_entry = file_entry?;
                let fname = file_entry.file_name().to_string_lossy().to_string();
                if fname.ends_with(".meta") {
                    let meta = SecretMetadata::load(&file_entry.path())?;
                    results.push(meta);
                }
            }
        }
        Ok(results)
    }

    /// Resolve the identity key to use for decryption.
    /// Priority: --key flag > AGENT_VAULT_KEY env > ~/.agent-vault/owner.key
    pub fn resolve_identity_key(key_flag: Option<&str>) -> Result<PathBuf, VaultError> {
        if let Some(k) = key_flag {
            let p = PathBuf::from(k);
            if p.exists() {
                return Ok(p);
            }
            return Err(VaultError::NoIdentityKey);
        }

        if let Ok(env_key) = std::env::var("AGENT_VAULT_KEY") {
            let p = PathBuf::from(env_key);
            if p.exists() {
                return Ok(p);
            }
        }

        let owner_path = paths::owner_key_path();
        if owner_path.exists() {
            return Ok(owner_path);
        }

        Err(VaultError::NoIdentityKey)
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "owner".to_string())
}
