use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::core::{config::Config, crypto, git, keys, manifest::Manifest, metadata::SecretMetadata, paths};
use crate::error::VaultError;

#[derive(Debug)]
pub enum CheckIssue {
    Warning(String),
    Error(String),
}

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
        expires: Option<chrono::DateTime<chrono::Utc>>,
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

        // Write .meta file (preserve created timestamp on update)
        let meta_path = self.paths.secret_meta_file(secret_path);
        let mut meta = if meta_path.exists() {
            let mut existing = SecretMetadata::load(&meta_path)?;
            existing.rotated = chrono::Utc::now();
            existing.authorized_agents = authorized.clone();
            existing
        } else {
            SecretMetadata::new(secret_path, group, authorized.clone())
        };
        if let Some(exp) = expires {
            meta.expires = Some(exp);
        }
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

    /// Pull latest from git (best-effort, silently skips if no remote).
    pub fn pull(&self) -> Result<(), VaultError> {
        let repo = git::open_repo(self.paths.root())?;
        git::pull(&repo)
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

    /// Re-encrypt a single secret for its current set of authorized recipients.
    /// Decrypts with the owner key, then re-encrypts for owner + all currently authorized agents.
    fn re_encrypt_secret(&self, secret_path: &str, manifest: &Manifest) -> Result<Vec<PathBuf>, VaultError> {
        let owner_key_path = paths::owner_key_path();
        let owner_private = keys::load_private_key(&owner_key_path)?;
        let owner_identity = crypto::parse_identity(owner_private.expose_secret())?;

        let enc_path = self.paths.secret_enc_file(secret_path);
        let ciphertext = std::fs::read(&enc_path)?;
        let plaintext = crypto::decrypt(&ciphertext, &owner_identity)?;

        // Build new recipient list: owner + authorized agents
        let mut recipients = vec![];
        let owner_pub_str = keys::load_public_key(&self.paths.owner_pub_file())?;
        recipients.push(crypto::parse_recipient(&owner_pub_str)?);

        let authorized = manifest.authorized_agents_for_secret(secret_path);
        for agent_name in &authorized {
            let pub_path = self.paths.agent_pub_file(agent_name);
            if pub_path.exists() {
                let pub_str = keys::load_public_key(&pub_path)?;
                recipients.push(crypto::parse_recipient(&pub_str)?);
            }
        }

        let new_ciphertext = crypto::encrypt(plaintext.expose_secret().as_bytes(), &recipients)?;
        std::fs::write(&enc_path, &new_ciphertext)?;

        // Update metadata
        let meta_path = self.paths.secret_meta_file(secret_path);
        if meta_path.exists() {
            let mut meta = SecretMetadata::load(&meta_path)?;
            meta.authorized_agents = authorized;
            meta.rotated = chrono::Utc::now();
            meta.save(&meta_path)?;
        }

        Ok(vec![enc_path, meta_path])
    }

    /// Grant an agent access to a group. Re-encrypts all secrets in that group.
    pub fn grant_agent(&self, agent_name: &str, group_name: &str) -> Result<Vec<String>, VaultError> {
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        manifest.grant(agent_name, group_name)?;

        let secret_paths = manifest.secrets_in_group(group_name);
        let mut changed_files = vec![self.paths.manifest_file()];

        for sp in &secret_paths {
            let mut files = self.re_encrypt_secret(sp, &manifest)?;
            changed_files.append(&mut files);
        }

        manifest.save(&self.paths.manifest_file())?;

        let repo = git::open_repo(self.paths.root())?;
        git::commit_files(
            &repo,
            &changed_files,
            &format!("agent-vault: grant '{agent_name}' access to '{group_name}'"),
        )?;

        Ok(secret_paths)
    }

    /// Revoke an agent's access to a group. Re-encrypts all secrets in that group.
    /// Returns the list of secret paths that were re-encrypted.
    pub fn revoke_agent(&self, agent_name: &str, group_name: &str) -> Result<Vec<String>, VaultError> {
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        manifest.revoke(agent_name, group_name)?;

        let secret_paths = manifest.secrets_in_group(group_name);
        let mut changed_files = vec![self.paths.manifest_file()];

        for sp in &secret_paths {
            let mut files = self.re_encrypt_secret(sp, &manifest)?;
            changed_files.append(&mut files);
        }

        manifest.save(&self.paths.manifest_file())?;

        let repo = git::open_repo(self.paths.root())?;
        git::commit_files(
            &repo,
            &changed_files,
            &format!("agent-vault: revoke '{agent_name}' access to '{group_name}'"),
        )?;

        Ok(secret_paths)
    }

    /// Remove an agent from the vault entirely.
    /// Re-encrypts all secrets the agent had access to, removes agent files.
    /// Returns the list of groups the agent belonged to (for rotation warnings).
    pub fn remove_agent(&self, name: &str) -> Result<Vec<String>, VaultError> {
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        let groups = manifest.remove_agent(name)?;

        // Collect all secrets that need re-encryption
        let mut all_secret_paths = vec![];
        for group_name in &groups {
            for sp in manifest.secrets_in_group(group_name) {
                if !all_secret_paths.contains(&sp) {
                    all_secret_paths.push(sp);
                }
            }
        }

        let mut changed_files = vec![self.paths.manifest_file()];
        for sp in &all_secret_paths {
            let mut files = self.re_encrypt_secret(sp, &manifest)?;
            changed_files.append(&mut files);
        }

        manifest.save(&self.paths.manifest_file())?;

        // Git: remove agent files from index before deleting from disk
        let repo = git::open_repo(self.paths.root())?;
        let agent_relative = std::path::Path::new(".agent-vault").join("agents").join(name);
        git::remove_dir_from_index(&repo, &agent_relative)?;

        // Remove agent directory from disk
        let agent_dir = self.paths.agent_dir(name);
        if agent_dir.exists() {
            std::fs::remove_dir_all(&agent_dir)?;
        }

        // Commit the manifest + re-encrypted secrets + index removals
        git::commit_files(
            &repo,
            &changed_files,
            &format!("agent-vault: remove agent '{name}'"),
        )?;

        Ok(groups)
    }

    /// Recover an agent: decrypt escrow, generate new keypair, re-encrypt secrets, new escrow.
    /// Returns the path to the new private key.
    pub fn recover_agent(&self, name: &str) -> Result<PathBuf, VaultError> {
        // Verify agent exists
        let escrow_path = self.paths.agent_escrow_file(name);
        if !escrow_path.exists() {
            return Err(VaultError::AgentNotFound(name.to_string()));
        }

        // Generate new keypair
        let (new_secret, new_public) = crypto::generate_keypair();

        // Save new private key locally
        let new_key_path = paths::agent_key_path(name);
        keys::save_private_key(&new_key_path, &new_secret)?;

        // Update public key in repo
        keys::save_public_key(&self.paths.agent_pub_file(name), &new_public)?;

        // Create new escrow
        let owner_pub = keys::load_public_key(&self.paths.owner_pub_file())?;
        keys::create_escrow(&new_secret, &owner_pub, &self.paths.agent_escrow_file(name))?;

        // Re-encrypt all secrets this agent has access to
        let manifest = Manifest::load(&self.paths.manifest_file())?;
        let agent_groups = manifest
            .agent_groups(name)
            .unwrap_or_default();

        let mut changed_files = vec![
            self.paths.agent_pub_file(name),
            self.paths.agent_escrow_file(name),
        ];

        for group_name in &agent_groups {
            for sp in manifest.secrets_in_group(group_name) {
                let mut files = self.re_encrypt_secret(&sp, &manifest)?;
                changed_files.append(&mut files);
            }
        }

        let repo = git::open_repo(self.paths.root())?;
        git::commit_files(
            &repo,
            &changed_files,
            &format!("agent-vault: recover agent '{name}' with new keypair"),
        )?;

        Ok(new_key_path)
    }

    /// Restore an agent's original private key from escrow.
    /// Writes the decrypted key to the specified path.
    pub fn restore_agent(&self, name: &str, to_path: &Path) -> Result<(), VaultError> {
        let escrow_path = self.paths.agent_escrow_file(name);
        if !escrow_path.exists() {
            return Err(VaultError::AgentNotFound(name.to_string()));
        }

        let owner_key_path = paths::owner_key_path();
        let owner_private = keys::load_private_key(&owner_key_path)?;
        let agent_private = keys::recover_from_escrow(&escrow_path, &owner_private)?;

        keys::save_private_key(to_path, &SecretString::from(agent_private.expose_secret().to_string()))?;

        Ok(())
    }

    /// Audit the vault for issues.
    pub fn check(&self) -> Result<Vec<CheckIssue>, VaultError> {
        let manifest = Manifest::load(&self.paths.manifest_file())?;
        let mut issues = vec![];

        // Verify config is valid
        if let Err(e) = Config::load(&self.paths.config_file()) {
            issues.push(CheckIssue::Error(format!("Invalid config.yaml: {e}")));
        }

        // Check for agents with no group access
        for agent in &manifest.agents {
            if agent.groups.is_empty() {
                issues.push(CheckIssue::Warning(format!(
                    "Agent '{}' has no group access",
                    agent.name
                )));
            }
        }

        // Check for empty groups
        for group in &manifest.groups {
            if group.secrets.is_empty() {
                issues.push(CheckIssue::Warning(format!(
                    "Group '{}' has no secrets",
                    group.name
                )));
            }
            if manifest.agents_in_group(&group.name).is_empty() {
                issues.push(CheckIssue::Warning(format!(
                    "Group '{}' has no agents assigned",
                    group.name
                )));
            }
        }

        // Check for orphaned secret files (on disk but not in manifest)
        let secrets_dir = self.paths.secrets_dir();
        if secrets_dir.exists() {
            for group_entry in std::fs::read_dir(&secrets_dir)? {
                let group_entry = group_entry?;
                if !group_entry.file_type()?.is_dir() {
                    continue;
                }
                let group_name = group_entry.file_name().to_string_lossy().to_string();
                for file_entry in std::fs::read_dir(group_entry.path())? {
                    let file_entry = file_entry?;
                    let fname = file_entry.file_name().to_string_lossy().to_string();
                    if let Some(secret_name) = fname.strip_suffix(".enc") {
                        let secret_path = format!("{group_name}/{secret_name}");
                        if manifest.authorized_agents_for_secret(&secret_path).is_empty()
                            && !manifest.groups.iter().any(|g| g.secrets.contains(&secret_path))
                        {
                            issues.push(CheckIssue::Warning(format!(
                                "Orphaned secret file: {secret_path}"
                            )));
                        }
                    }
                }
            }
        }

        // Check for missing .enc files referenced in manifest
        for group in &manifest.groups {
            for secret_path in &group.secrets {
                let enc_path = self.paths.secret_enc_file(secret_path);
                if !enc_path.exists() {
                    issues.push(CheckIssue::Error(format!(
                        "Secret '{secret_path}' listed in manifest but .enc file missing"
                    )));
                }
            }
        }

        // Check for missing agent key files referenced in manifest
        for agent in &manifest.agents {
            let pub_path = self.paths.agent_pub_file(&agent.name);
            if !pub_path.exists() {
                issues.push(CheckIssue::Error(format!(
                    "Agent '{}' in manifest but public key file missing",
                    agent.name
                )));
            }
            let escrow_path = self.paths.agent_escrow_file(&agent.name);
            if !escrow_path.exists() {
                issues.push(CheckIssue::Error(format!(
                    "Agent '{}' missing escrow file",
                    agent.name
                )));
            }
        }

        // Check for expiring credentials
        let secrets = self.list_secrets(None)?;
        let now = chrono::Utc::now();
        for meta in &secrets {
            if let Some(expires) = meta.expires {
                let days_until = (expires - now).num_days();
                if days_until < 0 {
                    issues.push(CheckIssue::Error(format!(
                        "Secret '{}' expired {} days ago",
                        meta.name,
                        -days_until
                    )));
                } else if days_until < 30 {
                    issues.push(CheckIssue::Warning(format!(
                        "Secret '{}' expires in {} days",
                        meta.name, days_until
                    )));
                }
            }
        }

        // Check owner key exists
        let owner_key = paths::owner_key_path();
        if !owner_key.exists() {
            issues.push(CheckIssue::Warning(
                "Owner private key not found at ~/.agent-vault/owner.key".to_string(),
            ));
        }

        Ok(issues)
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
