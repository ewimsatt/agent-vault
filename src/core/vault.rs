use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::core::{
    config::Config, crypto, git, identifiers, keys, manifest::Manifest, metadata::SecretMetadata,
    paths,
};
use crate::error::VaultError;

#[derive(Debug)]
pub enum CheckIssue {
    Warning(String),
    Error(String),
}

/// An identity source selected without persisting raw environment key material.
pub enum IdentityKeySource {
    File(PathBuf),
    Raw(SecretString),
}

struct PreparedSecret {
    enc_path: PathBuf,
    ciphertext: Vec<u8>,
    meta_path: PathBuf,
    metadata: Vec<u8>,
}

fn discover_secret_records(
    directory: &Path,
    root: &Path,
    enc_records: &mut Vec<(String, PathBuf)>,
    meta_records: &mut Vec<(String, PathBuf)>,
) -> Result<(), VaultError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            discover_secret_records(&path, root, enc_records, meta_records)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .expect("secret record is under root");
        let relative = relative.to_string_lossy().replace('\\', "/");
        if let Some(secret_path) = relative.strip_suffix(".enc") {
            enc_records.push((secret_path.to_string(), path));
        } else if let Some(secret_path) = relative.strip_suffix(".meta") {
            meta_records.push((secret_path.to_string(), path));
        }
    }
    Ok(())
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

        Ok(Self { paths: vault_paths })
    }

    /// Add a new agent to the vault.
    pub fn add_agent(&self, name: &str) -> Result<PathBuf, VaultError> {
        identifiers::validate_agent(name)?;
        let agent_dir = self.paths.agent_dir(name);
        if agent_dir.exists() {
            return Err(VaultError::AgentExists(name.to_string()));
        }

        // Load and validate manifest before creating any key material.
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        manifest.add_agent(name)?;

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

        // Save validated manifest after vault key material is in place.
        manifest.save(&self.paths.manifest_file())?;

        // Commit
        let repo = git::open_repo(self.paths.root())?;
        let files = vec![
            self.paths.agent_pub_file(name),
            self.paths.agent_escrow_file(name),
            self.paths.manifest_file(),
        ];
        git::commit_files(&repo, &files, &format!("agent-vault: add agent '{name}'"))?;

        Ok(agent_key_path)
    }

    /// Set (create or update) a secret.
    /// `extra_agents` allows encrypting for specific agents beyond the group members.
    pub fn set_secret(
        &self,
        secret_path: &str,
        value: &str,
        group: &str,
        expires: Option<chrono::DateTime<chrono::Utc>>,
        extra_agents: Option<&[String]>,
    ) -> Result<(), VaultError> {
        identifiers::validate_secret_path(secret_path)?;
        identifiers::validate_group(group)?;
        if let Some(extras) = extra_agents {
            for agent_name in extras {
                identifiers::validate_agent(agent_name)?;
            }
        }

        let mut manifest = Manifest::load(&self.paths.manifest_file())?;

        // Ensure group exists and secret is registered
        manifest.add_secret_to_group(group, secret_path)?;

        // Collect authorized agents from group + extras
        let mut all_agents = manifest.agents_in_group(group);
        if let Some(extras) = extra_agents {
            for agent_name in extras {
                if !manifest.agents.iter().any(|a| a.name == *agent_name) {
                    return Err(VaultError::AgentNotFound(agent_name.clone()));
                }
                if !all_agents.contains(agent_name) {
                    all_agents.push(agent_name.clone());
                }
            }
        }

        // Collect recipients: owner + all agents
        let mut recipients = vec![];

        let owner_pub_str = keys::load_public_key(&self.paths.owner_pub_file())?;
        let owner_recipient = crypto::parse_recipient(&owner_pub_str)?;
        recipients.push(owner_recipient);

        for agent_name in &all_agents {
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
            existing.authorized_agents = all_agents.clone();
            existing
        } else {
            SecretMetadata::new(secret_path, group, all_agents.clone())
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
    pub fn get_secret(
        &self,
        secret_path: &str,
        key_path: &Path,
    ) -> Result<SecretString, VaultError> {
        let enc_path = self.encrypted_secret_path(secret_path)?;
        let private_key = keys::load_private_key(key_path)?;
        let identity = crypto::parse_identity(private_key.expose_secret())?;
        self.decrypt_secret_file(&enc_path, &identity)
    }

    /// Get a secret using private key material already held in memory.
    pub fn get_secret_with_key(
        &self,
        secret_path: &str,
        private_key: &SecretString,
    ) -> Result<SecretString, VaultError> {
        let enc_path = self.encrypted_secret_path(secret_path)?;
        let identity = crypto::parse_identity(private_key.expose_secret())?;
        self.decrypt_secret_file(&enc_path, &identity)
    }

    fn encrypted_secret_path(&self, secret_path: &str) -> Result<PathBuf, VaultError> {
        identifiers::validate_secret_path(secret_path)?;
        let enc_path = self.paths.secret_enc_file(secret_path);
        if !enc_path.exists() {
            return Err(VaultError::SecretNotFound(secret_path.to_string()));
        }
        Ok(enc_path)
    }

    fn decrypt_secret_file(
        &self,
        enc_path: &Path,
        identity: &age::x25519::Identity,
    ) -> Result<SecretString, VaultError> {
        let ciphertext = std::fs::read(enc_path)?;
        crypto::decrypt(&ciphertext, identity)
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
    pub fn list_secrets(
        &self,
        group_filter: Option<&str>,
    ) -> Result<Vec<SecretMetadata>, VaultError> {
        if let Some(group) = group_filter {
            identifiers::validate_group(group)?;
        }

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

            let mut enc_records = vec![];
            let mut meta_records = vec![];
            let group_dir = group_entry.path();
            discover_secret_records(
                &group_dir,
                &secrets_dir,
                &mut enc_records,
                &mut meta_records,
            )?;
            for (_, metadata_path) in meta_records {
                results.push(SecretMetadata::load(&metadata_path)?);
            }
        }
        results.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(results)
    }


    /// Read, decrypt, and prepare every affected record before lifecycle writes begin.
    fn prepare_re_encrypted_secrets(
        &self,
        secret_paths: &[String],
        manifest: &Manifest,
        replacement_public_key: Option<(&str, &str)>,
    ) -> Result<Vec<PreparedSecret>, VaultError> {
        let secret_paths: BTreeSet<_> = secret_paths.iter().cloned().collect();
        if secret_paths.is_empty() {
            return Ok(vec![]);
        }

        let owner_private = keys::load_private_key(&paths::owner_key_path())?;
        let owner_identity = crypto::parse_identity(owner_private.expose_secret())?;
        let owner_public = keys::load_public_key(&self.paths.owner_pub_file())?;
        let mut prepared = Vec::with_capacity(secret_paths.len());

        for secret_path in secret_paths {
            identifiers::validate_secret_path(&secret_path)?;
            let enc_path = self.paths.secret_enc_file(&secret_path);
            let plaintext = crypto::decrypt(&std::fs::read(&enc_path)?, &owner_identity)?;

            let authorized = manifest.authorized_agents_for_secret(&secret_path);
            let mut recipients = vec![crypto::parse_recipient(&owner_public)?];
            for agent_name in &authorized {
                let public_key = match replacement_public_key {
                    Some((replacement_name, public_key)) if agent_name == replacement_name => {
                        public_key.to_string()
                    }
                    _ => keys::load_public_key(&self.paths.agent_pub_file(agent_name))?,
                };
                recipients.push(crypto::parse_recipient(&public_key)?);
            }

            let meta_path = self.paths.secret_meta_file(&secret_path);
            let mut meta = SecretMetadata::load(&meta_path)?;
            meta.authorized_agents = authorized.clone();
            meta.rotated = chrono::Utc::now();
            let metadata = serde_yaml::to_string(&meta)?.into_bytes();
            prepared.push(PreparedSecret {
                enc_path,
                ciphertext: crypto::encrypt(plaintext.expose_secret().as_bytes(), &recipients)?,
                meta_path,
                metadata,
            });
        }
        Ok(prepared)
    }

    fn write_prepared_secrets(prepared: &[PreparedSecret]) -> Result<Vec<PathBuf>, VaultError> {
        let mut changed_files = Vec::with_capacity(prepared.len() * 2);
        for record in prepared {
            std::fs::write(&record.enc_path, &record.ciphertext)?;
            std::fs::write(&record.meta_path, &record.metadata)?;
            changed_files.push(record.enc_path.clone());
            changed_files.push(record.meta_path.clone());
        }
        Ok(changed_files)
    }

    fn sort_and_deduplicate_paths(paths: &mut Vec<PathBuf>) {
        paths.sort();
        paths.dedup();
    }

    /// Grant an agent access to a group. Re-encrypts all secrets in that group.
    pub fn grant_agent(
        &self,
        agent_name: &str,
        group_name: &str,
    ) -> Result<Vec<String>, VaultError> {
        identifiers::validate_agent(agent_name)?;
        identifiers::validate_group(group_name)?;
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        let secret_paths = manifest.secrets_in_group(group_name);
        manifest.grant(agent_name, group_name)?;
        let prepared = self.prepare_re_encrypted_secrets(&secret_paths, &manifest, None)?;

        // No lifecycle file has been written until every affected record is prepared.
        let mut changed_files = vec![self.paths.manifest_file()];
        changed_files.extend(Self::write_prepared_secrets(&prepared)?);
        manifest.save(&self.paths.manifest_file())?;
        Self::sort_and_deduplicate_paths(&mut changed_files);

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
    pub fn revoke_agent(
        &self,
        agent_name: &str,
        group_name: &str,
    ) -> Result<Vec<String>, VaultError> {
        identifiers::validate_agent(agent_name)?;
        identifiers::validate_group(group_name)?;
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        let secret_paths = manifest.secrets_in_group(group_name);
        manifest.revoke(agent_name, group_name)?;
        let prepared = self.prepare_re_encrypted_secrets(&secret_paths, &manifest, None)?;

        // No lifecycle file has been written until every affected record is prepared.
        let mut changed_files = vec![self.paths.manifest_file()];
        changed_files.extend(Self::write_prepared_secrets(&prepared)?);
        manifest.save(&self.paths.manifest_file())?;
        Self::sort_and_deduplicate_paths(&mut changed_files);

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
        identifiers::validate_agent(name)?;
        let mut manifest = Manifest::load(&self.paths.manifest_file())?;
        let groups = manifest
            .agent_groups(name)
            .ok_or_else(|| VaultError::AgentNotFound(name.to_string()))?;
        let all_secret_paths: Vec<_> = groups
            .iter()
            .flat_map(|group_name| manifest.secrets_in_group(group_name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        manifest.remove_agent(name)?;
        let prepared = self.prepare_re_encrypted_secrets(&all_secret_paths, &manifest, None)?;

        // No lifecycle file has been written until every affected record is prepared.
        let mut changed_files = vec![
            self.paths.manifest_file(),
            self.paths.agent_pub_file(name),
            self.paths.agent_escrow_file(name),
        ];
        changed_files.extend(Self::write_prepared_secrets(&prepared)?);
        manifest.save(&self.paths.manifest_file())?;
        Self::sort_and_deduplicate_paths(&mut changed_files);

        // Remove agent directory from disk before committing its tracked deletions.
        let agent_dir = self.paths.agent_dir(name);
        if agent_dir.exists() {
            std::fs::remove_dir_all(&agent_dir)?;
        }

        // Commit the manifest + re-encrypted secrets + agent-file deletions.
        let repo = git::open_repo(self.paths.root())?;
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
        identifiers::validate_agent(name)?;
        // Verify agent exists
        let escrow_path = self.paths.agent_escrow_file(name);
        if !escrow_path.exists() {
            return Err(VaultError::AgentNotFound(name.to_string()));
        }

        let manifest = Manifest::load(&self.paths.manifest_file())?;
        let agent_groups = manifest
            .agent_groups(name)
            .ok_or_else(|| VaultError::AgentNotFound(name.to_string()))?;

        // Generate replacement key material and prepare every output before any lifecycle write.
        let (new_secret, new_public) = crypto::generate_keypair();
        let owner_public = keys::load_public_key(&self.paths.owner_pub_file())?;
        let owner_recipient = crypto::parse_recipient(&owner_public)?;
        let new_escrow =
            crypto::encrypt(new_secret.expose_secret().as_bytes(), &[owner_recipient])?;
        let secret_paths: Vec<_> = agent_groups
            .iter()
            .flat_map(|group_name| manifest.secrets_in_group(group_name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let prepared = self.prepare_re_encrypted_secrets(
            &secret_paths,
            &manifest,
            Some((name, new_public.as_str())),
        )?;

        // All affected records and replacement key material preflighted successfully.
        let new_key_path = paths::agent_key_path(name);
        keys::save_private_key(&new_key_path, &new_secret)?;
        keys::save_public_key(&self.paths.agent_pub_file(name), &new_public)?;
        std::fs::write(self.paths.agent_escrow_file(name), new_escrow)?;

        let mut changed_files = vec![
            self.paths.agent_pub_file(name),
            self.paths.agent_escrow_file(name),
        ];
        changed_files.extend(Self::write_prepared_secrets(&prepared)?);
        Self::sort_and_deduplicate_paths(&mut changed_files);

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
        identifiers::validate_agent(name)?;
        let escrow_path = self.paths.agent_escrow_file(name);
        if !escrow_path.exists() {
            return Err(VaultError::AgentNotFound(name.to_string()));
        }

        let owner_key_path = paths::owner_key_path();
        let owner_private = keys::load_private_key(&owner_key_path)?;
        let agent_private = keys::recover_from_escrow(&escrow_path, &owner_private)?;

        keys::save_private_key(
            to_path,
            &SecretString::from(agent_private.expose_secret().to_string()),
        )?;

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

        // Recursively discover encrypted and metadata records. Secret paths may be nested below
        // their group directory, so treating only immediate children as records misses valid paths.
        let secrets_dir = self.paths.secrets_dir();
        let mut enc_records = vec![];
        let mut meta_records = vec![];
        if secrets_dir.exists() {
            discover_secret_records(
                &secrets_dir,
                &secrets_dir,
                &mut enc_records,
                &mut meta_records,
            )?;
        }
        let enc_paths: BTreeSet<_> = enc_records
            .iter()
            .map(|(secret_path, _)| secret_path.clone())
            .collect();
        let meta_paths: BTreeSet<_> = meta_records
            .iter()
            .map(|(secret_path, _)| secret_path.clone())
            .collect();
        let manifest_paths: BTreeSet<_> = manifest
            .groups
            .iter()
            .flat_map(|group| group.secrets.iter().cloned())
            .collect();

        // Every manifest entry needs a complete pair of records.
        for secret_path in &manifest_paths {
            if !enc_paths.contains(secret_path) {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' listed in manifest but .enc file missing"
                )));
            }
            if !meta_paths.contains(secret_path) {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' listed in manifest but .meta file missing"
                )));
            }
        }

        // Records not authorized by the manifest are retained as warnings for manual recovery.
        for secret_path in enc_paths.difference(&manifest_paths) {
            issues.push(CheckIssue::Warning(format!(
                "Orphaned .enc record: {secret_path}"
            )));
        }
        for secret_path in meta_paths.difference(&manifest_paths) {
            issues.push(CheckIssue::Warning(format!(
                "Orphaned .meta record: {secret_path}"
            )));
        }

        // Metadata is the readable record of the manifest relationship. Invalid metadata is an
        // integrity error, but it should not prevent check from reporting the remaining records.
        let mut metadata_for_expiry = vec![];
        for (secret_path, metadata_path) in meta_records {
            let metadata = match SecretMetadata::load(&metadata_path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    issues.push(CheckIssue::Error(format!(
                        "Invalid metadata for secret '{secret_path}': {error}"
                    )));
                    continue;
                }
            };
            metadata_for_expiry.push(metadata);

            if !manifest_paths.contains(&secret_path) {
                continue;
            }
            if metadata_for_expiry.last().unwrap().name != secret_path {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' metadata name does not match its path"
                )));
            }
            let metadata = metadata_for_expiry.last().unwrap();
            let group_contains_secret = manifest
                .groups
                .iter()
                .any(|group| group.name == metadata.group && group.secrets.contains(&secret_path));
            if !group_contains_secret {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' metadata group '{}' is not authorized by the manifest",
                    metadata.group
                )));
            }

            let expected_agents: BTreeSet<_> = manifest
                .authorized_agents_for_secret(&secret_path)
                .into_iter()
                .collect();
            let metadata_agents: BTreeSet<_> = metadata.authorized_agents.iter().cloned().collect();
            if !expected_agents.is_subset(&metadata_agents) {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' metadata authorized agents do not include all manifest-authorized agents"
                )));
            }
            let known_agents: BTreeSet<_> = manifest
                .agents
                .iter()
                .map(|agent| agent.name.clone())
                .collect();
            if !metadata_agents.is_subset(&known_agents) {
                issues.push(CheckIssue::Error(format!(
                    "Secret '{secret_path}' metadata authorized agents include agents absent from the manifest"
                )));
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
        let now = chrono::Utc::now();
        for meta in &metadata_for_expiry {
            if let Some(expires) = meta.expires {
                let days_until = (expires - now).num_days();
                if days_until < 0 {
                    issues.push(CheckIssue::Error(format!(
                        "Secret '{}' expired {} days ago",
                        meta.name, -days_until
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
    ///
    /// AGENT_VAULT_KEY supports both file paths and raw key strings
    /// (starting with `AGE-SECRET-KEY-`).
    pub fn resolve_identity_key(key_flag: Option<&str>) -> Result<IdentityKeySource, VaultError> {
        if let Some(k) = key_flag {
            let p = PathBuf::from(k);
            if p.exists() {
                return Ok(IdentityKeySource::File(p));
            }
            return Err(VaultError::NoIdentityKey);
        }

        if let Ok(env_key) = std::env::var("AGENT_VAULT_KEY") {
            let trimmed = env_key.trim();
            if trimmed.starts_with("AGE-SECRET-KEY-") {
                return Ok(IdentityKeySource::Raw(SecretString::from(
                    trimmed.to_string(),
                )));
            }

            let p = PathBuf::from(&env_key);
            if p.exists() {
                return Ok(IdentityKeySource::File(p));
            }
        }

        let owner_path = paths::owner_key_path();
        if owner_path.exists() {
            return Ok(IdentityKeySource::File(owner_path));
        }

        Err(VaultError::NoIdentityKey)
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "owner".to_string())
}
