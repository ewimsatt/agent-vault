use std::path::{Path, PathBuf};

/// All path resolution for vault directories and files.
pub struct VaultPaths {
    /// Root of the repository (where .agent-vault/ lives).
    root: PathBuf,
}

impl VaultPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `.agent-vault/`
    pub fn vault_dir(&self) -> PathBuf {
        self.root.join(".agent-vault")
    }

    /// `.agent-vault/config.yaml`
    pub fn config_file(&self) -> PathBuf {
        self.vault_dir().join("config.yaml")
    }

    /// `.agent-vault/owner.pub`
    pub fn owner_pub_file(&self) -> PathBuf {
        self.vault_dir().join("owner.pub")
    }

    /// `.agent-vault/manifest.yaml`
    pub fn manifest_file(&self) -> PathBuf {
        self.vault_dir().join("manifest.yaml")
    }

    /// `.agent-vault/.gitignore`
    pub fn gitignore_file(&self) -> PathBuf {
        self.vault_dir().join(".gitignore")
    }

    /// `.agent-vault/agents/`
    pub fn agents_dir(&self) -> PathBuf {
        self.vault_dir().join("agents")
    }

    /// `.agent-vault/agents/<name>/`
    pub fn agent_dir(&self, name: &str) -> PathBuf {
        self.agents_dir().join(name)
    }

    /// `.agent-vault/agents/<name>/public.key`
    pub fn agent_pub_file(&self, name: &str) -> PathBuf {
        self.agent_dir(name).join("public.key")
    }

    /// `.agent-vault/agents/<name>/private.key.escrow`
    pub fn agent_escrow_file(&self, name: &str) -> PathBuf {
        self.agent_dir(name).join("private.key.escrow")
    }

    /// `.agent-vault/secrets/`
    pub fn secrets_dir(&self) -> PathBuf {
        self.vault_dir().join("secrets")
    }

    /// `.agent-vault/secrets/<group>/<name>.enc`
    pub fn secret_enc_file(&self, path: &str) -> PathBuf {
        let (group, name) = split_secret_path(path);
        self.secrets_dir().join(group).join(format!("{name}.enc"))
    }

    /// `.agent-vault/secrets/<group>/<name>.meta`
    pub fn secret_meta_file(&self, path: &str) -> PathBuf {
        let (group, name) = split_secret_path(path);
        self.secrets_dir().join(group).join(format!("{name}.meta"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// `~/.agent-vault/owner.key`
pub fn owner_key_path() -> PathBuf {
    home_vault_dir().join("owner.key")
}

/// `~/.agent-vault/agents/<name>.key`
pub fn agent_key_path(name: &str) -> PathBuf {
    home_vault_dir().join("agents").join(format!("{name}.key"))
}

/// `~/.agent-vault/`
pub fn home_vault_dir() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".agent-vault")
}

/// Split `group/secret-name` into `("group", "secret-name")`.
/// If no slash, treat the whole thing as the name under a "default" group.
fn split_secret_path(path: &str) -> (&str, &str) {
    match path.split_once('/') {
        Some((group, name)) => (group, name),
        None => ("default", path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_secret_path() {
        assert_eq!(split_secret_path("stripe/api-key"), ("stripe", "api-key"));
        assert_eq!(split_secret_path("my-secret"), ("default", "my-secret"));
    }

    #[test]
    fn test_vault_paths() {
        let paths = VaultPaths::new("/tmp/repo");
        assert_eq!(paths.vault_dir(), PathBuf::from("/tmp/repo/.agent-vault"));
        assert_eq!(
            paths.secret_enc_file("stripe/api-key"),
            PathBuf::from("/tmp/repo/.agent-vault/secrets/stripe/api-key.enc")
        );
    }
}
