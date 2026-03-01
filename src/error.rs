use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault already initialized in {0}")]
    AlreadyInitialized(String),

    #[error("vault not found — run `agent-vault init` first")]
    NotInitialized,

    #[error("agent '{0}' already exists")]
    AgentExists(String),

    #[error("agent '{0}' not found")]
    AgentNotFound(String),

    #[error("secret '{0}' not found")]
    SecretNotFound(String),

    #[error("group '{0}' not found in manifest")]
    GroupNotFound(String),

    #[error("owner key not found — checked {0}")]
    OwnerKeyNotFound(String),

    #[error("no identity key found — use --key or set AGENT_VAULT_KEY")]
    NoIdentityKey,

    #[error("decryption failed — key may not be authorized for this secret")]
    DecryptionFailed,

    #[error("not yet implemented: {0}")]
    NotImplemented(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("git error: {0}")]
    Git(#[from] git2::Error),

    #[error("age encryption error: {0}")]
    AgeEncrypt(String),

    #[error("age decryption error: {0}")]
    AgeDecrypt(String),

    #[error("age key error: {0}")]
    AgeKey(String),
}
