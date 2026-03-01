use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::VaultError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub name: String,
    pub group: String,
    pub created: DateTime<Utc>,
    pub rotated: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub authorized_agents: Vec<String>,
}

impl SecretMetadata {
    pub fn new(name: &str, group: &str, authorized_agents: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            name: name.to_string(),
            group: group.to_string(),
            created: now,
            rotated: now,
            expires: None,
            authorized_agents,
        }
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let contents = std::fs::read_to_string(path)?;
        let meta: SecretMetadata = serde_yaml::from_str(&contents)?;
        Ok(meta)
    }

    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}
