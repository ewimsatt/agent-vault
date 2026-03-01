use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::VaultError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub encryption: EncryptionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub format: String,
}

impl Config {
    pub fn new() -> Self {
        Self {
            version: 1,
            encryption: EncryptionConfig {
                format: "age".to_string(),
            },
        }
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}
