use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::core::crypto;
use crate::error::VaultError;

/// Save a private key to a file with restricted permissions.
pub fn save_private_key(path: &Path, key: &SecretString) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key.expose_secret())?;
    set_permissions_600(path)?;
    Ok(())
}

/// Save a public key to a file.
pub fn save_public_key(path: &Path, key: &str) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key)?;
    Ok(())
}

/// Read a public key from a file.
pub fn load_public_key(path: &Path) -> Result<String, VaultError> {
    let key = std::fs::read_to_string(path)?.trim().to_string();
    Ok(key)
}

/// Read a private key from a file.
pub fn load_private_key(path: &Path) -> Result<SecretString, VaultError> {
    let key = std::fs::read_to_string(path)?.trim().to_string();
    Ok(SecretString::from(key))
}

/// Create an escrow file: encrypt the agent's private key with the owner's public key.
pub fn create_escrow(
    agent_private_key: &SecretString,
    owner_pub_key: &str,
    escrow_path: &Path,
) -> Result<(), VaultError> {
    let owner_recipient = crypto::parse_recipient(owner_pub_key)?;
    let encrypted = crypto::encrypt(agent_private_key.expose_secret().as_bytes(), &[owner_recipient])?;
    if let Some(parent) = escrow_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(escrow_path, encrypted)?;
    Ok(())
}

/// Recover an agent's private key from an escrow file using the owner's private key.
pub fn recover_from_escrow(
    escrow_path: &Path,
    owner_private_key: &SecretString,
) -> Result<SecretString, VaultError> {
    let ciphertext = std::fs::read(escrow_path)?;
    let identity = crypto::parse_identity(owner_private_key.expose_secret())?;
    crypto::decrypt(&ciphertext, &identity)
}

#[cfg(unix)]
fn set_permissions_600(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions_600(_path: &Path) -> Result<(), VaultError> {
    // On non-Unix, we can't set permissions the same way.
    Ok(())
}
