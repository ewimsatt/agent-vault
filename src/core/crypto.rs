use std::io::{Read, Write};

use secrecy::{ExposeSecret, SecretString};

use crate::error::VaultError;

/// Generate a new age X25519 keypair. Returns (secret_key_string, public_key_string).
pub fn generate_keypair() -> (SecretString, String) {
    let identity = age::x25519::Identity::generate();
    let secret = identity.to_string();
    let public = identity.to_public().to_string();
    (SecretString::from(secret.expose_secret().to_string()), public)
}

/// Parse an age identity (private key) from its string representation.
pub fn parse_identity(key_str: &str) -> Result<age::x25519::Identity, VaultError> {
    key_str
        .parse::<age::x25519::Identity>()
        .map_err(|e| VaultError::AgeKey(e.to_string()))
}

/// Parse an age recipient (public key) from its string representation.
pub fn parse_recipient(key_str: &str) -> Result<age::x25519::Recipient, VaultError> {
    key_str
        .parse::<age::x25519::Recipient>()
        .map_err(|e| VaultError::AgeKey(e.to_string()))
}

/// Encrypt plaintext for multiple recipients. Returns the encrypted bytes.
pub fn encrypt(plaintext: &[u8], recipients: &[age::x25519::Recipient]) -> Result<Vec<u8>, VaultError> {
    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r as &dyn age::Recipient),
    )
    .map_err(|e| VaultError::AgeEncrypt(e.to_string()))?;

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| VaultError::AgeEncrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| VaultError::AgeEncrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| VaultError::AgeEncrypt(e.to_string()))?;

    Ok(encrypted)
}

/// Decrypt ciphertext using an identity. Returns the plaintext as a SecretString.
pub fn decrypt(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<SecretString, VaultError> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| VaultError::AgeDecrypt(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| VaultError::AgeDecrypt(e.to_string()))?;

    let mut plaintext = String::new();
    reader
        .read_to_string(&mut plaintext)
        .map_err(|e| VaultError::AgeDecrypt(e.to_string()))?;

    Ok(SecretString::from(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let (secret, public) = generate_keypair();
        let recipient = parse_recipient(&public).unwrap();
        let identity = parse_identity(secret.expose_secret()).unwrap();

        let plaintext = b"hello world";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert_eq!(decrypted.expose_secret(), "hello world");
    }

    #[test]
    fn test_multi_recipient() {
        let (secret1, public1) = generate_keypair();
        let (secret2, public2) = generate_keypair();
        let r1 = parse_recipient(&public1).unwrap();
        let r2 = parse_recipient(&public2).unwrap();
        let id1 = parse_identity(secret1.expose_secret()).unwrap();
        let id2 = parse_identity(secret2.expose_secret()).unwrap();

        let ciphertext = encrypt(b"multi", &[r1, r2]).unwrap();
        assert_eq!(decrypt(&ciphertext, &id1).unwrap().expose_secret(), "multi");
        assert_eq!(decrypt(&ciphertext, &id2).unwrap().expose_secret(), "multi");
    }
}
