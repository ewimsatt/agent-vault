use std::path::PathBuf;

use crate::core::vault::Vault;

pub fn run_recover(name: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let new_key_path = vault.recover_agent(name)?;

    eprintln!("Agent '{name}' recovered with new keypair.");
    eprintln!("New private key saved to: {}", new_key_path.display());
    eprintln!("All secrets have been re-encrypted for the new key.");

    Ok(())
}

pub fn run_restore(name: &str, to_path: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    vault.restore_agent(name, &PathBuf::from(to_path))?;

    eprintln!("Agent '{name}' private key restored to: {to_path}");

    Ok(())
}
