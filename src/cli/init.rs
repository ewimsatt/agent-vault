use std::path::PathBuf;

use crate::core::vault::Vault;

pub fn run(directory: Option<String>) -> anyhow::Result<()> {
    let root = match directory {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir()?,
    };

    let _vault = Vault::init(&root)?;

    eprintln!("Vault initialized in {}", root.display());
    eprintln!();
    eprintln!("WARNING: Your owner key has been saved to ~/.agent-vault/owner.key");
    eprintln!("This is the master recovery key for the vault. Back it up securely.");
    eprintln!("If lost, all secrets become unrecoverable.");

    Ok(())
}
