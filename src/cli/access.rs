use crate::core::vault::Vault;

pub fn run_grant(agent: &str, group: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let secrets = vault.grant_agent(agent, group)?;

    eprintln!("Granted '{agent}' access to group '{group}'.");
    if !secrets.is_empty() {
        eprintln!("Re-encrypted {} secret(s).", secrets.len());
    }

    Ok(())
}

pub fn run_revoke(agent: &str, group: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let secrets = vault.revoke_agent(agent, group)?;

    eprintln!("Revoked '{agent}' access to group '{group}'.");
    if !secrets.is_empty() {
        eprintln!("Re-encrypted {} secret(s).", secrets.len());
        eprintln!();
        eprintln!("WARNING: '{agent}' previously had access to these secrets.");
        eprintln!("You should rotate them at the source:");
        for s in &secrets {
            eprintln!("  - {s}");
        }
    }

    Ok(())
}
