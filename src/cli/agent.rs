use crate::core::vault::Vault;

pub fn run_add(name: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let key_path = vault.add_agent(name)?;

    eprintln!("Agent '{name}' created.");
    eprintln!("Private key saved to: {}", key_path.display());
    eprintln!("The agent has no group access yet — use `agent-vault grant` to add access.");

    Ok(())
}

pub fn run_remove(name: &str) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let groups = vault.remove_agent(name)?;

    eprintln!("Agent '{name}' removed.");
    if !groups.is_empty() {
        eprintln!();
        eprintln!("WARNING: '{name}' previously had access to secrets in these groups:");
        for g in &groups {
            eprintln!("  - {g}");
        }
        eprintln!("Those secrets have been re-encrypted without '{name}'.");
        eprintln!("You should rotate them at the source, as '{name}' previously held decrypted copies.");
    }

    Ok(())
}

pub fn run_list() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let agents = vault.list_agents()?;

    if agents.is_empty() {
        println!("No agents configured.");
        return Ok(());
    }

    for (name, groups) in &agents {
        if groups.is_empty() {
            println!("{name}  (no groups)");
        } else {
            println!("{name}  [{}]", groups.join(", "));
        }
    }

    Ok(())
}
