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
    let _root = std::env::current_dir()?;
    anyhow::bail!("not yet implemented: remove-agent '{name}'")
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
