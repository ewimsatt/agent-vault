use chrono::DateTime;
use secrecy::ExposeSecret;

use crate::core::vault::Vault;

pub fn run_set(
    path: &str,
    value: Option<&str>,
    from_file: Option<&str>,
    group: Option<&str>,
    expires: Option<&str>,
) -> anyhow::Result<()> {
    let secret_value = match (value, from_file) {
        (Some(v), None) => v.to_string(),
        (None, Some(f)) => std::fs::read_to_string(f)?,
        (None, None) => anyhow::bail!("provide a value or --from-file"),
        (Some(_), Some(_)) => anyhow::bail!("provide either a value or --from-file, not both"),
    };

    let expires_dt = match expires {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| anyhow::anyhow!("invalid --expires date (use ISO 8601): {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    // Default group is the first component of the path
    let group = group.unwrap_or_else(|| {
        path.split_once('/')
            .map(|(g, _)| g)
            .unwrap_or("default")
    });

    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    vault.set_secret(path, &secret_value, group, expires_dt)?;

    eprintln!("Secret '{path}' set in group '{group}'.");

    Ok(())
}

pub fn run_get(path: &str, key: Option<&str>) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;

    // Pull latest before decrypting
    vault.pull()?;

    let key_path = Vault::resolve_identity_key(key)?;
    let plaintext = vault.get_secret(path, &key_path)?;

    print!("{}", plaintext.expose_secret());

    Ok(())
}

pub fn run_list(group: Option<&str>) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let secrets = vault.list_secrets(group)?;

    if secrets.is_empty() {
        println!("No secrets found.");
        return Ok(());
    }

    for meta in &secrets {
        let expires_str = meta
            .expires
            .map(|e| format!("  expires={}", e.format("%Y-%m-%d")))
            .unwrap_or_default();
        println!(
            "{:<30} group={:<15} agents=[{}]  rotated={}{}",
            meta.name,
            meta.group,
            meta.authorized_agents.join(", "),
            meta.rotated.format("%Y-%m-%d"),
            expires_str,
        );
    }

    Ok(())
}
