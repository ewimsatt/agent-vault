use crate::core::vault::{CheckIssue, Vault};

pub fn run() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let vault = Vault::open(&root)?;
    let issues = vault.check()?;

    if issues.is_empty() {
        println!("No issues found. Vault is healthy.");
        return Ok(());
    }

    let mut errors = 0;
    let mut warnings = 0;

    for issue in &issues {
        match issue {
            CheckIssue::Error(msg) => {
                println!("ERROR: {msg}");
                errors += 1;
            }
            CheckIssue::Warning(msg) => {
                println!("WARNING: {msg}");
                warnings += 1;
            }
        }
    }

    println!();
    println!("{errors} error(s), {warnings} warning(s).");

    if errors > 0 {
        std::process::exit(1);
    }

    Ok(())
}
