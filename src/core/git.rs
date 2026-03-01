use std::path::{Path, PathBuf};

use git2::{Repository, Signature};

use crate::error::VaultError;

/// Content for .agent-vault/.gitignore
pub fn gitignore_content() -> &'static str {
    "# agent-vault: block unencrypted key material\n\
     *.key\n\
     *.pem\n\
     **/private.*\n\
     !**/*.escrow\n"
}

/// Pre-commit hook script that blocks commits containing unencrypted age private keys.
pub fn pre_commit_hook_script() -> &'static str {
    r#"#!/bin/sh
# agent-vault pre-commit hook: block unencrypted private key material
if git diff --cached --diff-filter=ACM -z --name-only | \
   xargs -0 grep -l 'AGE-SECRET-KEY-' 2>/dev/null; then
    echo ""
    echo "ERROR: Commit blocked by agent-vault pre-commit hook."
    echo "Staged files contain unencrypted age private key material."
    echo "Remove the private key material before committing."
    exit 1
fi
exit 0
"#
}

/// Open an existing git repository at the given path.
pub fn open_repo(path: &Path) -> Result<Repository, VaultError> {
    let repo = Repository::discover(path)?;
    Ok(repo)
}

/// Stage files and create a commit.
pub fn commit_files(repo: &Repository, paths: &[PathBuf], message: &str) -> Result<(), VaultError> {
    let mut index = repo.index()?;

    let workdir = repo
        .workdir()
        .ok_or_else(|| VaultError::Git(git2::Error::from_str("bare repository")))?;

    // Canonicalize workdir to handle symlinks (e.g., /var -> /private/var on macOS)
    let workdir_canonical = workdir.canonicalize().unwrap_or_else(|_| workdir.to_path_buf());

    for path in paths {
        // Canonicalize the file path too, then strip the workdir prefix
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        let relative = canonical
            .strip_prefix(&workdir_canonical)
            .unwrap_or(&canonical);
        index.add_path(relative)?;
    }
    index.write()?;

    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;

    let sig = Signature::now("agent-vault", "agent-vault@localhost")?;

    // Check if there's a HEAD commit to use as parent
    let parent_commit = repo.head().ok().and_then(|head| head.peel_to_commit().ok());

    match parent_commit {
        Some(parent) => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])?;
        }
        None => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[])?;
        }
    };

    Ok(())
}

/// Remove a directory from the git index by its relative path within the vault.
/// `relative_path` should be relative to the repo root (e.g., ".agent-vault/agents/bot1").
pub fn remove_dir_from_index(repo: &Repository, relative_path: &Path) -> Result<(), VaultError> {
    let mut index = repo.index()?;
    index.remove_dir(relative_path, 0)?;
    index.write()?;
    Ok(())
}

/// Install the pre-commit hook in the repository's hooks directory.
pub fn install_pre_commit_hook(repo: &Repository) -> Result<(), VaultError> {
    let hooks_dir = repo.path().join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("pre-commit");

    // Don't overwrite an existing hook
    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path)?;
        if existing.contains("agent-vault") {
            return Ok(());
        }
        // Append to existing hook
        let combined = format!("{existing}\n{}", pre_commit_hook_script());
        std::fs::write(&hook_path, combined)?;
    } else {
        std::fs::write(&hook_path, pre_commit_hook_script())?;
    }

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}
