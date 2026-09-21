use std::path::{Path, PathBuf};
use std::process::Command;

use git2::Repository;

use crate::error::VaultError;

/// Content for .agent-vault/.gitignore
pub fn gitignore_content() -> &'static str {
    "# agent-vault: block unencrypted key material\n\
     *.key\n\
     *.pem\n\
     **/private.*\n\
     !**/*.escrow\n"
}

/// Pre-commit hook script that blocks commits containing unencrypted private key material.
pub fn pre_commit_hook_script() -> &'static str {
    r#"#!/bin/sh
# agent-vault pre-commit hook: block unencrypted private key material
PATTERNS='AGE-SECRET-KEY-\|-----BEGIN PRIVATE KEY-----\|-----BEGIN RSA PRIVATE KEY-----\|-----BEGIN EC PRIVATE KEY-----\|-----BEGIN OPENSSH PRIVATE KEY-----'

if git diff --cached --diff-filter=ACM -z --name-only | \
   xargs -0 grep -l "$PATTERNS" 2>/dev/null; then
    echo ""
    echo "ERROR: Commit blocked by agent-vault pre-commit hook."
    echo "Staged files contain unencrypted private key material."
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

/// Commit only the supplied paths, preserving the caller's index and running the pre-commit hook.
pub fn commit_files(repo: &Repository, paths: &[PathBuf], message: &str) -> Result<(), VaultError> {
    if paths.is_empty() {
        return Err(VaultError::Git(git2::Error::from_str(
            "refusing to create a commit with no explicit paths",
        )));
    }

    let workdir = repo
        .workdir()
        .ok_or_else(|| VaultError::Git(git2::Error::from_str("bare repository")))?;
    let workdir_canonical = workdir
        .canonicalize()
        .unwrap_or_else(|_| workdir.to_path_buf());

    let mut relative_paths = Vec::with_capacity(paths.len());
    for path in paths {
        let canonical = canonicalize_existing_ancestor(path)?;
        let relative = canonical.strip_prefix(&workdir_canonical).map_err(|_| {
            VaultError::Git(git2::Error::from_str(
                "commit path is outside the repository worktree",
            ))
        })?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(VaultError::Git(git2::Error::from_str(
                "commit path must be repository-relative",
            )));
        }
        relative_paths.push(relative.to_path_buf());
    }

    // Build an isolated index so unrelated staged work can neither enter this commit nor be changed.
    let index_dir = tempfile::tempdir()?;
    let index_path = index_dir.path().join("index");
    let git_command = |args: &[&str]| {
        Command::new("git")
            .current_dir(workdir)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_PREFIX")
            .env("GIT_INDEX_FILE", &index_path)
            .args(args)
            .output()
    };

    let read_tree_args = if repo.head().is_ok() {
        vec!["read-tree", "HEAD"]
    } else {
        vec!["read-tree", "--empty"]
    };
    let output = git_command(&read_tree_args)?;
    if !output.status.success() {
        return Err(git_command_error("prepare isolated index", &output));
    }

    let path_args: Vec<&str> = relative_paths
        .iter()
        .map(|path| {
            path.to_str().ok_or_else(|| {
                VaultError::Git(git2::Error::from_str("commit path is not valid UTF-8"))
            })
        })
        .collect::<Result<_, _>>()?;
    let mut add_args = vec!["add", "--all", "--force", "--"];
    add_args.extend(path_args.iter().copied());
    let output = git_command(&add_args)?;
    if !output.status.success() {
        return Err(git_command_error("stage isolated commit paths", &output));
    }

    let output = git_command(&["hook", "run", "pre-commit"])?;
    if !output.status.success() {
        return Err(git_command_error("run pre-commit hook", &output));
    }

    let output = git_command(&["diff", "--cached", "--name-only"])?;
    if !output.status.success() {
        return Err(git_command_error(
            "inspect pre-commit hook changes",
            &output,
        ));
    }
    for changed_path in String::from_utf8_lossy(&output.stdout).lines() {
        if !relative_paths
            .iter()
            .any(|path| path == Path::new(changed_path))
        {
            return Err(VaultError::Git(git2::Error::from_str(
                "pre-commit hook staged a path outside this vault operation",
            )));
        }
    }

    let commit_args = vec![
        "-c",
        "user.name=agent-vault",
        "-c",
        "user.email=agent-vault@localhost",
        "commit",
        "--no-verify",
        "-m",
        message,
    ];
    let output = git_command(&commit_args)?;
    if !output.status.success() {
        return Err(git_command_error("commit isolated paths", &output));
    }

    Ok(())
}

fn canonicalize_existing_ancestor(path: &Path) -> Result<PathBuf, VaultError> {
    let mut missing = Vec::new();
    let mut ancestor = path;
    while !ancestor.exists() {
        let name = ancestor.file_name().ok_or_else(|| {
            VaultError::Git(git2::Error::from_str(
                "commit path has no existing ancestor",
            ))
        })?;
        missing.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            VaultError::Git(git2::Error::from_str(
                "commit path has no existing ancestor",
            ))
        })?;
    }

    let mut canonical = ancestor.canonicalize()?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn git_command_error(action: &str, output: &std::process::Output) -> VaultError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    VaultError::Git(git2::Error::from_str(&format!(
        "git {action} failed: {stderr}{stdout}"
    )))
}

/// Pull latest from the remote (if one exists). Best-effort; silently skips if no remote.
pub fn pull(repo: &Repository) -> Result<(), VaultError> {
    // Only pull if there's a remote named "origin"
    let remote = match repo.find_remote("origin") {
        Ok(r) => r,
        Err(_) => return Ok(()), // no remote, skip
    };
    let remote_name = remote.name().unwrap_or("origin").to_string();
    drop(remote);

    // Refuse to touch a repository with local work. This is intentionally stricter than
    // a normal Git pull: the CLI invokes this automatically before reading a secret.
    let mut status_options = git2::StatusOptions::new();
    status_options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_unmodified(false);
    if !repo.statuses(Some(&mut status_options))?.is_empty() {
        return Err(VaultError::Git(git2::Error::from_str(
            "refusing to pull into a repository with local changes or untracked files",
        )));
    }

    // Fetch only after confirming the local worktree and index are clean.
    let mut remote = repo.find_remote(&remote_name)?;
    remote.fetch(&[] as &[&str], None, None)?;

    // Try to fast-forward merge the current branch
    let fetch_head = match repo.find_reference("FETCH_HEAD") {
        Ok(r) => r,
        Err(_) => return Ok(()), // no FETCH_HEAD (empty remote)
    };
    let fetch_commit = repo.reference_to_annotated_commit(&fetch_head)?;

    let (analysis, _) = repo.merge_analysis(&[&fetch_commit])?;
    if analysis.is_fast_forward() {
        if let Ok(mut head_ref) = repo.head() {
            let commit = repo.find_commit(fetch_commit.id())?;
            let mut checkout = git2::build::CheckoutBuilder::default();
            // A safe checkout runs before moving HEAD, so checkout failure cannot advance it.
            repo.checkout_tree(commit.as_object(), Some(&mut checkout))?;
            let msg = format!("Fast-forward to {}", fetch_commit.id());
            head_ref.set_target(fetch_commit.id(), &msg)?;
        }
    }
    // If not fast-forward or up-to-date, do nothing (don't attempt merge)

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

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature};
    use tempfile::TempDir;

    fn commit_file(repo: &Repository, path: &str, content: &str, message: &str) -> Oid {
        let workdir = repo.workdir().unwrap();
        let file_path = workdir.join(path);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&file_path, content).unwrap();

        let mut index = repo.index().unwrap();
        index.add_path(Path::new(path)).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("agent-vault test", "test@agent-vault.invalid").unwrap();
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        let parents: Vec<&git2::Commit<'_>> = parent.iter().collect();

        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .unwrap()
    }

    fn push_master(repo: &Repository) {
        repo.find_remote("origin")
            .unwrap()
            .push(&["refs/heads/master:refs/heads/master"], None)
            .unwrap();
    }

    fn cloned_repo_with_origin() -> (TempDir, TempDir, TempDir, Repository, Repository) {
        let bare_dir = tempfile::tempdir().unwrap();
        Repository::init_bare(bare_dir.path()).unwrap();

        let seed_dir = tempfile::tempdir().unwrap();
        let seed = Repository::init(seed_dir.path()).unwrap();
        seed.remote("origin", bare_dir.path().to_str().unwrap())
            .unwrap();
        commit_file(&seed, "tracked.txt", "base\n", "initial commit");
        push_master(&seed);

        let local_dir = tempfile::tempdir().unwrap();
        let local = Repository::clone(bare_dir.path().to_str().unwrap(), local_dir.path()).unwrap();
        (bare_dir, seed_dir, local_dir, seed, local)
    }

    #[test]
    fn test_pre_commit_hook_contains_all_patterns() {
        let script = pre_commit_hook_script();
        assert!(script.contains("AGE-SECRET-KEY-"));
        assert!(script.contains("BEGIN PRIVATE KEY"));
        assert!(script.contains("BEGIN RSA PRIVATE KEY"));
        assert!(script.contains("BEGIN EC PRIVATE KEY"));
        assert!(script.contains("BEGIN OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn pull_fast_forwards_clean_clone() {
        let (_bare_dir, _seed_dir, local_dir, seed, local) = cloned_repo_with_origin();
        let remote_commit = commit_file(&seed, "remote.txt", "from remote\n", "remote update");
        push_master(&seed);

        pull(&local).unwrap();

        assert_eq!(local.head().unwrap().target(), Some(remote_commit));
        assert_eq!(
            std::fs::read_to_string(local_dir.path().join("remote.txt")).unwrap(),
            "from remote\n"
        );
    }

    #[test]
    fn pull_rejects_dirty_repository_without_changing_head_index_or_worktree() {
        let (_bare_dir, _seed_dir, local_dir, seed, local) = cloned_repo_with_origin();
        commit_file(&seed, "remote.txt", "from remote\n", "remote update");
        push_master(&seed);
        let original_head = local.head().unwrap().target();

        std::fs::write(
            local_dir.path().join("tracked.txt"),
            "staged local content\n",
        )
        .unwrap();
        let mut index = local.index().unwrap();
        index.add_path(Path::new("tracked.txt")).unwrap();
        index.write().unwrap();
        std::fs::write(
            local_dir.path().join("tracked.txt"),
            "unstaged local content\n",
        )
        .unwrap();

        assert!(pull(&local).is_err());

        assert_eq!(local.head().unwrap().target(), original_head);
        let index = local.index().unwrap();
        let staged = index.get_path(Path::new("tracked.txt"), 0).unwrap();
        assert_eq!(
            local.find_blob(staged.id).unwrap().content(),
            b"staged local content\n"
        );
        assert_eq!(
            std::fs::read_to_string(local_dir.path().join("tracked.txt")).unwrap(),
            "unstaged local content\n"
        );
    }

    #[test]
    fn pull_rejects_untracked_file_collision_without_advancing_head() {
        let (_bare_dir, _seed_dir, local_dir, seed, local) = cloned_repo_with_origin();
        let remote_commit =
            commit_file(&seed, "collision.txt", "remote content\n", "remote update");
        push_master(&seed);
        let original_head = local.head().unwrap().target();
        std::fs::write(
            local_dir.path().join("collision.txt"),
            "local untracked content\n",
        )
        .unwrap();

        assert!(pull(&local).is_err());

        assert_eq!(local.head().unwrap().target(), original_head);
        assert_ne!(local.head().unwrap().target(), Some(remote_commit));
        assert_eq!(
            std::fs::read_to_string(local_dir.path().join("collision.txt")).unwrap(),
            "local untracked content\n"
        );
    }

    #[test]
    fn pull_without_origin_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        pull(&repo).unwrap();
    }

    #[test]
    fn pull_leaves_non_fast_forward_branch_unchanged() {
        let (_bare_dir, _seed_dir, local_dir, seed, local) = cloned_repo_with_origin();
        let original_head = commit_file(&local, "local.txt", "local commit\n", "local update");
        commit_file(&seed, "remote.txt", "remote commit\n", "remote update");
        push_master(&seed);

        pull(&local).unwrap();

        assert_eq!(local.head().unwrap().target(), Some(original_head));
        assert!(!local_dir.path().join("remote.txt").exists());
    }
}
