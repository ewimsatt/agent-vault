use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
# agent-vault-managed-pre-commit-v1
scan_staged_index() {
if git grep --cached -a -q -F \
    -e 'AGE-SECRET-KEY-' \
    -e '-----BEGIN PRIVATE KEY-----' \
    -e '-----BEGIN RSA PRIVATE KEY-----' \
    -e '-----BEGIN EC PRIVATE KEY-----' \
    -e '-----BEGIN OPENSSH PRIVATE KEY-----' --
then
    return 1
else
    scan_status=$?
fi

case "$scan_status" in
    1) return 0 ;;
    *) return 2 ;;
esac
}

reject_scan() {
    echo "ERROR: Commit blocked by agent-vault pre-commit hook."
    echo "Staged files contain unencrypted private key material or could not be scanned."
    echo "Remove the private key material before committing."
    exit 1
}

scan_staged_index
case $? in
    0) ;;
    *) reject_scan ;;
esac

sidecar="${0}.agent-vault-original-v1"
sidecar_status=0
if [ -f "$sidecar" ]; then
    "$sidecar"
    sidecar_status=$?
fi

scan_staged_index
case $? in
    0) exit "$sidecar_status" ;;
    *) reject_scan ;;
esac
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

const PRE_COMMIT_SIDECAR: &str = "pre-commit.agent-vault-original-v1";
const PRE_COMMIT_INSTALL_LOCK: &str = "pre-commit.agent-vault-install-v1.lock";

/// Install a versioned dispatcher in Git's effective pre-commit hook path.
pub fn install_pre_commit_hook(repo: &Repository) -> Result<(), VaultError> {
    let hook_path = effective_hook_path(repo)?;
    let hooks_dir = hook_path
        .parent()
        .ok_or_else(|| hook_error("hook path has no parent"))?;
    fs::create_dir_all(hooks_dir)?;
    let _lock = acquire_install_lock(hooks_dir)?;
    let sidecar_path = hooks_dir.join(PRE_COMMIT_SIDECAR);
    let hook_metadata = checked_regular_executable(&hook_path, "pre-commit hook")?;
    let sidecar_metadata = checked_regular_executable(&sidecar_path, "pre-commit sidecar")?;

    if let Some(hook_metadata) = hook_metadata {
        let existing = fs::read(&hook_path)?;
        if existing == pre_commit_hook_script().as_bytes() {
            if sidecar_metadata.is_some() || !sidecar_path.exists() {
                return Ok(());
            }
        }
        if existing
            .windows(b"agent-vault".len())
            .any(|part| part == b"agent-vault")
        {
            return Err(hook_error(
                "refusing ambiguous legacy agent-vault pre-commit hook",
            ));
        }
        if sidecar_metadata.is_some() {
            return Err(hook_error("refusing occupied pre-commit sidecar"));
        }
        let permissions = hook_metadata.permissions();
        write_new_file(&sidecar_path, &existing, permissions.clone())?;
        verify_hook_unchanged(&hook_path, &existing, &permissions)?;
    } else if sidecar_metadata.is_some() {
        return Err(hook_error("refusing occupied pre-commit sidecar"));
    } else if fs::symlink_metadata(&hook_path).is_ok() {
        return Err(hook_error("pre-commit hook changed during installation"));
    }

    write_wrapper_atomically(&hook_path, pre_commit_hook_script().as_bytes())
}

struct InstallLock(PathBuf);

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn acquire_install_lock(hooks_dir: &Path) -> Result<InstallLock, VaultError> {
    let lock_path = hooks_dir.join(PRE_COMMIT_INSTALL_LOCK);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| {
            hook_error(&format!(
                "refusing concurrent pre-commit hook installation: {error}"
            ))
        })?;
    Ok(InstallLock(lock_path))
}

fn verify_hook_unchanged(
    path: &Path,
    expected_bytes: &[u8],
    expected_permissions: &fs::Permissions,
) -> Result<(), VaultError> {
    let metadata = checked_regular_executable(path, "pre-commit hook")?
        .ok_or_else(|| hook_error("pre-commit hook disappeared during installation"))?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != expected_permissions.mode() & 0o7777 {
        return Err(hook_error(
            "pre-commit hook mode changed during installation",
        ));
    }
    if fs::read(path)? != expected_bytes {
        return Err(hook_error("pre-commit hook changed during installation"));
    }
    Ok(())
}

fn effective_hook_path(repo: &Repository) -> Result<PathBuf, VaultError> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| VaultError::Git(git2::Error::from_str("bare repository")))?;
    let output = Command::new("git")
        .current_dir(workdir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_PREFIX")
        .args(["rev-parse", "--git-path", "hooks/pre-commit"])
        .output()?;
    if !output.status.success() {
        return Err(git_command_error(
            "resolve effective pre-commit hook path",
            &output,
        ));
    }
    let mut path_bytes = output.stdout;
    if path_bytes.pop() != Some(b'\n') {
        return Err(hook_error("Git returned a malformed pre-commit hook path"));
    }
    if path_bytes.last() == Some(&b'\r') {
        path_bytes.pop();
    }
    if path_bytes.is_empty() {
        return Err(hook_error("Git returned an empty pre-commit hook path"));
    }
    #[cfg(unix)]
    let path = PathBuf::from(std::ffi::OsString::from_vec(path_bytes));
    #[cfg(not(unix))]
    let path = PathBuf::from(
        String::from_utf8(path_bytes)
            .map_err(|_| hook_error("Git returned a non-UTF-8 pre-commit hook path"))?,
    );
    Ok(if path.is_absolute() {
        path
    } else {
        workdir.join(path)
    })
}

fn checked_regular_executable(
    path: &Path,
    label: &str,
) -> Result<Option<fs::Metadata>, VaultError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(hook_error(&format!("refusing non-regular {label}")));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(hook_error(&format!("refusing non-executable {label}")));
    }
    Ok(Some(metadata))
}

fn write_new_file(
    path: &Path,
    bytes: &[u8],
    permissions: fs::Permissions,
) -> Result<(), VaultError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(permissions)?;
    file.sync_all()?;
    Ok(())
}

fn write_wrapper_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .ok_or_else(|| hook_error("hook path has no parent"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".agent-vault-pre-commit-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn hook_error(message: &str) -> VaultError {
    std::io::Error::other(message).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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
    fn installed_hook_ignores_unstaged_marker_when_staged_blob_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let path = dir.path().join("note.txt");
        std::fs::write(&path, "safe staged content\n").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("note.txt")).unwrap();
        index.write().unwrap();
        std::fs::write(&path, "AGE-SECRET-KEY-SYNTHETIC-UNSTAGED\n").unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(repo.path().join("hooks/pre-commit"))
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "hook rejected safe staged content: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn installed_hook_rejects_binary_staged_marker() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let marker = dir.path().join("marker.bin");
        std::fs::write(&marker, b"\0\xffAGE-SECRET-KEY-SYNTHETIC-BINARY\0").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("marker.bin")).unwrap();
        index.write().unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(repo.path().join("hooks/pre-commit"))
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "binary staged marker bypassed the hook"
        );
    }

    #[test]
    fn installed_hook_scans_before_an_early_exit_custom_hook() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let hook = repo.path().join("hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        std::fs::write(
            dir.path().join("marker.txt"),
            "AGE-SECRET-KEY-SYNTHETIC-STAGED\n",
        )
        .unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("marker.txt")).unwrap();
        index.write().unwrap();
        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(&hook)
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert!(!output.status.success(), "staged marker bypassed the hook");
        let sidecar = hook.parent().unwrap().join(PRE_COMMIT_SIDECAR);
        assert_eq!(std::fs::read(&sidecar).unwrap(), b"#!/bin/sh\nexit 0\n");
        assert_ne!(
            std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o111,
            0
        );
    }

    #[test]
    fn installed_hook_rejects_marker_staged_by_preserved_hook() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let hook = repo.path().join("hooks/pre-commit");
        std::fs::write(
            &hook,
            "#!/bin/sh\nprintf '%s\\n' AGE-SECRET-KEY-SYNTHETIC-LATE > late.txt\ngit add late.txt\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(&hook)
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "marker staged by preserved hook bypassed final scan"
        );
    }

    #[test]
    fn installed_hook_uses_absolute_core_hooks_path() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        repo.config()
            .unwrap()
            .set_str("core.hooksPath", hooks.path().to_str().unwrap())
            .unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let hook = hooks.path().join("pre-commit");
        assert!(hook.is_file());
        assert!(!repo.path().join("hooks/pre-commit").exists());
    }

    #[test]
    fn installed_hook_preserves_leading_whitespace_in_relative_core_hooks_path() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        repo.config()
            .unwrap()
            .set_str("core.hooksPath", " custom-hooks")
            .unwrap();

        install_pre_commit_hook(&repo).unwrap();

        assert!(dir.path().join(" custom-hooks/pre-commit").is_file());
        assert!(!dir.path().join("custom-hooks/pre-commit").exists());
    }

    #[test]
    fn wrapper_runs_sidecar_from_hooks_path_ending_in_newline() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        repo.config()
            .unwrap()
            .set_str("core.hooksPath", "custom-hooks\n")
            .unwrap();
        let hook = dir.path().join("custom-hooks\n/pre-commit");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, "#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(&hook)
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(7));
    }

    #[test]
    fn occupied_install_lock_refuses_to_change_hook_state() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let hooks_dir = repo.path().join("hooks");
        std::fs::write(hooks_dir.join(PRE_COMMIT_INSTALL_LOCK), b"synthetic lock").unwrap();

        assert!(install_pre_commit_hook(&repo).is_err());
        assert!(!hooks_dir.join("pre-commit").exists());
        assert_eq!(
            std::fs::read(hooks_dir.join(PRE_COMMIT_INSTALL_LOCK)).unwrap(),
            b"synthetic lock"
        );
    }

    #[test]
    fn unsafe_hook_or_sidecar_leaves_existing_bytes_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let hook = repo.path().join("hooks/pre-commit");
        let target = dir.path().join("hook-target");
        std::fs::write(&target, b"synthetic hook bytes").unwrap();
        std::os::unix::fs::symlink(&target, &hook).unwrap();

        assert!(install_pre_commit_hook(&repo).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"synthetic hook bytes");

        std::fs::remove_file(&hook).unwrap();
        let sidecar = hook.parent().unwrap().join(PRE_COMMIT_SIDECAR);
        std::fs::write(&sidecar, b"occupied synthetic sidecar").unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(install_pre_commit_hook(&repo).is_err());
        assert_eq!(
            std::fs::read(&sidecar).unwrap(),
            b"occupied synthetic sidecar"
        );
        assert!(!hook.exists());
    }

    #[test]
    fn installed_hook_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        install_pre_commit_hook(&repo).unwrap();
        let hook = repo.path().join("hooks/pre-commit");
        let first = std::fs::read(&hook).unwrap();

        install_pre_commit_hook(&repo).unwrap();

        assert_eq!(std::fs::read(&hook).unwrap(), first);
        assert!(!hook.parent().unwrap().join(PRE_COMMIT_SIDECAR).exists());
    }

    #[test]
    fn preserved_hook_failure_status_propagates_after_clean_final_scan() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let hook = repo.path().join("hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        install_pre_commit_hook(&repo).unwrap();
        let output = Command::new(&hook)
            .current_dir(dir.path())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(7));
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
