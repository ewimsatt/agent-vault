"""Main Vault class — read-only agent access to secrets."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from agent_vault.crypto import decrypt_secret, load_identity, load_identity_from_str
from agent_vault.errors import (
    InvalidIdentifierError,
    GitSyncError,
    NotAuthorizedError,
    SecretNotFoundError,
    VaultNotFoundError,
)
from agent_vault.manifest import Manifest
from agent_vault.metadata import SecretMetadata

def _git_environment() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


def _run_git(repo_path: Path, *args: str, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args], cwd=repo_path, env=_git_environment(), capture_output=True,
        text=True, timeout=30,
    )
    if not allow_failure and result.returncode != 0:
        raise GitSyncError("vault Git synchronization failed")
    return result


def _safe_sync(repo_path: Path) -> None:
    """Fast-forward ``origin`` safely, or fail before a credential read."""
    remotes = _run_git(repo_path, "remote").stdout.splitlines()
    if "origin" not in remotes:
        return
    _run_git(repo_path, "remote", "get-url", "origin")
    if _run_git(repo_path, "status", "--porcelain", "--untracked-files=all").stdout:
        raise GitSyncError("refusing to synchronize a vault with local changes or untracked files")
    branch = _run_git(repo_path, "symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True)
    if branch.returncode != 0 or not branch.stdout.strip():
        raise GitSyncError("refusing to synchronize a detached or unborn vault branch")
    branch_name = branch.stdout.strip()
    remote = _run_git(repo_path, "config", "--get", f"branch.{branch_name}.remote", allow_failure=True)
    merge_ref = _run_git(repo_path, "config", "--get", f"branch.{branch_name}.merge", allow_failure=True)
    if remote.stdout.strip() != "origin" or not merge_ref.stdout.strip().startswith("refs/heads/"):
        raise GitSyncError("refusing to synchronize without an origin tracking branch")
    remote_branch = merge_ref.stdout.strip().removeprefix("refs/heads/")
    if not remote_branch:
        raise GitSyncError("refusing to synchronize without an origin tracking branch")
    target = f"refs/remotes/origin/{remote_branch}"
    _run_git(
        repo_path, "fetch", "--no-tags", "origin",
        f"refs/heads/{remote_branch}:refs/remotes/origin/{remote_branch}",
    )
    _run_git(repo_path, "rev-parse", "--verify", target)
    head = _run_git(repo_path, "rev-parse", "HEAD").stdout.strip()
    target_oid = _run_git(repo_path, "rev-parse", target).stdout.strip()
    if head == target_oid:
        return
    if _run_git(repo_path, "merge-base", "--is-ancestor", "HEAD", target, allow_failure=True).returncode != 0:
        raise GitSyncError("refusing to synchronize a vault with divergent local history")
    _run_git(repo_path, "merge", "--ff-only", target)


def _resolve_repo_path(repo_path: str | Path, auto_pull: bool = True) -> Path:
    """Resolve a local path or safely update a cached remote checkout."""
    path_str = str(repo_path)
    if not any(path_str.startswith(prefix) for prefix in ("https://", "git@", "ssh://", "git://")):
        return Path(repo_path).expanduser().resolve()

    url_hash = hashlib.sha256(path_str.encode()).hexdigest()[:16]
    cache_dir = Path.home() / ".agent-vault" / "cache" / url_hash
    try:
        if cache_dir.exists() and (cache_dir / ".git").exists():
            configured_origin = _run_git(cache_dir, "remote", "get-url", "origin", allow_failure=True)
            if configured_origin.returncode != 0 or configured_origin.stdout.strip() != path_str:
                raise GitSyncError("cached vault origin does not match the requested repository")
            if auto_pull:
                _safe_sync(cache_dir)
        else:
            cache_dir.parent.mkdir(parents=True, exist_ok=True)
            if cache_dir.exists():
                raise VaultNotFoundError("cached vault path is not a Git repository")
            temporary_parent = Path(tempfile.mkdtemp(prefix=".agent-vault-clone-", dir=cache_dir.parent))
            temporary_dir = temporary_parent / "checkout"
            try:
                _run_git(temporary_parent, "clone", "--", path_str, str(temporary_dir))
                os.replace(temporary_dir, cache_dir)
            finally:
                if temporary_parent.exists():
                    shutil.rmtree(temporary_parent)
    except GitSyncError:
        raise
    except Exception as error:
        raise VaultNotFoundError("Failed to clone or initialize the vault cache") from error
    return cache_dir


class Vault:
    """Read-only vault for agents to retrieve secrets.

    Example::

        vault = Vault(
            repo_path="/path/to/vault",
            key_path="~/.agent-vault/agents/my-agent.key",
        )
        api_key = vault.get("stripe/api-key")
    """

    def __init__(
        self,
        repo_path: str | Path,
        key_path: Optional[str | Path] = None,
        key_str: Optional[str] = None,
        auto_pull: bool = True,
    ):
        """Initialize the vault.

        Args:
            repo_path: Path to the Git repository (local or remote URL).
            key_path: Path to the age private key file. If not provided,
                falls back to AGENT_VAULT_KEY env var (as key string),
                then ~/.agent-vault/owner.key.
            key_str: Raw age private key string. Overrides key_path.
            auto_pull: Whether to git pull before each get() call.
        """
        self._repo_path = _resolve_repo_path(repo_path, auto_pull=auto_pull)
        self._vault_dir = self._repo_path / ".agent-vault"
        self._auto_pull = auto_pull

        if not self._vault_dir.is_dir():
            raise VaultNotFoundError(
                f"No vault found at {self._repo_path}. "
                "Run 'agent-vault init' first."
            )

        # Load identity (private key)
        if key_str is not None:
            self._identity = load_identity_from_str(key_str)
        elif key_path is not None:
            self._identity = load_identity(str(Path(key_path).expanduser()))
        elif os.environ.get("AGENT_VAULT_KEY"):
            self._identity = load_identity_from_str(os.environ["AGENT_VAULT_KEY"])
        else:
            default_key = Path.home() / ".agent-vault" / "owner.key"
            if default_key.exists():
                self._identity = load_identity(str(default_key))
            else:
                raise VaultNotFoundError(
                    "No key provided. Pass key_path=, key_str=, "
                    "set AGENT_VAULT_KEY env var, or ensure "
                    "~/.agent-vault/owner.key exists."
                )

        # Load manifest
        self._manifest = Manifest.load(self._vault_dir / "manifest.yaml")

    def pull(self) -> None:
        """Safely fast-forward from ``origin`` or raise ``GitSyncError``."""
        _safe_sync(self._repo_path)

    def get(self, secret_path: str) -> str:
        """Retrieve and decrypt a secret.

        Args:
            secret_path: The secret path (e.g. "stripe/api-key").

        Returns:
            The decrypted plaintext value.

        Raises:
            SecretNotFoundError: If the secret doesn't exist.
            NotAuthorizedError: If the key can't decrypt the secret.
        """
        validate_secret_path(secret_path)

        if self._auto_pull:
            self.pull()

        # Resolve the encrypted file path
        # Secret path "stripe/api-key" -> .agent-vault/secrets/stripe/api-key.enc
        enc_path = self._vault_dir / "secrets" / _to_file_path(secret_path, ".enc")

        if not enc_path.exists():
            raise SecretNotFoundError(f"Secret not found: {secret_path}")

        ciphertext = enc_path.read_bytes()

        try:
            return decrypt_secret(ciphertext, self._identity)
        except Exception as e:
            raise NotAuthorizedError(
                f"Cannot decrypt '{secret_path}': {e}"
            ) from e

    def list_secrets(self, group: Optional[str] = None) -> list[SecretMetadata]:
        """List secret metadata without decrypting.

        Args:
            group: Optional group name to filter by.

        Returns:
            List of SecretMetadata objects.
        """
        secrets_dir = self._vault_dir / "secrets"
        if not secrets_dir.exists():
            return []

        results = []
        for meta_path in sorted(secrets_dir.rglob("*.meta")):
            try:
                meta = SecretMetadata.load(meta_path)
                if group is None or meta.group == group:
                    results.append(meta)
            except Exception:
                continue

        return results

    def list_agents(self) -> list[dict]:
        """List all agents and their group memberships.

        Returns:
            List of dicts with "name" and "groups" keys.
        """
        return self._manifest.list_agents()

    @property
    def manifest(self) -> Manifest:
        """Access the parsed manifest."""
        return self._manifest

    def reload(self) -> None:
        """Reload the manifest from disk (e.g. after a pull)."""
        self._manifest = Manifest.load(self._vault_dir / "manifest.yaml")

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        return False


def validate_secret_path(secret_path: object) -> None:
    """Ensure a caller-provided secret path cannot escape ``secrets/``.

    This deliberately mirrors the Rust CLI's lexical identifier contract rather
    than relying on host filesystem normalization.
    """
    if not isinstance(secret_path, str):
        raise InvalidIdentifierError("invalid secret path: expected a string")

    if (
        not secret_path
        or "\\" in secret_path
        or any(ord(char) <= 31 or 127 <= ord(char) <= 159 for char in secret_path)
        or (
            len(secret_path) >= 2
            and secret_path[0].isascii()
            and secret_path[0].isalpha()
            and secret_path[1] == ":"
        )
    ):
        raise InvalidIdentifierError(f"invalid secret path: {secret_path!r}")

    if any(component in ("", ".", "..") for component in secret_path.split("/")):
        raise InvalidIdentifierError(f"invalid secret path: {secret_path!r}")


def _to_file_path(secret_path: str, suffix: str) -> Path:
    """Convert a secret path like "stripe/api-key" to a file path.

    The convention used by the Rust CLI is:
      secret_path = "group/name"
      file = secrets/group/name.enc (and .meta)

    But the actual file path uses the last component as the filename.
    e.g. "stripe/api-key" -> "stripe/api-key.enc"
    """
    parts = secret_path.split("/")
    if len(parts) < 2:
        return Path(parts[0] + suffix)
    # group/name -> group/name.enc
    return Path(*parts[:-1]) / (parts[-1] + suffix)
