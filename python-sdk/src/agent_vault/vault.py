"""Main Vault class — read-only agent access to secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from agent_vault.crypto import decrypt_secret, load_identity, load_identity_from_str
from agent_vault.errors import (
    NotAuthorizedError,
    SecretNotFoundError,
    VaultNotFoundError,
)
from agent_vault.manifest import Manifest
from agent_vault.metadata import SecretMetadata


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
            repo_path: Path to the Git repository containing the vault.
            key_path: Path to the age private key file. If not provided,
                falls back to AGENT_VAULT_KEY env var (as key string),
                then ~/.agent-vault/owner.key.
            key_str: Raw age private key string. Overrides key_path.
            auto_pull: Whether to git pull before each get() call.
        """
        self._repo_path = Path(repo_path).expanduser().resolve()
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
        """Pull latest changes from the Git remote (best-effort)."""
        try:
            import git

            repo = git.Repo(str(self._repo_path))
            if repo.remotes:
                origin = repo.remotes[0]
                origin.pull(rebase=False)
        except Exception:
            # Best-effort: if no remote, offline, or merge conflict, skip
            pass

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
