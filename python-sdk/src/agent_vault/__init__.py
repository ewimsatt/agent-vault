"""agent-vault: Zero-trust credential manager for AI agents."""

from agent_vault.vault import Vault
from agent_vault.errors import (
    VaultError,
    VaultNotFoundError,
    SecretNotFoundError,
    NotAuthorizedError,
)

__version__ = "0.1.0"
__all__ = [
    "Vault",
    "VaultError",
    "VaultNotFoundError",
    "SecretNotFoundError",
    "NotAuthorizedError",
]
