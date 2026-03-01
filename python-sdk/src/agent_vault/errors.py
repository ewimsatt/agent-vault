"""Error types for agent-vault."""


class VaultError(Exception):
    """Base error for all vault operations."""


class VaultNotFoundError(VaultError):
    """No .agent-vault directory found at the given path."""


class SecretNotFoundError(VaultError):
    """The requested secret does not exist in the vault."""


class NotAuthorizedError(VaultError):
    """The provided key cannot decrypt the requested secret."""


class ManifestError(VaultError):
    """Error parsing or querying the manifest."""
