/**
 * Error types for agent-vault.
 */

/** Base error for all vault operations. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** No .agent-vault directory found at the given path. */
export class VaultNotFoundError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "VaultNotFoundError";
  }
}

/** The requested secret does not exist in the vault. */
export class SecretNotFoundError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "SecretNotFoundError";
  }
}

/** The provided key cannot decrypt the requested secret. */
export class NotAuthorizedError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "NotAuthorizedError";
  }
}

/** Error parsing or querying the manifest. */
export class ManifestError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}
