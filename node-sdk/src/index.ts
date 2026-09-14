/**
 * agent-vault: Zero-trust credential manager for AI agents — Node.js SDK.
 *
 * @packageDocumentation
 */

export { Vault, type VaultOptions } from "./vault.js";
export {
  VaultError,
  VaultNotFoundError,
  SecretNotFoundError,
  InvalidIdentifierError,
  NotAuthorizedError,
  ManifestError,
} from "./errors.js";
export { type SecretMetadata, parseMetadataFile, parseMetadata } from "./metadata.js";
export { Manifest, type ManifestAgent, type ManifestGroup } from "./manifest.js";
