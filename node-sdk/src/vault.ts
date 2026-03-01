/**
 * Main Vault class — read-only agent access to secrets.
 *
 * The Vault handles key loading, Git synchronization, and age decryption.
 * Decrypted material is never written to disk — it stays in memory only.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import * as age from "age-encryption";
import {
  VaultNotFoundError,
  SecretNotFoundError,
  NotAuthorizedError,
} from "./errors.js";
import { Manifest } from "./manifest.js";
import { parseMetadataFile, type SecretMetadata } from "./metadata.js";

/** Options for constructing a Vault instance. */
export interface VaultOptions {
  /** Path to the Git repository containing the vault. */
  repoPath: string;
  /**
   * Path to the age private key file.
   * Falls back to AGENT_VAULT_KEY env var, then ~/.agent-vault/owner.key.
   */
  keyPath?: string;
  /** Raw age private key string. Overrides keyPath. */
  keyStr?: string;
  /** Whether to git pull before each get() call. Defaults to true. */
  autoPull?: boolean;
}

/**
 * Extract the AGE-SECRET-KEY line from key file contents.
 * Key files may contain comments (lines starting with #) and blank lines.
 */
function extractIdentity(content: string): string {
  const lines = content.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("AGE-SECRET-KEY-")) {
      return trimmed;
    }
  }
  throw new VaultNotFoundError(
    "No valid age identity found. Expected a line starting with AGE-SECRET-KEY-.",
  );
}

/**
 * Convert a secret path like "stripe/api-key" to a relative file path.
 * "stripe/api-key" becomes "stripe/api-key.enc" (or .meta).
 */
function toFilePath(secretPath: string, suffix: string): string {
  const parts = secretPath.split("/");
  if (parts.length < 2) {
    return parts[0] + suffix;
  }
  const dir = parts.slice(0, -1).join("/");
  const file = parts[parts.length - 1] + suffix;
  return join(dir, file);
}

/**
 * Recursively find all files matching a glob suffix in a directory.
 */
function findFiles(dir: string, suffix: string): string[] {
  const results: string[] = [];
  if (!existsSync(dir)) {
    return results;
  }

  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFiles(fullPath, suffix));
    } else if (entry.name.endsWith(suffix)) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Read-only vault for agents to retrieve secrets.
 *
 * @example
 * ```typescript
 * const vault = new Vault({
 *   repoPath: "/path/to/repo",
 *   keyPath: "~/.agent-vault/agents/my-agent.key",
 * });
 * const apiKey = await vault.get("stripe/api-key");
 * ```
 */
export class Vault {
  private readonly _repoPath: string;
  private readonly _vaultDir: string;
  private readonly _identity: string;
  private readonly _autoPull: boolean;
  private _manifest: Manifest;

  constructor(options: VaultOptions) {
    this._repoPath = resolve(options.repoPath);
    this._vaultDir = join(this._repoPath, ".agent-vault");
    this._autoPull = options.autoPull ?? true;

    if (!existsSync(this._vaultDir) || !statSync(this._vaultDir).isDirectory()) {
      throw new VaultNotFoundError(
        `No vault found at ${this._repoPath}. Run 'agent-vault init' first.`,
      );
    }

    // Load identity (private key)
    this._identity = this._loadIdentity(options);

    // Load manifest
    this._manifest = Manifest.load(join(this._vaultDir, "manifest.yaml"));
  }

  /**
   * Resolve and load the age identity (private key).
   *
   * Priority:
   *   1. keyStr option (raw string)
   *   2. keyPath option (file path)
   *   3. AGENT_VAULT_KEY env var (raw string)
   *   4. ~/.agent-vault/owner.key (default file)
   */
  private _loadIdentity(options: VaultOptions): string {
    if (options.keyStr) {
      return extractIdentity(options.keyStr);
    }

    if (options.keyPath) {
      const resolvedPath = options.keyPath.startsWith("~")
        ? join(homedir(), options.keyPath.slice(1))
        : resolve(options.keyPath);

      if (!existsSync(resolvedPath)) {
        throw new VaultNotFoundError(
          `Key file not found: ${resolvedPath}`,
        );
      }
      return extractIdentity(readFileSync(resolvedPath, "utf-8"));
    }

    const envKey = process.env.AGENT_VAULT_KEY;
    if (envKey) {
      return extractIdentity(envKey);
    }

    const defaultKeyPath = join(homedir(), ".agent-vault", "owner.key");
    if (existsSync(defaultKeyPath)) {
      return extractIdentity(readFileSync(defaultKeyPath, "utf-8"));
    }

    throw new VaultNotFoundError(
      "No key provided. Pass keyPath, keyStr, set the AGENT_VAULT_KEY " +
      "environment variable, or ensure ~/.agent-vault/owner.key exists.",
    );
  }

  /**
   * Pull latest changes from the Git remote (best-effort).
   *
   * Failures are logged to stderr but do not throw. The vault continues
   * with whatever local state is available.
   */
  pull(): void {
    try {
      execSync("git pull", {
        cwd: this._repoPath,
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 30_000,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `Warning: git pull failed (continuing with local state): ${message}\n`,
      );
    }
  }

  /**
   * Retrieve and decrypt a secret.
   *
   * @param secretPath - The secret path (e.g. "stripe/api-key").
   * @returns The decrypted plaintext value.
   * @throws SecretNotFoundError if the secret does not exist.
   * @throws NotAuthorizedError if the key cannot decrypt the secret.
   */
  async get(secretPath: string): Promise<string> {
    if (this._autoPull) {
      this.pull();
    }

    const encPath = join(
      this._vaultDir,
      "secrets",
      toFilePath(secretPath, ".enc"),
    );

    if (!existsSync(encPath)) {
      throw new SecretNotFoundError(`Secret not found: ${secretPath}`);
    }

    const ciphertext = readFileSync(encPath);

    try {
      const d = new age.Decrypter();
      d.addIdentity(this._identity);
      const plaintext = await d.decrypt(ciphertext, "text");
      return plaintext;
    } catch (err) {
      throw new NotAuthorizedError(
        `Cannot decrypt '${secretPath}': ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * List secret metadata without decrypting.
   *
   * @param group - Optional group name to filter by.
   * @returns Array of SecretMetadata objects.
   */
  listSecrets(group?: string): SecretMetadata[] {
    const secretsDir = join(this._vaultDir, "secrets");
    if (!existsSync(secretsDir)) {
      return [];
    }

    const metaFiles = findFiles(secretsDir, ".meta").sort();
    const results: SecretMetadata[] = [];

    for (const metaPath of metaFiles) {
      try {
        const meta = parseMetadataFile(metaPath);
        if (group === undefined || meta.group === group) {
          results.push(meta);
        }
      } catch {
        // Skip unparseable metadata files
        continue;
      }
    }

    return results;
  }

  /**
   * List all agents and their group memberships.
   */
  listAgents(): Array<{ name: string; groups: string[] }> {
    return this._manifest.listAgents();
  }

  /** Access the parsed manifest. */
  get manifest(): Manifest {
    return this._manifest;
  }

  /**
   * Reload the manifest from disk (e.g. after a pull).
   */
  reload(): void {
    this._manifest = Manifest.load(join(this._vaultDir, "manifest.yaml"));
  }
}
