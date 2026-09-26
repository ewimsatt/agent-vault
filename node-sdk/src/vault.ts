/**
 * Main Vault class — read-only agent access to secrets.
 *
 * The Vault handles key loading, Git synchronization, and age decryption.
 * Decrypted material is never written to disk — it stays in memory only.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import * as age from "age-encryption";
import {
  VaultNotFoundError,
  SecretNotFoundError,
  InvalidIdentifierError,
  GitSyncError,
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
 * Ensure a caller-provided secret path cannot escape the secrets directory.
 * This mirrors the Rust CLI's lexical identifier contract instead of relying
 * on host filesystem normalization.
 */
export function validateSecretPath(secretPath: unknown): asserts secretPath is string {
  if (typeof secretPath !== "string") {
    throw new InvalidIdentifierError("invalid secret path: expected a string");
  }

  if (
    secretPath.length === 0 ||
    secretPath.includes("\\") ||
    /[\x00-\x1F\x7F-\x9F]/.test(secretPath) ||
    /^[A-Za-z]:/.test(secretPath)
  ) {
    throw new InvalidIdentifierError(`invalid secret path: ${JSON.stringify(secretPath)}`);
  }

  if (secretPath.split("/").some((component) => component === "" || component === "." || component === "..")) {
    throw new InvalidIdentifierError(`invalid secret path: ${JSON.stringify(secretPath)}`);
  }
}

const gitEnvironment = (): NodeJS.ProcessEnv => {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.startsWith("GIT_")) delete environment[name];
  }
  return environment;
};

function runGit(repoPath: string, args: string[], allowFailure = false): string | null {
  try {
    return execFileSync("git", args, {
      cwd: repoPath, env: gitEnvironment(), encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"], timeout: 30_000,
    });
  } catch {
    if (allowFailure) return null;
    throw new GitSyncError("vault Git synchronization failed");
  }
}

function safeSync(repoPath: string): void {
  const remotes = runGit(repoPath, ["remote"])!.split("\n");
  if (!remotes.includes("origin")) return;
  runGit(repoPath, ["remote", "get-url", "origin"]);
  if (runGit(repoPath, ["status", "--porcelain", "--untracked-files=all"])!.trim()) {
    throw new GitSyncError("refusing to synchronize a vault with local changes or untracked files");
  }
  const branch = (runGit(repoPath, ["symbolic-ref", "--quiet", "--short", "HEAD"], true) ?? "").trim();
  if (!branch) throw new GitSyncError("refusing to synchronize a detached or unborn vault branch");
  const remote = (runGit(repoPath, ["config", "--get", `branch.${branch}.remote`], true) ?? "").trim();
  const mergeRef = (runGit(repoPath, ["config", "--get", `branch.${branch}.merge`], true) ?? "").trim();
  if (remote !== "origin" || !mergeRef.startsWith("refs/heads/")) {
    throw new GitSyncError("refusing to synchronize without an origin tracking branch");
  }
  const remoteBranch = mergeRef.slice("refs/heads/".length);
  if (!remoteBranch) throw new GitSyncError("refusing to synchronize without an origin tracking branch");
  const target = `refs/remotes/origin/${remoteBranch}`;
  runGit(repoPath, [
    "fetch", "--no-tags", "origin",
    `refs/heads/${remoteBranch}:refs/remotes/origin/${remoteBranch}`,
  ]);
  runGit(repoPath, ["rev-parse", "--verify", target]);
  const head = runGit(repoPath, ["rev-parse", "HEAD"])!.trim();
  const targetOid = runGit(repoPath, ["rev-parse", target])!.trim();
  if (head === targetOid) return;
  if (runGit(repoPath, ["merge-base", "--is-ancestor", "HEAD", target], true) === null) {
    throw new GitSyncError("refusing to synchronize a vault with divergent local history");
  }
  runGit(repoPath, ["merge", "--ff-only", target]);
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

  /** Safely fast-forward from ``origin`` or throw ``GitSyncError``. */
  pull(): void {
    safeSync(this._repoPath);
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
    validateSecretPath(secretPath);

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
