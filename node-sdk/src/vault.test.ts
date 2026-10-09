import { describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateSecretPath, Vault } from "./vault.js";
import { parseMetadata } from "./metadata.js";
import { GitSyncError, InvalidIdentifierError, MetadataError, SecretNotFoundError } from "./index.js";

function makeVault(manifest = "version: 1\n", autoPull = true): Vault {
  const repoPath = mkdtempSync(join(tmpdir(), "agent-vault-node-test-"));
  const vaultDir = join(repoPath, ".agent-vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "manifest.yaml"), manifest);
  return new Vault({
    repoPath,
    keyStr: "AGE-SECRET-KEY-1SYNTHETIC",
    autoPull,
  });
}

describe("Vault.get secret path validation", () => {
  it.each([
    "",
    "/outside",
    "../outside",
    "stripe/../../outside",
    "stripe//api-key",
    "stripe/./api-key",
    "stripe/../api-key",
    "stripe/api-key/",
    "stripe\\api-key",
    "C:temp",
    "x\u0000y",
    "x\u007fy",
    "x\u0085y",
  ])("rejects malformed path %j before pulling", async (secretPath) => {
    const vault = makeVault();
    const pull = vi.spyOn(vault, "pull");

    await expect(vault.get(secretPath)).rejects.toBeInstanceOf(
      InvalidIdentifierError,
    );
    expect(pull).not.toHaveBeenCalled();
  });

  it.each([
    "api-key",
    "stripe/api-key",
    "stripe/production/api-key",
    "dotted.name/_ok-1",
    "unicode/秘密",
  ])("accepts valid path shape %j", (secretPath) => {
    expect(() => validateSecretPath(secretPath)).not.toThrow();
  });

  it("refuses an orphaned ciphertext absent from the current manifest", async () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: stripe\n    secrets: [stripe/api-key]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretDir = join(vaultDir, "secrets", "stripe");
    mkdirSync(secretDir, { recursive: true });
    writeFileSync(join(secretDir, "api-key.enc"), "not-an-age-ciphertext");
    writeFileSync(join(vaultDir, "manifest.yaml"), "version: 1\ngroups:\n  - name: stripe\n    secrets: []\n");

    await expect(vault.get("stripe/api-key")).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it("refuses a symlinked ciphertext at a manifest-managed path", async () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: stripe\n    secrets: [stripe/api-key]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretDir = join(vaultDir, "secrets", "stripe");
    mkdirSync(secretDir, { recursive: true });
    const ciphertext = join(secretDir, "api-key.enc");
    const externalCiphertext = join(vaultDir, "outside-vault.enc");
    writeFileSync(externalCiphertext, "not-an-age-ciphertext");
    symlinkSync(externalCiphertext, ciphertext);

    await expect(vault.get("stripe/api-key")).rejects.toBeInstanceOf(SecretNotFoundError);
  });
  it("refuses a symlinked ciphertext directory at a manifest-managed path", async () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: stripe\n    secrets: [stripe/api-key]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretDir = join(vaultDir, "secrets", "stripe");
    const externalDirectory = join(vaultDir, "outside-vault-records");
    mkdirSync(join(vaultDir, "secrets"), { recursive: true });
    mkdirSync(externalDirectory, { recursive: true });
    writeFileSync(join(externalDirectory, "api-key.enc"), "not-an-age-ciphertext");
    symlinkSync(externalDirectory, secretDir);

    await expect(vault.get("stripe/api-key")).rejects.toBeInstanceOf(SecretNotFoundError);
  });
});

describe("Vault.listSecrets metadata integrity", () => {
  it("refuses malformed metadata instead of silently omitting it", () => {
    const vault = makeVault();
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretsDir = join(vaultDir, "secrets", "stripe");
    mkdirSync(secretsDir, { recursive: true });
    writeFileSync(join(secretsDir, "api-key.meta"), "name: stripe/api-key\ngroup: [not-a-string]\n");

    expect(() => vault.listSecrets()).toThrow(MetadataError);
  });

  it("refuses metadata removed from the current manifest", () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: stripe\n    secrets: [stripe/api-key]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretsDir = join(vaultDir, "secrets", "stripe");
    mkdirSync(secretsDir, { recursive: true });
    writeFileSync(
      join(secretsDir, "api-key.meta"),
      "name: stripe/api-key\ngroup: stripe\ncreated: 2026-01-01T00:00:00Z\nrotated: 2026-01-01T00:00:00Z\nauthorized_agents: []\n",
    );
    writeFileSync(join(vaultDir, "manifest.yaml"), "version: 1\ngroups:\n  - name: stripe\n    secrets: []\n");

    expect(() => vault.listSecrets()).toThrow(/absent from the current manifest/);
  });
  it("refuses metadata whose file path impersonates a manifest secret", () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: current\n    secrets: [current/real]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const staleDir = join(vaultDir, "secrets", "stale");
    mkdirSync(staleDir, { recursive: true });
    writeFileSync(
      join(staleDir, "old.meta"),
      "name: current/real\ngroup: current\ncreated: 2026-01-01T00:00:00Z\nrotated: 2026-01-01T00:00:00Z\nauthorized_agents: []\n",
    );

    expect(() => vault.listSecrets()).toThrow(/does not match metadata name/);
  });
  it("refuses a symlinked metadata record", () => {
    const vault = makeVault(
      "version: 1\ngroups:\n  - name: stripe\n    secrets: [stripe/api-key]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    const secretsDir = join(vaultDir, "secrets", "stripe");
    mkdirSync(secretsDir, { recursive: true });
    const original = join(secretsDir, "api-key.meta");
    const target = join(vaultDir, "stale-source.meta");
    writeFileSync(target, "name: stripe/api-key\ngroup: stripe\ncreated: 2026-01-01T00:00:00Z\nrotated: 2026-01-01T00:00:00Z\nauthorized_agents: []\n");
    symlinkSync(target, original);

    expect(() => vault.listSecrets()).toThrow(/symbolic link/);
  });
});

describe("Vault.listAgents", () => {
  it("reloads replacement policy from disk when auto-pull is disabled", () => {
    const vault = makeVault(
      "version: 1\nagents:\n  - name: initial-bot\n    groups: [initial-group]\n",
      false,
    );
    const vaultDir = (vault as unknown as { _vaultDir: string })._vaultDir;
    writeFileSync(
      join(vaultDir, "manifest.yaml"),
      "version: 1\nagents:\n  - name: replacement-bot\n    groups: [replacement-group]\n",
    );

    expect(vault.listAgents()).toEqual([
      { name: "replacement-bot", groups: ["replacement-group"] },
    ]);
  });
});

describe("metadata timestamps", () => {
  const documentWith = (timestamp: string) =>
    `name: stripe/api-key\ngroup: stripe\ncreated: ${timestamp}\nrotated: "${timestamp}"\nauthorized_agents: []\n`;

  it.each(["2026-02-30T10:00:00Z", "2026-01-01", "2026-01-01T10:00:00", "Oct 4 2026"])
  ("rejects non-RFC3339 timestamp %s", (timestamp) => {
    expect(() => parseMetadata(documentWith(timestamp))).toThrow(MetadataError);
  });

  it.each(["2026-01-01T10:00:00Z", "2026-01-01T10:00:00+05:30", "0001-01-01T00:00:00Z"])
  ("accepts RFC3339 timestamp %s", (timestamp) => {
    expect(() => parseMetadata(documentWith(timestamp))).not.toThrow();
  });
});

describe("Vault.pull", () => {
  it("rejects a dirty checkout without discarding its local bytes", () => {
    const repoPath = mkdtempSync(join(tmpdir(), "agent-vault-node-sync-"));
    execFileSync("git", ["init"], { cwd: repoPath });
    execFileSync("git", ["config", "user.email", "test@agent-vault.invalid"], { cwd: repoPath });
    execFileSync("git", ["config", "user.name", "Agent Vault test"], { cwd: repoPath });
    const vaultDir = join(repoPath, ".agent-vault");
    mkdirSync(vaultDir);
    const manifest = join(vaultDir, "manifest.yaml");
    writeFileSync(manifest, "version: 1\n");
    execFileSync("git", ["add", "."], { cwd: repoPath });
    execFileSync("git", ["commit", "-m", "seed"], { cwd: repoPath });
    const bareRemote = mkdtempSync(join(tmpdir(), "agent-vault-node-remote-"));
    execFileSync("git", ["init", "--bare", bareRemote]);
    const branch = execFileSync("git", ["branch", "--show-current"], { cwd: repoPath, encoding: "utf8" }).trim();
    execFileSync("git", ["remote", "add", "origin", bareRemote], { cwd: repoPath });
    execFileSync("git", ["push", "-u", "origin", branch], { cwd: repoPath });
    const originalHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoPath, encoding: "utf8" }).trim();
    writeFileSync(manifest, "version: 999\n");

    const vault = new Vault({ repoPath, keyStr: "AGE-SECRET-KEY-1SYNTHETIC", autoPull: false });
    expect(() => vault.pull()).toThrow(GitSyncError);
    expect(execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoPath, encoding: "utf8" }).trim()).toBe(originalHead);
    expect(readFileSync(manifest, "utf8")).toBe("version: 999\n");
  });

  it("refreshes cached agent policy after a successful fast-forward", () => {
    const repoPath = mkdtempSync(join(tmpdir(), "agent-vault-node-policy-"));
    execFileSync("git", ["init"], { cwd: repoPath });
    execFileSync("git", ["config", "user.email", "test@agent-vault.invalid"], { cwd: repoPath });
    execFileSync("git", ["config", "user.name", "Agent Vault test"], { cwd: repoPath });
    const vaultDir = join(repoPath, ".agent-vault");
    mkdirSync(vaultDir);
    const manifest = join(vaultDir, "manifest.yaml");
    writeFileSync(manifest, "version: 1\nagents:\n  - name: existing-bot\n    groups: []\n");
    execFileSync("git", ["add", "."], { cwd: repoPath });
    execFileSync("git", ["commit", "-m", "seed"], { cwd: repoPath });
    const bareRemote = mkdtempSync(join(tmpdir(), "agent-vault-node-policy-remote-"));
    execFileSync("git", ["init", "--bare", bareRemote]);
    const branch = execFileSync("git", ["branch", "--show-current"], { cwd: repoPath, encoding: "utf8" }).trim();
    execFileSync("git", ["remote", "add", "origin", bareRemote], { cwd: repoPath });
    execFileSync("git", ["push", "-u", "origin", branch], { cwd: repoPath });
    const updater = mkdtempSync(join(tmpdir(), "agent-vault-node-policy-updater-"));
    execFileSync("git", ["clone", bareRemote, updater]);
    writeFileSync(manifest.replace(repoPath, updater), "version: 1\nagents:\n  - name: existing-bot\n    groups: []\n  - name: fresh-bot\n    groups: []\n");
    execFileSync("git", ["add", ".agent-vault/manifest.yaml"], { cwd: updater });
    execFileSync("git", ["commit", "-m", "add agent policy"], { cwd: updater });
    execFileSync("git", ["push"], { cwd: updater });

    const vault = new Vault({ repoPath, keyStr: "AGE-SECRET-KEY-1SYNTHETIC", autoPull: false });
    expect(vault.listAgents().map((agent) => agent.name)).toEqual(["existing-bot"]);
    vault.pull();
    expect(vault.listAgents().map((agent) => agent.name)).toEqual(["existing-bot", "fresh-bot"]);
  });
});
