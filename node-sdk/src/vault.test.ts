import { describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateSecretPath, Vault } from "./vault.js";
import { GitSyncError, InvalidIdentifierError } from "./index.js";

function makeVault(): Vault {
  const repoPath = mkdtempSync(join(tmpdir(), "agent-vault-node-test-"));
  const vaultDir = join(repoPath, ".agent-vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "manifest.yaml"), "version: 1\n");
  return new Vault({
    repoPath,
    keyStr: "AGE-SECRET-KEY-1SYNTHETIC",
    autoPull: true,
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
});
