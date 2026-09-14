import { describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateSecretPath, Vault } from "./vault.js";
import { InvalidIdentifierError } from "./index.js";

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
