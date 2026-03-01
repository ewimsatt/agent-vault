# agent-vault — Node.js SDK

Zero-trust credential manager for AI agents. This is the read-only Node.js/TypeScript SDK for retrieving secrets from an agent-vault repository.

Secrets are encrypted locally using [age encryption](https://age-encryption.org/) and synced via Git. No server, no SaaS -- the Git repo is an untrusted encrypted blob store. All crypto happens locally.

## Installation

```bash
npm install agent-vault
```

Requires Node.js 20 or later.

## Quick Start

```typescript
import { Vault } from "agent-vault";

const vault = new Vault({
  repoPath: "/path/to/repo",
  keyPath: "~/.agent-vault/agents/my-agent.key",
});

// Decrypt a secret (pulls latest from Git first)
const apiKey = await vault.get("stripe/api-key");
```

## API

### `new Vault(options)`

Create a read-only vault instance.

| Option     | Type      | Default | Description                                      |
|------------|-----------|---------|--------------------------------------------------|
| `repoPath` | `string`  | -       | Path to the Git repository containing the vault.  |
| `keyPath`  | `string?` | -       | Path to the age private key file.                 |
| `keyStr`   | `string?` | -       | Raw age private key string. Overrides `keyPath`.  |
| `autoPull` | `boolean` | `true`  | Whether to `git pull` before each `get()` call.  |

Key resolution order:
1. `keyStr` option
2. `keyPath` option
3. `AGENT_VAULT_KEY` environment variable
4. `~/.agent-vault/owner.key`

### `vault.get(secretPath): Promise<string>`

Decrypt and return a secret value. The secret path follows the format `group/name` (e.g., `stripe/api-key`).

Throws `SecretNotFoundError` if the secret does not exist. Throws `NotAuthorizedError` if the key cannot decrypt it.

### `vault.listSecrets(group?): SecretMetadata[]`

List secret metadata without decrypting. Optionally filter by group name.

### `vault.pull(): void`

Manually trigger a `git pull`. Failures are logged to stderr but do not throw.

### `vault.listAgents(): Array<{ name: string; groups: string[] }>`

List all agents and their group memberships from the manifest.

### `vault.reload(): void`

Reload the manifest from disk (useful after a pull).

## Error Types

```typescript
import {
  VaultError,          // Base error
  VaultNotFoundError,  // No vault or key found
  SecretNotFoundError, // Secret path does not exist
  NotAuthorizedError,  // Key cannot decrypt the secret
  ManifestError,       // Manifest parsing failure
} from "agent-vault";
```

## Environment Variables

- `AGENT_VAULT_KEY` -- Raw age secret key string (used if no `keyPath`/`keyStr` provided)

## How It Works

1. The vault reads encrypted `.enc` files from `.agent-vault/secrets/` in the repo.
2. It decrypts them in memory using the [age-encryption](https://www.npmjs.com/package/age-encryption) package.
3. Decrypted values are never written to disk -- they exist only in memory.
4. Metadata (`.meta` YAML files) can be browsed without decryption.

## License

MIT
