# Agent Vault

[![CI](https://github.com/ewimsatt/agent-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ewimsatt/agent-vault/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/agent-vault.svg)](https://crates.io/crates/agent-vault)
[![PyPI](https://img.shields.io/pypi/v/agent-vault-sdk.svg)](https://pypi.org/project/agent-vault-sdk/)
[![npm](https://img.shields.io/npm/v/@ewimsatt/agent-vault.svg)](https://www.npmjs.com/package/@ewimsatt/agent-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Encrypted credentials for AI agents, managed locally and shared through Git.**

Agent Vault stores API keys, database passwords, and other text secrets in an encrypted vault. Each agent gets its own decryption key, and you decide which groups of secrets that key can unlock. Agents retrieve credentials through a CLI, Python or TypeScript SDK, or an optional MCP server.

It is built for developers and operators running multiple agents, scripts, or CI jobs who want to stop copying the same collection of credentials into every environment. It uses [age encryption](https://age-encryption.org/) for secret values and Git for distribution and change history. You do not need to run a secrets server or subscribe to a hosted vault.

For example, a research agent can receive access to a `search` group while a deployment agent receives access to `deploy`. Both can read the same encrypted repository without sharing the ability to decrypt every secret in it. The owner retains access to all secrets.

> **Security boundary:** Agent Vault protects secret values stored in the repository and limits which keys can decrypt them. An authorized caller receives the plaintext credential. It is not a credential-hiding API proxy, and it cannot prevent that caller from logging, copying, or misusing the value. MCP retrieval also returns plaintext to the client.

## Why use it?

A single `.env` file is straightforward for one application. Once several agents need different subsets of credentials, copying that file around makes it harder to know who has access and which copy is current.

Agent Vault gives you a shared encrypted source for those credentials, with separate keys for each consumer:

| Situation | How Agent Vault helps |
| --- | --- |
| A research agent needs a search API key, but should not have deployment credentials | Grant it the `search` group, not the `deploy` group. |
| The same automation runs on a laptop and a server | Distribute the encrypted repository through Git and provision the appropriate private key separately. |
| You add or retire an agent | Create or remove its identity and update the recipients of affected encrypted secrets. Rotate service credentials when previously granted access must truly end. |
| You need to investigate configuration changes | Inspect Git history for secret updates and access-policy changes. This is change history, not a log of every secret read. |
| An agent loses its private key | The owner can restore the escrowed key or issue a replacement keypair. |
| You want to notice expired credentials or inconsistent vault records | Run `agent-vault check`, with JSON output available for automation. |

### When another approach is a better fit

Use your cloud provider's IAM or workload identities when services support short-lived credentials directly. Consider a managed secrets service when you need centrally enforced policies, read-access audit logs, automatic rotation, or immediate online revocation.

Agent Vault is useful when you want local encryption, ordinary Git distribution, and a small set of tools you can operate yourself. It does not provide those managed-service features.

## What is included

| Component | Role |
| --- | --- |
| Rust CLI | Initialize a vault, manage agents and access, write/read secrets, inspect metadata, and recover agent keys. |
| Python SDK | Read secrets and metadata from a local vault or a cached clone of a remote Git repository. |
| Node.js / TypeScript SDK | Read secrets and metadata from a local vault checkout. |
| Python MCP server | Expose secret retrieval and metadata listing to an MCP client over stdio. |
| Git integration | Create local commits for vault changes and retrieve updates before reads, with behavior depending on the client. |

The SDKs are read-only. Use the owner-side CLI to change credentials or access policy.

## Quick start

This README describes the code on `main`. Published packages and release binaries can lag behind it; build from source to use the implementation described here.

### Install

The CLI requires Git on `PATH`. Building from source also requires a Rust toolchain and the platform's native build tools. Use a recent Git version that supports `git hook run`.

```bash
# Latest repository implementation
git clone https://github.com/ewimsatt/agent-vault.git
cd agent-vault
cargo install --locked --path .
```

Or install the published CLI:

```bash
cargo install --locked agent-vault
```

The Python SDK requires Python 3.10 or later. The Node.js SDK requires Node.js 20 or later. Git is also needed for repository synchronization.

### Create a vault and grant access

Run this example in a directory where you want a **new, dedicated secrets repository**, not inside the Agent Vault source checkout. The credential below is a dummy value.

**Before running `init`: back up any existing `~/.agent-vault/owner.key`. The current CLI writes a new owner key at that fixed path, including when you initialize another vault. Agent keys likewise use shared paths under `~/.agent-vault/agents/`. Use an isolated home or separate OS account for experiments or independent vault identities.**

```bash
git init -b main agent-secrets
cd agent-secrets

agent-vault init
agent-vault add-agent researcher
agent-vault set search/api-key "demo-only-not-a-real-key"
agent-vault grant researcher search

# Inspect metadata without printing the credential.
agent-vault list --group search
agent-vault list-agents
agent-vault check

# Demonstrate retrieval with the agent's key, not the owner's key.
# This prints the dummy value to stdout. Do not log real credentials.
agent-vault get search/api-key --key "$HOME/.agent-vault/agents/researcher.key"
```

The first part of a secret path determines its default group: `search/api-key` belongs to `search`. Granting an agent a group allows it to decrypt that group's secrets, not just one named secret. Use separate groups where access requirements differ. The CLI also supports an explicit `--group` when storing a secret.

Run vault commands from the directory that contains `.agent-vault/`. Back up the owner key outside the vault repository before relying on it.

### Store real credentials

Passing real values as command-line arguments can expose them through shell history and process inspection. Prefer reading from a securely provisioned file outside the repository:

```bash
agent-vault set search/api-key --from-file /secure/input/search-api-key
```

The input file is plaintext that **you** manage. Agent Vault does not delete it. Protect it, avoid committing it, and dispose of it according to your environment's security requirements.

You can attach an expiry timestamp for later checks:

```bash
agent-vault set search/api-key \
  --from-file /secure/input/search-api-key \
  --expires 2027-01-01T00:00:00Z
```

Expiry is metadata used by `check`; it does not automatically invalidate the credential at its provider or prevent decryption.

### Share the encrypted vault

`init`, `add-agent`, `set`, `grant`, `revoke`, `remove-agent`, and `recover-agent` create local Git commits. They do **not** push them for you. Add a remote you control, inspect the changes, and push:

```bash
git remote add origin git@github.com:YOUR-ORG/agent-secrets.git
git log --oneline -5
git status
git push -u origin main
```

On the agent's machine:

1. Clone that repository using the machine's normal Git credentials.
2. Provision only that agent's private key through a secure channel outside Git.
3. Configure the SDK or CLI with the explicit agent key path.

Repository access and decryption access are separate: a private repository requires Git authentication, and reading a secret also requires an authorized age key. Prefer a private repository because secret names, group memberships, and timestamps are readable metadata.

**Sync behavior matters:**

- The CLI's `get` fetches from `origin` when configured and fast-forwards when possible. It refuses a repository with staged, modified, or untracked files. It does not automatically resolve divergent history. Without `origin`, it reads the local vault.
- Both SDKs default to pulling before `get()`. A pull failure can leave them reading the existing local checkout; do not assume a successful read proves the latest policy or secret was fetched.
- For a deliberately offline or read-only checkout, disable SDK pulling with `auto_pull=False` in Python or `autoPull: false` in Node.js. You are responsible for distributing updated ciphertext.

## Use credentials in your application

Retrieve a value inside the code that needs it, pass it to the service client, and keep it out of prompts, debug output, and exception messages where possible. Agent Vault does not make requests to the service on your behalf.

### Python

```bash
pip install agent-vault-sdk

# Alternatively, from this repository's root:
pip install ./python-sdk
```

```python
from agent_vault import Vault

vault = Vault(
    repo_path="/path/to/agent-secrets",
    key_path="~/.agent-vault/agents/researcher.key",
)
api_key = vault.get("search/api-key")
# Pass api_key directly to your service client. Do not print it.

for secret in vault.list_secrets(group="search"):
    print(secret.name, secret.expires)  # Metadata only.
```

For a remote repository, Python creates or updates a persistent checkout under `~/.agent-vault/cache/<url-hash>`:

```python
with Vault(
    repo_path="https://github.com/YOUR-ORG/agent-secrets.git",
    key_path="~/.agent-vault/agents/researcher.key",
) as vault:
    api_key = vault.get("search/api-key")
```

The process still needs Git authentication for private remotes.

### Node.js / TypeScript

```bash
npm install @ewimsatt/agent-vault
```

```typescript
import { Vault } from "@ewimsatt/agent-vault";

const vault = new Vault({
  repoPath: "/path/to/agent-secrets",
  keyPath: "~/.agent-vault/agents/researcher.key",
});

const apiKey = await vault.get("search/api-key");
// Pass apiKey directly to your service client. Do not log it.

const metadata = vault.listSecrets("search");
```

### Which key is used?

| Client | Resolution order |
| --- | --- |
| CLI `get` | `--key` file path, then `AGENT_VAULT_KEY` (file path or raw age identity), then `~/.agent-vault/owner.key`. |
| Python SDK | `key_str`, then `key_path`, then `AGENT_VAULT_KEY` as a raw age identity, then the default owner key. |
| Node.js SDK | `keyStr`, then `keyPath`, then `AGENT_VAULT_KEY` as a raw age identity, then the default owner key. |

**Always configure an agent's identity explicitly.** Do not deploy the owner key to ordinary agent runtimes or rely on the owner-key fallback for agents. Private keys themselves are credentials and need secure provisioning and storage.

### MCP clients

Install the Python package with its MCP extra:

```bash
pip install 'agent-vault-sdk[mcp]'

# Alternatively, from this repository's root:
pip install './python-sdk[mcp]'

agent-vault-mcp --repo /path/to/agent-secrets \
  --key /path/to/researcher.key
```

The stdio server exposes:

| Tool | Result |
| --- | --- |
| `agent_vault_get(secret)` | Decrypt and return the named secret as plaintext. |
| `agent_vault_list(group?)` | List secret metadata, optionally filtered by group. |

Example configuration for an MCP client that accepts `mcpServers` entries:

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "agent-vault-mcp",
      "args": [
        "--repo", "/path/to/agent-secrets",
        "--key", "/path/to/researcher.key"
      ]
    }
  }
}
```

Use actual absolute paths on the machine running the server. Because retrieved values are MCP tool results, the client may include them in model context or transcripts. Use direct SDK integration in your tool implementation if you want to avoid returning credentials to the model; that isolation is your integration's responsibility.

## How access and encryption work

1. The owner initializes the vault and creates an age identity for each agent.
2. Each secret is encrypted to the owner's public key and its authorized agent recipients.
3. The encrypted secret, public keys, access manifest, and metadata are committed to Git. Private identity keys stay outside the repository; encrypted copies of agent keys are stored for owner recovery.
4. Readers sync the repository and decrypt locally using their own identity.
5. Group grants and revocations rewrite affected ciphertext with the changed recipient list.

A vault repository contains more than encrypted blobs:

```text
.agent-vault/
├── config.yaml                 # Readable configuration
├── owner.pub                   # Owner's public key
├── manifest.yaml               # Readable agent/group/secret relationships
├── agents/
│   └── researcher/
│       ├── public.key          # Agent's public key
│       └── private.key.escrow  # Agent identity encrypted to the owner
└── secrets/
    └── search/
        ├── api-key.enc         # Encrypted credential value
        └── api-key.meta        # Readable names, recipients, and timestamps
```

The owner key is stored at `~/.agent-vault/owner.key`; agent keys are stored at `~/.agent-vault/agents/<name>.key`. Private key files receive restrictive permissions on Unix. Losing the owner key removes the owner's recovery capability; an agent key is not a replacement for it.

### Revocation is not credential rotation

```bash
agent-vault revoke researcher search
# Or remove the agent's vault registration and group access:
agent-vault remove-agent researcher
```

These operations re-encrypt affected current secrets without the removed group recipient. They cannot erase a plaintext value already copied by an agent, or remove that agent's ability to decrypt older ciphertext it retained or can obtain from Git history.

If an agent is compromised or should no longer use a service, revoke its vault access **and rotate the actual credential at the service provider**, update the vault, push the changes, and refresh the remaining consumers. Re-encrypting an unchanged API key is not enough.

### Recovery

| Command | What it does |
| --- | --- |
| `agent-vault restore-agent researcher --to /secure/researcher.key` | Decrypt the escrowed identity with the owner key and write that original private key to the specified file. |
| `agent-vault recover-agent researcher` | Generate a replacement agent keypair, replace its escrow, and re-encrypt secrets in the agent's assigned groups for the new key. |

Use replacement when you need a new identity; restoring the old identity does not remove the risk from a copied key. Neither command rotates credentials at external services.

## Security and operational limits

- **Decryption is local, but plaintext exists during use.** The SDKs return it in memory; CLI `get` writes it to stdout. Your application, shell redirection, host, logs, or MCP client can expose it. `restore-agent` intentionally writes a decrypted private key to a file.
- **Repository readers can see metadata.** Secret names, public keys, memberships, timestamps, and historical encrypted versions are not hidden.
- **Trust repository writers and the runtime.** Protect write access, review policy and public-key changes, and use trusted checkouts. Encryption does not stop a compromised host from reading keys or a repository writer from altering policy files. There is no claim here of protection against rollback to older repository state.
- **Git records changes, not reads.** The project does not provide a central credential-access audit log, service request log, or proof of which agent used a credential.
- **The pre-commit hook is a guardrail.** Initialization installs a check for recognizable private-key markers, and `.gitignore` excludes common private-key filenames inside the vault. This is not a general API-key scanner or an enforcement boundary. Git hooks are local and do not travel with a clone.
- **Expiry checks are advisory about the credential's lifecycle.** They do not enforce TTLs or verify whether an API provider still accepts a key.
- **Vault-changing commands create local commits.** The commands listed under [sharing the vault](#share-the-encrypted-vault) use an isolated index to avoid including unrelated staged work and run the repository's pre-commit hook. Inspect `git status` before subsequent Git operations; the existing index is preserved rather than normalized to the new commit. Read-only commands and `restore-agent` do not create commits.
- **Key paths are shared per home directory.** Initializing another vault or reusing an agent name across vaults can overwrite local key material. Back it up and isolate identities where necessary.

Agent and group identifiers and secret paths have lexical validation to reject traversal and malformed names. Explicit input, key, and restore destination paths are caller-controlled. These checks do not turn an untrusted filesystem or agent host into a safe execution environment.

## CLI reference

Run `agent-vault <command> --help` for full arguments.

| Command | Purpose |
| --- | --- |
| `init [directory]` | Initialize the vault in an existing Git repository, create owner keys, and install the hook. |
| `add-agent <name>` | Create an agent keypair and owner-encrypted escrow. |
| `list-agents [--json]` | List registered agents and their groups. |
| `set <path> <value>` | Write a text secret; the first path component supplies the default group. |
| `set <path> --from-file <file>` | Read a text secret from a caller-managed file. Supports `--group`, `--expires`, and additional recipient agents via `--agents`. |
| `get <path> [--key <file>]` | Sync when applicable and print the decrypted value to stdout. |
| `list [--group <name>] [--json]` | Inspect secret metadata without decryption. |
| `grant <agent> <group>` | Add a group membership and re-encrypt affected secrets. |
| `revoke <agent> <group>` | Remove a group membership and re-encrypt affected secrets. |
| `remove-agent <name>` | Remove the agent and re-encrypt secrets in its assigned groups. |
| `check [--json]` | Audit expiry and vault integrity: recursively verify manifest secrets have `.enc` and `.meta` records, flag orphaned records, and validate metadata path, group, and authorized-agent relationships. Errors produce a nonzero exit status. |
| `restore-agent <name> --to <file>` | Restore an escrowed private key to a file. |
| `recover-agent <name>` | Replace an agent keypair and re-encrypt its group secrets. |
| `completions <shell>` | Generate shell completion definitions. |

Prefer group grants for ongoing access policy. `set --agents` adds recipients to that write; it is not a substitute for a persistent group membership.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Vault not found | The repo path or current CLI directory must contain `.agent-vault/`. Cloning the application's source code is not the same as initializing a secrets vault. |
| An agent cannot decrypt a secret | Confirm the explicit identity, group grant, secret path, and that the encrypted checkout includes the grant. |
| CLI `get` refuses local changes | Inspect `git status` and reconcile the worktree/index deliberately before retrying. Do not discard unrelated work just to make a read succeed. |
| An agent reads an old value | Confirm the owner pushed the update and the reader fetched it. Check SDK pull warnings, local changes, and divergent branches. |
| A supposedly revoked credential still works | Rotate it at the external provider. Vault revocation cannot erase previously learned values. |
| MCP command not found | Install the `mcp` extra into the environment used by the MCP client, or configure the full path to that environment's `agent-vault-mcp` executable. |

## Development

From the repository root, build the CLI first; SDK tests use the compiled binary for fixtures.

```bash
cargo build --locked
cargo test --locked

# Python, in an isolated environment
python3 -m venv .venv
. .venv/bin/activate
pip install -e './python-sdk[dev]'
pytest python-sdk/tests/ -v

# Node.js / TypeScript
(cd node-sdk && npm ci && npm run build && npm test -- --run)
```

The [product requirements document](agent-vault-prd.md) describes design intent and may include behavior beyond the current implementation. For implementation details, see the [Rust CLI](src/cli/), [vault core](src/core/vault.rs), [Python SDK](python-sdk/src/agent_vault/), and [Node.js SDK](node-sdk/src/).

## License

[MIT](LICENSE)
