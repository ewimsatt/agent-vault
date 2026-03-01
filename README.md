# agent-vault

Zero-trust credential manager for AI agents. Secrets are encrypted locally using [age encryption](https://age-encryption.org/) and synced via Git. No server, no SaaS — the Git repo is an untrusted encrypted blob store.

## Install

```bash
cargo install --path .
```

## Quick Start

```bash
# Initialize a vault in a git repo
cd my-project
agent-vault init

# Add an agent
agent-vault add-agent my-agent

# Store a secret
agent-vault set stripe/api-key "sk_test_123"

# Grant the agent access
agent-vault grant my-agent stripe

# Retrieve as owner
agent-vault get stripe/api-key

# Retrieve as agent
agent-vault get stripe/api-key --key ~/.agent-vault/agents/my-agent.key
```

## Commands

| Command | Description |
|---------|-------------|
| `init [dir]` | Initialize vault, generate owner keypair, install pre-commit hook |
| `add-agent <name>` | Create agent keypair with escrow backup |
| `remove-agent <name>` | Remove agent, re-encrypt secrets, warn about rotation |
| `list-agents` | List agents and their group memberships |
| `grant <agent> <group>` | Grant access, re-encrypt group secrets |
| `revoke <agent> <group>` | Revoke access, re-encrypt group secrets |
| `set <path> <value>` | Encrypt and store a secret |
| `set <path> --from-file <file>` | Store secret from file |
| `get <path> [--key <path>]` | Pull latest, decrypt, output to stdout |
| `list [--group <name>]` | List secrets with metadata |
| `check` | Audit for issues (expiring creds, orphaned secrets, etc.) |
| `recover-agent <name>` | Generate new keypair, re-encrypt secrets |
| `restore-agent <name> --to <path>` | Restore original key from escrow |

## How It Works

- **Owner key** (`~/.agent-vault/owner.key`) is the master key. Never committed. Back it up.
- **Agent keys** are generated per-agent, with an escrow copy encrypted to the owner.
- **Secrets** are age-encrypted for the owner + all authorized agents.
- **Access control** is managed via groups in `manifest.yaml`.
- **Git** is used as the sync/storage layer. All mutations auto-commit.

## Security

- Decrypted material is never written to disk
- Pre-commit hook blocks unencrypted key material
- `.gitignore` blocks `*.key`, `*.pem`, `**/private.*`
- Revocation re-encrypts affected secrets and warns about rotation
- Private keys get `chmod 600` on Unix

## Key Resolution

The `get` command resolves identity keys in this order:
1. `--key <path>` flag
2. `AGENT_VAULT_KEY` environment variable
3. `~/.agent-vault/owner.key` (default)

## Python SDK

Read-only SDK for agents to retrieve secrets programmatically.

```bash
pip install agent-vault
```

```python
from agent_vault import Vault

vault = Vault(
    repo_path="/path/to/vault",
    key_path="~/.agent-vault/agents/my-agent.key",
)
api_key = vault.get("stripe/api-key")
```

See [python-sdk/README.md](python-sdk/README.md) for full docs.

## MCP Server

Stdio-based MCP server so any MCP-compatible agent can request credentials through the standard tool-use protocol. The server holds the agent's private key in memory — the agent process never touches key material directly.

```bash
pip install 'agent-vault[mcp]'
agent-vault-mcp --repo /path/to/vault --key ~/.agent-vault/agents/my-agent.key
```

Exposes `agent_vault_get` and `agent_vault_list` tools. See [python-sdk/README.md](python-sdk/README.md) for Claude Desktop configuration.
