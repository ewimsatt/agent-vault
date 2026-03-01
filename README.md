# agent-vault

[![CI](https://github.com/ewimsatt/agent-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ewimsatt/agent-vault/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/agent-vault.svg)](https://crates.io/crates/agent-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Zero-trust credential manager for AI agents.**

Give your AI agents access to API keys, database passwords, and other secrets — without ever exposing the raw credentials in plaintext. Secrets are encrypted locally using [age encryption](https://age-encryption.org/) and synced via Git. No server, no SaaS, no third-party trust. The Git repo is just an encrypted blob store.

## Why agent-vault?

AI agents need credentials to call APIs, connect to databases, and interact with services. But giving an agent a raw API key is risky:

- **Keys leak into logs, prompts, and error messages.** Even well-designed agents can accidentally expose credentials.
- **Revoking access is hard.** If you share one key across agents, you can't cut off a single agent without rotating for everyone.
- **There's no audit trail.** You don't know which agent used which key, or when.

agent-vault solves this with a simple model:

1. **Each agent gets its own key.** Grant and revoke access per-agent, per-secret-group.
2. **Secrets stay encrypted at rest.** The Git repo only ever contains ciphertext. Decryption happens in memory, never touching disk.
3. **The owner controls everything.** One master key to rule them all — add agents, manage access, recover from compromise.
4. **Git is the sync layer.** Push, pull, branch, merge — use the Git workflows you already know.

## Quick Start

### Install

```bash
# From source
cargo install --path .

# Or from crates.io
cargo install agent-vault

# macOS (Homebrew)
brew install ewimsatt/tap/agent-vault
```

### Set up a vault

```bash
cd my-project
agent-vault init          # Creates .agent-vault/, generates owner key
agent-vault add-agent ci  # Creates a key for the "ci" agent

# Store a secret
agent-vault set stripe/api-key "sk_live_abc123"

# Grant the agent access to the "stripe" group
agent-vault grant ci stripe

# Retrieve as owner
agent-vault get stripe/api-key

# Retrieve as agent
agent-vault get stripe/api-key --key ~/.agent-vault/agents/ci.key
```

That's it. The agent can now decrypt `stripe/api-key` using its own key. If you revoke access later, the secret is re-encrypted without the agent's key — they lose access immediately.

---

## How It Works

### Trust Model

There are two types of keys:

| Key | Location | Purpose |
|-----|----------|---------|
| **Owner key** | `~/.agent-vault/owner.key` | Master key. Can decrypt everything. Never committed to Git. **Back this up.** |
| **Agent keys** | `~/.agent-vault/agents/<name>.key` | Per-agent keys. Can only decrypt secrets in groups they've been granted access to. |

Each agent also has an **escrow file** committed to the repo — the agent's private key encrypted to the owner's public key. If an agent key is lost, the owner can recover it.

### Encryption

Every secret is encrypted using [age](https://age-encryption.org/) multi-recipient encryption. The recipient list includes:

- The **owner's** public key (always)
- Every **agent** that has been granted access to the secret's group

When you `grant` or `revoke` access, agent-vault re-encrypts all affected secrets with the updated recipient list. When you `remove-agent`, all their secrets are re-encrypted without their key.

### Repository Layout

All vault data lives under `.agent-vault/` in your Git repo:

```
.agent-vault/
├── config.yaml              # Vault configuration
├── owner.pub                # Owner's public key (plaintext, safe to commit)
├── manifest.yaml            # Access control: agents → groups → secrets
├── agents/
│   └── my-agent/
│       ├── public.key       # Agent's public key
│       └── private.key.escrow  # Agent's private key, encrypted to owner
└── secrets/
    └── stripe/
        ├── api-key.enc      # Encrypted secret
        └── api-key.meta     # Plaintext metadata (name, group, timestamps)
```

### Security Guarantees

- Decrypted material is **never written to disk** — memory or stdout only
- A **pre-commit hook** blocks commits containing age private keys, PEM keys, RSA keys, EC keys, and OpenSSH keys
- `.gitignore` blocks `*.key`, `*.pem`, `**/private.*` (but allows `*.escrow`)
- Revocation **re-encrypts** affected secrets and warns about credential rotation
- Private key files get `chmod 600` on Unix

---

## CLI Reference

### Vault Management

| Command | Description |
|---------|-------------|
| `agent-vault init [dir]` | Initialize vault, generate owner keypair, install pre-commit hook |
| `agent-vault check [--json]` | Audit for expiring credentials, orphaned secrets, manifest inconsistencies |

### Agent Management

| Command | Description |
|---------|-------------|
| `agent-vault add-agent <name>` | Create agent keypair with escrow backup |
| `agent-vault remove-agent <name>` | Remove agent, re-encrypt all their secrets, warn about rotation |
| `agent-vault list-agents [--json]` | List agents and their group memberships |
| `agent-vault recover-agent <name>` | Generate new keypair from escrow, re-encrypt secrets |
| `agent-vault restore-agent <name> --to <path>` | Restore original key from escrow to a file |

### Secret Management

| Command | Description |
|---------|-------------|
| `agent-vault set <path> <value> [--agents a,b]` | Encrypt and store a secret |
| `agent-vault set <path> --from-file <file>` | Store secret from file |
| `agent-vault get <path> [--key <path>]` | Pull latest, decrypt, output to stdout |
| `agent-vault list [--group <name>] [--json]` | List secrets with metadata |

### Access Control

| Command | Description |
|---------|-------------|
| `agent-vault grant <agent> <group>` | Grant access, re-encrypt group secrets for the agent |
| `agent-vault revoke <agent> <group>` | Revoke access, re-encrypt group secrets without the agent |

### Utilities

| Command | Description |
|---------|-------------|
| `agent-vault completions <shell>` | Generate shell completions (bash, zsh, fish, powershell) |

### Key Resolution

The `get` command resolves identity keys in this order:

1. `--key <path>` flag
2. `AGENT_VAULT_KEY` environment variable (file path or raw `AGE-SECRET-KEY-...` string)
3. `~/.agent-vault/owner.key` (default)

---

## SDKs

### Python SDK

Read-only SDK for agents to retrieve secrets programmatically. Uses [pyrage](https://pypi.org/project/pyrage/) for age decryption.

```bash
pip install agent-vault
```

```python
from agent_vault import Vault

vault = Vault(
    repo_path="/path/to/vault",
    key_path="~/.agent-vault/agents/my-agent.key",
)

# Get a secret
api_key = vault.get("stripe/api-key")

# List secrets
for secret in vault.list_secrets(group="stripe"):
    print(f"{secret.name}  expires={secret.expires}")

# Works as a context manager
with Vault(repo_path="/path/to/vault") as vault:
    db_url = vault.get("postgres/conn")
```

Supports local paths and remote Git URLs:

```python
vault = Vault(repo_path="https://github.com/myorg/secrets.git")
```

### Node.js / TypeScript SDK

Read-only SDK using the [age-encryption](https://www.npmjs.com/package/age-encryption) package.

```bash
npm install agent-vault
```

```typescript
import { Vault } from "agent-vault";

const vault = new Vault({
  repoPath: "/path/to/vault",
  keyPath: "~/.agent-vault/agents/my-agent.key",
});

const apiKey = await vault.get("stripe/api-key");

const secrets = vault.listSecrets("stripe");
```

### Environment Variable

All SDKs (and the CLI) support the `AGENT_VAULT_KEY` environment variable:

```bash
export AGENT_VAULT_KEY="AGE-SECRET-KEY-1QFNZ..."

# Now no key path needed
python -c "from agent_vault import Vault; print(Vault('/path/to/vault').get('stripe/api-key'))"
```

---

## MCP Server

agent-vault ships an [MCP](https://modelcontextprotocol.io/) server so any MCP-compatible AI agent (Claude, etc.) can retrieve credentials through the standard tool-use protocol. The server holds the agent's private key in memory — the agent process never touches key material.

```bash
pip install 'agent-vault[mcp]'
agent-vault-mcp --repo /path/to/vault --key ~/.agent-vault/agents/my-agent.key
```

### Tools Exposed

| Tool | Description |
|------|-------------|
| `agent_vault_get(secret)` | Decrypt and return a secret |
| `agent_vault_list(group?)` | List available secrets with metadata |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "agent-vault-mcp",
      "args": ["--repo", "/path/to/vault", "--key", "/path/to/agent.key"]
    }
  }
}
```

### Claude Code Configuration

Add to your `.mcp.json` project config:

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "agent-vault-mcp",
      "args": ["--repo", "/path/to/vault", "--key", "/path/to/agent.key"]
    }
  }
}
```

---

## For AI Agents: Getting Started

If you're an AI agent (or a developer setting up an agent), here's what to do after installation:

### 1. Get your key

Your operator should have run `agent-vault add-agent <your-name>` and given you a key file. Store it at:

```
~/.agent-vault/agents/<your-name>.key
```

Or set the environment variable:

```bash
export AGENT_VAULT_KEY="AGE-SECRET-KEY-1..."
```

### 2. Access secrets

**Python:**
```python
from agent_vault import Vault

vault = Vault(repo_path="/path/to/vault")
api_key = vault.get("stripe/api-key")
```

**TypeScript:**
```typescript
import { Vault } from "agent-vault";
const vault = new Vault({ repoPath: "/path/to/vault" });
const apiKey = await vault.get("stripe/api-key");
```

**CLI:**
```bash
agent-vault get stripe/api-key
```

**MCP (no code needed):** If your operator configured the MCP server, just call the `agent_vault_get` tool with the secret path.

### 3. Handle errors

| Error | Meaning | What to do |
|-------|---------|------------|
| `SecretNotFoundError` | Secret path doesn't exist | Check the path, ask operator to create the secret |
| `NotAuthorizedError` | Your key can't decrypt this secret | Ask operator to grant you access to the group |
| `VaultNotFoundError` | No vault at the repo path, or no key configured | Check repo path and key configuration |

### 4. Best practices

- **Never log or print decrypted secrets.** Access them, use them, discard them.
- **Don't cache secrets in files.** Re-read from the vault each time.
- **Use `auto_pull=True` (the default)** to get the latest secrets on each access.
- **Handle `NotAuthorizedError` gracefully.** Your access may be revoked at any time.

---

## Deployment Examples

### Docker

```dockerfile
FROM python:3.12-slim
RUN pip install agent-vault
COPY . /app
WORKDIR /app
CMD ["python", "agent.py"]
```

```bash
docker run \
  -e AGENT_VAULT_KEY="$(cat ~/.agent-vault/agents/my-agent.key)" \
  -v /path/to/vault:/vault:ro \
  my-agent
```

```python
# agent.py
from agent_vault import Vault

vault = Vault(repo_path="/vault")
api_key = vault.get("stripe/api-key")
```

### GitHub Actions

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install agent-vault
      - run: |
          SECRET=$(python -c "
            from agent_vault import Vault
            v = Vault(repo_path='.', auto_pull=False)
            print(v.get('deploy/token'))
          ")
          echo "::add-mask::$SECRET"
          echo "DEPLOY_TOKEN=$SECRET" >> "$GITHUB_ENV"
        env:
          AGENT_VAULT_KEY: ${{ secrets.AGENT_VAULT_KEY }}
```

### CI/CD with CLI

```bash
export AGENT_VAULT_KEY="$VAULT_KEY"
DB_PASSWORD=$(agent-vault get postgres/password)
API_KEY=$(agent-vault get stripe/api-key)
./deploy.sh
```

---

## Development

### Building from source

```bash
# Rust CLI
cargo build
cargo test

# Python SDK
cd python-sdk
pip install -e '.[dev]'
pytest -v

# Node.js SDK
cd node-sdk
npm install
npm run build
```

### Running all tests

```bash
# Build the CLI first (Python tests use it)
cargo build

# Run everything
cargo test && (cd python-sdk && pytest -v)
```

### Shell Completions

```bash
# Bash
agent-vault completions bash > ~/.local/share/bash-completion/completions/agent-vault

# Zsh
agent-vault completions zsh > ~/.zfunc/_agent-vault

# Fish
agent-vault completions fish > ~/.config/fish/completions/agent-vault.fish
```

---

## License

[MIT](LICENSE)
