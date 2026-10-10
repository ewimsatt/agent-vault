# agent-vault Python SDK

Read-only Python SDK for [agent-vault](https://github.com/ewimsatt/agent-vault) — a zero-trust credential manager for AI agents.

## Installation

```bash
pip install agent-vault

# With MCP server support:
pip install 'agent-vault[mcp]'
```

## Quick Start

```python
from agent_vault import Vault

vault = Vault(
    repo_path="/path/to/vault",
    key_path="~/.agent-vault/agents/my-agent.key",
)

# Pull latest and decrypt
api_key = vault.get("stripe/api-key")
```

## Key Resolution

The SDK resolves the identity key in this order:

1. `key_str=` parameter (raw key string)
2. `key_path=` parameter (path to key file)
3. `AGENT_VAULT_KEY` environment variable (key as string)
4. `~/.agent-vault/owner.key` (default owner key)

## API

### `Vault(repo_path, key_path=None, key_str=None, auto_pull=True)`

Create a read-only vault connection.

- `repo_path`: Path to the Git repo containing `.agent-vault/`
- `key_path`: Path to an age private key file
- `key_str`: Raw age private key string
- `auto_pull`: Safely fast-forward from the checked-out branch's `origin` tracking branch before each `get()` (default: True). Dirty, untracked, or ignored files, and detached, missing-upstream, fetch-failed, local-ahead, or divergent checkouts raise `GitSyncError` instead of returning a possibly stale secret or overwriting a local ignored path. Set False only for an intentionally offline checkout you update yourself.

### `vault.get(secret_path) -> str`

Decrypt and return a secret. Raises `SecretNotFoundError` or `NotAuthorizedError`.

### `vault.list_secrets(group=None) -> list[SecretMetadata]`

List secret metadata without decrypting. It returns a complete, name-sorted view or raises `MetadataError` when any metadata record is malformed or unreadable; it never silently omits a record.

### `vault.list_agents() -> list[dict]`

List agents and their group memberships. Each call reloads the on-disk manifest, so long-lived clients observe the current local agent policy even when `auto_pull=False`; disabling automatic sync does not make policy reads stale.

### `vault.pull()`

Safely fast-forward from the `origin` tracking branch. Raises `GitSyncError` rather than reading stale state when synchronization is unsafe or fails.

### `vault.reload()`

Reload the manifest from disk (e.g., after a pull).

## MCP Server

The package includes an MCP server for use with MCP-compatible AI agents:

```bash
agent-vault-mcp --repo /path/to/vault --key ~/.agent-vault/agents/my-agent.key
```

This runs a stdio-based MCP server exposing:

- `agent_vault_get(secret)` — retrieve and decrypt a secret
- `agent_vault_list(group?)` — list available secrets

### Claude Desktop Configuration

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
