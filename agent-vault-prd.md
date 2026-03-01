# agent-vault: Product Requirements Document

## Overview

agent-vault is an open-source, zero-trust credential manager designed for AI agents. Secrets are encrypted locally and synced via Git. There is no server, no SaaS dependency, and no third-party trust required. The Git repository serves as the single source of truth for credentials, access policy, agent identity, and disaster recovery.

GitHub (or any Git provider) is treated as an untrusted encrypted blob store. All encryption and decryption happens locally. Even full compromise of the repository exposes nothing but encrypted data.

---

## Problem Statement

AI agents increasingly need access to APIs, databases, and third-party services. Today, credentials for these agents are managed through ad hoc methods: hardcoded values, `.env` files, or manual configuration per deployment. There is no standardized, agent-native approach to credential management that provides:

- Unique agent identity with scoped access
- Encrypted, version-controlled credential storage
- Zero-infrastructure self-hosted operation
- Owner-controlled recovery when agent keys are lost

---

## Design Principles

1. **Zero trust toward the Git provider.** All data stored in the repository is encrypted. The repo could be made public without exposing secrets.
2. **Self-contained.** The repository holds everything needed for management and recovery: encrypted secrets, agent public keys, escrowed private keys, and access policy.
3. **No infrastructure.** No daemon, no server, no database. The tool is a CLI and library that interacts with Git.
4. **Owner authority.** The repo owner (a human) has full governance. They provision agents, grant access, and can recover any agent's credentials via key escrow.
5. **Agent autonomy at runtime.** Once provisioned, agents retrieve and decrypt their own credentials without human intervention.

---

## Architecture

### Trust Model

The security model rests on two foundations:

- **The owner's private key.** This is the master key for the system. It never enters the repository. It lives on the owner's machine (file, OS keychain, hardware key, etc.). Loss of this key requires reprovisioning the entire vault.
- **Each agent's private key.** Generated during agent provisioning. Stored locally on the machine where the agent runs. Also stored in the repository as an escrow copy encrypted with the owner's public key, enabling recovery.

GitHub/Git sees only encrypted blobs and plaintext policy metadata. Compromise of the repository without the owner's key or an agent's private key yields no usable data.

### Key Escrow Model

When an agent is created, its private key is encrypted with the owner's public key and committed to the repository. This means:

- The owner can recover any agent's private key using their own key
- The owner can impersonate any agent (this is intentional and mirrors the sysadmin/service-account trust model: the person who provisioned the agent already has full authority)
- Agent recovery does not require re-encryption of all secrets; the original key can simply be restored to a new environment

### Encryption

The tool should use [age](https://age-encryption.org/) as the encryption layer. age is modern, audited, simple, and supports multi-recipient encryption natively.

- Secrets are encrypted using the `age` format
- Each secret is encrypted for all authorized agents (multi-recipient)
- Escrow files are encrypted for the owner (single-recipient)
- The Go reference implementation (`filippo.io/age`) or Rust implementation (`rage`) are preferred for the core tool
- Python bindings (`pyrage`) should be used for the SDK/library

---

## Repository Structure

```
.agent-vault/
  config.yaml              # vault configuration (age version, defaults)
  owner.pub                # owner's age public key (plaintext)
  manifest.yaml            # access control policy (plaintext, see below)
  agents/
    seo-crawler/
      public.key           # agent's age public key (plaintext)
      private.key.escrow   # agent's private key, encrypted with owner.pub
    billing-agent/
      public.key
      private.key.escrow
  secrets/
    stripe/
      api-key.enc          # encrypted secret value
      api-key.meta         # plaintext metadata (see below)
      webhook-secret.enc
      webhook-secret.meta
    postgres/
      connection-string.enc
      connection-string.meta
  .gitignore               # blocks any unencrypted key material
```

### manifest.yaml (Plaintext Access Policy)

```yaml
version: 1
owners:
  - name: eric
    public_key: owner.pub

agents:
  - name: seo-crawler
    groups: [stripe]
  - name: billing-agent
    groups: [stripe, postgres]

groups:
  - name: stripe
    secrets:
      - stripe/api-key
      - stripe/webhook-secret
  - name: postgres
    secrets:
      - postgres/connection-string
```

This file contains no secret material. It defines which agents can access which credential groups. Changes to this file should be the mechanism for granting or revoking access.

### Secret Metadata Files (Plaintext)

```yaml
name: stripe-api-key
group: stripe
created: 2026-02-20T14:30:00Z
rotated: 2026-02-25T10:00:00Z
expires: 2026-08-20T14:30:00Z
authorized_agents: [seo-crawler, billing-agent]
```

Metadata enables browsing and auditing the vault without decrypting anything. The tool should warn when credentials are approaching expiration.

---

## CLI Specification

### Initialization

```bash
agent-vault init [directory]
```

- Creates the `.agent-vault/` directory structure
- Generates the owner's age keypair
- Saves the owner's private key to `~/.agent-vault/owner.key` with `chmod 600`
- Commits the owner's public key and initial config to the repo
- Generates `.gitignore` with aggressive patterns to block unencrypted key material
- Installs a Git pre-commit hook that scans for unencrypted key material and blocks the commit if found
- Prints a warning that the owner key is the master recovery key and should be backed up

### Agent Management

```bash
agent-vault add-agent <name>
```

- Generates a new age keypair for the agent
- Saves the agent's private key to `~/.agent-vault/agents/<name>.key` with `chmod 600`
- Encrypts the agent's private key with the owner's public key and commits as `private.key.escrow`
- Commits the agent's public key to the repo
- Adds the agent to `manifest.yaml` with no group access (access must be explicitly granted)

```bash
agent-vault remove-agent <name>
```

- Removes the agent from `manifest.yaml`
- Removes the agent's key files from the repo
- Re-encrypts all secrets the agent previously had access to (excluding the removed agent's key)
- Prints a warning listing all credentials that should be rotated at the source, since the removed agent previously had access to the decrypted values

```bash
agent-vault list-agents
```

- Lists all agents with their group memberships

### Access Control

```bash
agent-vault grant <agent-name> <group>
```

- Adds the agent to the specified group in `manifest.yaml`
- Re-encrypts all secrets in that group to include the new agent as a recipient
- Commits the changes

```bash
agent-vault revoke <agent-name> <group>
```

- Removes the agent from the specified group in `manifest.yaml`
- Re-encrypts all secrets in that group without the revoked agent
- Commits the changes
- Prints a warning that the revoked agent previously had access to these secrets and they should be rotated at the source

### Secret Management

```bash
agent-vault set <path> <value> [--agents agent1,agent2] [--group group-name]
```

- Encrypts the value for all authorized agents (per manifest or per explicit flag)
- Creates/updates the `.enc` file and `.meta` file
- Commits to the repo

```bash
agent-vault set <path> --from-file <filepath>
```

- Same behavior, but reads the secret value from a file (useful for certificates, multi-line values)

```bash
agent-vault get <path>
```

- Pulls latest from Git
- Decrypts the secret using the caller's private key (owner or agent)
- Returns the plaintext value to stdout (never writes to disk)

```bash
agent-vault list [--group group-name]
```

- Lists all secrets with metadata (name, group, last rotated, expiration, authorized agents)
- Does not decrypt anything

```bash
agent-vault check
```

- Audits the vault for issues: expiring credentials, agents with no access, orphaned secrets, manifest inconsistencies

### Recovery

```bash
agent-vault recover-agent <name>
```

- Decrypts the agent's escrowed private key using the owner's key
- Generates a new keypair for the agent
- Re-encrypts all secrets for the new agent key
- Creates a new escrow file
- Commits the changes
- Outputs the new private key path for deployment

```bash
agent-vault restore-agent <name> --to <path>
```

- Decrypts the escrowed private key using the owner's key
- Writes the original private key to the specified path
- No re-encryption needed; the agent resumes with its original identity

### Multi-Owner (v2)

```bash
agent-vault add-owner <name> --key <path-to-public-key>
```

- Adds an additional owner public key
- Re-encrypts all escrow files for all owners
- Future: support threshold-based recovery (e.g., 2-of-3 owners required)

---

## Agent SDK / Library

Beyond the CLI, the tool should ship as a library that agents can import directly. Priority languages:

1. **Python** (highest priority due to agent ecosystem overlap)
2. **Node.js / TypeScript**
3. **Rust** (if the core is written in Rust)

### Python SDK Example

```python
from agent_vault import Vault

vault = Vault(
    repo_path="/path/to/vault",      # or a Git remote URL
    key_path="~/.agent-vault/agents/seo-crawler.key"
)

# Pull latest and decrypt
stripe_key = vault.get("stripe/api-key")

# Use it
stripe.api_key = stripe_key
```

The SDK should:

- Handle Git pull internally (fetch latest encrypted state)
- Decrypt in memory only (never write plaintext to disk)
- Raise clear errors if the agent is not authorized for a requested secret
- Support a read-only mode (agents cannot modify secrets)

---

## MCP Server Interface

An MCP (Model Context Protocol) server wrapper should be provided so any MCP-compatible agent can request credentials through the standard tool-use protocol.

The MCP server:

- Runs locally alongside the agent
- Holds the agent's private key in memory
- Handles Git sync and decryption
- Exposes a single tool:

```json
{
  "name": "agent_vault_get",
  "parameters": {
    "secret": "stripe/api-key"
  }
}
```

This creates a cleaner security boundary than direct library usage, as the agent process itself never touches the private key. The MCP server is the only process that holds key material.

---

## Private Key Storage

The agent's local private key is the one piece of the system that cannot be protected by the repository. The tool should support multiple storage backends, selectable during agent creation.

### Tier 1: File on Disk (Default)

- Stored at `~/.agent-vault/agents/<name>.key`
- Permissions set to `chmod 600`
- Relies on OS-level user isolation
- This is the SSH model and is the sensible default

### Tier 2: OS Keychain (Optional)

- macOS Keychain, Linux `secret-service` (GNOME Keyring / KWallet), Windows Credential Manager
- Selected via `agent-vault add-agent <name> --key-backend keychain`
- Key never exists as a raw file on disk

### Tier 3: TPM / Hardware-Backed (Optional)

- Private key generated inside the TPM and never extracted
- Crypto operations happen on the hardware
- Selected via `agent-vault add-agent <name> --key-backend tpm`
- Requires `tpm2-tss` / PKCS#11 support on the host
- Key is bound to the physical machine (non-extractable)
- Not available in all environments (containers, cheap VPS)

Regardless of backend, the escrow copy in the repository always exists as the recovery path.

---

## Security Requirements

### Pre-Commit Hook

The tool must install a Git pre-commit hook during `agent-vault init` that:

- Scans all staged files for unencrypted private key material (age private key headers, raw key patterns)
- Blocks the commit if any unencrypted key material is detected
- Can be bypassed with `--no-verify` (standard Git escape hatch, but the user accepts the risk)

### .gitignore

Generated during `init` with patterns including:

```
*.key
*.pem
**/private.*
!**/*.escrow
```

### Decrypted Material

The CLI and SDK must never write decrypted secret values to disk. All decryption returns values in memory or to stdout only.

### Revocation

When an agent's access is revoked or the agent is removed:

- All secrets the agent had access to are re-encrypted without the agent's key
- The tool prints an explicit warning that the secrets should be rotated at the source, since the agent previously held decrypted copies

---

## Credential Rotation

For v1, agents are read-only. They can retrieve secrets but cannot write new values back to the vault. Credential rotation is performed by a human (or CI job) via the CLI.

Future versions may support:

- Agents submitting rotation requests as pull requests
- Agents with write access pushing directly (requires careful trust model consideration)

---

## Technology Recommendations

### Core Tool

**Rust** is recommended for the core CLI:

- Single static binary with no runtime dependencies
- `rage` library (Rust implementation of age) is mature
- Strong security properties (memory safety)
- Easy distribution (one binary, no interpreter needed)
- Cross-platform compilation

**Go** is a viable alternative with similar single-binary distribution and the canonical `age` library.

### Python SDK

- Use `pyrage` bindings for age encryption
- Publish to PyPI as `agent-vault`
- Minimal dependencies

### MCP Server

- Implement as a lightweight process (Rust or Python)
- Communicate via stdio (standard MCP transport)
- Single-tool interface for credential retrieval

---

## Out of Scope for v1

- Multi-owner quorum / Shamir's Secret Sharing
- Agent write access to the vault
- Automated credential rotation
- Time-based access windows
- Secret versioning (beyond Git history)
- GUI / web interface
- Git LFS support for large vaults
- Non-Git storage backends

---

## Success Criteria

- A developer can install the tool, initialize a vault, provision an agent, and have that agent retrieve a credential in under 5 minutes
- Zero plaintext secrets exist in the repository at any point in its history
- An agent's lost key can be recovered using only the repository and the owner's key
- The tool operates with no network calls other than Git push/pull

---

## Open Items for Developer Discussion

1. **Git conflict resolution strategy.** Since each secret is a separate encrypted file, conflicts should be rare. But the tool should handle the case where two people update the manifest simultaneously.
2. **Repo history bloat.** Frequent re-encryption (on access changes) creates new encrypted blobs. At scale, Git history grows. Consider whether periodic history squashing or shallow clones should be documented as a maintenance practice.
3. **Secret size limits.** age handles arbitrary data sizes, but very large secrets (certificates, large config files) may warrant chunking or compression before encryption.
4. **CI/CD integration patterns.** Document how the tool works in GitHub Actions, GitLab CI, etc., where the agent's key might be injected via the CI platform's native secret storage.
