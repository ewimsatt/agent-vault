# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agent-vault is a zero-trust credential manager for AI agents. Secrets are encrypted locally using [age encryption](https://age-encryption.org/) and synced via Git. No server, no SaaS — the Git repo is an untrusted encrypted blob store. All crypto happens locally.

The PRD is in `agent-vault-prd.md` — refer to it for full specifications.

## Architecture

### Trust Model

Two key foundations:
- **Owner's private key** — master key, never enters the repo, lives at `~/.agent-vault/owner.key`
- **Agent private keys** — generated during provisioning, stored locally at `~/.agent-vault/agents/<name>.key`, with escrow copies encrypted to the owner's public key committed to the repo

### Repository Layout

All vault data lives under `.agent-vault/` in the target repo:
- `config.yaml` — vault config
- `owner.pub` — owner's age public key (plaintext)
- `manifest.yaml` — access control policy (plaintext, defines agent-to-group-to-secret mappings)
- `agents/<name>/public.key` + `private.key.escrow` — per-agent keys
- `secrets/<path>/<name>.enc` + `<name>.meta` — encrypted secrets with plaintext metadata

### Encryption Model

- Uses age format (multi-recipient encryption)
- Each secret is encrypted for all authorized agents
- Escrow files are encrypted for the owner only
- Preferred implementations: `rage` (Rust), `filippo.io/age` (Go), `pyrage` (Python)

### Key Design Rules

- Decrypted material is NEVER written to disk — memory or stdout only
- Revoking access requires re-encrypting all affected secrets without the revoked agent's key
- A pre-commit hook must block commits containing unencrypted private key material
- `.gitignore` blocks `*.key`, `*.pem`, `**/private.*` (but allows `*.escrow`)

## Deliverables

Three components to build:

1. **Core CLI** (Rust recommended, Go alternative) — `agent-vault init|add-agent|remove-agent|list-agents|grant|revoke|set|get|list|check|recover-agent|restore-agent`
2. **Python SDK** — library using `pyrage`, published as `agent-vault` on PyPI. Read-only agent access via `Vault` class with Git pull + in-memory decryption.
3. **MCP Server** — local stdio-based MCP server exposing `agent_vault_get` tool. Holds the agent's private key in memory so the agent process never touches key material directly.

## Key CLI Commands (from spec)

- `agent-vault init [dir]` — create vault, generate owner keypair, install pre-commit hook
- `agent-vault add-agent <name>` — generate agent keypair, create escrow, add to manifest with no access
- `agent-vault grant/revoke <agent> <group>` — modify access + re-encrypt affected secrets
- `agent-vault set <path> <value>` — encrypt and store a secret
- `agent-vault get <path>` — git pull, decrypt, output to stdout
- `agent-vault remove-agent <name>` — remove agent, re-encrypt all their secrets, warn about rotation
- `agent-vault recover-agent <name>` — decrypt escrow, generate new keypair, re-encrypt secrets
- `agent-vault check` — audit for expiring creds, orphaned secrets, manifest inconsistencies

## v1 Scope Boundaries

**In scope:** read-only agent access, file-based key storage (Tier 1), single owner, CLI + Python SDK + MCP server

**Out of scope:** multi-owner quorum, agent write access, automated rotation, time-based access, secret versioning, GUI, Git LFS, non-Git backends
