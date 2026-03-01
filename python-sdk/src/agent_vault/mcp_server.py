"""MCP server exposing agent_vault_get tool via stdio transport.

Usage:
    agent-vault-mcp --repo /path/to/vault --key ~/.agent-vault/agents/my-agent.key

The server holds the agent's private key in memory so the agent process
never touches key material directly.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def create_server(repo_path: str, key_path: str | None = None, key_str: str | None = None):
    """Create and configure the MCP server.

    Importing mcp is deferred so the module can be imported without the
    mcp extra installed (e.g., for type checking or vault-only usage).
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Error: MCP server requires the 'mcp' extra.\n"
            "Install with: pip install 'agent-vault[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)

    from agent_vault.vault import Vault

    vault = Vault(
        repo_path=repo_path,
        key_path=key_path,
        key_str=key_str,
        auto_pull=True,
    )

    mcp = FastMCP("agent-vault")

    @mcp.tool()
    def agent_vault_get(secret: str) -> str:
        """Retrieve a decrypted secret from the agent-vault.

        Args:
            secret: The secret path (e.g. "stripe/api-key").

        Returns:
            The decrypted plaintext value.
        """
        return vault.get(secret)

    @mcp.tool()
    def agent_vault_list(group: str | None = None) -> str:
        """List available secrets in the vault.

        Args:
            group: Optional group name to filter by.

        Returns:
            A formatted list of secrets with metadata.
        """
        secrets = vault.list_secrets(group)
        if not secrets:
            return "No secrets found."

        lines = []
        for meta in secrets:
            expires_str = ""
            if meta.expires:
                expires_str = f"  expires={meta.expires.strftime('%Y-%m-%d')}"
            lines.append(
                f"{meta.name}  group={meta.group}  "
                f"agents=[{', '.join(meta.authorized_agents)}]  "
                f"rotated={meta.rotated.strftime('%Y-%m-%d')}"
                f"{expires_str}"
            )
        return "\n".join(lines)

    return mcp


def main():
    """Entry point for the agent-vault-mcp command."""
    parser = argparse.ArgumentParser(
        description="MCP server for agent-vault credential retrieval"
    )
    parser.add_argument(
        "--repo",
        default=os.getcwd(),
        help="Path to the Git repository containing the vault (default: cwd)",
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Path to the agent's private key file",
    )
    args = parser.parse_args()

    # Also support AGENT_VAULT_KEY env var (key as string)
    key_str = os.environ.get("AGENT_VAULT_KEY")

    server = create_server(
        repo_path=args.repo,
        key_path=args.key,
        key_str=key_str if not args.key else None,
    )

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
