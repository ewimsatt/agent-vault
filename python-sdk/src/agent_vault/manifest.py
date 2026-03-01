"""Manifest parsing for vault access control."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from agent_vault.errors import ManifestError


class Manifest:
    """Parsed manifest.yaml — access control policy."""

    def __init__(self, data: dict):
        self._data = data
        self._agents = {a["name"]: a for a in data.get("agents", [])}
        self._groups = {g["name"]: g for g in data.get("groups", [])}

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        """Load a manifest from a YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise ManifestError(f"Manifest not found: {path}")
        except yaml.YAMLError as e:
            raise ManifestError(f"Invalid manifest YAML: {e}")
        return cls(data)

    def agent_groups(self, agent_name: str) -> list[str]:
        """Return the list of groups an agent belongs to."""
        agent = self._agents.get(agent_name)
        if agent is None:
            return []
        return list(agent.get("groups", []))

    def group_secrets(self, group_name: str) -> list[str]:
        """Return the list of secret paths in a group."""
        group = self._groups.get(group_name)
        if group is None:
            return []
        return list(group.get("secrets", []))

    def agents_for_secret(self, secret_path: str) -> list[str]:
        """Return agent names authorized for a given secret."""
        agents = []
        for agent_name, agent in self._agents.items():
            for group_name in agent.get("groups", []):
                group = self._groups.get(group_name)
                if group and secret_path in group.get("secrets", []):
                    agents.append(agent_name)
                    break
        return agents

    def list_agents(self) -> list[dict]:
        """Return all agents with their group memberships."""
        return [
            {"name": a["name"], "groups": list(a.get("groups", []))}
            for a in self._data.get("agents", [])
        ]

    def list_groups(self) -> list[str]:
        """Return all group names."""
        return list(self._groups.keys())

    def list_secrets(self, group: Optional[str] = None) -> list[str]:
        """Return all secret paths, optionally filtered by group."""
        if group is not None:
            return self.group_secrets(group)
        secrets = []
        for g in self._groups.values():
            secrets.extend(g.get("secrets", []))
        return secrets
