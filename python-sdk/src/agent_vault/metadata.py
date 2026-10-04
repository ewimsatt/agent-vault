"""Secret metadata parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from agent_vault.errors import MetadataError

_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


@dataclass
class SecretMetadata:
    """Plaintext metadata for a single secret."""

    name: str
    group: str
    created: datetime
    rotated: datetime
    expires: Optional[datetime]
    authorized_agents: list[str]

    @classmethod
    def load(cls, path: Path) -> "SecretMetadata":
        """Load a complete metadata record with RFC 3339 timestamps."""
        try:
            # BaseLoader preserves timestamp scalars as strings, avoiding YAML's
            # implicit timestamp coercion differences between quoted and unquoted input.
            with open(path, "r") as f:
                data = yaml.load(f, Loader=yaml.BaseLoader)
            if not isinstance(data, dict):
                raise ValueError("expected a mapping")
            authorized_agents = data.get("authorized_agents")
            if not isinstance(authorized_agents, list) or not all(
                isinstance(agent, str) for agent in authorized_agents
            ):
                raise ValueError("authorized_agents must be a list of strings")
            expires = data.get("expires")
            return cls(
                name=_required_string(data, "name"),
                group=_required_string(data, "group"),
                created=_parse_rfc3339(data.get("created"), "created"),
                rotated=_parse_rfc3339(data.get("rotated"), "rotated"),
                expires=_parse_rfc3339(expires, "expires") if expires is not None else None,
                authorized_agents=authorized_agents,
            )
        except (OSError, TypeError, ValueError, yaml.YAMLError) as error:
            raise MetadataError(f"invalid metadata file {path}: {error}") from error


def _required_string(data: dict, field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _parse_rfc3339(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError(f"{field} must be an RFC 3339 timestamp with a timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must be an RFC 3339 timestamp with a timezone")
    return parsed
