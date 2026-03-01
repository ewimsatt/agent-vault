"""Secret metadata parsing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml


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
        """Load metadata from a .meta YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        return cls(
            name=data.get("name", ""),
            group=data.get("group", ""),
            created=_parse_dt(data.get("created")),
            rotated=_parse_dt(data.get("rotated")),
            expires=_parse_dt(data.get("expires")) if data.get("expires") else None,
            authorized_agents=list(data.get("authorized_agents", [])),
        )


def _parse_dt(val) -> datetime:
    """Parse a datetime from YAML (may be string or datetime)."""
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        return datetime.fromisoformat(val)
    return datetime.min
