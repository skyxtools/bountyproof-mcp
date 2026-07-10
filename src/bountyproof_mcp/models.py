"""Serializable HTTP observations kept independent from the MCP framework."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class Observation:
    probe_id: str
    family: str
    variant: str
    request_url: str
    status_code: int | None
    elapsed_ms: int
    body_length: int
    body_sha256: str
    title: str
    headers: dict[str, str]
    waf_signals: list[str]
    block_score: int
    blocked: bool
    error: str = ""
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
