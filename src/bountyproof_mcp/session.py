"""Per-engagement scope/rules sessions collected before any network activity."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import Settings
from .scope import ScopeDecision, ScopeError, ScopeGuard


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _valid_session_id(session_id: str) -> bool:
    return bool(session_id) and all(char.isalnum() or char in "-_" for char in session_id)


@dataclass(frozen=True, slots=True)
class ScopeRule:
    raw: str
    scheme: str
    host_rule: str
    port: int | None
    path_prefix: str

    @classmethod
    def parse(cls, raw: str) -> "ScopeRule":
        value = raw.strip()
        if not value:
            raise ValueError("Scope entries cannot be empty")
        if "://" not in value:
            if "/" in value or "?" in value or "#" in value:
                raise ValueError(f"Host-only scope entry {value!r} cannot contain a path, query, or fragment")
            host_rule = value.lower().rstrip(".")
            cls._validate_host_rule(host_rule)
            return cls(raw=value, scheme="", host_rule=host_rule, port=None, path_prefix="/")

        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Invalid scope URL: {value!r}")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Scope URLs cannot contain credentials, query strings, or fragments")
        host_rule = parsed.hostname.lower().rstrip(".")
        cls._validate_host_rule(host_rule)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        return cls(raw=value, scheme=parsed.scheme, host_rule=host_rule, port=port, path_prefix=path)

    @staticmethod
    def _validate_host_rule(host_rule: str) -> None:
        base = host_rule.removeprefix("*.")
        if not base or "*" in base or any(char.isspace() for char in base):
            raise ValueError(f"Invalid host scope rule: {host_rule!r}")
        try:
            base.encode("idna")
        except UnicodeError as exc:
            raise ValueError(f"Invalid internationalized hostname: {host_rule!r}") from exc

    def matches(self, url: str) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        host = parsed.hostname.lower().rstrip(".")
        if self.host_rule.startswith("*."):
            base = self.host_rule[2:]
            host_matches = host.endswith(f".{base}") and host != base
        else:
            host_matches = host == self.host_rule
        if not host_matches:
            return False
        if self.scheme and parsed.scheme != self.scheme:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.port is not None and port != self.port:
            return False
        path = parsed.path or "/"
        return path.startswith(self.path_prefix)


class SessionPolicy:
    def __init__(self, base_settings: Settings, session: dict[str, Any]):
        self.session = session
        self.in_scope = [ScopeRule.parse(item) for item in session["in_scope"]]
        self.out_of_scope = [ScopeRule.parse(item) for item in session["out_of_scope"]]
        host_rules = tuple(sorted({rule.host_rule for rule in self.in_scope}))
        explicit_ports = {rule.port for rule in self.in_scope if rule.port is not None}
        ports = tuple(sorted(set(base_settings.allowed_ports) | explicit_ports))
        rate_limit = min(base_settings.nuclei_rate_limit, int(session["max_requests_per_second"]))
        self.settings = replace(
            base_settings,
            allowed_hosts=host_rules,
            allowed_ports=ports,
            nuclei_rate_limit=rate_limit,
        )
        self.guard = ScopeGuard(self.settings)

    def validate(self, url: str, *, resolve: bool = True) -> ScopeDecision:
        matching_out = next((rule for rule in self.out_of_scope if rule.matches(url)), None)
        if matching_out:
            raise ScopeError(f"URL matches out-of-scope rule: {matching_out.raw}")
        matching_in = next((rule for rule in self.in_scope if rule.matches(url)), None)
        if not matching_in:
            raise ScopeError("URL does not match any in-scope rule from the active session")
        return self.guard.validate(url, resolve=resolve)


class SessionStore:
    def __init__(self, directory: Path, base_settings: Settings):
        self.directory = directory
        self.base_settings = base_settings

    def create(
        self,
        *,
        program_name: str,
        in_scope: list[str],
        out_of_scope: list[str],
        rules: str,
        allowed_activities: list[str],
        forbidden_tests: list[str],
        max_requests_per_second: int,
        authorization_confirmed: bool,
    ) -> dict[str, Any]:
        if not authorization_confirmed:
            raise ValueError("Explicit authorization confirmation is required")
        if not program_name.strip():
            raise ValueError("program_name is required")
        if not in_scope:
            raise ValueError("At least one in-scope host or URL is required")
        if not rules.strip():
            raise ValueError("Program rules or a concise rule summary is required")
        valid_activities = {
            "preflight",
            "discovery",
            "nuclei-scan",
            "verification",
            "origin-discovery",
            "origin-verification",
            "surface-import",
            "authorization-testing",
        }
        unknown_activities = sorted(set(allowed_activities) - valid_activities)
        if unknown_activities:
            raise ValueError(f"Unknown allowed activities: {', '.join(unknown_activities)}")
        if not 1 <= max_requests_per_second <= 10:
            raise ValueError("max_requests_per_second must be between 1 and 10")
        parsed_in = [ScopeRule.parse(item) for item in in_scope]
        parsed_out = [ScopeRule.parse(item) for item in out_of_scope]
        if any(out.raw == inside.raw for inside in parsed_in for out in parsed_out):
            raise ValueError("The same exact entry cannot be both in scope and out of scope")

        session_id = f"session-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
        session = {
            "kind": "session",
            "session_id": session_id,
            "program_name": program_name.strip(),
            "created_at": _now(),
            "in_scope": [rule.raw for rule in parsed_in],
            "out_of_scope": [rule.raw for rule in parsed_out],
            "rules": rules.strip(),
            "allowed_activities": sorted(set(allowed_activities)),
            "forbidden_tests": sorted({item.strip() for item in forbidden_tests if item.strip()}),
            "max_requests_per_second": max_requests_per_second,
            "authorization_confirmed": True,
            "status": "active",
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{session_id}.json"
        path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
        session["session_path"] = str(path.resolve())
        return session

    def load(self, session_id: str) -> dict[str, Any]:
        if not _valid_session_id(session_id):
            raise ValueError("Invalid session_id")
        path = self.directory / f"{session_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Session {session_id!r} was not found")
        session = json.loads(path.read_text(encoding="utf-8"))
        if session.get("status") != "active" or not session.get("authorization_confirmed"):
            raise ValueError("Session is not active and authorized")
        return session

    def policy(self, session_id: str) -> SessionPolicy:
        return SessionPolicy(self.base_settings, self.load(session_id))
