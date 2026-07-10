"""Strict target allowlisting and SSRF-resistant URL validation."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .config import Settings


class ScopeError(ValueError):
    """Raised when a target is invalid or outside the configured scope."""


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    normalized_url: str
    host: str
    port: int
    resolved_ips: tuple[str, ...]
    matched_rule: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "port": self.port,
            "resolved_ips": list(self.resolved_ips),
            "matched_rule": self.matched_rule,
            "reason": self.reason,
        }


class ScopeGuard:
    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.rstrip(".").encode("idna").decode("ascii").lower()

    def _match_rule(self, host: str) -> str:
        for raw_rule in self.settings.allowed_hosts:
            rule = self._normalize_host(raw_rule.removeprefix("*."))
            if raw_rule.startswith("*."):
                if host.endswith(f".{rule}") and host != rule:
                    return raw_rule
            elif host == rule:
                return raw_rule
        return ""

    @staticmethod
    def _is_non_public(address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return not ip.is_global

    def validate(self, url: str, *, resolve: bool = True) -> ScopeDecision:
        parsed = urlsplit(url.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("Only http:// and https:// URLs are supported")
        if parsed.scheme == "http" and not self.settings.allow_http:
            raise ScopeError("Plain HTTP is disabled; set BOUNTYPROOF_ALLOW_HTTP=true only when in scope")
        if parsed.username or parsed.password:
            raise ScopeError("Credentials embedded in target URLs are not accepted")
        if not parsed.hostname:
            raise ScopeError("Target URL must include a hostname")
        if parsed.fragment:
            raise ScopeError("URL fragments are not sent to servers and are not accepted")

        host = self._normalize_host(parsed.hostname)
        matched_rule = self._match_rule(host)
        if not matched_rule:
            raise ScopeError(f"Host {host!r} is not in the active engagement session")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.settings.allowed_ports:
            raise ScopeError(f"Port {port} is not permitted by the active session/configuration")

        resolved_ips: tuple[str, ...] = ()
        if resolve:
            try:
                results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                resolved_ips = tuple(sorted({item[4][0] for item in results}))
            except socket.gaierror as exc:
                raise ScopeError(f"DNS resolution failed for {host}: {exc}") from exc
            if not self.settings.allow_private:
                private = [address for address in resolved_ips if self._is_non_public(address)]
                if private:
                    raise ScopeError(
                        "Target resolves to a non-public address; set BOUNTYPROOF_ALLOW_PRIVATE=true "
                        "only for an explicitly authorized lab"
                    )

        netloc = host
        default_port = 443 if parsed.scheme == "https" else 80
        if port != default_port:
            netloc = f"{host}:{port}"
        normalized = urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
        return ScopeDecision(True, normalized, host, port, resolved_ips, matched_rule, "Target is explicitly allowed")
