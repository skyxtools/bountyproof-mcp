"""Low-volume origin candidate discovery and explicit direct-origin verification."""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import re
import socket
import ssl
from collections import defaultdict
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .config import Settings
from .probe import HttpProbeClient
from .session import SessionPolicy


_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HINT_LABELS = ("origin", "direct", "backend", "server", "dev", "staging")


def _public_ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _extract_ips(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(_extract_ips(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_extract_ips(child))
    elif isinstance(value, str):
        candidate = value.strip()
        if _IP_RE.fullmatch(candidate):
            public = _public_ip(candidate)
            if public:
                found.add(public)
    return found


def _resolve(hostname: str) -> set[str]:
    try:
        records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {public for item in records if (public := _public_ip(item[4][0]))}


def _wildcard_bases(policy: SessionPolicy, hostname: str) -> list[str]:
    bases: list[str] = []
    for rule in policy.in_scope:
        if not rule.host_rule.startswith("*."):
            continue
        base = rule.host_rule[2:]
        if hostname == base or hostname.endswith(f".{base}"):
            bases.append(base)
    return sorted(set(bases), key=len, reverse=True)


class OriginService:
    def __init__(self, settings: Settings, policy: SessionPolicy):
        self.settings = settings
        self.policy = policy

    async def discover(self, target_url: str, current_ips: list[str]) -> dict[str, Any]:
        decision = self.policy.validate(target_url, resolve=True)
        hostname = decision.host
        edge_ips = {str(ipaddress.ip_address(item)) for item in current_ips if _public_ip(item)}
        evidence: dict[str, list[dict[str, str]]] = defaultdict(list)
        sources: list[dict[str, Any]] = []

        for base in _wildcard_bases(self.policy, hostname):
            for label in _HINT_LABELS:
                candidate_host = f"{label}.{base}"
                candidate_url = f"https://{candidate_host}/"
                try:
                    self.policy.validate(candidate_url, resolve=False)
                except ValueError:
                    continue
                addresses = await asyncio.to_thread(_resolve, candidate_host)
                sources.append(
                    {
                        "type": "in-scope-dns-hint",
                        "hostname": candidate_host,
                        "resolved_count": len(addresses),
                    }
                )
                for address in addresses - edge_ips:
                    evidence[address].append({"source": "in-scope-dns-hint", "hostname": candidate_host})

        historical_available = bool(self.settings.securitytrails_api_key)
        historical_error = ""
        if historical_available:
            endpoint = f"https://api.securitytrails.com/v1/history/{quote(hostname, safe='')}/dns/a"
            try:
                async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                    response = await client.get(endpoint, headers={"apikey": self.settings.securitytrails_api_key})
                    response.raise_for_status()
                    historical_ips = _extract_ips(response.json())
                for address in historical_ips - edge_ips:
                    evidence[address].append({"source": "securitytrails-historical-a", "hostname": hostname})
                sources.append(
                    {
                        "type": "securitytrails-historical-a",
                        "hostname": hostname,
                        "record_count": len(historical_ips),
                    }
                )
            except (httpx.HTTPError, ValueError) as exc:
                historical_error = f"{type(exc).__name__}: {exc}"

        candidates: list[dict[str, Any]] = []
        for address, items in evidence.items():
            source_names = {item["source"] for item in items}
            score = 0
            if "securitytrails-historical-a" in source_names:
                score += 50
            if "in-scope-dns-hint" in source_names:
                score += 30
            if len(items) > 1:
                score += min(20, (len(items) - 1) * 5)
            confidence = "medium" if score >= 50 else "low"
            candidates.append(
                {
                    "ip": address,
                    "score": score,
                    "confidence": confidence,
                    "evidence": items,
                    "is_current_edge_ip": False,
                    "status": "unverified-origin-candidate",
                }
            )
        candidates.sort(key=lambda item: (-item["score"], item["ip"]))
        return {
            "kind": "origin-discovery",
            "target": decision.normalized_url,
            "hostname": hostname,
            "current_edge_ips": sorted(edge_ips),
            "candidate_count": len(candidates),
            "candidates": candidates[:25],
            "sources": sources,
            "securitytrails_configured": historical_available,
            "securitytrails_error": historical_error,
            "classification": "candidate-only",
            "next_action": {
                "automatic_action": "none",
                "instruction": (
                    "Do not scan a candidate IP. First check whether direct-origin verification is explicitly "
                    "allowed by the session rules. If allowed, ask the user to approve one candidate and call "
                    "verify_origin_candidate. Otherwise stop and present the passive evidence only."
                ),
            },
        }

    async def verify(self, target_url: str, ip: str) -> dict[str, Any]:
        decision = self.policy.validate(target_url, resolve=True)
        parsed = urlsplit(decision.normalized_url)
        if parsed.scheme != "https" or decision.port != 443:
            raise ValueError("Direct-origin verification currently supports HTTPS on port 443 only")
        public_ip = _public_ip(ip)
        if not public_ip:
            raise ValueError("Origin candidate must be a public IP address")

        async with HttpProbeClient(self.settings) as client:
            edge = await client.fetch(
                probe_id="origin-edge-control",
                family="origin-verification",
                variant="edge-control",
                url=decision.normalized_url,
            )
        direct = await asyncio.to_thread(
            _direct_https_get,
            public_ip,
            decision.host,
            parsed.path or "/",
            parsed.query,
            self.settings.timeout_seconds,
            self.settings.max_body_bytes,
            self.settings.contact,
        )

        score = 0
        comparisons: dict[str, bool] = {}
        comparisons["tls_hostname_verified"] = bool(direct.get("tls_hostname_verified"))
        if comparisons["tls_hostname_verified"]:
            score += 2
        comparisons["status_equal"] = direct.get("status_code") == edge.status_code and edge.status_code is not None
        if comparisons["status_equal"]:
            score += 2
        comparisons["title_equal"] = bool(edge.title) and direct.get("title") == edge.title
        if comparisons["title_equal"]:
            score += 1
        edge_length = edge.body_length
        direct_length = int(direct.get("body_length") or 0)
        comparisons["body_length_similar"] = bool(edge_length) and 0.65 <= direct_length / edge_length <= 1.35
        if comparisons["body_length_similar"]:
            score += 1
        comparisons["server_header_equal"] = (
            bool(edge.headers.get("server"))
            and direct.get("headers", {}).get("server") == edge.headers.get("server")
        )
        if comparisons["server_header_equal"]:
            score += 1

        probable = not direct.get("error") and score >= 4
        return {
            "kind": "origin-verification",
            "target": decision.normalized_url,
            "hostname": decision.host,
            "candidate_ip": public_ip,
            "request_count": 2,
            "probable_origin": probable,
            "confidence_score": score,
            "comparisons": comparisons,
            "edge_observation": edge.to_dict(),
            "direct_observation": direct,
            "classification": "probable-origin" if probable else "not-confirmed",
            "next_action": {
                "automatic_action": "stop",
                "instruction": (
                    "Never pass the IP to scan_high_signal automatically. Show the evidence to the user and "
                    "re-check the program rules, provider ownership, and whether the raw IP is explicitly in "
                    "scope. If any point is unclear, stop. Additional testing requires a new explicit user decision."
                ),
            },
        }


def _direct_https_get(
    ip: str,
    hostname: str,
    path: str,
    query: str,
    timeout: float,
    max_body_bytes: int,
    contact: str,
) -> dict[str, Any]:
    request_path = path + (f"?{query}" if query else "")
    if any(ord(char) < 32 for char in request_path) or any(ord(char) < 32 for char in hostname):
        return {
            "status_code": None,
            "headers": {},
            "body_length": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "title": "",
            "tls_hostname_verified": False,
            "error": "Control characters are not allowed in the direct request target",
        }
    request_path = quote(request_path, safe="/?&=%+@!$'()*;,~-._:")
    contact = contact.replace("\r", "").replace("\n", "")
    request = (
        f"GET {request_path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"User-Agent: bountyproof-mcp/0.1 authorized-security-research (+{contact})\r\n"
        "Accept: text/html,application/json;q=0.9,*/*;q=0.5\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                tls_socket.sendall(request)
                response = bytearray()
                while len(response) < max_body_bytes + 65_536:
                    chunk = tls_socket.recv(min(65_536, max_body_bytes + 65_536 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
    except (OSError, ssl.SSLError) as exc:
        return {
            "status_code": None,
            "headers": {},
            "body_length": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "title": "",
            "tls_hostname_verified": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    header_bytes, separator, body = bytes(response).partition(b"\r\n\r\n")
    header_lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    status_code: int | None = None
    if header_lines:
        parts = header_lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.lower() in {"server", "content-type", "content-length", "via"}:
            headers[name.lower()] = value.strip()[:512]
    body = body[:max_body_bytes] if separator else b""
    text = body.decode("utf-8", errors="replace")
    title_match = _TITLE_RE.search(text)
    title = html.unescape(" ".join(title_match.group(1).split()))[:160] if title_match else ""
    sans = [value for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"]
    return {
        "status_code": status_code,
        "headers": headers,
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "title": title,
        "tls_hostname_verified": True,
        "certificate_sans": sans[:50],
        "tls_cipher": cipher[0] if cipher else "",
        "error": "",
    }
