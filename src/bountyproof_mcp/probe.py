"""Low-volume HTTP probing and conservative WAF/block-page classification."""

from __future__ import annotations

import hashlib
import html
import re
import time
from typing import Any

import httpx

from .config import Settings
from .models import Observation


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BLOCK_PHRASES = (
    "access denied",
    "request blocked",
    "the requested url was rejected",
    "web application firewall",
    "security policy",
    "malicious request",
    "incident id",
)


def fingerprint_edge(headers: dict[str, str], body: str) -> list[str]:
    """Return vendor/edge signals, never a vulnerability claim."""
    joined = "\n".join(f"{key}:{value}" for key, value in headers.items()).lower()
    body_lower = body.lower()
    signals: list[str] = []
    rules = {
        "cloudflare-edge": ("cf-ray", "cf-cache-status", "server:cloudflare", "__cf_bm"),
        "akamai-edge": ("akamai", "x-akamai", "ak_bmsc", "bm_sz"),
        "imperva-incapsula": ("x-iinfo", "visid_incap", "incap_ses", "incapsula"),
        "aws-cloudfront-edge": ("x-amz-cf-id", "x-amz-cf-pop", "server:cloudfront"),
        "f5-edge": ("x-wa-info", "bigipserver", "f5 trafficshield"),
        "sucuri-waf": ("x-sucuri", "sucuri/cloudproxy"),
        "fastly-edge": ("x-served-by", "x-timer", "server:fastly"),
        "azure-edge": ("x-azure-ref", "azure front door"),
    }
    haystack = f"{joined}\n{body_lower[:4096]}"
    for name, needles in rules.items():
        if any(needle in haystack for needle in needles):
            signals.append(name)
    return signals


def classify_block(status_code: int, headers: dict[str, str], body: str) -> tuple[int, bool, str]:
    score = 0
    if status_code in {403, 406, 409, 418, 429, 451, 503}:
        score += 2
    lowered_headers = {key.lower(): value.lower() for key, value in headers.items()}
    if lowered_headers.get("cf-mitigated") == "challenge" or "x-sucuri-block" in lowered_headers:
        score += 3
    body_lower = body.lower()
    matched = next((phrase for phrase in _BLOCK_PHRASES if phrase in body_lower), "")
    if matched:
        score += 2
    excerpt = ""
    if matched:
        index = body_lower.index(matched)
        excerpt = " ".join(body[max(0, index - 80) : index + 160].split())
    return score, score >= 3, excerpt[:240]


class HttpProbeClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        contact = settings.contact.replace("\r", "").replace("\n", "")
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            verify=settings.verify_tls,
            timeout=httpx.Timeout(settings.timeout_seconds),
            headers={
                "User-Agent": f"bountyproof-mcp/0.1 authorized-security-research (+{contact})",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
                "Cache-Control": "no-cache",
            },
        )

    async def __aenter__(self) -> "HttpProbeClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.client.aclose()

    async def fetch(self, *, probe_id: str, family: str, variant: str, url: str) -> Observation:
        started = time.perf_counter()
        status: int | None = None
        headers: dict[str, str] = {}
        body_bytes = bytearray()
        error = ""
        try:
            async with self.client.stream("GET", url) as response:
                status = response.status_code
                keep = {
                    "server",
                    "via",
                    "location",
                    "content-type",
                    "content-length",
                    "set-cookie",
                    "cf-ray",
                    "cf-cache-status",
                    "cf-mitigated",
                    "x-amz-cf-id",
                    "x-amz-cf-pop",
                    "x-iinfo",
                    "x-sucuri-id",
                    "x-sucuri-block",
                    "x-azure-ref",
                    "x-served-by",
                    "x-cache",
                    "retry-after",
                }
                headers = {key.lower(): value[:512] for key, value in response.headers.items() if key.lower() in keep}
                async for chunk in response.aiter_bytes():
                    remaining = self.settings.max_body_bytes - len(body_bytes)
                    if remaining <= 0:
                        break
                    body_bytes.extend(chunk[:remaining])
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"

        elapsed_ms = round((time.perf_counter() - started) * 1000)
        body = body_bytes.decode("utf-8", errors="replace")
        title_match = _TITLE_RE.search(body)
        title = html.unescape(" ".join(title_match.group(1).split()))[:160] if title_match else ""
        score, blocked, excerpt = classify_block(status or 0, headers, body)
        return Observation(
            probe_id=probe_id,
            family=family,
            variant=variant,
            request_url=url,
            status_code=status,
            elapsed_ms=elapsed_ms,
            body_length=len(body_bytes),
            body_sha256=hashlib.sha256(body_bytes).hexdigest(),
            title=title,
            headers=headers,
            waf_signals=fingerprint_edge(headers, body),
            block_score=score,
            blocked=blocked,
            error=error,
            excerpt=excerpt,
        )
