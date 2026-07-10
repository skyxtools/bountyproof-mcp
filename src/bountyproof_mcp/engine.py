"""Low-volume preflight gate run before live bug-bounty testing."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from statistics import median
from urllib.parse import urljoin, urlsplit

from .config import Settings
from .models import Observation
from .probe import HttpProbeClient
from .scope import ScopeDecision, ScopeGuard


class PreflightEngine:
    def __init__(
        self,
        settings: Settings,
        *,
        client_factory: Callable[[], HttpProbeClient] | None = None,
        resolve_scope: bool = True,
    ):
        self.settings = settings
        self.guard = ScopeGuard(settings)
        self.client_factory = client_factory or (lambda: HttpProbeClient(settings))
        self.resolve_scope = resolve_scope

    def scope_check(self, url: str) -> ScopeDecision:
        return self.guard.validate(url, resolve=self.resolve_scope)

    async def _pause(self) -> None:
        if self.settings.delay_ms:
            await asyncio.sleep(self.settings.delay_ms / 1000)

    async def run(self, url: str, samples: int = 3) -> dict[str, object]:
        """Profile target friction only; this method never creates vulnerability findings."""
        decision = self.scope_check(url)
        samples = max(2, min(samples, 5))
        observations: list[Observation] = []
        async with self.client_factory() as client:
            for index in range(samples):
                observations.append(
                    await client.fetch(
                        probe_id=f"preflight-{index + 1}",
                        family="preflight",
                        variant="exact-url",
                        url=decision.normalized_url,
                    )
                )
                if index + 1 < samples:
                    await self._pause()

        healthy = [item for item in observations if not item.error]
        statuses = [item.status_code for item in healthy]
        signals = sorted({signal for item in healthy for signal in item.waf_signals})
        block_count = sum(item.blocked for item in healthy)
        rate_limited = any(item.status_code == 429 or "retry-after" in item.headers for item in healthy)
        stable_status = bool(statuses) and len(set(statuses)) == 1
        typical_latency_ms = round(median(item.elapsed_ms for item in healthy)) if healthy else None

        source_host = decision.host
        redirect_hosts: set[str] = set()
        for item in healthy:
            location = item.headers.get("location")
            if not location:
                continue
            redirected = urlsplit(urljoin(decision.normalized_url, location))
            if redirected.hostname and redirected.hostname.lower().rstrip(".") != source_host:
                redirect_hosts.add(redirected.hostname.lower().rstrip("."))

        reasons: list[str] = []
        if not healthy:
            gate = "blocked"
            reasons.append("All preflight requests failed")
        elif rate_limited:
            gate = "blocked"
            reasons.append("Rate limiting or Retry-After was observed during low-volume preflight")
        elif block_count >= max(2, samples - 1):
            gate = "blocked"
            reasons.append("Repeated challenge/block-page behavior was observed")
        elif signals or not stable_status or redirect_hosts or (typical_latency_ms or 0) > 5000:
            gate = "guarded"
            if signals:
                reasons.append("WAF/CDN/edge signals were detected")
            if not stable_status:
                reasons.append("Baseline status codes were unstable")
            if redirect_hosts:
                reasons.append("The target redirects to a different hostname")
            if (typical_latency_ms or 0) > 5000:
                reasons.append("Baseline latency is high and may waste live-test time")
        else:
            gate = "clear"
            reasons.append("No obvious friction was detected in the small preflight sample")

        return {
            "kind": "preflight",
            "target": decision.normalized_url,
            "host": decision.host,
            "scope": decision.to_dict(),
            "gate": gate,
            "recommended_action": {
                "clear": "proceed",
                "guarded": "review protection and program rules before continuing",
                "blocked": "stop automated live testing for this target",
            }[gate],
            "reasons": reasons,
            "request_count": len(observations),
            "stable_status": stable_status,
            "statuses": statuses,
            "typical_latency_ms": typical_latency_ms,
            "rate_limited": rate_limited,
            "block_count": block_count,
            "edge_or_waf_signals": signals,
            "redirect_hosts": sorted(redirect_hosts),
            "note": "WAF/CDN detection is a time-cost signal only and is never reported as a vulnerability.",
            "observations": [item.to_dict() for item in observations],
        }
