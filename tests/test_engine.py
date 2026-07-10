from __future__ import annotations

import unittest

from bountyproof_mcp.config import Settings
from bountyproof_mcp.engine import PreflightEngine
from bountyproof_mcp.models import Observation


def observation(
    probe_id: str,
    *,
    status: int = 200,
    blocked: bool = False,
    signals: list[str] | None = None,
    headers: dict[str, str] | None = None,
    error: str = "",
) -> Observation:
    return Observation(
        probe_id=probe_id,
        family="preflight",
        variant="exact-url",
        request_url="https://example.com/",
        status_code=status,
        elapsed_ms=50,
        body_length=1000,
        body_sha256="0" * 64,
        title="Example",
        headers=headers or {"server": "origin"},
        waf_signals=signals or [],
        block_score=4 if blocked else 0,
        blocked=blocked,
        error=error,
    )


class FakeClient:
    def __init__(self, observations: list[Observation]):
        self.observations = iter(observations)

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def fetch(self, **_: object) -> Observation:
        return next(self.observations)


class PreflightTests(unittest.IsolatedAsyncioTestCase):
    def settings(self) -> Settings:
        return Settings(allowed_hosts=("example.com",), allowed_ports=(443,), delay_ms=0)

    async def test_clear_gate_for_stable_unprotected_target(self) -> None:
        fake = FakeClient([observation(f"p{i}") for i in range(3)])
        engine = PreflightEngine(self.settings(), client_factory=lambda: fake, resolve_scope=False)
        report = await engine.run("https://example.com/")
        self.assertEqual(report["gate"], "clear")
        self.assertEqual(report["recommended_action"], "proceed")

    async def test_waf_signal_is_guarded_not_a_finding(self) -> None:
        fake = FakeClient([observation(f"p{i}", signals=["cloudflare-edge"]) for i in range(3)])
        engine = PreflightEngine(self.settings(), client_factory=lambda: fake, resolve_scope=False)
        report = await engine.run("https://example.com/")
        self.assertEqual(report["gate"], "guarded")
        self.assertNotIn("findings", report)

    async def test_rate_limit_blocks_live_automation(self) -> None:
        fake = FakeClient(
            [observation(f"p{i}", status=429, headers={"retry-after": "30"}) for i in range(3)]
        )
        engine = PreflightEngine(self.settings(), client_factory=lambda: fake, resolve_scope=False)
        report = await engine.run("https://example.com/")
        self.assertEqual(report["gate"], "blocked")
        self.assertTrue(report["rate_limited"])


if __name__ == "__main__":
    unittest.main()
