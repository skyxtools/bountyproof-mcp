from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bountyproof_mcp.config import Settings
from bountyproof_mcp.scope import ScopeError
from bountyproof_mcp.session import SessionPolicy, SessionStore


class SessionTests(unittest.TestCase):
    def settings(self) -> Settings:
        return Settings(allowed_hosts=(), allowed_ports=(443,), delay_ms=0)

    def create_session(self, directory: Path) -> tuple[SessionStore, dict[str, object]]:
        store = SessionStore(directory, self.settings())
        session = store.create(
            program_name="Example BBP",
            in_scope=["https://app.example.com/api/", "*.assets.example.com"],
            out_of_scope=["https://app.example.com/api/admin/", "private.assets.example.com"],
            rules="Automated scanning is allowed at no more than two requests per second.",
            allowed_activities=["preflight", "discovery", "nuclei-scan", "verification"],
            forbidden_tests=["DoS", "brute force"],
            max_requests_per_second=2,
            authorization_confirmed=True,
        )
        return store, session

    def test_session_requires_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(Path(directory), self.settings())
            with self.assertRaises(ValueError):
                store.create(
                    program_name="Example",
                    in_scope=["example.com"],
                    out_of_scope=[],
                    rules="Testing allowed",
                    allowed_activities=["preflight"],
                    forbidden_tests=[],
                    max_requests_per_second=1,
                    authorization_confirmed=False,
                )

    def test_path_scope_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, session = self.create_session(Path(directory))
            policy = SessionPolicy(self.settings(), session)
            decision = policy.validate("https://app.example.com/api/users", resolve=False)
            self.assertTrue(decision.allowed)
            with self.assertRaises(ScopeError):
                policy.validate("https://app.example.com/other", resolve=False)

    def test_out_of_scope_wins_over_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, session = self.create_session(Path(directory))
            policy = SessionPolicy(self.settings(), session)
            with self.assertRaises(ScopeError):
                policy.validate("https://app.example.com/api/admin/users", resolve=False)
            with self.assertRaises(ScopeError):
                policy.validate("https://private.assets.example.com/", resolve=False)

    def test_session_rate_limit_reduces_runner_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, session = self.create_session(Path(directory))
            policy = SessionPolicy(self.settings(), session)
            self.assertEqual(policy.settings.nuclei_rate_limit, 2)


if __name__ == "__main__":
    unittest.main()
