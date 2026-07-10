from __future__ import annotations

import unittest

from bountyproof_mcp.config import Settings
from bountyproof_mcp.scope import ScopeError, ScopeGuard


class ScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        settings = Settings(
            allowed_hosts=("example.com", "*.example.com"),
            allowed_ports=(443,),
            delay_ms=0,
        )
        self.guard = ScopeGuard(settings)

    def test_exact_host_is_allowed(self) -> None:
        result = self.guard.validate("https://example.com/path", resolve=False)
        self.assertTrue(result.allowed)
        self.assertEqual(result.host, "example.com")

    def test_wildcard_subdomain_is_allowed(self) -> None:
        result = self.guard.validate("https://api.example.com/", resolve=False)
        self.assertEqual(result.matched_rule, "*.example.com")

    def test_suffix_confusion_is_denied(self) -> None:
        with self.assertRaises(ScopeError):
            self.guard.validate("https://example.com.attacker.test/", resolve=False)

    def test_http_is_denied_by_default(self) -> None:
        with self.assertRaises(ScopeError):
            self.guard.validate("http://example.com/", resolve=False)

    def test_embedded_credentials_are_denied(self) -> None:
        with self.assertRaises(ScopeError):
            self.guard.validate("https://user:pass@example.com/", resolve=False)


if __name__ == "__main__":
    unittest.main()
