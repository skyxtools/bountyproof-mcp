from __future__ import annotations

import unittest

from bountyproof_mcp.origin import _extract_ips, _public_ip, _wildcard_bases
from bountyproof_mcp.session import ScopeRule


class FakePolicy:
    def __init__(self) -> None:
        self.in_scope = [ScopeRule.parse("*.example.co.uk"), ScopeRule.parse("api.example.co.uk")]


class OriginTests(unittest.TestCase):
    def test_extract_ips_keeps_only_public_addresses(self) -> None:
        data = {"records": [{"values": [{"ip": "8.8.8.8"}, {"ip": "127.0.0.1"}]}]}
        self.assertEqual(_extract_ips(data), {"8.8.8.8"})

    def test_non_public_candidate_is_rejected(self) -> None:
        self.assertIsNone(_public_ip("10.0.0.1"))

    def test_wildcard_base_does_not_guess_public_suffix(self) -> None:
        bases = _wildcard_bases(FakePolicy(), "app.example.co.uk")
        self.assertEqual(bases, ["example.co.uk"])


if __name__ == "__main__":
    unittest.main()
