from __future__ import annotations

import unittest

from bountyproof_mcp.probe import classify_block, fingerprint_edge


class ProbeTests(unittest.TestCase):
    def test_status_alone_does_not_overclaim_block(self) -> None:
        score, blocked, _ = classify_block(403, {}, "ordinary forbidden page")
        self.assertEqual(score, 2)
        self.assertFalse(blocked)

    def test_block_page_phrase_and_status_are_evidence(self) -> None:
        score, blocked, excerpt = classify_block(403, {}, "Your request was blocked by a security policy")
        self.assertGreaterEqual(score, 4)
        self.assertTrue(blocked)
        self.assertIn("security policy", excerpt)

    def test_cloudflare_signal_is_informational(self) -> None:
        signals = fingerprint_edge({"server": "cloudflare", "cf-ray": "abc"}, "")
        self.assertIn("cloudflare-edge", signals)


if __name__ == "__main__":
    unittest.main()
