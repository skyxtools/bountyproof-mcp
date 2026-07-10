from __future__ import annotations

import unittest

from bountyproof_mcp.pipeline import parse_jsonl, summarize_nuclei


class PipelineTests(unittest.TestCase):
    def test_jsonl_parser_keeps_valid_rows(self) -> None:
        rows, errors = parse_jsonl('{"url":"https://example.com/"}\nnot-json\n')
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(errors), 1)

    def test_nuclei_summary_has_stable_index(self) -> None:
        result = summarize_nuclei(
            {
                "template-id": "example-cve",
                "matched-at": "https://example.com/path",
                "info": {"name": "Example finding", "severity": "high"},
            },
            2,
        )
        self.assertEqual(result["finding_index"], 2)
        self.assertEqual(result["severity"], "high")


if __name__ == "__main__":
    unittest.main()
