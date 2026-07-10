from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bountyproof_mcp.config import Settings
from bountyproof_mcp.session import SessionPolicy
from bountyproof_mcp.surface import SurfaceImporter


class SurfaceTests(unittest.TestCase):
    def test_har_import_redacts_values_and_rejects_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(allowed_hosts=(), allowed_ports=(443,), import_root=root, delay_ms=0)
            session = {
                "in_scope": ["https://api.example.com/v1/"],
                "out_of_scope": ["https://api.example.com/v1/admin/"],
                "max_requests_per_second": 2,
            }
            policy = SessionPolicy(settings, session)
            har = {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/v1/users/12345?token=secret&id=12345",
                                "headers": [{"name": "Authorization", "value": "Bearer secret"}],
                                "queryString": [
                                    {"name": "token", "value": "secret"},
                                    {"name": "id", "value": "12345"},
                                ],
                            }
                        },
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/v1/admin/users",
                                "headers": [],
                                "queryString": [],
                            }
                        },
                    ]
                }
            }
            path = root / "capture.har"
            path.write_text(json.dumps(har), encoding="utf-8")
            report = SurfaceImporter(settings, policy).import_file("capture.har")
            self.assertEqual(report["endpoint_count"], 1)
            self.assertEqual(report["rejected_out_of_scope"], 1)
            safe = report["safe_endpoints"][0]
            self.assertNotIn("secret", safe["url_template"])
            self.assertIn("<object-id>", safe["url_template"])
            self.assertEqual(set(safe["parameter_names"]), {"id", "token"})

    def test_import_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(allowed_hosts=(), allowed_ports=(443,), import_root=root, delay_ms=0)
            session = {"in_scope": ["example.com"], "out_of_scope": [], "max_requests_per_second": 1}
            importer = SurfaceImporter(settings, SessionPolicy(settings, session))
            with self.assertRaises((ValueError, FileNotFoundError)):
                importer.import_file(str(root.parent / "outside.har"))

    def test_openapi_yaml_import_marks_path_parameters_non_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(allowed_hosts=(), allowed_ports=(443,), import_root=root, delay_ms=0)
            session = {"in_scope": ["api.example.com"], "out_of_scope": [], "max_requests_per_second": 1}
            document = root / "openapi.yaml"
            document.write_text(
                "openapi: 3.0.0\nservers:\n  - url: https://api.example.com\npaths:\n"
                "  /v1/users/{id}:\n    get:\n      parameters:\n        - name: id\n          in: path\n",
                encoding="utf-8",
            )
            report = SurfaceImporter(settings, SessionPolicy(settings, session)).import_file("openapi.yaml")
            self.assertEqual(report["input_format"], "openapi")
            self.assertFalse(report["safe_endpoints"][0]["replayable"])

    def test_postman_base_url_is_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(allowed_hosts=(), allowed_ports=(443,), import_root=root, delay_ms=0)
            session = {"in_scope": ["api.example.com"], "out_of_scope": [], "max_requests_per_second": 1}
            collection = {
                "item": [
                    {
                        "name": "Me",
                        "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/v1/me"}, "header": []},
                    }
                ]
            }
            path = root / "collection.json"
            path.write_text(json.dumps(collection), encoding="utf-8")
            report = SurfaceImporter(settings, SessionPolicy(settings, session)).import_file(
                "collection.json", base_url="https://api.example.com"
            )
            self.assertEqual(report["input_format"], "postman")
            self.assertTrue(report["safe_endpoints"][0]["replayable"])


if __name__ == "__main__":
    unittest.main()
