from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bountyproof_mcp.auth import (
    AuthProfileInput,
    AuthProfileStore,
    compare_observations,
    profile_expected_denied,
)


class AuthTests(unittest.TestCase):
    def test_profile_file_stores_reference_not_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"BOUNTY_USER_A_TOKEN": "super-secret-token"}
        ):
            store = AuthProfileStore(Path(directory))
            result = store.register(
                "session-test",
                [
                    AuthProfileInput(
                        name="user_a",
                        role="owner",
                        auth_type="bearer",
                        credential_env="BOUNTY_USER_A_TOKEN",
                    )
                ],
            )
            stored = (Path(directory) / "session-test" / "user_a.json").read_text(encoding="utf-8")
            self.assertNotIn("super-secret-token", stored)
            self.assertTrue(result[0]["credential_configured"])
            headers, _ = store.resolve_headers("session-test", "user_a")
            self.assertEqual(headers["Authorization"], "Bearer super-secret-token")

    def test_strong_match_requires_body_or_canonical_json(self) -> None:
        owner = {
            "status_code": 200,
            "body_length": 100,
            "body_sha256": "same",
            "json_canonical_sha256": "",
            "json_shape_sha256": "shape",
        }
        other = dict(owner)
        result = compare_observations(owner, other)
        self.assertTrue(result["strong_content_match"])
        other["body_sha256"] = "different"
        result = compare_observations(owner, other)
        self.assertFalse(result["strong_content_match"])

    def test_anonymous_profile_does_not_need_environment_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AuthProfileStore(Path(directory))
            store.register(
                "session-test",
                [AuthProfileInput(name="anonymous", role="anonymous", auth_type="anonymous")],
            )
            headers, profile = store.resolve_headers("session-test", "anonymous")
            self.assertEqual(headers, {})
            self.assertEqual(profile["credential_env"], "")

    def test_authenticated_only_policy_does_not_flag_other_authenticated_users(self) -> None:
        self.assertFalse(profile_expected_denied("authenticated-only", "bearer"))
        self.assertTrue(profile_expected_denied("authenticated-only", "anonymous"))
        self.assertTrue(profile_expected_denied("owner-only", "bearer"))


if __name__ == "__main__":
    unittest.main()
