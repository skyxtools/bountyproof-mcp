"""Secret-reference auth profiles and repeatable GET-only authorization comparison."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from .config import Settings
from .session import SessionPolicy


AuthType = Literal["anonymous", "bearer", "cookie", "header"]
ExpectedPolicy = Literal["owner-only", "authenticated-only", "public"]
_PROFILE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}$")
_VOLATILE_KEYS = {
    "timestamp",
    "created_at",
    "updated_at",
    "request_id",
    "requestid",
    "trace_id",
    "traceid",
    "nonce",
}


class AuthProfileInput(BaseModel):
    name: str = Field(description="Short profile name, for example user_a, user_b, or anonymous")
    role: str = Field(description="Human-readable role such as owner, other-user, admin, or anonymous")
    auth_type: AuthType
    credential_env: str = Field(
        default="",
        description="Environment variable containing the secret. Never pass the actual token or cookie.",
    )
    header_name: str = Field(default="", description="Required only for auth_type=header")


def _canonical_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _canonical_json(child)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key).lower() not in _VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_canonical_json(child) for child in value]
    return value


def _json_shape(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(key): _json_shape(child, depth + 1) for key, child in sorted(value.items())}
    if isinstance(value, list):
        return [_json_shape(value[0], depth + 1)] if value else []
    if value is None:
        return "null"
    return type(value).__name__


def _digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AuthProfileStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def register(self, session_id: str, profiles: list[AuthProfileInput]) -> list[dict[str, Any]]:
        if not profiles:
            raise ValueError("At least one auth profile is required")
        session_dir = self.directory / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        registered: list[dict[str, Any]] = []
        seen: set[str] = set()
        for profile_input in profiles:
            profile = profile_input.model_dump()
            name = profile["name"]
            if not _PROFILE_RE.fullmatch(name) or name in seen:
                raise ValueError(f"Invalid or duplicate auth profile name: {name!r}")
            seen.add(name)
            auth_type = profile["auth_type"]
            credential_env = profile["credential_env"]
            header_name = profile["header_name"]
            role = str(profile["role"]).strip()
            if not role:
                raise ValueError(f"Profile {name!r} must include a role description")
            if auth_type == "anonymous":
                credential_env = ""
                header_name = ""
            else:
                if not _ENV_RE.fullmatch(credential_env):
                    raise ValueError(f"Profile {name!r} must reference a valid uppercase environment variable")
                if auth_type == "bearer":
                    header_name = "Authorization"
                elif auth_type == "cookie":
                    header_name = "Cookie"
                elif not _HEADER_RE.fullmatch(header_name):
                    raise ValueError(f"Profile {name!r} has an invalid header_name")
            stored = {
                "name": name,
                "role": role,
                "auth_type": auth_type,
                "credential_env": credential_env,
                "header_name": header_name,
            }
            path = session_dir / f"{name}.json"
            path.write_text(json.dumps(stored, indent=2), encoding="utf-8")
            registered.append({**stored, "credential_configured": bool(os.getenv(credential_env)) if credential_env else True})
        return registered

    def load(self, session_id: str, name: str) -> dict[str, Any]:
        if not _PROFILE_RE.fullmatch(name):
            raise ValueError("Invalid auth profile name")
        path = self.directory / session_id / f"{name}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Auth profile {name!r} was not found for this session")
        return json.loads(path.read_text(encoding="utf-8"))

    def resolve_headers(self, session_id: str, name: str) -> tuple[dict[str, str], dict[str, Any]]:
        profile = self.load(session_id, name)
        if profile["auth_type"] == "anonymous":
            return {}, profile
        env_name = profile["credential_env"]
        secret = os.getenv(env_name)
        if not secret:
            raise ValueError(f"Environment variable {env_name} is not set for profile {name!r}")
        if "\r" in secret or "\n" in secret:
            raise ValueError(f"Credential environment variable {env_name} contains control characters")
        value = f"Bearer {secret}" if profile["auth_type"] == "bearer" else secret
        return {profile["header_name"]: value}, profile


def compare_observations(owner: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    status_equal = owner.get("status_code") == other.get("status_code") and owner.get("status_code") is not None
    body_equal = owner.get("body_sha256") == other.get("body_sha256") and owner.get("body_length", 0) > 0
    canonical_equal = (
        bool(owner.get("json_canonical_sha256"))
        and owner.get("json_canonical_sha256") == other.get("json_canonical_sha256")
    )
    shape_equal = bool(owner.get("json_shape_sha256")) and owner.get("json_shape_sha256") == other.get(
        "json_shape_sha256"
    )
    owner_length = int(owner.get("body_length") or 0)
    other_length = int(other.get("body_length") or 0)
    length_similar = bool(owner_length) and 0.8 <= other_length / owner_length <= 1.2
    score = (1 if status_equal else 0) + (3 if body_equal or canonical_equal else 0)
    score += 1 if shape_equal else 0
    score += 1 if length_similar else 0
    return {
        "status_equal": status_equal,
        "body_equal": body_equal,
        "canonical_json_equal": canonical_equal,
        "json_shape_equal": shape_equal,
        "body_length_similar": length_similar,
        "strong_content_match": body_equal or canonical_equal,
        "score": score,
    }


def profile_expected_denied(expected_policy: ExpectedPolicy, auth_type: AuthType) -> bool:
    return expected_policy == "owner-only" or (expected_policy == "authenticated-only" and auth_type == "anonymous")


class AuthorizationComparator:
    def __init__(self, settings: Settings, policy: SessionPolicy, profile_store: AuthProfileStore):
        self.settings = settings
        self.policy = policy
        self.profile_store = profile_store

    async def compare(
        self,
        *,
        session_id: str,
        endpoint: dict[str, Any],
        owner_profile: str,
        comparison_profiles: list[str],
        expected_policy: ExpectedPolicy,
        rounds: int = 2,
    ) -> dict[str, Any]:
        method = str(endpoint.get("method", "")).upper()
        replay_url = str(endpoint.get("replay_url", ""))
        if method != "GET" or not endpoint.get("replayable") or not replay_url:
            raise ValueError("Authorization comparison v0.1 accepts only replayable GET endpoints")
        self.policy.validate(replay_url, resolve=True)
        if not comparison_profiles or len(comparison_profiles) > 3:
            raise ValueError("Provide between one and three comparison profiles")
        if owner_profile in comparison_profiles or len(set(comparison_profiles)) != len(comparison_profiles):
            raise ValueError("Owner and comparison profile names must be distinct")
        rounds = max(2, min(rounds, 3))

        owner_headers, owner_metadata = self.profile_store.resolve_headers(session_id, owner_profile)
        if owner_metadata["auth_type"] == "anonymous" and expected_policy != "public":
            raise ValueError("A restricted expected_policy requires a non-anonymous owner profile")
        comparison_data = [
            self.profile_store.resolve_headers(session_id, name) for name in comparison_profiles
        ]
        if expected_policy == "authenticated-only" and not any(
            metadata["auth_type"] == "anonymous" for _, metadata in comparison_data
        ):
            raise ValueError("authenticated-only comparison requires an anonymous profile")

        owner_observations: list[dict[str, Any]] = []
        for _ in range(rounds):
            owner_observations.append(await self._fetch(replay_url, owner_headers))
            await self._pause()

        comparisons: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        for profile_name, (headers, metadata) in zip(comparison_profiles, comparison_data, strict=True):
            observations: list[dict[str, Any]] = []
            round_matches: list[dict[str, Any]] = []
            for _ in range(rounds):
                observation = await self._fetch(replay_url, headers)
                observations.append(observation)
                best = max(
                    (compare_observations(owner, observation) for owner in owner_observations),
                    key=lambda item: item["score"],
                )
                round_matches.append(best)
                await self._pause()
            owner_success = all(_success(item.get("status_code")) for item in owner_observations)
            other_success = all(_success(item.get("status_code")) for item in observations)
            repeatable_strong_match = all(item["strong_content_match"] for item in round_matches)
            profile_should_be_denied = profile_expected_denied(expected_policy, metadata["auth_type"])
            violates_expectation = (
                profile_should_be_denied and owner_success and other_success and repeatable_strong_match
            )
            comparison = {
                "profile": profile_name,
                "role": metadata["role"],
                "auth_type": metadata["auth_type"],
                "observations": observations,
                "round_matches": round_matches,
                "violates_expected_policy": violates_expectation,
            }
            comparisons.append(comparison)
            if violates_expectation:
                candidates.append(
                    {
                        "profile": profile_name,
                        "role": metadata["role"],
                        "classification": "repeatable-authorization-candidate",
                        "confidence": "high" if all(item["body_equal"] for item in round_matches) else "medium",
                        "reason": (
                            "The comparison profile repeatedly received a successful response with the same "
                            "body or stable canonical JSON as the owner profile."
                        ),
                    }
                )

        return {
            "kind": "authorization-comparison",
            "method": method,
            "url_template": endpoint.get("url_template", ""),
            "endpoint_index": endpoint.get("endpoint_index"),
            "expected_policy": expected_policy,
            "rounds": rounds,
            "request_count": rounds * (1 + len(comparison_profiles)),
            "owner_profile": {
                "name": owner_profile,
                "role": owner_metadata["role"],
                "auth_type": owner_metadata["auth_type"],
                "observations": owner_observations,
            },
            "comparisons": comparisons,
            "candidate_count": len(candidates),
            "candidates": candidates,
            "classification": "candidate-found" if candidates else "no-repeatable-candidate",
            "next_action": {
                "automatic_action": "stop",
                "instruction": (
                    "Do not enumerate or modify object IDs automatically. Show the differential evidence to the "
                    "user, confirm that the compared profile should not access this exact object, and perform any "
                    "additional impact validation only after a new explicit decision."
                ),
            },
        }

    async def _pause(self) -> None:
        delay = max(self.settings.delay_ms / 1000, 1 / self.settings.nuclei_rate_limit)
        await asyncio.sleep(delay)

    async def _fetch(self, url: str, auth_headers: dict[str, str]) -> dict[str, Any]:
        contact = self.settings.contact.replace("\r", "").replace("\n", "")
        headers = {
            "User-Agent": f"bountyproof-mcp/0.1 authorized-security-research (+{contact})",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.5",
            "Cache-Control": "no-cache",
            **auth_headers,
        }
        started = time.perf_counter()
        body = bytearray()
        status: int | None = None
        selected_headers: dict[str, str] = {}
        error = ""
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                verify=self.settings.verify_tls,
                timeout=httpx.Timeout(self.settings.timeout_seconds),
            ) as client:
                async with client.stream("GET", url, headers=headers) as response:
                    status = response.status_code
                    selected_headers = {
                        key.lower(): value[:512]
                        for key, value in response.headers.items()
                        if key.lower() in {"content-type", "content-length", "location", "server", "etag"}
                    }
                    async for chunk in response.aiter_bytes():
                        remaining = self.settings.max_body_bytes - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"
        parsed_json: Any = None
        content_type = selected_headers.get("content-type", "")
        if "json" in content_type.lower() and body:
            try:
                parsed_json = json.loads(body.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed_json = None
        canonical_hash = _digest_json(_canonical_json(parsed_json)) if parsed_json is not None else ""
        shape_hash = _digest_json(_json_shape(parsed_json)) if parsed_json is not None else ""
        top_keys = sorted(str(key) for key in parsed_json)[:100] if isinstance(parsed_json, dict) else []
        return {
            "status_code": status,
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "json_canonical_sha256": canonical_hash,
            "json_shape_sha256": shape_hash,
            "json_top_level_keys": top_keys,
            "headers": selected_headers,
            "error": error,
        }


def _success(status: Any) -> bool:
    return isinstance(status, int) and 200 <= status < 300
