"""FastMCP entrypoint for session-gated, authorized bug-bounty work."""

from __future__ import annotations

import argparse
from typing import Any, Literal
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from .auth import AuthProfileInput, AuthProfileStore, AuthorizationComparator
from .config import Settings
from .engine import PreflightEngine
from .origin import OriginService
from .pipeline import BountyPipeline, ExternalToolRunner, new_run_id, now
from .session import SessionPolicy, SessionStore
from .storage import ReportStore, render_markdown, safe_report_view
from .surface import SurfaceImporter


settings = Settings.from_env()
store = ReportStore(settings.report_dir)
sessions = SessionStore(settings.report_dir.parent / "sessions", settings)
auth_profiles = AuthProfileStore(settings.report_dir.parent / "auth-profiles")

mcp = FastMCP(
    "bountyproof-mcp",
    instructions=(
        "The first tool for every engagement is start_session. If scope, out-of-scope items, program rules, "
        "forbidden tests, rate limit, or authorization are missing, ask the user before calling it. Every other "
        "tool requires the returned session_id. Run preflight_target before live discovery or scanning. WAF/CDN "
        "signals are only time-cost gates, never findings. Origin candidates are passive leads: never scan a "
        "candidate IP automatically, and always obey the next_action returned by origin tools. Authorization "
        "comparison is GET-only, uses secret environment references, and must stop after differential evidence."
    ),
)


def _services(session_id: str) -> tuple[dict[str, Any], SessionPolicy, PreflightEngine, BountyPipeline, ExternalToolRunner]:
    session = sessions.load(session_id)
    policy = SessionPolicy(settings, session)
    runner = ExternalToolRunner(policy.settings)
    preflight = PreflightEngine(policy.settings)
    preflight.guard = policy  # Enforce path-level in-scope and out-of-scope rules.
    pipeline = BountyPipeline(policy.settings, runner)
    pipeline.guard = policy
    return session, policy, preflight, pipeline, runner


def _origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.scheme not in {"http", "https"}:
        return None
    return (
        parsed.scheme,
        parsed.hostname.lower().rstrip("."),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def _require_activity(session: dict[str, Any], activity: str) -> None:
    if activity not in session.get("allowed_activities", []):
        raise ValueError(f"Activity {activity!r} was not approved when this engagement session was created")


def _require_preflight(
    session_id: str,
    run_id: str,
    urls: list[str],
    *,
    override_guarded: bool,
) -> dict[str, Any]:
    report = store.load(run_id)
    if report.get("kind") != "preflight":
        raise ValueError("preflight_run_id does not reference a preflight report")
    if report.get("session_id") != session_id:
        raise ValueError("The preflight report belongs to a different engagement session")
    expected_origin = _origin(str(report.get("target", "")))
    if not expected_origin or any(_origin(url) != expected_origin for url in urls):
        raise ValueError("Every live-test URL must use the exact scheme, hostname, and port that passed preflight")
    gate = report.get("gate")
    if gate == "blocked":
        raise ValueError("Preflight gate is blocked; live automation is intentionally disabled for this target")
    if gate == "guarded" and not override_guarded:
        raise ValueError("Preflight gate is guarded; review the signals and set override_guarded=true to continue")
    if gate not in {"clear", "guarded"}:
        raise ValueError("Preflight report has an invalid gate state")
    return report


def _origin_preflight(session_id: str, run_id: str, target_url: str) -> dict[str, Any]:
    report = store.load(run_id)
    if report.get("kind") != "preflight" or report.get("session_id") != session_id:
        raise ValueError("preflight_run_id does not reference this session's preflight report")
    if _origin(str(report.get("target", ""))) != _origin(target_url):
        raise ValueError("Origin discovery target must use the same origin as the preflight report")
    return report


@mcp.tool()
def start_session(
    program_name: str,
    in_scope: list[str],
    out_of_scope: list[str],
    rules: str,
    allowed_activities: list[Literal["preflight", "discovery", "nuclei-scan", "verification"]],
    forbidden_tests: list[str],
    authorization_confirmed: bool,
    max_requests_per_second: int = 2,
) -> dict[str, Any]:
    """FIRST TOOL. Ask the user for every field before creating an engagement session; this sends no traffic."""
    return sessions.create(
        program_name=program_name,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        rules=rules,
        allowed_activities=allowed_activities,
        forbidden_tests=forbidden_tests,
        max_requests_per_second=max_requests_per_second,
        authorization_confirmed=authorization_confirmed,
    )


@mcp.tool()
def scope_check(session_id: str, url: str) -> dict[str, Any]:
    """Validate a URL against the active session's in-scope and out-of-scope rules without HTTP traffic."""
    session, policy, _, _, _ = _services(session_id)
    result = policy.validate(url, resolve=True).to_dict()
    result["session_id"] = session_id
    result["program_name"] = session["program_name"]
    return result


@mcp.tool()
async def preflight_target(session_id: str, url: str, samples: int = 3) -> dict[str, Any]:
    """Check friction before live testing: stability, latency, redirect, rate limit, and WAF/CDN hints."""
    session, _, preflight, _, runner = _services(session_id)
    _require_activity(session, "preflight")
    started_at = now()
    report = await preflight.run(url, samples=samples)
    report["run_id"] = new_run_id("preflight")
    report["session_id"] = session_id
    report["started_at"] = started_at
    report["finished_at"] = now()
    report["external_tools"] = runner.status()
    path = store.save(report)
    report["report_path"] = str(path.resolve())
    return report


@mcp.tool()
async def discover_surface(
    session_id: str,
    url: str,
    preflight_run_id: str,
    depth: int = 2,
    max_urls: int = 100,
    override_guarded: bool = False,
) -> dict[str, Any]:
    """Use Katana at the session rate limit after scope and preflight gates pass."""
    session, _, _, pipeline, _ = _services(session_id)
    _require_activity(session, "discovery")
    _require_preflight(session_id, preflight_run_id, [url], override_guarded=override_guarded)
    report = await pipeline.discover(url, depth=depth, max_urls=max_urls)
    report["session_id"] = session_id
    report["preflight_run_id"] = preflight_run_id
    path = store.save(report)
    report["report_path"] = str(path.resolve())
    return report


@mcp.tool()
async def scan_high_signal(
    session_id: str,
    urls: list[str],
    preflight_run_id: str,
    profile: Literal["critical-only", "high-signal"] = "high-signal",
    override_guarded: bool = False,
) -> dict[str, Any]:
    """Run HTTP-only Nuclei high/critical templates under session scope, rules, and rate limit."""
    session, _, _, pipeline, _ = _services(session_id)
    _require_activity(session, "nuclei-scan")
    _require_preflight(session_id, preflight_run_id, urls, override_guarded=override_guarded)
    report = await pipeline.scan(urls, profile=profile)
    report["session_id"] = session_id
    report["preflight_run_id"] = preflight_run_id
    path = store.save(report)
    result = safe_report_view(report)
    result["report_path"] = str(path.resolve())
    return result


@mcp.tool()
async def verify_finding(session_id: str, scan_run_id: str, finding_index: int, rounds: int = 2) -> dict[str, Any]:
    """Re-run one exact Nuclei template 2-3 times inside the same authorized session."""
    session, _, _, pipeline, _ = _services(session_id)
    _require_activity(session, "verification")
    scan_report = store.load(scan_run_id)
    if scan_report.get("kind") != "scan":
        raise ValueError("scan_run_id does not reference a scan report")
    if scan_report.get("session_id") != session_id:
        raise ValueError("The scan report belongs to a different engagement session")
    report = await pipeline.verify(scan_report, finding_index, rounds=rounds)
    report["session_id"] = session_id
    path = store.save(report)
    result = safe_report_view(report)
    result["report_path"] = str(path.resolve())
    return result


@mcp.tool()
def import_surface(
    session_id: str,
    file_path: str,
    input_format: Literal["auto", "har", "openapi", "postman"] = "auto",
    base_url: str = "",
) -> dict[str, Any]:
    """Import a local HAR/OpenAPI/Postman file; values are redacted and out-of-scope endpoints are rejected."""
    session, policy, _, _, _ = _services(session_id)
    _require_activity(session, "surface-import")
    importer = SurfaceImporter(policy.settings, policy)
    report = importer.import_file(file_path, input_format=input_format, base_url=base_url)
    report["run_id"] = new_run_id("surface")
    report["session_id"] = session_id
    report["created_at"] = now()
    path = store.save(report)
    result = safe_report_view(report)
    result["report_path"] = str(path.resolve())
    return result


@mcp.tool()
def register_auth_profiles(session_id: str, profiles: list[AuthProfileInput]) -> dict[str, Any]:
    """Register auth profile metadata and secret environment-variable names; actual credentials are never stored."""
    session = sessions.load(session_id)
    _require_activity(session, "authorization-testing")
    registered = auth_profiles.register(session_id, profiles)
    return {
        "kind": "auth-profile-registration",
        "session_id": session_id,
        "profile_count": len(registered),
        "profiles": registered,
        "note": "Only environment-variable names were stored. Credential values remain in the MCP process environment.",
    }


@mcp.tool()
async def compare_authorization(
    session_id: str,
    surface_run_id: str,
    endpoint_index: int,
    preflight_run_id: str,
    owner_profile: str,
    comparison_profiles: list[str],
    expected_policy: Literal["owner-only", "authenticated-only", "public"],
    rounds: int = 2,
    override_guarded: bool = False,
) -> dict[str, Any]:
    """Replay one imported GET as owner and 1-3 other profiles, twice, without changing IDs or request data."""
    session, policy, _, _, _ = _services(session_id)
    _require_activity(session, "authorization-testing")
    surface_report = store.load(surface_run_id)
    if surface_report.get("kind") != "surface-import" or surface_report.get("session_id") != session_id:
        raise ValueError("surface_run_id does not reference this session's imported surface")
    endpoints = surface_report.get("endpoints", [])
    if not isinstance(endpoints, list) or not 0 <= endpoint_index < len(endpoints):
        raise IndexError("endpoint_index is outside the stored surface")
    endpoint = endpoints[endpoint_index]
    if not isinstance(endpoint, dict) or not endpoint.get("replay_url"):
        raise ValueError("Selected endpoint is not replayable")
    _require_preflight(
        session_id,
        preflight_run_id,
        [str(endpoint["replay_url"])],
        override_guarded=override_guarded,
    )
    comparator = AuthorizationComparator(policy.settings, policy, auth_profiles)
    report = await comparator.compare(
        session_id=session_id,
        endpoint=endpoint,
        owner_profile=owner_profile,
        comparison_profiles=comparison_profiles,
        expected_policy=expected_policy,
        rounds=rounds,
    )
    report["run_id"] = new_run_id("authz")
    report["session_id"] = session_id
    report["surface_run_id"] = surface_run_id
    report["preflight_run_id"] = preflight_run_id
    report["created_at"] = now()
    path = store.save(report)
    result = safe_report_view(report)
    result["report_path"] = str(path.resolve())
    return result


@mcp.tool()
async def find_origin_candidates(
    session_id: str,
    target_url: str,
    preflight_run_id: str,
) -> dict[str, Any]:
    """Find unverified origin IP candidates using in-scope DNS hints and optional historical DNS; sends no IP traffic."""
    session, policy, _, _, _ = _services(session_id)
    _require_activity(session, "origin-discovery")
    preflight_report = _origin_preflight(session_id, preflight_run_id, target_url)
    service = OriginService(policy.settings, policy)
    current_ips = list(preflight_report.get("scope", {}).get("resolved_ips", []))
    report = await service.discover(target_url, current_ips)
    report["run_id"] = new_run_id("origin")
    report["session_id"] = session_id
    report["preflight_run_id"] = preflight_run_id
    report["created_at"] = now()
    path = store.save(report)
    report["report_path"] = str(path.resolve())
    return report


@mcp.tool()
async def verify_origin_candidate(
    session_id: str,
    origin_run_id: str,
    candidate_index: int,
    direct_request_confirmed: bool,
) -> dict[str, Any]:
    """After a fresh user decision, compare one HTTPS edge response with one direct-IP response using the target SNI/Host."""
    if not direct_request_confirmed:
        raise ValueError("Direct-origin verification requires explicit confirmation for this exact candidate")
    session, policy, _, _, _ = _services(session_id)
    _require_activity(session, "origin-verification")
    origin_report = store.load(origin_run_id)
    if origin_report.get("kind") != "origin-discovery" or origin_report.get("session_id") != session_id:
        raise ValueError("origin_run_id does not reference this session's origin discovery report")
    candidates = origin_report.get("candidates", [])
    if not isinstance(candidates, list) or not 0 <= candidate_index < len(candidates):
        raise IndexError("candidate_index is outside the stored origin candidates")
    candidate = candidates[candidate_index]
    if not isinstance(candidate, dict) or not candidate.get("ip"):
        raise ValueError("Stored origin candidate is malformed")
    service = OriginService(policy.settings, policy)
    report = await service.verify(str(origin_report["target"]), str(candidate["ip"]))
    report["run_id"] = new_run_id("origin-verify")
    report["session_id"] = session_id
    report["origin_run_id"] = origin_run_id
    report["candidate_index"] = candidate_index
    report["created_at"] = now()
    path = store.save(report)
    report["report_path"] = str(path.resolve())
    return report


@mcp.tool()
def get_report(
    session_id: str,
    run_id: str,
    output_format: Literal["json", "markdown"] = "markdown",
) -> dict[str, Any]:
    """Load a report only when it belongs to the active engagement session."""
    sessions.load(session_id)
    report = store.load(run_id)
    if report.get("session_id") != session_id:
        raise ValueError("The report belongs to a different engagement session")
    if output_format == "json":
        return {"format": "json", "report": safe_report_view(report)}
    return {"format": "markdown", "content": render_markdown(report)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the BountyProof MCP server")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    args = parser.parse_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
