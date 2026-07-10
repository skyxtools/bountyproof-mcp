"""Local evidence storage. The report directory is intentionally gitignored."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def save(self, report: dict[str, Any]) -> Path:
        run_id = str(report.get("run_id", ""))
        self._validate_run_id(run_id)
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{run_id}.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def load(self, run_id: str) -> dict[str, Any]:
        self._validate_run_id(run_id)
        path = self.directory / f"{run_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Report {run_id!r} was not found")
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _validate_run_id(run_id: str) -> None:
        if not run_id or not all(char.isalnum() or char in "-_" for char in run_id):
            raise ValueError("Invalid run_id")


def render_markdown(report: dict[str, Any]) -> str:
    kind = report.get("kind", "report")
    lines = [f"# BountyProof {kind}: {report.get('run_id', 'unknown')}", ""]
    if kind == "preflight":
        lines.extend(
            [
                f"- Target: `{report.get('target', '')}`",
                f"- Gate: **{report.get('gate', 'unknown')}**",
                f"- Action: {report.get('recommended_action', '')}",
                f"- WAF/CDN signals: {', '.join(report.get('edge_or_waf_signals', [])) or 'none'}",
                "",
                "## Reasons",
                "",
            ]
        )
        lines.extend(f"- {reason}" for reason in report.get("reasons", []))
    elif kind == "discovery":
        lines.extend([f"- Target: `{report.get('target', '')}`", f"- URLs: {report.get('url_count', 0)}", ""])
        lines.extend(f"- `{url}`" for url in report.get("urls", []))
    elif kind == "scan":
        lines.extend(
            [
                f"- Profile: `{report.get('profile', '')}`",
                f"- Candidate findings: {report.get('finding_count', 0)}",
                "",
                "## Candidates",
                "",
            ]
        )
        for finding in report.get("finding_summaries", []):
            lines.extend(
                [
                    f"### #{finding.get('finding_index')} — {finding.get('name') or finding.get('template_id')}",
                    "",
                    f"- Severity: **{finding.get('severity', 'unknown')}**",
                    f"- Template: `{finding.get('template_id', '')}`",
                    f"- Matched at: `{finding.get('matched_at', '')}`",
                    "",
                ]
            )
    elif kind == "verification":
        candidate = report.get("candidate", {})
        lines.extend(
            [
                f"- Verified: **{report.get('verified', False)}**",
                f"- Classification: `{report.get('classification', '')}`",
                f"- Template: `{candidate.get('template_id', '')}`",
                f"- Matched at: `{candidate.get('matched_at', '')}`",
                f"- Repetitions: {report.get('rounds', 0)}",
                "",
            ]
        )
    elif kind == "origin-discovery":
        lines.extend(
            [
                f"- Target: `{report.get('target', '')}`",
                f"- Current edge IPs: {', '.join(report.get('current_edge_ips', [])) or 'none'}",
                f"- Unverified candidates: {report.get('candidate_count', 0)}",
                "",
                "## Origin candidates",
                "",
            ]
        )
        for index, candidate in enumerate(report.get("candidates", [])):
            lines.extend(
                [
                    f"### #{index}: `{candidate.get('ip', '')}`",
                    "",
                    f"- Confidence: **{candidate.get('confidence', 'low')}**",
                    f"- Score: {candidate.get('score', 0)}",
                    f"- Status: `{candidate.get('status', '')}`",
                    "",
                ]
            )
    elif kind == "origin-verification":
        lines.extend(
            [
                f"- Target: `{report.get('target', '')}`",
                f"- Candidate IP: `{report.get('candidate_ip', '')}`",
                f"- Probable origin: **{report.get('probable_origin', False)}**",
                f"- Confidence score: {report.get('confidence_score', 0)}",
                f"- Classification: `{report.get('classification', '')}`",
                "",
                "> Automatic scanning must stop after this result.",
                "",
            ]
        )
    elif kind == "surface-import":
        lines.extend(
            [
                f"- Format: `{report.get('input_format', '')}`",
                f"- Endpoints: {report.get('endpoint_count', 0)}",
                f"- Replayable GET endpoints: {report.get('replayable_get_count', 0)}",
                f"- Rejected out-of-scope: {report.get('rejected_out_of_scope', 0)}",
                "",
                "## Safe endpoint map",
                "",
            ]
        )
        for endpoint in report.get("safe_endpoints", []):
            lines.append(
                f"- #{endpoint.get('endpoint_index')} `{endpoint.get('method')}` "
                f"`{endpoint.get('url_template')}`"
            )
    elif kind == "authorization-comparison":
        lines.extend(
            [
                f"- Endpoint: `{report.get('method', '')} {report.get('url_template', '')}`",
                f"- Expected policy: `{report.get('expected_policy', '')}`",
                f"- Rounds: {report.get('rounds', 0)}",
                f"- Candidates: {report.get('candidate_count', 0)}",
                f"- Classification: `{report.get('classification', '')}`",
                "",
                "## Authorization candidates",
                "",
            ]
        )
        for candidate in report.get("candidates", []):
            lines.extend(
                [
                    f"### {candidate.get('profile', '')} ({candidate.get('role', '')})",
                    "",
                    f"- Confidence: **{candidate.get('confidence', '')}**",
                    f"- Classification: `{candidate.get('classification', '')}`",
                    f"- Reason: {candidate.get('reason', '')}",
                    "",
                ]
            )
    if report.get("note"):
        lines.extend(["", f"> {report['note']}", ""])
    return "\n".join(lines)


def safe_report_view(report: dict[str, Any]) -> dict[str, Any]:
    """Remove raw Nuclei request/response material from MCP responses; it remains local."""
    if report.get("kind") == "scan":
        return {key: value for key, value in report.items() if key != "findings"}
    if report.get("kind") == "verification":
        safe = dict(report)
        safe["attempts"] = [
            {key: value for key, value in attempt.items() if key != "matches"}
            for attempt in report.get("attempts", [])
        ]
        return safe
    if report.get("kind") == "surface-import":
        safe = {key: value for key, value in report.items() if key not in {"endpoints", "source_file"}}
        safe["endpoints"] = report.get("safe_endpoints", [])
        safe.pop("safe_endpoints", None)
        return safe
    return report
