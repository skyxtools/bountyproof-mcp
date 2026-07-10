"""Fixed-argument adapters for Katana discovery and high-signal Nuclei checks."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import Settings
from .scope import ScopeGuard


_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")


def new_run_id(prefix: str) -> str:
    import secrets

    return f"{prefix}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"


def now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class ExternalToolRunner:
    """Runs only argument arrays; no shell strings or user-controlled flags are accepted."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def resolve(configured: str) -> str | None:
        return shutil.which(configured) or (str(Path(configured).resolve()) if Path(configured).is_file() else None)

    def status(self) -> dict[str, dict[str, object]]:
        katana = self.resolve(self.settings.katana_bin)
        nuclei = self.resolve(self.settings.nuclei_bin)
        return {
            "katana": {"available": bool(katana), "path": katana or ""},
            "nuclei": {"available": bool(nuclei), "path": nuclei or ""},
        }

    async def run(self, arguments: list[str], timeout: int | None = None) -> CommandResult:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout or self.settings.command_timeout_seconds
            )
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return CommandResult(
                returncode=process.returncode or -1,
                stdout=stdout.decode("utf-8", errors="replace")[:10_000_000],
                stderr=stderr.decode("utf-8", errors="replace")[:200_000],
                timed_out=True,
            )
        return CommandResult(
            returncode=process.returncode or 0,
            stdout=stdout.decode("utf-8", errors="replace")[:10_000_000],
            stderr=stderr.decode("utf-8", errors="replace")[:200_000],
        )


def parse_jsonl(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: {exc.msg}")
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows, errors


def _candidate_urls(value: Any, *, key: str = "") -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            urls.extend(_candidate_urls(child, key=str(child_key).lower()))
    elif isinstance(value, list):
        for child in value:
            urls.extend(_candidate_urls(child, key=key))
    elif isinstance(value, str) and key in {"url", "endpoint", "source", "request-url"}:
        if value.startswith(("http://", "https://")):
            urls.append(value)
    return urls


def summarize_nuclei(item: dict[str, Any], index: int) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    return {
        "finding_index": index,
        "template_id": item.get("template-id") or item.get("template_id") or "",
        "name": info.get("name") or item.get("name") or "",
        "severity": info.get("severity") or item.get("severity") or "unknown",
        "matched_at": item.get("matched-at") or item.get("matched_at") or item.get("host") or "",
        "matcher_name": item.get("matcher-name") or item.get("matcher_name") or "",
        "type": item.get("type") or "http",
        "timestamp": item.get("timestamp") or "",
    }


class BountyPipeline:
    def __init__(self, settings: Settings, runner: ExternalToolRunner | None = None, *, resolve_scope: bool = True):
        self.settings = settings
        self.guard = ScopeGuard(settings)
        self.runner = runner or ExternalToolRunner(settings)
        self.resolve_scope = resolve_scope

    async def discover(self, url: str, *, depth: int = 2, max_urls: int = 100) -> dict[str, Any]:
        decision = self.guard.validate(url, resolve=self.resolve_scope)
        binary = self.runner.resolve(self.settings.katana_bin)
        if not binary:
            raise FileNotFoundError("Katana is not installed or BOUNTYPROOF_KATANA_BIN is incorrect")
        depth = max(1, min(depth, 3))
        max_urls = max(1, min(max_urls, self.settings.max_urls))
        rate_limit = min(2, self.settings.nuclei_rate_limit)
        arguments = [
            binary,
            "-u",
            decision.normalized_url,
            "-d",
            str(depth),
            "-fs",
            "fqdn",
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-rl",
            str(rate_limit),
            "-c",
            "1",
            "-p",
            "1",
            "-ct",
            "60s",
        ]
        started_at = now()
        result = await self.runner.run(arguments)
        rows, parse_errors = parse_jsonl(result.stdout)
        discovered: list[str] = []
        seen: set[str] = set()
        for row in rows:
            for candidate in _candidate_urls(row):
                if candidate in seen:
                    continue
                try:
                    self.guard.validate(candidate, resolve=False)
                except ValueError:
                    continue
                seen.add(candidate)
                discovered.append(candidate)
                if len(discovered) >= max_urls:
                    break
            if len(discovered) >= max_urls:
                break
        return {
            "kind": "discovery",
            "run_id": new_run_id("discover"),
            "target": decision.normalized_url,
            "started_at": started_at,
            "finished_at": now(),
            "command_policy": {
                "depth": depth,
                "rate_limit": rate_limit,
                "scope": "fqdn",
                "max_urls": max_urls,
            },
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stderr": result.stderr[-4000:],
            "parse_errors": parse_errors[:20],
            "url_count": len(discovered),
            "urls": discovered,
        }

    async def scan(self, urls: list[str], *, profile: str = "high-signal") -> dict[str, Any]:
        if not urls:
            raise ValueError("At least one URL is required")
        if len(urls) > min(25, self.settings.max_urls):
            raise ValueError("A scan accepts at most 25 URLs to keep each run focused")
        normalized: list[str] = []
        for url in urls:
            decision = self.guard.validate(url, resolve=self.resolve_scope)
            if decision.normalized_url not in normalized:
                normalized.append(decision.normalized_url)

        binary = self.runner.resolve(self.settings.nuclei_bin)
        if not binary:
            raise FileNotFoundError("Nuclei is not installed or BOUNTYPROOF_NUCLEI_BIN is incorrect")
        severity = {"critical-only": "critical", "high-signal": "critical,high"}.get(profile)
        if not severity:
            raise ValueError("profile must be 'critical-only' or 'high-signal'")

        temp_parent = self.settings.report_dir / ".tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        started_at = now()
        with tempfile.TemporaryDirectory(prefix="bountyproof-", dir=temp_parent) as directory:
            target_file = Path(directory) / "targets.txt"
            target_file.write_text("\n".join(normalized) + "\n", encoding="utf-8")
            arguments = [
                binary,
                "-l",
                str(target_file),
                "-s",
                severity,
                "-pt",
                "http",
                "-etags",
                "fuzz,dos,bruteforce,headless",
                "-rl",
                str(self.settings.nuclei_rate_limit),
                "-bs",
                "1",
                "-c",
                "1",
                "-j",
                "-silent",
                "-nc",
                "-duc",
                "-rd",
                "authorization,cookie,set-cookie",
            ]
            result = await self.runner.run(arguments)

        findings, parse_errors = parse_jsonl(result.stdout)
        summaries = [summarize_nuclei(item, index) for index, item in enumerate(findings)]
        return {
            "kind": "scan",
            "run_id": new_run_id("scan"),
            "started_at": started_at,
            "finished_at": now(),
            "targets": normalized,
            "profile": profile,
            "policy": {
                "severity": severity,
                "protocol": "http",
                "excluded_tags": ["fuzz", "dos", "bruteforce", "headless"],
                "rate_limit": self.settings.nuclei_rate_limit,
                "concurrency": 1,
            },
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stderr": result.stderr[-4000:],
            "parse_errors": parse_errors[:20],
            "finding_count": len(findings),
            "finding_summaries": summaries,
            "findings": findings,
            "note": "Nuclei matches are candidates until verify_finding reproduces the same template twice.",
        }

    async def verify(self, scan_report: dict[str, Any], finding_index: int, *, rounds: int = 2) -> dict[str, Any]:
        findings = scan_report.get("findings")
        if not isinstance(findings, list) or not 0 <= finding_index < len(findings):
            raise IndexError("finding_index is outside the stored scan results")
        candidate = findings[finding_index]
        if not isinstance(candidate, dict):
            raise ValueError("Stored finding is malformed")
        summary = summarize_nuclei(candidate, finding_index)
        template_id = str(summary["template_id"])
        matched_at = str(summary["matched_at"])
        if not _TEMPLATE_ID_RE.fullmatch(template_id):
            raise ValueError("Stored template ID is invalid")
        if not matched_at.startswith(("http://", "https://")):
            raise ValueError("Stored finding does not contain a verifiable HTTP URL")
        decision = self.guard.validate(matched_at, resolve=self.resolve_scope)
        binary = self.runner.resolve(self.settings.nuclei_bin)
        if not binary:
            raise FileNotFoundError("Nuclei is not installed or BOUNTYPROOF_NUCLEI_BIN is incorrect")
        rounds = max(2, min(rounds, 3))
        started_at = now()
        attempts: list[dict[str, Any]] = []
        for round_number in range(1, rounds + 1):
            arguments = [
                binary,
                "-u",
                decision.normalized_url,
                "-id",
                template_id,
                "-pt",
                "http",
                "-rl",
                "1",
                "-bs",
                "1",
                "-c",
                "1",
                "-j",
                "-silent",
                "-nc",
                "-duc",
                "-rd",
                "authorization,cookie,set-cookie",
            ]
            result = await self.runner.run(arguments)
            matches, parse_errors = parse_jsonl(result.stdout)
            same_template = [
                item
                for item in matches
                if (item.get("template-id") or item.get("template_id")) == template_id
            ]
            attempts.append(
                {
                    "round": round_number,
                    "matched": bool(same_template),
                    "returncode": result.returncode,
                    "timed_out": result.timed_out,
                    "parse_errors": parse_errors[:10],
                    "matches": same_template,
                    "stderr": result.stderr[-2000:],
                }
            )
        verified = all(attempt["matched"] for attempt in attempts)
        return {
            "kind": "verification",
            "run_id": new_run_id("verify"),
            "source_scan_run_id": scan_report.get("run_id", ""),
            "finding_index": finding_index,
            "candidate": summary,
            "started_at": started_at,
            "finished_at": now(),
            "rounds": rounds,
            "verified": verified,
            "classification": "repeatable-candidate" if verified else "not-reproduced",
            "attempts": attempts,
            "note": (
                "Repeatability reduces false positives but does not replace manual impact validation "
                "and a review of the program policy."
            ),
        }
