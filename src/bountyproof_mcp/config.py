"""Environment-based configuration with conservative bug-bounty defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _as_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings. An empty host allowlist intentionally denies all targets."""

    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...] = (443,)
    allow_http: bool = False
    allow_private: bool = False
    verify_tls: bool = True
    timeout_seconds: float = 12.0
    delay_ms: int = 250
    contact: str = "security-research"
    report_dir: Path = Path(".bountyproof/reports")
    max_body_bytes: int = 262_144
    max_urls: int = 100
    command_timeout_seconds: int = 300
    nuclei_rate_limit: int = 2
    katana_bin: str = "katana"
    nuclei_bin: str = "nuclei"
    securitytrails_api_key: str = ""
    import_root: Path = Path.cwd()
    max_import_bytes: int = 20_000_000

    @classmethod
    def from_env(cls) -> "Settings":
        ports_raw = _csv("BOUNTYPROOF_ALLOWED_PORTS")
        ports = tuple(int(port) for port in ports_raw) if ports_raw else (443,)
        return cls(
            # Engagement hosts are collected by start_session, not environment variables.
            allowed_hosts=(),
            allowed_ports=ports,
            allow_http=_as_bool("BOUNTYPROOF_ALLOW_HTTP", False),
            allow_private=_as_bool("BOUNTYPROOF_ALLOW_PRIVATE", False),
            verify_tls=_as_bool("BOUNTYPROOF_VERIFY_TLS", True),
            timeout_seconds=float(os.getenv("BOUNTYPROOF_TIMEOUT_SECONDS", "12")),
            delay_ms=max(0, int(os.getenv("BOUNTYPROOF_DELAY_MS", "350"))),
            contact=os.getenv("BOUNTYPROOF_CONTACT", "security-research").strip(),
            report_dir=Path(os.getenv("BOUNTYPROOF_REPORT_DIR", ".bountyproof/reports")),
            max_body_bytes=max(16_384, int(os.getenv("BOUNTYPROOF_MAX_BODY_BYTES", "262144"))),
            max_urls=max(1, min(500, int(os.getenv("BOUNTYPROOF_MAX_URLS", "100")))),
            command_timeout_seconds=max(
                30, min(1800, int(os.getenv("BOUNTYPROOF_COMMAND_TIMEOUT_SECONDS", "300")))
            ),
            nuclei_rate_limit=max(1, min(10, int(os.getenv("BOUNTYPROOF_NUCLEI_RATE_LIMIT", "2")))),
            katana_bin=os.getenv("BOUNTYPROOF_KATANA_BIN", "katana").strip(),
            nuclei_bin=os.getenv("BOUNTYPROOF_NUCLEI_BIN", "nuclei").strip(),
            securitytrails_api_key=os.getenv("BOUNTYPROOF_SECURITYTRAILS_API_KEY", "").strip(),
            import_root=Path(os.getenv("BOUNTYPROOF_IMPORT_ROOT", str(Path.cwd()))).resolve(),
            max_import_bytes=max(
                1_000_000, min(100_000_000, int(os.getenv("BOUNTYPROOF_MAX_IMPORT_BYTES", "20000000")))
            ),
        )
