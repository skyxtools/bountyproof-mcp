"""Local HAR, OpenAPI, and Postman surface import with aggressive value redaction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import yaml

from .config import Settings
from .session import SessionPolicy


InputFormat = Literal["auto", "har", "openapi", "postman"]
_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_PATH_ID_RE = re.compile(
    r"(?<=/)(?:\d{3,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|[0-9a-fA-F]{24,})(?=/|$)"
)


def _body_fields(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    fields: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            fields.append(path)
            fields.extend(_body_fields(child, path, depth + 1))
    elif isinstance(value, list) and value:
        fields.extend(_body_fields(value[0], f"{prefix}[]", depth + 1))
    return fields[:200]


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    query = urlencode([(name, "<redacted>") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    path = _PATH_ID_RE.sub("<object-id>", parsed.path)
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))


def safe_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpoint_index": endpoint["endpoint_index"],
        "method": endpoint["method"],
        "url_template": endpoint["url_template"],
        "parameter_names": endpoint["parameter_names"],
        "body_fields": endpoint["body_fields"],
        "header_names": endpoint["header_names"],
        "source": endpoint["source"],
        "replayable": endpoint["replayable"],
        "safe_method": endpoint["safe_method"],
    }


class SurfaceImporter:
    def __init__(self, settings: Settings, policy: SessionPolicy):
        self.settings = settings
        self.policy = policy

    def import_file(self, file_path: str, input_format: InputFormat = "auto", base_url: str = "") -> dict[str, Any]:
        path = self._resolve_path(file_path)
        if path.stat().st_size > self.settings.max_import_bytes:
            raise ValueError(f"Import exceeds BOUNTYPROOF_MAX_IMPORT_BYTES={self.settings.max_import_bytes}")
        raw = path.read_text(encoding="utf-8-sig")
        data = self._load_document(path, raw)
        detected = self._detect(data) if input_format == "auto" else input_format
        if detected == "har":
            endpoints = self._from_har(data)
        elif detected == "openapi":
            endpoints = self._from_openapi(data, base_url)
        elif detected == "postman":
            endpoints = self._from_postman(data, base_url)
        else:
            raise ValueError("Unsupported surface format")

        accepted: list[dict[str, Any]] = []
        rejected = 0
        seen: set[tuple[str, str]] = set()
        for endpoint in endpoints:
            scope_url = str(endpoint.pop("scope_url", ""))
            try:
                self.policy.validate(scope_url, resolve=False)
            except ValueError:
                rejected += 1
                continue
            key = (endpoint["method"], endpoint["replay_url"] or endpoint["url_template"])
            if key in seen:
                continue
            seen.add(key)
            endpoint["endpoint_index"] = len(accepted)
            accepted.append(endpoint)
        return {
            "kind": "surface-import",
            "source_file": str(path),
            "input_format": detected,
            "endpoint_count": len(accepted),
            "replayable_get_count": sum(
                item["replayable"] and item["method"] == "GET" for item in accepted
            ),
            "rejected_out_of_scope": rejected,
            "endpoints": accepted,
            "safe_endpoints": [safe_endpoint(item) for item in accepted],
            "note": (
                "Header values and request bodies were not imported. Replay URLs remain only in the local, "
                "gitignored report; MCP responses redact query values and object-like path segments."
            ),
        }

    def _resolve_path(self, file_path: str) -> Path:
        candidate = Path(file_path).expanduser()
        if not candidate.is_absolute():
            candidate = self.settings.import_root / candidate
        candidate = candidate.resolve()
        root = self.settings.import_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError(f"Import path must stay inside BOUNTYPROOF_IMPORT_ROOT={root}")
        if not candidate.is_file():
            raise FileNotFoundError(f"Surface file not found: {candidate}")
        return candidate

    @staticmethod
    def _load_document(path: Path, raw: str) -> dict[str, Any]:
        try:
            value = yaml.safe_load(raw) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"Unable to parse surface file: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("Surface document must contain an object at the root")
        return value

    @staticmethod
    def _detect(data: dict[str, Any]) -> InputFormat:
        if isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
            return "har"
        if "openapi" in data or "swagger" in data:
            return "openapi"
        if isinstance(data.get("item"), list):
            return "postman"
        raise ValueError("Could not detect HAR, OpenAPI, or Postman format")

    @staticmethod
    def _endpoint(
        *,
        method: str,
        url: str,
        source: str,
        parameter_names: list[str] | None = None,
        body_fields: list[str] | None = None,
        header_names: list[str] | None = None,
        replayable: bool = True,
        scope_url: str | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        parsed_names = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        return {
            "method": method,
            "replay_url": url if replayable and method == "GET" else "",
            "url_template": _safe_url(url),
            "parameter_names": sorted(set((parameter_names or []) + parsed_names)),
            "body_fields": sorted(set(body_fields or []))[:200],
            "header_names": sorted(set(name.lower() for name in (header_names or [])))[:100],
            "source": source,
            "replayable": replayable and method == "GET",
            "safe_method": method in {"GET", "HEAD"},
            "scope_url": scope_url or url,
        }

    def _from_har(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []
        for entry in data.get("log", {}).get("entries", []):
            request = entry.get("request") if isinstance(entry, dict) else None
            if not isinstance(request, dict):
                continue
            method = str(request.get("method", "GET")).upper()
            url = str(request.get("url", ""))
            if method not in _HTTP_METHODS or not url.startswith(("http://", "https://")):
                continue
            parameter_names = [
                str(item.get("name"))
                for item in request.get("queryString", [])
                if isinstance(item, dict) and item.get("name")
            ]
            header_names = [
                str(item.get("name"))
                for item in request.get("headers", [])
                if isinstance(item, dict) and item.get("name")
            ]
            fields: list[str] = []
            post_data = request.get("postData")
            if isinstance(post_data, dict) and "json" in str(post_data.get("mimeType", "")).lower():
                try:
                    fields = _body_fields(json.loads(str(post_data.get("text", ""))))
                except json.JSONDecodeError:
                    fields = []
            endpoints.append(
                self._endpoint(
                    method=method,
                    url=url,
                    source="har",
                    parameter_names=parameter_names,
                    body_fields=fields,
                    header_names=header_names,
                )
            )
        return endpoints

    def _from_openapi(self, data: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
        servers = data.get("servers") if isinstance(data.get("servers"), list) else []
        server_url = base_url or next(
            (str(item.get("url")) for item in servers if isinstance(item, dict) and item.get("url")),
            "",
        )
        if not server_url or "{" in server_url:
            raise ValueError("A concrete base_url is required for this OpenAPI document")
        self.policy.validate(server_url, resolve=False)
        endpoints: list[dict[str, Any]] = []
        paths = data.get("paths") if isinstance(data.get("paths"), dict) else {}
        for path_name, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                upper = str(method).upper()
                if upper not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                url = urljoin(server_url.rstrip("/") + "/", str(path_name).lstrip("/"))
                parameters = []
                path_parameters = path_item.get("parameters", [])
                operation_parameters = operation.get("parameters", [])
                if not isinstance(path_parameters, list):
                    path_parameters = []
                if not isinstance(operation_parameters, list):
                    operation_parameters = []
                for value in path_parameters + operation_parameters:
                    if isinstance(value, dict) and value.get("name"):
                        parameters.append(str(value["name"]))
                body_fields: list[str] = []
                request_body = operation.get("requestBody", {})
                request_body = request_body if isinstance(request_body, dict) else {}
                content = request_body.get("content", {})
                content = content if isinstance(content, dict) else {}
                json_content = content.get("application/json", {})
                json_content = json_content if isinstance(json_content, dict) else {}
                schema = json_content.get("schema", {})
                if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                    body_fields = [str(key) for key in schema["properties"]]
                replayable = "{" not in url
                endpoints.append(
                    self._endpoint(
                        method=upper,
                        url=url,
                        source="openapi",
                        parameter_names=parameters,
                        body_fields=body_fields,
                        replayable=replayable,
                        scope_url=server_url,
                    )
                )
        return endpoints

    def _from_postman(self, data: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []

        def visit(items: list[Any]) -> None:
            for item in items:
                if not isinstance(item, dict):
                    continue
                if isinstance(item.get("item"), list):
                    visit(item["item"])
                    continue
                request = item.get("request")
                if not isinstance(request, dict):
                    continue
                method = str(request.get("method", "GET")).upper()
                url_value = request.get("url")
                url = str(url_value.get("raw", "")) if isinstance(url_value, dict) else str(url_value or "")
                if base_url:
                    url = url.replace("{{baseUrl}}", base_url.rstrip("/")).replace(
                        "{{base_url}}", base_url.rstrip("/")
                    )
                if method not in _HTTP_METHODS or not url:
                    continue
                unresolved = "{{" in url
                scope_url = base_url if unresolved else url
                if not scope_url.startswith(("http://", "https://")):
                    continue
                header_names = [
                    str(header.get("key"))
                    for header in request.get("header", [])
                    if isinstance(header, dict) and header.get("key")
                ]
                body_fields: list[str] = []
                body = request.get("body")
                if isinstance(body, dict) and body.get("mode") == "raw":
                    try:
                        body_fields = _body_fields(json.loads(str(body.get("raw", ""))))
                    except json.JSONDecodeError:
                        body_fields = []
                endpoints.append(
                    self._endpoint(
                        method=method,
                        url=url,
                        source="postman",
                        body_fields=body_fields,
                        header_names=header_names,
                        replayable=not unresolved,
                        scope_url=scope_url,
                    )
                )

        visit(data.get("item", []))
        return endpoints
