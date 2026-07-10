# BountyProof MCP

BountyProof is a small MCP server for authorized bug bounty work. It keeps the workflow explicit and evidence-driven:

```text
session (scope + rules) -> preflight -> surface discovery/import -> targeted checks -> verification -> evidence
```

WAF detection is not treated as a vulnerability. It is part of the preflight check, where BountyProof decides whether live testing is practical or likely to be wasted on challenges, rate limits, unstable responses, off-host redirects, or other edge protection.

## What it uses

BountyProof has a built-in HTTP client and relies on only two external binaries:

- **Katana** for URL discovery, restricted to hosts that passed preflight.
- **Nuclei** for high- and critical-severity HTTP templates. Fuzzing, DoS, brute force, and headless templates are excluded.

There is no generic shell tool, custom payload runner, mass scanner, subdomain brute force, credential attack, or automatic exploitation.

## MCP tools

1. `start_session(...)` records the program, scope, exclusions, rules, allowed activities, restrictions, rate limit, and authorization. It does not send network traffic.
2. `scope_check(session_id, url)` checks a URL against the session scope without sending a request.
3. `preflight_target(session_id, url)` classifies a target as `clear`, `guarded`, or `blocked`.
4. `discover_surface(...)` runs Katana after a successful preflight.
5. `scan_high_signal(...)` runs a tightly rate-limited Nuclei scan using high- or critical-severity HTTP templates.
6. `verify_finding(...)` repeats one matched template two or three times.
7. `find_origin_candidates(...)` looks for possible origin IPs through in-scope DNS hints and, when configured, historical A records.
8. `verify_origin_candidate(...)` compares one edge response with one direct-IP HTTPS response after fresh user approval.
9. `import_surface(...)` imports HAR, OpenAPI, or Postman data with scope filtering and value redaction.
10. `register_auth_profiles(...)` stores roles and environment variable names, never credential values.
11. `compare_authorization(...)` compares the same GET request as the owner and another identity for two or three rounds.
12. `get_report(...)` returns a sanitized JSON or Markdown report.

Every tool except `start_session` requires a `session_id`. Exclusions take priority over inclusions, including URL path prefixes. An activity is rejected unless it appears in the session's `allowed_activities` list:

```text
preflight
discovery
nuclei-scan
verification
origin-discovery
origin-verification
surface-import
authorization-testing
```

Live discovery, scanning, and authorization comparison also require a `preflight_run_id`. The scheme, host, and port must match the preflight target. A `blocked` result cannot be overridden. A `guarded` result requires a manual review and `override_guarded=true`.

## Preflight results

| Result | Meaning | Next step |
|---|---|---|
| `clear` | The baseline is stable and no obvious friction was found | Continue at the approved rate |
| `guarded` | A WAF/CDN, redirect, high latency, or unstable response was observed | Review the program rules and testing approach |
| `blocked` | Repeated challenges, blocks, rate limits, or connection failures were observed | Stop live automation |

Cloudflare, Akamai, Imperva, CloudFront, F5, Sucuri, Fastly, and Azure edge indicators are recorded only as preflight metadata. They are never reported as vulnerabilities.

## Installation

Requirements:

- Python 3.11 or newer
- Katana
- Nuclei and nuclei-templates

```bash
git clone https://github.com/skyxtools/bountyproof-mcp.git
cd bountyproof-mcp
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e .
```

Basic PowerShell configuration:

```powershell
$env:BOUNTYPROOF_ALLOWED_PORTS = "443"
$env:BOUNTYPROOF_CONTACT = "researcher@example.com"
bountyproof-mcp
```

If Katana or Nuclei is not in `PATH`, set the executable paths explicitly:

```powershell
$env:BOUNTYPROOF_KATANA_BIN = "C:\Tools\katana.exe"
$env:BOUNTYPROOF_NUCLEI_BIN = "C:\Tools\nuclei.exe"
```

## OpenCode setup

Copy [opencode.jsonc.example](opencode.jsonc.example) to `opencode.jsonc` in your OpenCode project and update the absolute executable path. Set `BOUNTYPROOF_WORKSPACE` and any credential environment variables before starting OpenCode. OpenCode expands `{env:VARIABLE}` and passes the value to the MCP process through its `environment` option, so secrets do not need to be written into the config file.

Copy `.opencode/commands/bounty-start.md` into the project where OpenCode runs, or place it at `~/.config/opencode/commands/bounty-start.md` to make it available globally. Start each engagement with:

```text
/bounty-start
```

The command asks for the program name, in-scope assets, exclusions, rules, allowed activities, restrictions, rate limit, and confirmation that the test is authorized. Once you approve the summary, OpenCode calls `bountyproof_start_session` and returns a `session_id`.

An MCP server cannot open a dialog simply because its process has started. The client must initiate the interaction, which is why the custom command is the entry point.

For MCP clients other than OpenCode:

```json
{
  "mcpServers": {
    "bountyproof": {
      "command": "/absolute/path/to/.venv/bin/bountyproof-mcp",
      "args": [],
      "env": {
        "BOUNTYPROOF_ALLOWED_PORTS": "443",
        "BOUNTYPROOF_CONTACT": "researcher@example.com"
      }
    }
  }
}
```

On Windows, use `.venv\\Scripts\\bountyproof-mcp.exe`.

## Workflow

### 1. Start a session

Run `/bounty-start` in OpenCode. Supported scope formats include:

- Exact host: `api.example.com`
- Wildcard subdomain: `*.example.com`
- URL and path prefix: `https://app.example.com/api/`

Out-of-scope entries always win. For example, an in-scope entry of `https://app.example.com/api/` combined with an exclusion of `https://app.example.com/api/admin/` blocks the entire admin path.

### 2. Run preflight

```text
scope_check(session_id="session-...", url="https://app.example.com/")
preflight_target(session_id="session-...", url="https://app.example.com/", samples=3)
```

Preflight sends between two and five GET requests to the same URL. It does not send attack payloads.

### 3. Discover the surface

```text
discover_surface(
  session_id="session-...",
  url="https://app.example.com/",
  preflight_run_id="preflight-...",
  depth=2
)
```

Katana is restricted to `fqdn` scope, concurrency 1, and the session rate limit, with a hard maximum of two requests per second.

### 4. Run a high-signal scan

```text
scan_high_signal(
  session_id="session-...",
  urls=["https://app.example.com/api"],
  preflight_run_id="preflight-...",
  profile="high-signal"
)
```

The `high-signal` profile includes only high and critical findings. The `critical-only` profile is narrower. A Nuclei match remains a candidate until it has been verified.

### 5. Verify a candidate

```text
verify_finding(
  session_id="session-...",
  scan_run_id="scan-...",
  finding_index=0,
  rounds=2
)
```

`repeatable-candidate` means that the same template matched on every verification round. Business impact and program-policy compliance still require manual review.

### 6. Check a possible origin

`find_origin_candidates` uses two sources:

- DNS resolution for hostnames labeled `origin`, `direct`, `backend`, `server`, `dev`, or `staging`. A hostname is queried only when it matches the wildcard scope and is not excluded.
- Historical A records from SecurityTrails when `BOUNTYPROOF_SECURITYTRAILS_API_KEY` is configured.

Every result starts as an `unverified-origin-candidate`. Do not send it directly to a scanner.

```text
find_origin_candidates(
  session_id="session-...",
  target_url="https://app.example.com/",
  preflight_run_id="preflight-..."
)
```

If `origin-verification` is allowed by the program rules, review the candidate IP and confirm a direct request separately. The verification tool then sends exactly two requests: one to the edge and one to the candidate IP, using the target's TLS SNI and HTTP `Host` header.

```text
verify_origin_candidate(
  session_id="session-...",
  origin_run_id="origin-...",
  candidate_index=0,
  direct_request_confirmed=true
)
```

The workflow stops after this comparison. Review the evidence, check the IP owner and hosting provider, and confirm whether the raw IP is covered by the program scope. BountyProof will not pass the IP to `scan_high_signal`. Any further testing requires a separate decision.

### 7. Import a surface and compare authorization

Surfaces can be imported from HAR, OpenAPI JSON/YAML, or a Postman Collection. The file must be inside `BOUNTYPROOF_IMPORT_ROOT`. Header values and request bodies are not stored; only header names, parameter names, and body field names are retained. Out-of-scope endpoints are discarded.

Full replay URLs remain in the local, gitignored report. MCP output masks query values and path segments that look like object identifiers.

```text
import_surface(
  session_id="session-...",
  file_path="captures/app.har",
  input_format="auto"
)
```

Do not send credentials through chat or MCP parameters. Put tokens or cookies in environment variables available to the MCP process, then register references to those variables:

```powershell
$env:BOUNTY_USER_A_TOKEN = "<SET_OUTSIDE_CHAT>"
$env:BOUNTY_USER_B_TOKEN = "<SET_OUTSIDE_CHAT>"
```

```text
register_auth_profiles(
  session_id="session-...",
  profiles=[
    {"name":"user_a", "role":"owner", "auth_type":"bearer", "credential_env":"BOUNTY_USER_A_TOKEN"},
    {"name":"user_b", "role":"other-user", "auth_type":"bearer", "credential_env":"BOUNTY_USER_B_TOKEN"},
    {"name":"anonymous", "role":"anonymous", "auth_type":"anonymous"}
  ]
)
```

`compare_authorization` accepts only replayable GET endpoints. It does not change the object ID, parameters, method, or body. The owner and comparison profiles are requested two or three times. A candidate is created only when the comparison profile consistently receives a 2xx response whose body is identical to the owner's response or whose canonical JSON is stable and equal.

```text
compare_authorization(
  session_id="session-...",
  surface_run_id="surface-...",
  endpoint_index=0,
  preflight_run_id="preflight-...",
  owner_profile="user_a",
  comparison_profiles=["user_b", "anonymous"],
  expected_policy="owner-only",
  rounds=2
)
```

The workflow stops when a differential candidate is found. BountyProof does not enumerate or replace object IDs automatically. Before any additional impact testing, confirm that the comparison identity should not have access to the object.

## Evidence and privacy

Sessions are stored in `.bountyproof/sessions/`, authentication profile metadata in `.bountyproof/auth-profiles/`, and reports in `.bountyproof/reports/`. All three paths are excluded from Git.

Authentication profiles contain environment variable names, not their values. Raw Nuclei request and response data stays local and is not returned through MCP. Nuclei is instructed to redact `authorization`, `cookie`, and `set-cookie` fields.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `BOUNTYPROOF_ALLOWED_PORTS` | `443` | Allowed destination ports |
| `BOUNTYPROOF_ALLOW_HTTP` | `false` | Allow unencrypted HTTP |
| `BOUNTYPROOF_ALLOW_PRIVATE` | `false` | Allow non-public IP addresses for lab use |
| `BOUNTYPROOF_VERIFY_TLS` | `true` | Verify TLS certificates |
| `BOUNTYPROOF_DELAY_MS` | `350` | Delay between preflight requests |
| `BOUNTYPROOF_MAX_URLS` | `100` | Maximum number of discovered URLs |
| `BOUNTYPROOF_NUCLEI_RATE_LIMIT` | `2` | Maximum Nuclei requests per second |
| `BOUNTYPROOF_REPORT_DIR` | `.bountyproof/reports` | Local evidence directory |
| `BOUNTYPROOF_SECURITYTRAILS_API_KEY` | empty | Optional historical DNS lookup; never written to reports |
| `BOUNTYPROOF_IMPORT_ROOT` | current directory | Allowed root for HAR, OpenAPI, and Postman files |
| `BOUNTYPROOF_MAX_IMPORT_BYTES` | `20000000` | Maximum imported surface file size |

## Tests

```bash
python -m unittest discover -s tests -v
```

The unit tests do not contact external targets.

## License

MIT. The project was inspired by HexStrike AI's MCP orchestration concept, but the implementation is independent and deliberately limited to a small workflow with strict guardrails.
