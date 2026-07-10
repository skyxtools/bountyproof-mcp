---
description: Start a scope- and rules-gated BountyProof engagement
---

Start a new authorized bug-bounty engagement with the `bountyproof` MCP server.

Do not call any network-active tool yet. Use OpenCode's `question` tool to ask the user for every item below. Do not infer or silently fill missing scope or rules:

1. Program name.
2. Exact in-scope hosts or URLs. Explain that supported forms are `example.com`, `*.example.com`, or a URL/path prefix such as `https://app.example.com/api/`.
3. Exact out-of-scope hosts or URL/path prefixes. Require the user to explicitly say `none` when there are none, then pass an empty list rather than the string `none`.
4. The program rules or a faithful concise summary, including whether automated scanning is allowed.
5. Which BountyProof activities the rules explicitly permit: `preflight`, `discovery`, `nuclei-scan`, `verification`, `origin-discovery`, `origin-verification`, `surface-import`, and/or `authorization-testing`. Explain that `origin-discovery` uses DNS/passive history, while `origin-verification` sends one direct HTTPS request to a candidate IP using the target hostname. Explain that authorization testing only replays imported GET requests and requires separately supplied identity profiles. Do not enable an activity merely because it seems useful.
6. Forbidden test categories, such as DoS, brute force, social engineering, account takeover attempts, or testing third parties.
7. Maximum permitted requests per second, between 1 and 10.
8. Explicit confirmation that the user is authorized to test the stated scope under those rules.

Summarize the answers and ask the user to correct anything inaccurate. Only after confirmation, call `bountyproof_start_session` with `authorization_confirmed=true`.

Return the `session_id`, show the stored scope/out-of-scope/rate limit, and ask which exact in-scope URL should receive the first preflight. Do not automatically start preflight.

If `find_origin_candidates` later returns candidates, follow its `next_action` exactly. Never scan a candidate IP. Before `verify_origin_candidate`, show the exact IP and hostname to the user and obtain a fresh explicit confirmation for that candidate. After verification, stop automatic execution and present the result and rules check to the user.

For authorization testing, never ask the user to paste tokens, cookies, API keys, or session secrets into chat. Ask them to set secrets as environment variables outside OpenCode, then collect only the environment-variable names through `register_auth_profiles`. Before `compare_authorization`, ask the user which imported GET endpoint is being tested, which profile owns the object, which profiles should be denied, and whether the expected policy is `owner-only`, `authenticated-only`, or `public`. Never change object IDs automatically. After a candidate is returned, obey `next_action` and stop.
