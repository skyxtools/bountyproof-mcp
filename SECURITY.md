# Security policy

BountyProof is intended only for systems you own or are explicitly authorized to test.

Please report vulnerabilities in this project privately through GitHub Security Advisories. Do not include live third-party targets, credentials, cookies, or unredacted bug-bounty evidence in public issues.

The project intentionally excludes arbitrary command execution, user-supplied scanner flags, brute force, credential testing, fuzzing templates, denial-of-service templates, headless templates, and automatic exploitation.

Origin discovery returns candidates, not ownership claims. Direct-origin verification requires a separately approved session activity and fresh confirmation for the exact candidate. The workflow intentionally stops after comparison and never feeds an origin IP into automated scanning.

Authentication profiles store only environment-variable names. Secret values must be injected into the MCP process environment and are never written to profile or report files. Authorization comparison is limited to imported GET requests, never mutates identifiers, and stops after repeatable differential evidence.
