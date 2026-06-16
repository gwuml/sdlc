# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.** Instead use GitHub's
private vulnerability reporting (Security → "Report a vulnerability") on this repo, or
email the maintainer listed in `KEYS.md`.

Please include: affected version/commit, a reproduction, and the impact. We aim to
acknowledge within a few business days.

## Supported versions

The latest released minor version is supported. Older versions may not receive fixes.

## What we consider in scope

This tool runs local AI workers and writes evidence/artifacts. In-scope concerns include:
command injection, path traversal, unsafe deserialization, secret leakage into
evidence/logs, finding-closure/actor-proof bypass, ledger tampering that goes
undetected, and release-signature/SBOM integrity.

Out of scope (by current design): DoS/resource exhaustion, issues that require
control of trusted environment variables or CLI flags, and the security of the
operator-installed worker CLIs themselves (Claude Code, Codex, Gemini, etc.).

## Verifying release integrity

Releases are signed with **Sigstore keyless cosign** and ship a CycloneDX SBOM.
Verify before installing (see `docs/USAGE.md`):

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gwuml/sdlc/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem SHA256SUMS
sha256sum -c SHA256SUMS
```

Signing identities and key rotation/compromise procedures are documented in `KEYS.md`.

## Hardening already in place

- Secret redaction across worker output, ledger events, and artifacts (PEM/PuTTY/SSH2/
  JWK/token/kv formats).
- Tamper-evident ledger (chained digests), checked in every `validate` mode.
- HMAC actor-proof for finding closure; implementers cannot close their own findings.
- Workers run with an env allowlist and cannot mutate the control-plane ledger.
