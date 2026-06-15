# KEYS.md — Release Signing Identity Registry

> **Signing method: Sigstore keyless (default).** Releases are signed with
> [Sigstore](https://www.sigstore.dev/) cosign in keyless mode — there is no
> private key to generate, store, leak, or rotate. The signer's identity is an
> OIDC identity (the GitHub Actions workflow identity), and every signature is
> recorded in the public Rekor transparency log. This satisfies Final Approval
> Condition 15 without any secret-key custody.

## Why keyless

A long-lived GPG private key is a standing liability: it can be exfiltrated, must
be rotated, and its compromise invalidates trust in everything it signed. Sigstore
issues a short-lived certificate bound to a verified OIDC identity for the duration
of one signing operation, then logs it publicly. Nothing persists that an attacker
can steal. For a tool distributed to interns, this is the safest option.

## Registered signing identities

Signatures are accepted only from the identities below. The identity is the GitHub
Actions OIDC subject of the release workflow running from this repository.

| Identity (OIDC subject) | Issuer | Scope | Added | Status |
|-------------------------|--------|-------|-------|--------|
| `https://github.com/gwuml/sdlc/.github/workflows/release.yml@refs/heads/main` | `https://token.actions.githubusercontent.com` | Release signing on `main` | 2026-06-14 | ACTIVE |
| `https://github.com/gwuml/sdlc/.github/workflows/release.yml@refs/tags/v*` | `https://token.actions.githubusercontent.com` | Release signing on `v*` tags | 2026-06-14 | ACTIVE |

A human release manager must approve each release via branch protection (an
approving review from a non-author) before the workflow that owns these identities
can run on `main`. See `docs/RELEASE_PROCESS.md`.

Granting any non-default identity (e.g. a personal account or a second CI job)
authority to sign releases or close findings requires the approval of a named human
release manager who is not the implementer, recorded as a `keys.identity_granted`
ledger event before it takes effect.

## Verification (downloader side)

```bash
# Verify SHA256SUMS was signed by this repo's release workflow on main.
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gwuml/sdlc/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.pem \
  SHA256SUMS

# Then verify the binary checksum.
sha256sum -c SHA256SUMS
```

The auto-update path (`sdlc update apply`) performs the equivalent verification
programmatically and aborts if either the signature identity or the checksum fails
(checksum alone is insufficient).

## Identity rotation

1. Add the new OIDC identity (e.g. a renamed workflow path or new release branch)
   to the table with `Status: ACTIVE` and today's date.
2. Mark the superseded identity `Status: RETIRED` with the date. Do not delete
   retired rows — historical releases were signed under them and must remain
   verifiable against Rekor.
3. Append a `keys.identity_rotated` ledger event.

## Identity compromise (e.g. repo or workflow takeover)

1. Mark the affected identity `Status: REVOKED` with the date and incident ID.
2. Append a `keys.identity_revoked` ledger event and publish a security advisory in
   the affected GitHub Release notes.
3. Audit Rekor for signatures produced by the compromised identity within the
   exposure window; re-sign the latest supported release from a clean identity.

## Optional fallback: GPG

If an air-gapped or offline-verifiable signature is ever required, a GPG key may be
added as a second method. Record its 40-character fingerprint and holder here with
`Method: GPG`, give the private key to CI as a repository secret, and follow standard
GPG rotation/revocation. This is **not** required for normal releases and is left
unconfigured by default.
