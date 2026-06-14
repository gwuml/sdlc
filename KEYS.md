# KEYS.md — Release Signing Key Registry

> **Status: TEMPLATE.** This file must contain at least one real, independently
> verifiable key fingerprint before any release asset is signed (Final Approval
> Condition 15). Until an operator fills the registry below with a genuine
> fingerprint, no `SHA256SUMS.sig` produced against these entries is valid.

## Purpose

Release artifacts (`SHA256SUMS`) are signed so that downloaders and the auto-update
path can verify provenance. Checksum verification alone is insufficient — a tampered
`SHA256SUMS` file would still match a tampered binary. The signature is the
tamper-evident control. The auto-update flow verifies the signature against a key
registered here (or a Sigstore transparency-log identity) before replacing the binary.

## Registered Signing Keys

| Key holder (identity) | Role | Method | Fingerprint / Sigstore identity | Added | Status |
|-----------------------|------|--------|----------------------------------|-------|--------|
| `<TO BE FILLED BY OPERATOR>` | Release manager | GPG | `<40-char GPG fingerprint>` | `<date>` | PLACEHOLDER |
| `<TO BE FILLED BY OPERATOR>` | Backup signer | Sigstore | `<oidc-identity@domain>` | `<date>` | PLACEHOLDER |

The key holder MUST be a named human who is not the implementer of the release being
signed. Granting a CI identity signing or finding-closing authority requires the
approval of a named human in this file who is not the implementer, recorded as a
ledger event (`keys.ci_authority_granted`) before the authority takes effect.

## Key Rotation Procedure

1. Generate the new key on hardware the operator controls.
2. Add the new fingerprint to the table above with `Status: ACTIVE` and today's date.
3. Sign the new key's fingerprint with the outgoing key; record the cross-signature
   in `docs/RELEASE_PROCESS.md`.
4. Mark the outgoing key `Status: RETIRED` with the retirement date. Do not delete
   retired rows — historical releases were signed with them and must remain verifiable.
5. Append a `keys.rotated` ledger event with both fingerprints.

## Key Compromise Procedure

1. Immediately mark the compromised key `Status: REVOKED` with the date and incident ID.
2. Publish a revocation (GPG revocation certificate, or Sigstore revocation).
3. Append a `keys.revoked` ledger event.
4. Re-sign the most recent still-supported release with an active key and publish a
   security advisory in the GitHub Release notes.
5. Audit all releases signed by the compromised key within the exposure window.

## Verification (downloader side)

```bash
# GPG
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

# Sigstore
cosign verify-blob --signature SHA256SUMS.sig --certificate-identity <identity> SHA256SUMS
```
