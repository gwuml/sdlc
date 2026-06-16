"""Hardening tests for redact_secrets across secret-format variants + fuzzing.

Redaction is a CRITICAL-class safety surface (worker/deploy output and ledger events
pass through it). These tests assert no secret BODY survives redaction across PEM
variants, PuTTY .ppk, SSH2, JWK private params, and key/value forms — including
multi-line and base64-wrapped bodies — and that benign short fields are not
over-redacted.
"""

from __future__ import annotations

import base64
import random
import textwrap
import unittest

from sdlc.util import redact_secrets


def _b64(n: int, seed: int) -> str:
    rng = random.Random(seed)
    raw = bytes(rng.randrange(256) for _ in range(n))
    return base64.b64encode(raw).decode()


def _b64url(n: int, seed: int) -> str:
    rng = random.Random(seed)
    raw = bytes(rng.randrange(256) for _ in range(n))
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _pem(kind: str, body: str) -> str:
    wrapped = "\n".join(textwrap.wrap(body, 64))
    return f"-----BEGIN {kind}-----\n{wrapped}\n-----END {kind}-----"


class RedactionVariantTests(unittest.TestCase):
    def _assert_redacted(self, secret_body: str, text: str, label: str) -> None:
        out = redact_secrets(text)
        self.assertNotIn(secret_body, out, f"{label}: secret body survived redaction")
        self.assertIn("[REDACTED]", out, f"{label}: nothing was redacted")

    def test_pem_variants_multiline(self) -> None:
        for i, kind in enumerate([
            "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY",
            "PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
        ]):
            body = _b64(240, seed=i)
            text = f"log line before\n{_pem(kind, body)}\nlog line after"
            self._assert_redacted(body, text, f"PEM {kind}")

    def test_putty_ppk(self) -> None:
        priv = "\n".join(_b64(48, seed=100 + j) for j in range(6))
        mac = _b64(20, seed=200)
        ppk = (
            "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: rsa-key\n"
            f"Public-Lines: 6\n{_b64(48, seed=300)}\n"
            f"Private-Lines: 6\n{priv}\nPrivate-MAC: {mac}"
        )
        out = redact_secrets(f"before\n{ppk}\nafter")
        self.assertNotIn(priv.splitlines()[0], out, "PuTTY private body survived")
        self.assertNotIn(mac, out, "PuTTY MAC survived")
        self.assertIn("[REDACTED]", out)

    def test_ssh2_rfc4716(self) -> None:
        body = _b64(200, seed=400)
        text = _pem("", "")  # noop to keep import warm
        block = f"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n{body}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----"
        self._assert_redacted(body, f"x{block}y", "SSH2")

    def test_jwk_private_params_both_orders(self) -> None:
        d = _b64url(48, seed=500)
        # kty before d
        self._assert_redacted(d, f'{{"kty":"RSA","n":"abc","d":"{d}"}}', "JWK kty-before-d")
        # d before kty
        self._assert_redacted(d, f'{{"d":"{d}","kty":"EC","crv":"P-256"}}', "JWK d-before-kty")
        # other private params
        for param in ("p", "q", "dp", "dq", "qi", "k"):
            v = _b64url(40, seed=hash(param) % 1000)
            self._assert_redacted(v, f'{{"kty":"RSA","{param}":"{v}"}}', f"JWK {param}")

    def test_kv_and_quoted_secrets(self) -> None:
        self._assert_redacted("supersecretvalue123", "api_key=supersecretvalue123", "kv api_key")
        self._assert_redacted("hunter2primrose", '{"password": "hunter2primrose"}', "quoted password")

    def test_token_formats(self) -> None:
        for body, label in [
            ("AKIA" + "A" * 16, "AWS AKIA"),
            ("sk-" + "a" * 32, "openai sk-"),
            ("ghp_" + "b" * 32, "github ghp_"),
            ("Bearer " + "c" * 40, "bearer"),
        ]:
            out = redact_secrets(f"value: {body}")
            self.assertIn("[REDACTED]", out, f"{label}: not redacted")

    def test_fuzz_pem_bodies_never_survive(self) -> None:
        # 50 randomized PEM bodies inside surrounding noise — none may survive.
        for seed in range(50):
            body = _b64(random.Random(seed).randrange(120, 400), seed)
            kind = ["RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY"][seed % 3]
            text = f"prefix {seed}\n{_pem(kind, body)}\nsuffix {seed}"
            out = redact_secrets(text)
            # No 32+ char base64 chunk of the body should remain.
            self.assertNotIn(body[:40], out, f"fuzz seed {seed}: body chunk survived")

    def test_benign_short_fields_not_over_redacted(self) -> None:
        # Short d/p/q fields (e.g. coordinates, indices) must NOT be redacted.
        benign = '{"d": "12", "p": "north", "q": "ok", "k": "v"}'
        self.assertEqual(redact_secrets(benign), benign)
        prose = "The deploy ran and the pipeline is green. Nothing secret here."
        self.assertEqual(redact_secrets(prose), prose)


if __name__ == "__main__":
    unittest.main()
