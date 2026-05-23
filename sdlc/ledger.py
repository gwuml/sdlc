"""Evidence ledger for each SDLC run."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import secrets
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Iterable, Mapping

try:  # pragma: no cover - Windows fallback is exercised by behavior tests.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from .util import append_jsonl, now_iso, redact_secrets, sha256_text

LEDGER_EVENT_SCHEMA = "sdlc.ledger.event.v1"
LEDGER_ARTIFACT_SCHEMA = "sdlc.ledger.artifact.v1"
LEDGER_SIGNATURE_SCHEMA = "sdlc.ledger.hmac.v1"
LEGACY_PREFIX_SEAL_EVENT = "ledger.legacy_prefix_sealed"
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def ledger_event_digest(payload: dict[str, Any]) -> str:
    """Return the canonical digest for a ledger event payload."""
    unsigned = {key: value for key, value in payload.items() if key not in {"event_sha256", "ledger_signature"}}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_text(canonical)


def ledger_event_origin_signature(payload: Mapping[str, object], key: bytes) -> str:
    unsigned = {item_key: value for item_key, value in payload.items() if item_key != "ledger_signature"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def ledger_key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def is_origin_authenticated_ledger_event(event: Mapping[str, object], *, run_dir: Path | None = None, key: bytes | None = None) -> bool:
    signature = event.get("ledger_signature")
    if not isinstance(signature, Mapping):
        return False
    if signature.get("scheme") != LEDGER_SIGNATURE_SCHEMA:
        return False
    key = key or _load_ledger_key(run_dir, str(event.get("run_id") or ""), create=False)
    if key is None:
        return False
    if signature.get("key_id") != ledger_key_id(key):
        return False
    signed = signature.get("signature")
    if not isinstance(signed, str) or len(signed) != 64:
        return False
    expected = ledger_event_origin_signature(event, key)
    return hmac.compare_digest(expected, signed)


def is_canonical_ledger_event(
    event: Mapping[str, object],
    *,
    sequence: int | None = None,
    previous_sha256: str | None = None,
    require_origin: bool = False,
    run_dir: Path | None = None,
) -> bool:
    if event.get("ledger_schema") != LEDGER_EVENT_SCHEMA:
        return False
    if sequence is not None and event.get("ledger_sequence") != sequence:
        return False
    if (sequence is not None or previous_sha256 is not None) and event.get("prev_event_sha256") != previous_sha256:
        return False
    event_sha256 = event.get("event_sha256")
    if not isinstance(event_sha256, str) or not event_sha256:
        return False
    if event_sha256 != ledger_event_digest(dict(event)):
        return False
    if require_origin and not is_origin_authenticated_ledger_event(event, run_dir=run_dir):
        return False
    return True


def canonical_chain_start(
    events: Iterable[Mapping[str, object]],
    *,
    require_origin: bool = False,
    run_dir: Path | None = None,
) -> tuple[int, str | None] | None:
    event_list = list(events)
    if not event_list:
        return 0, None
    if is_canonical_ledger_event(event_list[0], sequence=0, previous_sha256=None, require_origin=require_origin, run_dir=run_dir):
        return 0, None
    if not require_origin:
        return None
    return _legacy_prefix_boundary(event_list, run_dir=run_dir)


def is_canonical_artifact_event(
    event: Mapping[str, object],
    *,
    run_id: str,
    path: str,
    sha256: str,
    allowed_events: set[str] | None = None,
    require_origin: bool = False,
    run_dir: Path | None = None,
) -> bool:
    event_name = event.get("event")
    if not isinstance(event_name, str) or not event_name:
        return False
    if allowed_events is not None and event_name not in allowed_events:
        return False
    return (
        event.get("artifact_schema") == LEDGER_ARTIFACT_SCHEMA
        and event.get("run_id") == run_id
        and event.get("path") == path
        and event.get("sha256") == sha256
        and is_canonical_ledger_event(event, require_origin=require_origin, run_dir=run_dir)
    )


def canonical_artifact_event(
    events: Iterable[Mapping[str, object]],
    *,
    run_id: str,
    path: str,
    sha256: str,
    allowed_events: set[str] | None = None,
    require_origin: bool = False,
    run_dir: Path | None = None,
) -> dict[str, object] | None:
    event_list = list(events)
    start = canonical_chain_start(event_list, require_origin=require_origin, run_dir=run_dir)
    if start is None:
        return None
    start_index, previous_sha256 = start
    match: dict[str, object] | None = None
    for sequence in range(start_index, len(event_list)):
        event = event_list[sequence]
        if not is_canonical_ledger_event(
            event,
            sequence=sequence,
            previous_sha256=previous_sha256,
            require_origin=require_origin,
            run_dir=run_dir,
        ):
            return None
        if is_canonical_artifact_event(
            event,
            run_id=run_id,
            path=path,
            sha256=sha256,
            allowed_events=allowed_events,
            require_origin=require_origin,
            run_dir=run_dir,
        ):
            match = dict(event)
        event_sha256 = event.get("event_sha256")
        previous_sha256 = event_sha256 if isinstance(event_sha256, str) else None
    return match


def _legacy_prefix_boundary(events: list[Mapping[str, object]], *, run_dir: Path | None) -> tuple[int, str | None] | None:
    for index, event in enumerate(events):
        if event.get("event") != LEGACY_PREFIX_SEAL_EVENT:
            continue
        if event.get("legacy_line_count") != index:
            continue
        previous_sha256 = _event_link_hash(events[index - 1]) if index else None
        if is_canonical_ledger_event(
            event,
            sequence=index,
            previous_sha256=previous_sha256,
            require_origin=True,
            run_dir=run_dir,
        ):
            return index, previous_sha256
    return None


def _event_link_hash(event: Mapping[str, object]) -> str:
    event_sha256 = event.get("event_sha256")
    if isinstance(event_sha256, str) and event_sha256:
        return event_sha256
    return ledger_event_digest(dict(event))


class Ledger:
    def __init__(self, run_dir: Path, run_id: str):
        self.run_dir = run_dir
        self.run_id = run_id
        self.events_path = run_dir / "events.jsonl"
        self.artifacts_dir = run_dir / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def event(self, event: str, **kwargs: Any) -> None:
        with self._locked_events_file():
            self._append_event_locked(event, **kwargs)

    def seal_legacy_prefix(self, *, reason: str) -> None:
        """Record a signed boundary for pre-HMAC ledger history.

        The seal does not make legacy events release-valid evidence. It binds
        the byte-for-byte legacy prefix so later validators can accept a signed
        epoch after the boundary without silently trusting old mutable records.
        """
        with self._locked_events_file():
            prefix_bytes = self.events_path.read_bytes() if self.events_path.exists() else b""
            prefix_lines = [line for line in prefix_bytes.decode("utf-8", errors="replace").splitlines() if line.strip()]
            self._append_event_locked(
                LEGACY_PREFIX_SEAL_EVENT,
                legacy_line_count=len(prefix_lines),
                legacy_prefix_sha256=hashlib.sha256(prefix_bytes).hexdigest(),
                reason=reason,
            )

    def artifact(self, relative_path: str, content: str, *, event: str = "artifact.written", redact: bool = True, **kwargs: Any) -> str:
        reserved = {"path", "sha256", "artifact_schema"}
        if collision := reserved.intersection(kwargs):
            raise ValueError("Artifact event kwargs cannot override reserved provenance fields: " + ", ".join(sorted(collision)))
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_content = redact_secrets(content) if redact else content
        path.write_text(safe_content, encoding="utf-8")
        digest = sha256_text(safe_content)
        self.event(event, path=relative_path, sha256=digest, artifact_schema=LEDGER_ARTIFACT_SCHEMA, **kwargs)
        return relative_path

    def _next_sequence_and_previous_hash(self) -> tuple[int, str | None]:
        if not self.events_path.exists():
            return 0, None
        lines = [line for line in self.events_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        if not lines:
            return 0, None
        previous_line = lines[-1]
        try:
            previous_event = json.loads(previous_line)
        except json.JSONDecodeError:
            return len(lines), sha256_text(previous_line)
        previous_hash = previous_event.get("event_sha256")
        if isinstance(previous_hash, str) and previous_hash:
            return len(lines), previous_hash
        return len(lines), ledger_event_digest(previous_event)

    def _origin_signature(self, payload: dict[str, Any]) -> dict[str, str] | None:
        key = _load_ledger_key(self.run_dir, self.run_id, create=True)
        if key is None:
            return None
        return {
            "scheme": LEDGER_SIGNATURE_SCHEMA,
            "key_id": ledger_key_id(key),
            "signature": ledger_event_origin_signature(payload, key),
        }

    def _append_event_locked(self, event: str, **kwargs: Any) -> None:
        sequence, previous = self._next_sequence_and_previous_hash()
        payload = {
            "ts": now_iso(),
            "run_id": self.run_id,
            "event": event,
            "ledger_schema": LEDGER_EVENT_SCHEMA,
            "ledger_sequence": sequence,
            "prev_event_sha256": previous,
            **kwargs,
        }
        payload["event_sha256"] = ledger_event_digest(payload)
        origin_signature = self._origin_signature(payload)
        if origin_signature is not None:
            payload["ledger_signature"] = origin_signature
        append_jsonl(self.events_path, payload)

    @contextmanager
    def _locked_events_file(self) -> Iterator[None]:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.run_dir / "events.lock"
        lock_key = str(lock_path.resolve(strict=False))
        with _THREAD_LOCKS_GUARD:
            thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.Lock())
        with thread_lock:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with lock_path.open("a", encoding="utf-8") as lock_handle:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _load_ledger_key(run_dir: Path | None, run_id: str, *, create: bool) -> bytes | None:
    env_key = os.environ.get("SDLC_LEDGER_HMAC_KEY", "")
    if env_key:
        return env_key.encode("utf-8")
    env_key_file = os.environ.get("SDLC_LEDGER_HMAC_KEY_FILE", "")
    if env_key_file:
        try:
            key_path = Path(env_key_file).expanduser().resolve(strict=True)
            if run_dir is not None and _path_inside_boundary(key_path, _repo_root_from_run_dir(run_dir), run_dir):
                return None
            return key_path.read_bytes()
        except OSError:
            return None
    if run_dir is None:
        return None
    key_path = _ledger_key_path(run_dir, run_id)
    if key_path.exists():
        try:
            return key_path.read_bytes()
        except OSError:
            return None
    if not create:
        return None
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(key_path, flags, 0o600)
    except FileExistsError:
        try:
            return key_path.read_bytes()
        except OSError:
            return None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
    return key


def _ledger_key_path(run_dir: Path, run_id: str) -> Path:
    configured = os.environ.get("SDLC_LEDGER_KEY_DIR", "").strip()
    repo = _repo_root_from_run_dir(run_dir)
    if configured:
        base = Path(configured).expanduser()
    elif repo is not None:
        base = repo.parent / ".sdlc-ledger-keys"
    else:
        base = run_dir.parent / ".ledger-keys"
    repo_identity = str((repo or run_dir).resolve(strict=False))
    repo_digest = hashlib.sha256(repo_identity.encode("utf-8")).hexdigest()[:16]
    return base / repo_digest / f"{run_id}.key"


def _repo_root_from_run_dir(run_dir: Path) -> Path | None:
    parts = run_dir.resolve(strict=False).parts
    for index in range(len(parts) - 2):
        if parts[index] == ".sdlc" and parts[index + 1] == "runs":
            return Path(*parts[:index])
    return None


def _path_inside_boundary(path: Path, repo: Path | None, run_dir: Path | None) -> bool:
    for base in (repo, run_dir):
        if base is None:
            continue
        try:
            path.relative_to(base.resolve(strict=False))
            return True
        except ValueError:
            continue
    return False
