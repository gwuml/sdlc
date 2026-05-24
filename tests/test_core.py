from __future__ import annotations

import json
import io
import hashlib
import hmac
import os
import shlex
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import sdlc.cli as cli_module
from sdlc.adapters import ADAPTERS, ClaudeAdapter, CodexAdapter, GeminiAdapter, KimiAdapter, adapter_from_policy
from sdlc.classifier import classify_feature
from sdlc.attestations import _verify_manifest_entries
from sdlc.cli import _final_report_attestation_event_error, _ledger_event_records_after_sequence, _ledger_integrity_errors, _release_git_provenance_source_error, _release_readiness_errors, _validate_final_report_gate_completion, _validate_git_provenance_payload, _validate_non_placeholder_evidence, main
from sdlc.engine import RunStore, _create_audit_workspace, _parse_worker_findings, _repo_snapshot as engine_repo_snapshot, _worker_declared_verdict, final_verdict, run_dry_gates
from sdlc.ledger import LEDGER_ARTIFACT_SCHEMA, LEDGER_EVENT_SCHEMA, Ledger, canonical_artifact_event, is_canonical_artifact_event, is_canonical_ledger_event, is_origin_authenticated_ledger_event, ledger_event_digest
from sdlc.memory import export_memory
from sdlc.models import Finding, GateState, open_findings
from sdlc.pipeline import DEFAULT_GATES
from sdlc.prompts import render_redteam_prompt
from sdlc.reporting import build_report
from sdlc.util import git_current_branch, read_json, run_cmd, write_json
from sdlc.validation import validate_json_schema


for _worker_env_key in ("SDLC_WORKER_EXECUTION", "SDLC_WORKER_REPO", "SDLC_WORKER_RUN_ID", "SDLC_WORKER_SANITIZED_ENV"):
    os.environ.pop(_worker_env_key, None)


def ensure_git_fixture(repo: Path, run_id: str) -> str:
    if run_cmd(["git", "rev-parse", "--is-inside-work-tree"], repo)["returncode"] != 0:
        if run_cmd(["git", "init"], repo)["returncode"] != 0:
            raise AssertionError("git init failed for test fixture")
        self_email = run_cmd(["git", "config", "user.email", "sdlc@example.test"], repo)
        self_name = run_cmd(["git", "config", "user.name", "SDLC Test"], repo)
        if self_email["returncode"] != 0 or self_name["returncode"] != 0:
            raise AssertionError("git config failed for test fixture")
    branch = f"sdlc/{run_id}"
    if run_cmd(["git", "checkout", "-B", branch], repo)["returncode"] != 0:
        raise AssertionError("git branch setup failed for test fixture")
    if run_cmd(["git", "rev-parse", "--verify", "HEAD"], repo)["returncode"] != 0:
        (repo / "fixture.txt").write_text(f"fixture for {run_id}\n", encoding="utf-8")
        if run_cmd(["git", "add", "fixture.txt"], repo)["returncode"] != 0:
            raise AssertionError("git add failed for test fixture")
        if run_cmd(["git", "commit", "-m", "chore: fixture"], repo)["returncode"] != 0:
            raise AssertionError("git commit failed for test fixture")
    store = RunStore(repo)
    plan = store.load_plan(run_id)
    plan.branch = branch
    store.save_plan(plan)
    if run_cmd(["git", "add", ".gitignore", ".sdlc"], repo)["returncode"] != 0:
        raise AssertionError("git add baseline failed for test fixture")
    staged = run_cmd(["git", "diff", "--cached", "--quiet"], repo)
    if staged["returncode"] == 1 and run_cmd(["git", "commit", "-m", "chore: sdlc fixture"], repo)["returncode"] != 0:
        raise AssertionError("git baseline commit failed for test fixture")
    return branch


def git_transcript_text(gate_id: str, key: str, command: list[str], result: dict[str, object], *, stdout_override: str | None = None) -> str:
    stdout = str(result.get("stdout", "") if stdout_override is None else stdout_override)
    stderr = str(result.get("stderr", ""))
    return "\n".join([
        f"# {gate_id}.{key}",
        "artifact_type: machine_git_command_transcript",
        f"provenance: git.command_capture for {gate_id}.{key}",
        f"scope: machine captured git evidence for {gate_id}.{key}",
        "acceptance: release validation parses command, cwd, timestamp, returncode, stdout, stderr, and branch semantics.",
        f"timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"cwd: {result.get('cwd', '<test-repo>')}",
        f"command: {' '.join(command)}",
        f"returncode: {result.get('returncode')}",
        "stdout:",
        stdout if stdout else "<empty>",
        "stderr:",
        stderr if stderr else "<empty>",
        "Concrete references: .sdlc/runs/events.jsonl, sdlc/cli.py, tests/test_core.py, git.command_capture.",
        "",
    ])


def append_unsigned_canonical_event(run_dir: Path, payload: dict[str, object]) -> dict[str, object]:
    events_path = run_dir / "events.jsonl"
    lines = [line for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()] if events_path.exists() else []
    previous = json.loads(lines[-1]).get("event_sha256") if lines else None
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ledger_schema": LEDGER_EVENT_SCHEMA,
        "ledger_sequence": len(lines),
        "prev_event_sha256": previous,
        **payload,
    }
    event["event_sha256"] = ledger_event_digest(event)
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def git_provenance_payload(plan: object, cwd: Path) -> dict[str, object]:
    branch = str(getattr(plan, "branch"))
    head = "a" * 40
    timestamp = datetime.now(timezone.utc).isoformat()

    def command_payload(command: list[str], stdout: str) -> dict[str, object]:
        return {
            "command": command,
            "cwd": str(cwd),
            "timestamp": timestamp,
            "returncode": 0,
            "stdout": stdout,
            "stderr": "",
        }

    return {
        "schema_version": 1,
        "run_id": getattr(plan, "run_id"),
        "captured_at": timestamp,
        "repo": str(cwd),
        "expected_branch": branch,
        "branch": {"current": branch, "protected": False, "matches_plan": True},
        "head": {"sha": head, "subject": "feat: release fixture", "exists": True},
        "commit": {"message": "feat: release fixture", "created_by_sdlc": True, "artifact": "artifacts/git_commit_fixture.md"},
        "working_tree": {"status_short": f"## {branch}\n"},
        "pr": {"mode": "planned", "artifact": "artifacts/git_pr_plan.md"},
        "ci": {"mode": "local_release_gate_state", "status": "passed", "source_gates": {}},
        "commands": {
            "inside_work_tree": command_payload(["git", "rev-parse", "--is-inside-work-tree"], "true\n"),
            "current_branch": command_payload(["git", "branch", "--show-current"], f"{branch}\n"),
            "status_short": command_payload(["git", "status", "--short", "--branch"], f"## {branch}\n"),
            "remote_summary": command_payload(["git", "remote", "-v"], ""),
            "head_sha": command_payload(["git", "rev-parse", "HEAD"], f"{head}\n"),
            "head_subject": command_payload(["git", "log", "-1", "--pretty=%s"], "feat: release fixture\n"),
        },
        "environment": {"ci": False, "github_run_id_present": False},
    }


def record_gate_evidence(repo: Path, run_id: str, gate_id: str, actor: str) -> str:
    gate_def = next(item for item in DEFAULT_GATES if item.id == gate_id)
    run_dir = RunStore(repo).run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    lines = [f"# {gate_id} source evidence", ""]
    artifact_args: list[str] = ["--artifact"]
    semantics = {
        "adr": "Decision: require concrete artifact bindings. Consequence: release validation fails on digest drift.",
        "api_contracts": "Command contract: sdlc gate evidence records required artifact references and sha256 bindings.",
        "data_contracts": "JSON schema contract: gate evidence contains artifact_bindings and source_evidence fields.",
        "invariants": "Invariant: every required artifact resolves to an existing file with provenance.",
        "failure_modes": "Failure mode: missing, stale, or source-summary-only evidence blocks GO.",
        "trust_boundaries": "Trust boundary: source repo, run ledger, and worker output remain separated.",
        "threat_model": "Threat model: fabricated evidence and stale closure attempts are rejected.",
        "abuse_cases": "Abuse case: marker-only text cannot satisfy required artifacts.",
        "misuse_cases": "Misuse case: implementers cannot close their own findings.",
        "security_acceptance_criteria": "Security acceptance criteria: no open CRITICAL/HIGH findings and ledger-backed validations.",
        "metrics": "Metric: release readiness exposes blocker counts and per-gate release state.",
        "logs": "Log: events.jsonl captures gate, finding, worker, and attestation events.",
        "alerts": "Alert: release validation returns non-zero when required evidence is missing.",
        "runbook": "Runbook: run tests, validate, scan, red-team, close findings, attest, then report.",
        "incident_response_notes": "Incident response: keep deploy skipped and reopen findings on validation regression.",
    }
    git_commands = {
        ("repo_context_env_branch", "git_status"): ["git", "status", "--short", "--branch"],
        ("repo_context_env_branch", "current_branch"): ["git", "branch", "--show-current"],
        ("repo_context_env_branch", "remote_summary"): ["git", "remote", "-v"],
        ("baseline_freeze", "git_status_before"): ["git", "status", "--short", "--branch"],
        ("commit_branch_pr_ci", "branch_name"): ["git", "branch", "--show-current"],
    }
    if any(gate_id == item[0] for item in git_commands):
        ensure_git_fixture(repo, run_id)
    for key in gate_def.required_artifacts:
        artifact_rel = f"artifacts/gates/{gate_id}/{key}.md"
        if (gate_id, key) in git_commands:
            command = git_commands[(gate_id, key)]
            result = run_cmd(command, repo)
            artifact_text = git_transcript_text(gate_id, key, command, result)
        else:
            artifact_text = "\n".join([
                f"# {gate_id}.{key}",
                "artifact_type: gate_required_artifact",
                f"provenance: gate.required_artifact_recorded for {gate_id}.{key}",
                f"scope: {gate_def.title} / {key}",
                f"acceptance: release validation must reject this artifact if the path, sha256, or key-specific content is missing.",
                f"evidence_id: {gate_id}.{key}",
                f"claim: {key} is substantively satisfied for {gate_id} by this gate-specific artifact.",
                "method: ledger-backed artifact review plus focused command validation.",
                f"result: {semantics.get(key, f'{key} gate-specific evidence is recorded for {gate_def.title}.')}",
                "limitations: this fixture proves validator behavior and is not production rollout evidence.",
                f"supporting_artifacts: artifacts/gates/{gate_id}/{key}.md",
                f"{key} evidence for {gate_id} is bound to this run artifact and ledger event.",
                semantics.get(key, f"{key}: gate-specific evidence for {gate_def.title}."),
                "Command: python -m unittest discover -s tests",
                "returncode: 0",
                "Concrete references: tests/test_core.py, sdlc/cli.py, .sdlc/schemas/gate_result.schema.json, gate.evidence_recorded.",
            ])
        ledger.artifact(
            artifact_rel,
            artifact_text + "\n",
            event="gate.required_artifact_recorded",
            gate=gate_id,
            artifact_key=key,
        )
        lines.extend([
            f"## {key}",
            (
                f"evidence_id: {gate_id}.{key}\n"
                f"claim: Substantive {key} evidence for {gate_id} is recorded in {artifact_rel}.\n"
                f"result: {semantics.get(key, f'{key} gate-specific evidence for {gate_def.title}.')}\n"
                f"Concrete reference: tests/test_core.py and command python -m unittest discover -s tests returncode: 0. "
                f"Ledger event gate.required_artifact_recorded binds this required artifact before gate.evidence_recorded."
            ),
            "",
        ])
        artifact_args.append(f"{key}={artifact_rel}")
    source_rel = f"artifacts/gates/{gate_id}/source.md"
    ledger.artifact(source_rel, "\n".join(lines) + "\n", event="gate.source_evidence_recorded", gate=gate_id)
    result = main(["--repo", str(repo), "gate", "evidence", run_id, gate_id, "--actor", actor, *artifact_args, "--source", source_rel])
    if result != 0:
        raise AssertionError(f"gate evidence failed for {gate_id}: {result}")
    return f".sdlc/runs/{run_id}/artifacts/gates/{gate_id}-evidence.json"


def record_finding_closure_evidence(
    repo: Path,
    run_id: str,
    finding_id: str,
    *,
    validated_by: str = "agent_6_redteam_deploy_rollback",
    validator_actor_proof: str | None = None,
) -> list[str]:
    run_dir = RunStore(repo).run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    diff = ledger.artifact(
        f"artifacts/findings/{finding_id}/remediation.patch",
        f"diff --git a/sdlc/cli.py b/sdlc/cli.py\n--- a/sdlc/cli.py\n+++ b/sdlc/cli.py\n@@ -1 +1 @@\n-# before {finding_id}\n+# after {finding_id}\n",
        event="finding.remediation_diff",
        finding_id=finding_id,
    )
    validation = ledger.artifact(
        f"artifacts/findings/{finding_id}/validation.txt",
        f"{finding_id} independent second validation\nCommand: python -m unittest discover -s tests\nreturncode: 0\nRan focused tests\nOK\n",
        event="finding.remediation_validation",
        finding_id=finding_id,
        returncode=0,
        validated_by=validated_by,
        **({"validator_actor_proof_sha256": hashlib.sha256(validator_actor_proof.encode("utf-8")).hexdigest()} if validator_actor_proof else {}),
    )
    summary = ledger.artifact(
        f"artifacts/findings/{finding_id}/summary.md",
        f"# {finding_id} remediation summary\n\nFix summary: changes implemented and independently validated for {finding_id}.\n",
        event="finding.remediation_summary",
        finding_id=finding_id,
    )
    return [f".sdlc/runs/{run_id}/{rel}" for rel in (diff, validation, summary)]


def record_risk_acceptance_evidence(repo: Path, run_id: str, finding_id: str, title: str | None = None) -> str:
    run_dir = RunStore(repo).run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    title_text = f" / {title}" if title else ""
    rel = ledger.artifact(
        f"artifacts/findings/{finding_id}/risk_acceptance.md",
        (
            f"{finding_id}{title_text} residual risk acceptance.\n"
            f"Reason: human accepted residual risk with finding-specific traceability for {finding_id}.\n"
            "This risk acceptance remains visible to release validation.\n"
        ),
        event="finding.risk_acceptance",
        finding_id=finding_id,
    )
    return f".sdlc/runs/{run_id}/{rel}"


def actor_proof(run_id: str, finding_id: str, actor: str, key: str) -> str:
    message = f"{run_id}:{finding_id}:{actor}:finding.close".encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def deploy_residual_actor_proof(run_id: str, env: str, actor: str, key: str) -> str:
    message = f"{run_id}:deploy:{env}:{actor}:deploy.verify_residual_risk".encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def deploy_approval_actor_proof(run_id: str, env: str, actor: str, key: str, repo: Path, evidence_paths: list[str]) -> str:
    evidence = []
    for rel in evidence_paths:
        content = (repo / rel).read_bytes()
        evidence.append({
            "path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
    payload: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "environment": env,
        "actor": actor,
        "evidence": evidence,
    }
    payload["binding_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    message = f"{run_id}:deploy:{env}:{actor}:deploy.approve:{payload['binding_sha256']}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


class CoreTests(unittest.TestCase):
    def _mark_prior_gates_go(self, store: RunStore, run_id: str, target_gate_id: str) -> None:
        plan = store.load_plan(run_id)
        target = next(gate for gate in plan.gates if gate.id == target_gate_id)
        for gate in plan.gates:
            if gate.order < target.order and gate.state != "SKIPPED":
                gate.state = "GO"
                gate.verdict = "GO"
                gate.evidence = ["test-prerequisite-evidence.md"]
        store.save_plan(plan)

    def test_pipeline_has_world_class_gates(self) -> None:
        self.assertGreaterEqual(len(DEFAULT_GATES), 25)
        ids = {gate.id for gate in DEFAULT_GATES}
        self.assertIn("supply_chain_sbom", ids)
        self.assertIn("data_privacy_secrets", ids)
        self.assertIn("independent_redteam_cross_model", ids)
        self.assertIn("evidence_traceability_attestations", ids)

    def test_classifier_activates_ui_security_infra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            result = classify_feature("Build RBAC dashboard with audit logs and deploy monitoring", repo)
            self.assertTrue(result.has_ui)
            self.assertTrue(result.has_security)
            self.assertTrue(result.has_infra)
            self.assertEqual(result.risk_level, "EXTREME")
            agent_ids = {agent["id"] for agent in result.activated_agents}
            self.assertIn("agent_7_ui_architect", agent_ids)
            self.assertIn("agent_8_cybersecurity_engineer", agent_ids)
            self.assertIn("agent_9_sre_sysadmin", agent_ids)

    def test_classifier_keeps_trivial_fibonacci_low_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            result = classify_feature("I need a fibonacci series", repo)
            self.assertEqual(result.risk_level, "LOW")
            self.assertFalse(result.has_ui)
            self.assertFalse(result.has_infra)

    def test_cli_init_plan_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertTrue((repo / ".sdlc" / "pipeline.json").exists())
            gitignore_text = (repo / ".gitignore").read_text(encoding="utf-8")
            self.assertIn(".sdlc/runs/", gitignore_text)
            self.assertIn(".sdlc/memory.sqlite", gitignore_text)
            self.assertIs(read_json(repo / ".sdlc" / "policies" / "high-risk.json", {}).get("actor_proof_required_for_finding_closure"), True)
            run_id = "test-rbac"
            self.assertEqual(main(["--repo", str(repo), "plan", "Build RBAC dashboard", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            self.assertEqual(plan.run_id, run_id)
            self.assertGreaterEqual(len(plan.gates), 25)
            self.assertTrue((store.run_dir(run_id) / "prompts" / "execution_prompt.md").exists())
            self.assertEqual(main(["--repo", str(repo), "validate", "--run-id", run_id]), 0)

    def test_ledger_provenance_accepts_only_canonical_artifact_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "ledger-provenance"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            ledger = Ledger(run_dir, run_id)
            ledger.event("run.created")
            content = "canonical artifact evidence\n"
            rel = ledger.artifact(
                "artifacts/gates/intake_scope/feature_request.md",
                content,
                event="gate.required_artifact_recorded",
                gate="intake_scope",
                artifact_key="feature_request",
            )
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            events = [json.loads(line) for line in ledger.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            canonical = canonical_artifact_event(
                events,
                run_id=run_id,
                path=rel,
                sha256=digest,
                allowed_events={"gate.required_artifact_recorded"},
            )
            self.assertIsNotNone(canonical)
            self.assertTrue(
                is_canonical_artifact_event(
                    canonical or {},
                    run_id=run_id,
                    path=rel,
                    sha256=digest,
                    allowed_events={"gate.required_artifact_recorded"},
                )
            )

            forged = {"run_id": run_id, "event": "forged.path_sha", "path": rel, "sha256": digest}
            self.assertFalse(is_canonical_artifact_event(forged, run_id=run_id, path=rel, sha256=digest))
            self.assertIsNone(canonical_artifact_event([forged], run_id=run_id, path=rel, sha256=digest))

    def test_ledger_provenance_rejects_tampered_event_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "ledger-provenance-chain"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            ledger = Ledger(run_dir, run_id)
            content = "chain-bound artifact evidence\n"
            rel = ledger.artifact("artifacts/findings/HIGH-139/validation.txt", content, event="finding.remediation_validation")
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            events = [json.loads(line) for line in ledger.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertIsNotNone(canonical_artifact_event(events, run_id=run_id, path=rel, sha256=digest))

            forged = {"run_id": run_id, "event": "worker.completed", "path": rel, "sha256": digest}
            self.assertIsNone(canonical_artifact_event(events + [forged], run_id=run_id, path=rel, sha256=digest))

            tampered = [dict(item) for item in events]
            tampered[0]["event"] = "finding.remediation_summary"
            self.assertIsNone(canonical_artifact_event(tampered, run_id=run_id, path=rel, sha256=digest))

    def test_ledger_parallel_writes_preserve_signed_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "ledger-parallel"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            ledger = Ledger(run_dir, run_id)

            def write_event(index: int) -> None:
                ledger.event("agents.task_started", task_id=f"task-{index}")

            with ThreadPoolExecutor(max_workers=12) as executor:
                list(executor.map(write_event, range(60)))

            events = [json.loads(line) for line in ledger.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(events), 60)
            previous = None
            for sequence, event in enumerate(events):
                self.assertTrue(
                    is_canonical_ledger_event(
                        event,
                        sequence=sequence,
                        previous_sha256=previous,
                        require_origin=True,
                        run_dir=run_dir,
                    )
                )
                previous = event["event_sha256"]

    def test_ledger_hmac_key_file_inside_repo_is_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "ledger-key-boundary"
            run_dir = repo / ".sdlc" / "runs" / run_id
            key_file = repo / "repo-local-ledger.key"
            key_file.write_text("do-not-use-repo-local-ledger-secret", encoding="utf-8")
            old_key_file = os.environ.get("SDLC_LEDGER_HMAC_KEY_FILE")
            old_key = os.environ.get("SDLC_LEDGER_HMAC_KEY")
            old_key_dir = os.environ.get("SDLC_LEDGER_KEY_DIR")
            os.environ["SDLC_LEDGER_HMAC_KEY_FILE"] = str(key_file)
            os.environ.pop("SDLC_LEDGER_HMAC_KEY", None)
            os.environ.pop("SDLC_LEDGER_KEY_DIR", None)
            try:
                ledger = Ledger(run_dir, run_id)
                ledger.event("run.created")
                event = json.loads(ledger.events_path.read_text(encoding="utf-8").splitlines()[0])
                self.assertNotIn("ledger_signature", event)
                self.assertFalse(is_origin_authenticated_ledger_event(event, run_dir=run_dir))
            finally:
                if old_key_file is None:
                    os.environ.pop("SDLC_LEDGER_HMAC_KEY_FILE", None)
                else:
                    os.environ["SDLC_LEDGER_HMAC_KEY_FILE"] = old_key_file
                if old_key is not None:
                    os.environ["SDLC_LEDGER_HMAC_KEY"] = old_key
                if old_key_dir is not None:
                    os.environ["SDLC_LEDGER_KEY_DIR"] = old_key_dir

    def test_legacy_ledger_prefix_can_be_sealed_without_trusting_old_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "ledger-legacy-seal"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            run_dir.mkdir(parents=True)
            events_path = run_dir / "events.jsonl"
            events_path.write_text(json.dumps({"event": "legacy.artifact", "run_id": run_id, "path": "artifacts/old.md", "sha256": "0" * 64}) + "\n", encoding="utf-8")
            ledger = Ledger(run_dir, run_id)
            ledger.seal_legacy_prefix(reason="test migration boundary")
            content = "Finding HIGH-139 remediation evidence after a signed legacy boundary.\nreturncode: 0\n"
            rel = ledger.artifact(
                "artifacts/findings/HIGH-139/validation.txt",
                content,
                event="finding.remediation_validation",
                finding_id="HIGH-139",
                returncode=0,
                validated_by="agent_6_redteam_deploy_rollback",
            )
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            self.assertEqual(_ledger_integrity_errors(run_dir), [])
            self.assertIsNotNone(
                canonical_artifact_event(
                    events,
                    run_id=run_id,
                    path=rel,
                    sha256=digest,
                    allowed_events={"finding.remediation_validation"},
                    require_origin=True,
                    run_dir=run_dir,
                )
            )
            self.assertIsNone(
                canonical_artifact_event(
                    events,
                    run_id=run_id,
                    path="artifacts/old.md",
                    sha256="0" * 64,
                    allowed_events={"legacy.artifact"},
                    require_origin=True,
                    run_dir=run_dir,
                )
            )

            text = events_path.read_text(encoding="utf-8")
            events_path.write_text(text.replace("legacy.artifact", "legacy.tampered", 1), encoding="utf-8")
            self.assertTrue(_ledger_integrity_errors(run_dir))

    def test_ledger_seal_legacy_command_records_explicit_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "ledger-seal-command"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            run_dir = repo / ".sdlc" / "runs" / run_id
            run_dir.mkdir(parents=True)
            (run_dir / "events.jsonl").write_text(json.dumps({"event": "legacy.start", "run_id": run_id}) + "\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "ledger", "seal-legacy", run_id, "--reason", "test boundary"]), 0)
            self.assertEqual(_ledger_integrity_errors(run_dir), [])
            self.assertNotEqual(main(["--repo", str(repo), "ledger", "seal-legacy", run_id, "--reason", "duplicate boundary"]), 0)

    def test_audit_copy_can_verify_ledger_hash_chain_without_origin_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            audit_repo = Path(tmp) / "audit"
            run_id = "ledger-audit-copy"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Audit copied ledger", "--run-id", run_id]), 0)
            run_dir = repo / ".sdlc" / "runs" / run_id
            copied_run_dir = audit_repo / ".sdlc" / "runs" / run_id
            shutil.copytree(run_dir, copied_run_dir)
            self.assertTrue(_ledger_integrity_errors(copied_run_dir, require_origin=True))
            self.assertEqual(_ledger_integrity_errors(copied_run_dir, require_origin=False), [])

    def test_audit_copy_can_verify_closure_artifacts_without_origin_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            audit_repo = Path(tmp) / "audit"
            run_id = "closure-audit-copy"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Audit copied closure", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-CHAIN",
                severity="MEDIUM",
                title="Closure chain finding",
                evidence=["redteam"],
                impact="Audit workspace must verify copied closure artifacts without private origin key.",
                required_fix="Verify copied ledger hash chain.",
                owner="agent_3_implementation_owner",
                status="CLOSED",
                closed_by="human_security_owner",
                closure_evidence=record_finding_closure_evidence(repo, run_id, "MEDIUM-CHAIN", validated_by="human_security_owner"),
            )])
            copied_run_dir = audit_repo / ".sdlc" / "runs" / run_id
            shutil.copytree(store.run_dir(run_id), copied_run_dir)
            audit_store = RunStore(audit_repo)
            strict_errors = _release_readiness_errors(audit_store, audit_store.load_plan(run_id), audit_store.load_findings(run_id))
            self.assertTrue(any("MEDIUM-CHAIN closure evidence is not release-valid" in error for error in strict_errors), strict_errors)

            old_execution = os.environ.get("SDLC_WORKER_EXECUTION")
            old_readonly = os.environ.get("SDLC_WORKER_AUDIT_READONLY")
            try:
                os.environ["SDLC_WORKER_EXECUTION"] = "1"
                os.environ["SDLC_WORKER_AUDIT_READONLY"] = "1"
                audit_errors = _release_readiness_errors(audit_store, audit_store.load_plan(run_id), audit_store.load_findings(run_id), audit_workspace=True)
            finally:
                if old_execution is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_execution
                if old_readonly is None:
                    os.environ.pop("SDLC_WORKER_AUDIT_READONLY", None)
                else:
                    os.environ["SDLC_WORKER_AUDIT_READONLY"] = old_readonly
            self.assertFalse(any("MEDIUM-CHAIN closure evidence is not release-valid" in error for error in audit_errors), audit_errors)

    def test_ledger_sequence_freshness_detects_same_second_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "ledger-sequence-freshness"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            run_dir.mkdir(parents=True)
            ledger = Ledger(run_dir, run_id)
            report_rel = ledger.artifact("final-report.md", "report\n", event="report.generated")
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            report_event = next(
                event for event in events
                if event.get("event") == "report.generated" and event.get("path") == report_rel
            )
            ledger.event("finding.closed", finding_id="HIGH-999")
            records = _ledger_event_records_after_sequence(run_dir, int(report_event["ledger_sequence"]), ignored_events={"report.generated"})
            self.assertTrue(any(event.get("event") == "finding.closed" for event in records), records)

    def test_start_creates_prework_agent_plan_and_next_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "start-fib"
            self.assertEqual(main(["--repo", str(repo), "start", "I need a fibonacci series", "--run-id", run_id, "--json"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            self.assertEqual(plan.risk_level, "LOW")
            run_dir = store.run_dir(run_id)
            self.assertTrue((run_dir / "artifacts" / "prework" / "intake_brief.json").exists())
            self.assertTrue((run_dir / "artifacts" / "prework" / "standards_mapping.json").exists())
            self.assertTrue((run_dir / "artifacts" / "prework" / "expectations.html").exists())
            self.assertTrue((run_dir / "artifacts" / "agents" / "task-plan.json").exists())
            self.assertTrue((run_dir / "artifacts" / "release" / "next_action.json").exists())
            self.assertTrue((run_dir / "artifacts" / "release" / "readiness.json").exists())

    def test_brief_for_trading_request_asks_blocking_questions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "brief-trading"
            self.assertEqual(main(["--repo", str(repo), "brief", "build a world class trading system", "--run-id", run_id, "--json"]), 0)
            brief = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "prework" / "intake_brief.json")
            self.assertEqual(brief["risk_level"], "EXTREME")
            self.assertIn("finance", brief["domains"])
            self.assertGreaterEqual(len(brief["blocking_questions"]), 3)
            self.assertIn("profitable", brief["forbidden_claims"])

    def test_next_json_reports_first_blocking_gate_without_deploy_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "next-run"
            self.assertEqual(main(["--repo", str(repo), "plan", "Build helper", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "next", run_id, "--json"]), 0)
            self.assertFalse((repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "next_action.json").exists())
            self.assertFalse((repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "readiness.json").exists())
            self.assertEqual(main(["--repo", str(repo), "next", run_id, "--json", "--persist"]), 0)
            payload = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "next_action.json")
            self.assertFalse(payload["release_satisfied"])
            self.assertEqual(payload["top_recommendation"]["action_id"], "gate-intake_scope")
            self.assertNotIn("deploy execute", payload["top_recommendation"]["command"])

    def test_audit_readonly_worker_next_and_report_do_not_write_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "audit-readonly"
            self.assertEqual(main(["--repo", str(repo), "plan", "Audit readonly", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            events_before = (run_dir / "events.jsonl").read_text(encoding="utf-8")
            old_worker = os.environ.get("SDLC_WORKER_EXECUTION")
            old_readonly = os.environ.get("SDLC_WORKER_AUDIT_READONLY")
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            os.environ["SDLC_WORKER_AUDIT_READONLY"] = "1"
            try:
                self.assertEqual(main(["--repo", str(repo), "next", run_id, "--json"]), 0)
                self.assertEqual(main(["--repo", str(repo), "report", run_id, "--print"]), 0)
            finally:
                if old_worker is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_worker
                if old_readonly is None:
                    os.environ.pop("SDLC_WORKER_AUDIT_READONLY", None)
                else:
                    os.environ["SDLC_WORKER_AUDIT_READONLY"] = old_readonly
            self.assertEqual((run_dir / "events.jsonl").read_text(encoding="utf-8"), events_before)
            self.assertFalse((run_dir / "artifacts" / "release" / "next_action.json").exists())
            self.assertFalse((run_dir / "artifacts" / "release" / "readiness.json").exists())
            self.assertFalse((run_dir / "final-report.md").exists())

    def test_status_json_separates_local_and_release_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "status-readiness"
            self.assertEqual(main(["--repo", str(repo), "plan", "Status clarity", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            plan.gates[0].state = "GO"
            plan.gates[0].verdict = "GO"
            plan.gates[0].evidence = ["README.md"]
            store.save_plan(plan)
            self.assertEqual(main(["--repo", str(repo), "status", run_id, "--json"]), 0)
            self.assertFalse((repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "readiness.json").exists())
            self.assertEqual(main(["--repo", str(repo), "status", run_id, "--json", "--persist"]), 0)
            readiness = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "readiness.json")
            self.assertFalse(readiness["release_satisfied"])
            self.assertEqual(readiness["release_verdict"], "NO_GO")
            payload = main(["--repo", str(repo), "next", run_id, "--json"])
            self.assertEqual(payload, 0)
            self.assertFalse((repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "next_action.json").exists())
            payload = main(["--repo", str(repo), "next", run_id, "--json", "--persist"])
            self.assertEqual(payload, 0)
            next_payload = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "release" / "next_action.json")
            self.assertFalse(next_payload["release_satisfied"])

    def test_agents_plan_and_execute_six_role_tasks_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "agents-six"
            self.assertEqual(main(["--repo", str(repo), "start", "Build CLI helper", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "agents", "plan", run_id, "--parallel", "6", "--json"]), 0)
            self.assertEqual(main(["--repo", str(repo), "agents", "execute", run_id, "--parallel", "6", "--json"]), 0)
            task_plan = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "agents" / "task-plan.json")
            self.assertGreaterEqual(task_plan["effective_parallelism"], 6)
            self.assertEqual(len(task_plan["batches"][0]["task_ids"]), 6)
            first_six = {task["agent_id"] for task in task_plan["tasks"][:6]}
            self.assertEqual(len(first_six), 6)
            self.assertTrue(all(task["status"] == "completed" for task in task_plan["tasks"][:6]))

    def test_agents_execute_invokes_workers_only_with_execute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "agents-real-exec"
            bin_dir = repo / "bin"
            bin_dir.mkdir()
            for name in ["codex", "claude"]:
                script = bin_dir / name
                script.write_text("#!/bin/sh\ncat >/dev/null\nprintf '{\"verdict\":\"GO\",\"findings\":[]}\\n'\n", encoding="utf-8")
                script.chmod(0o755)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            try:
                self.assertEqual(main(["--repo", str(repo), "start", "Build CLI helper", "--run-id", run_id]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self.assertEqual(main(["--repo", str(repo), "agents", "execute", run_id, "--parallel", "6", "--execute", "--allow-network", "--json"]), 0)
            finally:
                os.environ["PATH"] = old_path
            run_dir = RunStore(repo).run_dir(run_id)
            task_plan = read_json(run_dir / "artifacts" / "agents" / "task-plan.json")
            self.assertTrue(all(task["execute_requested"] is True for task in task_plan["tasks"][:6]))
            self.assertTrue(any("agent_1_pm_coordinator" in path.name for path in (run_dir / "worker-results").iterdir()))
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(any(event["event"] == "agents.parallel_batch_completed" and event["execute_requested"] is True for event in events))

    def test_agents_execute_blocks_read_only_role_workspace_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "agents-permission"
            bin_dir = repo / "bin"
            bin_dir.mkdir()
            codex = bin_dir / "codex"
            codex.write_text("#!/bin/sh\ncat >/dev/null\nprintf '{}\\n'\n", encoding="utf-8")
            codex.chmod(0o755)
            claude = bin_dir / "claude"
            claude.write_text("#!/bin/sh\ncat >/dev/null\nprintf bad > forbidden.txt\nprintf '{}\\n'\n", encoding="utf-8")
            claude.chmod(0o755)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            try:
                self.assertEqual(main(["--repo", str(repo), "start", "Build CLI helper", "--run-id", run_id]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self.assertNotEqual(main(["--repo", str(repo), "agents", "execute", run_id, "--parallel", "6", "--execute", "--allow-network", "--json"]), 0)
            finally:
                os.environ["PATH"] = old_path
            task_plan = read_json(repo / ".sdlc" / "runs" / run_id / "artifacts" / "agents" / "task-plan.json")
            blocked = [task for task in task_plan["tasks"] if task["worker_family"] == "claude"]
            self.assertTrue(blocked)
            self.assertTrue(all(task["status"] == "blocked_by_permissions" for task in blocked))

    def test_custom_worker_family_is_policy_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "custom-worker"
            self.assertEqual(main(["--repo", str(repo), "plan", "Custom worker", "--run-id", run_id]), 0)
            worker = repo / "custom-worker"
            worker.write_text("#!/bin/sh\ncat >/dev/null\nprintf custom\\n\n", encoding="utf-8")
            worker.chmod(0o755)
            policy = read_json(repo / ".sdlc" / "policies" / "default.json")
            policy["worker_families"] = {"custom": {"command": [str(worker)]}}
            write_json(repo / ".sdlc" / "policies" / "default.json", policy)
            self.assertEqual(main(["--repo", str(repo), "worker", run_id, "custom"]), 0)
            capture = next((repo / ".sdlc" / "runs" / run_id / "worker-results").iterdir())
            result = read_json(capture / "result.json")
            self.assertEqual(result["worker"], "custom")
            self.assertFalse(result["executed"])

    def test_memory_lifecycle_records_exports_and_deletes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "memory-run"
            self.assertEqual(main(["--repo", str(repo), "start", "I need a fibonacci series", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "memory", "record", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "memory", "init", "--json"]), 0)
            self.assertEqual(main(["--repo", str(repo), "memory", "record", run_id, "--json"]), 0)
            self.assertEqual(main(["--repo", str(repo), "memory", "search", "fibonacci", "--json"]), 0)
            exported = export_memory(repo)
            self.assertEqual(len(exported["episodes"]), 1)
            self.assertNotIn("raw_prompt", json.dumps(exported))
            self.assertEqual(main(["--repo", str(repo), "memory", "delete", "--all", "--json"]), 0)
            self.assertFalse((repo / ".sdlc" / "memory.sqlite").exists())

    def test_plan_rejects_run_id_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "plan", "Bad run id", "--run-id", "../escape"]), 0)
            self.assertFalse((repo / ".sdlc" / "escape").exists())

    def test_validate_release_checks_run_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "release-validate"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Validate release", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "validate", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "validate", "--run-id", run_id, "--release"]), 0)

    def test_repeated_artifact_provenance_uses_cached_ledger_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "artifact-index"
            run_dir = Path(tmp) / ".sdlc" / "runs" / run_id
            run_dir.mkdir(parents=True)
            ledger = Ledger(run_dir, run_id)
            artifacts: list[tuple[Path, str]] = []
            for index in range(40):
                rel = ledger.artifact(f"artifacts/perf/{index}.txt", f"evidence {index}\n")
                path = run_dir / rel
                artifacts.append((path, hashlib.sha256(path.read_bytes()).hexdigest()))

            with mock.patch.object(cli_module, "canonical_chain_start", wraps=cli_module.canonical_chain_start) as chain_start:
                for path, digest in artifacts:
                    self.assertIsNotNone(cli_module._ledger_artifact_event(run_dir, path, digest))
                self.assertEqual(chain_start.call_count, 1)

    def test_release_validation_rejects_skipped_gate_when_condition_is_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "skipped-condition"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Conditional deploy", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            gate = next(item for item in plan.gates if item.id == "deploy_rollout_postdeploy")
            gate.state = "SKIPPED"
            gate.verdict = "SKIPPED"
            gate.conditional_on = "production_rollout_allowed"
            store.save_plan(plan)
            errors = _release_readiness_errors(store, plan, [])
            self.assertTrue(any("deploy_rollout_postdeploy has invalid skipped state" in error for error in errors))
            self.assertEqual(final_verdict([], plan), "NO_GO")

    def test_release_validation_accepts_classification_backed_skipped_ui_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "skipped-ui-condition"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Backend utility", "--run-id", run_id, "--ui", "no"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            gate = next(item for item in plan.gates if item.id == "ui_architecture_accessibility")
            self.assertEqual(gate.state, "SKIPPED")
            self.assertEqual(gate.verdict, "SKIPPED")
            errors = _release_readiness_errors(store, plan, [])
            self.assertFalse(any("ui_architecture_accessibility has invalid skipped state" in error for error in errors))

    def test_release_validation_rejects_plan_repo_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            other = Path(tmp) / "other"
            run_id = "repo-mismatch"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Repo mismatch", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            plan.repo = str(other)
            store.save_plan(plan)
            errors = _release_readiness_errors(store, plan, [])
            self.assertTrue(any("repo mismatch" in error for error in errors))

    def test_release_validation_allows_repo_mismatch_only_in_worker_audit_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            audit = root / "audit"
            run_id = "audit-repo-mismatch"
            self.assertEqual(main(["--repo", str(source), "init"]), 0)
            self.assertEqual(main(["--repo", str(source), "plan", "Audit repo mismatch", "--run-id", run_id]), 0)
            ensure_git_fixture(source, run_id)
            shutil.copytree(source, audit, ignore=shutil.ignore_patterns(".git"))
            store = RunStore(audit)
            plan = store.load_plan(run_id)
            strict_errors = _release_readiness_errors(store, plan, [])
            self.assertTrue(any("repo mismatch" in error for error in strict_errors))
            old_value = os.environ.get("SDLC_WORKER_EXECUTION")
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            try:
                audit_errors = _release_readiness_errors(store, plan, [], audit_workspace=True)
            finally:
                if old_value is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_value
            self.assertFalse(any("repo mismatch" in error for error in audit_errors))
            self.assertFalse(any("git work tree" in error for error in audit_errors))

    def test_audit_workspace_git_repo_does_not_replace_plan_repo_provenance(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for audit workspace git provenance tests")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            audit = root / "audit"
            run_id = "audit-git-short-circuit"
            self.assertEqual(main(["--repo", str(source), "init"]), 0)
            self.assertEqual(main(["--repo", str(source), "plan", "Audit git short circuit", "--run-id", run_id]), 0)
            audit.mkdir()
            shutil.copytree(source / ".sdlc", audit / ".sdlc")
            self.assertEqual(run_cmd(["git", "init"], audit)["returncode"], 0)
            store = RunStore(audit)
            plan = store.load_plan(run_id)
            plan.repo = str(root / "missing-source")
            store.save_plan(plan)
            error = _release_git_provenance_source_error(store, plan, audit_workspace=True)
            self.assertIsNotNone(error)
            self.assertIn("valid attested git provenance snapshot", error or "")

    def test_audit_workspace_rejects_unrelated_plan_repo_git(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for audit workspace git provenance tests")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            unrelated = root / "unrelated"
            audit = root / "audit"
            run_id = "audit-unrelated-git"
            self.assertEqual(main(["--repo", str(source), "init"]), 0)
            self.assertEqual(main(["--repo", str(source), "plan", "Reject unrelated audit git", "--run-id", run_id]), 0)
            ensure_git_fixture(source, run_id)
            unrelated.mkdir()
            self.assertEqual(run_cmd(["git", "init"], unrelated)["returncode"], 0)
            audit.mkdir()
            shutil.copytree(source / ".sdlc", audit / ".sdlc")
            store = RunStore(audit)
            plan = store.load_plan(run_id)
            plan.repo = str(unrelated)
            store.save_plan(plan)
            error = _release_git_provenance_source_error(store, plan, audit_workspace=True)
            self.assertIsNotNone(error)
            self.assertIn("ledger-bound run.created source repo", error or "")

    def test_audit_workspace_uses_attested_git_snapshot_when_plan_repo_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            audit = root / "audit"
            run_id = "audit-attested-git"
            self.assertEqual(main(["--repo", str(source), "init"]), 0)
            self.assertEqual(main(["--repo", str(source), "plan", "Audit attested git", "--run-id", run_id]), 0)
            ensure_git_fixture(source, run_id)
            shutil.copytree(source, audit, ignore=shutil.ignore_patterns(".git"))

            store = RunStore(audit)
            plan = store.load_plan(run_id)
            plan.repo = str(root / "missing-source")
            store.save_plan(plan)
            run_dir = store.run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            ledger.seal_legacy_prefix(reason="audit workspace copied without source-repo ledger key")
            ledger.artifact(
                "artifacts/git/provenance.json",
                json.dumps(git_provenance_payload(plan, source), indent=2, sort_keys=True) + "\n",
                event="git.provenance_artifact",
            )
            self.assertEqual(main(["--repo", str(audit), "attest", "manifest", run_id]), 0)
            ledger = Ledger(run_dir, run_id)
            verification = ledger.artifact(
                "artifacts/attestations/verification.json",
                json.dumps({
                    "status": "GO",
                    "verified": True,
                    "artifact_integrity_verified": True,
                    "release_gate_blockers": [],
                    "failures": [],
                }, indent=2, sort_keys=True) + "\n",
                event="attestation.verification_artifact",
                verdict="GO",
            )
            ledger.event("attestation.verified", verdict="GO", failures=[], evidence=[verification])

            old_value = os.environ.get("SDLC_WORKER_EXECUTION")
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            try:
                audit_errors = _release_readiness_errors(store, store.load_plan(run_id), [], audit_workspace=True)
            finally:
                if old_value is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_value
            self.assertFalse(any("git work tree" in error for error in audit_errors))
            self.assertFalse(any("valid attested git provenance snapshot" in error for error in audit_errors))

    def test_audit_workspace_defers_git_snapshot_until_commit_gate_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            audit = root / "audit"
            run_id = "audit-pending-commit-git"
            self.assertEqual(main(["--repo", str(source), "init"]), 0)
            self.assertEqual(main(["--repo", str(source), "plan", "Audit pending commit", "--run-id", run_id]), 0)
            shutil.copytree(source, audit, ignore=shutil.ignore_patterns(".git"))
            store = RunStore(audit)
            plan = store.load_plan(run_id)
            plan.repo = str(root / "missing-source")
            store.save_plan(plan)
            old_value = os.environ.get("SDLC_WORKER_EXECUTION")
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            try:
                audit_errors = _release_readiness_errors(store, store.load_plan(run_id), [], audit_workspace=True)
            finally:
                if old_value is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_value
            self.assertFalse(any("valid attested git provenance snapshot" in error for error in audit_errors), audit_errors)
            self.assertTrue(any("Gate commit_branch_pr_ci is not release-satisfied" in error for error in audit_errors), audit_errors)

    def test_release_validation_rechecks_closed_severe_finding_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "closed-finding-evidence"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Closed finding evidence", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            finding = Finding(
                id="HIGH-CLOSED",
                severity="HIGH",
                title="Closed without evidence",
                evidence=["redteam"],
                impact="Blocks release.",
                required_fix="Add closure evidence.",
                owner="agent_3_implementation_owner",
                status="CLOSED",
                closed_by="agent_6_redteam_deploy_rollback",
                closure_evidence=[],
            )
            errors = _release_readiness_errors(store, plan, [finding])
            self.assertTrue(any("HIGH-CLOSED" in error and "closure evidence" in error for error in errors))

    def test_deferred_medium_or_higher_findings_remain_open_for_release(self) -> None:
        finding = Finding(
            id="HIGH-DEFERRED",
            severity="HIGH",
            title="Deferred high finding",
            evidence=["redteam"],
            impact="Still blocks release validation.",
            required_fix="Close or formally accept with human residual-risk handling.",
            owner="agent_6_redteam_deploy_rollback",
            status="DEFERRED",
            closed_by="human_security_owner",
            closure_evidence=["human deferred"],
        )
        self.assertEqual([item.id for item in open_findings([finding], {"HIGH"})], ["HIGH-DEFERRED"])

    def test_positive_gate_evidence_rejects_generic_multiline_prose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            generic = repo / "generic.md"
            generic.write_text(
                "This is a long explanation.\\n"
                "It uses several lines.\\n"
                "It says the work was reviewed.\\n"
                "It gives no command, digest, path, event, or source reference.\\n",
                encoding="utf-8",
            )
            error = _validate_non_placeholder_evidence(repo, "GO", ["generic.md"])
            self.assertIn("concrete evidence references", error or "")

    def test_release_validation_rejects_quality_scan_redteam_evidence_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "stale-post-commit"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Stale post commit evidence", "--run-id", run_id]), 0)
            branch = ensure_git_fixture(repo, run_id)
            store = RunStore(repo)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("gate.manually_completed", gate="deterministic_quality", verdict="GO")
            ledger.event("gate.manually_completed", gate="qa_tests_integration_smoke", verdict="GO")
            ledger.event("security.scans_completed", verdict="GO")
            ledger.event("redteam.execution_completed", verdict="GO")
            ledger.event("git.commit_created", branch=branch, commit="a" * 40, message="feat: stale evidence")
            errors = _release_readiness_errors(store, store.load_plan(run_id), [])
            self.assertTrue(any("deterministic_quality requires deterministic quality gate completion after the latest sdlc git commit" in error for error in errors))
            self.assertTrue(any("qa_tests_integration_smoke requires QA gate completion after the latest sdlc git commit" in error for error in errors))
            self.assertTrue(any("security_scans requires security scan completion after the latest sdlc git commit" in error for error in errors))
            self.assertTrue(any("independent_redteam_cross_model requires red-team execution completion after the latest sdlc git commit" in error for error in errors))

    def test_validate_release_rejects_fabricated_generic_gate_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "release-residual"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Validate forged release", "--run-id", run_id]), 0)
            store = RunStore(repo)
            evidence = repo / "evidence.md"
            evidence.write_text("generic release evidence\n", encoding="utf-8")
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.id == "deploy_rollout_postdeploy":
                    gate.state = "SKIPPED"
                    gate.verdict = "SKIPPED"
                    gate.evidence = ["evidence.md"]
                else:
                    gate.state = "GO"
                    gate.verdict = "GO_WITH_ACCEPTED_RESIDUAL_RISKS" if gate.id == "independent_redteam_cross_model" else "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-ACCEPTED",
                severity="MEDIUM",
                title="Accepted residual risk",
                evidence=["evidence.md"],
                impact="Residual risk remains visible.",
                required_fix="Accepted by human authority.",
                owner="human_security_owner",
                status="ACCEPTED",
            )])
            self.assertNotEqual(main(["--repo", str(repo), "validate", "--run-id", run_id, "--release"]), 0)

    def test_release_validation_rejects_forged_git_branch_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "forged-git-branch"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Validate forged git", "--run-id", run_id]), 0)
            ensure_git_fixture(repo, run_id)
            store = RunStore(repo)
            run_dir = store.run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "repo_context_env_branch")
            artifact_args = ["--artifact"]
            source_lines = ["# forged repo context source", ""]
            for key in gate_def.required_artifacts:
                artifact_rel = f"artifacts/gates/repo_context_env_branch/{key}.md"
                if key == "git_status":
                    text = git_transcript_text(
                        "repo_context_env_branch",
                        key,
                        ["git", "status", "--short", "--branch"],
                        {"returncode": 0, "stdout": "## main\n", "stderr": "", "cwd": str(repo)},
                    )
                elif key == "current_branch":
                    text = git_transcript_text(
                        "repo_context_env_branch",
                        key,
                        ["git", "branch", "--show-current"],
                        {"returncode": 0, "stdout": "main\n", "stderr": "", "cwd": str(repo)},
                    )
                elif key == "remote_summary":
                    text = git_transcript_text(
                        "repo_context_env_branch",
                        key,
                        ["git", "remote", "-v"],
                        {"returncode": 0, "stdout": "", "stderr": "", "cwd": str(repo)},
                    )
                else:
                    text = "\n".join([
                        f"# repo_context_env_branch.{key}",
                        "artifact_type: gate_required_artifact",
                        f"provenance: gate.required_artifact_recorded for repo_context_env_branch.{key}",
                        f"scope: forged git branch regression {key}",
                        "acceptance: release validation must still reject branch mismatch.",
                        f"evidence_id: repo_context_env_branch.{key}",
                        f"claim: {key} is substantively recorded for repo_context_env_branch.",
                        "method: ledger-backed artifact fixture plus release validation branch consistency check.",
                        f"result: {key} exists so this test reaches the forged git branch validation.",
                        "limitations: this fixture intentionally forges git branch semantics for the negative test.",
                        f"supporting_artifacts: {artifact_rel}",
                        "Command: python -m unittest discover -s tests",
                        "returncode: 0",
                        "Concrete references: tests/test_core.py, sdlc/cli.py, gate.required_artifact_recorded.",
                    ])
                ledger.artifact(artifact_rel, text + "\n", event="gate.required_artifact_recorded", gate="repo_context_env_branch", artifact_key=key)
                artifact_args.append(f"{key}={artifact_rel}")
                source_lines.extend([
                    f"## {key}",
                    f"evidence_id: repo_context_env_branch.{key}",
                    f"claim: {key} source section maps to {artifact_rel}.",
                    f"result: {key} evidence is intentionally ledger-backed but semantically forged for branch mismatch regression. "
                    "Concrete references: tests/test_core.py, sdlc/cli.py, returncode: 0, gate.required_artifact_recorded.",
                    "",
                ])
            source = ledger.artifact(
                "artifacts/gates/repo_context_env_branch/source.md",
                "\n".join(source_lines) + "\n",
                event="gate.source_evidence_recorded",
                gate="repo_context_env_branch",
            )
            self.assertEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "repo_context_env_branch", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)
            evidence = f".sdlc/runs/{run_id}/artifacts/gates/repo_context_env_branch-evidence.json"
            plan = store.load_plan(run_id)
            generic = repo / "generic-evidence.md"
            generic.write_text("generic release evidence with command python -m unittest discover -s tests returncode: 0\n", encoding="utf-8")
            for gate in plan.gates:
                if gate.id == "deploy_rollout_postdeploy":
                    gate.state = "SKIPPED"
                    gate.verdict = "SKIPPED"
                    gate.evidence = ["generic-evidence.md"]
                elif gate.id == "repo_context_env_branch":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = [evidence]
                else:
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["generic-evidence.md"]
            store.save_plan(plan)
            out = io.StringIO()
            with redirect_stdout(out):
                result = main(["--repo", str(repo), "validate", "--run-id", run_id, "--release"])
            self.assertNotEqual(result, 0)
            self.assertIn("git branch evidence main does not match run plan branch", out.getvalue())

    def test_gate_evidence_requires_machine_git_command_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-transcript-required"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject narrative git evidence", "--run-id", run_id]), 0)
            ensure_git_fixture(repo, run_id)
            run_dir = RunStore(repo).run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "repo_context_env_branch")
            artifact_args = ["--artifact"]
            source_lines = ["# source", ""]
            for key in gate_def.required_artifacts:
                artifact_rel = f"artifacts/gates/repo_context_env_branch/{key}.md"
                command = ["python", "-m", "sdlc", "validate"] if key == "git_status" else ["git", "branch", "--show-current"]
                text = "\n".join([
                    f"# repo_context_env_branch.{key}",
                    "artifact_type: gate_required_artifact",
                    "provenance: gate.required_artifact_recorded",
                    f"scope: transcript rejection {key}",
                    "acceptance: git artifacts must record the exact git command.",
                    f"timestamp: {datetime.now(timezone.utc).isoformat()}",
                    f"cwd: {repo}",
                    f"command: {' '.join(command)}",
                    "returncode: 0",
                    "stdout:",
                    "sdlc/git-transcript-required",
                    "stderr:",
                    "<empty>",
                    "Concrete references: tests/test_core.py, sdlc/cli.py, gate.required_artifact_recorded.",
                ])
                ledger.artifact(artifact_rel, text + "\n", event="gate.required_artifact_recorded", gate="repo_context_env_branch", artifact_key=key)
                artifact_args.append(f"{key}={artifact_rel}")
                source_lines.extend([
                    f"## {key}",
                    f"{key} source section has enough detail and concrete references to tests/test_core.py and sdlc/cli.py returncode: 0.",
                    "",
                ])
            source = ledger.artifact("artifacts/gates/repo_context_env_branch/source.md", "\n".join(source_lines) + "\n", event="gate.source_evidence_recorded", gate="repo_context_env_branch")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "repo_context_env_branch", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)

    def test_gate_completion_rejects_template_stuffed_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "template-stuffed"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject template evidence", "--run-id", run_id]), 0)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "intake_scope")
            run_dir = RunStore(repo).run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            lines = ["# Template evidence", ""]
            artifact_args = ["--artifact"]
            for key in gate_def.required_artifacts:
                artifact_rel = f"artifacts/gates/intake_scope/{key}.md"
                ledger.artifact(
                    artifact_rel,
                    "\n".join([
                        f"# intake_scope.{key}",
                        "artifact_type: gate_required_artifact",
                        f"provenance: gate.required_artifact_recorded for intake_scope.{key}",
                        "scope: intake template rejection fixture",
                        "acceptance: command should record the artifact, but completion should reject the template source.",
                        f"evidence_id: intake_scope.{key}",
                        f"claim: {key} is present as a structured required artifact for intake_scope.",
                        "method: ledger-backed artifact fixture with a deliberately template-stuffed source summary.",
                        f"result: {key} contains intake-specific evidence for the test fixture.",
                        "limitations: source evidence remains intentionally template-stuffed for the negative completion path.",
                        f"supporting_artifacts: {artifact_rel}",
                        "Command: python -m unittest discover -s tests",
                        "returncode: 0",
                        "Concrete references: tests/test_core.py, sdlc/cli.py, gate.required_artifact_recorded.",
                    ]) + "\n",
                    event="gate.required_artifact_recorded",
                    gate="intake_scope",
                    artifact_key=key,
                )
                artifact_args.append(f"{key}={artifact_rel}")
                lines.extend([
                    f"## {key}",
                    (
                        f"{key} is supported by the active run artifacts, implementation diff, "
                        "validation outputs, policy controls, and ledger events rather than a placeholder assertion."
                    ),
                    "",
                ])
            source = ledger.artifact("artifacts/gates/intake_scope/template-source.md", "\n".join(lines), event="gate.source_evidence_recorded", gate="intake_scope")
            self.assertEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "intake_scope", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)
            evidence = f".sdlc/runs/{run_id}/artifacts/gates/intake_scope-evidence.json"
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", evidence]), 0)

    def test_gate_evidence_rejects_source_summary_as_required_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "source-as-artifact"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject source as artifact", "--run-id", run_id]), 0)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "intake_scope")
            source = repo / "source.md"
            source.write_text(
                "\n".join(
                    [f"## {key}\nCommand: python -m unittest discover -s tests\nreturncode: 0\nConcrete reference: tests/test_core.py gate.evidence_recorded." for key in gate_def.required_artifacts]
                ),
                encoding="utf-8",
            )
            artifact_args = ["--artifact", *[f"{key}=source.md#{key}" for key in gate_def.required_artifacts]]
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "intake_scope", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", "source.md"]), 0)

    def test_gate_evidence_rejects_syntactic_artifact_type_filler(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "syntactic-filler"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject shallow filler", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "intake_scope")
            artifact_args = ["--artifact"]
            for key in gate_def.required_artifacts:
                rel = f"artifacts/gates/intake_scope/{key}.md"
                ledger.artifact(
                    rel,
                    f"# {key}\nartifact_type: gate_required_artifact\nprovenance: gate.required_artifact_recorded\nCommand: python -m unittest discover -s tests\nreturncode: 0\nConcrete references: tests/test_core.py and sdlc/cli.py.\n",
                    event="gate.required_artifact_recorded",
                    gate="intake_scope",
                    artifact_key=key,
                )
                artifact_args.append(f"{key}={rel}")
            source = ledger.artifact("artifacts/gates/intake_scope/source.md", "\n".join([f"## {key}\n{key} -> artifacts/gates/intake_scope/{key}.md with python -m unittest discover -s tests returncode: 0." for key in gate_def.required_artifacts]), event="gate.source_evidence_recorded", gate="intake_scope")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "intake_scope", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)

    def test_gate_evidence_rejects_round50b_style_boilerplate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "round50b-boilerplate"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject governance boilerplate", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            gate_id = "stakeholders_raci"
            gate_def = next(item for item in DEFAULT_GATES if item.id == gate_id)
            artifact_args = ["--artifact"]
            source_lines = ["# stakeholders_raci source evidence round50b", ""]
            for key in gate_def.required_artifacts:
                rel = f"artifacts/gates/{gate_id}/round50b/{key}.md"
                ledger.artifact(
                    rel,
                    "\n".join([
                        f"# {gate_id}.{key}",
                        "artifact_type: gate_required_artifact",
                        "provenance: ledger artifact generated during round50b evidence refresh",
                        f"scope: Stakeholders, RACI, and approval authority / {key}",
                        "acceptance: validation rejects this artifact if ledger sha256, required key, source section, or concrete reference is missing.",
                        f"{key}: role names and policy labels are repeated with generic references but no artifact-specific structured facts.",
                        "Concrete references: .sdlc/runs/round50b-boilerplate/plan.json, .sdlc/runs/round50b-boilerplate/events.jsonl, tests/test_core.py, sdlc/cli.py.",
                        "Command: python -m unittest discover -s tests",
                        "returncode: 0",
                    ]) + "\n",
                    event="gate.required_artifact_recorded",
                    gate=gate_id,
                    artifact_key=key,
                )
                artifact_args.append(f"{key}={rel}")
                source_lines.extend([
                    f"## {key}",
                    f"{key}: generic role prose with artifacts/gates/{gate_id}/round50b/{key}.md, tests/test_core.py, sdlc/cli.py, command python -m unittest discover -s tests, returncode: 0.",
                    "",
                ])
            source = ledger.artifact(
                f"artifacts/gates/{gate_id}/round50b/source.md",
                "\n".join(source_lines) + "\n",
                event="gate.source_evidence_recorded",
                gate=gate_id,
            )
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, gate_id, "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)

    def test_gate_evidence_rejects_generic_artifact_path_marker_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "generic-path-marker"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject generic path marker", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "intake_scope")
            artifact_args = ["--artifact"]
            for key in gate_def.required_artifacts:
                rel = f"artifacts/gates/intake_scope/{key}.md"
                ledger.artifact(
                    rel,
                    "\n".join([
                        f"# {key}",
                        "artifact_type: gate_required_artifact",
                        "provenance: gate.required_artifact_recorded",
                        "scope: generic marker fixture",
                        "acceptance: this text has labels but no independently corroborating command, digest, event, or source path.",
                        "This filler repeats words to pass a shallow word-count based check without proving the artifact.",
                        "Concrete references: artifacts/fake.md",
                    ]) + "\n",
                    event="gate.required_artifact_recorded",
                    gate="intake_scope",
                    artifact_key=key,
                )
                artifact_args.append(f"{key}={rel}")
            source = ledger.artifact(
                "artifacts/gates/intake_scope/source.md",
                "\n".join([f"## {key}\n{key} has source text with artifacts/fake.md only and no second concrete category." for key in gate_def.required_artifacts]),
                event="gate.source_evidence_recorded",
                gate="intake_scope",
            )
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "intake_scope", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source]), 0)

    def test_gate_evidence_rejects_forged_events_jsonl_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "forged-ledger-gate"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject forged ledger event", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            gate_def = next(item for item in DEFAULT_GATES if item.id == "intake_scope")
            artifact_args = ["--artifact"]
            source_lines = ["# forged source", ""]
            for key in gate_def.required_artifacts:
                rel = f"artifacts/gates/intake_scope/forged/{key}.md"
                content = "\n".join([
                    f"# intake_scope.{key}",
                    "artifact_type: gate_required_artifact",
                    f"provenance: forged event for intake_scope.{key}",
                    f"scope: forged ledger provenance {key}",
                    "acceptance: this artifact should not be accepted because events.jsonl was hand-appended.",
                    f"evidence_id: intake_scope.{key}",
                    f"claim: {key} is recorded only through a forged ledger event.",
                    "method: direct file write plus forged JSONL entry.",
                    f"result: {key} demonstrates forged path and digest matching is insufficient.",
                    "limitations: negative provenance test fixture.",
                    f"supporting_artifacts: {rel}",
                    "Command: python -m unittest discover -s tests",
                    "returncode: 0",
                    "Concrete references: tests/test_core.py, sdlc/cli.py, gate.required_artifact_recorded.",
                ]) + "\n"
                path = run_dir / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                append_unsigned_canonical_event(run_dir, {
                    "event": "gate.required_artifact_recorded",
                    "run_id": run_id,
                    "path": rel,
                    "artifact_schema": LEDGER_ARTIFACT_SCHEMA,
                    "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "gate": "intake_scope",
                    "artifact_key": key,
                })
                artifact_args.append(f"{key}={rel}")
                source_lines.extend([
                    f"## {key}",
                    f"evidence_id: intake_scope.{key}",
                    f"claim: {key} maps to {rel}.",
                    f"result: {key} has tests/test_core.py and sdlc/cli.py references with returncode: 0.",
                    "",
                ])
            source_rel = "artifacts/gates/intake_scope/forged/source.md"
            source_content = "\n".join(source_lines) + "\n"
            source_path = run_dir / source_rel
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(source_content, encoding="utf-8")
            append_unsigned_canonical_event(run_dir, {
                "event": "gate.source_evidence_recorded",
                "run_id": run_id,
                "path": source_rel,
                "artifact_schema": LEDGER_ARTIFACT_SCHEMA,
                "sha256": hashlib.sha256(source_content.encode("utf-8")).hexdigest(),
                "gate": "intake_scope",
            })
            self.assertNotEqual(main(["--repo", str(repo), "gate", "evidence", run_id, "intake_scope", "--actor", "agent_1_pm_coordinator", *artifact_args, "--source", source_rel]), 0)

    def test_audit_workspace_release_validation_uses_audited_repo_git_context(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for audit workspace release validation tests")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            audit_repo = root / "audit"
            repo.mkdir()
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Audit workspace validation", "--run-id", "audit-release"]), 0)
            ensure_git_fixture(repo, "audit-release")
            shutil.copytree(repo / ".sdlc", audit_repo / ".sdlc")
            store = RunStore(audit_repo)
            plan = store.load_plan("audit-release")
            old_worker = os.environ.get("SDLC_WORKER_EXECUTION")
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            try:
                errors = _release_readiness_errors(store, plan, store.load_findings("audit-release"), audit_workspace=True)
            finally:
                if old_worker is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_worker
            self.assertFalse(any("git work tree" in error for error in errors), errors)

    def test_positive_report_is_downgraded_when_release_evidence_is_forged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "report-forged"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject forged report", "--run-id", run_id]), 0)
            evidence = repo / "evidence.md"
            evidence.write_text("generic release evidence\n", encoding="utf-8")
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.id == "deploy_rollout_postdeploy":
                    gate.state = "SKIPPED"
                    gate.verdict = "SKIPPED"
                else:
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            report = (store.run_dir(run_id) / "final-report.md").read_text(encoding="utf-8")
            self.assertIn("Verdict: **NO_GO**", report)
            self.assertIn("Release Readiness Blockers", report)

    def test_accepted_severe_findings_force_residual_final_verdict(self) -> None:
        finding = Finding(
            id="HIGH-ACCEPTED",
            severity="HIGH",
            title="Accepted severe finding",
            evidence=["test"],
            impact="Residual risk must remain visible.",
            required_fix="Accept explicitly or fix.",
            owner="human_security_owner",
            status="ACCEPTED",
        )
        self.assertEqual(final_verdict([finding]), "GO_WITH_ACCEPTED_RESIDUAL_RISKS")

    def test_report_preserves_residual_risk_release_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "report-residual"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Residual report", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.id == "deploy_rollout_postdeploy":
                    gate.state = "SKIPPED"
                    gate.verdict = "SKIPPED"
                else:
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["README.md"]
            store.save_plan(plan)
            store.save_findings(run_id, [Finding(
                id="HIGH-ACCEPTED",
                severity="HIGH",
                title="Accepted severe finding",
                evidence=["human accepted residual risk reason"],
                impact="Residual risk remains.",
                required_fix="Track the accepted risk.",
                owner="human_security_owner",
                status="ACCEPTED",
                closed_by="human_security_owner",
            )])
            report = build_report(repo, run_id, readiness_errors=[])
            self.assertIn("Verdict: **GO_WITH_ACCEPTED_RESIDUAL_RISKS**", report)
            self.assertIn("- Release verdict: GO_WITH_ACCEPTED_RESIDUAL_RISKS", report)

    def test_deterministic_quality_uses_current_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            tests_dir = repo / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_sample.py").write_text("import unittest\n\nclass Sample(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n", encoding="utf-8")
            run_id = "quality-python"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Run deterministic quality", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.order < 15 and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["tests/test_sample.py"]
            store.save_plan(plan)
            run_dry_gates(store, run_id)
            artifact = (store.run_dir(run_id) / "artifacts" / "deterministic_quality.md").read_text(encoding="utf-8")
            self.assertIn(sys.executable, artifact)
            self.assertIn("returncode: 0", artifact)
            self.assertNotIn("Command not found: python", artifact)

    def test_dry_run_does_not_mark_placeholder_gates_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "dry-placeholder"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Check placeholder gates", "--run-id", run_id]), 0)
            store = RunStore(repo)
            run_dry_gates(store, run_id)
            plan = store.load_plan(run_id)
            intake = next(gate for gate in plan.gates if gate.id == "intake_scope")
            self.assertEqual(intake.verdict, "NO_GO")
            self.assertIn("placeholder", intake.notes)

    def test_dry_run_blocks_later_gates_after_unresolved_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "dry-dependency-block"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Check dry dependencies", "--run-id", run_id]), 0)
            store = RunStore(repo)
            run_dry_gates(store, run_id)
            plan = store.load_plan(run_id)
            repo_context = next(gate for gate in plan.gates if gate.id == "repo_context_env_branch")
            self.assertEqual(repo_context.state, "BLOCKED")
            self.assertIn("intake_scope", repo_context.notes)

    def test_dry_run_git_context_no_go_without_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "dry-nongit-context"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Check non-git context", "--run-id", run_id]), 0)
            store = RunStore(repo)
            self._mark_prior_gates_go(store, run_id, "repo_context_env_branch")
            run_dry_gates(store, run_id)
            plan = store.load_plan(run_id)
            repo_context = next(gate for gate in plan.gates if gate.id == "repo_context_env_branch")
            artifact = (store.run_dir(run_id) / "artifacts" / "repo_context_env_branch.md").read_text(encoding="utf-8")
            self.assertEqual(repo_context.verdict, "NO_GO")
            self.assertIn("git_context_failures", repo_context.notes)
            self.assertIn("git rev-parse --is-inside-work-tree", artifact)
            self.assertIn("returncode:", artifact)

    def test_dry_run_baseline_no_go_without_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "dry-nongit-baseline"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Check non-git baseline", "--run-id", run_id]), 0)
            store = RunStore(repo)
            self._mark_prior_gates_go(store, run_id, "baseline_freeze")
            run_dry_gates(store, run_id)
            plan = store.load_plan(run_id)
            baseline = next(gate for gate in plan.gates if gate.id == "baseline_freeze")
            artifact = (store.run_dir(run_id) / "artifacts" / "baseline_freeze.md").read_text(encoding="utf-8")
            self.assertEqual(baseline.verdict, "NO_GO")
            self.assertIn("baseline_git_failures", baseline.notes)
            self.assertIn("git status --short --branch", artifact)
            self.assertIn("returncode:", artifact)

    def test_redteam_prompt_avoids_lifecycle_status_loops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-prompt-scope"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Scope red-team prompt", "--run-id", run_id]), 0)
            prompt = render_redteam_prompt(RunStore(repo).load_plan(run_id))
            self.assertIn("Do not create a blocking finding solely because those later", prompt)
            self.assertIn("whose only evidence is that the active run's authoritative", prompt)
            self.assertIn("would allow a release", prompt)
            self.assertIn("TMPDIR=", prompt)
            self.assertIn('cd "${SDLC_WORKER_REPO:?orchestrator_repo_not_set}"', prompt)
            self.assertIn('TMPDIR="${TMPDIR:?orchestrator_TMPDIR_not_set}"', prompt)
            self.assertIn("python -m sdlc validate --run-id redteam-prompt-scope --release --audit-workspace", prompt)
            self.assertNotIn("TMPDIR=$PWD/.sdlc-redteam-tmp", prompt)
            self.assertIn("not from an older `worker-results/**/stdout.txt` transcript", prompt)

    def test_deterministic_quality_no_go_on_failing_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            tests_dir = repo / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_fail.py").write_text("import unittest\n\nclass Fail(unittest.TestCase):\n    def test_fail(self):\n        self.fail('boom')\n", encoding="utf-8")
            run_id = "quality-fails"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Fail deterministic quality", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.order < 15 and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["tests/test_fail.py"]
            store.save_plan(plan)
            run_dry_gates(store, run_id)
            quality = next(gate for gate in store.load_plan(run_id).gates if gate.id == "deterministic_quality")
            self.assertEqual(quality.verdict, "NO_GO")

    def test_final_verdict_blocks_pending_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "pending-verdict"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Check final verdict", "--run-id", run_id]), 0)
            plan = RunStore(repo).load_plan(run_id)
            self.assertEqual(final_verdict([], plan), "NO_GO")

    def test_final_verdict_blocks_open_medium_findings(self) -> None:
        finding = Finding(
            id="MEDIUM-001",
            severity="MEDIUM",
            title="Open medium",
            evidence=["test"],
            impact="Needs handling.",
            required_fix="Close or accept.",
            owner="agent_3_implementation_owner",
        )
        self.assertEqual(final_verdict([finding]), "NO_GO")


if __name__ == "__main__":
    unittest.main()

class FindingLifecycleTests(unittest.TestCase):
    def test_finding_lifecycle_requires_override_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-run"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build auth dashboard", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "redteam", run_id]), 0)
            evidence = repo / "evidence.md"
            evidence.write_text("validated by independent red-team\n", encoding="utf-8")
            weak_fix_summary = repo / "weak_fix_summary.md"
            weak_fix_summary.write_text("unrelated note\n", encoding="utf-8")
            weak_second_validation = repo / "weak_second_validation.txt"
            weak_second_validation.write_text("unrelated note\n", encoding="utf-8")
            closure_evidence = record_finding_closure_evidence(repo, run_id, "HIGH-001")
            # HIGH acceptance without human override is blocked.
            self.assertNotEqual(main(["--repo", str(repo), "finding", "accept", run_id, "HIGH-001", "--reason", "not important", "--closed-by", "human_security_owner", "--evidence", "evidence.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "finding", "accept", run_id, "HIGH-001", "--reason", "not important", "--closed-by", "agent_3_implementation_owner", "--human-override", "--evidence", "evidence.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "finding", "defer", run_id, "HIGH-002", "--reason", "human accepted residual risk for test", "--closed-by", "human_security_owner", "--human-override", "--evidence", "evidence.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-001", "--closed-by", "random_actor", "--evidence", *closure_evidence]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-001", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", "weak_fix_summary.md", "weak_second_validation.txt"]), 0)
            key = "test-local-actor-key"
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                risk_artifact = Ledger(RunStore(repo).run_dir(run_id), run_id).artifact(
                    "artifacts/findings/HIGH-002/risk_acceptance.md",
                    "HIGH-002 residual risk acceptance: human accepted residual risk for test.\n",
                    event="finding.risk_acceptance",
                    finding_id="HIGH-002",
                )
                defer_proof = actor_proof(run_id, "HIGH-002", "human_security_owner", key)
                self.assertEqual(main([
                    "--repo", str(repo), "finding", "defer", run_id, "HIGH-002",
                    "--reason", "human accepted residual risk for test",
                    "--closed-by", "human_security_owner",
                    "--human-override",
                    "--actor-proof", defer_proof,
                    "--evidence", f".sdlc/runs/{run_id}/{risk_artifact}",
                ]), 0)
                proof = actor_proof(run_id, "HIGH-001", "agent_6_redteam_deploy_rollback", key)
                closure_evidence = record_finding_closure_evidence(
                    repo,
                    run_id,
                    "HIGH-001",
                    validator_actor_proof=proof,
                )
                self.assertEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-001", "--closed-by", "agent_6_redteam_deploy_rollback", "--actor-proof", proof, "--evidence", *closure_evidence]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            store = RunStore(repo)
            findings = store.load_findings(run_id)
            self.assertEqual(findings[0].status, "CLOSED")
            self.assertEqual(findings[1].status, "DEFERRED")

    def test_medium_finding_close_requires_ledger_backed_remediation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "medium-close-evidence"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Close medium finding", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-777",
                severity="MEDIUM",
                title="Medium release blocker",
                evidence=["redteam"],
                impact="Blocks release until evidence is real.",
                required_fix="Fix and independently validate.",
                owner="agent_4_evidence_reporting_owner",
            )])
            weak = Ledger(store.run_dir(run_id), run_id).artifact(
                "artifacts/findings/MEDIUM-777/summary-only.md",
                "MEDIUM-777 summary-only note without diff or validation.\n",
                event="finding.remediation_summary",
                finding_id="MEDIUM-777",
            )
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "close", run_id, "MEDIUM-777",
                "--closed-by", "human_security_owner",
                "--evidence", f".sdlc/runs/{run_id}/{weak}",
            ]), 0)
            closure_evidence = record_finding_closure_evidence(repo, run_id, "MEDIUM-777", validated_by="human_security_owner")
            self.assertEqual(main([
                "--repo", str(repo), "finding", "close", run_id, "MEDIUM-777",
                "--closed-by", "human_security_owner",
                "--evidence", *closure_evidence,
            ]), 0)

    def test_medium_finding_accept_rejects_generic_evidence_at_command_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "medium-accept-generic"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Accept medium finding", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-GAP",
                severity="MEDIUM",
                title="Medium acceptance gap",
                evidence=["redteam"],
                impact="Generic acceptance can hide risk.",
                required_fix="Require ledger-backed residual risk evidence.",
                owner="agent_4_evidence_reporting_owner",
            )])
            generic = repo / "generic.md"
            generic.write_text("generic human note\n", encoding="utf-8")
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "accept", run_id, "MEDIUM-GAP",
                "--closed-by", "human_security_owner",
                "--reason", "accepted residual risk reason: generic",
                "--evidence", "generic.md",
            ]), 0)

    def test_medium_finding_defer_rejects_generic_evidence_at_command_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "medium-defer-generic"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Defer medium finding", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-DEFER",
                severity="MEDIUM",
                title="Medium defer gap",
                evidence=["redteam"],
                impact="Generic deferral can hide risk.",
                required_fix="Require ledger-backed residual risk evidence.",
                owner="agent_4_evidence_reporting_owner",
            )])
            generic = repo / "generic.md"
            generic.write_text("generic human note\n", encoding="utf-8")
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "defer", run_id, "MEDIUM-DEFER",
                "--closed-by", "human_security_owner",
                "--reason", "deferred risk reason: generic",
                "--evidence", "generic.md",
            ]), 0)

    def test_medium_finding_accept_allows_ledger_backed_risk_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "medium-accept-ledger"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Accept medium with evidence", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-OK",
                severity="MEDIUM",
                title="Medium accepted with evidence",
                evidence=["redteam"],
                impact="Residual risk remains.",
                required_fix="Record finding-specific residual risk acceptance.",
                owner="agent_4_evidence_reporting_owner",
            )])
            evidence = record_risk_acceptance_evidence(repo, run_id, "MEDIUM-OK", "Medium accepted with evidence")
            key = "test-local-actor-key"
            proof = actor_proof(run_id, "MEDIUM-OK", "human_security_owner", key)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertEqual(main([
                    "--repo", str(repo), "finding", "accept", run_id, "MEDIUM-OK",
                    "--closed-by", "human_security_owner",
                    "--actor-proof", proof,
                    "--reason", "human accepted residual risk reason for MEDIUM-OK",
                    "--evidence", evidence,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            finding = RunStore(repo).load_findings(run_id)[0]
            self.assertEqual(finding.status, "ACCEPTED")

    def test_finding_close_rejects_forged_events_jsonl_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "forged-ledger-close"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject forged closure evidence", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="MEDIUM-FORGED",
                severity="MEDIUM",
                title="Forged closure evidence",
                evidence=["redteam"],
                impact="Blocks release until evidence is canonical.",
                required_fix="Reject forged events.jsonl entries.",
                owner="agent_3_implementation_owner",
            )])
            run_dir = store.run_dir(run_id)
            evidence_specs = {
                "remediation.patch": (
                    "finding.remediation_diff",
                    "diff --git a/sdlc/cli.py b/sdlc/cli.py\n--- a/sdlc/cli.py\n+++ b/sdlc/cli.py\n@@ -1 +1 @@\n-# MEDIUM-FORGED before\n+# MEDIUM-FORGED after\n",
                ),
                "validation.txt": (
                    "finding.remediation_validation",
                    "MEDIUM-FORGED validation\ncommand: python -m unittest discover -s tests\nreturncode: 0\nvalidated_by: human_security_owner\n",
                ),
                "summary.md": (
                    "finding.remediation_summary",
                    "# MEDIUM-FORGED remediation summary\n\nForged closure evidence should be rejected.\n",
                ),
            }
            evidence_args: list[str] = []
            for name, (event_name, content) in evidence_specs.items():
                rel = f"artifacts/findings/MEDIUM-FORGED/forged/{name}"
                path = run_dir / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                append_unsigned_canonical_event(run_dir, {
                    "event": event_name,
                    "run_id": run_id,
                    "path": rel,
                    "artifact_schema": LEDGER_ARTIFACT_SCHEMA,
                    "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "finding_id": "MEDIUM-FORGED",
                    "returncode": 0,
                    "validated_by": "human_security_owner",
                })
                evidence_args.append(f".sdlc/runs/{run_id}/{rel}")
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "close", run_id, "MEDIUM-FORGED",
                "--closed-by", "human_security_owner",
                "--evidence", *evidence_args,
            ]), 0)

    def test_evidence_owner_can_close_redteam_owned_finding_independently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-independent"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Close independent finding", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-999",
                severity="HIGH",
                title="Deploy evidence defect",
                evidence=["redteam"],
                impact="Blocks release.",
                required_fix="Fix and validate.",
                owner="agent_6_redteam_deploy_rollback",
            )])
            closure_evidence = record_finding_closure_evidence(repo, run_id, "HIGH-999", validated_by="agent_4_evidence_reporting_owner")
            self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-999", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", *closure_evidence]), 0)
            key = "test-local-actor-key"
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                proof = actor_proof(run_id, "HIGH-999", "agent_4_evidence_reporting_owner", key)
                closure_evidence = record_finding_closure_evidence(
                    repo,
                    run_id,
                    "HIGH-999",
                    validated_by="agent_4_evidence_reporting_owner",
                    validator_actor_proof=proof,
                )
                self.assertEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-999", "--closed-by", "agent_4_evidence_reporting_owner", "--actor-proof", proof, "--evidence", *closure_evidence]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def test_release_validation_rejects_weak_accepted_high_finding_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "weak-accepted-high"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Weak accepted high", "--run-id", run_id]), 0)
            weak = repo / "weak.md"
            weak.write_text("generic human note\n", encoding="utf-8")
            finding = Finding(
                id="HIGH-WEAK",
                severity="HIGH",
                title="Weak accepted blocker",
                evidence=["redteam"],
                impact="Blocks release.",
                required_fix="Provide tied residual risk evidence.",
                owner="agent_6_redteam_deploy_rollback",
                status="ACCEPTED",
                closed_by="human_security_owner",
                closure_evidence=["accept: generic reason", "weak.md"],
            )
            store = RunStore(repo)
            store.save_findings(run_id, [finding])
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("HIGH-WEAK accepted/deferred residual risk evidence is invalid" in error for error in errors))

    def test_release_validation_rejects_weak_accepted_medium_finding_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "weak-accepted-medium"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Weak accepted medium", "--run-id", run_id]), 0)
            weak = repo / "weak.md"
            weak.write_text("generic human note\n", encoding="utf-8")
            finding = Finding(
                id="MEDIUM-WEAK",
                severity="MEDIUM",
                title="Weak accepted medium blocker",
                evidence=["redteam"],
                impact="Blocks release unless accepted with traceable evidence.",
                required_fix="Provide tied residual risk evidence.",
                owner="agent_6_redteam_deploy_rollback",
                status="ACCEPTED",
                closed_by="human_security_owner",
                closure_evidence=["accept: generic reason", "weak.md"],
            )
            store = RunStore(repo)
            store.save_findings(run_id, [finding])
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("MEDIUM-WEAK accepted/deferred residual risk evidence is invalid" in error for error in errors))

    def test_finding_close_requires_actor_proof_when_policy_requires_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-proof"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Proof close finding", "--run-id", run_id]), 0)
            policy_path = repo / ".sdlc" / "policies" / "default.json"
            policy = read_json(policy_path)
            policy["actor_proof_required_for_finding_closure"] = True
            write_json(policy_path, policy)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-888",
                severity="HIGH",
                title="Proof required",
                evidence=["redteam"],
                impact="Spoofing closure blocks release.",
                required_fix="Require actor proof.",
                owner="agent_3_implementation_owner",
            )])
            key = "test-local-actor-key"
            proof = actor_proof(run_id, "HIGH-888", "agent_6_redteam_deploy_rollback", key)
            closure_evidence = record_finding_closure_evidence(
                repo,
                run_id,
                "HIGH-888",
                validator_actor_proof=proof,
            )
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-888", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", *closure_evidence]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-888", "--closed-by", "agent_6_redteam_deploy_rollback", "--actor-proof", "bad", "--evidence", *closure_evidence]), 0)
                self.assertEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-888", "--closed-by", "agent_6_redteam_deploy_rollback", "--actor-proof", proof, "--evidence", *closure_evidence]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def test_high_finding_close_rejects_spoofed_validation_actor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-spoof-validator"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject spoofed validation actor", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-SPOOF",
                severity="HIGH",
                title="Spoofed validation",
                evidence=["redteam"],
                impact="Fake validation can close a blocker.",
                required_fix="Bind validation to the closer.",
                owner="agent_3_implementation_owner",
            )])
            key = "test-local-actor-key"
            proof = actor_proof(run_id, "HIGH-SPOOF", "agent_6_redteam_deploy_rollback", key)
            closure_evidence = record_finding_closure_evidence(
                repo,
                run_id,
                "HIGH-SPOOF",
                validated_by="not-a-real-validator",
                validator_actor_proof=proof,
            )
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "finding", "close", run_id, "HIGH-SPOOF",
                    "--closed-by", "agent_6_redteam_deploy_rollback",
                    "--actor-proof", proof,
                    "--evidence", *closure_evidence,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def test_high_finding_close_rejects_unbound_validation_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-unbound-validator"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject unbound validator proof", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-UNBOUND",
                severity="HIGH",
                title="Unbound validation proof",
                evidence=["redteam"],
                impact="Validation without proof can be spoofed.",
                required_fix="Bind proof to validation artifact.",
                owner="agent_3_implementation_owner",
            )])
            key = "test-local-actor-key"
            proof = actor_proof(run_id, "HIGH-UNBOUND", "agent_6_redteam_deploy_rollback", key)
            closure_evidence = record_finding_closure_evidence(repo, run_id, "HIGH-UNBOUND")
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "finding", "close", run_id, "HIGH-UNBOUND",
                    "--closed-by", "agent_6_redteam_deploy_rollback",
                    "--actor-proof", proof,
                    "--evidence", *closure_evidence,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def test_actor_proof_key_file_must_be_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-key-boundary"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Key boundary", "--run-id", run_id]), 0)
            RunStore(repo).save_findings(run_id, [Finding(
                id="HIGH-KEY",
                severity="HIGH",
                title="Key boundary",
                evidence=["redteam"],
                impact="Repo-local key material can self-authorize closure.",
                required_fix="Use external actor proof material.",
                owner="agent_3_implementation_owner",
            )])
            closure_evidence = record_finding_closure_evidence(repo, run_id, "HIGH-KEY")
            key_path = repo / "actor-proof.key"
            key_path.write_text("repo-local-key\n", encoding="utf-8")
            proof = actor_proof(run_id, "HIGH-KEY", "agent_6_redteam_deploy_rollback", "repo-local-key")
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            old_key_file = os.environ.get("SDLC_ACTOR_PROOF_KEY_FILE")
            os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
            os.environ["SDLC_ACTOR_PROOF_KEY_FILE"] = str(key_path)
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "finding", "close", run_id, "HIGH-KEY",
                    "--closed-by", "agent_6_redteam_deploy_rollback",
                    "--actor-proof", proof,
                    "--evidence", *closure_evidence,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
                if old_key_file is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY_FILE", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY_FILE"] = old_key_file

    def test_run_state_acceptance_rejects_release_ready_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-runstate-accept"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Run-state finding accept", "--run-id", run_id, "--risk", "high"]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-RUNSTATE",
                severity="HIGH",
                title="Active release run is still NO_GO",
                evidence=["status"],
                impact="A release-ready claim would be unsupported.",
                required_fix="Do not accept release-state findings with contradictory readiness claims.",
                owner="agent_6_redteam_deploy_rollback",
            )])
            evidence = Ledger(store.run_dir(run_id), run_id).artifact(
                "artifacts/findings/HIGH-RUNSTATE/acceptance.md",
                "HIGH-RUNSTATE risk acceptance residual risk reason: Run is ready for production and release-ready.\n",
                event="finding.risk_acceptance",
                finding_id="HIGH-RUNSTATE",
            )
            key = "runstate-accept-key"
            proof = actor_proof(run_id, "HIGH-RUNSTATE", "human_product_owner", key)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "finding", "accept", run_id, "HIGH-RUNSTATE",
                    "--closed-by", "human_product_owner",
                    "--human-override",
                    "--actor-proof", proof,
                    "--reason", "risk acceptance residual risk reason: run is ready for production",
                    "--evidence", f".sdlc/runs/{run_id}/{evidence}",
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def test_gate_completion_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-run"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build CLI helper", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator"]), 0)
            evidence_path = record_gate_evidence(repo, run_id, "intake_scope", "agent_1_pm_coordinator")
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", evidence_path]), 0)

    def test_managed_worker_context_cannot_mutate_gate_or_finding_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-actor-block"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Block worker actor spoof", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="HIGH-777",
                severity="HIGH",
                title="Actor spoof",
                evidence=["redteam"],
                impact="Identity spoofing blocks release.",
                required_fix="Block managed worker control-plane mutation.",
                owner="agent_3_implementation_owner",
            )])
            evidence_path = record_gate_evidence(repo, run_id, "intake_scope", "agent_1_pm_coordinator")
            closure_evidence = record_finding_closure_evidence(repo, run_id, "HIGH-777")
            old = {key: os.environ.get(key) for key in ("SDLC_WORKER_EXECUTION", "SDLC_WORKER_REPO", "SDLC_WORKER_RUN_ID")}
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            os.environ["SDLC_WORKER_REPO"] = str(repo.resolve())
            os.environ["SDLC_WORKER_RUN_ID"] = run_id
            try:
                self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", evidence_path]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "finding", "close", run_id, "HIGH-777", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", *closure_evidence]), 0)
            finally:
                for key, value in old.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_managed_worker_context_blocks_any_control_plane_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            protected = Path(tmp) / "protected"
            repo = Path(tmp) / "test-repo"
            protected.mkdir()
            run_id = "worker-env-scope"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Block disposable test repo", "--run-id", run_id]), 0)
            evidence_path = record_gate_evidence(repo, run_id, "intake_scope", "agent_1_pm_coordinator")
            old = {key: os.environ.get(key) for key in ("SDLC_WORKER_EXECUTION", "SDLC_WORKER_REPO", "SDLC_WORKER_RUN_ID")}
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            os.environ["SDLC_WORKER_REPO"] = str(protected.resolve())
            os.environ["SDLC_WORKER_RUN_ID"] = "protected-run"
            try:
                self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", evidence_path]), 0)
            finally:
                for key, value in old.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_fixed_pending_review_findings_remain_open(self) -> None:
        finding = Finding(
            id="HIGH-888",
            severity="HIGH",
            title="Pending review",
            evidence=["redteam"],
            impact="Blocks release.",
            required_fix="Validate independently.",
            owner="agent_3_implementation_owner",
            status="FIXED_PENDING_REVIEW",
        )
        self.assertEqual(final_verdict([finding]), "NO_GO")

    def test_missing_gate_definition_rejects_positive_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "unknown-gate"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject unknown gate", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            plan.gates.append(GateState(id="unknown_release_gate", order=0, title="Unknown", owner="agent_1_pm_coordinator"))
            store.save_plan(plan)
            evidence = repo / "evidence.md"
            evidence.write_text(
                "artifact_type: manual\n"
                "provenance: test\n"
                "scope: unknown\n"
                "acceptance: reject unknown gate\n"
                "Command: python -m unittest discover -s tests\n"
                "returncode: 0\n"
                "Concrete references: tests/test_core.py and sdlc/cli.py.\n",
                encoding="utf-8",
            )
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "unknown_release_gate", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", str(evidence)]), 0)

    def test_gate_completion_enforces_actor_and_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-auth-deps"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build CLI helper", "--run-id", run_id]), 0)
            intake_evidence = record_gate_evidence(repo, run_id, "intake_scope", "agent_1_pm_coordinator")
            stakeholders_evidence = record_gate_evidence(repo, run_id, "stakeholders_raci", "agent_1_pm_coordinator")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_3_implementation_owner", "--evidence", intake_evidence]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "stakeholders_raci", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", stakeholders_evidence]), 0)
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", intake_evidence]), 0)
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "stakeholders_raci", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", stakeholders_evidence]), 0)

    def test_gate_completion_validates_schema_and_allowed_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-schema"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build CLI helper", "--run-id", run_id]), 0)
            evidence = repo / "evidence.md"
            evidence.write_text("feature_request assumptions ambiguities initial_blast_radius\n", encoding="utf-8")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--evidence", "evidence.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO_WITH_ACCEPTED_RESIDUAL_RISKS", "--actor", "agent_1_pm_coordinator", "--evidence", "evidence.md"]), 0)

    def test_generic_residual_risk_gate_verdict_requires_human_acceptance_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-residual"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Residual gate", "--run-id", run_id, "--ui", "yes"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            target = next(gate for gate in plan.gates if gate.id == "ui_architecture_accessibility")
            for gate in plan.gates:
                if gate.order < target.order:
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence.append("seed-prerequisite-evidence.md")
            store.save_plan(plan)
            typed_evidence = record_gate_evidence(repo, run_id, "ui_architecture_accessibility", "agent_7_ui_architect")
            residual = Ledger(store.run_dir(run_id), run_id).artifact(
                "artifacts/gates/ui_architecture_accessibility/residual-risk.md",
                "accepted residual risk reason: keyboard-only UI review is deferred with human accepted risk.\n",
                event="gate.residual_risk_acceptance",
                gate="ui_architecture_accessibility",
                actor="human_approval_authority",
            )
            residual_arg = f".sdlc/runs/{run_id}/{residual}"
            self.assertNotEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "ui_architecture_accessibility",
                "--verdict", "GO_WITH_ACCEPTED_RESIDUAL_RISKS",
                "--actor", "agent_7_ui_architect",
                "--evidence", typed_evidence, residual_arg,
                "--notes", "residual risk reason: deferred keyboard-only review",
            ]), 0)
            self.assertEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "ui_architecture_accessibility",
                "--verdict", "GO_WITH_ACCEPTED_RESIDUAL_RISKS",
                "--actor", "human_approval_authority",
                "--evidence", typed_evidence, residual_arg,
                "--notes", "accepted residual risk reason: deferred keyboard-only review",
            ]), 0)

    def test_gate_source_evidence_is_digest_bound_at_record_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-source-freeze"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Freeze source evidence", "--run-id", run_id]), 0)
            evidence = record_gate_evidence(repo, run_id, "intake_scope", "agent_1_pm_coordinator")
            source = repo / ".sdlc" / "runs" / run_id / "artifacts" / "gates" / "intake_scope" / "source.md"
            source.write_text(
                "# feature_request\n"
                "artifact_type: source\nprovenance: tampered after recording\nscope: intake\nacceptance: should not be accepted\n"
                "Command: python -m sdlc validate\nreturncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py.\n"
                "# assumptions\n"
                "artifact_type: source\nprovenance: tampered after recording\nscope: intake\nacceptance: should not be accepted\n"
                "Command: python -m sdlc validate\nreturncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py.\n"
                "# ambiguities\n"
                "artifact_type: source\nprovenance: tampered after recording\nscope: intake\nacceptance: should not be accepted\n"
                "Command: python -m sdlc validate\nreturncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py.\n"
                "# initial_blast_radius\n"
                "artifact_type: source\nprovenance: tampered after recording\nscope: intake\nacceptance: should not be accepted\n"
                "Command: python -m sdlc validate\nreturncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py.\n",
                encoding="utf-8",
            )
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", evidence]), 0)

    def test_gate_completion_rejects_symlink_evidence_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            run_id = "gate-symlink"
            outside = root / "outside.md"
            outside.write_text("outside evidence\n", encoding="utf-8")
            link = repo / "linked-evidence.md"
            try:
                link.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build CLI helper", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", "linked-evidence.md"]), 0)

    def test_gate_completion_rejects_placeholder_evidence_for_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-placeholder"
            placeholder = repo / "placeholder.md"
            placeholder.write_text("Gate requires agent/human evidence. This placeholder is not sufficient for production GO.\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject placeholder evidence", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "intake_scope", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", "placeholder.md"]), 0)

    def test_security_scan_no_go_requires_structured_residual_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "security-residual"
            evidence = repo / "evidence.md"
            evidence.write_text("prior gate evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Accept scanner residual risk", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.order < 17 and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            summary = store.run_dir(run_id) / "artifacts" / "security_scan_summary.md"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("# Security Scan Summary\n\nsast_result dependency_scan secret_scan iac_scan policy_check\n\nVerdict: NO_GO\n", encoding="utf-8")
            Ledger(store.run_dir(run_id), run_id).event("security.scans_completed", evidence=["artifacts/security_scan_summary.md"])
            summary_arg = f".sdlc/runs/{run_id}/artifacts/security_scan_summary.md"
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "security_scans", "--verdict", "GO", "--actor", "agent_8_cybersecurity_engineer", "--evidence", summary_arg]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "security_scans", "--verdict", "GO_WITH_ACCEPTED_RESIDUAL_RISKS", "--actor", "agent_8_cybersecurity_engineer", "--evidence", summary_arg, "--notes", "residual risk reason: network scanner blocked by policy and manually adjudicated"]), 0)
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "security_scans", "--verdict", "GO_WITH_ACCEPTED_RESIDUAL_RISKS", "--actor", "human_security_owner", "--evidence", summary_arg, "--notes", "residual risk reason: network scanner blocked by policy and manually adjudicated"]), 0)

    def test_final_report_gate_rejects_stale_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "stale-report"
            evidence = repo / "evidence.md"
            evidence.write_text("gate evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject stale final report", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.order < 25 and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            store.save_findings(run_id, [Finding(
                id="RT-CRITICAL-001",
                severity="CRITICAL",
                title="Report must include this finding",
                evidence=["test"],
                impact="The report is stale.",
                required_fix="Regenerate the report.",
                owner="agent_3_implementation_owner",
            )])
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "final_report_reaudit", "--verdict", "GO", "--actor", "agent_4_evidence_reporting_owner", "--evidence", f".sdlc/runs/{run_id}/final-report.md"]), 0)
            report_path = store.run_dir(run_id) / "final-report.md"
            future = report_path.stat().st_mtime + 100
            os.utime(report_path, (future, future))
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "final_report_reaudit", "--verdict", "GO", "--actor", "agent_4_evidence_reporting_owner", "--evidence", f".sdlc/runs/{run_id}/final-report.md"]), 0)

    def test_final_report_gate_go_requires_atomic_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            run_id = "finalize-report"
            evidence = repo / "evidence.md"
            evidence.write_text("gate evidence\n", encoding="utf-8")
            key = root / "signing.key"
            key.write_text("test signing key\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Finalize report", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.id == "deploy_rollout_postdeploy":
                    gate.state = "SKIPPED"
                    gate.verdict = "SKIPPED"
                    gate.evidence = ["evidence.md"]
                elif gate.id != "final_report_reaudit":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "final_report_reaudit", "--verdict", "GO", "--actor", "agent_4_evidence_reporting_owner", "--evidence", f".sdlc/runs/{run_id}/final-report.md"]), 0)

            self.assertNotEqual(main(["--repo", str(repo), "report", run_id, "--finalize", "--key", str(key)]), 0)
            plan = store.load_plan(run_id)
            final_gate = next(gate for gate in plan.gates if gate.id == "final_report_reaudit")
            self.assertNotEqual(final_gate.verdict, "GO")

    def test_final_report_gate_requires_attested_readiness_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            run_id = "final-readiness-snapshot"
            key = root / "signing.key"
            key.write_text("test signing key\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Final readiness snapshot", "--run-id", run_id]), 0)
            store = RunStore(repo)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
            manifest = read_json(store.run_dir(run_id) / "artifacts" / "attestations" / "manifest.json", {})
            manifest_paths = {item.get("path") for item in manifest.get("artifacts", []) if isinstance(item, dict)}
            self.assertIn("artifacts/attestations/control-snapshots/release-readiness.json", manifest_paths)

            plan = store.load_plan(run_id)
            final_gate = next(gate for gate in plan.gates if gate.id == "final_report_reaudit")
            final_gate.state = "READY"
            final_gate.verdict = None
            store.save_plan(plan)
            readiness_snapshot = store.run_dir(run_id) / "artifacts" / "attestations" / "control-snapshots" / "release-readiness.json"
            readiness_snapshot.unlink()
            self.assertNotEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "final_report_reaudit",
                "--verdict", "GO",
                "--actor", "agent_4_evidence_reporting_owner",
                "--evidence", f".sdlc/runs/{run_id}/final-report.md",
            ]), 0)

    def test_finding_close_refreshes_nonfinal_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-refresh-report"
            evidence = repo / "evidence.md"
            evidence.write_text("returncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Refresh report after closure", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="LOW-REFRESH",
                severity="LOW",
                title="Refresh report finding",
                evidence=["test"],
                impact="Report can become stale.",
                required_fix="Refresh after lifecycle mutation.",
                owner="agent_4_evidence_reporting_owner",
            )])
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "finding", "close", run_id, "LOW-REFRESH", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", "evidence.md"]), 0)
            report = (store.run_dir(run_id) / "final-report.md").read_text(encoding="utf-8")
            self.assertIn("| LOW-REFRESH | LOW | CLOSED |", report)

    def test_gate_completion_refreshes_materialized_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gate-refresh-report"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Refresh report after gate change", "--run-id", run_id]), 0)
            store = RunStore(repo)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            self.assertEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "intake_scope",
                "--verdict", "NO_GO",
                "--actor", "agent_1_pm_coordinator",
                "--notes", "scope evidence is incomplete",
            ]), 0)
            events = [
                json.loads(line)
                for line in (store.run_dir(run_id) / "events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(any(
                event.get("event") == "report.auto_refreshed"
                and event.get("reason") == "gate.complete.intake_scope"
                for event in events
            ))
            report = (store.run_dir(run_id) / "final-report.md").read_text(encoding="utf-8")
            self.assertIn("intake_scope", report)
            self.assertIn("NO_GO", report)

    def test_finding_lifecycle_invalidates_final_report_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "finding-invalidates-final"
            evidence = repo / "evidence.md"
            evidence.write_text("returncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Invalidate final report", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            final_gate = next(gate for gate in plan.gates if gate.id == "final_report_reaudit")
            final_gate.state = "GO"
            final_gate.verdict = "GO"
            final_gate.evidence = [f".sdlc/runs/{run_id}/final-report.md"]
            store.save_plan(plan)
            store.save_findings(run_id, [Finding(
                id="LOW-FINAL",
                severity="LOW",
                title="Final report invalidation finding",
                evidence=["test"],
                impact="Report can become stale.",
                required_fix="Invalidate final gate after finding mutation.",
                owner="agent_4_evidence_reporting_owner",
            )])
            self.assertEqual(main(["--repo", str(repo), "finding", "close", run_id, "LOW-FINAL", "--closed-by", "agent_6_redteam_deploy_rollback", "--evidence", "evidence.md"]), 0)
            plan = store.load_plan(run_id)
            final_gate = next(gate for gate in plan.gates if gate.id == "final_report_reaudit")
            self.assertEqual(final_gate.state, "BLOCKED")
            self.assertEqual(final_gate.verdict, "NO_GO")

    def test_report_counts_fixed_pending_review_as_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "report-open-count"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Count pending findings", "--run-id", run_id]), 0)
            store = RunStore(repo)
            finding = Finding(
                id="MEDIUM-PENDING",
                severity="MEDIUM",
                title="Pending review still open",
                evidence=["test"],
                impact="Open count is misleading.",
                required_fix="Use open_findings utility.",
                owner="agent_4_evidence_reporting_owner",
            )
            finding.status = "FIXED_PENDING_REVIEW"
            store.save_findings(run_id, [finding])
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            report = (store.run_dir(run_id) / "final-report.md").read_text(encoding="utf-8")
            self.assertIn("- Open findings: 1", report)

    def test_run_state_finding_close_rejects_premature_release_ready_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "run-state-close"
            claim = repo / "claim.md"
            claim.write_text("This release-blocker run is production-ready and release-ready.\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject premature run-state closure", "--run-id", run_id]), 0)
            store = RunStore(repo)
            store.save_findings(run_id, [Finding(
                id="RT-HIGH-STATE",
                severity="HIGH",
                title="Active release run is still NO_GO",
                evidence=["test"],
                impact="The active release-blocker run remains blocked.",
                required_fix="Only close after computed run state changes.",
                owner="agent_3_implementation_owner",
            )])
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "close", run_id, "RT-HIGH-STATE",
                "--closed-by", "agent_6_redteam_deploy_rollback",
                "--evidence", "claim.md",
            ]), 0)

    def test_run_state_finding_close_considers_other_open_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "run-state-other-findings"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject run-state closure with other blockers", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            findings = [
                Finding(
                    id="RT-HIGH-STATE",
                    severity="HIGH",
                    title="Active release run is still NO_GO",
                    evidence=["test"],
                    impact="The active release-blocker run remains blocked.",
                    required_fix="Only close after computed run state changes.",
                    owner="agent_3_implementation_owner",
                ),
                Finding(
                    id="HIGH-OTHER",
                    severity="HIGH",
                    title="Another open blocker",
                    evidence=["test"],
                    impact="This separate blocker must still prevent release.",
                    required_fix="Close this independently first.",
                    owner="agent_3_implementation_owner",
                ),
            ]
            store.save_findings(run_id, findings)
            evidence = record_finding_closure_evidence(repo, run_id, "RT-HIGH-STATE")
            self.assertNotEqual(main([
                "--repo", str(repo), "finding", "close", run_id, "RT-HIGH-STATE",
                "--closed-by", "agent_6_redteam_deploy_rollback",
                "--evidence", *evidence,
            ]), 0)

    def test_upstream_no_go_invalidates_downstream_go_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "downstream-invalid"
            evidence = repo / "evidence.md"
            evidence.write_text("gate evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Invalidate downstream gates", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "independent_redteam_cross_model", "--verdict", "NO_GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", "evidence.md"]), 0)
            plan = store.load_plan(run_id)
            commit_gate = next(gate for gate in plan.gates if gate.id == "commit_branch_pr_ci")
            self.assertEqual(commit_gate.state, "BLOCKED")

    def test_manual_redteam_go_requires_executed_cross_model_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-manual-guard"
            evidence = repo / "evidence.md"
            evidence.write_text("prior gate evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Manual redteam guard", "--run-id", run_id, "--risk", "high"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            redteam_gate = next(gate for gate in plan.gates if gate.id == "independent_redteam_cross_model")
            for gate in plan.gates:
                if gate.order < redteam_gate.order and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            summary = store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("verdict: GO\nexecute_requested: False\nrounds: 2\nexecuted_families: codex, claude\n", encoding="utf-8")
            summary_arg = f".sdlc/runs/{run_id}/artifacts/redteam_execution_summary.md"
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "independent_redteam_cross_model", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", summary_arg]), 0)

            summary.write_text("verdict: GO\nexecute_requested: True\nrounds: 2\nexecuted_families: codex\n", encoding="utf-8")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "independent_redteam_cross_model", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", summary_arg]), 0)

            summary.write_text("verdict: GO\nexecute_requested: True\nrounds: 2\nexecuted_families: codex, claude\n", encoding="utf-8")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "independent_redteam_cross_model", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", summary_arg]), 0)

    def test_fix_loop_go_requires_fix_loop_evidence_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "fix-loop-evidence"
            evidence = repo / "evidence.md"
            evidence.write_text("prior gate evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Fix loop evidence", "--run-id", run_id, "--risk", "low"]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            for gate in plan.gates:
                if gate.order < 21 and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            summary = store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("verdict: GO\nexecute_requested: True\nrounds: 1\nexecuted_families: codex\n", encoding="utf-8")
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("worker.completed", worker="codex", mode="REDTEAM_ROUND_1", executed=True, returncode=0)
            ledger.event("redteam.execution_completed", verdict="GO", execute_requested=True, rounds=1, executed_families=["codex"], evidence=["artifacts/redteam_execution_summary.md"])
            summary_arg = f".sdlc/runs/{run_id}/artifacts/redteam_execution_summary.md"
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "critical_high_fix_loop", "--verdict", "GO", "--actor", "agent_1_pm_coordinator", "--evidence", summary_arg]), 0)

    def test_release_gate_go_rejects_generic_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "release-evidence-guard"
            evidence = repo / "evidence.md"
            evidence.write_text("generic existing evidence\n", encoding="utf-8")
            quality = repo / "quality.md"
            quality.write_text("deterministic quality evidence\nformat_result lint_result typecheck_result static_check_result\nCommand: python -m unittest discover -s tests\nreturncode: 0\nRan 1 tests\nOK\nConcrete references: tests/test_core.py and sdlc/cli.py\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Release evidence guard", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            quality_gate = next(gate for gate in plan.gates if gate.id == "deterministic_quality")
            for gate in plan.gates:
                if gate.order < quality_gate.order and gate.state != "SKIPPED":
                    gate.state = "GO"
                    gate.verdict = "GO"
                    gate.evidence = ["evidence.md"]
            store.save_plan(plan)
            quality_evidence = record_gate_evidence(repo, run_id, "deterministic_quality", "agent_5_qa_validation_owner")
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deterministic_quality", "--verdict", "GO", "--actor", "agent_5_qa_validation_owner", "--evidence", "evidence.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deterministic_quality", "--verdict", "GO", "--actor", "agent_5_qa_validation_owner", "--evidence", "quality.md"]), 0)
            self.assertEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deterministic_quality", "--verdict", "GO", "--actor", "agent_5_qa_validation_owner", "--evidence", quality_evidence, "quality.md"]), 0)


class SchemaValidationTests(unittest.TestCase):
    def test_schema_validator_reports_type_errors(self) -> None:
        schema = {
            "type": "object",
            "required": ["gate_id", "verdict", "evidence", "notes", "actor"],
            "properties": {
                "gate_id": {"type": "string"},
                "verdict": {"enum": ["GO", "NO_GO"]},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "actor": {"type": "string"},
            },
        }
        errors = validate_json_schema({"gate_id": "intake_scope", "verdict": "GO", "evidence": "not-a-list", "notes": "", "actor": "agent_1_pm_coordinator"}, schema)
        self.assertTrue(errors)


class WorkerCaptureTests(unittest.TestCase):
    def _install_fake_worker(self, repo: Path, name: str, body: str) -> tuple[Path, str]:
        bin_dir = repo / "bin"
        bin_dir.mkdir()
        script = bin_dir / name
        script.write_text(body, encoding="utf-8")
        script.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
        return script, old_path

    def _load_events(self, run_dir: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _allow_worker_network(self, repo: Path) -> None:
        policy = read_json(repo / ".sdlc" / "policies" / "default.json")
        policy["network_allowed"] = True
        write_json(repo / ".sdlc" / "policies" / "default.json", policy)

    def test_engine_snapshot_tracks_control_plane_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_artifact = repo / ".sdlc" / "runs" / "snapshot-run" / "events.jsonl"
            run_artifact.parent.mkdir(parents=True)
            run_artifact.write_text("{}\n", encoding="utf-8")
            snapshot = engine_repo_snapshot(repo)
            self.assertIn(".sdlc/runs/snapshot-run/events.jsonl", snapshot)

    def test_worker_tempdir_is_isolated_for_build_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / ".sdlc" / "runs" / "tempdir-run" / "prompts" / "execution_prompt.md"
            prompt.parent.mkdir(parents=True)
            prompt.write_text("prompt\n", encoding="utf-8")
            env = CodexAdapter().build_env(prompt, repo, "BUILD")
            self.assertIn(".sdlc-worker-tmp", env["TMPDIR"])
            self.assertEqual(env["TMPDIR"], env["TMP"])
            self.assertEqual(env["TMPDIR"], env["TEMP"])
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
            command = CodexAdapter().build_command(prompt, repo, "BUILD")
            self.assertIn("--add-dir", command)
            self.assertTrue(any(str(item).startswith(str(repo / ".sdlc-worker-tmp")) for item in command))

    def test_worker_dry_run_captures_outputs_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-dry-run"
            marker = repo / "worker-invoked"
            script_body = f"#!/bin/sh\nprintf invoked > {str(marker)!r}\nprintf 'worker stdout\\n'\nprintf 'worker stderr\\n' >&2\n"
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Capture worker output", "--run-id", run_id]), 0)
                self.assertEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD"]), 0)
            finally:
                os.environ["PATH"] = old_path

            self.assertFalse(marker.exists())
            run_dir = RunStore(repo).run_dir(run_id)
            captures = sorted((run_dir / "worker-results").iterdir())
            self.assertEqual(len(captures), 1)
            result = json.loads((captures[0] / "result.json").read_text(encoding="utf-8"))
            self.assertFalse(result["executed"])
            self.assertTrue(result["available"])
            self.assertEqual(result["stderr_path"], f"worker-results/{captures[0].name}/stderr.txt")
            self.assertIn("DRY_RUN", (captures[0] / "stderr.txt").read_text(encoding="utf-8"))
            events = self._load_events(run_dir)
            event_names = [event["event"] for event in events]
            self.assertIn("worker.started", event_names)
            self.assertIn("worker.completed", event_names)
            self.assertGreaterEqual(event_names.count("worker.output_captured"), 3)

    def test_worker_execute_captures_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-execute"
            script_body = "#!/bin/sh\ncat >/dev/null\nprintf 'fake stdout\\n'\nprintf 'fake stderr\\n' >&2\n"
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Capture executed worker output", "--run-id", run_id]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path

            run_dir = RunStore(repo).run_dir(run_id)
            captures = sorted((run_dir / "worker-results").iterdir())
            self.assertEqual(len(captures), 1)
            self.assertEqual((captures[0] / "stdout.txt").read_text(encoding="utf-8"), "fake stdout\n")
            self.assertEqual((captures[0] / "stderr.txt").read_text(encoding="utf-8"), "fake stderr\n")
            result = json.loads((captures[0] / "result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["executed"])
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["stdout_path"], f"worker-results/{captures[0].name}/stdout.txt")

    def test_claude_adapter_uses_stdin_not_prompt_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("prompt with sensitive run context\n", encoding="utf-8")
            adapter = ClaudeAdapter()
            command = adapter.build_command(prompt, repo, "SECURITY_REVIEW")
            self.assertNotIn("prompt with sensitive run context", command)
            self.assertIn("--print", command)
            self.assertEqual(command[command.index("--permission-mode") + 1], "plan")
            self.assertTrue(adapter.security_review_write_protected())
            self.assertEqual(adapter.build_stdin(prompt, repo, "SECURITY_REVIEW"), "prompt with sensitive run context\n")

    def test_gemini_adapter_uses_stdin_and_plan_mode_for_security_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("prompt with sensitive run context\n", encoding="utf-8")
            adapter = GeminiAdapter()
            command = adapter.build_command(prompt, repo, "SECURITY_REVIEW")
            self.assertNotIn("prompt with sensitive run context", command)
            self.assertEqual(command[command.index("--approval-mode") + 1], "plan")
            self.assertIn("--skip-trust", command)
            self.assertIn("stdin", command[command.index("--prompt") + 1])
            self.assertTrue(adapter.security_review_write_protected())
            self.assertEqual(adapter.build_stdin(prompt, repo, "SECURITY_REVIEW"), "prompt with sensitive run context\n")

    def test_kimi_adapter_uses_stdin_not_prompt_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("prompt with sensitive run context\n", encoding="utf-8")
            adapter = KimiAdapter()
            command = adapter.build_command(prompt, repo, "PLAN")
            self.assertNotIn("prompt with sensitive run context", command)
            self.assertEqual(command[0], "kimi")
            self.assertEqual(adapter.build_stdin(prompt, repo, "PLAN"), "prompt with sensitive run context\n")

    def test_codex_security_review_uses_disposable_workspace_tmpdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("audit prompt\n", encoding="utf-8")
            adapter = CodexAdapter()
            command = adapter.build_command(prompt, repo, "SECURITY_REVIEW")
            self.assertIn("--sandbox", command)
            self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
            codex_cwd = command[command.index("--cd") + 1]
            self.assertEqual(codex_cwd, str(repo.resolve(strict=False)))
            add_dirs = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--add-dir"]
            self.assertNotIn(str(repo.resolve(strict=False)), add_dirs)
            writable_dir = next(item for item in add_dirs if "sdlc-worker-tmp" in item)
            self.assertIn("sdlc-worker-tmp", writable_dir)
            self.assertNotIn(str(repo / ".sdlc-worker-tmp"), command)
            self.assertTrue(adapter.security_review_write_protected())
            env = adapter.build_env(prompt, repo, "SECURITY_REVIEW")
            self.assertEqual(env["TMPDIR"], writable_dir)
            self.assertNotIn(str(repo), env["TMPDIR"])
            self.assertNotIn("unknown-run", env["TMPDIR"])
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
            self.assertTrue(Path(env["TMPDIR"]).exists())

    def test_codex_audit_workspace_review_has_writable_tmp_without_source_repo_add_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("audit prompt\n", encoding="utf-8")
            adapter = CodexAdapter()
            command = adapter.build_command(prompt, repo, "SECURITY_REVIEW_AUDIT_WORKSPACE")
            self.assertEqual(command[command.index("--sandbox") + 1], "workspace-write")
            self.assertEqual(command[command.index("--cd") + 1], str(repo.resolve(strict=False)))
            add_dirs = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--add-dir"]
            self.assertNotIn(str(repo.resolve(strict=False)), add_dirs)
            writable_dir = next(item for item in add_dirs if "sdlc-worker-tmp" in item)
            env = adapter.build_env(prompt, repo, "SECURITY_REVIEW_AUDIT_WORKSPACE")
            self.assertEqual(env["TMPDIR"], writable_dir)
            self.assertNotIn(str(repo), env["TMPDIR"])
            self.assertTrue(Path(env["TMPDIR"]).exists())

    def test_run_cmd_strips_sensitive_environment_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            old_secret = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            old_leak = os.environ.get("LEAK_TEST_SECRET")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = "super-secret-value"
            os.environ["LEAK_TEST_SECRET"] = "leaky"  # pragma: allowlist secret
            try:
                result = run_cmd([
                    sys.executable,
                    "-c",
                    "import os; print(os.getenv('SDLC_ACTOR_PROOF_KEY', 'absent')); print(os.getenv('LEAK_TEST_SECRET', 'absent'))",
                ], repo)
            finally:
                if old_secret is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_secret
                if old_leak is None:
                    os.environ.pop("LEAK_TEST_SECRET", None)
                else:
                    os.environ["LEAK_TEST_SECRET"] = old_leak
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["stdout"].splitlines(), ["absent", "absent"])

    def test_run_cmd_disables_git_hooks_by_default(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for hook isolation tests")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "file.txt").write_text("initial\n", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "init"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "config", "user.email", "sdlc@example.test"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "config", "user.name", "SDLC Test"], repo)["returncode"], 0)
            hook = repo / ".git" / "hooks" / "commit-msg"
            hook.write_text("#!/bin/sh\nprintf 'HOOK:%s\\n' \"${SDLC_ACTOR_PROOF_KEY:-missing}\" >&2\nexit 1\n", encoding="utf-8")
            hook.chmod(0o755)
            old_secret = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = "hook-secret"
            try:
                self.assertEqual(run_cmd(["git", "add", "file.txt"], repo)["returncode"], 0)
                result = run_cmd(["git", "commit", "-m", "chore: fixture"], repo)
            finally:
                if old_secret is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_secret
            self.assertEqual(result["returncode"], 0, result.get("stderr"))
            self.assertNotIn("HOOK:", result.get("stderr", ""))

    def test_configured_codex_alias_uses_openai_provider_and_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            prompt = repo / "prompt.md"
            prompt.write_text("audit prompt\n", encoding="utf-8")
            adapter = adapter_from_policy("openai-redteam", {
                "worker_families": {
                    "openai-redteam": {
                        "adapter": "codex",
                        "provider": "openai",
                        "model": "o3",
                        "read_only_security_review": True,
                    }
                }
            })
            self.assertIsNotNone(adapter)
            self.assertEqual(adapter.provider, "openai")
            command = adapter.build_command(prompt, repo, "SECURITY_REVIEW")
            self.assertIn("--model", command)
            self.assertEqual(command[command.index("--model") + 1], "o3")
            self.assertTrue(adapter.security_review_write_protected())

    def test_configured_local_redteam_worker_requires_declared_write_isolation(self) -> None:
        unprotected = adapter_from_policy("local-review", {"worker_families": {"local-review": {"command": ["reviewer"]}}})
        self.assertIsNotNone(unprotected)
        self.assertFalse(unprotected.security_review_write_protected())
        protected = adapter_from_policy("local-review", {"worker_families": {"local-review": {"command": ["reviewer"], "read_only_security_review": True}}})
        self.assertIsNotNone(protected)
        self.assertTrue(protected.security_review_write_protected())

    def test_audit_workspace_precreates_redteam_tmpdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "sdlc").mkdir()
            (repo / "sdlc" / "__init__.py").write_text("", encoding="utf-8")
            holder, workspace = _create_audit_workspace(repo)
            try:
                self.assertTrue((workspace / ".sdlc-redteam-tmp").is_dir())
                self.assertTrue((workspace.parent / ".sdlc-worker-tmp" / workspace.name).is_dir())
            finally:
                holder.cleanup()

    def test_audit_workspace_preserves_git_provenance(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for provenance workspace tests")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "sdlc").mkdir()
            (repo / "sdlc" / "__init__.py").write_text("", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "init"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "config", "user.email", "sdlc@example.test"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "config", "user.name", "SDLC Test"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "add", "sdlc/__init__.py"], repo)["returncode"], 0)
            self.assertEqual(run_cmd(["git", "commit", "-m", "chore: fixture"], repo)["returncode"], 0)
            holder, workspace = _create_audit_workspace(repo)
            try:
                self.assertTrue((workspace / ".git").exists())
                status = run_cmd(["git", "status", "--short", "--branch"], workspace)
                self.assertEqual(status["returncode"], 0, status.get("stderr"))
                self.assertIn("##", status.get("stdout", ""))
            finally:
                holder.cleanup()

    def test_worker_capture_redacts_secret_like_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-redact"
            secret = "ghp_ABCDEFGHIJKLMNOPQRSTUV123456"  # pragma: allowlist secret
            script_body = f"#!/bin/sh\ncat >/dev/null\nprintf 'token={secret}\\n'\n"
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Capture redacted worker output", "--run-id", run_id]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            capture = next((RunStore(repo).run_dir(run_id) / "worker-results").iterdir())
            stdout = (capture / "stdout.txt").read_text(encoding="utf-8")
            result = (capture / "result.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, result)
            self.assertIn("[REDACTED]", stdout)

    def test_worker_execute_restores_protected_run_ledger_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-ledger-protect"
            script_body = (
                "#!/bin/sh\n"
                "cat >/dev/null\n"
                f"printf '{{\"event\":\"forged\",\"run_id\":\"{run_id}\"}}\\n' >> .sdlc/runs/{run_id}/events.jsonl\n"
                "printf forged > .sdlc/runs/{run_id}/forged.txt\n"
            ).replace("{run_id}", run_id)
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Protect ledger", "--run-id", run_id]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            run_dir = RunStore(repo).run_dir(run_id)
            self.assertFalse((run_dir / "forged.txt").exists())
            events = self._load_events(run_dir)
            self.assertFalse(any(event.get("event") == "forged" for event in events))
            violation = [event for event in events if event.get("event") == "worker.policy_violation"]
            self.assertTrue(violation)
            self.assertTrue(any(".sdlc/runs/" in path for path in violation[-1].get("deny_path_changes", [])))
            self.assertTrue(violation[-1].get("resolved"))

    def test_worker_environment_strips_orchestrator_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-env-strip"
            script_body = (
                "#!/bin/sh\n"
                "cat >/dev/null\n"
                "if [ -n \"${SDLC_ACTOR_PROOF_KEY+x}\" ]; then printf 'secret-present\\n'; else printf 'secret-absent\\n'; fi\n"
                "if [ -n \"${SDLC_ACTOR_PROOF_KEY_FILE+x}\" ]; then printf 'keyfile-present\\n'; else printf 'keyfile-absent\\n'; fi\n"
                "printf 'sanitized=%s\\n' \"$SDLC_WORKER_SANITIZED_ENV\"\n"
            )
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            old_key_file = os.environ.get("SDLC_ACTOR_PROOF_KEY_FILE")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = "do-not-leak"
            os.environ["SDLC_ACTOR_PROOF_KEY_FILE"] = str(repo / "do-not-leak")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Strip worker env", "--run-id", run_id]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
                if old_key_file is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY_FILE", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY_FILE"] = old_key_file
            capture = next((RunStore(repo).run_dir(run_id) / "worker-results").iterdir())
            stdout = (capture / "stdout.txt").read_text(encoding="utf-8")
            self.assertIn("secret-absent", stdout)
            self.assertIn("keyfile-absent", stdout)
            self.assertIn("sanitized=1", stdout)

    def test_worker_verdict_ignores_tool_output_verdicts(self) -> None:
        event_output = "\n".join([
            json.dumps({
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "aggregated_output": "old artifact says verdict: NO_GO",
                },
            }),
            json.dumps({
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": json.dumps({
                        "verdict": "GO",
                        "reviewed_run_id": "production-grade-release-blockers",
                        "prompt_sha256": "a" * 64,
                        "findings": [],
                    }),
                },
            }),
        ])
        self.assertEqual(_worker_declared_verdict(event_output), "GO")

    def test_worker_verdict_requires_agent_message_for_transport_jsonl(self) -> None:
        event_output = "\n".join([
            json.dumps({"type": "thread.started", "thread_id": "test"}),
            json.dumps({
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "aggregated_output": "# Final Report\nVerdict: **NO_GO**\n",
                },
            }),
            json.dumps({"type": "turn.completed", "usage": {}}),
        ])
        self.assertIsNone(_worker_declared_verdict(event_output))

    def test_gemini_response_field_is_parsed_for_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "gemini-response"
            run_dir = repo / ".sdlc" / "runs" / run_id
            ledger = Ledger(run_dir, run_id)
            response = {
                "verdict": "NO_GO",
                "reviewed_run_id": run_id,
                "prompt_sha256": "b" * 64,
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "title": "Ledger forgery is possible",
                        "evidence": ["sdlc/adapters.py"],
                        "impact": "Release evidence can be forged.",
                        "required_fix": "Protect run ledger paths from workers.",
                        "owner": "agent_6_redteam_deploy_rollback",
                    }
                ],
            }
            output = json.dumps({"response": "```json\n" + json.dumps(response) + "\n```"})
            self.assertEqual(_worker_declared_verdict(output), "NO_GO")
            findings = _parse_worker_findings(repo, run_dir, "gemini", output, [], ledger)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "CRITICAL")
            self.assertEqual(findings[0].title, "Ledger forgery is possible")

    def test_redteam_summary_records_executed_families_even_for_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-executed-no-go"
            body = (
                "#!/bin/sh\n"
                "cat >/dev/null\n"
                "printf '%s\\n' '{\"verdict\":\"NO_GO\",\"reviewed_run_id\":\"redteam-executed-no-go\",\"prompt_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"findings\":[]}'\n"
            )
            _codex, old_path = self._install_fake_worker(repo, "codex", body)
            gemini = repo / "bin" / "gemini"
            gemini.write_text(body, encoding="utf-8")
            gemini.chmod(0o755)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Executed no go", "--run-id", run_id, "--risk", "high"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["redteam"]["allowed_providers"] = ["openai", "google"]
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex,gemini", "--rounds", "3", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("executed_families: codex, gemini", summary)
            self.assertIn("worker_verdicts: codex:NO_GO:round1, gemini:NO_GO:round1", summary)

    def test_redteam_execution_persists_parsed_findings_before_final_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-persist-findings"
            payload = {
                "verdict": "NO_GO",
                "reviewed_run_id": run_id,
                "prompt_sha256": "a" * 64,
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Persist parsed finding",
                        "evidence": ["sdlc/engine.py"],
                        "impact": "Dropped findings can bypass release readiness.",
                        "required_fix": "Persist findings transactionally.",
                        "owner": "agent_3_implementation_owner",
                    }
                ],
            }
            body = "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' " + shlex.quote(json.dumps(payload)) + "\n"
            _script, old_path = self._install_fake_worker(repo, "codex", body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Persist redteam findings", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--rounds", "1", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            findings = RunStore(repo).load_findings(run_id)
            self.assertTrue(any(finding.title == "Persist parsed finding" for finding in findings))
            events = self._load_events(RunStore(repo).run_dir(run_id))
            self.assertTrue(any(event.get("event") == "redteam.findings_persisted" for event in events))

    def test_worker_execute_requires_network_policy_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-policy"
            script_body = "#!/bin/sh\ncat >/dev/null\nprintf 'fake stdout\\n'\n"
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Block worker without network policy", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute"]), 0)
            finally:
                os.environ["PATH"] = old_path

    def test_worker_execute_blocks_out_of_ownership_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-ownership"
            script_body = "#!/bin/sh\ncat >/dev/null\nprintf bad > unowned.txt\n"
            _script, old_path = self._install_fake_worker(repo, "codex", script_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Worker ownership", "--run-id", run_id]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "worker", run_id, "codex", "--mode", "BUILD", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            events = self._load_events(RunStore(repo).run_dir(run_id))
            violations = [event for event in events if event["event"] == "worker.policy_violation"]
            self.assertTrue(any("ownership_violations" in event for event in violations))
            self.assertFalse((repo / "unowned.txt").exists())
            self.assertTrue(any(event.get("resolved") for event in violations))

    def test_managed_worker_cannot_mutate_control_plane_even_for_other_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "managed-worker-block"
            evidence = repo / "evidence.md"
            evidence.write_text("returncode: 0\nConcrete references: sdlc/cli.py and tests/test_core.py\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Block managed worker", "--run-id", run_id]), 0)
            old_env = {key: os.environ.get(key) for key in ["SDLC_WORKER_EXECUTION", "SDLC_WORKER_REPO", "SDLC_WORKER_RUN_ID"]}
            os.environ["SDLC_WORKER_EXECUTION"] = "1"
            os.environ["SDLC_WORKER_REPO"] = str(repo / "audit-copy")
            os.environ["SDLC_WORKER_RUN_ID"] = "other-run"
            try:
                result = main([
                    "--repo", str(repo), "gate", "complete", run_id, "intake_scope",
                    "--verdict", "GO",
                    "--actor", "agent_1_pm_coordinator",
                    "--evidence", "evidence.md",
                ])
            finally:
                for key, value in old_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertNotEqual(result, 0)
            events = self._load_events(RunStore(repo).run_dir(run_id))
            self.assertTrue(any(event.get("event") == "gate.completion_rejected" and "Managed worker processes cannot mutate" in event.get("reason", "") for event in events))

    def test_release_validation_blocks_unresolved_worker_policy_violation_and_missing_parsed_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "worker-integrity-release"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Worker integrity", "--run-id", run_id]), 0)
            store = RunStore(repo)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("worker.policy_violation", worker="codex", mode="BUILD", ownership_violations=["unowned.txt"])
            ledger.event("redteam.findings_parsed", worker="codex", findings=["MISSING-CRITICAL-001"])
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("Unresolved worker policy violation" in error for error in errors))
            self.assertTrue(any("Parsed red-team findings are missing" in error for error in errors))

    def test_release_validation_allows_prior_redteam_mutation_after_later_clean_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-mutation-superseded"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Worker integrity", "--run-id", run_id]), 0)
            store = RunStore(repo)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("redteam.worker_policy_violation", worker="claude", round=1, mutated_paths=["sdlc/engine.py"])
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("Red-team worker mutation violation remains" in error for error in errors))

            ledger.event(
                "redteam.execution_completed",
                verdict="NO_GO",
                execute_requested=True,
                mutation_violations=[],
                executed_families=["codex", "claude"],
                evidence=["artifacts/redteam_execution_summary.md"],
            )
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertFalse(any("Red-team worker mutation violation remains" in error for error in errors))

    def test_run_cmd_caps_large_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            result = run_cmd([sys.executable, "-c", "print('x' * 200)"], repo, max_output_chars=64)
            self.assertEqual(result["returncode"], 0)
            self.assertTrue(result["stdout_truncated"])
            self.assertLessEqual(len(result["stdout"]), 64)

    def test_run_cmd_passes_explicit_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            result = run_cmd([sys.executable, "-c", "import os; print(os.environ['SDLC_TEST_ENV'])"], repo, env={"SDLC_TEST_ENV": "present"})
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["stdout"].strip(), "present")


class ScannerEvidenceTests(unittest.TestCase):
    def _install_fake_tool(self, repo: Path, name: str, *, exit_code: int = 0, output: str = "{}\n") -> tuple[Path, str]:
        bin_dir = repo / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / name
        script.write_text(f"#!/bin/sh\nprintf {output!r}\nexit {exit_code}\n", encoding="utf-8")
        script.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
        return script, old_path

    def _install_fake_scanners(self, repo: Path, *, exit_code: int = 0) -> str:
        old_path = os.environ.get("PATH", "")
        bin_dir = repo / "bin"
        bin_dir.mkdir(exist_ok=True)
        for name in ["bandit", "detect-secrets", "pip-audit", "checkov"]:
            script = bin_dir / name
            script.write_text(f"#!/bin/sh\nprintf '{{}}\\n'\nexit {exit_code}\n", encoding="utf-8")
            script.chmod(0o755)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
        return old_path

    def _satisfy_scan_prerequisites(self, repo: Path, run_id: str) -> None:
        evidence = repo / "scan-prereq.md"
        evidence.write_text("scanner prerequisite evidence\n", encoding="utf-8")
        store = RunStore(repo)
        plan = store.load_plan(run_id)
        security_gate = next(gate for gate in plan.gates if gate.id == "security_scans")
        for gate in plan.gates:
            if gate.order < security_gate.order and gate.state != "SKIPPED":
                gate.state = "GO"
                gate.verdict = "GO"
                gate.evidence = ["scan-prereq.md"]
        store.save_plan(plan)

    def test_scan_records_policy_blocked_dependency_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-blocked"
            old_path = self._install_fake_scanners(repo)
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                (repo / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan evidence", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            security_gate = next(gate for gate in plan.gates if gate.id == "security_scans")
            self.assertEqual(security_gate.verdict, "NO_GO")
            summary = (store.run_dir(run_id) / "artifacts" / "security_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("pip-audit", summary)
            self.assertIn("BLOCKED_BY_POLICY", summary)

    def test_scan_can_go_when_policy_allows_network_and_fake_scanners_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-pass"
            old_path = self._install_fake_scanners(repo)
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                (repo / "main.tf").write_text("resource \"null_resource\" \"demo\" {}\n", encoding="utf-8")
                (repo / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan evidence", "--run-id", run_id]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._satisfy_scan_prerequisites(repo, run_id)
                self.assertEqual(main(["--repo", str(repo), "scan", run_id, "--allow-network", "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            security_gate = next(gate for gate in plan.gates if gate.id == "security_scans")
            self.assertEqual(security_gate.verdict, "GO")

    def test_pip_audit_policy_ignore_records_residual_nonblocking_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "pip-audit-ignore"
            pip_audit_output = json.dumps({
                "dependencies": [{
                    "name": "markdown",
                    "version": "3.8.1",
                    "vulns": [{
                        "id": "PYSEC-2026-89",
                        "aliases": ["CVE-2025-69534"],
                        "fix_versions": [],
                        "description": "test advisory",
                    }],
                }]
            }) + "\n"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=0, output="{}\n")
            self._install_fake_tool(repo, "detect-secrets", exit_code=0, output="{}\n")
            self._install_fake_tool(repo, "pip-audit", exit_code=1, output=pip_audit_output)
            try:
                (repo / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan ignored pip advisory", "--run-id", run_id]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                policy["scanner_ignored_vulnerabilities"] = [{
                    "scanner": "pip-audit",
                    "package": "markdown",
                    "id": "PYSEC-2026-89",
                    "reason": "Advisory metadata flags versions after the stated fixed version; record as residual finding for this test.",
                }]
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._satisfy_scan_prerequisites(repo, run_id)
                self.assertEqual(main(["--repo", str(repo), "scan", run_id, "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "security_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("PASS_WITH_FINDINGS", summary)
            self.assertIn("ignored_vulnerabilities=1", summary)

    def test_scan_no_go_returns_nonzero_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-fail"
            old_path = self._install_fake_scanners(repo, exit_code=1)
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan evidence", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path

    def test_iac_scanner_unavailable_blocks_when_iac_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-iac-required"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=0, output="{}\n")
            self._install_fake_tool(repo, "detect-secrets", exit_code=0, output="{}\n")
            os.environ["PATH"] = str(repo / "bin")
            try:
                (repo / "main.tf").write_text("resource \"null_resource\" \"demo\" {}\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan IaC required", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            security_gate = next(gate for gate in store.load_plan(run_id).gates if gate.id == "security_scans")
            self.assertEqual(security_gate.verdict, "NO_GO")
            summary = (store.run_dir(run_id) / "artifacts" / "security_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("checkov", summary)
            self.assertIn("UNAVAILABLE", summary)

    def test_bandit_low_only_findings_are_residual_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "bandit-low"
            bandit_output = json.dumps({
                "results": [{
                    "test_id": "B603",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "filename": str(repo / "app.py"),
                    "line_number": 1,
                    "issue_text": "subprocess call",
                }],
                "metrics": {},
                "errors": [],
            }) + "\n"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=1, output=bandit_output)
            self._install_fake_tool(repo, "detect-secrets", exit_code=0, output="{}\n")
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan low bandit finding", "--run-id", run_id, "--risk", "medium"]), 0)
                self._satisfy_scan_prerequisites(repo, run_id)
                self.assertEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            security_gate = next(gate for gate in plan.gates if gate.id == "security_scans")
            self.assertEqual(security_gate.verdict, "GO")
            summary = (store.run_dir(run_id) / "artifacts" / "security_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("PASS_WITH_FINDINGS", summary)
            self.assertIn("LOW=1", summary)

    def test_bandit_high_findings_block_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "bandit-high"
            bandit_output = json.dumps({
                "results": [{
                    "test_id": "B999",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "filename": str(repo / "app.py"),
                    "line_number": 1,
                    "issue_text": "high severity issue",
                }],
                "metrics": {},
                "errors": [],
            }) + "\n"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=1, output=bandit_output)
            self._install_fake_tool(repo, "detect-secrets", exit_code=0, output="{}\n")
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan high bandit finding", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            security_gate = next(gate for gate in store.load_plan(run_id).gates if gate.id == "security_scans")
            self.assertEqual(security_gate.verdict, "NO_GO")

    def test_scanner_artifacts_are_referenced_in_gate_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-ledger"
            old_path = self._install_fake_scanners(repo)
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan ledger evidence", "--run-id", run_id]), 0)
                self._satisfy_scan_prerequisites(repo, run_id)
                self.assertEqual(main(["--repo", str(repo), "scan", run_id, "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            run_dir = store.run_dir(run_id)
            gate = next(item for item in store.load_plan(run_id).gates if item.id == "security_scans")
            self.assertIn("artifacts/scans/bandit.txt", gate.evidence)
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            scan_events = [event for event in events if event["event"] == "security.scan_result" and event["scanner"] == "bandit"]
            self.assertTrue(scan_events)
            self.assertEqual(scan_events[-1]["artifact"], "artifacts/scans/bandit.txt")

    def test_scanner_artifacts_redact_common_secret_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "scan-redact"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=0, output="{}\n")
            self._install_fake_tool(repo, "detect-secrets", exit_code=1, output="token=ghp_ABCDEFGHIJKLMNOPQRSTUV123456\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n")
            try:
                (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Scan redaction", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            artifact = (RunStore(repo).run_dir(run_id) / "artifacts" / "scans" / "detect-secrets.txt").read_text(encoding="utf-8")
            redacted_value = "ghp_" + "".join(chr(code) for code in [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 49, 50, 51, 52, 53, 54])
            bearer_value = "Bearer " + "".join(chr(code) for code in [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 49, 50, 51, 52, 53, 54])
            self.assertNotIn(redacted_value, artifact)
            self.assertNotIn(bearer_value, artifact)
            self.assertIn("[REDACTED]", artifact)

    def test_detect_secrets_json_findings_block_even_with_zero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "detect-secrets-json"
            payload = json.dumps({
                "results": {
                    "app.py": [{
                        "type": "Secret Keyword",
                        "line_number": 1,
                        "hashed_secret": "abc123",  # pragma: allowlist secret
                    }]
                }
            }) + "\n"
            old_path = os.environ.get("PATH", "")
            self._install_fake_tool(repo, "bandit", exit_code=0, output="{}\n")
            self._install_fake_tool(repo, "detect-secrets", exit_code=0, output=payload)
            try:
                (repo / "app.py").write_text("token = 'example'\n", encoding="utf-8")
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Detect secret JSON", "--run-id", run_id]), 0)
                self.assertNotEqual(main(["--repo", str(repo), "scan", run_id, "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "security_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("secret_findings=1", summary)


class RedTeamExecutionTests(unittest.TestCase):
    def _install_fake_worker(self, repo: Path, name: str, body: str) -> str:
        bin_dir = repo / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / name
        script.write_text(body, encoding="utf-8")
        script.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
        return old_path

    def _allow_worker_network(self, repo: Path) -> None:
        policy = read_json(repo / ".sdlc" / "policies" / "default.json")
        policy["network_allowed"] = True
        write_json(repo / ".sdlc" / "policies" / "default.json", policy)

    def test_redteam_execute_records_interrupted_lifecycle(self) -> None:
        class InterruptingAdapter:
            name = "interrupting-redteam"
            provider = "openai"

            def security_review_write_protected(self, policy: dict[str, object] | None = None) -> bool:
                return True

            def run(self, prompt_path: Path, repo: Path, mode: str, *, execute: bool = False, timeout: int = 120) -> object:
                raise KeyboardInterrupt()

        previous = ADAPTERS.get("interrupting-redteam")
        ADAPTERS["interrupting-redteam"] = InterruptingAdapter()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                run_id = "redteam-interrupted"
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Interrupted redteam", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "interrupting-redteam", "--execute", "--allow-network"]), 0)
                store = RunStore(repo)
                run_dir = store.run_dir(run_id)
                events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
                self.assertTrue(any(event.get("event") == "redteam.execution_started" for event in events))
                self.assertTrue(any(
                    event.get("event") == "redteam.execution_interrupted"
                    and event.get("active_worker") == "interrupting-redteam"
                    and event.get("reason") == "KeyboardInterrupt"
                    for event in events
                ))
                self.assertFalse(any(event.get("event") == "redteam.execution_completed" for event in events))
                gate = next(item for item in store.load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
                self.assertEqual(gate.verdict, "NO_GO")
                summary = (run_dir / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
                self.assertIn("interrupted before completion", summary)
                errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
                self.assertTrue(any("Latest red-team execution was interrupted" in error for error in errors))
                self.assertFalse(any("matching completion" in error for error in errors))
        finally:
            if previous is None:
                ADAPTERS.pop("interrupting-redteam", None)
            else:
                ADAPTERS["interrupting-redteam"] = previous

    def test_release_validation_reports_paused_redteam_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-paused"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Paused redteam", "--run-id", run_id]), 0)
            store = RunStore(repo)
            Ledger(store.run_dir(run_id), run_id).event("redteam.execution_started", workers=["codex"], rounds=1, execute_requested=True)
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("appears paused or interrupted" in error for error in errors))
            self.assertFalse(any("matching completion" in error for error in errors))

    def test_release_validation_reports_cancelled_redteam_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-cancelled"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Cancelled redteam", "--run-id", run_id]), 0)
            store = RunStore(repo)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("redteam.execution_started", workers=["codex"], rounds=1, execute_requested=True)
            ledger.event("redteam.execution_cancelled", reason="operator paused the run", verdict="NO_GO")
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("Latest red-team execution was cancelled" in error and "operator paused the run" in error for error in errors))
            self.assertFalse(any("matching completion" in error for error in errors))

    def test_redteam_execute_dry_run_captures_worker_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-dry"
            marker = repo / "worker-ran"
            old_path = self._install_fake_worker(repo, "codex", f"#!/bin/sh\nprintf ran > {str(marker)!r}\nprintf '{{}}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build redteam dry run", "--run-id", run_id]), 0)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            self.assertFalse(marker.exists())
            store = RunStore(repo)
            run_dir = store.run_dir(run_id)
            gate = next(item for item in store.load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertTrue((run_dir / "artifacts" / "redteam_execution_summary.md").exists())
            self.assertTrue((run_dir / "worker-results").exists())

    def test_redteam_records_unavailable_workers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-unavailable"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Build unavailable redteam", "--run-id", run_id, "--risk", "high"]), 0)
            self._allow_worker_network(repo)
            self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "missing-model", "--execute", "--allow-network", "--rounds", "2", "--allow-no-go-exit-zero"]), 0)
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("missing-model", summary)
            self.assertIn("verdict: NO_GO", summary)

    def test_redteam_worker_timeout_is_explicit_in_progress_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-worker-timeout"
            worker_body = """#!/usr/bin/env python3
import sys
import time

sys.stdin.read()
time.sleep(2)
print('{"verdict":"GO","findings":[]}')
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Timeout redteam worker", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main([
                        "--repo", str(repo), "redteam", "execute", run_id,
                        "--workers", "codex",
                        "--execute", "--allow-network",
                        "--timeout", "1",
                        "--allow-no-go-exit-zero",
                    ]), 0)
            finally:
                os.environ["PATH"] = old_path
            output = out.getvalue()
            self.assertIn("worker-timeout=1s", output)
            self.assertIn("completed timed out scope=per_worker", output)
            run_dir = RunStore(repo).run_dir(run_id)
            summary = (run_dir / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("worker_timeout_seconds: 1", summary)
            self.assertIn("timed_out_workers: codex@round1:per_worker:1s", summary)
            result_path = next((run_dir / "worker-results").glob("*/result.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["timeout_seconds"], 1)
            self.assertEqual(result["timeout_scope"], "per_worker")

    def test_redteam_total_timeout_skips_remaining_workers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-total-timeout"
            worker_body = """#!/usr/bin/env python3
import sys
import time

sys.stdin.read()
time.sleep(2)
print('{"verdict":"GO","findings":[]}')
"""
            old_path = self._install_fake_worker(repo, "slow-worker", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Total timeout redteam", "--run-id", run_id, "--risk", "low"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                policy["redteam"]["allowed_providers"] = ["local"]
                policy["worker_families"] = {
                    "slow-one": {"command": ["slow-worker"], "provider": "local", "read_only_security_review": True},
                    "slow-two": {"command": ["slow-worker"], "provider": "local", "read_only_security_review": True},
                }
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main([
                        "--repo", str(repo), "redteam", "execute", run_id,
                        "--workers", "slow-one,slow-two",
                        "--execute", "--allow-network",
                        "--timeout", "5",
                        "--total-timeout", "1",
                        "--allow-no-go-exit-zero",
                    ]), 0)
            finally:
                os.environ["PATH"] = old_path
            output = out.getvalue()
            self.assertIn("total-timeout=1s", output)
            self.assertIn("slow-two round 1 skipped", output)
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("total_timeout_seconds: 1", summary)
            self.assertIn("timed_out_workers: slow-one@round1:total_command:1s", summary)
            self.assertIn("skipped_due_total_timeout: slow-two@round1", summary)

    def test_redteam_parallel_per_round_requires_policy_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-parallel-policy"
            marker = repo / "parallel-worker-ran"
            old_path = self._install_fake_worker(repo, "codex", f"#!/bin/sh\ncat >/dev/null\nprintf ran > {str(marker)!r}\nprintf '{{\"verdict\":\"GO\",\"findings\":[]}}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Parallel policy redteam", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main([
                        "--repo", str(repo), "redteam", "execute", run_id,
                        "--workers", "codex",
                        "--execute", "--allow-network",
                        "--parallel-per-round",
                        "--allow-no-go-exit-zero",
                    ]), 0)
            finally:
                os.environ["PATH"] = old_path
            self.assertFalse(marker.exists())
            output = out.getvalue()
            self.assertIn("Red-team rejected: Parallel red-team per-round execution requires redteam.parallel_per_round_allowed=true in policy.", output)
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("parallel_per_round_requested: True", summary)
            self.assertIn("parallel_per_round: disabled", summary)

    def test_redteam_parallel_per_round_runs_when_policy_allows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-parallel-allowed"
            worker_body = """#!/usr/bin/env python3
import json
import re
import sys

prompt = sys.stdin.read()
run_id = re.search(r"^Run ID: (.+)$", prompt, re.MULTILINE).group(1)
binding = re.search(r"^Prompt binding SHA256: ([a-f0-9]{64})$", prompt, re.MULTILINE).group(1)
print(json.dumps({
    "verdict": "GO",
    "findings": [],
    "reviewed_run_id": run_id,
    "prompt_sha256": binding,
}))
"""
            original_path = os.environ.get("PATH", "")
            self._install_fake_worker(repo, "local-a", worker_body)
            self._install_fake_worker(repo, "local-b", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Parallel allowed redteam", "--run-id", run_id, "--risk", "low"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["network_allowed"] = True
                policy["redteam"]["allowed_providers"] = ["local"]
                policy["redteam"]["parallel_per_round_allowed"] = True
                policy["worker_families"] = {
                    "local-a": {"command": ["local-a"], "provider": "local", "read_only_security_review": True},
                    "local-b": {"command": ["local-b"], "provider": "local", "read_only_security_review": True},
                }
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main([
                        "--repo", str(repo), "redteam", "execute", run_id,
                        "--workers", "local-a,local-b",
                        "--execute", "--allow-network",
                        "--parallel-per-round",
                    ]), 0)
            finally:
                os.environ["PATH"] = original_path
            output = out.getvalue()
            self.assertIn("scheduling=parallel-per-round", output)
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("parallel_per_round: enabled", summary)
            self.assertIn("executed_families: local-a, local-b", summary)

    def test_redteam_rejects_non_openai_worker_when_policy_restricts_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-openai-only"
            old_path = self._install_fake_worker(repo, "claude", "#!/bin/sh\ncat >/dev/null\nprintf '{\"verdict\":\"GO\",\"findings\":[]}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Reject non OpenAI redteam", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "claude", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            run_dir = RunStore(repo).run_dir(run_id)
            summary = (run_dir / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("Red-team policy restricts worker providers to openai", summary)
            self.assertIn("claude:anthropic", summary)
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(any(event.get("event") == "redteam.execution_completed" and event.get("rejected") is True for event in events))

    def test_redteam_rejects_unprotected_configured_local_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-local-unprotected"
            marker = repo / "local-worker-ran"
            old_path = self._install_fake_worker(repo, "local-reviewer", f"#!/bin/sh\nprintf ran > {str(marker)!r}\nprintf '{{\"verdict\":\"GO\",\"findings\":[]}}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Reject unsafe local redteam", "--run-id", run_id, "--risk", "low"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["worker_families"] = {"local-review": {"command": ["local-reviewer"]}}
                policy["redteam"]["allowed_providers"] = ["local"]
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "local-review", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            self.assertFalse(marker.exists())
            run_dir = RunStore(repo).run_dir(run_id)
            summary = (run_dir / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("verdict: NO_GO", summary)
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(any(event.get("event") == "redteam.worker_rejected" and event.get("reason") == "security_review_write_isolation_missing" for event in events))

    def test_redteam_refreshes_report_after_persisting_findings_between_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-report-refresh"
            state = repo / "worker-state"
            first_payload = json.dumps({"findings": [{
                "severity": "HIGH",
                "title": "First round finding",
                "evidence": ["round1"],
                "impact": "Report must reflect this before the next worker snapshot.",
                "required_fix": "Refresh report after persistence.",
                "owner": "agent_3_implementation_owner",
            }]})
            stale_payload = json.dumps({"findings": [{
                "severity": "HIGH",
                "title": "Report stale during redteam execution",
                "evidence": ["final-report.md"],
                "impact": "Later red-team rounds saw stale open finding counts.",
                "required_fix": "Refresh report immediately after findings persist.",
                "owner": "agent_4_evidence_reporting_owner",
            }]})
            ok_payload = json.dumps({"verdict": "GO", "findings": []})
            worker_body = "\n".join([
                "#!/bin/sh",
                "cat >/dev/null",
                f"state={str(state)!r}",
                "count=0",
                "[ -f \"$state\" ] && count=$(cat \"$state\")",
                "count=$((count + 1))",
                "printf '%s' \"$count\" > \"$state\"",
                "if [ \"$count\" -eq 1 ]; then",
                f"  printf '%s\\n' {first_payload!r}",
                "else",
                f"  if grep -q 'Open findings: 1' \"$SDLC_WORKER_REPO/.sdlc/runs/{run_id}/final-report.md\"; then",
                f"    printf '%s\\n' {ok_payload!r}",
                "  else",
                f"    printf '%s\\n' {stale_payload!r}",
                "  fi",
                "fi",
            ]) + "\n"
            old_path = self._install_fake_worker(repo, "local-reviewer", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Refresh report during redteam", "--run-id", run_id, "--risk", "low"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["worker_families"] = {"local-review": {"command": ["local-reviewer"], "provider": "local", "read_only_security_review": True}}
                policy["redteam"]["allowed_providers"] = ["local"]
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "local-review", "--rounds", "2", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            findings = RunStore(repo).load_findings(run_id)
            self.assertEqual([finding.title for finding in findings], ["First round finding"])
            report = (RunStore(repo).run_dir(run_id) / "final-report.md").read_text(encoding="utf-8")
            self.assertIn("- Open findings: 1", report)

    def test_redteam_parses_worker_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-parse"
            payload = json.dumps({"findings": [{
                "severity": "HIGH",
                "title": "Worker found missing authorization check",
                "evidence": ["worker stdout"],
                "impact": "Unauthorized access may be possible.",
                "required_fix": "Add authorization validation and tests.",
                "owner": "agent_3_implementation_owner",
            }]})
            old_path = self._install_fake_worker(repo, "codex", f"#!/bin/sh\ncat >/dev/null\nprintf {payload!r}\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build parser redteam", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            findings = RunStore(repo).load_findings(run_id)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "HIGH")
            self.assertEqual(findings[0].owner, "agent_3_implementation_owner")

    def test_redteam_parses_markdown_worker_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-markdown"
            output = "\n".join([
                "**Verdict: NO_GO**",
                "## Critical Blockers",
                "**F-001 — Deployment execution is a confirmed no-op** (`sdlc/deploy.py:88`)",
                "The command reports success without a command.",
                "## High Findings",
                "- **F-002 — Prompt content is exposed in argv**",
                "Worker prompt can be read from process lists.",
            ])
            old_path = self._install_fake_worker(repo, "codex", f"#!/bin/sh\ncat >/dev/null\nprintf {output!r}\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build markdown redteam", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            findings = RunStore(repo).load_findings(run_id)
            self.assertEqual([finding.severity for finding in findings], ["CRITICAL", "HIGH"])
            self.assertIn("Deployment execution", findings[0].title)

    def test_redteam_worker_no_go_verdict_blocks_without_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-worker-verdict"
            old_path = self._install_fake_worker(repo, "codex", "#!/bin/sh\ncat >/dev/null\nprintf '{\"verdict\":\"NO_GO\",\"findings\":[]}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Worker verdict", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("Worker-declared NO_GO", gate.notes)

    def test_redteam_empty_successful_output_does_not_count_as_executed_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-empty-output"
            old_path = self._install_fake_worker(repo, "codex", "#!/bin/sh\ncat >/dev/null\nexit 0\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Empty redteam output", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")

    def test_redteam_detects_disposable_audit_workspace_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-audit-mutation"
            source = repo / "sdlc" / "__init__.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("# original\n", encoding="utf-8")
            worker_body = """#!/bin/sh
cat >/dev/null
printf '# mutated by red-team worker\\n' > sdlc/__init__.py
printf '{"verdict":"GO","findings":[]}\\n'
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Detect audit workspace mutation", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--rounds", "1", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            gate = next(item for item in store.load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("audit_workspace:sdlc/__init__.py", gate.notes)
            self.assertEqual(source.read_text(encoding="utf-8"), "# original\n")
            summary = (store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("mutation_violations: audit_workspace:sdlc/__init__.py", summary)
            events = [json.loads(line) for line in (store.run_dir(run_id) / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(any(
                event.get("event") == "redteam.worker_policy_violation"
                and "sdlc/__init__.py" in event.get("audit_workspace_mutations", [])
                for event in events
            ))

    def test_redteam_detects_mutate_then_revert_audit_workspace_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-mutate-revert"
            source = repo / "sdlc" / "__init__.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("# original\n", encoding="utf-8")
            worker_body = """#!/bin/sh
cat >/dev/null
original="$(cat sdlc/__init__.py)"
printf '# transient mutation\\n' > sdlc/__init__.py
sleep 0.12
printf '%s' "$original" > sdlc/__init__.py
printf '{"verdict":"GO","findings":[]}\\n'
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Detect transient audit mutation", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--rounds", "1", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            summary = (store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("mutation_violations: audit_workspace:sdlc/__init__.py", summary)
            self.assertEqual(source.read_text(encoding="utf-8"), "# original\n")

    def test_release_validation_reports_interrupted_redteam_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-interrupted"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Interrupted redteam", "--run-id", run_id]), 0)
            store = RunStore(repo)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("redteam.execution_started", workers=["codex"], rounds=3, execute_requested=True)
            ledger.event("redteam.execution_interrupted", workers=["codex"], rounds=3, execute_requested=True, reason="test_interrupt")
            errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id))
            self.assertTrue(any("Red-team execution was interrupted before completion" in error for error in errors), errors)
            self.assertFalse(any("without a matching completion event" in error for error in errors), errors)

    def test_audit_workspace_validation_treats_active_redteam_as_in_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            run_id = "redteam-active-audit"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Active audit redteam", "--run-id", run_id]), 0)
            store = RunStore(repo)
            plan = store.load_plan(run_id)
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event("redteam.execution_started", workers=["codex"], rounds=1, execute_requested=True)
            strict_errors = _release_readiness_errors(store, plan, store.load_findings(run_id))
            self.assertTrue(any("Latest red-team execution appears paused or interrupted" in error for error in strict_errors), strict_errors)
            audit_repo = root / "audit"
            shutil.copytree(repo / ".sdlc", audit_repo / ".sdlc")
            audit_store = RunStore(audit_repo)
            old_execution = os.environ.get("SDLC_WORKER_EXECUTION")
            old_readonly = os.environ.get("SDLC_WORKER_AUDIT_READONLY")
            try:
                os.environ["SDLC_WORKER_EXECUTION"] = "1"
                os.environ["SDLC_WORKER_AUDIT_READONLY"] = "1"
                source_errors = _release_readiness_errors(store, plan, store.load_findings(run_id), audit_workspace=True)
                audit_errors = _release_readiness_errors(audit_store, audit_store.load_plan(run_id), audit_store.load_findings(run_id), audit_workspace=True)
            finally:
                if old_execution is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_execution
                if old_readonly is None:
                    os.environ.pop("SDLC_WORKER_AUDIT_READONLY", None)
                else:
                    os.environ["SDLC_WORKER_AUDIT_READONLY"] = old_readonly
            self.assertTrue(any("Latest red-team execution appears paused or interrupted" in error for error in source_errors), source_errors)
            self.assertFalse(any("Latest red-team execution appears paused or interrupted" in error for error in audit_errors), audit_errors)

    def test_audit_workspace_release_validation_does_not_skip_late_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "audit-late-gates"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Audit late gates", "--run-id", run_id]), 0)
            store = RunStore(repo)
            old_execution = os.environ.get("SDLC_WORKER_EXECUTION")
            old_readonly = os.environ.get("SDLC_WORKER_AUDIT_READONLY")
            try:
                os.environ["SDLC_WORKER_EXECUTION"] = "1"
                os.environ["SDLC_WORKER_AUDIT_READONLY"] = "1"
                errors = _release_readiness_errors(store, store.load_plan(run_id), store.load_findings(run_id), audit_workspace=True)
            finally:
                if old_execution is None:
                    os.environ.pop("SDLC_WORKER_EXECUTION", None)
                else:
                    os.environ["SDLC_WORKER_EXECUTION"] = old_execution
                if old_readonly is None:
                    os.environ.pop("SDLC_WORKER_AUDIT_READONLY", None)
                else:
                    os.environ["SDLC_WORKER_AUDIT_READONLY"] = old_readonly
            self.assertTrue(any("Release validation final verdict is NO_GO" in error for error in errors), errors)
            for gate_id in [
                "independent_redteam_cross_model",
                "critical_high_fix_loop",
                "evidence_traceability_attestations",
                "commit_branch_pr_ci",
                "final_report_reaudit",
            ]:
                self.assertTrue(any(f"Gate {gate_id} is not release-satisfied" in error for error in errors), errors)

    def test_redteam_positive_verdict_requires_prompt_context_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-context"
            worker_body = """#!/usr/bin/env python3
import json
import re
import sys

prompt = sys.stdin.read()
run_id = re.search(r"^Run ID: (.+)$", prompt, re.MULTILINE).group(1)
binding = re.search(r"^Prompt binding SHA256: ([a-f0-9]{64})$", prompt, re.MULTILINE).group(1)
print(json.dumps({
    "verdict": "GO",
    "findings": [],
    "reviewed_run_id": run_id,
    "prompt_sha256": binding,
}))
"""
            old_path = self._install_fake_worker(repo, "gemini", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Context-bound redteam", "--run-id", run_id, "--risk", "low"]), 0)
                policy = read_json(repo / ".sdlc" / "policies" / "default.json")
                policy["redteam"]["allowed_providers"] = ["google"]
                write_json(repo / ".sdlc" / "policies" / "default.json", policy)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "gemini", "--execute", "--allow-network"]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            gate = next(item for item in store.load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "GO")
            summary = (store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("executed_families: gemini", summary)
            self.assertIn("unverified_positive_worker_verdicts: <none>", summary)

    def test_redteam_positive_verdict_without_prompt_context_is_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-context-missing"
            old_path = self._install_fake_worker(repo, "codex", "#!/bin/sh\ncat >/dev/null\nprintf '{\"verdict\":\"GO\",\"findings\":[]}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Unbound redteam GO", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main([
                    "--repo", str(repo), "redteam", "execute", run_id,
                    "--workers", "codex",
                    "--execute", "--allow-network",
                    "--allow-no-go-exit-zero",
                ]), 0)
            finally:
                os.environ["PATH"] = old_path
            store = RunStore(repo)
            gate = next(item for item in store.load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("reviewed_run_id and prompt_sha256", gate.notes)
            summary = (store.run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("unverified_positive_worker_verdicts: codex@round1", summary)

    def test_redteam_parser_prioritizes_final_agent_json_over_transport_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-jsonl-late"
            worker_body = """#!/usr/bin/env python3
import json
import sys

sys.stdin.read()
for index in range(80):
    print(json.dumps({
        "type": "item.completed",
        "item": {
            "type": "command_execution",
            "aggregated_output": "**F-001 — stale transport text**",
        },
    }))
finding = {
    "severity": "HIGH",
    "title": "Final JSON finding",
    "evidence": ["final agent message"],
    "impact": "The final worker verdict must not be dropped.",
    "required_fix": "Parse late agent-message JSON payloads before markdown fallback.",
    "owner": "agent_3_implementation_owner",
}
print(json.dumps({
    "type": "item.completed",
    "item": {
        "type": "agent_message",
        "text": json.dumps({"findings": [finding], "verdict": "NO_GO"}),
    },
}))
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build JSONL parser", "--run-id", run_id, "--risk", "low"]), 0)
                self._allow_worker_network(repo)
                self.assertNotEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--fail-on-findings"]), 0)
            finally:
                os.environ["PATH"] = old_path
            findings = RunStore(repo).load_findings(run_id)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].title, "Final JSON finding")

    def test_transport_command_output_is_not_parsed_as_markdown_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-transport-ignore"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Ignore transport command output", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            output = "\n".join([
                json.dumps({"type": "item.started", "item": {"type": "command_execution", "aggregated_output": ""}}),
                json.dumps({
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "aggregated_output": "**F-001 — Deployment execution is a confirmed no-op**\nHistorical text from docs, not final worker findings.",
                    },
                }),
            ])
            parsed = _parse_worker_findings(repo, run_dir, "codex", output, [], Ledger(run_dir, run_id))
            self.assertEqual(parsed, [])

    def test_high_risk_requires_two_executed_worker_families(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-cross-model"
            worker_body = """#!/usr/bin/env python3
import json
import re
import sys

prompt = sys.stdin.read()
run_id = re.search(r"^Run ID: (.+)$", prompt, re.MULTILINE).group(1)
binding = re.search(r"^Prompt binding SHA256: ([a-f0-9]{64})$", prompt, re.MULTILINE).group(1)
print(json.dumps({
    "verdict": "GO",
    "findings": [],
    "reviewed_run_id": run_id,
    "prompt_sha256": binding,
}))
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build high risk redteam", "--run-id", run_id, "--risk", "high"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--rounds", "3", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("two independent executed worker families", gate.notes)

    def test_high_risk_requires_distinct_redteam_model_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-model-identity"
            worker_body = """#!/usr/bin/env python3
import json
import re
import sys

prompt = sys.stdin.read()
run_id = re.search(r"^Run ID: (.+)$", prompt, re.MULTILINE).group(1)
binding = re.search(r"^Prompt binding SHA256: ([a-f0-9]{64})$", prompt, re.MULTILINE).group(1)
print(json.dumps({
    "verdict": "GO",
    "findings": [],
    "reviewed_run_id": run_id,
    "prompt_sha256": binding,
}))
"""
            old_path = self._install_fake_worker(repo, "codex", worker_body)
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build high risk redteam", "--run-id", run_id, "--risk", "high"]), 0)
                for policy_path in (repo / ".sdlc" / "policies").glob("*.json"):
                    policy = read_json(policy_path)
                    policy["network_allowed"] = True
                    policy["worker_families"]["openai-codex-same"] = dict(policy["worker_families"]["openai-codex-primary"])
                    write_json(policy_path, policy)
                self.assertEqual(main([
                    "--repo", str(repo), "redteam", "execute", run_id,
                    "--workers", "openai-codex-primary,openai-codex-same",
                    "--execute", "--allow-network", "--rounds", "3", "--allow-no-go-exit-zero",
                ]), 0)
            finally:
                os.environ["PATH"] = old_path
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("distinct red-team model identities", gate.notes)
            summary = (RunStore(repo).run_dir(run_id) / "artifacts" / "redteam_execution_summary.md").read_text(encoding="utf-8")
            self.assertIn("executed_model_groups: openai:gpt-5.5", summary)

    def test_high_risk_redteam_enforces_minimum_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "redteam-min-rounds"
            old_path = self._install_fake_worker(repo, "codex", "#!/bin/sh\ncat >/dev/null\nprintf '{\"findings\": []}\\n'\n")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Build high risk min rounds", "--run-id", run_id, "--risk", "high"]), 0)
                self._allow_worker_network(repo)
                self.assertEqual(main(["--repo", str(repo), "redteam", "execute", run_id, "--workers", "codex", "--execute", "--allow-network", "--rounds", "1", "--allow-no-go-exit-zero"]), 0)
            finally:
                os.environ["PATH"] = old_path
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "independent_redteam_cross_model")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("at least 3 rounds", gate.notes)


class DeployGateTests(unittest.TestCase):
    def _approve_production(self, repo: Path, run_id: str, evidence: str = "approval.md", actor: str = "human_release_manager") -> int:
        key = "deploy-approval-secret"
        proof = deploy_approval_actor_proof(run_id, "production", actor, key, repo, [evidence])
        old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
        os.environ["SDLC_ACTOR_PROOF_KEY"] = key
        try:
            return main([
                "--repo", str(repo),
                "deploy", "approve", run_id,
                "--env", "production",
                "--actor", actor,
                "--evidence", evidence,
                "--actor-proof", proof,
            ])
        finally:
            if old_key is None:
                os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
            else:
                os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key

    def _satisfy_prior_release_gates(self, repo: Path, run_id: str, evidence_path: str = "evidence.md") -> None:
        store = RunStore(repo)
        ledger = Ledger(store.run_dir(run_id), run_id)
        redteam_summary = ledger.artifact(
            "artifacts/redteam_execution_summary.md",
            "\n".join([
                "# Red-Team Execution Summary",
                "",
                "execute_requested: True",
                "rounds: 3",
                "workers: codex, gemini",
                "available_families: codex, gemini",
                "executed_families: codex, gemini",
                "unavailable_workers: <none>",
                "worker_verdicts: codex:GO:round1, gemini:GO:round1, codex:GO:round2, gemini:GO:round2, codex:GO:round3, gemini:GO:round3",
                "mutation_violations: <none>",
                "parsed_findings: <none>",
                "verdict: GO",
                "",
                "Executed red-team evidence captured with no open blocking findings.",
            ]) + "\n",
            event="artifact.written",
        )
        for round_number in (1, 2, 3):
            ledger.event("worker.completed", worker="codex", mode=f"REDTEAM_ROUND_{round_number}", executed=True, available=True, returncode=0)
            ledger.event("worker.completed", worker="gemini", mode=f"REDTEAM_ROUND_{round_number}", executed=True, available=True, returncode=0)
        ledger.event(
            "redteam.execution_completed",
            verdict="GO",
            workers=["codex", "gemini"],
            rounds=3,
            execute_requested=True,
            available_families=["codex", "gemini"],
            executed_families=["codex", "gemini"],
            unavailable=[],
            parsed_findings=[],
            worker_verdicts=[
                {"worker": "codex", "round": "1", "verdict": "GO", "context_attested": True},
                {"worker": "gemini", "round": "1", "verdict": "GO", "context_attested": True},
                {"worker": "codex", "round": "2", "verdict": "GO", "context_attested": True},
                {"worker": "gemini", "round": "2", "verdict": "GO", "context_attested": True},
                {"worker": "codex", "round": "3", "verdict": "GO", "context_attested": True},
                {"worker": "gemini", "round": "3", "verdict": "GO", "context_attested": True},
            ],
            mutation_violations=[],
            evidence=[redteam_summary],
        )
        scan_summary = ledger.artifact(
            "artifacts/security_scan_summary.md",
            "Security scan summary\nVerdict: GO\nscanner: policy PASS\n",
            event="artifact.written",
        )
        ledger.event("security.scans_completed", verdict="GO", evidence=[scan_summary])
        implementation_diff = ledger.artifact(
            "artifacts/implementation_fixture.patch",
            "diff --git a/sdlc/example.py b/sdlc/example.py\n--- a/sdlc/example.py\n+++ b/sdlc/example.py\n@@ -0,0 +1 @@\n+# fixture diff\n",
            event="artifact.written",
        )
        run_evidence = lambda rel: f".sdlc/runs/{run_id}/{rel}"
        attestation_key = repo.parent / f"{repo.name}-attestation-key"
        attestation_key.write_text("test signing key\n", encoding="utf-8")

        for gate in sorted(store.load_plan(run_id).gates, key=lambda item: item.order):
            if gate.order >= 24 or gate.state == "SKIPPED":
                continue
            if gate.id == "security_scans":
                result = main(["--repo", str(repo), "gate", "complete", run_id, gate.id, "--verdict", "GO", "--actor", gate.owner, "--evidence", run_evidence(scan_summary)])
            elif gate.id == "independent_redteam_cross_model":
                result = main(["--repo", str(repo), "gate", "complete", run_id, gate.id, "--verdict", "GO", "--actor", gate.owner, "--evidence", run_evidence(redteam_summary)])
            elif gate.id == "critical_high_fix_loop":
                evidence = record_gate_evidence(repo, run_id, gate.id, gate.owner)
                result = main(["--repo", str(repo), "gate", "complete", run_id, gate.id, "--verdict", "GO", "--actor", gate.owner, "--evidence", evidence, run_evidence(redteam_summary)])
            elif gate.id == "implementation":
                evidence = record_gate_evidence(repo, run_id, gate.id, gate.owner)
                result = main(["--repo", str(repo), "gate", "complete", run_id, gate.id, "--verdict", "GO", "--actor", gate.owner, "--evidence", evidence, run_evidence(implementation_diff)])
            elif gate.id == "evidence_traceability_attestations":
                self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
                self.assertEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(attestation_key), "--execute"]), 0)
                result = main(["--repo", str(repo), "attest", "verify", run_id, "--key", str(attestation_key)])
            elif gate.id == "commit_branch_pr_ci":
                ensure_git_fixture(repo, run_id)
                (repo / "release-change.txt").write_text(f"release change for {run_id}\n", encoding="utf-8")
                self.assertEqual(run_cmd(["git", "add", "-A"], repo)["returncode"], 0)
                self.assertEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "feat: release fixture"]), 0)
                ledger.event("gate.manually_completed", gate="deterministic_quality", verdict="GO")
                ledger.event("gate.manually_completed", gate="qa_tests_integration_smoke", verdict="GO")
                ledger.event("security.scans_completed", verdict="GO", evidence=[scan_summary])
                ledger.event(
                    "redteam.execution_completed",
                    verdict="GO",
                    workers=["codex", "gemini"],
                    rounds=3,
                    execute_requested=True,
                    available_families=["codex", "gemini"],
                    executed_families=["codex", "gemini"],
                    unavailable=[],
                    parsed_findings=[],
                    worker_verdicts=[
                        {"worker": "codex", "round": "1", "verdict": "GO", "context_attested": True},
                        {"worker": "gemini", "round": "1", "verdict": "GO", "context_attested": True},
                        {"worker": "codex", "round": "2", "verdict": "GO", "context_attested": True},
                        {"worker": "gemini", "round": "2", "verdict": "GO", "context_attested": True},
                        {"worker": "codex", "round": "3", "verdict": "GO", "context_attested": True},
                        {"worker": "gemini", "round": "3", "verdict": "GO", "context_attested": True},
                    ],
                    mutation_violations=[],
                    evidence=[redteam_summary],
                )
                self.assertEqual(main(["--repo", str(repo), "git", "pr", run_id]), 0)
                result = main([
                    "--repo", str(repo), "gate", "complete", run_id, gate.id,
                    "--verdict", "GO",
                    "--actor", gate.owner,
                    "--evidence", f".sdlc/runs/{run_id}/artifacts/git/provenance.json",
                ])
            else:
                evidence = record_gate_evidence(repo, run_id, gate.id, gate.owner)
                result = main(["--repo", str(repo), "gate", "complete", run_id, gate.id, "--verdict", "GO", "--actor", gate.owner, "--evidence", evidence])
            if result != 0:
                raise AssertionError(f"failed to satisfy {gate.id}: {result}")
            if gate.id == "commit_branch_pr_ci":
                self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
                self.assertEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(attestation_key), "--execute"]), 0)
                self.assertEqual(main(["--repo", str(repo), "attest", "verify", run_id, "--key", str(attestation_key)]), 0)

    def test_production_deploy_plan_is_skipped_when_rollout_not_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-skipped"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Plan locked production deploy", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "plan", run_id, "--env", "production"]), 0)
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "SKIPPED")

    def test_production_execute_blocks_without_approval_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-blocked"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy production", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "production", "--execute"]), 0)
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("missing", gate.notes)

    def test_production_execute_requires_prior_release_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-prior-gates"
            approval = repo / "approval.md"
            approval.write_text("approved\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy production", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            rollback_command = f"{sys.executable} -c \"print('rollback ok')\""
            deploy_command = f"{sys.executable} -c \"print('deploy ok')\""
            self.assertEqual(main(["--repo", str(repo), "deploy", "plan", run_id, "--env", "production", "--rollback-command", rollback_command]), 0)
            self.assertEqual(self._approve_production(repo, run_id), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "production", "--execute", "--command", deploy_command]), 0)
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "production.json")
            self.assertIn("Canonical release-readiness validation", record["execution_rejection"])

    def test_production_execute_requires_rollback_command_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-rollback-plan"
            approval = repo / "approval.md"
            approval.write_text("approved\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy production", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self._satisfy_prior_release_gates(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "deploy", "plan", run_id, "--env", "production"]), 0)
            self.assertEqual(self._approve_production(repo, run_id), 0)
            deploy_command = f"{sys.executable} -c \"print('deploy ok')\""
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "production", "--execute", "--command", deploy_command]), 0)
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "production.json")
            self.assertIn("Rollback command", record["execution_rejection"])

    def test_deploy_approval_requires_human_release_actor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-approval"
            evidence = repo / "approval.md"
            evidence.write_text("approved by release manager\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy approval", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "approve", run_id, "--env", "production", "--actor", "agent_3_implementation_owner", "--evidence", "approval.md"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "approve", run_id, "--env", "production", "--actor", "human_release_manager", "--evidence", "approval.md"]), 0)
            self.assertEqual(self._approve_production(repo, run_id), 0)
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "production.json")
            self.assertEqual(record["approver"], "human_release_manager")
            self.assertIs(record["approval_actor_proof_verified"], True)

    def test_deploy_approval_proof_binds_evidence_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-approval-binding"
            evidence = repo / "approval.md"
            actor = "human_release_manager"
            key = "deploy-approval-secret"
            evidence.write_text("approved version one\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy approval binding", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            proof = deploy_approval_actor_proof(run_id, "production", actor, key, repo, ["approval.md"])
            evidence.write_text("approved version two\n", encoding="utf-8")
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "deploy", "approve", run_id,
                    "--env", "production",
                    "--actor", actor,
                    "--evidence", "approval.md",
                    "--actor-proof", proof,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            self.assertEqual(self._approve_production(repo, run_id), 0)

    def test_deploy_approval_rejects_absolute_evidence_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "approval.md"
            outside.write_text("outside approval\n", encoding="utf-8")
            run_id = "deploy-outside-evidence"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy approval", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "approve", run_id, "--env", "production", "--actor", "human_release_manager", "--evidence", str(outside)]), 0)

    def test_staging_execute_requires_real_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-command-required"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy staging", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "staging", "--execute"]), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "staging", "--execute", "--command", f"{sys.executable} -c \"print('staged')\""]), 0)
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "staging.json")
            self.assertEqual(record["execution_returncode"], 0)
            self.assertEqual(record["execution_stdout"], "staged\n")
            self.assertIn("execution_command", record)

    def test_full_rollout_evidence_can_record_accepted_residual_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-full"
            approval = repo / "approval.md"
            verify = repo / "verify.md"
            approval.write_text("approved\n", encoding="utf-8")
            verify.write_text("smoke and monitoring passed\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy full production", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            deploy_command = f"{sys.executable} -c \"print('deploy ok')\""
            rollback_command = f"{sys.executable} -c \"print('rollback ok')\""
            self._satisfy_prior_release_gates(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "deploy", "plan", run_id, "--env", "production", "--rollback-command", rollback_command]), 0)
            self.assertEqual(self._approve_production(repo, run_id), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "production", "--execute", "--command", deploy_command]), 0)
            key = "deploy-residual-secret"
            actor = "human_release_manager"
            proof = deploy_residual_actor_proof(run_id, "production", actor, key)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertEqual(main([
                    "--repo", str(repo), "deploy", "verify", run_id,
                    "--env", "production",
                    "--evidence", "verify.md",
                    "--accepted-residual-risk", "monitoring window is shortened",
                    "--actor", actor,
                    "--actor-proof", proof,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            self.assertEqual(main(["--repo", str(repo), "deploy", "rollback", run_id, "--env", "production", "--execute", "--command", rollback_command]), 0)
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "production.json")
            self.assertEqual(record["execution_returncode"], 0)
            self.assertEqual(record["rollback_returncode"], 0)
            self.assertEqual(record["accepted_residual_risks"][-1]["accepted_by"], actor)
            self.assertIs(record["accepted_residual_risks"][-1]["actor_proof_verified"], True)
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "GO_WITH_ACCEPTED_RESIDUAL_RISKS")

    def test_manual_deploy_gate_go_requires_deploy_record_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-manual-go"
            evidence = repo / "evidence.md"
            evidence.write_text("deploy evidence\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Manual deploy gate", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self._satisfy_prior_release_gates(repo, run_id)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deploy_rollout_postdeploy", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", "evidence.md"]), 0)

    def test_production_gate_rejects_dry_run_rollback_as_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-dry-rollback"
            approval = repo / "approval.md"
            verify = repo / "verify.md"
            rollback_proof = repo / "rollback-proof.md"
            approval.write_text("approved\n", encoding="utf-8")
            verify.write_text("smoke passed\n", encoding="utf-8")
            rollback_proof.write_text("staging rollback proof passed\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Dry rollback", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            deploy_command = f"{sys.executable} -c \"print('deploy ok')\""
            rollback_command = f"{sys.executable} -c \"print('rollback ok')\""
            self._satisfy_prior_release_gates(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "deploy", "plan", run_id, "--env", "production", "--rollback-command", rollback_command]), 0)
            self.assertEqual(self._approve_production(repo, run_id), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "execute", run_id, "--env", "production", "--execute", "--command", deploy_command]), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "verify", run_id, "--env", "production", "--evidence", "verify.md"]), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "rollback", run_id, "--env", "production", "--command", rollback_command]), 0)
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("rollback validation evidence", gate.notes)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deploy_rollout_postdeploy", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", f".sdlc/runs/{run_id}/artifacts/deploy/production.json"]), 0)
            self.assertEqual(main(["--repo", str(repo), "deploy", "rollback", run_id, "--env", "production", "--command", rollback_command, "--evidence", "rollback-proof.md"]), 0)
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "NO_GO")
            self.assertIn("accepted residual risk", gate.notes)
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deploy_rollout_postdeploy", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", f".sdlc/runs/{run_id}/artifacts/deploy/production.json"]), 0)
            self.assertNotEqual(main([
                "--repo", str(repo), "deploy", "verify", run_id,
                "--env", "production",
                "--evidence", "verify.md",
                "--accepted-residual-risk", "accepted residual risk reason: rollback was validated by non-destructive staging proof",
            ]), 0)
            key = "deploy-residual-secret"
            actor = "human_security_owner"
            proof = deploy_residual_actor_proof(run_id, "production", actor, key)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertEqual(main([
                    "--repo", str(repo), "deploy", "verify", run_id,
                    "--env", "production",
                    "--evidence", "verify.md",
                    "--accepted-residual-risk", "accepted residual risk reason: rollback was validated by non-destructive staging proof",
                    "--actor", actor,
                    "--actor-proof", proof,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            gate = next(item for item in RunStore(repo).load_plan(run_id).gates if item.id == "deploy_rollout_postdeploy")
            self.assertEqual(gate.verdict, "GO_WITH_ACCEPTED_RESIDUAL_RISKS")

    def test_deploy_residual_risk_acceptance_requires_human_actor_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-risk-proof"
            verify = repo / "verify.md"
            verify.write_text("smoke passed\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy residual proof", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self.assertNotEqual(main([
                "--repo", str(repo), "deploy", "verify", run_id,
                "--env", "production",
                "--evidence", "verify.md",
                "--accepted-residual-risk", "accepted residual risk reason: operator review",
            ]), 0)
            key = "deploy-residual-secret"
            actor = "human_release_manager"
            proof = deploy_residual_actor_proof(run_id, "production", actor, key)
            old_key = os.environ.get("SDLC_ACTOR_PROOF_KEY")
            os.environ["SDLC_ACTOR_PROOF_KEY"] = key
            try:
                self.assertNotEqual(main([
                    "--repo", str(repo), "deploy", "verify", run_id,
                    "--env", "production",
                    "--evidence", "verify.md",
                    "--accepted-residual-risk", "accepted residual risk reason: operator review",
                    "--actor", "agent_3_implementation_owner",
                    "--actor-proof", proof,
                ]), 0)
                self.assertEqual(main([
                    "--repo", str(repo), "deploy", "verify", run_id,
                    "--env", "production",
                    "--evidence", "verify.md",
                    "--accepted-residual-risk", "accepted residual risk reason: operator review",
                    "--actor", actor,
                    "--actor-proof", proof,
                ]), 0)
            finally:
                if old_key is None:
                    os.environ.pop("SDLC_ACTOR_PROOF_KEY", None)
                else:
                    os.environ["SDLC_ACTOR_PROOF_KEY"] = old_key
            record = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "deploy" / "production.json")
            self.assertEqual(record["accepted_residual_risks"][-1]["accepted_by"], actor)
            self.assertIs(record["accepted_residual_risks"][-1]["actor_proof_verified"], True)

    def test_production_gate_rejects_fabricated_record_without_ledger_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "deploy-forged-record"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Deploy forged record", "--run-id", run_id, "--production-rollout-allowed"]), 0)
            self._satisfy_prior_release_gates(repo, run_id)
            store = RunStore(repo)
            record_path = store.run_dir(run_id) / "artifacts" / "deploy" / "production.json"
            write_json(record_path, {
                "planned_at": "2026-01-01T00:00:00+00:00",
                "rollback_command": "echo rollback",
                "approved_at": "2026-01-01T00:00:00+00:00",
                "approver": "human_release_manager",
                "approval_evidence": ["evidence.md"],
                "executed_at": "2026-01-01T00:00:00+00:00",
                "execution_returncode": 0,
                "verification_evidence": ["evidence.md"],
                "rollback_status": "EXECUTED",
                "rollback_returncode": 0,
            })
            self.assertNotEqual(main(["--repo", str(repo), "gate", "complete", run_id, "deploy_rollout_postdeploy", "--verdict", "GO", "--actor", "agent_6_redteam_deploy_rollback", "--evidence", f".sdlc/runs/{run_id}/artifacts/deploy/production.json"]), 0)


class AttestationTests(unittest.TestCase):
    def _external_key(self, repo: Path) -> Path:
        return repo.parent / f"{repo.name}-attestation-key"

    def test_final_report_attestation_event_rejects_later_no_go_verification(self) -> None:
        self.assertIsNone(_final_report_attestation_event_error([{
            "event": "attestation.verified",
            "verdict": "GO",
            "evidence": ["artifacts/attestations/verification.json"],
        }]))
        self.assertIn("failed attestation", _final_report_attestation_event_error([{
            "event": "attestation.verified",
            "verdict": "NO_GO",
            "evidence": ["artifacts/attestations/verification.json"],
        }]) or "")
        self.assertIn("requires ledger-backed", _final_report_attestation_event_error([]) or "")

    def test_final_report_gate_rejects_forged_verification_json_without_artifact_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "forged-verification"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Forged verification", "--run-id", run_id]), 0)
            store = RunStore(repo)
            run_dir = store.run_dir(run_id)
            ledger = Ledger(run_dir, run_id)
            readiness = {
                "schema_version": 1,
                "run_id": run_id,
                "release_satisfied": True,
                "release_verdict": "GO",
                "blockers": [],
                "gate_readiness": [],
            }
            readiness_text = json.dumps(readiness, indent=2, sort_keys=True) + "\n"
            ledger.artifact(
                "artifacts/release/readiness.json",
                readiness_text,
                event="release.readiness_evaluated",
                release_satisfied=True,
                blockers=0,
            )
            report_text = build_report(repo, run_id)
            ledger.artifact("final-report.md", report_text, event="report.generated", verdict="NO_GO")
            snapshot_dir = run_dir / "artifacts" / "attestations" / "control-snapshots"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            (snapshot_dir / "final-report.md").write_text(report_text, encoding="utf-8")
            (snapshot_dir / "release-readiness.json").write_text(readiness_text, encoding="utf-8")
            manifest_path = run_dir / "artifacts" / "attestations" / "manifest.json"
            manifest = {
                "manifest_version": 1,
                "artifacts": [
                    {
                        "path": "artifacts/attestations/control-snapshots/final-report.md",
                        "sha256": hashlib.sha256(report_text.encode("utf-8")).hexdigest(),
                        "size": len(report_text.encode("utf-8")),
                    },
                    {
                        "path": "artifacts/attestations/control-snapshots/release-readiness.json",
                        "sha256": hashlib.sha256(readiness_text.encode("utf-8")).hexdigest(),
                        "size": len(readiness_text.encode("utf-8")),
                    },
                ],
            }
            manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            manifest_path.write_text(manifest_text, encoding="utf-8")
            (run_dir / "artifacts" / "attestations" / "manifest.signature.json").write_text(json.dumps({
                "algorithm": "HMAC-SHA256",
                "manifest_path": "artifacts/attestations/manifest.json",
                "manifest_sha256": hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
                "signature": "forged",
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            (run_dir / "artifacts" / "attestations" / "verification.json").write_text(json.dumps({
                "status": "GO",
                "verified": True,
                "artifact_integrity_verified": True,
                "release_gate_blockers": [],
                "failures": [],
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            ledger.event("attestation.verified", verdict="GO", failures=[], evidence=["artifacts/attestations/verification.json"])
            plan = store.load_plan(run_id)
            gate = next(gate for gate in plan.gates if gate.id == "final_report_reaudit")
            gate.state = "GO"
            gate.verdict = "GO"
            gate.evidence = [f".sdlc/runs/{run_id}/final-report.md"]
            error = _validate_final_report_gate_completion(store, run_id, gate, "GO", gate.evidence)
            self.assertIn("attestation.verification_artifact", error or "")

    def test_manifest_generation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-manifest"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Create manifest", "--run-id", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "report", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
            manifest_path = RunStore(repo).run_dir(run_id) / "artifacts" / "attestations" / "manifest.json"
            first = manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(first)
            manifest_paths = {item["path"] for item in manifest["artifacts"]}
            self.assertIn("artifacts/attestations/control-snapshots/plan.json", manifest_paths)
            self.assertIn("artifacts/attestations/control-snapshots/findings.json", manifest_paths)
            self.assertIn("artifacts/attestations/control-snapshots/events.jsonl", manifest_paths)
            self.assertIn("artifacts/attestations/control-snapshots/final-report.md", manifest_paths)
            self.assertIn("artifacts/attestations/control-snapshots/release-readiness.json", manifest_paths)
            time.sleep(1.1)
            self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
            second = manifest_path.read_text(encoding="utf-8")
            self.assertEqual(first, second)

    def test_manifest_rejects_symlinked_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-symlink"
            outside_file = Path(tmp) / "outside.txt"
            outside_dir = Path(tmp) / "outside-dir"
            outside_file.write_text("outside secret\n", encoding="utf-8")
            outside_dir.mkdir()
            (outside_dir / "nested.txt").write_text("outside nested\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject symlink", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            link = run_dir / "artifacts" / "leak.txt"
            dir_link = run_dir / "artifacts" / "leak-dir"
            try:
                link.symlink_to(outside_file)
                dir_link.symlink_to(outside_dir, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            self.assertNotEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
            manifest_path = run_dir / "artifacts" / "attestations" / "manifest.json"
            if manifest_path.exists():
                manifest = read_json(manifest_path, {})
                manifest_paths = {item.get("path") for item in manifest.get("artifacts", []) if isinstance(item, dict)}
                self.assertNotIn("artifacts/leak.txt", manifest_paths)
                self.assertNotIn("artifacts/leak-dir/nested.txt", manifest_paths)

    def test_manifest_rejects_hardlinked_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            outside = Path(tmp) / "outside.txt"
            run_id = "attest-hardlink"
            outside.write_text("outside linked artifact\n", encoding="utf-8")
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Reject hardlink", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            hardlink = run_dir / "artifacts" / "hardlinked.txt"
            hardlink.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(outside, hardlink)
            except OSError as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            self.assertGreater(hardlink.stat().st_nlink, 1)
            self.assertNotEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
            manifest = {
                "manifest_version": 1,
                "artifacts": [{
                    "path": "artifacts/hardlinked.txt",
                    "sha256": hashlib.sha256(hardlink.read_bytes()).hexdigest(),
                    "size": hardlink.stat().st_size,
                }],
            }
            failures = _verify_manifest_entries(run_dir, manifest)
            self.assertTrue(any("multiple hard links" in item for item in failures), failures)

    def test_signing_requires_existing_key_when_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-missing-key"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Missing key", "--run-id", run_id]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(repo / "missing.key"), "--execute"]), 0)

    def test_attestation_key_must_be_outside_repo_and_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-key-boundary"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Repo key", "--run-id", run_id]), 0)
            repo_key = repo / "signing.key"
            repo_key.write_text("repo-local signing key\n", encoding="utf-8")
            run_key = RunStore(repo).run_dir(run_id) / "artifacts" / "signing.key"
            run_key.parent.mkdir(parents=True, exist_ok=True)
            run_key.write_text("run-local signing key\n", encoding="utf-8")
            self.assertNotEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(repo_key), "--execute"]), 0)
            self.assertNotEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(run_key), "--execute"]), 0)

    def test_attestation_gate_requires_signature_and_release_blocker_free_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-gate-strict"
            self.assertEqual(main(["--repo", str(repo), "init"]), 0)
            self.assertEqual(main(["--repo", str(repo), "plan", "Strict attestation", "--run-id", run_id]), 0)
            run_dir = RunStore(repo).run_dir(run_id)
            manifest = run_dir / "artifacts" / "attestations" / "manifest.json"
            verification = run_dir / "artifacts" / "attestations" / "verification.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(json.dumps({"manifest_version": 1, "artifacts": []}), encoding="utf-8")
            verification.write_text(json.dumps({
                "status": "GO",
                "verified": True,
                "artifact_integrity_verified": True,
                "release_gate_blockers": [],
            }), encoding="utf-8")
            self.assertNotEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "evidence_traceability_attestations",
                "--verdict", "GO",
                "--actor", "agent_4_evidence_reporting_owner",
                "--evidence", "artifacts/attestations/manifest.json", "artifacts/attestations/verification.json",
            ]), 0)

    def test_sign_verify_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "attest-verify"
            key = self._external_key(repo)
            key.write_text("local signing key\n", encoding="utf-8")
            try:
                self.assertEqual(main(["--repo", str(repo), "init"]), 0)
                self.assertEqual(main(["--repo", str(repo), "plan", "Verify manifest", "--run-id", run_id]), 0)
                store = RunStore(repo)
                evidence = repo / "attestation-prereq.md"
                evidence.write_text("attestation prerequisites satisfied\n", encoding="utf-8")
                plan = store.load_plan(run_id)
                attestation_gate = next(gate for gate in plan.gates if gate.id == "evidence_traceability_attestations")
                for gate in plan.gates:
                    if gate.order < attestation_gate.order and gate.state != "SKIPPED":
                        gate.state = "GO"
                        gate.verdict = "GO"
                        gate.evidence = ["attestation-prereq.md"]
                store.save_plan(plan)
                self.assertEqual(main(["--repo", str(repo), "attest", "manifest", run_id]), 0)
                self.assertEqual(main(["--repo", str(repo), "attest", "sign", run_id, "--key", str(key), "--execute"]), 0)
                self.assertEqual(main(["--repo", str(repo), "attest", "verify", run_id, "--key", str(key)]), 0)
                snapshot = RunStore(repo).run_dir(run_id) / "artifacts" / "attestations" / "control-snapshots" / "plan.json"
                snapshot.write_text(snapshot.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")
                self.assertNotEqual(main(["--repo", str(repo), "attest", "verify", run_id, "--key", str(key)]), 0)
            finally:
                if key.exists():
                    key.unlink()


@unittest.skipUnless(shutil.which("git"), "git is required for git integration tests")
class GitIntegrationTests(unittest.TestCase):
    def _init_git_repo(self, repo: Path, run_id: str = "git-run") -> RunStore:
        self.assertEqual(main(["--repo", str(repo), "init"]), 0)
        self.assertEqual(run_cmd(["git", "init", "-b", "main"], repo)["returncode"], 0)
        self.assertEqual(run_cmd(["git", "config", "user.email", "sdlc@example.test"], repo)["returncode"], 0)
        self.assertEqual(run_cmd(["git", "config", "user.name", "SDLC Test"], repo)["returncode"], 0)
        (repo / "README.md").write_text("initial\n", encoding="utf-8")
        self.assertEqual(run_cmd(["git", "add", "README.md"], repo)["returncode"], 0)
        self.assertEqual(run_cmd(["git", "commit", "-m", "chore: initial"], repo)["returncode"], 0)
        self.assertEqual(main(["--repo", str(repo), "plan", "Add git integration", "--run-id", run_id]), 0)
        return RunStore(repo)

    def _satisfy_commit_gates(self, repo: Path, run_id: str) -> None:
        evidence = repo / "release-evidence.md"
        evidence.write_text("release gates satisfied for git helper test\n", encoding="utf-8")
        store = RunStore(repo)
        plan = store.load_plan(run_id)
        for gate in plan.gates:
            if gate.order > 22 or gate.state == "SKIPPED":
                continue
            gate.state = "GO"
            gate.verdict = "GO"
            gate.evidence = ["release-evidence.md"]
        store.save_plan(plan)

    def test_git_branch_creates_feature_branch_and_updates_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-branch"
            store = self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self.assertEqual(git_current_branch(repo), "sdlc/git-branch")
            self.assertEqual(store.load_plan(run_id).branch, "sdlc/git-branch")
            self.assertTrue((RunStore(repo).run_dir(run_id) / "artifacts" / "git" / "provenance.json").exists())

    def test_git_provenance_command_records_machine_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-provenance"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "git", "provenance", run_id]), 0)
            payload = read_json(RunStore(repo).run_dir(run_id) / "artifacts" / "git" / "provenance.json")
            self.assertEqual(payload["commands"]["current_branch"]["command"], ["git", "branch", "--show-current"])
            self.assertEqual(payload["branch"]["current"], "sdlc/git-provenance")
            events = [json.loads(line) for line in (RunStore(repo).run_dir(run_id) / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertIn("git.provenance_artifact", {event["event"] for event in events})

    def test_commit_branch_gate_requires_git_provenance_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-provenance-required"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            evidence = repo / "ordinary.md"
            evidence.write_text("ordinary commit branch evidence\n", encoding="utf-8")
            plan = RunStore(repo).load_plan(run_id)
            gate = next(item for item in plan.gates if item.id == "commit_branch_pr_ci")
            gate.state = "READY"
            gate.verdict = None
            RunStore(repo).save_plan(plan)
            self.assertNotEqual(main([
                "--repo", str(repo), "gate", "complete", run_id, "commit_branch_pr_ci",
                "--verdict", "GO",
                "--actor", "agent_1_pm_coordinator",
                "--evidence", "ordinary.md",
            ]), 0)

    def test_git_provenance_rejects_dirty_working_tree_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-dirty-provenance"
            store = self._init_git_repo(repo, run_id)
            plan = store.load_plan(run_id)
            plan.branch = "sdlc/git-dirty-provenance"
            dirty_lines = [
                " M sdlc/cli.py",
                "M  tests/test_core.py",
                " D README.md",
                "?? scratch.txt",
            ]
            for dirty_line in dirty_lines:
                with self.subTest(dirty_line=dirty_line):
                    payload = git_provenance_payload(plan, repo)
                    status = f"## {plan.branch}\n{dirty_line}\n"
                    payload["working_tree"]["status_short"] = status
                    payload["working_tree"]["clean"] = False
                    payload["commands"]["status_short"]["stdout"] = status
                    error = _validate_git_provenance_payload(plan, payload)
                    self.assertIsNotNone(error)
                    self.assertIn("clean working tree", error or "")

    def test_git_commit_requires_feature_branch_and_clean_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-commit"
            self._init_git_repo(repo, run_id)
            (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "add", "feature.txt"], repo)["returncode"], 0)
            self.assertNotEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "feat: add feature"]), 0)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self._satisfy_commit_gates(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "feat: add feature"]), 0)
            log = run_cmd(["git", "log", "-1", "--pretty=%s"], repo)
            self.assertEqual(log["stdout"].strip(), "feat: add feature")

    def test_git_commit_blocks_unresolved_release_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-gates"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            (repo / "gates.txt").write_text("gates\n", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "add", "gates.txt"], repo)["returncode"], 0)
            self.assertNotEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "feat: gated"]), 0)

    def test_git_commit_blocks_open_critical_high_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-blocked"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self.assertEqual(main(["--repo", str(repo), "redteam", run_id]), 0)
            (repo / "blocked.txt").write_text("blocked\n", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "add", "blocked.txt"], repo)["returncode"], 0)
            self.assertNotEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "feat: blocked"]), 0)

    def test_git_commit_requires_message_discipline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-message"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            (repo / "message.txt").write_text("message\n", encoding="utf-8")
            self.assertEqual(run_cmd(["git", "add", "message.txt"], repo)["returncode"], 0)
            self._satisfy_commit_gates(repo, run_id)
            self.assertNotEqual(main(["--repo", str(repo), "git", "commit", run_id, "--message", "bad message"]), 0)

    def test_git_pr_is_dry_run_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-pr"
            store = self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self._satisfy_commit_gates(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "pr", run_id, "--title", "feat: add git integration"]), 0)
            run_dir = store.run_dir(run_id)
            plan = (run_dir / "artifacts" / "git_pr_plan.md").read_text(encoding="utf-8")
            self.assertIn("gh pr create", plan)
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertIn("git.pr_planned", {event["event"] for event in events})

    def test_git_pr_execute_requires_policy_network_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_id = "git-pr-execute"
            self._init_git_repo(repo, run_id)
            self.assertEqual(main(["--repo", str(repo), "git", "branch", run_id]), 0)
            self._satisfy_commit_gates(repo, run_id)
            self.assertNotEqual(main(["--repo", str(repo), "git", "pr", run_id, "--execute", "--allow-network"]), 0)
            policy = read_json(repo / ".sdlc" / "policies" / "default.json")
            self.assertFalse(policy["network_allowed"])
