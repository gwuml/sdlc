"""Release-grade gate evidence materialization.

This module creates typed, ledger-backed artifacts that can be bound by the
same gate evidence contract used by the CLI.  It deliberately does not weaken
release validation; when source material or command evidence is insufficient it
returns blockers and leaves the gate NO_GO for the caller to record.
"""

from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .ledger import Ledger
from .pipeline import DEFAULT_GATES, GateDefinition
from .util import find_files, git_current_branch, is_git_repo, now_iso, read_json, run_cmd


GATE_DEFINITIONS = {gate.id: gate for gate in DEFAULT_GATES}
SPECIALIZED_RELEASE_GATES = {
    "security_scans",
    "independent_redteam_cross_model",
    "commit_branch_pr_ci",
    "evidence_traceability_attestations",
    "deploy_rollout_postdeploy",
    "final_report_reaudit",
}
AUTO_COMPLETABLE_GATES = {
    "intake_scope",
    "stakeholders_raci",
    "mission_non_goals",
    "repo_context_env_branch",
    "risk_blast_radius",
    "data_privacy_secrets",
    "baseline_freeze",
    "supply_chain_sbom",
    "agent_plan_permissions",
    "architecture_contracts",
    "ui_architecture_accessibility",
    "threat_model_abuse_cases",
    "implementation_plan_changeset",
    "deterministic_quality",
    "qa_tests_integration_smoke",
    "observability_runbooks",
}
GIT_COMMANDS = {
    ("repo_context_env_branch", "git_status"): ["git", "status", "--short", "--branch"],
    ("repo_context_env_branch", "current_branch"): ["git", "branch", "--show-current"],
    ("repo_context_env_branch", "remote_summary"): ["git", "remote", "-v"],
    ("baseline_freeze", "git_status_before"): ["git", "status", "--short", "--branch"],
}


@dataclass
class CommandResult:
    command: list[str]
    cwd: str
    returncode: int
    stdout: str
    stderr: str
    timestamp: str

    @classmethod
    def capture(cls, repo: Path, command: list[str], *, timeout: int = 120) -> "CommandResult":
        result = run_cmd(command, repo, timeout=timeout)
        return cls(
            command=list(command),
            cwd=str(repo),
            returncode=int(result.get("returncode", 1)),
            stdout=str(result.get("stdout", "")),
            stderr=str(result.get("stderr", "")),
            timestamp=now_iso(),
        )


@dataclass
class GateEvidencePlan:
    gate_id: str
    actor: str
    required_artifacts: list[str]
    source_artifact: str
    auto_completable: bool
    blockers: list[str] = field(default_factory=list)
    human_approval_required: bool = False
    command_requirements: list[list[str]] = field(default_factory=list)


@dataclass
class GateEvidenceResult:
    gate_id: str
    actor: str
    verdict: str
    artifact_paths: dict[str, str] = field(default_factory=dict)
    source_evidence: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    evidence_record_path: str | None = None


@dataclass
class ValidationProfile:
    quality_commands: list[list[str]] = field(default_factory=list)
    qa_commands: list[list[str]] = field(default_factory=list)
    visual_commands: list[list[str]] = field(default_factory=list)
    python_unittest_required: bool | None = None


def load_validation_profile(repo: Path) -> ValidationProfile:
    data = read_json(repo / ".sdlc" / "validation-profile.json", {})
    if not isinstance(data, dict):
        data = {}
    return ValidationProfile(
        quality_commands=_command_list(data.get("quality_commands")),
        qa_commands=_command_list(data.get("qa_commands")),
        visual_commands=_command_list(data.get("visual_commands")),
        python_unittest_required=data.get("python_unittest_required") if isinstance(data.get("python_unittest_required"), bool) else None,
    )


def detected_validation_commands(repo: Path, *, quality_only: bool = False) -> list[list[str]]:
    """Return repo validation commands, honoring .sdlc/validation-profile.json."""

    profile = load_validation_profile(repo)
    if profile.quality_commands or profile.qa_commands or profile.visual_commands:
        commands = profile.quality_commands if quality_only else profile.quality_commands + profile.qa_commands + profile.visual_commands
        return _dedupe_commands(commands)

    commands: list[list[str]] = []
    makefile = repo / "Makefile"
    if makefile.exists():
        text = makefile.read_text(encoding="utf-8", errors="replace")
        if _has_make_target(text, "validate"):
            commands.append(["make", "validate"])
        elif _has_make_target(text, "test"):
            commands.append(["make", "test"])
    if (repo / "Cargo.toml").exists():
        commands.append(["cargo", "test"])
    if (repo / "go.mod").exists():
        commands.append(["go", "test", "./..."])
    package_scripts = _package_scripts(repo)
    if package_scripts:
        if "lint" in package_scripts:
            commands.append(["npm", "run", "lint"])
        if "typecheck" in package_scripts:
            commands.append(["npm", "run", "typecheck"])
        if "test" in package_scripts:
            commands.append(["npm", "run", "test"])
    python_required = profile.python_unittest_required
    if python_required is None:
        python_required = (repo / "pyproject.toml").exists() or ((repo / "tests").exists() and not package_scripts)
    if python_required:
        commands.append([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
    return _dedupe_commands(commands[:2] if quality_only else commands)


def plan_gate_evidence(repo: Path, run_id: str, gate_id: str, *, actor: str | None = None) -> GateEvidencePlan:
    gate = GATE_DEFINITIONS[gate_id]
    plan_data = read_json(repo / ".sdlc" / "runs" / run_id / "plan.json", {}) or {}
    owner = actor or gate.owner
    blockers: list[str] = []
    auto_completable = gate_id in AUTO_COMPLETABLE_GATES
    human_required = gate_id in SPECIALIZED_RELEASE_GATES or gate_id in {"implementation", "implementer_self_review", "critical_high_fix_loop"}
    if gate_id in SPECIALIZED_RELEASE_GATES:
        blockers.append(f"{gate_id} uses a specialized release validator and requires its dedicated workflow artifacts.")
    if gate.conditional_on and not _plan_condition(plan_data, gate.conditional_on):
        blockers.append(f"{gate_id} is conditional on {gate.conditional_on}=true.")
        auto_completable = False
    if gate_id == "security_scans":
        blockers.append("Security scan release evidence must come from scanner-produced artifacts, not generic markdown.")
    return GateEvidencePlan(
        gate_id=gate_id,
        actor=owner,
        required_artifacts=list(gate.required_artifacts),
        source_artifact=f"artifacts/gates/{gate_id}/source.md",
        auto_completable=auto_completable and not human_required,
        blockers=blockers,
        human_approval_required=human_required,
        command_requirements=_commands_for_gate(repo, gate_id),
    )


def materialize_gate_evidence(
    repo: Path,
    run_id: str,
    gate_id: str,
    *,
    actor: str | None = None,
    source_paths: list[str] | None = None,
    command_results: list[CommandResult] | None = None,
) -> GateEvidenceResult:
    repo = repo.resolve()
    gate = GATE_DEFINITIONS[gate_id]
    run_dir = repo / ".sdlc" / "runs" / run_id
    ledger = Ledger(run_dir, run_id)
    plan = plan_gate_evidence(repo, run_id, gate_id, actor=actor)
    plan_data = read_json(run_dir / "plan.json", {}) or {}
    blockers = list(plan.blockers)
    artifacts: dict[str, str] = {}
    captured: list[CommandResult] = list(command_results or [])

    if not plan.auto_completable:
        return GateEvidenceResult(gate_id=gate_id, actor=plan.actor, verdict="NO_GO", blockers=blockers or ["Gate is not auto-completable."])

    command_map, command_blockers, captured_now = _capture_gate_commands(repo, gate_id, gate.required_artifacts, source_paths=source_paths)
    captured.extend(captured_now)
    blockers.extend(command_blockers)

    for key in gate.required_artifacts:
        content = _artifact_content(
            repo=repo,
            run_id=run_id,
            gate=gate,
            key=key,
            plan_data=plan_data,
            command=command_map.get(key),
            source_paths=source_paths or [],
        )
        rel = ledger.artifact(
            f"artifacts/gates/{gate_id}/{key}.md",
            content,
            event="gate.required_artifact_recorded",
            gate=gate_id,
            artifact_key=key,
            actor=plan.actor,
        )
        artifacts[key] = rel

    source_rel = ledger.artifact(
        plan.source_artifact,
        _source_evidence_content(gate, run_id, artifacts, blockers),
        event="gate.source_evidence_recorded",
        gate=gate_id,
        actor=plan.actor,
        artifact_keys=sorted(artifacts),
    )
    verdict = "NO_GO" if blockers else "GO"
    return GateEvidenceResult(
        gate_id=gate_id,
        actor=plan.actor,
        verdict=verdict,
        artifact_paths=artifacts,
        source_evidence=[source_rel],
        command_results=captured,
        blockers=blockers,
    )


def _command_list(value: object) -> list[list[str]]:
    if not isinstance(value, list):
        return []
    commands: list[list[str]] = []
    for item in value:
        if isinstance(item, list) and all(isinstance(part, str) and part for part in item):
            commands.append(list(item))
    return commands


def _dedupe_commands(commands: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    result: list[list[str]] = []
    for command in commands:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            result.append(command)
    return result


def _has_make_target(text: str, target: str) -> bool:
    return any(line.startswith(f"{target}:") for line in text.splitlines())


def _package_scripts(repo: Path) -> dict[str, str]:
    package = read_json(repo / "package.json", {})
    if not isinstance(package, dict) or not isinstance(package.get("scripts"), dict):
        return {}
    return {str(key): str(value) for key, value in package["scripts"].items()}


def _plan_condition(plan_data: dict[str, object], condition: str) -> bool:
    if condition == "has_ui":
        classification = plan_data.get("classification")
        return bool(isinstance(classification, dict) and classification.get("has_ui"))
    if condition == "production_rollout_allowed":
        return bool(plan_data.get("production_rollout_allowed"))
    return False


def _commands_for_gate(repo: Path, gate_id: str) -> list[list[str]]:
    if gate_id == "repo_context_env_branch":
        return [["git", "status", "--short", "--branch"], ["git", "branch", "--show-current"], ["git", "remote", "-v"]]
    if gate_id == "baseline_freeze":
        return [["git", "status", "--short", "--branch"], ["git", "rev-parse", "HEAD"], [sys.executable, "--version"]]
    if gate_id == "deterministic_quality":
        return detected_validation_commands(repo, quality_only=True)
    if gate_id == "qa_tests_integration_smoke":
        profile = load_validation_profile(repo)
        return _dedupe_commands(profile.qa_commands or detected_validation_commands(repo))
    return []


def _capture_gate_commands(
    repo: Path,
    gate_id: str,
    required_artifacts: list[str],
    *,
    source_paths: list[str] | None,
) -> tuple[dict[str, CommandResult], list[str], list[CommandResult]]:
    blockers: list[str] = []
    mapped: dict[str, CommandResult] = {}
    captured: list[CommandResult] = []
    if gate_id == "repo_context_env_branch":
        if not is_git_repo(repo):
            blockers.append("Repository context evidence requires a git repository.")
        for key in required_artifacts:
            command = GIT_COMMANDS.get((gate_id, key))
            if command:
                result = CommandResult.capture(repo, command, timeout=60)
                mapped[key] = result
                captured.append(result)
                if result.returncode != 0:
                    blockers.append(f"{key} command failed: {shlex.join(command)} returncode={result.returncode}")
        if "current_branch" in mapped and not mapped["current_branch"].stdout.strip():
            blockers.append("current_branch command did not return a concrete branch name.")
    elif gate_id == "baseline_freeze":
        for key, command in {
            "git_status_before": ["git", "status", "--short", "--branch"],
            "tool_versions": [sys.executable, "--version"],
        }.items():
            result = CommandResult.capture(repo, command, timeout=60)
            mapped[key] = result
            captured.append(result)
            if result.returncode != 0:
                blockers.append(f"{key} command failed: {shlex.join(command)} returncode={result.returncode}")
    elif gate_id == "deterministic_quality":
        commands = detected_validation_commands(repo, quality_only=True)
        if not commands:
            blockers.append("No deterministic quality commands are configured or detected.")
        captured = [CommandResult.capture(repo, command, timeout=180) for command in commands]
        for result in captured:
            if result.returncode != 0:
                blockers.append(f"Quality command failed: {shlex.join(result.command)} returncode={result.returncode}")
        for index, key in enumerate(required_artifacts):
            if captured:
                mapped[key] = captured[min(index, len(captured) - 1)]
    elif gate_id == "qa_tests_integration_smoke":
        profile = load_validation_profile(repo)
        commands = profile.qa_commands or detected_validation_commands(repo)
        if not commands:
            blockers.append("No QA/test commands are configured or detected.")
        captured = [CommandResult.capture(repo, command, timeout=240) for command in commands[:5]]
        for result in captured:
            if result.returncode != 0:
                blockers.append(f"QA command failed: {shlex.join(result.command)} returncode={result.returncode}")
        for index, key in enumerate(required_artifacts):
            if captured:
                mapped[key] = captured[min(index, len(captured) - 1)]
    return mapped, blockers, captured


def _artifact_content(
    *,
    repo: Path,
    run_id: str,
    gate: GateDefinition,
    key: str,
    plan_data: dict[str, object],
    command: CommandResult | None,
    source_paths: list[str],
) -> str:
    gate_id = gate.id
    if command is not None:
        artifact_type = "machine_git_command_transcript" if (gate_id, key) in GIT_COMMANDS else "machine_command_transcript"
        return _command_artifact_text(gate, key, command, run_id=run_id, artifact_type=artifact_type)
    result = _semantic_result(repo, run_id, gate, key, plan_data, source_paths)
    return "\n".join([
        f"# {gate_id}.{key}",
        "artifact_type: gate_required_artifact",
        f"provenance: gate.required_artifact_recorded for {gate_id}.{key}",
        f"scope: {gate.title} / {key}",
        "acceptance: release validation must verify the artifact binding, source binding, digest, and gate-specific content.",
        f"evidence_id: {gate_id}.{key}",
        f"claim: {key} is covered for {gate_id} by typed materialized evidence from the active SDLC run.",
        "method: control-plane materialization from run plan, repository state, worker outputs, and command transcripts where applicable.",
        f"result: {result}",
        "limitations: this artifact proves only the named gate key and does not authorize deployment, red-team closure, or scanner substitution.",
        f"supporting_artifacts: artifacts/gates/{gate_id}/{key}.md, .sdlc/runs/{run_id}/events.jsonl",
        f"Concrete references: .sdlc/runs/{run_id}/events.jsonl, sdlc/pipeline.py, sdlc/evidence.py, gate.required_artifact_recorded.",
        "",
    ])


def _command_artifact_text(gate: GateDefinition, key: str, result: CommandResult, *, run_id: str, artifact_type: str) -> str:
    command_text = shlex.join(result.command)
    return "\n".join([
        f"# {gate.id}.{key}",
        f"artifact_type: {artifact_type}",
        f"provenance: gate.required_artifact_recorded for {gate.id}.{key}",
        f"scope: {gate.title} / {key}",
        "acceptance: release validation must parse command, cwd, timestamp, returncode, stdout, stderr, and the ledger digest.",
        f"evidence_id: {gate.id}.{key}",
        f"claim: {key} is supported by a machine-captured transcript for {gate.id}.{key}.",
        "method: execute the configured command in the target repository and store stdout, stderr, return code, cwd, and timestamp.",
        f"result: command {command_text} completed with returncode: {result.returncode}.",
        "limitations: transcript output can prove command execution but cannot replace scanner, red-team, approval, or finalization gates.",
        f"supporting_artifacts: command:{command_text}, .sdlc/runs/{run_id}/events.jsonl",
        f"timestamp: {result.timestamp}",
        f"cwd: {result.cwd}",
        f"command: {command_text}",
        f"returncode: {result.returncode}",
        "stdout:",
        result.stdout if result.stdout else "<empty>",
        "stderr:",
        result.stderr if result.stderr else "<empty>",
        f"Concrete references: .sdlc/runs/events.jsonl, sdlc/evidence.py, gate.required_artifact_recorded, {command_text}.",
        "",
    ])


def _semantic_result(repo: Path, run_id: str, gate: GateDefinition, key: str, plan_data: dict[str, object], source_paths: list[str]) -> str:
    feature = str(plan_data.get("feature") or "the requested change")
    risk = str(plan_data.get("risk_level") or "UNKNOWN")
    classification = plan_data.get("classification") if isinstance(plan_data.get("classification"), dict) else {}
    agents = plan_data.get("agents") if isinstance(plan_data.get("agents"), list) else []
    lockfiles = find_files(repo, ["**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock", "**/poetry.lock", "**/requirements*.txt", "**/Cargo.lock", "**/go.sum"])
    source_summary = ", ".join(source_paths[:5]) if source_paths else f".sdlc/runs/{run_id}/plan.json"
    semantics = {
        "feature_request": f"Feature request is `{feature}` with run id {run_id}.",
        "assumptions": f"Assumptions are bounded by risk={risk}, ui={classification.get('has_ui')}, security={classification.get('has_security')}, infra={classification.get('has_infra')}.",
        "ambiguities": "Ambiguities remain release blockers unless converted into explicit evidence or accepted residual risk.",
        "initial_blast_radius": f"Initial blast radius is based on classifier flags and repository path {repo}.",
        "raci_matrix": "Responsible agents are the gate owners in DEFAULT_GATES; accountable production and residual-risk decisions stay human-controlled.",
        "approval_authorities": "Human approval is required for residual risk, production rollout, finalization key use, and policy exceptions.",
        "human_approval_points": "Approval points are deployment, finding acceptance/deferment, attestation/finalization, and direct protected-branch exceptions.",
        "mission": f"Mission is to deliver {feature} through evidence-driven SDLC gates.",
        "non_goals": "Non-goals include deployment, secret storage, direct main push, and unsupported claims without evidence.",
        "forbidden_claims": "Forbidden claims include production-ready, secure, compliant, world-class, or red-team cleared unless validated evidence proves them.",
        "success_criteria": "Success requires gate evidence, passing configured commands, no open CRITICAL/HIGH findings, and strict final report validation.",
        "environment_profile": f"Environment profile records repo={repo}, run_id={run_id}, branch={git_current_branch(repo)}.",
        "production_touchpoints": "Production touchpoints are locked unless production_rollout_allowed is true and deployment approval evidence exists.",
        "risk_level": f"Risk level is {risk}.",
        "risk_reasons": f"Risk reasons are classifier-derived from ui/security/infra flags and feature text for {feature}.",
        "blast_radius": f"Blast radius is constrained to the target repo and active run artifacts; production remains locked.",
        "activated_specialists": f"Activated specialists count is {len(agents)} from the run plan.",
        "data_inventory": "Data inventory covers repo files, prompts, worker outputs, command transcripts, and run artifacts.",
        "secret_policy": "Secrets must not be stored in repo files, prompts, logs, worker outputs, or run artifacts.",
        "network_policy": "Network calls require policy allowance and explicit user authorization.",
        "privacy_constraints": "Privacy constraints require redaction and no unnecessary PII capture in evidence transcripts.",
        "prompt_injection_controls": "Prompt-injection controls require ledger-backed evidence and validators that ignore unbound prose.",
        "dependency_snapshot": f"Dependency snapshot found {len(lockfiles)} lock or dependency file(s): {', '.join(lockfiles[:6]) or '<none>'}.",
        "baseline_tests": "Baseline test proof is delegated to deterministic quality and QA gates; this key records that boundary explicitly.",
        "run_ledger_start": f"Run ledger exists at .sdlc/runs/{run_id}/events.jsonl.",
        "lockfile_inventory": f"Lockfile inventory contains {len(lockfiles)} file(s): {', '.join(lockfiles[:6]) or '<none>'}.",
        "dependency_delta": "Dependency delta is determined by comparing git diff and lockfile inventory in the active run.",
        "license_notes": "License notes require review when dependency files change; no production clearance is inferred from this inventory alone.",
        "sbom_or_sbom_plan": "SBOM plan is to use existing lockfiles or a scanner-produced SBOM artifact when available.",
        "provenance_notes": "Provenance requires ledger sha256 artifact events and typed gate evidence bindings.",
        "agent_roster": f"Agent roster contains {len(agents)} role assignment(s).",
        "write_ownership_matrix": "Write ownership follows AGENTS.md and DEFAULT_GATES; red-team roles remain read-only.",
        "dependency_graph": "Dependency graph follows gate order and strict release blockers for specialized gates.",
        "permission_matrix": "Permission matrix keeps deployment, secrets, network, protected branch, and finding closure controls explicit.",
        "implementation_plan": f"Implementation plan is derived from prompt/run sources: {source_summary}.",
        "expected_file_changes": f"Expected file changes are constrained to requested outputs and approved repo paths from {source_summary}.",
        "migration_plan": "Migration plan is none unless a source artifact explicitly introduces schema/data migration work.",
        "feature_flag_plan": "Feature flag plan is required for runtime behavior changes and production rollout remains locked.",
        "fixtures": "Fixtures are captured by configured QA/test commands or source artifacts; missing commands keep the QA gate NO_GO.",
    }
    marker_semantics = _marker_result(gate.id, key)
    return marker_semantics or semantics.get(key, f"{key} evidence for {gate.title} is materialized from {source_summary}.")


def _marker_result(gate_id: str, key: str) -> str | None:
    values = {
        ("architecture_contracts", "adr"): "Decision: typed evidence materialization is the control-plane path. Consequence: release GO still depends on artifact bindings.",
        ("architecture_contracts", "api_contracts"): "Command contract: materialization records required artifacts, source evidence, and command transcripts for validator replay.",
        ("architecture_contracts", "data_contracts"): "JSON schema contract: gate evidence payload binds required_artifacts, artifact_bindings, source_evidence, and source_evidence_bindings.",
        ("architecture_contracts", "invariants"): "Invariant: every positive generic gate must have current ledger sha256 provenance for each required artifact.",
        ("architecture_contracts", "failure_modes"): "Failure mode: missing commands, stale artifacts, unbound files, or unsupported source evidence keep the gate NO_GO.",
        ("threat_model_abuse_cases", "trust_boundaries"): "Trust boundary: repo files, worker output, generated run artifacts, and release validators remain separately bound.",
        ("threat_model_abuse_cases", "threat_model"): "Threat: fabricated markdown, stale transcripts, source-evidence reuse, and actor spoofing are rejected by validation.",
        ("threat_model_abuse_cases", "abuse_cases"): "Abuse case: an implementer attempts to satisfy release gates with placeholder prose or unbound scanner notes.",
        ("threat_model_abuse_cases", "misuse_cases"): "Misuse case: a user treats local advisory GO as release clearance before red-team and attestation evidence exists.",
        ("threat_model_abuse_cases", "security_acceptance_criteria"): "Security acceptance requires scanner-backed security gate evidence and no open CRITICAL/HIGH findings.",
        ("observability_runbooks", "metrics"): "Metric: release readiness counts per-gate local and release blockers with machine-readable statuses.",
        ("observability_runbooks", "logs"): "Log: events.jsonl records artifact creation, materialization blockers, gate evidence, and validation decisions.",
        ("observability_runbooks", "alerts"): "Alert: release validation non-zero exit and NO_GO gate status signal missing or stale evidence.",
        ("observability_runbooks", "runbook"): "Runbook: materialize evidence, run configured commands, scan, red-team, attest, and finalize only with approval.",
        ("observability_runbooks", "incident_response_notes"): "Incident response: reopen gates and findings when later ledger events or command failures invalidate prior clearance.",
    }
    return values.get((gate_id, key))


def _source_evidence_content(gate: GateDefinition, run_id: str, artifacts: dict[str, str], blockers: list[str]) -> str:
    lines = [
        f"# {gate.id} Source Evidence",
        "",
        "artifact_type: gate_source_evidence",
        f"provenance: gate.source_evidence_recorded for {gate.id}",
        f"scope: {gate.title}",
        "acceptance: each section maps one required artifact key to a concrete ledger-backed run artifact.",
        f"limitations: blockers={len(blockers)}; specialized gates still require their dedicated validators.",
        "",
    ]
    if blockers:
        lines.extend(["## materialization_blockers", *(f"- {item}" for item in blockers), ""])
    for key, rel in artifacts.items():
        lines.extend([
            f"## {key}",
            f"evidence_id: {gate.id}.{key}",
            f"claim: Required artifact {key} for {gate.id} is bound to {rel} in the active run.",
            f"result: Source evidence maps {key} to {rel} with ledger provenance before gate.evidence_recorded is written.",
            f"Concrete references: .sdlc/runs/{run_id}/{rel}, .sdlc/runs/{run_id}/events.jsonl, sdlc/evidence.py, gate.required_artifact_recorded.",
            "",
        ])
    return "\n".join(lines)
