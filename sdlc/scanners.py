"""Security scanner orchestration and evidence capture."""

from __future__ import annotations

import shlex
import shutil
import sys
import json
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .util import find_files, redact_secrets, run_cmd, sha256_text


PASS_STATUSES = {"PASS", "PASS_WITH_FINDINGS", "NOT_APPLICABLE"}
BLOCKING_STATUSES = {"FAIL", "UNAVAILABLE", "BLOCKED_BY_POLICY"}
EXCLUDED_DIRS = {".git", ".sdlc", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", "target", "data", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EXCLUDE_FILES_RE = r"(^|/)(\.git|\.sdlc|\.venv|venv|__pycache__|node_modules|dist|build|target|data|\.pytest_cache|\.mypy_cache|\.ruff_cache)(/|$)|(^|/)docs/reports/.*\.(csv|json)$"


@dataclass
class ScanResult:
    scanner: str
    category: str
    status: str
    command: list[str]
    returncode: int | None
    artifact: str
    summary: str
    blocking: bool = False
    severity_counts: dict[str, int] = field(default_factory=dict)
    confidence_counts: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    manifest_bindings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_security_scans(
    *,
    repo: Path,
    run_dir: Path,
    run_id: str,
    policy: dict[str, Any],
    risk_level: str = "MEDIUM",
    allow_network: bool = False,
) -> tuple[list[ScanResult], list[str]]:
    ledger = Ledger(run_dir, run_id)
    scanner_results: list[ScanResult] = []
    scanner_results.append(_run_bandit(repo, run_dir, ledger, policy=policy, risk_level=risk_level))
    scanner_results.append(_run_detect_secrets(repo, run_dir, ledger))
    scanner_results.append(_run_pip_audit(repo, run_dir, ledger, policy=policy, network_allowed=allow_network and bool(policy.get("network_allowed", False))))
    scanner_results.append(_run_checkov(repo, run_dir, ledger))
    scanner_results.append(_run_policy_check(repo, run_dir, ledger, policy))
    summary_path = _write_summary(run_dir, ledger, scanner_results)
    summary_text = (run_dir / summary_path).read_text(encoding="utf-8")
    verdict = scan_verdict(scanner_results)
    artifacts = [result.artifact for result in scanner_results]
    artifacts.append(summary_path)
    ledger.event(
        "security.scans_completed",
        verdict=verdict,
        statuses={result.scanner: result.status for result in scanner_results},
        blocking_scanners=[result.scanner for result in scanner_results if result.blocking],
        summary_artifact=summary_path,
        summary_sha256=sha256_text(summary_text),
        evidence=artifacts,
    )
    return scanner_results, artifacts


def scan_verdict(results: list[ScanResult]) -> str:
    return "NO_GO" if any(result.blocking for result in results) else "GO"


def scan_notes(results: list[ScanResult]) -> str:
    failing = [f"{result.scanner}={result.status}" for result in results if result.blocking]
    if failing:
        return "Security scan issues require review: " + ", ".join(failing)
    return "Security scanner evidence captured with no blocking scanner status."


def _run_bandit(repo: Path, run_dir: Path, ledger: Ledger, *, policy: dict[str, Any], risk_level: str) -> ScanResult:
    if not _has_files(repo, ["**/*.py"]):
        return _not_applicable(run_dir, ledger, "bandit", "sast", "No Python files found")
    command = _tool_command("bandit", ["-r", str(repo), "-f", "json", "-x", ",".join(sorted(EXCLUDED_DIRS))])
    return _run_scanner(repo, run_dir, ledger, "bandit", "sast", command, normalizer=lambda result: _normalize_bandit(repo, result, policy, risk_level))


def _run_detect_secrets(repo: Path, run_dir: Path, ledger: Ledger) -> ScanResult:
    command = _tool_command("detect-secrets", ["scan", "--all-files", "--exclude-files", EXCLUDE_FILES_RE, "--exclude-lines", r'"[A-Za-z0-9_]*sha256"\s*:'])
    return _run_scanner(repo, run_dir, ledger, "detect-secrets", "secrets", command, timeout=300, normalizer=lambda result: _normalize_detect_secrets(repo, result))


def _run_pip_audit(repo: Path, run_dir: Path, ledger: Ledger, *, policy: dict[str, Any], network_allowed: bool) -> ScanResult:
    manifest_bindings = _dependency_manifest_bindings(repo)
    if not manifest_bindings:
        return _not_applicable(run_dir, ledger, "pip-audit", "dependency", "No Python dependency manifest found")
    if (repo / "pyproject.toml").is_file():
        command = _tool_command("pip-audit", ["--format", "json", str(repo)])
    else:
        requirements = [binding["path"] for binding in manifest_bindings if Path(binding["path"]).name.startswith("requirements")]
        args = ["--format", "json"]
        for requirement in requirements:
            args.extend(["-r", str(repo / requirement)])
        command = _tool_command("pip-audit", args)
    if not network_allowed:
        required = bool(policy.get("scanner_thresholds", {}).get("dependency_audit_required", True))
        return _blocked(
            run_dir,
            ledger,
            "pip-audit",
            "dependency",
            command,
            "Dependency vulnerability audit requires network_allowed=true and --allow-network",
            blocking=required,
            manifest_bindings=manifest_bindings,
        )
    return _run_scanner(repo, run_dir, ledger, "pip-audit", "dependency", command, timeout=180, normalizer=lambda result: _normalize_pip_audit(result, policy), manifest_bindings=manifest_bindings)


def _run_checkov(repo: Path, run_dir: Path, ledger: Ledger) -> ScanResult:
    if not _has_files(repo, ["**/*.tf", "**/*.tfvars", "**/Chart.yaml", "**/kustomization.yaml", "**/*.yaml", "**/*.yml"]):
        return _not_applicable(run_dir, ledger, "checkov", "iac", "No IaC files found")
    command = _tool_command("checkov", [
        "-d",
        str(repo),
        "-o",
        "json",
        "--quiet",
        "--skip-path",
        str(repo / ".venv"),
        "--skip-path",
        str(repo / ".sdlc"),
        "--skip-path",
        str(repo / ".git"),
    ])
    return _run_scanner(repo, run_dir, ledger, "checkov", "iac", command, required=True, timeout=180)


def _run_policy_check(repo: Path, run_dir: Path, ledger: Ledger, policy: dict[str, Any]) -> ScanResult:
    lines = [
        "policy: " + str(policy.get("name", "default")),
        f"direct_main_push_allowed: {policy.get('direct_main_push_allowed', False)}",
        f"production_rollout_allowed: {policy.get('production_rollout_allowed', False)}",
        f"network_allowed: {policy.get('network_allowed', False)}",
        "protected_operations:",
    ]
    lines.extend(f"- {item}" for item in policy.get("protected_operations", []))
    env_files = find_files(repo, [".env", ".env.*", "**/.env", "**/.env.*"])
    lines.append("env_files_detected:")
    lines.extend(f"- {item}" for item in env_files or ["<none>"])
    status = "FAIL" if env_files else "PASS"
    summary = "Environment files detected" if env_files else "No repo env files detected by policy check"
    return _write_result(run_dir, ledger, "policy", "policy", status, [], None, "\n".join(lines) + "\n", summary)


def _run_scanner(
    repo: Path,
    run_dir: Path,
    ledger: Ledger,
    scanner: str,
    category: str,
    command: list[str],
    *,
    required: bool = True,
    timeout: int = 120,
    normalizer: Any | None = None,
    manifest_bindings: list[dict[str, str]] | None = None,
) -> ScanResult:
    if not command or not _command_available(command[0]):
        status = "UNAVAILABLE" if required else "UNAVAILABLE"
        tool = command[0] if command else scanner
        return _write_result(
            run_dir,
            ledger,
            scanner,
            category,
            status,
            command,
            None,
            f"Scanner unavailable: {tool}\n",
            f"Scanner unavailable: {tool}",
            blocking=required,
            manifest_bindings=manifest_bindings,
        )
    result = run_cmd(command, repo, timeout=timeout)
    content = "\n".join([
        f"$ {shlex.join(command)}",
        f"returncode: {result['returncode']}",
        "",
        "stdout:",
        str(result["stdout"] or "<empty>"),
        "",
        "stderr:",
        str(result["stderr"] or "<empty>"),
        "",
    ])
    normalized = normalizer(result) if normalizer else {}
    status = str(normalized.get("status") or ("PASS" if result["returncode"] == 0 else "FAIL"))
    blocking = bool(normalized.get("blocking", status in BLOCKING_STATUSES))
    summary = str(normalized.get("summary") or f"returncode={result['returncode']}")
    return _write_result(
        run_dir,
        ledger,
        scanner,
        category,
        status,
        command,
        int(result["returncode"]),
        content,
        summary,
        blocking=blocking,
        severity_counts=normalized.get("severity_counts", {}),
        confidence_counts=normalized.get("confidence_counts", {}),
        findings=normalized.get("findings", []),
        manifest_bindings=manifest_bindings or [],
    )


def _normalize_bandit(repo: Path, result: dict[str, Any], policy: dict[str, Any], risk_level: str) -> dict[str, Any]:
    try:
        payload = json.loads(str(result.get("stdout") or "{}"))
    except json.JSONDecodeError:
        return {
            "status": "FAIL" if result.get("returncode") else "PASS",
            "blocking": bool(result.get("returncode")),
            "summary": "Bandit JSON output could not be parsed",
        }

    raw_findings = payload.get("results") if isinstance(payload, dict) else []
    if not isinstance(raw_findings, list):
        raw_findings = []

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNDEFINED": 0}
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNDEFINED": 0}
    findings: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("issue_severity") or "UNDEFINED").upper()
        confidence = str(item.get("issue_confidence") or "UNDEFINED").upper()
        severity_counts[severity if severity in severity_counts else "UNDEFINED"] += 1
        confidence_counts[confidence if confidence in confidence_counts else "UNDEFINED"] += 1
        filename = _repo_relative(repo, str(item.get("filename") or ""))
        findings.append({
            "test_id": item.get("test_id"),
            "severity": severity,
            "confidence": confidence,
            "filename": filename,
            "line_number": item.get("line_number"),
            "issue_text": item.get("issue_text"),
        })

    blocked_severities = _blocking_severities(policy, risk_level)
    blocking_findings = [item for item in findings if item["severity"] in blocked_severities]
    residual_findings = [item for item in findings if item["severity"] not in blocked_severities]
    if blocking_findings:
        status = "FAIL"
    elif findings:
        status = "PASS_WITH_FINDINGS"
    elif result.get("returncode") in {0, None}:
        status = "PASS"
    else:
        status = "FAIL"
    blocking = bool(blocking_findings or (status == "FAIL" and not findings))
    counts = ", ".join(f"{key}={value}" for key, value in severity_counts.items() if value)
    summary = (
        f"returncode={result.get('returncode')}; "
        f"severity_counts={counts or 'none'}; "
        f"blocking_severities={','.join(sorted(blocked_severities))}; "
        f"blocking_findings={len(blocking_findings)}; residual_findings={len(residual_findings)}"
    )
    return {
        "status": status,
        "blocking": blocking,
        "summary": summary,
        "severity_counts": severity_counts,
        "confidence_counts": confidence_counts,
        "findings": findings,
    }


def _normalize_detect_secrets(repo: Path, result: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(str(result.get("stdout") or "{}"))
    except json.JSONDecodeError:
        return {
            "status": "FAIL" if result.get("returncode") else "PASS",
            "blocking": bool(result.get("returncode")),
            "summary": "detect-secrets JSON output could not be parsed",
        }
    raw_results = payload.get("results") if isinstance(payload, dict) else {}
    findings: list[dict[str, Any]] = []
    if isinstance(raw_results, dict):
        for filename, items in raw_results.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                findings.append({
                    "filename": _repo_relative(repo, str(filename)),
                    "line_number": item.get("line_number"),
                    "type": item.get("type"),
                    "hashed_secret": item.get("hashed_secret"),
                })
    if findings:
        return {
            "status": "FAIL",
            "blocking": True,
            "summary": f"secret_findings={len(findings)}",
            "severity_counts": {"HIGH": len(findings)},
            "findings": findings,
        }
    if result.get("returncode") not in {0, None}:
        return {
            "status": "FAIL",
            "blocking": True,
            "summary": f"returncode={result.get('returncode')}; no parseable finding details",
        }
    return {
        "status": "PASS",
        "blocking": False,
        "summary": "secret_findings=0",
        "findings": [],
    }


def _normalize_pip_audit(result: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(str(result.get("stdout") or "{}"))
    except json.JSONDecodeError:
        return {
            "status": "FAIL" if result.get("returncode") else "PASS",
            "blocking": bool(result.get("returncode")),
            "summary": "pip-audit JSON output could not be parsed",
        }
    ignores = policy.get("scanner_ignored_vulnerabilities", [])
    findings: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for dependency in payload.get("dependencies", []) if isinstance(payload, dict) else []:
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name") or "")
        version = str(dependency.get("version") or "")
        for vuln in dependency.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            finding = {
                "package": name,
                "version": version,
                "id": vuln.get("id"),
                "aliases": vuln.get("aliases", []),
                "fix_versions": vuln.get("fix_versions", []),
                "description": vuln.get("description"),
            }
            if _pip_audit_finding_ignored(finding, ignores):
                ignored.append(finding)
            else:
                findings.append(finding)
    if findings:
        return {
            "status": "FAIL",
            "blocking": True,
            "summary": f"vulnerabilities={len(findings)}; ignored={len(ignored)}",
            "severity_counts": {"HIGH": len(findings)},
            "findings": findings,
        }
    if ignored:
        return {
            "status": "PASS_WITH_FINDINGS",
            "blocking": False,
            "summary": f"ignored_vulnerabilities={len(ignored)}; policy={policy.get('name', 'default')}",
            "severity_counts": {"LOW": len(ignored)},
            "findings": ignored,
        }
    if result.get("returncode") not in {0, None}:
        return {
            "status": "FAIL",
            "blocking": True,
            "summary": f"returncode={result.get('returncode')}; no parseable vulnerability details",
        }
    return {"status": "PASS", "blocking": False, "summary": "vulnerabilities=0", "findings": []}


def _pip_audit_finding_ignored(finding: dict[str, Any], ignores: Any) -> bool:
    if not isinstance(ignores, list):
        return False
    vuln_ids = {str(finding.get("id") or "")}
    vuln_ids.update(str(item) for item in finding.get("aliases", []) or [])
    for item in ignores:
        if not isinstance(item, dict):
            continue
        if item.get("scanner") not in {None, "pip-audit"}:
            continue
        if item.get("package") and str(item["package"]).lower() != str(finding.get("package") or "").lower():
            continue
        ignored_ids = {str(item.get("id") or "")}
        ignored_ids.update(str(alias) for alias in item.get("aliases", []) or [])
        if vuln_ids.isdisjoint(ignored_ids):
            continue
        if not item.get("reason"):
            continue
        return True
    return False


def _blocking_severities(policy: dict[str, Any], risk_level: str) -> set[str]:
    thresholds = policy.get("scanner_thresholds", {})
    severities = {str(item).upper() for item in thresholds.get("block_severities", ["CRITICAL", "HIGH"])}
    high_risk = risk_level.upper() in {"HIGH", "EXTREME"}
    if thresholds.get("block_medium", False) or (high_risk and thresholds.get("block_medium_for_high_risk", True)):
        severities.add("MEDIUM")
    if thresholds.get("block_low", False):
        severities.add("LOW")
    return severities


def _repo_relative(repo: Path, filename: str) -> str:
    if not filename:
        return ""
    path = Path(filename)
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except (OSError, ValueError):
        return filename


def _tool_command(executable: str, args: list[str]) -> list[str]:
    found = shutil.which(executable)
    if found:
        return [found, *args]
    venv_tool = Path(sys.executable).parent / executable
    if venv_tool.exists():
        return [str(venv_tool), *args]
    return [executable, *args]


def _command_available(command_name: str) -> bool:
    path = Path(command_name)
    if path.is_absolute() or path.parent != Path("."):
        return path.exists()
    return shutil.which(command_name) is not None


def _blocked(
    run_dir: Path,
    ledger: Ledger,
    scanner: str,
    category: str,
    command: list[str],
    reason: str,
    *,
    blocking: bool = True,
    manifest_bindings: list[dict[str, str]] | None = None,
) -> ScanResult:
    summary = reason if blocking else f"{reason}; recorded as non-blocking by policy"
    return _write_result(run_dir, ledger, scanner, category, "BLOCKED_BY_POLICY", command, None, reason + "\n", summary, blocking=blocking, manifest_bindings=manifest_bindings)


def _not_applicable(run_dir: Path, ledger: Ledger, scanner: str, category: str, reason: str) -> ScanResult:
    return _write_result(run_dir, ledger, scanner, category, "NOT_APPLICABLE", [], None, reason + "\n", reason)


def _write_result(
    run_dir: Path,
    ledger: Ledger,
    scanner: str,
    category: str,
    status: str,
    command: list[str],
    returncode: int | None,
    content: str,
    summary: str,
    *,
    blocking: bool | None = None,
    severity_counts: dict[str, int] | None = None,
    confidence_counts: dict[str, int] | None = None,
    findings: list[dict[str, Any]] | None = None,
    manifest_bindings: list[dict[str, str]] | None = None,
) -> ScanResult:
    artifact = f"artifacts/scans/{scanner}.txt"
    safe_content = redact_secrets(content)
    blocks_gate = status in BLOCKING_STATUSES if blocking is None else blocking
    severity_counts = severity_counts or {}
    confidence_counts = confidence_counts or {}
    findings = findings or []
    manifest_bindings = manifest_bindings or []
    ledger.artifact(
        artifact,
        safe_content,
        event="security.scan_artifact",
        scanner=scanner,
        category=category,
        status=status,
        blocking=blocks_gate,
        severity_counts=severity_counts,
        manifest_bindings=manifest_bindings,
    )
    ledger.event(
        "security.scan_result",
        scanner=scanner,
        category=category,
        status=status,
        blocking=blocks_gate,
        returncode=returncode,
        artifact=artifact,
        severity_counts=severity_counts,
        manifest_bindings=manifest_bindings,
    )
    return ScanResult(
        scanner=scanner,
        category=category,
        status=status,
        command=command,
        returncode=returncode,
        artifact=artifact,
        summary=summary,
        blocking=blocks_gate,
        severity_counts=severity_counts,
        confidence_counts=confidence_counts,
        findings=findings,
        manifest_bindings=manifest_bindings,
    )


def _write_summary(run_dir: Path, ledger: Ledger, results: list[ScanResult]) -> str:
    lines = [
        "# Security Scan Summary",
        "",
        "| Scanner | Category | Status | Blocks Gate | Artifact | Summary |",
        "|---|---|---|---:|---|---|",
    ]
    for result in results:
        manifest_note = ""
        if result.manifest_bindings:
            manifest_note = "; manifests=" + ",".join(f"{item['path']}@{item['sha256']}" for item in result.manifest_bindings)
        lines.append(f"| {result.scanner} | {result.category} | {result.status} | {str(result.blocking).lower()} | {result.artifact} | {result.summary}{manifest_note} |")
        if result.findings:
            counts = ", ".join(f"{severity}={count}" for severity, count in sorted(result.severity_counts.items()) if count)
            lines.append(f"| {result.scanner} normalized | findings | {counts or 'none'} | {str(result.blocking).lower()} | {result.artifact} | parsed_findings={len(result.findings)} |")
    lines.append("")
    lines.append(f"Verdict: {scan_verdict(results)}")
    return ledger.artifact("artifacts/security_scan_summary.md", "\n".join(lines) + "\n", event="security.scan_summary", verdict=scan_verdict(results))


def _has_files(repo: Path, patterns: list[str]) -> bool:
    for pattern in patterns:
        for path in repo.glob(pattern):
            if path.is_file() and not any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
                return True
    return False


def _dependency_manifest_bindings(repo: Path) -> list[dict[str, str]]:
    candidates = [repo / "pyproject.toml"]
    candidates.extend(sorted(repo.glob("requirements*.txt")))
    bindings: list[dict[str, str]] = []
    for path in candidates:
        if not path.is_file():
            continue
        rel = str(path.relative_to(repo))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        bindings.append({"path": rel, "sha256": digest})
    return bindings
