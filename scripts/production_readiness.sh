#!/usr/bin/env bash
set -euo pipefail

PYTHON="${PYTHON:-python3}"
RUN_ID="${RUN_ID:-production-grade-release-blockers}"
FEATURE="${FEATURE:-Production readiness validation}"
CREATE_RUN=0
EXECUTE_REDTEAM=0
ALLOW_NETWORK=0
ATTEST_KEY="${ATTEST_KEY:-}"
REDTEAM_WORKERS="${REDTEAM_WORKERS:-openai-codex-primary,openai-codex-adversary}"
REDTEAM_ROUNDS="${REDTEAM_ROUNDS:-3}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/production_readiness.sh [options]

Options:
  --run-id <id>             Run id to validate. Default: production-grade-release-blockers
  --fresh                   Create a fresh run before validation.
  --feature <text>          Feature text for --fresh. Default: Production readiness validation
  --execute-redteam         Execute configured red-team workers. Requires available workers.
  --allow-network           Allow networked scanner/worker operations where policy permits.
  --attest-key <path>       External attestation key path outside the repo and .sdlc/runs.
  --redteam-workers <csv>   Workers for red-team execute. Default: openai-codex-primary,openai-codex-adversary
  --redteam-rounds <n>      Red-team rounds. Default: 3
  -h, --help                Show this help.

Environment equivalents:
  PYTHON, RUN_ID, FEATURE, ATTEST_KEY, REDTEAM_WORKERS, REDTEAM_ROUNDS

This script does not deploy, restart production, push to origin/main, or mark gates GO.
It runs the evidence workflow and reports the authoritative readiness verdict.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --fresh)
      CREATE_RUN=1
      shift
      ;;
    --feature)
      FEATURE="$2"
      shift 2
      ;;
    --execute-redteam)
      EXECUTE_REDTEAM=1
      shift
      ;;
    --allow-network)
      ALLOW_NETWORK=1
      shift
      ;;
    --attest-key)
      ATTEST_KEY="$2"
      shift 2
      ;;
    --redteam-workers)
      REDTEAM_WORKERS="$2"
      shift 2
      ;;
    --redteam-rounds)
      REDTEAM_ROUNDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

step() {
  printf '\n==> %s\n' "$*"
}

run_allow_fail() {
  set +e
  "$@"
  local status=$?
  set -e
  return "$status"
}

step "Baseline git state"
git status --short --branch || true

step "Repository structural validation"
"$PYTHON" -m sdlc validate

if [[ "$CREATE_RUN" -eq 1 ]]; then
  step "Create fresh run: $RUN_ID"
  "$PYTHON" -m sdlc plan "$FEATURE" \
    --run-id "$RUN_ID" \
    --risk auto \
    --ui auto \
    --security auto \
    --infra auto
fi

step "Unit tests"
"$PYTHON" -m unittest discover -s tests

step "Local run status"
"$PYTHON" -m sdlc status "$RUN_ID"

step "Security scans"
SCAN_ARGS=(scan "$RUN_ID")
if [[ "$ALLOW_NETWORK" -eq 1 ]]; then
  SCAN_ARGS+=(--allow-network)
fi
run_allow_fail "$PYTHON" -m sdlc "${SCAN_ARGS[@]}" || true

step "Deterministic run advancement"
run_allow_fail "$PYTHON" -m sdlc run "$RUN_ID" --redteam || true

if [[ "$EXECUTE_REDTEAM" -eq 1 ]]; then
  step "Executed red-team"
  REDTEAM_ARGS=(redteam execute "$RUN_ID" --workers "$REDTEAM_WORKERS" --rounds "$REDTEAM_ROUNDS" --execute --fail-on-findings)
  if [[ "$ALLOW_NETWORK" -eq 1 ]]; then
    REDTEAM_ARGS+=(--allow-network)
  fi
  run_allow_fail "$PYTHON" -m sdlc "${REDTEAM_ARGS[@]}" || true
else
  step "Executed red-team skipped"
  echo "Pass --execute-redteam to run worker-backed red-team evidence."
fi

step "Release validation"
if "$PYTHON" -m sdlc validate --run-id "$RUN_ID" --release; then
  RELEASE_STATUS=0
else
  RELEASE_STATUS=$?
fi

step "Attestations"
if [[ -n "$ATTEST_KEY" ]]; then
  "$PYTHON" -m sdlc attest manifest "$RUN_ID" || true
  "$PYTHON" -m sdlc attest sign "$RUN_ID" --key "$ATTEST_KEY" --execute || true
  "$PYTHON" -m sdlc attest verify "$RUN_ID" --key "$ATTEST_KEY" || true
else
  echo "Attestation signing skipped. Provide --attest-key <external-key-path>."
fi

step "Final report"
"$PYTHON" -m sdlc report "$RUN_ID" --print

step "Final release validation"
if "$PYTHON" -m sdlc validate --run-id "$RUN_ID" --release; then
  echo "GO: release validation passed for $RUN_ID"
  exit 0
else
  echo "NO_GO: release validation still has blockers for $RUN_ID" >&2
  exit "${RELEASE_STATUS:-1}"
fi
