#!/usr/bin/env bash
set -euo pipefail
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m sdlc init
"$PYTHON" -m sdlc plan "Build RBAC dashboard" --run-id smoke-rbac
"$PYTHON" -m sdlc validate --run-id smoke-rbac
"$PYTHON" -m sdlc run smoke-rbac --redteam
"$PYTHON" -m sdlc report smoke-rbac --print >/tmp/sdlc-smoke-report.md
cat /tmp/sdlc-smoke-report.md
