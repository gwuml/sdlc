#!/usr/bin/env bash
# Capture real transcripts for each documented feature into one file.
# Run from the repo root:  bash scripts/capture_usage.sh > /tmp/usage_transcript.txt 2>&1
# Uses the project venv and a throwaway git repo. Worker/redteam/deploy use safe
# dry/plan modes (no live LLM calls, no real deploys). The release-signature example
# runs against the real v0.2.0 release.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
SDLC() { "$PY" -m sdlc --repo "$REPO" "$@"; }

REPO="$(mktemp -d)"
cd "$REPO"
git init -q && git config user.email demo@example.test && git config user.name demo
printf 'print("hello")\n' > app.py && git add app.py && git commit -qm "seed"

hdr() { printf '\n\n========== %s ==========\n' "$*"; }
cmd() { printf '$ %s\n' "$*"; }

hdr "1. init"
cmd "sdlc init"; SDLC init

hdr "2. plan (risk auto-classified)"
cmd "sdlc plan 'add OAuth login with audit logging' --risk auto --security auto"
SDLC plan "add OAuth login with audit logging" --risk auto --security auto
RID="$(ls "$REPO/.sdlc/runs" | head -1)"
printf '(run id: %s)\n' "$RID"

hdr "3. status"
cmd "sdlc status $RID"; SDLC status "$RID" | sed -n '1,12p'

hdr "4. next"
cmd "sdlc next $RID"; SDLC next "$RID"

hdr "5. run (advance deterministic + advisory gates)"
cmd "sdlc run $RID"; SDLC run "$RID" 2>&1 | tail -6

hdr "6. scan (security evidence)"
cmd "sdlc scan $RID"; SDLC scan "$RID" 2>&1 | tail -8

hdr "7. validate --release (deterministic verdict)"
cmd "sdlc validate --run-id $RID --release"; SDLC validate --run-id "$RID" --release 2>&1 | head -8

hdr "8. tui --no-tui (dashboard)"
cmd "sdlc tui $RID --no-tui"; SDLC tui "$RID" --no-tui 2>&1 | sed -n '1,16p'

hdr "9. worker (dry-run preview of the bounded prompt)"
cmd "sdlc worker $RID codex --mode BUILD"; SDLC worker "$RID" codex --mode BUILD 2>&1 | tail -8

hdr "10. redteam (deterministic findings)"
cmd "sdlc redteam $RID"; SDLC redteam "$RID" 2>&1 | tail -6

hdr "11. finding list"
cmd "sdlc finding list $RID"; SDLC finding list "$RID" 2>&1 | head -8

hdr "12. finding accept on a HIGH (FAC-10: blocked)"
cmd "sdlc finding accept $RID HIGH-001 --closed-by human_security_owner --reason x --evidence app.py"
SDLC finding accept "$RID" HIGH-001 --closed-by human_security_owner --reason "tracked" --evidence app.py 2>&1 | head -4

hdr "13. gate complete (manual typed evidence)"
printf 'runbook: alerts, logs, oncall\n' > runbook.md
cmd "sdlc gate complete $RID observability_runbooks --verdict GO --actor agent_9_sre_sysadmin --evidence runbook.md"
SDLC gate complete "$RID" observability_runbooks --verdict GO --actor agent_9_sre_sysadmin --evidence runbook.md 2>&1 | head -4

hdr "14. agents plan --parallel 6"
cmd "sdlc agents plan $RID --parallel 6"; SDLC agents plan "$RID" --parallel 6 2>&1 | head -12

hdr "15. agents doctor (worker availability)"
cmd "sdlc agents doctor"; SDLC agents doctor 2>&1 | head -10

hdr "16. providers: fallback chain (never silent-skip)"
cmd "python -c 'from sdlc.adapters import select_available_adapter as s; print(s([...]))'"
"$PY" -c "from sdlc.adapters import select_available_adapter as s; r=s(['definitely-not-real','ollama']); print({'name':r['name'],'status':r['status'],'tried':r['tried']})"

hdr "17. git provenance (ledger-backed)"
cmd "sdlc git provenance $RID"; SDLC git provenance "$RID" 2>&1 | head -8

hdr "18. attest manifest"
cmd "sdlc attest manifest $RID"; SDLC attest manifest "$RID" 2>&1 | head -6

hdr "19. deploy plan (production stays locked)"
cmd "sdlc deploy plan $RID --env production --rollback-command 'echo rollback'"
SDLC deploy plan "$RID" --env production --rollback-command "echo rollback" 2>&1 | head -8

hdr "20. bench run (12 dimensions, corpus-relative headline)"
cmd "sdlc bench run"; SDLC bench run 2>&1 | sed -n '1,15p'

hdr "21. diff quality (compare two runs)"
SDLC plan "second feature for diff" --risk low --run-id second-run >/dev/null 2>&1
SDLC run second-run >/dev/null 2>&1
cmd "sdlc diff quality $RID second-run"; SDLC diff quality "$RID" second-run 2>&1 | sed -n '1,14p'

hdr "22. learn record + suggest"
cmd "sdlc learn record $RID"; SDLC learn record "$RID" 2>&1 | tail -4
cmd "sdlc learn suggest"; SDLC learn suggest 2>&1 | "$PY" -c "import json,sys;d=json.load(sys.stdin);print('pending proposals:',len(d.get('pending',[])))" 2>/dev/null || true

hdr "23. ledger integrity: detect a tamper"
ev="$REPO/.sdlc/runs/$RID/events.jsonl"
"$PY" - "$ev" <<'PY'
import json,sys
p=sys.argv[1]; lines=open(p).read().splitlines()
e=json.loads(lines[0]); e['ts']=e['ts'].replace('2026','2027',1); lines[0]=json.dumps(e)
open(p,'w').write("\n".join(lines)+"\n")
PY
cmd "sdlc validate --run-id $RID   # after tampering one event"
SDLC validate --run-id "$RID" 2>&1 | head -4

hdr "24. memory (consent-based, local)"
cmd "sdlc memory init"; SDLC memory init 2>&1 | head -3
cmd "sdlc memory status"; SDLC memory status 2>&1 | head -4

hdr "25. report --print"
cmd "sdlc report second-run --print"; SDLC report second-run --print 2>&1 | sed -n '1,12p'

hdr "26. verify a signed release (real v0.2.0)"
VD="$(mktemp -d)"; ( cd "$VD" && gh release download v0.2.0 --repo gwuml/sdlc --pattern 'SHA256SUMS*' --clobber >/dev/null 2>&1
cmd "cosign verify-blob --certificate-identity-regexp ... SHA256SUMS"
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gwuml/sdlc/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem SHA256SUMS 2>&1 | tail -1 )
rm -rf "$VD"

printf '\n\n(captured against sdlc %s; demo repo: throwaway)\n' "$("$PY" -c 'import sdlc;print(sdlc.__version__)')"
rm -rf "$REPO"
