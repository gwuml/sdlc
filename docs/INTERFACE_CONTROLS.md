# Terminal Interface Controls

The target interface is a terminal-native command center.

## Current CLI

```bash
sdlc init
sdlc plan "Build feature"
sdlc status <run-id>
sdlc run <run-id> --redteam
sdlc worker <run-id> codex --mode BUILD
sdlc worker <run-id> claude --mode PLAN
sdlc redteam <run-id>
sdlc redteam execute <run-id> --execute --allow-network
sdlc deploy plan <run-id> --env production --rollback-command "rollback-command --flag"
sdlc deploy approve <run-id> --env production --actor human_release_manager --evidence approval.md
sdlc deploy execute <run-id> --env production --execute --command "deploy-command --flag"
sdlc deploy verify <run-id> --env production --evidence smoke.md
sdlc deploy rollback <run-id> --env production --execute --command "rollback-command --flag"
sdlc attest manifest <run-id>
sdlc attest sign <run-id> --key ~/.sdlc-control-plane/attestation.key --execute
sdlc attest verify <run-id> --key ~/.sdlc-control-plane/attestation.key
sdlc git branch <run-id>
sdlc git commit <run-id> --message "feat: ..."
sdlc git pr <run-id>
sdlc report <run-id> --print
sdlc validate --run-id <run-id>
```

## Future TUI controls

```text
/       command palette
g       jump to gate
a       approve selected gate
n       mark NO-GO
r       rerun selected gate
f       send selected finding to implementer
d       open diff
e       open evidence ledger
p       open permissions matrix
u       open UI review
s       open security review
k       kill active worker
x       quarantine run
m       switch model/worker
Ctrl+G  edit current prompt in $EDITOR
Ctrl+O  open full transcript/event stream
@       attach file/path/context
```

## Better-than-worker controls

The value is not replacing Codex or Claude. The value is adding:

- SDLC gates
- role ownership
- path permissions
- immutable findings
- evidence ledger
- cross-model audit
- direct-main/deploy lock
- claim discipline
- final report traceability
