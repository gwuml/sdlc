//! Gate engine — Rust counterpart of `sdlc/engine.py`.
//!
//! Phase 2 ports the release-critical decision function `final_verdict` and its
//! gate-completion helpers. Behavior matches the Python reference EXCEPT for one
//! deliberate, spec-mandated hardening (FAC 10): a CRITICAL or HIGH finding may
//! never reach a positive verdict via ACCEPTED/DEFERRED status. The Python
//! reference returns `GO_WITH_ACCEPTED_RESIDUAL_RISKS` for an ACCEPTED CRITICAL
//! finding; the Rust binary returns `NO_GO`. This divergence is intentional and
//! is covered by `final_verdict_blocks_accepted_critical_high` below.

use crate::models::{invalid_findings, open_findings, Finding, RunPlan};
use serde_json::Value;

/// Resolve a gate condition from its canonical plan location (mirror of
/// `models.plan_condition_value`): a `RunPlan` field, else a `classification`
/// key, else `None`.
fn plan_condition_value(plan: &RunPlan, condition: &str) -> Option<Value> {
    match condition {
        "production_rollout_allowed" => Some(Value::Bool(plan.production_rollout_allowed)),
        "direct_main_push_allowed" => Some(Value::Bool(plan.direct_main_push_allowed)),
        "risk_level" => Some(Value::String(plan.risk_level.clone())),
        _ => plan.classification.get(condition).cloned(),
    }
}

fn skipped_gate_valid(gate: &crate::models::GateState, plan: &RunPlan) -> bool {
    if gate.verdict.as_deref() != Some("SKIPPED") {
        return false;
    }
    let Some(cond) = gate.conditional_on.as_deref() else {
        return false;
    };
    plan_condition_value(plan, cond) == Some(Value::Bool(false))
}

fn gate_complete_for_final(gate: &crate::models::GateState, plan: &RunPlan) -> bool {
    match gate.state.as_str() {
        "SKIPPED" => skipped_gate_valid(gate, plan),
        "WAIVED" => true,
        "GO" => {
            matches!(
                gate.verdict.as_deref(),
                Some("GO") | Some("GO_WITH_ACCEPTED_RESIDUAL_RISKS")
            ) && !gate.evidence.is_empty()
        }
        _ => false,
    }
}

/// Compute the run's final verdict from findings and (optionally) the plan.
///
/// Allowed return values: "GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS".
pub fn final_verdict(findings: &[Finding], plan: Option<&RunPlan>) -> String {
    if let Some(plan) = plan {
        let blocked_gate = plan.gates.iter().any(|g| {
            g.verdict.as_deref() == Some("NO_GO")
                || matches!(g.state.as_str(), "NO_GO" | "FIX_REQUIRED" | "BLOCKED")
        });
        if blocked_gate {
            return "NO_GO".into();
        }
        if plan.gates.iter().any(|g| !gate_complete_for_final(g, plan)) {
            return "NO_GO".into();
        }
    }

    if !invalid_findings(findings).is_empty() {
        return "NO_GO".into();
    }

    // FAC 10 hardening (intentional divergence from the Python reference):
    // a CRITICAL or HIGH finding may NEVER be accepted/deferred into a positive
    // verdict. It must be RESOLVED (CLOSED with evidence). Any CRITICAL/HIGH that
    // is not CLOSED — including ACCEPTED or DEFERRED — blocks the release.
    let critical_high_not_closed = findings.iter().any(|f| {
        matches!(f.severity.as_str(), "CRITICAL" | "HIGH") && f.status != "CLOSED"
    });
    if critical_high_not_closed {
        return "NO_GO".into();
    }

    // Open MEDIUM (non-terminal, non-deferred-low) still blocks.
    if !open_findings(findings, Some(&["MEDIUM"])).is_empty() {
        return "NO_GO".into();
    }

    // Only MEDIUM (and lower) may be accepted/deferred as residual risk.
    let medium_accepted_or_deferred = findings.iter().any(|f| {
        matches!(f.status.as_str(), "ACCEPTED" | "DEFERRED") && f.severity == "MEDIUM"
    });
    if medium_accepted_or_deferred {
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS".into();
    }

    if let Some(plan) = plan {
        if plan
            .gates
            .iter()
            .any(|g| g.verdict.as_deref() == Some("GO_WITH_ACCEPTED_RESIDUAL_RISKS"))
        {
            return "GO_WITH_ACCEPTED_RESIDUAL_RISKS".into();
        }
    }

    "GO".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Finding;

    fn finding(id: &str, severity: &str, status: &str) -> Finding {
        Finding {
            id: id.into(),
            severity: severity.into(),
            title: "t".into(),
            evidence: vec!["e".into()],
            impact: "i".into(),
            required_fix: "f".into(),
            owner: "o".into(),
            status: status.into(),
            closed_by: None,
            closure_evidence: vec![],
        }
    }

    #[test]
    fn clean_run_with_no_findings_is_go() {
        assert_eq!(final_verdict(&[], None), "GO");
    }

    #[test]
    fn open_critical_blocks() {
        let f = vec![finding("C1", "CRITICAL", "OPEN")];
        assert_eq!(final_verdict(&f, None), "NO_GO");
    }

    #[test]
    fn resolved_critical_with_accepted_medium_is_residual_go() {
        let f = vec![
            finding("C1", "CRITICAL", "CLOSED"),
            finding("M1", "MEDIUM", "ACCEPTED"),
        ];
        assert_eq!(final_verdict(&f, None), "GO_WITH_ACCEPTED_RESIDUAL_RISKS");
    }

    /// FAC 10: the loophole the Python reference leaves open. An ACCEPTED CRITICAL
    /// must NOT yield a positive verdict in the Rust binary.
    #[test]
    fn final_verdict_blocks_accepted_critical_high() {
        for sev in ["CRITICAL", "HIGH"] {
            for status in ["ACCEPTED", "DEFERRED"] {
                let f = vec![finding("X", sev, status)];
                assert_eq!(
                    final_verdict(&f, None),
                    "NO_GO",
                    "{sev} {status} must block (FAC 10)"
                );
            }
        }
    }

    #[test]
    fn open_medium_blocks() {
        let f = vec![finding("M1", "MEDIUM", "OPEN")];
        assert_eq!(final_verdict(&f, None), "NO_GO");
    }
}
