//! Core data models — the Rust counterpart of `sdlc/models.py`.
//!
//! Field names and JSON shapes match the Python reference exactly so that
//! `plan.json` and `findings.json` produced by either implementation are
//! interchangeable (parity requirement, FAC 2). Equality in parity tests is
//! compared as parsed JSON values, so field ordering is irrelevant.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VALID_GATE_STATES: &[&str] = &[
    "PENDING",
    "READY",
    "RUNNING",
    "GO",
    "NO_GO",
    "FIX_REQUIRED",
    "SKIPPED",
    "WAIVED",
    "BLOCKED",
];
pub const VALID_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW"];
pub const VALID_FINDING_STATUSES: &[&str] = &[
    "OPEN",
    "FIXED_PENDING_REVIEW",
    "CLOSED",
    "ACCEPTED",
    "DEFERRED",
];
pub const VALID_FINAL_VERDICTS: &[&str] = &["GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"];

fn default_pending() -> String {
    "PENDING".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateState {
    pub id: String,
    pub order: i64,
    pub title: String,
    pub owner: String,
    #[serde(default = "default_pending")]
    pub state: String,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub conditional_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub evidence: Vec<String>,
    pub impact: String,
    pub required_fix: String,
    pub owner: String,
    #[serde(default = "default_open")]
    pub status: String,
    #[serde(default)]
    pub closed_by: Option<String>,
    #[serde(default)]
    pub closure_evidence: Vec<String>,
}

fn default_open() -> String {
    "OPEN".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunPlan {
    pub run_id: String,
    pub created_at: String,
    pub feature: String,
    pub repo: String,
    pub branch: String,
    pub risk_level: String,
    pub classification: Value,
    pub production_rollout_allowed: bool,
    pub direct_main_push_allowed: bool,
    pub policy_profile: String,
    pub gates: Vec<GateState>,
    pub agents: Vec<Value>,
    #[serde(default)]
    pub worker_preferences: Value,
}

/// Mirror of `models.open_findings`: findings in the given severities that are not
/// in a terminal status (CLOSED/ACCEPTED), excluding DEFERRED LOW.
pub fn open_findings<'a>(findings: &'a [Finding], severities: Option<&[&str]>) -> Vec<&'a Finding> {
    let sevs = severities.unwrap_or(VALID_SEVERITIES);
    findings
        .iter()
        .filter(|f| sevs.contains(&f.severity.as_str()))
        .filter(|f| f.status != "CLOSED" && f.status != "ACCEPTED")
        .filter(|f| !(f.status == "DEFERRED" && f.severity == "LOW"))
        .collect()
}

/// Mirror of `models.invalid_findings`.
pub fn invalid_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| {
            !VALID_SEVERITIES.contains(&f.severity.as_str())
                || !VALID_FINDING_STATUSES.contains(&f.status.as_str())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_findings_excludes_terminal_and_deferred_low() {
        let mk = |id: &str, sev: &str, status: &str| Finding {
            id: id.into(),
            severity: sev.into(),
            title: "t".into(),
            evidence: vec![],
            impact: "i".into(),
            required_fix: "f".into(),
            owner: "o".into(),
            status: status.into(),
            closed_by: None,
            closure_evidence: vec![],
        };
        let findings = vec![
            mk("1", "HIGH", "OPEN"),
            mk("2", "HIGH", "CLOSED"),
            mk("3", "HIGH", "ACCEPTED"),
            mk("4", "LOW", "DEFERRED"),
            mk("5", "MEDIUM", "DEFERRED"),
        ];
        let open = open_findings(&findings, None);
        let ids: Vec<&str> = open.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["1", "5"]);
    }
}
