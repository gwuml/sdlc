//! Secure SDLC pipeline definitions — Rust counterpart of `sdlc/pipeline.py`.
//!
//! The canonical 25 gate definitions are embedded verbatim from the Python
//! reference (`tests/parity/default_gates.json`, produced by serializing
//! `DEFAULT_GATES`). Embedding the exact bytes guarantees data parity; the
//! parity test in `tests/parity_pipeline.rs` re-verifies that the Rust struct
//! deserializes and re-serializes every field with no drift (FAC 2).

use serde::{Deserialize, Serialize};

/// A deterministic gate definition used by the orchestrator. Field set and
/// defaults mirror `pipeline.GateDefinition`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateDefinition {
    pub id: String,
    pub order: i64,
    pub title: String,
    pub owner: String,
    pub purpose: String,
    #[serde(default)]
    pub required_artifacts: Vec<String>,
    #[serde(default = "default_read_only")]
    pub default_mode: String,
    #[serde(default)]
    pub conditional_on: Option<String>,
    #[serde(default = "default_true")]
    pub auto_skip_when_false: bool,
    #[serde(default = "default_verdicts")]
    pub allowed_verdicts: Vec<String>,
    #[serde(default = "default_true")]
    pub blocks_commit: bool,
    #[serde(default = "default_true")]
    pub blocks_deploy: bool,
}

fn default_read_only() -> String {
    "READ_ONLY".to_string()
}
fn default_true() -> bool {
    true
}
fn default_verdicts() -> Vec<String> {
    vec!["GO".to_string(), "NO_GO".to_string()]
}

const DEFAULT_GATES_JSON: &str = include_str!("default_gates.json");

/// The canonical 25-gate pipeline, in order.
pub fn default_gates() -> Vec<GateDefinition> {
    serde_json::from_str(DEFAULT_GATES_JSON)
        .expect("embedded default_gates.json must deserialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_has_25_gates_in_strict_order() {
        let gates = default_gates();
        assert_eq!(gates.len(), 25, "pipeline must define exactly 25 gates");
        for (i, gate) in gates.iter().enumerate() {
            assert_eq!(
                gate.order as usize,
                i + 1,
                "gate {} order must be {}",
                gate.id,
                i + 1
            );
        }
    }

    #[test]
    fn conditional_gates_are_marked() {
        let gates = default_gates();
        let by_id = |id: &str| gates.iter().find(|g| g.id == id).unwrap().clone();
        assert_eq!(
            by_id("ui_architecture_accessibility").conditional_on.as_deref(),
            Some("has_ui")
        );
        assert_eq!(
            by_id("deploy_rollout_postdeploy").conditional_on.as_deref(),
            Some("production_rollout_allowed")
        );
    }
}
