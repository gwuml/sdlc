//! Phase 2 parity: the Rust pipeline's 25 gate definitions must equal the Python
//! reference `DEFAULT_GATES` value-for-value (FAC 2). The oracle file
//! `tests/parity/default_gates.json` is produced by serializing the Python
//! definitions; regenerate it with:
//!
//!   python3 -c "import json; from sdlc.pipeline import DEFAULT_GATES; \
//!     json.dump([g.to_dict() for g in DEFAULT_GATES], open('tests/parity/default_gates.json','w'), indent=2)"

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_read_only() -> String {
    "READ_ONLY".to_string()
}
fn default_true() -> bool {
    true
}
fn default_verdicts() -> Vec<String> {
    vec!["GO".to_string(), "NO_GO".to_string()]
}

#[derive(Serialize, Deserialize)]
struct GateDefinition {
    id: String,
    order: i64,
    title: String,
    owner: String,
    purpose: String,
    #[serde(default)]
    required_artifacts: Vec<String>,
    #[serde(default = "default_read_only")]
    default_mode: String,
    #[serde(default)]
    conditional_on: Option<String>,
    #[serde(default = "default_true")]
    auto_skip_when_false: bool,
    #[serde(default = "default_verdicts")]
    allowed_verdicts: Vec<String>,
    #[serde(default = "default_true")]
    blocks_commit: bool,
    #[serde(default = "default_true")]
    blocks_deploy: bool,
}

#[test]
fn rust_pipeline_matches_python_default_gates() {
    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/parity/default_gates.json");
    let embedded_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/default_gates.json");

    let oracle: Value = serde_json::from_str(&fs::read_to_string(&oracle_path).unwrap()).unwrap();
    let embedded_raw = fs::read_to_string(&embedded_path).unwrap();

    // 1. The embedded copy must equal the Python oracle value-for-value.
    let embedded: Value = serde_json::from_str(&embedded_raw).unwrap();
    assert_eq!(embedded, oracle, "src/default_gates.json drifted from Python oracle");

    // 2. The typed Rust struct must round-trip every gate with no value drift.
    let gates: Vec<GateDefinition> = serde_json::from_str(&embedded_raw).unwrap();
    assert_eq!(gates.len(), 25);
    let roundtrip = serde_json::to_value(&gates).unwrap();
    assert_eq!(roundtrip, oracle, "typed GateDefinition round-trip drifted");
}
