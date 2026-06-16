//! Phase 1 parity: every fixture's plan.json and findings.json must round-trip
//! through the Rust models with no value-level change. This proves the serde
//! shapes match the Python reference before any behavior is ported (FAC 2).
//!
//! The Rust models live in the binary crate; this integration test re-declares
//! the deserialization target via serde_json::Value comparison so it does not
//! depend on the crate's internal module visibility. We assert that parsing into
//! the typed model and re-serializing yields a value equal to the original JSON.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_pending() -> String {
    "PENDING".to_string()
}
fn default_open() -> String {
    "OPEN".to_string()
}

#[derive(Serialize, Deserialize)]
struct GateState {
    id: String,
    order: i64,
    title: String,
    owner: String,
    #[serde(default = "default_pending")]
    state: String,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    conditional_on: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Finding {
    id: String,
    severity: String,
    title: String,
    evidence: Vec<String>,
    impact: String,
    required_fix: String,
    owner: String,
    #[serde(default = "default_open")]
    status: String,
    #[serde(default)]
    closed_by: Option<String>,
    #[serde(default)]
    closure_evidence: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RunPlan {
    run_id: String,
    created_at: String,
    feature: String,
    repo: String,
    branch: String,
    risk_level: String,
    classification: Value,
    production_rollout_allowed: bool,
    direct_main_push_allowed: bool,
    policy_profile: String,
    gates: Vec<GateState>,
    agents: Vec<Value>,
    #[serde(default)]
    worker_preferences: Value,
}

fn runs_dir() -> PathBuf {
    // Committed, self-contained fixtures so parity passes on a clean clone
    // (`.sdlc/runs` is gitignored and empty on a fresh checkout).
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runs")
}

/// Compare two JSON values for semantic equality (object key order ignored).
fn assert_value_eq(original: &Value, roundtrip: &Value, ctx: &str) {
    assert_eq!(original, roundtrip, "round-trip mismatch in {ctx}");
}

#[test]
fn plan_json_round_trips_for_every_fixture() {
    let dir = runs_dir();
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("read .sdlc/runs") {
        let path = entry.unwrap().path().join("plan.json");
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        let original: Value = serde_json::from_str(&raw).unwrap();
        let plan: RunPlan = serde_json::from_value(original.clone())
            .unwrap_or_else(|e| panic!("deserialize {}: {e}", path.display()));
        let roundtrip = serde_json::to_value(&plan).unwrap();
        assert_value_eq(&original, &roundtrip, &path.display().to_string());
        checked += 1;
    }
    assert!(
        checked > 0,
        "no plan.json fixtures found under {}",
        dir.display()
    );
    eprintln!("plan.json round-trip verified for {checked} fixtures");
}

#[test]
fn findings_json_round_trips_for_every_fixture() {
    let dir = runs_dir();
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("read .sdlc/runs") {
        let path = entry.unwrap().path().join("findings.json");
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        let original: Value = serde_json::from_str(&raw).unwrap();
        let findings: Vec<Finding> = serde_json::from_value(original.clone())
            .unwrap_or_else(|e| panic!("deserialize {}: {e}", path.display()));
        let roundtrip = serde_json::to_value(&findings).unwrap();
        assert_value_eq(&original, &roundtrip, &path.display().to_string());
        checked += 1;
    }
    assert!(checked > 0, "no findings.json fixtures found");
    eprintln!("findings.json round-trip verified for {checked} fixtures");
}
