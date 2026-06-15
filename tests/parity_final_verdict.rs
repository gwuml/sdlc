//! Cross-language verdict parity (FAC 2): for every fixture, the Rust
//! `engine::final_verdict` must equal the Python reference's verdict — except
//! the documented FAC 10 hardening, where a fixture containing an ACCEPTED or
//! DEFERRED CRITICAL/HIGH finding is expected to diverge (Rust -> NO_GO).
//!
//! Oracle `tests/parity/final_verdicts.json` maps run_id -> Python verdict.
//! Regenerate with:
//!   python3 -c "import json,glob,os; from sdlc.models import RunPlan,Finding; \
//!     from sdlc.engine import final_verdict; \
//!     o={os.path.basename(os.path.dirname(p)): final_verdict( \
//!       [Finding.from_dict(x) for x in json.load(open(os.path.join(os.path.dirname(p),'findings.json')))] \
//!         if os.path.exists(os.path.join(os.path.dirname(p),'findings.json')) else [], \
//!       RunPlan.from_dict(json.load(open(p)))) for p in glob.glob('.sdlc/runs/*/plan.json')}; \
//!     json.dump(o, open('tests/parity/final_verdicts.json','w'), indent=2, sort_keys=True)"

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sdlc::engine::final_verdict;
use sdlc::models::{Finding, RunPlan};

fn manifest(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn final_verdict_matches_python_oracle_for_every_fixture() {
    let oracle: BTreeMap<String, String> =
        serde_json::from_str(&fs::read_to_string(manifest("tests/parity/final_verdicts.json")).unwrap())
            .unwrap();

    let runs_dir = manifest("tests/fixtures/runs"); // self-contained; clean-clone safe
    let mut checked = 0;
    for entry in fs::read_dir(&runs_dir).unwrap() {
        let dir = entry.unwrap().path();
        let plan_path = dir.join("plan.json");
        if !plan_path.exists() {
            continue;
        }
        let run_id = dir.file_name().unwrap().to_string_lossy().to_string();
        let Some(expected_python) = oracle.get(&run_id) else {
            continue;
        };

        let plan: RunPlan =
            serde_json::from_str(&fs::read_to_string(&plan_path).unwrap()).unwrap();
        let findings: Vec<Finding> = {
            let fp = dir.join("findings.json");
            if fp.exists() {
                serde_json::from_str(&fs::read_to_string(&fp).unwrap()).unwrap()
            } else {
                vec![]
            }
        };

        let rust_verdict = final_verdict(&findings, Some(&plan));

        // FAC 10 intentional divergence: an ACCEPTED/DEFERRED CRITICAL/HIGH makes
        // Rust stricter (NO_GO) than the Python reference may be.
        let has_accepted_crit_high = findings.iter().any(|f| {
            matches!(f.status.as_str(), "ACCEPTED" | "DEFERRED")
                && matches!(f.severity.as_str(), "CRITICAL" | "HIGH")
        });

        if has_accepted_crit_high {
            assert_eq!(
                rust_verdict, "NO_GO",
                "{run_id}: FAC 10 — accepted/deferred CRITICAL/HIGH must be NO_GO in Rust"
            );
        } else {
            assert_eq!(
                &rust_verdict, expected_python,
                "{run_id}: Rust verdict {rust_verdict} != Python {expected_python}"
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "no fixtures with plan.json found");
    eprintln!("final_verdict parity verified for {checked} fixtures");
}
