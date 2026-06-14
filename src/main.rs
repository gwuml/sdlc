//! `sdlc` — Rust implementation of the Secure SDLC control plane.
//!
//! Migration in progress (docs/RUST_MIGRATION_PLAN.md). The CLI surface mirrors
//! the 24 Python subcommands; handlers are ported command-by-command behind a
//! parity harness. Commands not yet ported print a clear not-implemented notice
//! and exit non-zero so they are never silently mistaken for the reference.

mod engine;
mod models;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "sdlc", version, about = "Secure SDLC control plane")]
struct Cli {
    /// Repository root.
    #[arg(long, global = true)]
    repo: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// The 24 subcommands of the reference implementation. Each variant maps 1:1 to
/// a Python subcommand so the surface is identical during migration.
#[derive(Subcommand)]
enum Command {
    /// Initialize .sdlc structure.
    Init,
    /// Create a gated SDLC run and execution prompt.
    Plan,
    /// Autopilot entrypoint: plan, brief, prework, agents, and next action.
    Start,
    /// Create intake brief, standards mapping, and prework reports.
    Brief,
    /// Show run status.
    Status,
    /// Recommend the safest next action for a run.
    Next,
    /// Advance deterministic/dry gates.
    Run,
    /// Invoke a worker adapter in dry-run or explicit execution mode.
    Worker,
    /// Run an external prompt under SDLC supervision.
    Prompt,
    /// Run deterministic or explicit worker red-team evidence.
    Redteam,
    /// Preflight audit worker hard-isolation runtime availability.
    Isolation,
    /// Run security scanners and capture evidence.
    Scan,
    /// Plan, approve, execute, verify, and rollback locked deployments.
    Deploy,
    /// Generate, sign, and verify run artifact attestations.
    Attest,
    /// Plan, execute, inspect, and diagnose role-agent work.
    Agents,
    /// Inspect and seal run ledger integrity boundaries.
    Ledger,
    /// Manage local consent-based episodic memory.
    Memory,
    /// Manage red-team finding lifecycle.
    Finding,
    /// Manually complete or update a gate with evidence.
    Gate,
    /// Safe Git branch, commit, and PR helpers.
    Git,
    /// Show a terminal dashboard for a run.
    Tui,
    /// Check and prepare release-lane prerequisites.
    Release,
    /// Generate final report.
    Report,
    /// Validate repo/run structure.
    Validate,
    // New subsystems (docs/RUST_MIGRATION_PLAN.md phases 4-6):
    /// Run, compare, and report the 12-dimension benchmark suite.
    Bench,
    /// Structural quality diff between two runs.
    Diff,
    /// Self-improvement loop: record, suggest, apply lessons.
    Learn,
    /// Signed auto-update from GitHub Releases.
    Update,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let name = match cli.command {
        Command::Init => "init",
        Command::Plan => "plan",
        Command::Start => "start",
        Command::Brief => "brief",
        Command::Status => "status",
        Command::Next => "next",
        Command::Run => "run",
        Command::Worker => "worker",
        Command::Prompt => "prompt",
        Command::Redteam => "redteam",
        Command::Isolation => "isolation",
        Command::Scan => "scan",
        Command::Deploy => "deploy",
        Command::Attest => "attest",
        Command::Agents => "agents",
        Command::Ledger => "ledger",
        Command::Memory => "memory",
        Command::Finding => "finding",
        Command::Gate => "gate",
        Command::Git => "git",
        Command::Tui => "tui",
        Command::Release => "release",
        Command::Report => "report",
        Command::Validate => "validate",
        Command::Bench => "bench",
        Command::Diff => "diff",
        Command::Learn => "learn",
        Command::Update => "update",
    };
    eprintln!(
        "sdlc: `{name}` is not yet ported to the Rust binary. \
         Use `python -m sdlc {name}` until this command reaches parity \
         (see docs/RUST_MIGRATION_PLAN.md)."
    );
    ExitCode::from(2)
}
