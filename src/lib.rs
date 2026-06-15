//! `sdlc` library crate — the ported control-plane logic, shared by the `sdlc`
//! binary and by the parity integration tests in `tests/`.
//!
//! Modules mirror the Python reference (`sdlc/*.py`) one-for-one. Keeping the
//! logic in a library (rather than only in the binary) lets the parity harness
//! call the real functions directly and diff them against `python -m sdlc`.

pub mod engine;
pub mod models;
pub mod pipeline;
