//! Bounded sanitized native completion retrieval. Never replays a model request.
use crate::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    harness: String,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    native_version: String,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    native_executable: PathBuf,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    expected_executable_digest: Option<String>,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    worktree: PathBuf,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    session: String,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    attempt_started_ms: u64,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    home: Option<PathBuf>,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    #[serde(default)]
    environment: crate::Environment,
}

pub(crate) fn call(harness: &str, value: &Value) -> Result<Value> {
    let p: Params = crate::decode(value)?;
    if p.harness != harness {
        return Err(Error::invalid());
    }
    Ok(json!({"recovered":false}))
}
