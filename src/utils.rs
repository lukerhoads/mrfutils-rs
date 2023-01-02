use ijson::IValue;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::process::Command;
use anyhow::Context;
use log::warn;

// Makes a hash for the given serde value
// Note - insert values with their keys sorted alphabetically
pub fn make_hash(raw: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let result = Vec::from(hasher.finalize().as_slice());
    let (left, _) = result.split_at(8);
    u64::from_le_bytes(left.try_into().unwrap()).to_string()
}

pub fn common_json<T: Serialize>(obj: &T) -> String {
    let ser_string = serde_json::to_string(&obj).unwrap();
    let split: Vec<_> = ser_string.split(":").collect();
    split.join(": ")
}

// Extracts value from obj and returns one option
// TODO: look into libraries to fix these nesting ifs
pub fn extract_string_val(obj: &IValue, key: &str) -> Option<String> {
    if let Some(pkg) = obj.get(key) {
        if let Some(pkga) = pkg.as_string() {
            Some(pkga.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

pub fn extract_number_val(obj: &IValue, key: &str) -> Option<String> {
    if let Some(pkg) = obj.get(key) {
        if let Some(pkga) = pkg.as_number() {
            Some(pkga.to_f64().unwrap().to_string())
        } else {
            None
        }
    } else {
        None
    }
}

// Only adds extra quotes around a value if it is not None
pub fn surround(opt: Option<&String>) -> String {
    match opt {
        Some(st) => {
            format!("'{}'", st)
        },
        None => "NULL".to_string()
    }
}

// TODO - remove warning from this function
pub fn execute_command(dolt_dir: &str, dolt_command: &str) -> anyhow::Result<()> {
    let output = Command::new("dolt")
        .args(["sql", "-q", dolt_command])
        .current_dir(dolt_dir.clone())
        .output()
        .context("Failed to execute dolt insert")?;
    if let Err(e) = output.status.exit_ok() {
        warn!("Database rejection due to error {}", e);
    }
    Ok(())
}