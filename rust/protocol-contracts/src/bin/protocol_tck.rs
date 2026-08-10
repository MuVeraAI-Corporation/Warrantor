//! Batch verifier used by the strict cross-language protocol TCK.

use std::{collections::BTreeMap, io::Read, path::PathBuf};

use warrantor_protocol_contracts::ProtocolValidator;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct Batch {
    keyring: BTreeMap<String, String>,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    protocol: String,
    validation_time: u64,
    document: Value,
}

#[derive(Serialize)]
struct VectorResult {
    id: String,
    valid: bool,
    error_code: Option<warrantor_protocol_contracts::ErrorCode>,
    detail: String,
}

#[derive(Serialize)]
struct Output {
    implementation: &'static str,
    results: Vec<VectorResult>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: protocol-tck-rust <registry.json>")?;
    let registry_json = std::fs::read_to_string(registry_path)?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let batch: Batch = serde_json::from_str(&input)?;
    let keyring = batch
        .keyring
        .into_iter()
        .map(|(key_id, encoded)| {
            let bytes = hex::decode(encoded)?;
            let key = <[u8; 32]>::try_from(bytes).map_err(|_| "key must contain 32 bytes")?;
            Ok((key_id, key))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let validator = ProtocolValidator::new(&registry_json, keyring)?;
    let results = batch
        .vectors
        .into_iter()
        .map(|vector| {
            let result =
                validator.validate(&vector.document, &vector.protocol, vector.validation_time);
            VectorResult {
                id: vector.id,
                valid: result.valid,
                error_code: result.error_code,
                detail: result.detail,
            }
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&Output {
            implementation: "rust",
            results,
        })?
    );
    Ok(())
}
