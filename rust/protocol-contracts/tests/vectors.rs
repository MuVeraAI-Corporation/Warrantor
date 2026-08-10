//! Retained P1-P12 vector verification.

use std::{collections::BTreeMap, path::PathBuf};

use aumos_protocol_contracts::ProtocolValidator;
use serde_json::Value;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_protocol_vector_matches_the_expected_outcome() {
    let root = repository_root();
    let vector_root = root.join("testvectors/protocols");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(vector_root.join("manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    let keyring = manifest["keyring"]
        .as_object()
        .expect("keyring object")
        .iter()
        .map(|(key_id, encoded)| {
            let bytes = hex::decode(encoded.as_str().expect("key hex")).expect("decode key");
            (
                key_id.clone(),
                <[u8; 32]>::try_from(bytes).expect("32-byte key"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let registry =
        std::fs::read_to_string(root.join("specs/protocols/registry.json")).expect("read registry");
    let validator = ProtocolValidator::new(&registry, keyring).expect("valid registry");
    let entries = manifest["vectors"].as_array().expect("vector entries");
    assert_eq!(entries.len(), 40);
    for entry in entries {
        let vector: Value = serde_json::from_str(
            &std::fs::read_to_string(
                vector_root.join(entry["path"].as_str().expect("vector path")),
            )
            .expect("read vector"),
        )
        .expect("parse vector");
        let result = validator.validate(
            &vector["document"],
            vector["protocol"].as_str().expect("protocol"),
            vector["validation_time"].as_u64().expect("validation time"),
        );
        let expected_valid = vector["expected"] == "valid";
        assert_eq!(result.valid, expected_valid, "{}: {result:?}", vector["id"]);
        if !expected_valid {
            assert_eq!(
                serde_json::to_value(result.error_code).expect("serialize code"),
                vector["expected_error"],
                "{}: {result:?}",
                vector["id"]
            );
        }
    }
}
