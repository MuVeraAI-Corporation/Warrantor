//! Canonical encoding for cross-language signature determinism.
//!
//! **Critical invariant**: the encoding MUST be deterministic — the same logical value
//! MUST always produce the same bytes, regardless of HashMap iteration order, platform,
//! or language. This is the backbone of every cross-language signature verification.
//!
//! Implementation: we recursively sort all map keys (lexicographically by UTF-8 bytes)
//! before serializing to CBOR. This ensures RFC 8949 §4.2.2 determinism even though
//! `serde_cbor` does not enable its `deterministic` feature by default.
//!
//! The sort is applied to `serde_cbor::Value` (an intermediate representation) so it
//! works for any serializable input — the caller's HashMap iteration order is irrelevant
//! because we re-encode through the sorted Value tree.

#![allow(clippy::needless_borrow)]

use serde::Serialize;
use serde_cbor::Value as CborValue;
use thiserror::Error;

/// Errors returned by canonical encoding.
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// The input could not be serialized to CBOR.
    #[error("cbor serialization failed: {0}")]
    Serialize(#[from] serde_cbor::Error),

    /// The encoded bytes could not be read back into a `Value` tree.
    ///
    /// In practice this is nesting depth: `serde_cbor`'s deserializer enforces a 128-level
    /// recursion limit while its serializer enforces none, so a value nested deeper than
    /// that encodes successfully and then fails to decode.
    ///
    /// This *must* stay an error. It was previously `.unwrap_or(CborValue::Null)`, which
    /// turned the failure into `Ok(vec![0xf6])` -- the one-byte encoding of null. Every
    /// input that tripped the limit therefore canonicalized to the same single byte, so a
    /// signature computed over one such value verified against any other (AX-01).
    #[error("cbor round-trip failed (input too deeply nested to re-read): {0}")]
    RoundTrip(#[source] serde_cbor::Error),
}

/// Recursively sort all map keys in a CBOR Value tree (lexicographic by UTF-8 bytes).
/// `serde_cbor::Value::Map` already uses a `BTreeMap<Value, Value>` which is sorted by key
/// (since `Value: Ord`), so the sort is already guaranteed by the intermediate representation.
/// This function exists as a defensive assertion + recurses into nested structures.
fn sort_value(value: &mut CborValue) {
    match value {
        CborValue::Map(map) => {
            // BTreeMap is already sorted by key (Value: Ord), so no explicit sort needed.
            // But we recurse into nested values to ensure they're also canonical.
            for v in map.values_mut() {
                sort_value(v);
            }
        }
        CborValue::Array(arr) => {
            for v in arr.iter_mut() {
                sort_value(v);
            }
        }
        _ => {} // scalars: no sorting needed
    }
}

/// Canonicalize a serializable value to deterministic CBOR bytes.
///
/// This function:
/// 1. Serializes the value to a `serde_cbor::Value` intermediate tree.
/// 2. Recursively sorts ALL map keys in the tree (lexicographic by UTF-8 bytes).
/// 3. Serializes the sorted tree to CBOR.
///
/// The result is RFC 8949 §4.2.2-compliant deterministic encoding. Two calls with
/// the same logical value ALWAYS produce identical bytes, even if the input was a
/// HashMap with non-deterministic iteration order.
///
/// # Errors
/// Returns [`CanonicalError::Serialize`] if the value cannot be CBOR-encoded.
pub fn canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    // Step 1: serialize to an intermediate CBOR Value tree.
    // A failure here is fatal by design -- see CanonicalError::RoundTrip. Substituting a
    // default would collapse distinct inputs onto one canonical form, which for a function
    // whose output gets signed is a signature-forgery primitive, not a fallback.
    let mut cbor_value: CborValue =
        serde_cbor::from_slice(&serde_cbor::to_vec(value)?).map_err(CanonicalError::RoundTrip)?;

    // Step 2: recursively sort all map keys.
    sort_value(&mut cbor_value);

    // Step 3: serialize the sorted tree.
    serde_cbor::to_vec(&cbor_value).map_err(CanonicalError::Serialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn round_trip_basic() {
        let value = ("hello", 42u64);
        let bytes = canonical_cbor(&value).expect("encode");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn determinism_same_input_same_output() {
        let value = std::collections::BTreeMap::from([
            ("a".to_string(), 1u64),
            ("b".to_string(), 2u64),
            ("c".to_string(), 3u64),
        ]);
        let bytes1 = canonical_cbor(&value).expect("encode");
        let bytes2 = canonical_cbor(&value).expect("encode");
        assert_eq!(bytes1, bytes2, "canonical encoding must be deterministic");
    }

    #[test]
    fn determinism_hashmap_vs_btreemap_same_output() {
        // THE CRITICAL TEST: a HashMap (random order) and a BTreeMap (sorted order)
        // with the same key-value pairs MUST produce identical canonical bytes.
        let mut hm: HashMap<String, u64> = HashMap::new();
        hm.insert("zebra".into(), 1);
        hm.insert("apple".into(), 2);
        hm.insert("mango".into(), 3);

        let bt = std::collections::BTreeMap::from([
            ("apple".to_string(), 2u64),
            ("mango".to_string(), 3u64),
            ("zebra".to_string(), 1u64),
        ]);

        let hm_bytes = canonical_cbor(&hm).expect("encode hashmap");
        let bt_bytes = canonical_cbor(&bt).expect("encode btreemap");
        assert_eq!(
            hm_bytes, bt_bytes,
            "HashMap and BTreeMap with same entries MUST produce identical canonical bytes"
        );
    }

    #[test]
    fn determinism_two_hashmaps_same_entries() {
        // Two HashMaps with the same entries but potentially different internal
        // ordering MUST produce identical canonical bytes.
        let mut hm1: HashMap<String, String> = HashMap::new();
        hm1.insert("key1".into(), "val1".into());
        hm1.insert("key2".into(), "val2".into());
        hm1.insert("key3".into(), "val3".into());

        let mut hm2: HashMap<String, String> = HashMap::new();
        hm2.insert("key3".into(), "val3".into());
        hm2.insert("key1".into(), "val1".into());
        hm2.insert("key2".into(), "val2".into());

        let bytes1 = canonical_cbor(&hm1).expect("encode hm1");
        let bytes2 = canonical_cbor(&hm2).expect("encode hm2");
        assert_eq!(
            bytes1, bytes2,
            "Two HashMaps with same entries MUST produce identical canonical bytes"
        );
    }

    #[test]
    fn nested_map_keys_sorted() {
        let outer: HashMap<String, HashMap<String, u64>> = HashMap::from([
            (
                "outer2".to_string(),
                HashMap::from([("inner_b".to_string(), 2u64), ("inner_a".to_string(), 1u64)]),
            ),
            (
                "outer1".to_string(),
                HashMap::from([("inner_d".to_string(), 4u64), ("inner_c".to_string(), 3u64)]),
            ),
        ]);
        let bytes = canonical_cbor(&outer).expect("encode");
        // The encoding should be stable regardless of HashMap order.
        let bytes2 = canonical_cbor(&outer).expect("encode again");
        assert_eq!(bytes, bytes2);
    }
}

#[cfg(test)]
mod ax01_deep_nesting {
    use super::*;
    use serde_json::json;

    /// Build a value nested `depth` levels deep: [[[...]]].
    fn nested(depth: usize) -> serde_json::Value {
        let mut value = json!(1);
        for _ in 0..depth {
            value = json!([value]);
        }
        value
    }

    #[test]
    fn shallow_values_still_canonicalize() {
        assert!(canonical_cbor(&nested(8)).is_ok());
    }

    /// The forgery AX-01 described: two DIFFERENT over-limit values used to canonicalize to
    /// the identical one-byte encoding of null, so one signature covered both.
    #[test]
    fn over_limit_values_error_instead_of_collapsing_to_null() {
        let a = canonical_cbor(&nested(200));
        let b = canonical_cbor(&nested(300));

        assert!(
            a.is_err(),
            "deeply nested input must not silently canonicalize"
        );
        assert!(b.is_err());

        // The specific historical failure: Ok(vec![0xf6]) for every such input.
        if let Ok(bytes) = canonical_cbor(&nested(200)) {
            panic!("expected an error, got {bytes:02x?} -- the null-collapse has returned");
        }
    }

    #[test]
    fn the_error_names_the_round_trip_not_serialization() {
        match canonical_cbor(&nested(200)) {
            Err(CanonicalError::RoundTrip(_)) => {}
            other => panic!("expected RoundTrip, got {other:?}"),
        }
    }
}
