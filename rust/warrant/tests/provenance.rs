//! L5-11: every proxied response carries origin, trust, expiry, compartment and non-transitivity.

use std::collections::BTreeMap;
use std::io::Cursor;

use serde_json::{json, Value};
use warrantor_warrant::mcp::{serve, Endpoint, ToolResult, ToolSpec};
use warrantor_warrant::provenance::{Origin, ProvenanceLabel, Trust, PROVENANCE_FORMAT};
use warrantor_warrant::report::sha256_hex;

const NOW: u64 = 1_786_000_000;

#[test]
fn a_label_states_no_authority_and_addresses_its_content() {
    let label = ProvenanceLabel::upstream("selftest.echo", "round trip", NOW + 3600, "wrt_a");
    assert_eq!(label.format, PROVENANCE_FORMAT);
    assert_eq!(
        label.origin,
        Origin::Upstream {
            server: "selftest".to_string(),
            tool: "echo".to_string()
        }
    );
    assert_eq!(label.trust, Trust::None);
    assert_eq!(label.expires_at, NOW + 3600);
    assert_eq!(label.compartment, "wrt_a");
    assert!(label.non_transitive);
    assert_eq!(label.lineage, sha256_hex(b"round trip"));
}

#[test]
fn a_label_cannot_be_deserialized_with_more_trust_than_none() {
    // Non-transitivity is enforced by the type: there is no value of `Trust` above `none`, so a
    // forwarded item cannot be re-labeled upward by anything that speaks this format.
    assert!(serde_json::from_str::<Trust>("\"none\"").is_ok());
    assert!(serde_json::from_str::<Trust>("\"authority\"").is_err());
    assert!(serde_json::from_str::<Trust>("\"instruction\"").is_err());
}

#[test]
fn a_label_rides_in_meta_beside_the_text_never_inside_it() {
    struct Labeled;
    impl Endpoint for Labeled {
        fn name(&self) -> &str {
            "labeled"
        }
        fn tools(&mut self) -> Vec<ToolSpec> {
            vec![ToolSpec {
                name: "t".to_string(),
                description: String::new(),
                input_schema: json!({"type": "object"}),
            }]
        }
        fn call(&mut self, _tool: &str, _a: &BTreeMap<String, Value>) -> ToolResult {
            ToolResult::ok("payload").labeled(ProvenanceLabel::upstream(
                "up.t",
                "payload",
                NOW + 60,
                "wrt_meta",
            ))
        }
    }
    let input = Cursor::new(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();
    serve(&mut Labeled, input, &mut output).expect("serve");
    let reply: Value = serde_json::from_slice(&output).expect("one JSON line");
    let result = &reply["result"];
    assert_eq!(
        result["content"][0]["text"], "payload",
        "the text is the upstream's bytes, untouched"
    );
    let label = &result["_meta"]["provenance"];
    assert_eq!(label["format"], PROVENANCE_FORMAT);
    assert_eq!(label["trust"], "none");
    assert_eq!(label["non_transitive"], true);
    assert_eq!(label["compartment"], "wrt_meta");
    assert_eq!(label["origin"]["kind"], "upstream");
    assert_eq!(label["origin"]["server"], "up");
}
