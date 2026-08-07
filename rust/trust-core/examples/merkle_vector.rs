//! Conformance helper: compute the RFC 6962 Merkle root over a JSON array of hex leaves.
//! Used by tools/conformance/run.sh to verify Merkle golden vectors cross-language.
//! Reads a JSON array of hex strings from argv[1] and prints `{"root_hex":"..."}`.
use aumos_trust_core::merkle::merkle_root;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("merkle_vector: usage: merkle_vector '<json-array-of-hex-leaves>'");
        std::process::exit(2);
    });
    let leaves_hex: Vec<String> = serde_json::from_str(&arg).unwrap_or_else(|e| {
        eprintln!("merkle_vector: parse leaves JSON: {e}");
        std::process::exit(2);
    });
    let leaves: Vec<Vec<u8>> = leaves_hex
        .iter()
        .map(|h| hex::decode(h).unwrap_or_else(|e| panic!("merkle_vector: bad leaf hex {h}: {e}")))
        .collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    let root = merkle_root(&refs);
    println!("{{\"root_hex\":\"{}\"}}", hex::encode(root));
}
