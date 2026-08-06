//! Merkle-tree primitives (RFC 6962 ordering) — used by S2 provena-chain to anchor its root
//! hash in a transparency log (Sigstore Rekor or blockchain).
//!
//! SHA-256 binary Merkle tree. Leaves are hashed as `SHA-256(0x00 || leaf)`;
//! internal nodes as `SHA-256(0x01 || left || right)` (RFC 6962 §2.1).

use sha2::{Digest, Sha256};

/// SHA-256 of `0x00 || leaf`.
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// SHA-256 of `0x01 || left || right`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Compute the Merkle root over `leaves` (RFC 6962). Empty input returns the zero hash.
///
/// For a non-power-of-two leaf count, the last node is promoted (RFC 6962-style duplication
/// is NOT used; we replicate the Bitcoin convention of promoting the orphan).
pub fn merkle_root(leaves: &[&[u8]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(node_hash(&layer[i], &layer[i + 1]));
            } else {
                // Odd node out — promote it.
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero_hash() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let leaf = b"hello";
        let root = merkle_root(&[leaf]);
        assert_eq!(root, leaf_hash(leaf));
    }

    #[test]
    fn two_leaves_combine() {
        let a = b"a";
        let b = b"b";
        let root = merkle_root(&[a, b]);
        assert_eq!(root, node_hash(&leaf_hash(a), &leaf_hash(b)));
    }

    #[test]
    fn three_leaves_promotes_orphan() {
        // Three leaves: hash(a,b), then promote c, then combine.
        let a = b"a";
        let b = b"b";
        let c = b"c";
        let root = merkle_root(&[a, b, c]);
        let ab = node_hash(&leaf_hash(a), &leaf_hash(b));
        assert_eq!(root, node_hash(&ab, &leaf_hash(c)));
    }

    #[test]
    fn determinism() {
        let leaves: Vec<&[u8]> = vec![b"x", b"y", b"z", b"w"];
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }

    #[test]
    fn order_matters() {
        let ab = merkle_root(&[b"a", b"b"]);
        let ba = merkle_root(&[b"b", b"a"]);
        assert_ne!(ab, ba, "leaf order must affect the root");
    }

    #[test]
    fn golden_vector_merkle_001() {
        // Locks testvectors/T1/merkle-001.json — four leaves [a,b,c,d], RFC 6962 root.
        let root = merkle_root(&[b"a", b"b", b"c", b"d"]);
        assert_eq!(
            hex::encode(root),
            "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0",
            "Merkle root must match the golden vector in testvectors/T1/merkle-001.json"
        );
    }
}
