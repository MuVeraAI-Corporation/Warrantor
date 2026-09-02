//! The twelve formal invariants, transcribed verbatim, and the check that keeps them honest.
//!
//! `docs/02-architecture.md` §3 is the source of record. Transcribing the statements into Rust
//! buys the suites a compile-time name for each invariant; it also creates the drift this module
//! exists to prevent, because two copies of a normative sentence are one copy and one lie waiting
//! to happen. [`statements_match_the_architecture_doc`] reads the doc table at test time and
//! refuses any divergence, so the corpus cannot quietly test a softer invariant than the one the
//! architecture publishes.

use crate::harness;

/// One invariant as the architecture doc states it.
pub struct Invariant {
    /// The identifier, `I-01` through `I-12`.
    pub id: &'static str,
    /// The statement, verbatim from the doc's `Invariant` column with `**` markers removed.
    pub statement: &'static str,
    /// The doc's `Enforced primarily by` column, verbatim.
    pub enforced_primarily_by: &'static str,
}

/// I-01 … I-12, in order, transcribed 2026-09-02 from `docs/02-architecture.md` §3.
pub const INVARIANTS: [Invariant; 12] = [
    Invariant {
        id: "I-01",
        statement: "No active identity, no action. Every action carries a verifiable AAE (P1) with a valid, unrevoked SPIFFE SVID.",
        enforced_primarily_by: "I1, all components check AAE",
    },
    Invariant {
        id: "I-02",
        statement: "No authority expansion. The intersection of authorities in the delegation chain is the maximum authority; never the union.",
        enforced_primarily_by: "I1, R3, MADE (P10)",
    },
    Invariant {
        id: "I-03",
        statement: "Purpose-bound data use. Data tagged with a purpose in CPE (P3) is only used for that purpose; violation fails-closed.",
        enforced_primarily_by: "(future context comps), all egress paths",
    },
    Invariant {
        id: "I-04",
        statement: "No consequential action without current policy. Policy is re-evaluated at commit time, not just at start.",
        enforced_primarily_by: "R5, R6, R3",
    },
    Invariant {
        id: "I-05",
        statement: "Revocation latency is bounded. Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in <1s.",
        enforced_primarily_by: "I1, R4",
    },
    Invariant {
        id: "I-06",
        statement: "Artifact identity is exact. A model/skill/dataset is identified by its content digest, not its name or URI.",
        enforced_primarily_by: "T1, S1, S4, AATM (P6)",
    },
    Invariant {
        id: "I-07",
        statement: "Evidence precedes commitment. The AAR (P2) is signed *before* the action's effect is visible; the action only commits once evidence is durable.",
        enforced_primarily_by: "E1, R3, R4",
    },
    Invariant {
        id: "I-08",
        statement: "Critical actions require non-delegable human authority. A defined class of actions (financial transfer, destructive op, physical actuation) require a human approval in the chain.",
        enforced_primarily_by: "R3, R5, I1",
    },
    Invariant {
        id: "I-09",
        statement: "Failure is safe. If any plane fails open, the action fails closed. Network loss to I1 = deny.",
        enforced_primarily_by: "All",
    },
    Invariant {
        id: "I-10",
        statement: "Replay is detectable. Every action carries a nonce + timestamp; replays outside the window are rejected.",
        enforced_primarily_by: "I1, all RPCs",
    },
    Invariant {
        id: "I-11",
        statement: "Self-change is governed. An agent cannot modify its own enforcement boundary, policy, or identity.",
        enforced_primarily_by: "R1, R2, R8, R5",
    },
    Invariant {
        id: "I-12",
        statement: "Physical systems can reach a safe state. For any cyber-physical action, there exists a kill path to a known-safe state.",
        enforced_primarily_by: "R3, (future physical authority), R4",
    },
];

/// Look up an invariant by id. Panics on an unknown id, which can only be a typo in a suite.
pub fn invariant(id: &str) -> &'static Invariant {
    INVARIANTS
        .iter()
        .find(|i| i.id == id)
        .unwrap_or_else(|| panic!("no such invariant: {id}"))
}

/// Parse the architecture doc's §3 table into `(id, statement, enforced_by)` rows.
///
/// Deliberately not a general Markdown parser: it matches the exact row shape the doc uses, so a
/// reformatting of that table is a failure here rather than a silent no-op.
fn doc_rows() -> Vec<(String, String, String)> {
    let doc = harness::read_repository_file("docs/02-architecture.md");
    let mut rows = Vec::new();
    for line in doc.lines() {
        let line = line.trim();
        if !line.starts_with("| **I-") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split(" | ").collect();
        assert_eq!(
            cells.len(),
            3,
            "the invariant table row does not have three cells: {line}"
        );
        rows.push((
            cells[0].trim().replace("**", ""),
            cells[1].trim().replace("**", ""),
            cells[2].trim().replace("**", ""),
        ));
    }
    rows
}

#[test]
fn statements_match_the_architecture_doc() {
    let rows = doc_rows();
    assert_eq!(
        rows.len(),
        INVARIANTS.len(),
        "docs/02-architecture.md publishes {} invariants, the corpus transcribes {}",
        rows.len(),
        INVARIANTS.len()
    );
    for (transcribed, (doc_id, doc_statement, doc_enforced_by)) in INVARIANTS.iter().zip(rows) {
        assert_eq!(transcribed.id, doc_id, "invariant ids are out of order");
        assert_eq!(
            transcribed.statement, doc_statement,
            "{}: the corpus tests a statement the architecture doc does not make. Reconcile the \
             two; do not soften the fixture.",
            transcribed.id
        );
        assert_eq!(
            transcribed.enforced_primarily_by, doc_enforced_by,
            "{}: the doc changed which components enforce this",
            transcribed.id
        );
    }
}

#[test]
fn every_invariant_has_a_suite_module() {
    // The corpus promises one suite per invariant. This reads the directory rather than a list,
    // so deleting a suite file is a failure here and not a quietly smaller corpus.
    let directory = harness::repository_root().join("rust/warrant/tests/invariants");
    let files: Vec<String> = std::fs::read_dir(&directory)
        .expect("the invariants directory is readable")
        .map(|entry| {
            entry
                .expect("readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for invariant in &INVARIANTS {
        let prefix = format!("i{}_", invariant.id.trim_start_matches("I-"));
        assert!(
            files.iter().any(|name| name.starts_with(&prefix)),
            "{} has no suite file (expected one named {prefix}*.rs in {})",
            invariant.id,
            directory.display()
        );
    }
}
