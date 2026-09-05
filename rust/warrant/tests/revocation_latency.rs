//! I-05's identity half, measured. An SLA nobody measures is a sentence.
//!
//! The bound this asserts is [`warrantor_warrant::IDENTITY_REVOCATION_SLA`] (5 s, from
//! `docs/02-architecture.md:84`). Two numbers are recorded, because wall-clock alone is gameable by
//! a fast disk: the elapsed nanoseconds, and `adjudications_between` — how many verdicts this
//! process computed between the revocation reaching disk and the first refusal. The blueprint asks
//! for "execution counts", and zero is the only defensible value for a single-process store.
//!
//! **What these tests do not establish.** Nothing here measures propagation to a second process or
//! a second machine, because this build has no fan-out. The measurement is this process's own.

use std::path::PathBuf;
use std::time::Duration;

use warrantor_warrant::revoke::{measure, RevocationLatency, RevocationSource, RevocationStore};
use warrantor_warrant::IDENTITY_REVOCATION_SLA;

const SUBJECT: &str = "spiffe://muveraai.com/agent/local";

/// A scratch store root under the system temp dir, never inside the repository: a concurrent
/// lane's `cargo` must not be able to race this journal.
fn scratch_root(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-revocation-latency-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("scratch root");
    path
}

#[test]
fn the_measured_propagation_latency_is_inside_the_stated_sla() {
    let root = scratch_root("within-sla");
    let mut store = RevocationStore::open(&root).expect("a fresh store opens");

    let record = store.revoke(SUBJECT).expect("revoke succeeds");
    let latency = store.latency(&record);

    assert!(
        latency.within_sla,
        "measured propagation was {:?}, over the stated SLA of {IDENTITY_REVOCATION_SLA:?}. \
         Do not raise the SLA to make this pass.",
        Duration::from_nanos(latency.elapsed_nanos as u64),
    );
    assert_eq!(
        latency.adjudications_between, 0,
        "a verdict was computed between the revocation reaching disk and the first refusal, so \
         an action was adjudicated against a stale revocation set",
    );
    assert_eq!(latency.sla_nanos, IDENTITY_REVOCATION_SLA.as_nanos());
}

/// A source that takes longer than the SLA to answer. The point is not that a real disk would: it
/// is that if one did, the measurement must FAIL rather than round the number down. An SLA that
/// cannot be seen to break is not measured.
struct SlowSource {
    delay: Duration,
}

impl RevocationSource for SlowSource {
    fn revoked_svids(&self) -> Vec<String> {
        std::thread::sleep(self.delay);
        vec![SUBJECT.to_string()]
    }
}

#[test]
fn a_propagation_slower_than_the_sla_fails_the_measurement() {
    // CONTROL: a source inside the budget measures within_sla == true. Without this half, a
    // measurement function that returned `within_sla: false` unconditionally would pass the
    // breach half and prove nothing.
    let fast: RevocationLatency = measure(&SlowSource {
        delay: Duration::from_millis(10),
    });
    assert!(
        fast.within_sla,
        "the CONTROL breached the SLA, so this test proves nothing about the breach case. \
         Measured {:?} against {IDENTITY_REVOCATION_SLA:?}.",
        Duration::from_nanos(fast.elapsed_nanos as u64),
    );

    // BREACH: over the budget. `within_sla` must be false, and the value must be the real one.
    let slow: RevocationLatency = measure(&SlowSource {
        delay: IDENTITY_REVOCATION_SLA + Duration::from_millis(250),
    });
    assert!(
        !slow.within_sla,
        "a source slower than the SLA was reported as inside it"
    );
    assert!(
        slow.elapsed_nanos > IDENTITY_REVOCATION_SLA.as_nanos(),
        "the breach must be recorded at its real magnitude, not clamped to the bound: \
         {} nanos against a bound of {}",
        slow.elapsed_nanos,
        IDENTITY_REVOCATION_SLA.as_nanos(),
    );
}

#[test]
fn the_evidence_record_names_what_the_measurement_does_not_cover() {
    let record = warrantor_warrant::revoke::latency_evidence();
    assert_eq!(record.format, "warrantor.revocation-latency/1");
    assert_eq!(
        record.enforcement_points, 2,
        "there are two decision points in this build: the notary identity gate and the egress \
         broker. Counting one would hide that the second does not consult revocation at all.",
    );
    assert_eq!(
        record.enforcement_points_consulting_revocation, 1,
        "only report.rs's notary call consults the revocation set; egress::decide takes no \
         revocation input (Task 7.7)",
    );
    assert!(
        record
            .not_covered
            .iter()
            .any(|line| line.contains("does not propagate")),
        "the record must name the absence of fan-out, or it reads as a fleet measurement: {:?}",
        record.not_covered,
    );
    // Added 2026-09-05 after review. The unit of revocation here is the STORE, not the machine:
    // `--root` is accepted on every command and each root holds its own journal, so a record naming
    // only machines and processes lets a multi-root operator read a store-scoped measurement as a
    // host-wide one.
    assert!(
        record
            .not_covered
            .iter()
            .any(|line| line.contains("second store on the SAME machine")),
        "the record must say the revoked set does not reach a second store on the same machine, or \
         a store-scoped bound reads as a machine-scoped one: {:?}",
        record.not_covered,
    );
}

/// The committed evidence file must equal the code that states the bound.
///
/// A rendered number nothing gates against its record is a number that drifts: someone edits the
/// JSON, or edits the constant, and the two disagree silently until a reader trusts the wrong one.
/// Regenerate with `warrantor revoke --write-evidence evidence/revocation-latency.json`.
#[test]
fn the_committed_evidence_file_matches_the_code_that_states_the_bound() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("evidence")
        .join("revocation-latency.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let on_disk: warrantor_warrant::revoke::LatencyEvidence =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert_eq!(
        on_disk,
        warrantor_warrant::revoke::latency_evidence(),
        "{} disagrees with `revoke::latency_evidence()`. Do not edit the file by hand; run \
         `warrantor revoke --write-evidence evidence/revocation-latency.json`.",
        path.display(),
    );
}
