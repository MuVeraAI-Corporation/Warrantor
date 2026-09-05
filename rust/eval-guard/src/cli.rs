//! `eval-guard` CLI.
//!
//! # What `--provenance` is for, and why it has no default (Task 13.7)
//!
//! This binary is shipped: `.github/workflows/release.yml` lists it by name. Until 2026-09-05 it
//! built [`CheckResults::all_pass`] unconditionally and flipped one boolean only if `--skip` was
//! passed, so `eval-guard --agent x`, run on a laptop in no sandbox at all, printed a signed
//! Ed25519 attestation asserting that four containment boundaries held. Nothing in it was a lie
//! that a human wrote; the falsehood was the default value of an argument nobody passed.
//!
//! `--provenance` is now required and participates in the signed bytes. There is no default,
//! because the whole defect was a default. `--assume-all-pass` is required as well, and separately:
//! naming a source is not the same act as declaring that the four booleans are true without having
//! looked, and collapsing the two would let `--provenance asserted:me` quietly restore the old
//! behavior.
//!
//! What this still does NOT do is measure anything. See the crate docs.

use clap::Parser;
use ed25519_dalek::SigningKey;
use warrantor_eval_guard::{run_preflight, CheckResults, Provenance};

#[derive(Parser, Debug)]
#[command(
    name = "eval-guard",
    version,
    about = "Sign a caller-asserted sandbox boundary result, and refuse to sign a failed one"
)]
struct Cli {
    /// The agent to gate.
    #[arg(long)]
    agent: String,
    /// Who or what produced the four booleans: `measured:<probe>` or `asserted:<who>`.
    ///
    /// There is no default. A caller who cannot name a source is a caller whose signature would
    /// mean nothing, and this binary used to hand one out anyway.
    #[arg(long, value_name = "measured:<probe> | asserted:<who>")]
    provenance: String,
    /// Declare the four boundary results true without having probed them.
    ///
    /// Separate from `--provenance` on purpose: the provenance says who is speaking, this flag
    /// says that they are speaking without measurement. This crate runs no probes, so today it is
    /// the only way to reach the passing path -- and it is spelled out at the call site rather
    /// than assumed.
    #[arg(long)]
    assume_all_pass: bool,
    /// Skip the named check (for testing failure paths). One of: network, fs, process, egress.
    #[arg(long)]
    skip: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let provenance = match Provenance::parse(&cli.provenance) {
        Ok(provenance) => provenance,
        Err(error) => {
            eprintln!("eval-guard: {error}");
            std::process::exit(2);
        }
    };

    if !cli.assume_all_pass {
        eprintln!(
            "eval-guard: refusing to sign anything. This crate performs no probes (see its module \
             docs), so the four boundary results can only come from the caller -- and it will not \
             invent them. Pass --assume-all-pass to declare, on the record and inside the \
             signature, that you are asserting four boundaries you did not measure here."
        );
        std::process::exit(2);
    }

    let mut results = CheckResults::all_pass();
    match cli.skip.as_deref() {
        Some("network") => results.network_isolation = false,
        Some("fs") => results.filesystem_boundary = false,
        Some("process") => results.process_isolation = false,
        Some("egress") => results.egress_attestation = false,
        Some(other) => {
            eprintln!("eval-guard: unknown --skip value '{other}' (try network|fs|process|egress)");
            std::process::exit(2);
        }
        None => {}
    }

    let mut rng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let signing_key = SigningKey::generate(&mut rng);

    match run_preflight(&results, &provenance, &signing_key) {
        Ok(attestation) => {
            let json = serde_json::to_string_pretty(&attestation).expect("serialize");
            println!("{}", json);
            // On stderr, so it cannot be mistaken for part of the record and cannot be lost by a
            // caller that only pipes stdout into a file.
            eprintln!(
                "eval-guard: this attestation is {} by {:?} -- {}",
                attestation.provenance.word(),
                attestation.provenance.source(),
                attestation.provenance.caveat()
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!(
                "eval-guard: pre-flight FAILED for agent '{}' — {e}",
                cli.agent
            );
            eprintln!("eval-guard: REFUSING to start the agent (invariant I-09: failure is safe).");
            std::process::exit(1);
        }
    }
}
