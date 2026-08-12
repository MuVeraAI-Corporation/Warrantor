//! `eval-guard` CLI.

use clap::Parser;
use ed25519_dalek::SigningKey;
use warrantor_eval_guard::{run_preflight, CheckResults};

#[derive(Parser, Debug)]
#[command(
    name = "eval-guard",
    version,
    about = "Run sandbox boundary pre-flight checks and emit a signed SandboxAttestation"
)]
struct Cli {
    /// The agent to gate.
    #[arg(long)]
    agent: String,
    /// Skip the named check (for testing failure paths). One of: network, fs, process, egress.
    #[arg(long)]
    skip: Option<String>,
}

fn main() {
    let cli = Cli::parse();

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

    match run_preflight(&results, &signing_key) {
        Ok(attestation) => {
            let json = serde_json::to_string_pretty(&attestation).expect("serialize");
            println!("{}", json);
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
