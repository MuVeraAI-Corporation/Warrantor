//! `nvtrust-verify` CLI.

use aumos_nvtrust_bridge::{AttestationReport, MockBackend, NvTrustBackend};
use clap::{Parser, Subcommand};
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(
    name = "nvtrust-verify",
    version,
    about = "Verify NVIDIA GPU attestation reports (Mock backend in Wave-1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify an attestation report from a JSON file (or stdin if `--path -`).
    Verify {
        /// Path to a JSON report, or `-` for stdin.
        #[arg(long, default_value = "-")]
        path: String,
    },
    /// Print the detected GPU / backend status.
    Status,
    /// Issue a mock attestation (CI/dev use only).
    IssueMock {
        /// Nonce as 32 hex chars (16 bytes). Defaults to all-zeros.
        #[arg(long)]
        nonce_hex: Option<String>,
    },
}

fn read_input(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn main() {
    let cli = Cli::parse();
    let backend = MockBackend::default();
    match cli.command {
        Commands::Status => {
            println!("nvtrust-verify: MockBackend active (gpu_model={})", backend.gpu_model);
            println!("note: Real backend is NDA-gated; see RFC C1-1");
        }
        Commands::Verify { path } => {
            let bytes = match read_input(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("nvtrust-verify: read {path} failed: {e}");
                    std::process::exit(2);
                }
            };
            let report: AttestationReport = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("nvtrust-verify: JSON decode failed: {e}");
                    std::process::exit(2);
                }
            };
            match backend.verify(&report) {
                Ok(()) => {
                    println!("valid=true backend=mock gpu_model={}", report.gpu_model);
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("valid=false reason={e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::IssueMock { nonce_hex } => {
            let nonce = match nonce_hex {
                Some(h) => match hex::decode(h.trim()) {
                    Ok(v) if v.len() == 16 => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&v);
                        a
                    }
                    Ok(v) => {
                        eprintln!("nvtrust-verify: --nonce-hex must be 16 bytes (32 hex chars), got {}", v.len());
                        std::process::exit(2);
                    }
                    Err(e) => {
                        eprintln!("nvtrust-verify: --nonce-hex decode: {e}");
                        std::process::exit(2);
                    }
                },
                None => [0u8; 16],
            };
            match backend.attest(nonce) {
                Ok(report) => {
                    let json = serde_json::to_string_pretty(&report).expect("serialize");
                    println!("{json}");
                }
                Err(e) => {
                    eprintln!("nvtrust-verify: issue-mock failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
