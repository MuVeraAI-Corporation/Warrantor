#![forbid(unsafe_code)]

use warrantor_gguf_ext::{
    inspect, payload_digest, rewrite_path_with_profile, strip_safety_path, verify, GgufLimits,
    SafetyManifest, TrustCoreManifestSigner, VerifyPolicy,
};
use warrantor_trust_core::signing::SigningKeyWrapper;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(name = "gguf-ext", version, about = "Bounded GGUF v3 safety tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Render concise human output instead of versioned JSON.
    #[arg(long, global = true)]
    human: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect and structurally validate a GGUF file.
    Inspect {
        /// Input GGUF path.
        input: PathBuf,
    },
    /// Compute the normalized S3 payload digest.
    Digest {
        /// Input GGUF path.
        input: PathBuf,
    },
    /// Add or replace the signed safety profile atomically.
    Sign {
        /// Input GGUF path.
        input: PathBuf,
        /// Destination GGUF path.
        output: PathBuf,
        /// RFC 8785 canonical P6 manifest path.
        #[arg(long)]
        manifest: PathBuf,
        /// Allow replacing an existing destination or the input path.
        #[arg(long)]
        replace: bool,
    },
    /// Verify structure, digests, time policy, and Ed25519 signature.
    Verify {
        /// Input GGUF path.
        input: PathBuf,
        /// Trusted current epoch seconds.
        #[arg(long)]
        now: u64,
        /// Maximum profile age in seconds.
        #[arg(long, default_value_t = 2_592_000)]
        maximum_age: u64,
        /// Permit profiles without explicit expiry.
        #[arg(long)]
        allow_missing_expiry: bool,
    },
    /// Remove all `osaf.safety.*` keys atomically.
    StripSafety {
        /// Input GGUF path.
        input: PathBuf,
        /// Destination GGUF path.
        output: PathBuf,
        /// Allow replacing an existing destination or the input path.
        #[arg(long)]
        replace: bool,
    },
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        println!(
            "{}",
            json!({
                "schema": "osaf.gguf.cli-error/1",
                "ok": false,
                "error": error,
            })
        );
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let limits = GgufLimits::default();
    match cli.command {
        Command::Inspect { input } => {
            let info = inspect(File::open(&input).map_err(display)?, &limits).map_err(display)?;
            if cli.human {
                println!(
                    "GGUF v{}: {} metadata entries, {} tensors, {} tensor-data bytes",
                    info.version,
                    info.metadata.len(),
                    info.tensors.len(),
                    info.tensor_data_length
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "schema": "osaf.gguf.inspect/1",
                        "ok": true,
                        "info": info,
                    }))
                    .map_err(display)?
                );
            }
        }
        Command::Digest { input } => {
            let digest =
                payload_digest(File::open(&input).map_err(display)?, &limits).map_err(display)?;
            let encoded = format!("sha256:{}", hex::encode(digest));
            if cli.human {
                println!("{encoded}");
            } else {
                println!(
                    "{}",
                    json!({"schema": "osaf.gguf.digest/1", "ok": true, "payload_sha256": encoded})
                );
            }
        }
        Command::Sign {
            input,
            output,
            manifest,
            replace,
        } => {
            let manifest_bytes = std::fs::read(manifest).map_err(display)?;
            let manifest = SafetyManifest::from_canonical_json(&manifest_bytes).map_err(display)?;
            let mut key_text = String::new();
            io::stdin().read_to_string(&mut key_text).map_err(display)?;
            let key_value = key_text.trim();
            if key_value.len() != 64
                || !key_value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                key_text.zeroize();
                return Err(
                    "stdin must contain exactly 64 lowercase hex signing-key characters".into(),
                );
            }
            let mut key_bytes = [0_u8; 32];
            hex::decode_to_slice(key_value, &mut key_bytes).map_err(display)?;
            key_text.zeroize();
            let signer = TrustCoreManifestSigner::new(SigningKeyWrapper::from_bytes(&key_bytes));
            key_bytes.zeroize();
            rewrite_path_with_profile(&input, &output, &manifest, &signer, &limits, replace)
                .map_err(display)?;
            print_success(cli.human, "signed", &output);
        }
        Command::Verify {
            input,
            now,
            maximum_age,
            allow_missing_expiry,
        } => {
            let mut policy = VerifyPolicy::strict(now);
            policy.maximum_age_seconds = Some(maximum_age);
            policy.require_expiry = !allow_missing_expiry;
            let mut file = File::open(input).map_err(display)?;
            let verified = verify(&mut file, &policy).map_err(display)?;
            if cli.human {
                println!(
                    "verified {} (issued {}, expires {:?})",
                    verified.payload_sha256, verified.issued_at, verified.expires_at
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "schema": "osaf.gguf.verify/1",
                        "ok": true,
                        "profile": verified,
                    }))
                    .map_err(display)?
                );
            }
        }
        Command::StripSafety {
            input,
            output,
            replace,
        } => {
            strip_safety_path(&input, &output, &limits, replace).map_err(display)?;
            print_success(cli.human, "stripped", &output);
        }
    }
    Ok(())
}

fn print_success(human: bool, operation: &str, output: &PathBuf) {
    if human {
        println!("{operation}: {}", output.display());
    } else {
        println!(
            "{}",
            json!({
                "schema": "osaf.gguf.mutation/1",
                "ok": true,
                "operation": operation,
                "output": output,
            })
        );
    }
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
