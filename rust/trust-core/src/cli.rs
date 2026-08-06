//! `trust-core` CLI entrypoint.
//!
//! Subcommands: `key-gen`, `sign`, `verify`, `notarize`.
//! Wave-1: `key-gen`, `sign`, `verify` are fully wired (local Ed25519 keys).
//! KMS / Rekor (`notarize`) lands in task 03.

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(name = "trust-core", version, about = "AumOS trusted core — sign and verify")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new Ed25519 signing key. Prints `verifying_key_hex` and `signing_key_hex`.
    /// WARNING: the signing key is printed to stdout — local dev only. KMS in task 03.
    KeyGen,
    /// Sign the payload read from stdin. `--key` is a hex-encoded 32-byte signing key.
    Sign {
        /// Hex-encoded signing key (64 hex chars).
        #[arg(long)]
        key: String,
    },
    /// Verify a signature. Payload read from stdin.
    Verify {
        /// Hex-encoded verifying key (64 hex chars).
        #[arg(long)]
        key: String,
        /// Hex-encoded signature (128 hex chars).
        #[arg(long)]
        signature: String,
    },
    /// Sign and record in the Rekor transparency log. (Stubbed — task 03.)
    Notarize {
        #[arg(long)]
        key: String,
    },
}

fn read_stdin_to_bytes() -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn decode_hex_64(s: &str) -> Result<[u8; 64], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 64 {
        return Err(format!("expected 64 bytes, got {}", v.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("trust-core: {}", msg.as_ref());
    std::process::exit(2);
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::KeyGen => {
            let mut rng = rand::rngs::OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();
            println!("verifying_key_hex={}", hex::encode(vk.to_bytes()));
            println!("signing_key_hex={}", hex::encode(sk.to_bytes()));
        }
        Commands::Sign { key } => {
            let key_arr = match decode_hex_32(&key) {
                Ok(a) => a,
                Err(e) => fail(e),
            };
            let payload = match read_stdin_to_bytes() {
                Ok(b) => b,
                Err(e) => fail(format!("read stdin: {e}")),
            };
            let sk = SigningKey::from_bytes(&key_arr);
            let sig: Signature = sk.sign(&payload);
            println!("signature_hex={}", hex::encode(sig.to_bytes()));
            println!("verifying_key_hex={}", hex::encode(sk.verifying_key().to_bytes()));
        }
        Commands::Verify { key, signature } => {
            let key_arr = match decode_hex_32(&key) {
                Ok(a) => a,
                Err(e) => fail(e),
            };
            let sig_arr = match decode_hex_64(&signature) {
                Ok(a) => a,
                Err(e) => fail(e),
            };
            let payload = match read_stdin_to_bytes() {
                Ok(b) => b,
                Err(e) => fail(format!("read stdin: {e}")),
            };
            let vk = match VerifyingKey::from_bytes(&key_arr) {
                Ok(v) => v,
                Err(_) => fail("invalid verifying key bytes"),
            };
            let sig = Signature::from_bytes(&sig_arr);
            match vk.verify(&payload, &sig) {
                Ok(()) => {
                    println!("valid=true");
                    std::process::exit(0);
                }
                Err(_) => {
                    println!("valid=false reason=signature_did_not_verify");
                    std::process::exit(1);
                }
            }
        }
        Commands::Notarize { key: _ } => {
            eprintln!("notarize: requires Rekor transparency log access (task 03). Stubbed.");
            std::process::exit(3);
        }
    }
}
