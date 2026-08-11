//! `trust-core` CLI entrypoint.
//!
//! Subcommands: `key-gen`, `sign`, `verify`, `notarize`.
//! `key-gen`, `sign`, `verify` are fully wired (local Ed25519 keys).
//! `notarize` records the signature in the Rekor transparency log via the
//! [`warrantor_trust_core::rekor::RekorClient`] (public Rekor by default).

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(
    name = "trust-core",
    version,
    about = "AumOS trusted core — sign and verify"
)]
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
    /// Sign and record in the Rekor transparency log via [RekorClient].
    Notarize {
        /// Hex-encoded signing key (64 hex chars).
        #[arg(long)]
        key: String,
        /// Rekor base URL (defaults to the public instance https://rekor.sigstore.dev).
        #[arg(long, default_value = warrantor_trust_core::rekor::DEFAULT_REKOR_BASE_URL)]
        rekor_url: String,
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
            println!(
                "verifying_key_hex={}",
                hex::encode(sk.verifying_key().to_bytes())
            );
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
        Commands::Notarize { key, rekor_url } => {
            let key_arr = match decode_hex_32(&key) {
                Ok(a) => a,
                Err(e) => fail(e),
            };
            let payload = match read_stdin_to_bytes() {
                Ok(b) => b,
                Err(e) => fail(format!("read stdin: {e}")),
            };
            let sk = SigningKey::from_bytes(&key_arr);
            // Sign the DIGEST, not the payload. A `hashedrekord` entry deliberately never
            // carries the payload -- that is what keeps the notarized artifact private --
            // so Rekor can only verify the signature against the digest it was given.
            // Signing the payload produces a signature Rekor rejects with
            // "ed25519: invalid signature", which reads like a key problem and is not.
            // Ed25519ph, not Ed25519-over-a-digest. RFC 8032 5.1 prehashed mode applies
            // domain separation, so the two produce DIFFERENT signatures and Rekor accepts
            // only the former. Context is empty, matching sigstore.
            let mut prehash = Sha512::new();
            prehash.update(&payload);
            let sig: Signature = match sk.sign_prehashed(prehash, None) {
                Ok(s) => s,
                Err(e) => fail(format!("ed25519ph sign: {e}")),
            };
            let vk = sk.verifying_key();
            let sig_hex = hex::encode(sig.to_bytes());
            let vk_hex = hex::encode(vk.to_bytes());
            println!("signature_hex={sig_hex}");
            println!("verifying_key_hex={vk_hex}");

            // Record the signature on Rekor. The public endpoint is HTTPS; the
            // bundled StdTransport is plaintext TCP and will not be able to
            // reach it directly — for production notarization supply a TLS-
            // capable transport (e.g. via reqwest) by building RekorClient with
            // `with_transport`. Here we attempt the call and report the typed
            // error if the transport cannot reach the endpoint.
            let client = warrantor_trust_core::rekor::RekorClient::with_base_url(&rekor_url);
            eprintln!("notarize: posting to {} ...", client.base_url());
            match client.notarize(&payload, sig.to_bytes().as_ref(), vk.to_bytes().as_ref()) {
                Ok(entry) => {
                    println!("rekor_log_id={}", entry.log_id);
                    println!("rekor_log_index={}", entry.log_index);
                    println!("rekor_integrated_time={}", entry.integrated_time);
                    if let Some(uuid) = &entry.uuid {
                        println!("rekor_uuid={uuid}");
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("notarize: rekor error: {e}");
                    std::process::exit(3);
                }
            }
        }
    }
}
