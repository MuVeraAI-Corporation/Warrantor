//! §2.3 — terminating TLS, behind a feature that is off by default.
//!
//! # Why this was deferred, and why the reason stopped holding
//!
//! `rust/warrant` carries seven external dependencies and no async runtime, and that posture is a
//! security property rather than a preference: the verifier and the policy engine are the smallest
//! auditable thing they can be. Adding a TLS stack to it looked like a dependency decision for the
//! owner, so [`crate::serve::bind_refusal`] shipped first — a bind beyond loopback refuses, and the
//! remedy it names is a reverse proxy.
//!
//! Then the tree was actually read. **`rustls` is already in it.** `ureq`'s `tls` feature has pulled
//! it since the archive client existed, so terminating TLS here compiles code that was already
//! being compiled and adds nothing to `Cargo.lock` but a PEM parser. The decision that was being
//! deferred had already been taken, by a client dependency, in a direction nobody wrote down.
//!
//! It is still **off by default**, because the default build of this crate should be the smallest
//! thing that can verify a receipt, and a server bound to loopback needs no TLS at all.
//!
//! # What this does not do
//!
//! **No certificate is issued, fetched, renewed or validated for name.** This loads a certificate
//! chain and a private key an operator already has, and serves with them. There is no ACME client,
//! no self-signed generator and no CA — each of those is a trust decision, and this crate's rule is
//! that it does not take those on anybody's behalf.
//!
//! A self-signed certificate works perfectly here and is the likely case on a private network. It
//! is also, from a client's point of view, indistinguishable from an attacker's until somebody
//! pins it — so [`describe`] says what was loaded rather than implying it was trusted.
//!
//! **Client certificates are not required.** Authentication is the bearer token and, since §2.2, the
//! operator registry behind it. TLS here provides confidentiality and integrity of the transport,
//! which is exactly the gap `bind_refusal` refuses over, and nothing else.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// What went wrong loading a certificate or key.
#[derive(Debug)]
pub enum TlsError {
    /// A file could not be read.
    Io {
        /// Which file.
        path: String,
        /// The OS error.
        detail: String,
    },
    /// The PEM held nothing of the kind expected.
    Empty {
        /// Which file.
        path: String,
        /// What was expected in it.
        expected: &'static str,
    },
    /// rustls refused the pair.
    Config(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, detail } => write!(f, "cannot read {path}: {detail}"),
            Self::Empty { path, expected } => write!(
                f,
                "{path} contains no {expected}. Refusing rather than serving without it: a server \
                 that started with half a TLS configuration would bind, accept connections, and \
                 fail every handshake -- which reads to a client as the server being down and to \
                 an operator as TLS being on."
            ),
            Self::Config(detail) => write!(
                f,
                "that certificate and key were not accepted: {detail}. The commonest cause is a key \
                 that does not match the certificate, which nothing detects until they are used \
                 together."
            ),
        }
    }
}

impl std::error::Error for TlsError {}

/// What was loaded, for the line an operator reads at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    /// How many certificates were in the chain.
    pub certificates: usize,
    /// The certificate path, as given.
    pub certificate_path: String,
    /// The key path, as given.
    pub key_path: String,
}

/// Build a server configuration from a PEM certificate chain and a private key.
///
/// # Errors
/// [`TlsError`] for an unreadable file, a PEM holding nothing of the expected kind, or a pair
/// rustls will not accept.
pub fn server_config(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<(Arc<ServerConfig>, Loaded), TlsError> {
    let certificate_bytes = std::fs::read(certificate_path).map_err(|e| TlsError::Io {
        path: certificate_path.display().to_string(),
        detail: e.to_string(),
    })?;
    let key_bytes = std::fs::read(key_path).map_err(|e| TlsError::Io {
        path: key_path.display().to_string(),
        detail: e.to_string(),
    })?;

    let certificates: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut certificate_bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Config(e.to_string()))?;
    if certificates.is_empty() {
        return Err(TlsError::Empty {
            path: certificate_path.display().to_string(),
            expected: "certificate",
        });
    }

    // `private_key` takes the first key of any supported kind — PKCS#8, PKCS#1 or SEC1 — so an
    // operator does not have to know which their tool emitted. A file holding several is a file
    // whose intent is ambiguous, and the first is the only defensible reading of it.
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .map_err(|e| TlsError::Config(e.to_string()))?
        .ok_or_else(|| TlsError::Empty {
            path: key_path.display().to_string(),
            expected: "private key",
        })?;

    let config = ServerConfig::builder()
        // No client certificates. Authentication here is the bearer token and the operator registry
        // behind it; requiring a client certificate as well would be a second credential system
        // solving a problem the first one already solves, and mTLS misconfigured is a server nobody
        // can reach.
        .with_no_client_auth()
        .with_single_cert(certificates.clone(), key)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok((
        Arc::new(config),
        Loaded {
            certificates: certificates.len(),
            certificate_path: certificate_path.display().to_string(),
            key_path: key_path.display().to_string(),
        },
    ))
}

/// The startup line, saying what was loaded and — carefully — what that does and does not mean.
#[must_use]
pub fn describe(loaded: &Loaded) -> String {
    format!(
        "warrantor: TLS -- serving with {} certificate(s) from {} and the key at {}.\n  \
         This encrypts the transport. It does NOT establish who this server is to a client: that \
         depends on whether the certificate chains to something the client already trusts, which is \
         a fact about the client and not about this process. A self-signed certificate works here \
         and is indistinguishable from an attacker's until somebody pins it.\n  \
         No certificate is issued, renewed or checked for name by this build.",
        loaded.certificates, loaded.certificate_path, loaded.key_path
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "warrantor-tls-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        path
    }

    #[test]
    fn a_missing_file_names_the_path_rather_than_the_operation() {
        let dir = tempdir("missing");
        let error =
            server_config(&dir.join("nope.pem"), &dir.join("nope.key")).expect_err("refuses");
        assert!(error.to_string().contains("nope.pem"), "{error}");
    }

    #[test]
    fn a_pem_with_no_certificate_is_refused_rather_than_served_around() {
        // A server that started with half a TLS configuration would bind, accept connections and
        // fail every handshake — which reads to a client as the server being down and to an
        // operator as TLS being on.
        let dir = tempdir("empty");
        std::fs::write(dir.join("cert.pem"), b"# nothing here\n").expect("write");
        std::fs::write(dir.join("key.pem"), b"# nothing here\n").expect("write");
        let error =
            server_config(&dir.join("cert.pem"), &dir.join("key.pem")).expect_err("refuses");
        let rendered = error.to_string();
        assert!(rendered.contains("no certificate"), "{rendered}");
        assert!(
            rendered.contains("reads to a client as the server being down"),
            "{rendered}"
        );
    }

    #[test]
    fn the_startup_line_never_implies_the_certificate_is_trusted() {
        // The distinction that matters on a private network, where self-signed is the likely case:
        // encrypting the transport is not establishing identity, and a line that blurred the two
        // would let an operator believe a client is authenticating this server when it is not.
        let line = describe(&Loaded {
            certificates: 2,
            certificate_path: "/etc/warrantor/fullchain.pem".into(),
            key_path: "/etc/warrantor/privkey.pem".into(),
        });
        assert!(line.contains("encrypts the transport"), "{line}");
        assert!(
            line.contains("does NOT establish who this server is"),
            "{line}"
        );
        assert!(
            line.contains("indistinguishable from an attacker's"),
            "{line}"
        );
        assert!(
            line.contains("No certificate is issued, renewed or checked for name"),
            "{line}"
        );
    }
}
