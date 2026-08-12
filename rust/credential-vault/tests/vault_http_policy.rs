//! Integration tests for the Vault backend's HTTP policy, driven against real sockets.
//!
//! Both defects these cover came from using a bare `ureq::get`, which inherits ureq's default
//! agent: five redirects with headers replayed, and no read timeout.
//!
//! * A single injected `302` sent the raw `X-Vault-Token` to an attacker-chosen origin, and the
//!   redirect target's body was then accepted as the brokered secret -- so one redirect both stole
//!   the token and chose the credential the caller received.
//! * A server that accepted the connection and never answered hung `resolve()` forever (observed
//!   still blocked after 120 seconds).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use warrantor_credential_vault::{CredentialBackend, CredentialError, HashiCorpVaultBackend};

/// Reads the request head and returns the raw header block, so a test can assert on what the
/// client actually sent (specifically: whether the Vault token came along).
fn read_request_head(stream: &mut TcpStream) -> String {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let done = line == "\r\n" || line == "\n";
        head.push_str(&line);
        if done {
            break;
        }
    }
    head
}

/// A server that answers every request with a 302 to `target`, recording whether the Vault token
/// was present on the initial request.
fn spawn_redirector(target_port: u16) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirector");
    let port = listener.local_addr().unwrap().port();
    let saw_token = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&saw_token);
    thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let Ok(mut stream) = stream else { continue };
            let head = read_request_head(&mut stream);
            if head.to_lowercase().contains("x-vault-token") {
                flag.store(true, Ordering::SeqCst);
            }
            let body = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/stolen\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, saw_token)
}

/// The attacker's sink: records whether it ever received the Vault token, and serves a
/// well-formed KV v2 body so that a client which follows the redirect returns "sink" as the
/// secret -- making a successful attack unmistakable in the assertion.
fn spawn_sink() -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let port = listener.local_addr().unwrap().port();
    let saw_token = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&saw_token);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let head = read_request_head(&mut stream);
            if head.to_lowercase().contains("x-vault-token") {
                flag.store(true, Ordering::SeqCst);
            }
            let payload = br#"{"data":{"data":{"value":"sink"}}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(payload);
            let _ = stream.flush();
        }
    });
    (port, saw_token)
}

/// Accepts the connection, reads the request, and then never replies -- the "black hole" server.
fn spawn_black_hole() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind black hole");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            // Hold the socket open without answering. Dropping it would send a FIN, which the
            // client would surface as a transport error rather than the hang we are testing.
            held.push(stream);
        }
    });
    port
}

#[test]
fn a_redirect_never_leaks_the_token_and_is_never_treated_as_a_secret() {
    let (sink_port, sink_saw_token) = spawn_sink();
    let (redirector_port, redirector_saw_token) = spawn_redirector(sink_port);

    let backend = HashiCorpVaultBackend::new(
        format!("http://127.0.0.1:{redirector_port}"),
        "warrantor-dev-root",
    );
    let result = backend.resolve("agents/coding");

    assert!(
        redirector_saw_token.load(Ordering::SeqCst),
        "sanity check: the legitimate first request should carry the token"
    );
    assert!(
        !sink_saw_token.load(Ordering::SeqCst),
        "SECURITY: the Vault token was replayed to the redirect target"
    );
    match result {
        Ok(secret) => panic!(
            "SECURITY: followed the redirect and returned the attacker's body as the secret: \
             {secret:?}"
        ),
        Err(CredentialError::BackendUnavailable(message)) => {
            assert!(
                message.contains("redirect") || message.contains("302"),
                "error should name the redirect, got: {message}"
            );
        }
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn a_server_that_never_answers_times_out_instead_of_hanging() {
    let port = spawn_black_hole();
    let timeout = Duration::from_secs(2);

    // resolve() runs on its own thread and reports back through a channel. Without a read timeout
    // it never returns, so calling it inline would hang this test -- and a hung test blocks CI
    // instead of reporting a failure. The channel converts "never returns" into a clean red.
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let backend =
            HashiCorpVaultBackend::new(format!("http://127.0.0.1:{port}"), "warrantor-dev-root")
                .with_timeout(timeout);
        let started = Instant::now();
        let result = backend.resolve("agents/coding");
        let _ = sender.send((result.is_err(), started.elapsed()));
    });

    match receiver.recv_timeout(timeout * 4) {
        Ok((is_err, elapsed)) => {
            assert!(is_err, "a black-hole server must not yield a secret");
            assert!(
                elapsed < timeout * 4,
                "resolve() took {elapsed:?}; the read timeout is not being applied"
            );
        }
        Err(_) => panic!(
            "resolve() had not returned after {:?} against a server that accepts and never \
             answers -- there is no read timeout",
            timeout * 4
        ),
    }
}

#[test]
fn the_default_timeout_is_bounded() {
    // The default must be short enough that a hung Vault does not outlive the caller's own
    // deadline; the exact value matters less than it being finite and small.
    assert!(warrantor_credential_vault::DEFAULT_VAULT_TIMEOUT <= Duration::from_secs(10));
}
