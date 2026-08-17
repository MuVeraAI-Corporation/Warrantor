//! The one test that opens a socket, and it is `#[ignore]`d.
//!
//! `tests/serve.rs` opens none, deliberately: a socket-loop bug must not be able to mask an
//! authorization bug, and a suite that binds ports is a suite that fails in a sandbox, in a
//! container with a port already taken, and on a machine where a firewall prompt is waiting for a
//! human. All of that still holds — which is why this file does not run by default.
//!
//! But the accept loop is real code with a real way to be wrong. It puts the listener in
//! non-blocking mode so Ctrl-C is answered without waiting for the next client, and an accepted
//! socket inherits that mode on Windows and the BSDs and not on Linux; getting that restoration
//! wrong produces a server that works in the unit tests, passes review, and returns nothing at all
//! to the first person who curls it. So the check exists, and it is committed rather than done once
//! by hand and forgotten:
//!
//! ```text
//! cargo test -p warrantor-warrant --test serve_socket -- --ignored
//! ```
//!
//! It binds a fixed high port on loopback. Run it when you touch [`listen`], the shutdown path, or
//! anything about how a connection is read.
//!
//! [`listen`]: warrantor_warrant::serve::listen

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;

use ed25519_dalek::SigningKey;
use warrantor_warrant::serve::{listen, no_adapter, Drain, SessionToken, Shutdown, StoreApi};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// Fixed rather than ephemeral: `listen` does not hand back the bound address, because a server
/// that chose its own port would be a server whose operator cannot write down a URL.
const PORT: u16 = 18787;

fn now() -> u64 {
    NOW
}

fn seed(dir: &Path, id: &str) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        "fix the auth bug",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    WarrantStore::open(dir)
        .expect("store")
        .save(&StoredWarrant {
            warrant,
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: None,
        })
        .expect("save");
}

/// One request, one connection — which is all the server offers: it closes every connection.
fn request(target: &str, token: Option<&str>) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", PORT)).expect("connect");
    let auth = token.map_or(String::new(), |t| format!("authorization: Bearer {t}\r\n"));
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nhost: localhost\r\n{auth}\r\n"
    )
    .expect("write");
    stream.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).expect("status line");
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).expect("header");
        if header.trim().is_empty() {
            break;
        }
        if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().expect("a content length");
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("a body of that length");
    format!("{}{}", status.trim(), String::from_utf8_lossy(&body))
}

#[ignore = "binds a real TCP port; run with --ignored"]
#[test]
fn a_real_listener_answers_and_a_shutdown_stops_it_without_cutting_anything_off() {
    let dir = std::env::temp_dir().join(format!(
        "warrantor-socket-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    seed(&dir, "wrt_socket");

    let api = StoreApi::new(
        WarrantStore::open(&dir).expect("store"),
        dir.clone(),
        SigningKey::from_bytes(&[1; 32]),
        Some(SigningKey::from_bytes(&[2; 32])),
        no_adapter,
        now,
    );
    let shutdown = Shutdown::new();
    let watched = shutdown.clone();
    let server = std::thread::spawn(move || {
        listen(
            api,
            SessionToken::from_value(TOKEN),
            format!("127.0.0.1:{PORT}").parse().expect("addr"),
            // The store root, for the operator registry and the approval policy -- read per
            // request so a revocation takes effect without a restart. This test's store has
            // neither file, which is the unscoped-session-token behaviour that predates them.
            dir.clone(),
            &watched,
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(400));

    // Sequential. Each of these is a fresh connection, because the server closes every one.
    for _ in 0..10 {
        let health = request("/v1/health", Some(TOKEN));
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    }
    let listing = request("/v1/warrants", Some(TOKEN));
    assert!(listing.contains("wrt_socket"), "{listing}");
    // The ordering property, over a real socket this time.
    let unauthenticated = request("/v1/warrants/wrt_socket", None);
    assert!(
        unauthenticated.starts_with("HTTP/1.1 401"),
        "{unauthenticated}"
    );
    let unknown = request("/v1/nope", Some(TOKEN));
    assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");

    // Concurrent, to exercise the connection cap's accounting and the one mutex.
    let concurrent: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(|| request("/v1/summary/daily", Some(TOKEN))))
        .collect();
    for handle in concurrent {
        let body = handle.join().expect("a joined request");
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    }

    let asked_at = std::time::Instant::now();
    shutdown.stop();
    let drain = server.join().expect("the server thread").expect("listen");
    let took = asked_at.elapsed();

    assert_eq!(drain, Drain::Complete, "nothing was in flight to cut off");
    assert!(
        took < std::time::Duration::from_secs(2),
        "a stop must be answered within a poll interval or two, took {took:?}"
    );
    // The listener is closed, not merely ignored.
    assert!(
        TcpStream::connect(("127.0.0.1", PORT)).is_err(),
        "the port must be released"
    );
}
