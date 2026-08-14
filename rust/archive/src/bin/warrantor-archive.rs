//! `warrantor-archive` — the evidence archive server and its two operator verbs.
//!
//! Three verbs, in the shape `rust/warrant/src/bin/warrantor.rs` established: arguments parsed by
//! hand with no `clap`, refusals written as sentences addressed to the operator, and nothing
//! printed that a reader could mistake for a verdict.
//!
//! ```text
//! warrantor-archive migrate [--database-url <url>]
//! warrantor-archive enrol --label "Ana's laptop" [--database-url <url>]
//! warrantor-archive serve [--bind 127.0.0.1:8788] [--database-url <url>]
//! ```
//!
//! `$WARRANTOR_ARCHIVE_DATABASE_URL` supplies the URL when `--database-url` is absent. The
//! environment is preferred to a flag for the credential itself, because a flag lands in every
//! process listing on the machine — the same reason `warrantor console` refuses to pass a token in
//! an argv.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use warrantor_archive::device::{EnrolmentCode, ENROLMENT_CODE_LIFETIME_SECONDS};
use warrantor_archive::http::{self, DEFAULT_PORT};
use warrantor_archive::postgres::PostgresStore;
use warrantor_archive::store::ArchiveStore;

/// Connections served at once before the listener refuses. A hard cap rather than a queue: a hung
/// client must not be able to exhaust the process.
const MAX_CONNECTIONS: usize = 64;

/// Socket read and write timeout, per syscall.
const SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    let rest: Vec<String> = args.collect();
    let flags = parse_flags(&rest);

    match command.as_str() {
        "migrate" => cmd_migrate(&flags),
        "enrol" | "enroll" => cmd_enrol(&flags),
        "serve" => cmd_serve(&flags),
        other => fail(&format!(
            "unknown command {other:?}. warrantor-archive has three: migrate, enrol, serve."
        )),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "warrantor-archive — self-hosted, append-only custody for signed Warrantor evidence.

  warrantor-archive migrate                       apply the schema, then exit
  warrantor-archive enrol --label \"Ana's laptop\"   mint a one-time device enrolment code
  warrantor-archive serve [--bind 127.0.0.1:{DEFAULT_PORT}]

The database URL comes from --database-url or $WARRANTOR_ARCHIVE_DATABASE_URL. Prefer the
environment: a flag lands in every process listing on this machine.

This archive relays evidence. It holds no settle key, no issuer key and no grant path, and it
never serves a verdict — every reader verifies locally with `warrantor verify <file> --issuer <hex>`."
    );
    ExitCode::FAILURE
}

fn fail(message: &str) -> ExitCode {
    eprintln!("warrantor-archive: {message}");
    ExitCode::FAILURE
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `--name value` and `--name=value`, nothing else.
fn parse_flags(tokens: &[String]) -> std::collections::BTreeMap<String, String> {
    let mut flags = std::collections::BTreeMap::new();
    let mut pending: Option<String> = None;
    for token in tokens {
        if let Some(name) = token.strip_prefix("--") {
            if let Some(previous) = pending.take() {
                flags.insert(previous, "true".to_string());
            }
            match name.split_once('=') {
                Some((name, value)) => {
                    flags.insert(name.to_string(), value.to_string());
                }
                None => pending = Some(name.to_string()),
            }
        } else if let Some(name) = pending.take() {
            flags.insert(name, token.clone());
        }
    }
    if let Some(remaining) = pending {
        flags.insert(remaining, "true".to_string());
    }
    flags
}

fn database_url(flags: &std::collections::BTreeMap<String, String>) -> Result<String, String> {
    if let Some(url) = flags.get("database-url") {
        if url != "true" {
            return Ok(url.clone());
        }
        return Err("--database-url needs a value".to_string());
    }
    std::env::var("WARRANTOR_ARCHIVE_DATABASE_URL").map_err(|_| {
        "no database URL. Set $WARRANTOR_ARCHIVE_DATABASE_URL, or pass --database-url. Prefer the \
         environment variable: a flag lands in every process listing on this machine."
            .to_string()
    })
}

fn open_store(flags: &std::collections::BTreeMap<String, String>) -> Result<PostgresStore, String> {
    let url = database_url(flags)?;
    PostgresStore::connect(&url).map_err(|e| e.to_string())
}

fn cmd_migrate(flags: &std::collections::BTreeMap<String, String>) -> ExitCode {
    let store = match open_store(flags) {
        Ok(store) => store,
        Err(e) => return fail(&e),
    };
    match store.migrate() {
        Ok(applied) if applied.is_empty() => {
            println!("schema is already current; nothing was applied");
            ExitCode::SUCCESS
        }
        Ok(applied) => {
            for version in &applied {
                println!("applied  {version}");
            }
            println!(
                "\nThe artifact table is append-only: a BEFORE UPDATE OR DELETE trigger refuses, \
                 and archive_runtime holds no UPDATE or DELETE grant on it. Retention is recorded \
                 and DISABLED for every kind — an absent window grants no deletion authority."
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_enrol(flags: &std::collections::BTreeMap<String, String>) -> ExitCode {
    let Some(label) = flags.get("label").filter(|l| *l != "true") else {
        return fail("enrol needs a label: warrantor-archive enrol --label \"Ana's laptop\"");
    };
    let mut store = match open_store(flags) {
        Ok(store) => store,
        Err(e) => return fail(&e),
    };
    let code = match EnrolmentCode::mint() {
        Ok(code) => code,
        Err(e) => return fail(&e.to_string()),
    };
    let created_at = now();
    let expires_at = created_at.saturating_add(ENROLMENT_CODE_LIFETIME_SECONDS);
    if let Err(e) = store.create_enrolment_code(code.digest(), label, created_at, expires_at) {
        return fail(&e.to_string());
    }
    // Printed to stdout, once, and never written anywhere or passed into another process's argv.
    // Only its SHA-256 was stored, so this is the single moment the code exists in readable form.
    println!("enrolment code for {label:?}:\n\n  {}\n", code.code());
    println!(
        "It is single-use, expires in {} minutes, and is shown once — only its SHA-256 was stored.\n\
         The device POSTs it with its public key:\n\n  \
         POST /v1/devices/enrol  {{\"code\": \"…\", \"public_key\": \"<64 hex chars>\"}}\n\n\
         The device keeps the private half. This archive never holds one.",
        ENROLMENT_CODE_LIFETIME_SECONDS / 60
    );
    ExitCode::SUCCESS
}

fn cmd_serve(flags: &std::collections::BTreeMap<String, String>) -> ExitCode {
    let bind = flags
        .get("bind")
        .filter(|b| *b != "true")
        .cloned()
        .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));
    let addr = match bind.to_socket_addrs().map(|mut a| a.next()) {
        Ok(Some(addr)) => addr,
        _ => return fail(&format!("{bind:?} is not an address this archive can bind")),
    };
    let store = match open_store(flags) {
        Ok(store) => store,
        Err(e) => return fail(&e),
    };
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(e) => return fail(&format!("cannot bind {addr}: {e}")),
    };

    if let Some(warning) = bind_warning(addr) {
        eprintln!("{warning}");
    }
    println!("warrantor-archive listening on http://{addr}");
    println!(
        "  routes: GET /v1/health · POST /v1/evidence · GET /v1/evidence/{{sha256}} · GET \
         /v1/warrants/{{id}}/evidence · POST /v1/devices/enrol"
    );
    println!(
        "  no settle, no void, no stop, no grant: this process holds no key that could sign one."
    );

    serve_forever(store, &listener)
}

/// The warning a non-loopback bind must print, or `None` for a loopback one.
///
/// A function rather than a `println!` so the wording is testable and cannot quietly lose a clause,
/// the same shape [`warrantor_warrant::serve::bind_warning`] takes. It says plainly that a device
/// signature authenticates a request without encrypting it, because a warning that let a reader
/// infer otherwise would be worse than no warning.
#[must_use]
fn bind_warning(addr: SocketAddr) -> Option<String> {
    if addr.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "warrantor-archive: WARNING -- binding {addr}, which is NOT loopback.\n  \
         There is no TLS here. Device signatures AUTHENTICATE a request; they do not ENCRYPT it. \
         Every byte of every request and response, including the evidence itself and the label \
         naming whoever filed it, crosses the network in the clear, and anyone who can watch the \
         traffic can read all of it.\n  \
         A signature cannot be replayed -- it is bound to the method, the path, the body digest, a \
         nonce and a timestamp -- so an eavesdropper cannot resubmit a captured request. That is \
         the only thing the absence of TLS does not cost you.\n  \
         Put a TLS-terminating reverse proxy in front of this before it leaves the machine. See \
         deploy/evidence-archive/docker-compose.yml."
    ))
}

/// Thread per connection, one request each, with a hard cap.
///
/// The same shape `serve.rs` uses and for the same reasons: read outside the lock, decide inside
/// it, write outside it, so a slow client stalls only itself. No `unwrap` and no index anywhere on
/// this path — the release profile is `panic = "abort"`, so a panicking handler takes the whole
/// server down rather than failing one request.
fn serve_forever(store: PostgresStore, listener: &TcpListener) -> ExitCode {
    let store = Arc::new(Mutex::new(store));
    let live = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            let mut stream = stream;
            let _ = http::write_response(
                &mut stream,
                &http::ArchiveResponse::error(
                    warrantor_warrant::serve::status::UNAVAILABLE,
                    "too_many_connections",
                    "this archive is serving as many connections as it accepts at once",
                ),
            );
            continue;
        }
        let Ok(read_half) = stream.try_clone() else {
            continue;
        };

        live.fetch_add(1, Ordering::SeqCst);
        let slot = Slot {
            live: Arc::clone(&live),
        };
        let store = Arc::clone(&store);
        let spawned = std::thread::Builder::new()
            .name("warrantor-archive".to_string())
            .spawn(move || {
                // Released by `Drop`, so an early return cannot leak a slot and walk the server
                // down to a permanent 503.
                let _slot = slot;
                let mut input = BufReader::new(read_half);
                let mut output = stream;
                let response = match http::parse(&mut input) {
                    Ok(request) => {
                        let mut guard = match store.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        http::handle(&mut *guard, &request, now())
                    }
                    Err(response) => response,
                };
                if let Err(e) = http::write_response(&mut output, &response) {
                    eprintln!("warrantor-archive: connection: {e}");
                }
            });
        if let Err(e) = spawned {
            // Not decrementing here: `slot` moved into the closure, and a failed spawn drops it, so
            // `Slot::drop` has already released this slot. A second decrement wraps the counter and
            // the server answers 503 forever after — the exact bug `serve.rs` records having hit.
            eprintln!("warrantor-archive: could not spawn a worker: {e}");
        }
    }
    ExitCode::SUCCESS
}

struct Slot {
    live: Arc<AtomicUsize>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
