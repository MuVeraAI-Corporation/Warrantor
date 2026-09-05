# Finding: the metadata floor held for one spelling of the address

Found 2026-09-05 while expanding Task 7.1, by an agent that compiled a probe instead of trusting the
task's stated premise. Fixed on `fix/egress-metadata-floor` off `origin/main` at `e4b5f10`.

## The claim, and the mechanism behind it

`rust/egress/src/lib.rs` documents the metadata ranges as **"ALWAYS denied and NEVER
catalog-addable"**, and `DenyReason::MetadataRange` carries the same promise: *"The resolved address
is in a metadata range (169.254.0.0/16 etc.) — never catalog-addable."*

The mechanism was a case-sensitive `str::starts_with` over three prefixes, applied after stripping
exactly two lowercase URL schemes:

```rust
const METADATA_RANGES: &[&str] = &["169.254.", "fd00:", "fe80:"];

fn is_metadata_range(addr: &str) -> bool {
    let clean = addr.trim_start_matches("https://").trim_start_matches("http://");
    METADATA_RANGES.iter().any(|r| clean.starts_with(r))
}
```

The crate's own test, `metadata_range_always_denied`, asserted the rule for exactly one input:
the dotted quad `169.254.169.254`.

## What reached Allow

Measured, by putting each address in a catalog entry and calling `decide`. Eight of nine spellings
of the same hosts were allowed:

| address | what it is | before | after |
|---|---|---|---|
| `169.254.169.254` | dotted quad, the canonical form | Deny | Deny |
| `100.100.100.200` | Alibaba Cloud metadata — **absent from the list entirely** | **Allow** | Deny |
| `2852039166` | decimal integer form of the same address | **Allow** | Deny |
| `0xa9fea9fe` | hexadecimal form | **Allow** | Deny |
| `0251.0376.0251.0376` | dotted octal form | **Allow** | Deny |
| `::ffff:169.254.169.254` | IPv4-mapped IPv6 | **Allow** | Deny |
| `HTTP://169.254.169.254` | uppercase scheme; `trim_start_matches` is case-sensitive | **Allow** | Deny |
| `FE80::1` | uppercase IPv6 link-local; so is `starts_with` | **Allow** | Deny |
| `" 169.254.169.254"` | leading space, never stripped | **Allow** | Deny |

Every one of these is accepted by ordinary HTTP clients and by the OS resolver. The list also
covered only the `fd00:` half of IPv6 unique-local (`fc00::/7`).

## What this is, and what it is not

`entry.addresses` comes from the destination catalog, which an operator authors — not from the agent,
which can only name a logical endpoint. So this is **not** "an agent trivially reads cloud
credentials." It is a **claim without a mechanism**: the code states an invariant it does not
enforce, in the crate that *is* reachable from the binary and *is* in the proxy path. Two things make
that worse than a documentation error:

1. `100.100.100.200` was missing outright, so an operator on Alibaba Cloud following the spec's own
   list got no protection at all.
2. Task 1.2 is deriving per-warrant catalogs from capabilities. Once catalog entries are machine
   generated, the human review step that this defect currently hides behind disappears.

## The fix

`is_metadata_range` and `is_private_range` now normalize, then parse, then classify:

- strip whitespace, strip `http`/`https`/`ftp` schemes case-insensitively, strip bracketed IPv6 and
  a trailing `:port`, drop a trailing dot, lowercase;
- parse all four IPv4 forms — dotted quad, bare decimal, `0x` hex, dotted octal;
- unwrap IPv4-mapped and IPv4-compatible IPv6 to the IPv4 address it wraps;
- classify with real range checks: `Ipv4Addr::is_link_local`, plus `fe80::/10` and `fc00::/7` on the
  first IPv6 segment, plus an explicit list for metadata services outside any private range.

The now-dead `PRIVATE_RANGES` prefix list is removed rather than left to read as a live rule.

## Two decisions deliberately left to Task 7.1

- **Failing closed on an unparseable address.** The `addresses` field is documented as *"pre-resolved
  IPs or explicit hostnames"*, and `rust/warrant/src/egress.rs:204` puts a hostname there. Refusing
  what does not parse would refuse the shipped path. A name is now matched against a metadata
  hostname list; anything else still passes. Making the floor fail closed is L4-25's work.
- **Giving `DenyReason::PrivateRange` a mechanism.** The branch that would construct it has an
  **empty body** — a comment that reasons itself into a no-op — so "private ranges denied unless
  explicitly catalogued" has no enforcement, and three existing tests depend on a catalogued private
  address being allowed. `metadata_floor.rs` now pins that count at zero so the variant cannot be
  quietly deleted or quietly given a body.

## Bound strength

**Tier B, chokepoint.** A specific line refuses the address at the moment the broker decides, but it
binds only calls that traverse the broker. Nothing outside the process enforces it: no netns, no
seccomp, no firewall rule exists in this repository, and `rust/warrant/src/egress.rs` still reports
`enforcement_mode: "advisory"`. The floor does **not** cover an agent that opens a socket without
going through the broker, and it does not cover a DNS name that resolves to a metadata address
without appearing on the hostname list — the DNS gap is stated in `egress.rs` and is unchanged here.

## Gate output

```
cargo fmt --check                                  exit 0
cargo clippy --all-targets -- -D warnings          exit 0
cargo test --workspace -j 2                        exit 0
  134 suites, 1389 passing, 0 failed, 24 ignored   (origin/main: 133 suites, 1385 passing)
python tools/ci/wiring_census.py                   9 of 39 crates over 17 path edges — unchanged
python tools/ci/check_invariant_ratchet.py         65 passing at floor 65, 19 findings at ceiling 19
python tools/ci/check_invariants.py                12 invariants; enforced=2 orphaned=2 partial=7 unimplemented=1
```

The refusal test is paired with two allowed controls (`93.184.216.34`, `8.8.8.8`), so it cannot pass
by refusing everything.
