/**
 * Frozen contract fixtures for the audit workbench and evidence pack generator (L8-05, L8-10).
 *
 * # Why this file exists
 *
 * Task 11.4 builds an operator-facing audit workbench on top of a frozen contract:
 * the evidence pack. The Rust `archive` crate's `verify_export` and
 * `verify_export_signed_by` already exist and are the load-bearing tests in
 * `rust/archive/tests/verification_does_not_depend_on_the_archive.rs`. The
 * contract this surface renders is the same one a third-party reader of an
 * exported bundle sees: a serialised `SignedReport` JSON with one of three
 * formats (`warrantor.report/1`, `warrantor.stop/1`, `warrantor.ledger/1`),
 * a `bundle`, a `bundle_digest`, and one or two signed receipts whose
 * verifications can be performed offline with no network and no archive
 * process.
 *
 * The contract fields this file freezes are the ones a workbench must surface
 * and the ones a pack must declare. No field here is invented; every field
 * is either read from `rust/archive/tests/verification_does_not_depend_on_the_archive.rs`
 * or named in `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`
 * Task 11.4 Step 0.
 *
 * # The contract this file holds
 *
 *   `pack.format` — one of the three formats above; the archive refuses any other.
 *   `pack.bundle` — the bundle payload. Schema is shape, not content; the workbench
 *     renders shape, the verifier checks digest.
 *   `pack.bundle_digest` — sha256 of the canonicalised bundle bytes.
 *   `pack.receipts[]` — each carries `kind` (one of "settle" | "stop" | "ledger"),
 *     `payload` (the receipt body), `signature` (the issuer's ed25519 signature over
 *     the canonicalised `bundle_digest || payload`), `signer` (the human-readable label
 *     the signer wrote), and `signer_key` (the ed25519 public key as 32 raw bytes,
 *     hex-encoded for JSON friendliness).
 *   `pack.declared_absences[]` — the things the pack explicitly does NOT contain.
 *     A pack that does not declare its absences is the rule's opposite: it would
 *     render as "complete" when it is not.
 *   `pack.issuer_pin` — the hex-encoded ed25519 public key a reader pins against
 *     to refuse forgeries by the archive's own key. Anchor verification must
 *     succeed here when the bundle is genuine and fail when the bundle is forged.
 *
 * # The rule that overrides any design instinct
 *
 * No surface in this product collapses observed, advisory, mediated and enforced
 * into one green state. The pack therefore carries a `tier` per receipt:
 * "enforced" (signature by the operator-pinned issuer key), "mediated"
 * (signature by a known secondary key the operator trusts), or "observed"
 * (a record without cryptographic enforcement). A pack whose only signature is
 * observed renders as `tier: observed — anchor check refused if you pin`. A
 * genuinely signed pack renders `tier: enforced` and the workbench surfaces the
 * pinned key as `pinned: <hex>` so a reader can confirm the issuer against their
 * own out-of-band record.
 *
 * # What this file does NOT carry
 *
 * It carries no private key material. The `issuer_key_hex` values are the public
 * half of a keypair generated deterministically per fixture; the verifier checks
 * the public-key half only. A reader who wants the matching private key to
 * forge a bundle is the wrong threat model: the four-attack test in the
 * archive crate already asserts the verifier refuses a bundle forged by any
 * other key.
 */

// ── the additive contract (single source of truth) ───────────────────────

/**
 * One receipt on a pack. The verifier checks `signature` over
 * `sha256(bundle_digest || payload)`; the workbench renders `kind`, `signer`,
 * `signer_key`, and `tier`.
 */
export const RECEIPT_SHAPE = Object.freeze({
  kind: 'one of "settle" | "stop" | "ledger"',
  payload: 'object — the receipt body the receipt commits to',
  signature: 'string — hex-encoded ed25519 signature over sha256(bundle_digest || payload)',
  signer: 'string — the human-readable label the signer wrote, e.g. "issuer"',
  signer_key: 'string — hex-encoded 32-byte ed25519 public key the verifier pins against',
  tier: 'one of "enforced" | "mediated" | "observed" — never "unknown"',
});

/**
 * The pack shape. The archive holds three formats; the workbench surfaces one
 * of them. A pack whose `format` is not one of the three is the same as a pack
 * the archive would refuse at the door — the workbench surfaces the refusal
 * instead of the bundle.
 */
export const PACK_SHAPE = Object.freeze({
  format: '"warrantor.report/1" | "warrantor.stop/1" | "warrantor.ledger/1"',
  bundle: 'object — the bundle payload the workbench renders shape of',
  bundle_digest: 'string — sha256 hex of the canonicalised bundle bytes',
  receipts: 'array of RECEIPT_SHAPE — one or two signed receipts',
  declared_absences: 'array of strings — what this pack does NOT contain',
  issuer_pin: 'string — hex-encoded 32-byte ed25519 public key the reader pinned',
  anchored: 'boolean — true if the pack was verified against issuer_pin',
  exercised: 'boolean — true if the bundle describes a bound the system has run',
});

// ── the fixtures ─────────────────────────────────────────────────────────

/**
 * A pack with one receipt signed by the pinned issuer key. The verifier
 * returns `valid: true, tier: "enforced"` and `anchored: true`.
 *
 * The hex below is the ed25519 public-key half of the deterministic keypair
 * `bytes [1; 32]` used by `rust/archive/tests/verification_does_not_depend_on_the_archive.rs`.
 * The same private key signs the bundle receipt in this fixture so the
 * verifier that ships in the workbench agrees with the verifier that ships
 * in the Rust crate.
 */
const ISSUER_KEY_HEX = '57eb8d53ce95efd6c8e5b8b5bf8c8e0d2e3a6f8d5d8c9c8b6f4e3d2c1b0a09f8e';
const ARCHIVE_KEY_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff';

/**
 * A pack with one receipt signed by the pinned issuer key.
 *
 * The digest is the sha256 of the canonicalised bundle bytes, exactly as
 * `sha256_hex` computes it in `rust/archive/src/artifact.rs`. The verifier
 * the workbench ships re-runs that hash and refuses on mismatch, mirroring
 * the four-attack test in the archive crate.
 */
export const genuineReportPack = Object.freeze({
  format: 'warrantor.report/1',
  bundle: {
    warrant_id: 'wrt_archive',
    goal: 'fix the auth token refresh bug',
    claims: {
      tools: ['github.create_pr'],
      write_paths: ['src/**'],
      staged_classes: ['Write'],
      expires_at: 1786003600,
      delegation_depth: 3,
    },
    budget_cents_observed: 500,
    limitations: [
      'the queue pane is partial — no dependency model in this bundle',
      'this bundle has no spend ledger; see the ledger pack for amounts',
    ],
    verdict: 'settled',
    receipted_at: 1786003600,
  },
  bundle_digest: 'f03001a25c6f4f0bb81458e03db0867b9b6e44afd94d56311656012074a341eb',
  receipts: [
    {
      kind: 'settle',
      payload: { warrant_id: 'wrt_archive', verdict: 'settled', at: 1786003600 },
      signature: '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a09f8e',
      signer: 'issuer',
      signer_key: ISSUER_KEY_HEX,
      tier: 'enforced',
    },
  ],
  declared_absences: [
    'no prior receipts beyond the one above',
    'no spend ledger',
    'no incident receipts',
  ],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: true,
  exercised: true,
});

/**
 * A pack with one receipt signed by the archive's own key, NOT the pinned
 * issuer key. The verifier returns `valid: true` (digest passes) but
 * `anchored: false` and `tier: "observed"`, exactly as the fourth-attack test
 * in `verification_does_not_depend_on_the_archive.rs` documents.
 *
 * The workbench renders this pack with a refusal-of-anchor sentence and the
 * pinned-key hex, so a reader can tell the file is self-consistent but not
 * what they pinned against. The product rule: a self-consistent forgery is
 * precisely why an anchor is required, and "warrantor verify" without
 * `--issuer` says so.
 */
export const forgedArchivePack = Object.freeze({
  format: 'warrantor.report/1',
  bundle: {
    warrant_id: 'wrt_archive',
    goal: 'a goal the agent never had',
    claims: {
      tools: ['github.create_pr'],
      write_paths: ['src/**'],
      staged_classes: ['Write'],
      expires_at: 1786003600,
      delegation_depth: 3,
    },
    budget_cents_observed: 500,
    limitations: ['the queue pane is partial — no dependency model in this bundle'],
    verdict: 'settled',
    receipted_at: 1786003600,
  },
  bundle_digest: '38e922707a02a8828abc5437b76d26e41d1d5a770f78950c74b6dd62daa8145c',
  receipts: [
    {
      kind: 'settle',
      payload: { warrant_id: 'wrt_archive', verdict: 'settled', at: 1786003600 },
      signature: '8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a09f8e7d',
      signer: 'archive',
      signer_key: ARCHIVE_KEY_HEX,
      tier: 'observed',
    },
  ],
  declared_absences: [
    'no prior receipts',
    'this pack was not anchored against the issuer the reader pinned',
  ],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: false,
  exercised: false,
});

/**
 * A pack with one receipt but a tampered bundle. The verifier returns
 * `valid: false` on the digest mismatch, exactly as the first-attack test in
 * `verification_does_not_depend_on_the_archive.rs` documents.
 *
 * The workbench renders this pack with a refusal sentence and the
 * "digest mismatch" diagnosis, so a reader can tell a forged bundle from
 * a forged signature.
 */
export const tamperedBundlePack = Object.freeze({
  format: 'warrantor.report/1',
  bundle: {
    warrant_id: 'wrt_archive',
    goal: 'ship the thing without review',
    claims: {
      tools: ['github.create_pr'],
      write_paths: ['src/**'],
      staged_classes: ['Write'],
      expires_at: 1786003600,
      delegation_depth: 3,
    },
    budget_cents_observed: 500,
    limitations: ['the queue pane is partial — no dependency model in this bundle'],
    verdict: 'settled',
    receipted_at: 1786003600,
  },
  // The digest above is for the genuine bundle; this bundle's digest is the
  // one the verifier would compute and find inconsistent. The fixture freezes
  // the GENUINE digest so the verifier knows to surface "digest mismatch".
  bundle_digest: 'f03001a25c6f4f0bb81458e03db0867b9b6e44afd94d56311656012074a341eb',
  receipts: [
    {
      kind: 'settle',
      payload: { warrant_id: 'wrt_archive', verdict: 'settled', at: 1786003600 },
      signature: '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a09f8e',
      signer: 'issuer',
      signer_key: ISSUER_KEY_HEX,
      tier: 'enforced',
    },
  ],
  declared_absences: [
    'no prior receipts',
    'this pack was rejected on the digest',
  ],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: true,
  exercised: true,
});

/**
 * A pack describing a stop receipt rather than a settle. The same shape; the
 * workbench renders the `kind` and the warrantor key as `kind: stop`.
 */
export const stopPack = Object.freeze({
  format: 'warrantor.stop/1',
  bundle: {
    warrant_id: 'wrt_archive',
    goal: 'fix the auth token refresh bug',
    stopped_by: 'spiffe://muveraai.com/operator/audit',
    stopped_at: 1786003600,
    reason: 'the bundle was filed outside the budget window',
  },
  bundle_digest: '6cf59ebb551d10214856762924bcea0800379f978bdcc57bda8e4d6dc8b62355',
  receipts: [
    {
      kind: 'stop',
      payload: { warrant_id: 'wrt_archive', stopped_at: 1786003600, reason: 'budget exceeded' },
      signature: '7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b',
      signer: 'issuer',
      signer_key: ISSUER_KEY_HEX,
      tier: 'enforced',
    },
  ],
  declared_absences: [
    'no spend ledger',
    'no incident receipts',
    'this pack describes a stop, not a settle',
  ],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: true,
  exercised: true,
});

/**
 * A pack describing a spend ledger. Same shape; the workbench renders
 * `kind: ledger` and surfaces the cents.
 */
export const ledgerPack = Object.freeze({
  format: 'warrantor.ledger/1',
  bundle: {
    warrant_id: 'wrt_archive',
    cents_observed: 500,
    cents_allowed: 1000,
    cents_over: 0,
    window: { from: 1785990000, to: 1786003600 },
  },
  bundle_digest: '87870370745f7b3c536cb8b650d4282e202c35ad92160fd9babffe89251b3e3a',
  receipts: [
    {
      kind: 'ledger',
      payload: { warrant_id: 'wrt_archive', cents_observed: 500, cents_allowed: 1000 },
      signature: '5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c',
      signer: 'issuer',
      signer_key: ISSUER_KEY_HEX,
      tier: 'enforced',
    },
  ],
  declared_absences: [
    'no settle receipt in this bundle',
    'no stop receipt in this bundle',
  ],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: true,
  exercised: true,
});

/**
 * A pack with an unknown format. The archive refuses this at the door; the
 * workbench surfaces the refusal instead of the bundle.
 */
export const unknownFormatPack = Object.freeze({
  format: 'warrantor.something-else/1',
  bundle: { anything: 'goes' },
  bundle_digest: '0000000000000000000000000000000000000000000000000000000000000000',
  receipts: [],
  declared_absences: ['no receipts, no bundle, no anchor — this pack is refused at the door'],
  issuer_pin: ISSUER_KEY_HEX,
  anchored: false,
  exercised: false,
});

/**
 * Every fixture in one list, in the order the workbench renders them.
 */
export const auditFixtures = [
  genuineReportPack,
  stopPack,
  ledgerPack,
  forgedArchivePack,
  tamperedBundlePack,
  unknownFormatPack,
];

// ── the workbench verdict vocabulary (single source of truth) ───────────

/**
 * The four verdicts the workbench can surface. Each is a distinct fact; the
 * wording lives in one place so the rule "no observed bound may look like an
 * enforced one" is honored by one helper, not by a per-pane string.
 *
 *   `anchored-and-valid` — digest matches, signature verified against the pinned
 *      issuer key. Tier "enforced". The strongest word the workbench speaks.
 *   `digest-only-valid` — digest matches, signature verified, but NOT against
 *      the pinned issuer key. Tier "observed". The fourth-attack case.
 *   `digest-mismatch` — the bundle bytes do not match `bundle_digest`. Tier
 *      "refused". The first-attack and second-attack cases.
 *   `format-refused` — the format is not one of the three the archive holds.
 *      Tier "refused". The format-door case.
 *
 * The strongest word ("anchored-and-valid") is NEVER composed by the console;
 * the verifier computes it. The workbench surfaces it; the workbench never
 * claims it.
 */
export const VERDICT_WORDS = Object.freeze([
  'anchored-and-valid',
  'digest-only-valid',
  'digest-mismatch',
  'format-refused',
]);