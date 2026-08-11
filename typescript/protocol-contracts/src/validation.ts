/**
 * Independent registry-driven structural, semantic, temporal, extension, and
 * signature validation for the AumOS P1-P12 wire protocols.
 *
 * This module is a generic interpreter over `specs/protocols/registry.json`.
 * It never hardcodes per-protocol structure, and it mirrors the check order,
 * error codes, and canonical signing form of
 * `rust/protocol-contracts/src/validation.rs` and
 * `python/protocol_contracts/src/protocol_contracts/validation.py` so that all
 * four implementations agree on every vector.
 *
 * The module deliberately has no runtime imports from sibling modules so that
 * it can be executed directly by Node's type-stripping loader.
 */

import { createPublicKey, verify as verifyEd25519, type KeyObject } from 'node:crypto';

/** Stable validation error identifiers from `specs/protocols/errors.json`. */
export type ErrorCode =
  | 'MALFORMED_DOCUMENT'
  | 'COMMON_SCHEMA'
  | 'UNSUPPORTED_PROTOCOL'
  | 'PROTOCOL_MISMATCH'
  | 'UNSUPPORTED_VERSION'
  | 'PAYLOAD_SCHEMA'
  | 'SEMANTIC_RULE'
  | 'NOT_YET_VALID'
  | 'EXPIRED'
  | 'UNKNOWN_CRITICAL_EXTENSION'
  | 'UNKNOWN_KEY'
  | 'INVALID_SIGNATURE';

/** One deterministic protocol validation outcome. */
export interface ValidationResult {
  readonly valid: boolean;
  readonly errorCode: ErrorCode | null;
  readonly detail: string;
}

type JsonRecord = Record<string, unknown>;

interface Descriptor {
  readonly $ref?: string;
  readonly type?: string;
  readonly const?: unknown;
  readonly enum?: readonly unknown[];
  readonly pattern?: string;
  readonly minLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly uniqueItems?: boolean;
  readonly items?: Descriptor;
  readonly additionalProperties?: boolean;
  readonly required?: readonly string[];
  readonly properties?: Readonly<Record<string, Descriptor>>;
}

interface Shape {
  readonly required?: readonly string[];
  readonly properties?: Readonly<Record<string, Descriptor>>;
}

interface ProtocolDefinition {
  readonly id: string;
  readonly payload: Shape;
}

interface Registry {
  readonly wire_version: string;
  readonly supported_critical_extensions: readonly string[];
  readonly common: Shape;
  readonly types: Readonly<Record<string, Shape>>;
  readonly protocols: readonly ProtocolDefinition[];
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})*$/;

function valid(): ValidationResult {
  return { valid: true, errorCode: null, detail: 'valid' };
}

function invalid(errorCode: ErrorCode, detail: string): ValidationResult {
  return { valid: false, errorCode, detail };
}

/** Narrow an unknown value to a plain JSON object. */
export function asRecord(value: unknown): JsonRecord | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as JsonRecord;
}

function asArray(value: unknown): readonly unknown[] | null {
  return Array.isArray(value) ? (value as readonly unknown[]) : null;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asUnsignedInteger(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return null;
  }
  return value;
}

function escapeCanonicalString(value: string): string {
  let escaped = '"';
  for (const character of value) {
    switch (character) {
      case '"':
        escaped += '\\"';
        break;
      case '\\':
        escaped += '\\\\';
        break;
      case '\b':
        escaped += '\\b';
        break;
      case '\f':
        escaped += '\\f';
        break;
      case '\n':
        escaped += '\\n';
        break;
      case '\r':
        escaped += '\\r';
        break;
      case '\t':
        escaped += '\\t';
        break;
      default: {
        const codePoint = character.codePointAt(0) ?? 0;
        if (codePoint < 0x20) {
          escaped += `\\u${codePoint.toString(16).padStart(4, '0')}`;
        } else {
          escaped += character;
        }
      }
    }
  }
  return `${escaped}"`;
}

/**
 * Render a decoded JSON value in the canonical signing form: object keys sorted
 * lexicographically, no insignificant whitespace, integers emitted verbatim,
 * and only the mandatory JSON string escapes.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical json: non-finite numbers are not representable');
    }
    return String(value);
  }
  if (typeof value === 'string') {
    return escapeCanonicalString(value);
  }
  const array = asArray(value);
  if (array !== null) {
    return `[${array.map((item) => canonicalJson(item)).join(',')}]`;
  }
  const record = asRecord(value);
  if (record !== null) {
    const parts = Object.keys(record)
      .sort()
      .map((key) => `${escapeCanonicalString(key)}:${canonicalJson(record[key])}`);
    return `{${parts.join(',')}}`;
  }
  throw new Error(`canonical json: unsupported value of type ${typeof value}`);
}

/**
 * Return the v1 JSON signing bytes: the document with `signature.value`
 * blanked, serialised in the canonical form.
 */
export function canonicalSigningBytes(document: unknown): Buffer {
  const root = asRecord(document);
  const signature = root === null ? null : asRecord(root['signature']);
  if (root === null || signature === null) {
    throw new Error('signature must be an object');
  }
  const signingDocument: JsonRecord = { ...root, signature: { ...signature, value: '' } };
  return Buffer.from(canonicalJson(signingDocument), 'utf8');
}

function canonicalKey(value: unknown): string {
  return canonicalJson(value);
}

/**
 * Registry-bound P1-P12 validator with a caller-owned Ed25519 keyring.
 */
export class ProtocolValidator {
  readonly #registry: Registry;
  readonly #keyring: ReadonlyMap<string, KeyObject>;
  readonly #supportedCriticalExtensions: ReadonlySet<string>;
  readonly #patterns = new Map<string, RegExp>();

  private constructor(registry: Registry, keyring: ReadonlyMap<string, KeyObject>) {
    this.#registry = registry;
    this.#keyring = keyring;
    this.#supportedCriticalExtensions = new Set(registry.supported_critical_extensions);
  }

  /** Parse the canonical registry and bind raw 32-byte Ed25519 public keys. */
  static fromRegistryJson(
    registryJson: string,
    keyring: ReadonlyMap<string, Uint8Array>,
  ): ProtocolValidator {
    const parsed = JSON.parse(registryJson) as unknown;
    const record = asRecord(parsed);
    if (record === null) {
      throw new Error('registry must be a JSON object');
    }
    const registry = record as unknown as Registry;
    if (typeof registry.wire_version !== 'string' || registry.wire_version.length === 0) {
      throw new Error('registry lacks a wire_version');
    }
    if (!Array.isArray(registry.protocols) || registry.protocols.length === 0) {
      throw new Error('registry declares no protocols');
    }
    const boundKeys = new Map<string, KeyObject>();
    for (const [keyId, keyBytes] of keyring) {
      if (keyBytes.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error(`key ${keyId} must contain ${ED25519_PUBLIC_KEY_BYTES} bytes`);
      }
      boundKeys.set(
        keyId,
        createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyBytes)]),
          format: 'der',
          type: 'spki',
        }),
      );
    }
    return new ProtocolValidator(registry, boundKeys);
  }

  /**
   * Validate structure, cross-field rules, time, critical extensions, and the
   * detached Ed25519 signature in a deterministic fail-closed order.
   */
  validate(document: unknown, expectedProtocol: string, validationTime: number): ValidationResult {
    const root = asRecord(document);
    if (root === null) {
      return invalid('MALFORMED_DOCUMENT', 'document must be a JSON object');
    }
    const protocol = asString(root['protocol']);
    if (protocol === null) {
      return invalid('UNSUPPORTED_PROTOCOL', 'protocol must identify P1 through P12');
    }
    const definition = this.#registry.protocols.find((candidate) => candidate.id === protocol);
    if (definition === undefined) {
      return invalid('UNSUPPORTED_PROTOCOL', 'protocol must identify P1 through P12');
    }
    if (protocol !== expectedProtocol) {
      return invalid(
        'PROTOCOL_MISMATCH',
        `document declares ${protocol}; lane requires ${expectedProtocol}`,
      );
    }
    if (asString(root['version']) !== this.#registry.wire_version) {
      return invalid(
        'UNSUPPORTED_VERSION',
        `only wire version ${this.#registry.wire_version} is accepted`,
      );
    }
    const commonDetail = this.#validateShape(root, this.#registry.common, '$');
    if (commonDetail !== null) {
      return invalid('COMMON_SCHEMA', commonDetail);
    }
    const payload = asRecord(root['payload']);
    if (payload === null) {
      return invalid('PAYLOAD_SCHEMA', 'payload must be an object');
    }
    const payloadDetail = this.#validateShape(payload, definition.payload, 'payload');
    if (payloadDetail !== null) {
      return invalid('PAYLOAD_SCHEMA', payloadDetail);
    }
    const semanticDetail = validateSemantics(protocol, payload, root);
    if (semanticDetail !== null) {
      return invalid('SEMANTIC_RULE', semanticDetail);
    }
    const issuedAt = asUnsignedInteger(root['issued_at']);
    if (issuedAt === null) {
      return invalid('COMMON_SCHEMA', 'issued_at must be uint');
    }
    const expiresAt = asUnsignedInteger(root['expires_at']);
    if (expiresAt === null) {
      return invalid('COMMON_SCHEMA', 'expires_at must be uint');
    }
    if (expiresAt <= issuedAt) {
      return invalid('COMMON_SCHEMA', 'expires_at must be greater than issued_at');
    }
    if (validationTime < issuedAt) {
      return invalid('NOT_YET_VALID', 'validation time precedes issued_at');
    }
    if (validationTime >= expiresAt) {
      return invalid('EXPIRED', 'validation time is at or after expires_at');
    }
    const unsupported = this.#unsupportedCriticalExtensions(root['critical_extensions']);
    if (unsupported.length > 0) {
      return invalid(
        'UNKNOWN_CRITICAL_EXTENSION',
        `unsupported critical extensions: ${unsupported.join(', ')}`,
      );
    }
    return this.#verifySignature(root);
  }

  #unsupportedCriticalExtensions(value: unknown): readonly string[] {
    const items = asArray(value);
    if (items === null) {
      return [];
    }
    const unsupported = new Set<string>();
    for (const item of items) {
      const extension = asString(item);
      if (extension === null || this.#supportedCriticalExtensions.has(extension)) {
        continue;
      }
      unsupported.add(extension);
    }
    return [...unsupported].sort();
  }

  #validateShape(value: JsonRecord, shape: Shape, path: string): string | null {
    const required = shape.required ?? [];
    const properties = shape.properties ?? {};
    for (const name of required) {
      if (!Object.hasOwn(value, name)) {
        return `${path}.${name}: required property is missing`;
      }
    }
    for (const key of Object.keys(value).sort()) {
      if (!Object.hasOwn(properties, key)) {
        return `${path}.${key}: additional property is forbidden`;
      }
    }
    for (const name of Object.keys(properties).sort()) {
      if (!Object.hasOwn(value, name)) {
        continue;
      }
      const descriptor = properties[name];
      if (descriptor === undefined) {
        continue;
      }
      const detail = this.#validateDescriptor(value[name], descriptor, `${path}.${name}`);
      if (detail !== null) {
        return detail;
      }
    }
    return null;
  }

  #validateDescriptor(value: unknown, descriptor: Descriptor, path: string): string | null {
    if (descriptor.$ref !== undefined) {
      const referenced = descriptor.$ref;
      if (!Object.hasOwn(this.#registry.types, referenced)) {
        return `${path}: unknown registry reference ${referenced}`;
      }
      const target = this.#registry.types[referenced];
      const object = asRecord(value);
      if (target === undefined) {
        return `${path}: unknown registry reference ${referenced}`;
      }
      if (object === null) {
        return `${path}: expected object`;
      }
      return this.#validateShape(object, target, path);
    }
    if (descriptor.const !== undefined && canonicalKey(descriptor.const) !== canonicalKey(value)) {
      return `${path}: value does not match constant`;
    }
    if (descriptor.enum !== undefined && descriptor.enum.length > 0) {
      const encoded = canonicalKey(value);
      if (!descriptor.enum.some((candidate) => canonicalKey(candidate) === encoded)) {
        return `${path}: value is outside the allowed enum`;
      }
    }
    switch (descriptor.type) {
      case 'string':
        return this.#validateString(value, descriptor, path);
      case 'integer':
        return validateInteger(value, descriptor, path);
      case 'boolean':
        return typeof value === 'boolean' ? null : `${path}: expected boolean`;
      case 'array':
        return this.#validateArray(value, descriptor, path);
      case 'object':
        return this.#validateObject(value, descriptor, path);
      case undefined:
        return `${path}: descriptor lacks a type`;
      default:
        return `${path}: unsupported registry type ${descriptor.type}`;
    }
  }

  #validateString(value: unknown, descriptor: Descriptor, path: string): string | null {
    const text = asString(value);
    if (text === null) {
      return `${path}: expected string`;
    }
    if (descriptor.minLength !== undefined && [...text].length < descriptor.minLength) {
      return `${path}: string is shorter than minLength`;
    }
    if (descriptor.pattern !== undefined && !this.#pattern(descriptor.pattern).test(text)) {
      return `${path}: string does not match pattern`;
    }
    return null;
  }

  #validateArray(value: unknown, descriptor: Descriptor, path: string): string | null {
    const items = asArray(value);
    if (items === null) {
      return `${path}: expected array`;
    }
    if (descriptor.minItems !== undefined && items.length < descriptor.minItems) {
      return `${path}: array is shorter than minItems`;
    }
    if (descriptor.maxItems !== undefined && items.length > descriptor.maxItems) {
      return `${path}: array exceeds maxItems`;
    }
    if (descriptor.uniqueItems === true) {
      const unique = new Set(items.map((item) => canonicalKey(item)));
      if (unique.size !== items.length) {
        return `${path}: array items must be unique`;
      }
    }
    const itemDescriptor = descriptor.items;
    if (itemDescriptor === undefined) {
      return `${path}: registry array lacks items`;
    }
    for (let index = 0; index < items.length; index += 1) {
      const detail = this.#validateDescriptor(items[index], itemDescriptor, `${path}[${index}]`);
      if (detail !== null) {
        return detail;
      }
    }
    return null;
  }

  #validateObject(value: unknown, descriptor: Descriptor, path: string): string | null {
    const object = asRecord(value);
    if (object === null) {
      return `${path}: expected object`;
    }
    if (descriptor.additionalProperties === true) {
      return null;
    }
    const nested: Shape = {
      required: descriptor.required ?? [],
      properties: descriptor.properties ?? {},
    };
    return this.#validateShape(object, nested, path);
  }

  #pattern(source: string): RegExp {
    const cached = this.#patterns.get(source);
    if (cached !== undefined) {
      return cached;
    }
    const compiled = new RegExp(source, 'u');
    this.#patterns.set(source, compiled);
    return compiled;
  }

  #verifySignature(root: JsonRecord): ValidationResult {
    const signature = asRecord(root['signature']);
    if (signature === null) {
      return invalid('COMMON_SCHEMA', 'signature must be an object');
    }
    const keyId = asString(signature['key_id']);
    if (keyId === null) {
      return invalid('COMMON_SCHEMA', 'key_id must be a string');
    }
    const publicKey = this.#keyring.get(keyId);
    if (publicKey === undefined) {
      return invalid('UNKNOWN_KEY', `key id is not resolvable: ${keyId}`);
    }
    const signatureHex = asString(signature['value']);
    if (signatureHex === null) {
      return invalid('COMMON_SCHEMA', 'signature value must be a string');
    }
    if (!HEX_PATTERN.test(signatureHex)) {
      return invalid('INVALID_SIGNATURE', 'signature is not valid hexadecimal');
    }
    const signatureBytes = Buffer.from(signatureHex, 'hex');
    if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) {
      return invalid('INVALID_SIGNATURE', 'signature must contain 64 bytes');
    }
    let signingBytes: Buffer;
    try {
      signingBytes = canonicalSigningBytes(root);
    } catch (error: unknown) {
      return invalid('COMMON_SCHEMA', error instanceof Error ? error.message : String(error));
    }
    if (!verifyEd25519(null, signingBytes, publicKey, signatureBytes)) {
      return invalid('INVALID_SIGNATURE', 'Ed25519 verification failed');
    }
    return valid();
  }
}

function validateInteger(value: unknown, descriptor: Descriptor, path: string): string | null {
  const integer = asUnsignedInteger(value);
  if (integer === null) {
    return `${path}: expected unsigned integer`;
  }
  if (descriptor.minimum !== undefined && integer < descriptor.minimum) {
    return `${path}: integer is below minimum`;
  }
  if (descriptor.maximum !== undefined && integer > descriptor.maximum) {
    return `${path}: integer exceeds maximum`;
  }
  return null;
}

/* ------------------------------------------------------------------------- */
/* Protocol cross-field safety invariants                                     */
/* ------------------------------------------------------------------------- */

type SemanticRule = (payload: JsonRecord, document: JsonRecord) => string | null;

function objectField(source: JsonRecord, key: string): JsonRecord {
  return asRecord(source[key]) ?? {};
}

function stringField(source: JsonRecord, key: string): string {
  return asString(source[key]) ?? '';
}

function booleanField(source: JsonRecord, key: string): boolean {
  return source[key] === true;
}

function arrayField(source: JsonRecord, key: string): readonly unknown[] {
  return asArray(source[key]) ?? [];
}

function integerField(source: JsonRecord, key: string): number {
  return asUnsignedInteger(source[key]) ?? 0;
}

function objectItems(source: JsonRecord, key: string): readonly JsonRecord[] {
  return arrayField(source, key).map((item) => asRecord(item) ?? {});
}

function stringItems(source: JsonRecord, key: string): readonly string[] {
  return arrayField(source, key).map((item) => asString(item) ?? '');
}

/** Require approval for consequential authority. */
function validateP1(payload: JsonRecord): string | null {
  const consequential = new Set(['financial', 'destructive', 'physical']);
  if (
    consequential.has(stringField(payload, 'side_effect_class')) &&
    arrayField(payload, 'approvals').length === 0
  ) {
    return 'consequential authority requires at least one approver';
  }
  return null;
}

/** Keep precommit and final receipt phases unambiguous. */
function validateP2(payload: JsonRecord): string | null {
  const phase = stringField(payload, 'phase');
  const outcome = stringField(payload, 'outcome');
  const parent = stringField(payload, 'parent_receipt');
  if (phase === 'precommit' && (outcome !== 'pending' || parent !== '')) {
    return 'precommit receipts must be pending and have no parent';
  }
  if (phase === 'final' && (outcome === 'pending' || parent === '')) {
    return 'final receipts require a terminal outcome and parent precommit receipt';
  }
  return null;
}

/** Require consent for sensitive context and a linked transform chain. */
function validateP3(payload: JsonRecord): string | null {
  const sensitive = new Set(['L2', 'L3', 'L4']);
  if (sensitive.has(stringField(payload, 'sensitivity')) && !booleanField(payload, 'consent')) {
    return 'L2-L4 context requires affirmative consent';
  }
  const transformations = objectItems(payload, 'transformations');
  for (let index = 1; index < transformations.length; index += 1) {
    const previous = transformations[index - 1] ?? {};
    const current = transformations[index] ?? {};
    if (stringField(previous, 'output_digest') !== stringField(current, 'input_digest')) {
      return 'transformation digest chain is discontinuous';
    }
  }
  return null;
}

/** Validate hash-chain genesis and consent quarantine semantics. */
function validateP4(payload: JsonRecord): string | null {
  const sequence = integerField(payload, 'sequence');
  const previous = stringField(payload, 'previous_digest');
  if ((sequence === 0 && previous !== '') || (sequence > 0 && !previous.startsWith('sha256:'))) {
    return 'previous_digest must be empty only for sequence zero';
  }
  if (
    booleanField(payload, 'consent_revoked') &&
    stringField(payload, 'quarantine_state') !== 'quarantined'
  ) {
    return 'consent-revoked memory must be quarantined';
  }
  return null;
}

/** Bind the declared runtime to the exact executable media type. */
function validateP5(payload: JsonRecord): string | null {
  const accepted = new Map<string, readonly string[]>([
    ['wasm', ['application/wasm']],
    ['python', ['text/x-python', 'application/vnd.aumos.python']],
    ['node', ['text/javascript', 'application/javascript']],
    ['container', ['application/vnd.oci.image.manifest.v1+json']],
  ]);
  const mediaType = stringField(objectField(payload, 'code'), 'media_type');
  const allowed = accepted.get(stringField(payload, 'runtime')) ?? [];
  if (!allowed.includes(mediaType)) {
    return 'runtime does not match the content-addressed code media type';
  }
  return null;
}

/** Require unique role/artifact pairs including model and policy. */
function validateP6(payload: JsonRecord): string | null {
  const roles = stringItems(payload, 'roles');
  const artifacts = objectItems(payload, 'artifacts');
  const uniqueRoles = new Set(roles);
  if (roles.length !== artifacts.length || uniqueRoles.size !== roles.length) {
    return 'artifact roles must be unique and align one-to-one with artifacts';
  }
  if (!uniqueRoles.has('model') || !uniqueRoles.has('policy')) {
    return 'artifact graph must contain model and policy roles';
  }
  const digests = new Set(artifacts.map((artifact) => stringField(artifact, 'digest')));
  if (digests.size !== artifacts.length) {
    return 'artifact digests must be unique';
  }
  return null;
}

/** Require explicit approval for high-risk or administrative authority. */
function validateP7(payload: JsonRecord): string | null {
  const highRisk = integerField(payload, 'expected_risk_micros') >= 500000;
  const administrative = stringField(payload, 'privilege') === 'admin';
  if ((highRisk || administrative) && !booleanField(payload, 'approval_required')) {
    return 'high-risk or administrative budgets must require approval';
  }
  return null;
}

/** Bind summary counts to the signed assertion set. */
function validateP8(payload: JsonRecord): string | null {
  const assertions = objectItems(payload, 'assertions');
  const passed = assertions.filter((assertion) => booleanField(assertion, 'passed')).length;
  const failed = assertions.length - passed;
  if (
    passed !== integerField(payload, 'passed_count') ||
    failed !== integerField(payload, 'failed_count')
  ) {
    return 'assertion summary counts do not match signed assertions';
  }
  return null;
}

/** Reject impossible incident containment timelines. */
function validateP9(payload: JsonRecord): string | null {
  const status = stringField(payload, 'containment_status');
  const containedAt = integerField(payload, 'contained_at');
  const detectedAt = integerField(payload, 'detected_at');
  if (status === 'open' && containedAt !== 0) {
    return 'open incidents cannot declare a containment timestamp';
  }
  if (status !== 'open' && containedAt < detectedAt) {
    return 'contained incidents cannot predate detection';
  }
  return null;
}

/** Enforce chain identity, quorum, depth, and budget attenuation. */
function validateP10(payload: JsonRecord): string | null {
  const chain = stringItems(payload, 'delegation_chain');
  const first = chain[0];
  const last = chain[chain.length - 1];
  if (
    first === undefined ||
    last === undefined ||
    first !== stringField(payload, 'delegator') ||
    last !== stringField(payload, 'delegatee')
  ) {
    return 'delegation chain endpoints must match delegator and delegatee';
  }
  const hopCount = integerField(payload, 'hop_count');
  if (hopCount !== chain.length - 1 || hopCount > integerField(payload, 'max_depth')) {
    return 'hop count must match the chain and remain within max depth';
  }
  if (integerField(payload, 'quorum') > arrayField(payload, 'approvals').length) {
    return 'approval quorum is not satisfied';
  }
  const parent = objectField(payload, 'parent_budget');
  const delegated = objectField(payload, 'delegated_budget');
  for (const key of Object.keys(parent).sort()) {
    if (integerField(delegated, key) > integerField(parent, key)) {
      return `delegated budget expands parent ceiling at ${key}`;
    }
  }
  return null;
}

/** Keep embargo state consistent with the signed disclosure state. */
function validateP11(payload: JsonRecord, document: JsonRecord): string | null {
  const embargoUntil = integerField(payload, 'embargo_until');
  const disclosureStatus = stringField(payload, 'disclosure_status');
  const issuedAt = integerField(document, 'issued_at');
  if (disclosureStatus === 'embargoed' && embargoUntil <= issuedAt) {
    return 'embargoed remediation requires a future embargo timestamp';
  }
  if (disclosureStatus !== 'embargoed' && embargoUntil > issuedAt) {
    return 'non-embargoed remediation cannot carry a future embargo';
  }
  return null;
}

/** Bind capability validity to the envelope and a fail-closed network profile. */
function validateP12(payload: JsonRecord, document: JsonRecord): string | null {
  if (integerField(payload, 'valid_until') > integerField(document, 'expires_at')) {
    return 'capability validity cannot exceed envelope expiry';
  }
  if (stringField(objectField(payload, 'network'), 'egress_default') !== 'deny') {
    return 'capability network policy must default deny';
  }
  const sandbox = stringField(payload, 'sandbox');
  const memoryIsolation = stringField(payload, 'memory_isolation');
  if (sandbox === 'wasm' && memoryIsolation !== 'wasm') {
    return 'Wasm sandbox must attest Wasm memory isolation';
  }
  if (sandbox === 'tee' && memoryIsolation !== 'tee') {
    return 'TEE sandbox must attest TEE memory isolation';
  }
  return null;
}

const SEMANTIC_RULES = new Map<string, SemanticRule>([
  ['P1', (payload) => validateP1(payload)],
  ['P2', (payload) => validateP2(payload)],
  ['P3', (payload) => validateP3(payload)],
  ['P4', (payload) => validateP4(payload)],
  ['P5', (payload) => validateP5(payload)],
  ['P6', (payload) => validateP6(payload)],
  ['P7', (payload) => validateP7(payload)],
  ['P8', (payload) => validateP8(payload)],
  ['P9', (payload) => validateP9(payload)],
  ['P10', (payload) => validateP10(payload)],
  ['P11', validateP11],
  ['P12', validateP12],
]);

/** Evaluate the protocol-specific cross-field invariant. */
export function validateSemantics(
  protocol: string,
  payload: JsonRecord,
  document: JsonRecord,
): string | null {
  const rule = SEMANTIC_RULES.get(protocol);
  if (rule === undefined) {
    return 'unsupported protocol escaped structural validation';
  }
  return rule(payload, document);
}
