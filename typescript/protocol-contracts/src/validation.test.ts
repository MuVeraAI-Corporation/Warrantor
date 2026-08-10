import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  ProtocolValidator,
  asRecord,
  canonicalSigningBytes,
  type ErrorCode,
} from './validation.js';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const VECTOR_ROOT = join(REPOSITORY_ROOT, 'testvectors', 'protocols');
const REGISTRY_PATH = join(REPOSITORY_ROOT, 'specs', 'protocols', 'registry.json');
const EXPECTED_VECTOR_COUNT = 40;

interface ManifestEntry {
  readonly id: string;
  readonly protocol: string;
  readonly category: string;
  readonly expected: string;
  readonly expected_error: string;
  readonly path: string;
}

interface Manifest {
  readonly keyring: Readonly<Record<string, string>>;
  readonly vector_count: number;
  readonly vectors: readonly ManifestEntry[];
}

interface VectorRecord {
  readonly id: string;
  readonly protocol: string;
  readonly expected: string;
  readonly expected_error: string;
  readonly validation_time: number;
  readonly document: unknown;
}

function loadManifest(): Manifest {
  return JSON.parse(readFileSync(join(VECTOR_ROOT, 'manifest.json'), 'utf8')) as Manifest;
}

function loadVector(relativePath: string): VectorRecord {
  return JSON.parse(readFileSync(join(VECTOR_ROOT, relativePath), 'utf8')) as VectorRecord;
}

function buildValidator(keyring: Readonly<Record<string, string>>): ProtocolValidator {
  const keys = new Map<string, Uint8Array>();
  for (const [keyId, encoded] of Object.entries(keyring)) {
    keys.set(keyId, Buffer.from(encoded, 'hex'));
  }
  return ProtocolValidator.fromRegistryJson(readFileSync(REGISTRY_PATH, 'utf8'), keys);
}

describe('ProtocolValidator', () => {
  const manifest = loadManifest();
  const validator = buildValidator(manifest.keyring);

  it('loads exactly the declared number of vectors', () => {
    expect(manifest.vectors).toHaveLength(EXPECTED_VECTOR_COUNT);
    expect(manifest.vector_count).toBe(EXPECTED_VECTOR_COUNT);
    expect(new Set(manifest.vectors.map((entry) => entry.protocol)).size).toBe(12);
    expect(new Set(manifest.vectors.map((entry) => entry.category))).toEqual(
      new Set(['positive', 'negative', 'adversarial']),
    );
  });

  it.each(manifest.vectors.map((entry) => [entry.id, entry] as const))(
    'matches the expected outcome for %s',
    (_id, entry) => {
      const record = loadVector(entry.path);
      const result = validator.validate(
        record.document,
        record.protocol,
        record.validation_time,
      );
      const expectedValid = record.expected === 'valid';
      expect(result.valid, `${entry.id}: ${result.errorCode ?? ''} ${result.detail}`).toBe(
        expectedValid,
      );
      if (expectedValid) {
        expect(result.errorCode).toBeNull();
      } else {
        expect(result.errorCode, `${entry.id}: ${result.detail}`).toBe(
          record.expected_error as ErrorCode,
        );
        expect(record.expected_error).toBe(entry.expected_error);
      }
    },
  );

  it('fails closed when the signing key cannot be resolved', () => {
    const entry = manifest.vectors[0];
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    const record = loadVector(entry.path);
    const result = buildValidator({}).validate(
      record.document,
      record.protocol,
      record.validation_time,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('UNKNOWN_KEY');
  });

  it('rejects a document whose protocol does not match the lane', () => {
    const entry = manifest.vectors[0];
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    const record = loadVector(entry.path);
    const result = validator.validate(record.document, 'P12', record.validation_time);
    expect(result.errorCode).toBe('PROTOCOL_MISMATCH');
  });

  it('fails closed on an unknown critical extension', () => {
    const entry = manifest.vectors[0];
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    const record = loadVector(entry.path);
    const document = asRecord(record.document);
    expect(document).not.toBeNull();
    if (document === null) return;
    const tampered = { ...document, critical_extensions: ['urn:aumos:extension:not-understood'] };
    const result = validator.validate(tampered, record.protocol, record.validation_time);
    expect(result.errorCode).toBe('UNKNOWN_CRITICAL_EXTENSION');
  });

  it('produces canonical signing bytes over which the reference signature verifies', () => {
    const entry = manifest.vectors[0];
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    const record = loadVector(entry.path);
    const signingBytes = canonicalSigningBytes(record.document).toString('utf8');
    expect(signingBytes.startsWith('{"critical_extensions":')).toBe(true);
    expect(signingBytes).toContain('"value":""');
    expect(signingBytes).toContain('"issued_at":1893456000,"issuer":');
    expect(signingBytes).not.toContain('": ');
    // The positive vector validating end to end above is the empirical proof
    // that these bytes match the Rust reference byte for byte.
    const result = validator.validate(record.document, record.protocol, record.validation_time);
    expect(result.valid).toBe(true);
  });
});
