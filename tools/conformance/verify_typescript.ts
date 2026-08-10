/** Strict TypeScript verifier for T1 signature and RFC 6962 Merkle vectors. */

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { readFileSync } from 'node:fs';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('vector root must be a JSON object');
  }
  return value as Record<string, unknown>;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${key} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((item) => typeof item === 'string' && item.length > 0)
  ) {
    throw new Error(`${key} must be a non-empty string array`);
  }
  return value;
}

function leafHash(leaf: Buffer): Buffer {
  return createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), leaf])).digest();
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), left, right]))
    .digest();
}

function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return Buffer.alloc(32);
  let layer = leaves.map(leafHash);
  while (layer.length > 1) {
    const next: Buffer[] = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      if (left === undefined) throw new Error('Merkle layer invariant violated');
      const right = layer[index + 1];
      next.push(right === undefined ? left : nodeHash(left, right));
    }
    layer = next;
  }
  const root = layer[0];
  if (root === undefined) throw new Error('Merkle root invariant violated');
  return root;
}

function verifySignatureVector(vector: Record<string, unknown>): boolean {
  const payload = Buffer.from(requireString(vector, 'payload_hex'), 'hex');
  const verifyingKey = Buffer.from(requireString(vector, 'verifying_key_hex'), 'hex');
  const signature = Buffer.from(requireString(vector, 'signature_hex'), 'hex');
  const expected = requireString(vector, 'expected');
  if (verifyingKey.length !== 32) throw new Error('verifying_key_hex must contain 32 bytes');
  if (signature.length !== 64) throw new Error('signature_hex must contain 64 bytes');
  if (expected !== 'valid' && expected !== 'invalid') {
    throw new Error("expected must be 'valid' or 'invalid'");
  }

  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, verifyingKey]),
    format: 'der',
    type: 'spki',
  });
  const valid = verifySignature(null, payload, publicKey, signature);
  console.log(`typescript: signature valid=${valid}, expected=${expected}`);
  return valid === (expected === 'valid');
}

function verifyMerkleVector(vector: Record<string, unknown>): boolean {
  const leaves = requireStringArray(vector, 'leaves_hex').map((leaf) =>
    Buffer.from(leaf, 'hex'),
  );
  const expected = requireString(vector, 'expected_root_hex');
  const computed = merkleRoot(leaves).toString('hex');
  console.log(`typescript: merkle computed=${computed}, expected=${expected}`);
  return computed === expected;
}

function main(): number {
  try {
    const vector = requireRecord(JSON.parse(readFileSync(0, 'utf8')) as unknown);
    if ('payload_hex' in vector) return verifySignatureVector(vector) ? 0 : 1;
    if ('leaves_hex' in vector) return verifyMerkleVector(vector) ? 0 : 1;
    throw new Error('unsupported T1 vector shape');
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`typescript: verifier error: ${message}`);
    return 2;
  }
}

process.exitCode = main();
