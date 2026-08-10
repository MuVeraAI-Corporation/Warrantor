/**
 * TypeScript batch verifier for the strict cross-language protocol TCK.
 *
 * Reads `{"keyring": {...}, "vectors": [...]}` from stdin and writes one JSON
 * line of per-vector results, matching the wire contract of
 * `rust/protocol-contracts/src/bin/protocol_tck.rs`.
 *
 * The import uses an explicit `.ts` specifier because Node's type-stripping
 * loader resolves TypeScript sources directly; `tsconfig.conformance.json`
 * enables `allowImportingTsExtensions` for the same reason.
 */

import { readFileSync } from 'node:fs';

import {
  ProtocolValidator,
  type ErrorCode,
} from '../../typescript/protocol-contracts/src/validation.ts';

interface BatchVector {
  readonly id: string;
  readonly protocol: string;
  readonly validation_time: number;
  readonly document: unknown;
}

interface Batch {
  readonly keyring: Readonly<Record<string, string>>;
  readonly vectors: readonly BatchVector[];
}

interface VectorResult {
  readonly id: string;
  readonly valid: boolean;
  readonly error_code: ErrorCode | null;
  readonly detail: string;
}

function main(): number {
  const registryPath = process.argv[2];
  if (registryPath === undefined) {
    console.error('usage: verify_protocol_typescript.ts <registry.json>');
    return 2;
  }
  try {
    const batch = JSON.parse(readFileSync(0, 'utf8')) as Batch;
    const keyring = new Map<string, Uint8Array>();
    for (const [keyId, encoded] of Object.entries(batch.keyring)) {
      keyring.set(keyId, Buffer.from(encoded, 'hex'));
    }
    const validator = ProtocolValidator.fromRegistryJson(
      readFileSync(registryPath, 'utf8'),
      keyring,
    );
    const results: VectorResult[] = batch.vectors.map((vector) => {
      const result = validator.validate(vector.document, vector.protocol, vector.validation_time);
      return {
        id: vector.id,
        valid: result.valid,
        error_code: result.errorCode,
        detail: result.detail,
      };
    });
    console.log(JSON.stringify({ implementation: 'typescript', results }));
    return 0;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`protocol-tck: ${message}`);
    return 2;
  }
}

process.exitCode = main();
