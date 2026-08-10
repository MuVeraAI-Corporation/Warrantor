/**
 * `@aumos/protocol-contracts` — generated P1-P12 wire types plus the
 * independent TypeScript protocol validator.
 */

export type * from './generated.js';
export {
  ProtocolValidator,
  asRecord,
  canonicalJson,
  canonicalSigningBytes,
  validateSemantics,
  type ErrorCode,
  type ValidationResult,
} from './validation.js';
