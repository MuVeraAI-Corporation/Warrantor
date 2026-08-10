/**
 * Invariant I-11 regression suite — "self-change is governed".
 *
 * This invariant had ZERO implementing code before AX-39: a grep across all four
 * languages for `self_change|self-change|self_modify|modify its own` returned
 * nothing, while `docs/02-architecture.md` listed it as an architectural invariant.
 * See docs/cross-cutting/21-threat-model.md section 4.
 */
import { describe, it, expect } from 'vitest';
import { isSelfChange, SELF_CHANGE_PROTECTED_PREFIXES, type ToolScope } from './index.js';

describe('I-11 — self-change is governed', () => {
  it('denies writes to every protected enforcement surface', () => {
    for (const prefix of SELF_CHANGE_PROTECTED_PREFIXES) {
      const scope: ToolScope = { toolSvid: `${prefix}/write`, sideEffectClass: 'write' };
      expect(isSelfChange(scope)).toBe(true);
    }
  });

  it('denies a destructive tool aimed at the policy corpus', () => {
    expect(
      isSelfChange({ toolSvid: 'spiffe://warrantor.dev/policy/corpus', sideEffectClass: 'destructive' })
    ).toBe(true);
  });

  it('denies a tool that mutates a protected surface indirectly', () => {
    expect(
      isSelfChange({
        toolSvid: 'spiffe://warrantor.dev/tools/generic-writer',
        sideEffectClass: 'write',
        mutates: ['spiffe://warrantor.dev/trust-bundle/keys'],
      })
    ).toBe(true);
  });

  it('permits READ access to a protected surface -- inspection is not modification', () => {
    expect(
      isSelfChange({ toolSvid: 'spiffe://warrantor.dev/policy/corpus', sideEffectClass: 'read' })
    ).toBe(false);
  });

  it('permits ordinary writes to unprotected resources', () => {
    expect(
      isSelfChange({ toolSvid: 'spiffe://warrantor.dev/tools/github', sideEffectClass: 'write' })
    ).toBe(false);
  });

  it('is not fooled by a prefix that merely shares a leading substring', () => {
    // "policy-playground" must not match the "policy" prefix.
    expect(
      isSelfChange({
        toolSvid: 'spiffe://warrantor.dev/policy-playground/scratch',
        sideEffectClass: 'write',
      })
    ).toBe(false);
  });
});
