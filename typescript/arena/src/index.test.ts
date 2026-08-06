import { describe, it, expect } from 'vitest';
import {
  Leaderboard,
  expectedScore,
  eloUpdate,
  eloUpdateDraw,
  DEFAULT_ELO,
  DEFAULT_K,
} from './index.js';

describe('expectedScore', () => {
  it('returns 0.5 for equal ratings', () => {
    expect(expectedScore(1200, 1200)).toBeCloseTo(0.5, 10);
  });

  it('returns a value > 0.5 when A is higher-rated', () => {
    expect(expectedScore(1400, 1200)).toBeGreaterThan(0.5);
    expect(expectedScore(1400, 1200)).toBeCloseTo(0.7597, 3);
  });

  it('returns a value < 0.5 when A is lower-rated', () => {
    expect(expectedScore(1000, 1200)).toBeLessThan(0.5);
  });

  it('is symmetric: E(A,B) + E(B,A) = 1', () => {
    const ea = expectedScore(1500, 1300);
    const eb = expectedScore(1300, 1500);
    expect(ea + eb).toBeCloseTo(1, 10);
  });

  it('approaches 1 for a very large rating gap', () => {
    expect(expectedScore(2400, 1200)).toBeGreaterThan(0.99);
  });

  it('approaches 0 for a very large negative gap', () => {
    expect(expectedScore(1200, 2400)).toBeLessThan(0.01);
  });
});

describe('eloUpdate (win/loss)', () => {
  it('is zero-sum for equal ratings at default K', () => {
    const [nw, nl] = eloUpdate(1200, 1200, DEFAULT_K);
    // Equal ratings: expected = 0.5, so winner +16, loser -16.
    expect(nw).toBeCloseTo(1216, 6);
    expect(nl).toBeCloseTo(1184, 6);
    expect(nw + nl).toBeCloseTo(2400, 6);
  });

  it('gives a smaller gain when the winner is heavily favored', () => {
    // 1800 vs 1200: expected ~0.997, so winner gains ~0.097*K ≈ 3.1 at K=32.
    const [nw, nl] = eloUpdate(1800, 1200, 32);
    expect(nw - 1800).toBeLessThan(5);
    expect(nw - 1800).toBeGreaterThan(0);
    expect(1200 - nl).toBeLessThan(5);
  });

  it('gives a large gain when the underdog wins (upset)', () => {
    const [nw, nl] = eloUpdate(1200, 1800, 32);
    // Underdog expected ~0.003, so gains ~0.997*K ≈ 31.9.
    expect(nw - 1200).toBeGreaterThan(30);
    expect(1800 - nl).toBeGreaterThan(30);
  });

  it('remains zero-sum across asymmetric ratings', () => {
    const [nw, nl] = eloUpdate(1500, 1300, 32);
    expect(nw + nl).toBeCloseTo(2800, 10);
  });

  it('respects the K-factor (bigger K = bigger swing)', () => {
    const [nw32] = eloUpdate(1200, 1200, 32);
    const [nw64] = eloUpdate(1200, 1200, 64);
    expect(nw64 - 1200).toBeCloseTo((nw32 - 1200) * 2, 6);
  });
});

describe('eloUpdateDraw', () => {
  it('does not move ratings when they are equal', () => {
    const [a, b] = eloUpdateDraw(1200, 1200, DEFAULT_K);
    expect(a).toBeCloseTo(1200, 10);
    expect(b).toBeCloseTo(1200, 10);
  });

  it('pulls the higher-rated contestant down and lower-rated up (half-credit)', () => {
    const [a, b] = eloUpdateDraw(1400, 1200, DEFAULT_K);
    expect(a).toBeLessThan(1400); // higher drifts down
    expect(b).toBeGreaterThan(1200); // lower drifts up
  });

  it('is zero-sum', () => {
    const [a, b] = eloUpdateDraw(1500, 1100, 40);
    expect(a + b).toBeCloseTo(2600, 10);
  });
});

describe('Leaderboard — registration', () => {
  it('adds contestants with default Elo and zero stats', () => {
    const lb = new Leaderboard();
    const c = lb.addContestant('m1', 'Model One');
    expect(c.elo).toBe(DEFAULT_ELO);
    expect(c.played).toBe(0);
    expect(lb.hasContestant('m1')).toBe(true);
    expect(lb.size).toBe(1);
  });

  it('defaults the name to the id when not provided', () => {
    const lb = new Leaderboard();
    expect(lb.addContestant('m1').name).toBe('m1');
  });

  it('supports a custom starting Elo', () => {
    const lb = new Leaderboard();
    expect(lb.addContestant('m1', 'M1', 1500).elo).toBe(1500);
  });

  it('rejects duplicate contestant ids', () => {
    const lb = new Leaderboard();
    lb.addContestant('m1');
    expect(() => lb.addContestant('m1')).toThrow(/already exists/);
  });

  it('exposes the configured K-factor', () => {
    expect(new Leaderboard(24).kFactor).toBe(24);
    expect(new Leaderboard().kFactor).toBe(DEFAULT_K);
  });
});

describe('Leaderboard — match recording', () => {
  it('updates Elo and win/loss counts on a decisive result', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    lb.addContestant('b');
    const m = lb.recordMatch('g1', 'a', 'b', 'a');
    expect(m.winner).toBe('a');
    const a = lb.getContestant('a')!;
    const b = lb.getContestant('b')!;
    expect(a.elo).toBeGreaterThan(DEFAULT_ELO);
    expect(b.elo).toBeLessThan(DEFAULT_ELO);
    expect(a.wins).toBe(1);
    expect(b.losses).toBe(1);
    expect(a.played).toBe(1);
    expect(b.played).toBe(1);
  });

  it('records before/after Elo snapshots on the match', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    lb.addContestant('b');
    const m = lb.recordMatch('g1', 'a', 'b', 'b');
    expect(m.eloABefore).toBe(DEFAULT_ELO);
    expect(m.eloBBefore).toBe(DEFAULT_ELO);
    expect(m.eloBAfter!).toBeGreaterThan(m.eloBBefore!);
    expect(m.eloAAfter!).toBeLessThan(m.eloABefore!);
  });

  it('handles draws with half-credit', () => {
    const lb = new Leaderboard();
    lb.addContestant('a', 'A', 1400);
    lb.addContestant('b', 'B', 1200);
    const m = lb.recordMatch('g1', 'a', 'b', 'draw');
    const a = lb.getContestant('a')!;
    const b = lb.getContestant('b')!;
    expect(a.elo).toBeLessThan(1400);
    expect(b.elo).toBeGreaterThan(1200);
    expect(a.draws).toBe(1);
    expect(b.draws).toBe(1);
    expect(m.winner).toBe('draw');
  });

  it('rejects unknown contestants', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    expect(() => lb.recordMatch('g1', 'a', 'ghost', 'a')).toThrow(/unknown contestant/);
  });

  it('rejects self-match', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    expect(() => lb.recordMatch('g1', 'a', 'a', 'draw')).toThrow(/play itself/);
  });

  it('rejects an invalid winner value', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    lb.addContestant('b');
    expect(() => lb.recordMatch('g1', 'a', 'b', 'c' as never)).toThrow(/invalid winner/);
  });

  it('records every match in getMatches() in play order', () => {
    const lb = new Leaderboard();
    lb.addContestant('a');
    lb.addContestant('b');
    lb.recordMatch('g1', 'a', 'b', 'a');
    lb.recordMatch('g2', 'a', 'b', 'b');
    lb.recordMatch('g3', 'a', 'b', 'draw');
    const ms = lb.getMatches();
    expect(ms.map((m) => m.id)).toEqual(['g1', 'g2', 'g3']);
  });
});

describe('Leaderboard — ranking', () => {
  it('sorts contestants by Elo descending', () => {
    const lb = new Leaderboard();
    lb.addContestant('a', 'A', 1500);
    lb.addContestant('b', 'B', 1300);
    lb.addContestant('c', 'C', 1400);
    const ranked = lb.getRankings();
    expect(ranked.map((c) => c.id)).toEqual(['a', 'c', 'b']);
  });

  it('breaks Elo ties by id ascending for stable ordering', () => {
    const lb = new Leaderboard();
    lb.addContestant('zeta', 'Z', 1200);
    lb.addContestant('alpha', 'A', 1200);
    lb.addContestant('mike', 'M', 1200);
    expect(lb.getRankings().map((c) => c.id)).toEqual(['alpha', 'mike', 'zeta']);
  });

  it('returns a ranked copy (mutations do not affect the board)', () => {
    const lb = new Leaderboard();
    lb.addContestant('a', 'A', 1500);
    const copy = lb.getRankings();
    copy[0].elo = 0;
    expect(lb.getContestant('a')?.elo).toBe(1500);
  });

  it('exposes a leader() helper', () => {
    const lb = new Leaderboard();
    expect(lb.leader()).toBeUndefined();
    lb.addContestant('a', 'A', 1500);
    lb.addContestant('b', 'B', 1300);
    expect(lb.leader()?.id).toBe('a');
  });

  it('supports topN slicing', () => {
    const lb = new Leaderboard();
    lb.addContestant('a', 'A', 1500);
    lb.addContestant('b', 'B', 1400);
    lb.addContestant('c', 'C', 1300);
    expect(lb.topN(2).map((x) => x.id)).toEqual(['a', 'b']);
    expect(lb.topN(0)).toEqual([]);
  });
});

describe('Leaderboard — K-factor sensitivity', () => {
  it('a higher K-factor produces larger Elo swings across matches', () => {
    const calm = new Leaderboard(16);
    const hot = new Leaderboard(64);
    for (const lb of [calm, hot]) {
      lb.addContestant('a');
      lb.addContestant('b');
    }
    calm.recordMatch('g1', 'a', 'b', 'a');
    hot.recordMatch('g1', 'a', 'b', 'a');
    const calmSwing = Math.abs(calm.getContestant('a')!.elo - DEFAULT_ELO);
    const hotSwing = Math.abs(hot.getContestant('a')!.elo - DEFAULT_ELO);
    expect(hotSwing).toBeGreaterThan(calmSwing);
  });
});
