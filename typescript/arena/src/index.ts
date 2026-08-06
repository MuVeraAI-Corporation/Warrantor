/**
 * @aumos/arena (A8) — A/B Elo ranking leaderboard for model/agent evaluation.
 *
 * Implements a standard Elo rating system for head-to-head comparison of models or agents.
 * Models/agents ("contestants") start at 1200. Each match updates both contestants' Elo:
 *   - Win/loss: winner gains K*(1 - expected), loser loses K*(expected). Zero-sum.
 *   - Draw: both get half-credit — each moves by K*(0.5 - expected) toward 0.5, so the
 *     higher-rated contestant drifts down and the lower-rated drifts up.
 *
 * Per RFC A8: this is the testable evaluation engine. The HTTP/scoreboard UI is task 03 and
 * consumes this library.
 */

/** Default starting Elo rating for new contestants. */
export const DEFAULT_ELO = 1200;

/** Default K-factor. Higher K = more volatile ratings (newer/smaller sample sizes). */
export const DEFAULT_K = 32;

/** A contestant in the leaderboard (a model or agent). */
export interface Contestant {
  /** Stable unique identifier (e.g. "claude-opus-4.5", "gpt-5"). */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** Current Elo rating (starts at 1200). */
  elo: number;
  /** Number of matches played. */
  played: number;
  /** Wins (excluding draws). */
  wins: number;
  /** Losses (excluding draws). */
  losses: number;
  /** Draws. */
  draws: number;
}

/** The match outcome from A's perspective. */
export type MatchOutcome = 'a' | 'b' | 'draw';

/** A recorded head-to-head match. */
export interface Match {
  /** Unique match id. */
  id: string;
  /** Contestant A's id. */
  contestantA: string;
  /** Contestant B's id. */
  contestantB: string;
  /** The winner: 'a', 'b', or 'draw'. */
  winner: MatchOutcome;
  /** Elo of A at match time (for auditability). */
  eloABefore?: number;
  /** Elo of B at match time. */
  eloBBefore?: number;
  /** Elo of A after the match. */
  eloAAfter?: number;
  /** Elo of B after the match. */
  eloBAfter?: number;
  /** Optional epoch-seconds timestamp. */
  playedAt?: number;
}

/**
 * expectedScore returns the expected score for contestant A against contestant B.
 * Standard Elo: E_A = 1 / (1 + 10^((R_B - R_A)/400)). Range (0, 1).
 * E_B is 1 - E_A.
 */
export function expectedScore(ratingA: number, ratingB: number): number {
  return 1 / (1 + Math.pow(10, (ratingB - ratingA) / 400));
}

/**
 * eloUpdate applies a single win/loss result and returns the new [winnerElo, loserElo].
 * Standard formula:
 *   newWinner = winner + K * (1 - E_winner)
 *   newLoser  = loser  + K * (0 - E_loser)
 * where E_winner + E_loser = 1, so the update is zero-sum.
 *
 * @param winnerElo current Elo of the winner
 * @param loserElo  current Elo of the loser
 * @param k         K-factor (default 32)
 */
export function eloUpdate(
  winnerElo: number,
  loserElo: number,
  k: number = DEFAULT_K
): [number, number] {
  const eWinner = expectedScore(winnerElo, loserElo);
  const newWinner = winnerElo + k * (1 - eWinner);
  const newLoser = loserElo + k * (0 - (1 - eWinner));
  return [newWinner, newLoser];
}

/**
 * eloUpdateDraw applies a draw result. Both contestants get half-credit (score 0.5):
 *   newA = A + K * (0.5 - E_A)
 *   newB = B + K * (0.5 - E_B)
 * Still zero-sum (E_A + E_B = 1 ⇒ the +K*(0.5-E_A) and +K*(0.5-E_B) terms sum to 0).
 *
 * @returns [newEloA, newEloB]
 */
export function eloUpdateDraw(
  eloA: number,
  eloB: number,
  k: number = DEFAULT_K
): [number, number] {
  const eA = expectedScore(eloA, eloB);
  const newA = eloA + k * (0.5 - eA);
  const newB = eloB + k * (0.5 - (1 - eA));
  return [newA, newB];
}

/**
 * Leaderboard tracks contestants and applies match results to update Elo ratings.
 */
export class Leaderboard {
  private readonly contestants = new Map<string, Contestant>();
  private readonly matches: Match[] = [];
  private readonly k: number;

  /** @param k K-factor for matches recorded on this board (default 32). */
  constructor(k: number = DEFAULT_K) {
    this.k = k;
  }

  /** The K-factor this board uses. */
  get kFactor(): number {
    return this.k;
  }

  /**
   * Registers a contestant. Throws if the id already exists.
   * @returns the new contestant.
   */
  addContestant(id: string, name: string = id, startingElo: number = DEFAULT_ELO): Contestant {
    if (this.contestants.has(id)) {
      throw new Error(`arena: contestant "${id}" already exists`);
    }
    const c: Contestant = {
      id,
      name,
      elo: startingElo,
      played: 0,
      wins: 0,
      losses: 0,
      draws: 0,
    };
    this.contestants.set(id, c);
    return c;
  }

  /**
   * Gets a contestant by id; undefined if not registered. Returns a shallow copy so external
   * callers cannot mutate the board's state.
   */
  getContestant(id: string): Contestant | undefined {
    const c = this.contestants.get(id);
    return c ? { ...c } : undefined;
  }

  /** True if a contestant with this id is registered. */
  hasContestant(id: string): boolean {
    return this.contestants.has(id);
  }

  /** Number of registered contestants. */
  get size(): number {
    return this.contestants.size;
  }

  /** All recorded matches, in play order. */
  getMatches(): Match[] {
    return [...this.matches];
  }

  /**
   * Records a match, updating both contestants' Elo. Both contestants must already be
   * registered. Throws on unknown contestants or self-match.
   *
   * @param id          match id
   * @param contestantA id of contestant A
   * @param contestantB id of contestant B
   * @param winner      'a', 'b', or 'draw'
   * @param playedAt    optional epoch-seconds timestamp
   * @returns the recorded Match (with before/after Elo snapshots)
   */
  recordMatch(
    id: string,
    contestantA: string,
    contestantB: string,
    winner: MatchOutcome,
    playedAt?: number
  ): Match {
    if (contestantA === contestantB) {
      throw new Error(`arena: contestant cannot play itself ("${contestantA}")`);
    }
    const a = this.contestants.get(contestantA);
    const b = this.contestants.get(contestantB);
    if (!a) throw new Error(`arena: unknown contestant "${contestantA}"`);
    if (!b) throw new Error(`arena: unknown contestant "${contestantB}"`);
    if (winner !== 'a' && winner !== 'b' && winner !== 'draw') {
      throw new Error(`arena: invalid winner "${winner}" (expected 'a'|'b'|'draw')`);
    }

    const eloABefore = a.elo;
    const eloBBefore = b.elo;

    let eloAAfter = eloABefore;
    let eloBAfter = eloBBefore;

    if (winner === 'a') {
      const [nw, nl] = eloUpdate(a.elo, b.elo, this.k);
      eloAAfter = nw;
      eloBAfter = nl;
      a.wins++;
      b.losses++;
    } else if (winner === 'b') {
      const [nw, nl] = eloUpdate(b.elo, a.elo, this.k);
      eloBAfter = nw;
      eloAAfter = nl;
      b.wins++;
      a.losses++;
    } else {
      const [na, nb] = eloUpdateDraw(a.elo, b.elo, this.k);
      eloAAfter = na;
      eloBAfter = nb;
      a.draws++;
      b.draws++;
    }

    a.elo = eloAAfter;
    b.elo = eloBAfter;
    a.played++;
    b.played++;

    const match: Match = {
      id,
      contestantA,
      contestantB,
      winner,
      eloABefore,
      eloBBefore,
      eloAAfter,
      eloBAfter,
      playedAt,
    };
    this.matches.push(match);
    return match;
  }

  /**
   * Returns all contestants sorted by Elo descending. Ties break by id ascending for stable
   * ordering. Each entry is a shallow copy — mutating the returned objects does not affect the
   * board.
   */
  getRankings(): Contestant[] {
    return [...this.contestants.values()]
      .map((c) => ({ ...c }))
      .sort((x, y) => {
        if (y.elo !== x.elo) return y.elo - x.elo;
        return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
      });
  }

  /**
   * Returns the top-N contestants (by Elo). N defaults to all.
   */
  topN(n: number = this.contestants.size): Contestant[] {
    return this.getRankings().slice(0, Math.max(0, n));
  }

  /** Returns the contestant at rank 1, or undefined if the board is empty. */
  leader(): Contestant | undefined {
    return this.getRankings()[0];
  }
}
