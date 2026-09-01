# Sequencing — 2026-08-30 → 2026-11-28

> Built for **burst mode**: heavy weeks and dead weeks around client work. So this is not a
> calendar. It is a set of **value-ordered queues plus four immovable dates**, designed so that when
> a window opens you know what to start, and — more importantly — what you can actually finish
> inside it.

---

## 1. The four dates that do not move

| Date | Days out | What | Consequence |
|---|---|---|---|
| **~10 Nov 2026** | 72 | IEEE S&P 2027 Cycle 2 — abstract registration | T-03 abstract must exist |
| **17 Nov 2026** | 79 | **IEEE S&P 2027 Cycle 2 — full submission** | T-03 + T-14 ship or slip to USENIX |
| **Nov 2026** | ~60–90 | DPDP consent rules take effect (India) | B-07 must publish before, not after |
| **26 Jan 2027** | 149 | USENIX Security '27 Cycle 2 | Outside window; T-12 corpus work is inside it |

**Two watch items can become dates without warning:** the Fed/OCC/FDIC **RFI** (check weekly — it
converts B-02 from forecast to response) and **NIST COSAiS** overlay publication (check monthly — it
reframes T-08).

⚠️ USENIX Security '27 **Cycle 1 closed 25 August 2026**, five days before this program was built.
That path is gone for this cycle.

---

## 2. Blocking reads — do these before drafting, not during

Four sources determine whether four pieces are written as specified or written differently. Reading
them is **~6 hours** and it is the highest-return six hours in the program.

| Read | Blocks | What it may change |
|---|---|---|
| `arXiv 2606.28690` AgentThread | **T-02** | Narrows T-02 to the enforcement-tier axis; protocol-composition novelty is gone |
| `arXiv 2606.20634` DEMM-Bench | **T-10** | Reframes T-10 to "sufficient for whom" — makes it stronger |
| NSA MCP CSI | **T-07** | T-07 *is* this document mapped to controls; read it or don't write it |
| OWASP Agentic Security Solutions Landscape | **T-11, B-08** | May already contain the layer taxonomy |

**Do not draft T-02, T-10, T-07, T-11 or B-08 before the corresponding read.** Everything else in
the catalog is unblocked.

---

## 3. Burst profiles — match the piece to the window you actually have

### Half-day window (3–4 hours)
Pieces that are fully evidence-ready, need no new runs, and fit one sitting.
**B-01** · **T-09** · **B-02** · **T-13**

B-01 is the standout: highest priority score in the entire program (35.0), zero new evidence
required, and it opens the US/NA lane the estate does not currently have.

### One-to-two day window
**T-01** · **T-07**¹ · **B-04** · **B-07**² · **B-03** · **T-06**³ · **B-05**

¹ after the CSI read · ² after verifying the June 2026 RBI draft · ³ decays fast, do it early

### Multi-day / multi-window
**T-02**⁴ · **T-05** · **T-08** · **T-10**⁴ · **B-13** · **B-06** · **B-12** · **T-11**⁴

⁴ blocked on a read

### Sustained campaign — needs the whole window
**T-03 + T-14** (the IEEE submission; clean re-runs are the long pole) · **T-12** (corpus work
inside the window, submission outside it)

---

## 4. The dependency graph

Nothing below can be written before what it points to.

```
T-01 mediation ceiling ──┬─> T-02 tiers ──┬─> T-07 NSA mapping ──> T-08 SP 800-53 overlay
   (root of Track 1)     │   [read A2]    │
                         │                ├─> T-11 layer differentiation ──> B-08 buyer's map
                         │                │      [read C3]
                         │                └─> T-06 MCP 2026-07-28
                         │
                         └─> T-12 SoK  [also needs T-05 + Track 3 canon]

T-05 no new trust root ──> T-12
   └─> B-12 sovereign AI without a sovereign root

T-10 receipts  [read A3] ──> B-13
   └─ needs T-05 (non-guarantees) + T-02 (tiering)

T-03 guard paper ──> ships with T-14 artifact
   └─ T-04 negative results shares the infrastructure

B-01 supervisory gap ──> B-02 the RFI ──> B-13 readiness sequence
B-03 autonomy perimeter ──┬─> B-04 containment self-audit ──> B-09 budget memo
                          ├─> B-10 AEC / BEP
                          └─> B-11 healthcare records  [heavy VERIFY first]
T-09 kill switch CI ── pairs with ─> T-13 verification audit
B-05 SDAIA ──> B-06 Gulf assurance brief
```

**Two roots, one each side:** **T-01** for the technical track, **B-01** for the business track.
Both are fully evidence-ready today. Start there in the first burst regardless of its length.

---

## 5. The critical path, if you want the highest-value outcome

The IEEE submission is the only thing in this program with a hard external deadline and a long lead
time. Everything else can slip without loss.

| By | What | Why |
|---|---|---|
| Week 1–2 | T-03 experimental design frozen; pinned envs confirmed; compute booked | Kaggle 30h/wk is free and finite; Modal only above 16 GB VRAM, $100 cap |
| Week 3–6 | Clean seed-controlled re-runs of all three experiments | The long pole. Nothing else in T-03 can start until these exist |
| Week 6–8 | T-14 package assembled; **clean-room reproduction on an untouched machine** | The acceptance test. If it fails, T-03's claims narrow |
| Week 9–10 | T-03 drafted; abstract registered ~10 Nov | Abstract registration is mandatory a week ahead |
| Week 11 | Submit 17 Nov | — |

**Decision gate at week 6:** if the clean re-runs are not done, stop and re-target USENIX Cycle 2
(26 Jan 2027). A rushed empirical paper is worse than a late one, and the negative-results companion
T-04 makes an honest deferral cheap.

---

## 6. Pre-publish gate — every piece, no exceptions

```bash
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <file...>
```

1. **US English**, verified by machine. Not by eye — a single file has already disagreed with itself.
2. **Every external claim traces to [`04-verified-anchors.md`](04-verified-anchors.md)**, or it does
   not ship. `VERIFY` tags are blockers, not notes.
3. **Freshness check** on anything cited that is older than 60 days.
4. **Naming doctrine:** every vendor claim carries the vendor's own published document inline.
   Describe by class anything not self-disclosed. Never characterize a firm. Never name a person
   critically.
5. **Claim-to-mechanism check:** every guarantee stated in prose has an assertion behind it, or is
   explicitly labeled an argument rather than a result.
6. **Regional check:** does this lead with the EU? If yes, re-anchor. Passing mention only.
7. **Authenticity:** the ideas and voice are yours, and you have approved this piece.

---

## 7. What to drop first if the quarter compresses

In order, cheapest to lose:

1. **T-12 (SoK)** — already ranked last, submission is outside the window anyway
2. **B-11 (healthcare)** — least evidence-ready; heavy verification burden before it is even writable
3. **B-10 (AEC)** — high commercial value but no external clock; it keeps
4. **T-04 (negative results)** — only if T-03 also slips; they share infrastructure
5. **T-06 (MCP changes)** — but only by *dropping* it, never by publishing it late; its value decays
   to zero as the ecosystem absorbs the release

**Never drop:** B-01, T-01, B-02, T-07. Those four are the estate's actual gap — the US/NA
supervisory lane and the honesty that makes every other claim credible.
