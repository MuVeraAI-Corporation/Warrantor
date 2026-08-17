//! Turning this store's own history into training rows — and refusing to invent labels.
//!
//! # The gap
//!
//! Four of the eight planned guard models are recorded as *cold-start blocked on real warrant
//! history*, and `recipes.py` says they "return `insufficient_evidence` until real warrant history
//! accumulates". That is true and it is only half the blockage: `build_corpus.py` builds corpora
//! from Hugging Face parquet and **nothing at all** reads this store. So the moment history does
//! accumulate, somebody still has to write the exporter — the wait and the work were stacked, and
//! only the wait was written down.
//!
//! This is the exporter. It converts what the store holds into JSONL rows, so the cold start is
//! blocked on data *arriving* rather than on data arriving and then a module being built.
//!
//! # The trap it exists to avoid
//!
//! The obvious implementation is to export every guard signal with the guard's own verdict as the
//! label. That is **training a model on its own output**, and at 0.8152 measured recall it would
//! distil roughly one adversarial miss in five into the next model as ground truth — and the miss
//! would then be invisible, because the model and its labels would agree.
//!
//! So [`Row::label`] is `Option`, a guard verdict is **never** written into it, and the only labels
//! this module emits come from **human decisions the store already recorded**:
//!
//! * a warrant that was **voided** after a guard flagged a call — a human looked and discarded, so
//!   the flag agreed with the outcome;
//! * a warrant that was **settled** after a guard flagged a call — a human looked and released
//!   anyway, so the flag was a false positive on the only evidence that can say so;
//! * a **refusal** a bound produced, which is a label about the *bound*, not about the content.
//!
//! Everything else is exported with `label: null` and a `why_unlabelled` sentence. An unlabelled row
//! is still worth having — it is real distribution, which is the thing corpora are worst at — and it
//! must never be silently counted as a labelled one.
//!
//! # What a settle or void actually licenses
//!
//! Weakly. A settle covers the whole warrant, not the individual call the guard flagged, so it is
//! **warrant-level supervision on a call-level example**. That is a genuine limitation rather than a
//! detail: an operator who settled a warrant containing one bad call and nine good ones has labelled
//! all ten "fine". [`ExportSummary::caveat`] says so, and the row carries the granularity in
//! `label_source` so a training recipe can weight or discard it. Recording the weakness where the
//! data is produced is the only place it cannot be lost.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::guard::{GuardLog, GuardOutcome};
use crate::WarrantState;

/// The wire format of one exported row.
pub const CORPUS_ROW_FORMAT: &str = "warrantor.corpus-row/1";

/// Where a row's label came from, or why it has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    /// A human voided the warrant this call happened under. Warrant-level, not call-level.
    WarrantVoided,
    /// A human settled the warrant this call happened under. Warrant-level, not call-level.
    WarrantSettled,
    /// A bound refused the call. A label about the bound, not about the content.
    BoundRefused,
    /// No human decision covers this row.
    Unlabelled,
}

impl LabelSource {
    /// The word it is written as.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::WarrantVoided => "warrant_voided",
            Self::WarrantSettled => "warrant_settled",
            Self::BoundRefused => "bound_refused",
            Self::Unlabelled => "unlabelled",
        }
    }

    /// How much this source actually establishes about the row.
    #[must_use]
    pub const fn granularity(self) -> &'static str {
        match self {
            Self::WarrantVoided | Self::WarrantSettled => {
                "warrant-level: the human decided about the whole run, not about this call"
            }
            Self::BoundRefused => "call-level, but about the BOUND rather than about the content",
            Self::Unlabelled => "none",
        }
    }
}

/// One exported row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Wire format.
    pub format: String,
    /// The warrant it came from.
    pub warrant_id: String,
    /// The tool that was called.
    pub tool: String,
    /// SHA-256 of the classified content, as the guard log recorded it.
    ///
    /// **The content itself is not exported.** A guard log holds tool arguments — source, commands,
    /// pull-request bodies — and a corpus file is a thing that gets copied to a training host. The
    /// digest is enough to join a row back to the log on the machine that produced it, and carrying
    /// the text would make every export a data-egress decision nobody was asked to make. A recipe
    /// that needs text runs [`hydrate`] locally, deliberately, as a separate step.
    pub content_digest: String,
    /// How many bytes the content was, so a recipe can filter by length without seeing it.
    pub content_bytes: usize,
    /// Whether the row is harmful, or `None` when no human decision covers it.
    ///
    /// **A guard verdict never appears here.** See the module docs.
    pub label: Option<bool>,
    /// Where the label came from.
    pub label_source: LabelSource,
    /// Why there is no label, when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_unlabelled: Option<String>,
    /// What the guard thought — recorded as a *feature*, never as the label.
    ///
    /// Present so a recipe can measure agreement between the model and the human decision, which is
    /// the useful thing to do with it. Naming it `guard_said` rather than anything label-shaped is
    /// deliberate: a field called `predicted` invites being used as a target.
    pub guard_said: Option<String>,
    /// When the call happened.
    pub at: u64,
}

/// What an export produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    /// Rows written.
    pub rows: usize,
    /// Rows carrying a label from a human decision.
    pub labelled: usize,
    /// Rows with no label.
    pub unlabelled: usize,
    /// Labelled rows, by where the label came from.
    pub by_source: BTreeMap<&'static str, usize>,
    /// Warrants contributing at least one row.
    pub warrants: usize,
}

impl ExportSummary {
    /// The sentence every export prints.
    #[must_use]
    pub fn caveat(&self) -> String {
        format!(
            "{} row(s) from {} warrant(s): {} labelled from a HUMAN DECISION, {} unlabelled.\n\n\
             NO GUARD VERDICT IS A LABEL HERE. Exporting the guard's own opinion as ground truth \
             would distil its misses into the next model as fact -- at 0.8152 measured recall that \
             is roughly one adversarial case in five, and the miss would then be invisible because \
             the model and its labels would agree. `guard_said` is carried as a FEATURE so a recipe \
             can measure agreement with the human decision, which is the useful thing to do with \
             it.\n\n\
             THE LABELS THAT EXIST ARE WEAK, AND WEAK IN A NAMED WAY. A settle or a void covers the \
             whole warrant, not the individual call: an operator who settled a warrant containing \
             one bad call and nine good ones has labelled all ten \"fine\". Every row carries its \
             `label_source` and that source's granularity, so a recipe can weight or discard it \
             rather than discovering the problem in a confusion matrix.\n\n\
             NO CONTENT IS EXPORTED, only digests and byte counts. A guard log holds tool arguments \
             -- source, commands, PR bodies -- and a corpus file is a thing that gets copied to a \
             training host. Hydrating text is a separate, local, deliberate step.",
            self.rows, self.warrants, self.labelled, self.unlabelled
        )
    }
}

/// Build rows from a store's guard log and the states of the warrants it covers.
///
/// `states` maps a warrant id to its lifecycle state; a warrant absent from it contributes
/// unlabelled rows, because "the state could not be read" and "the state is Open" are different
/// facts and only one of them means no human has decided.
///
/// # Errors
/// Nothing here fails: an unreadable guard log yields no rows, which the caller reports. Failing the
/// export would make one corrupt log block a corpus the rest of the store could support.
#[must_use]
pub fn rows_from(log: &GuardLog, states: &BTreeMap<String, WarrantState>) -> Vec<Row> {
    let mut rows = Vec::new();
    for signal in &log.signals {
        // Only calls that were actually classified. A backend-unavailable or over-budget signal
        // records that nothing looked, and a row whose feature is "nothing looked" teaches nothing.
        let guard_said = match signal.outcome {
            GuardOutcome::Harmful | GuardOutcome::NotHarmful => signal.outcome.word(),
            GuardOutcome::Unparseable
            | GuardOutcome::BackendUnavailable
            | GuardOutcome::SkippedOverBudget => continue,
        };

        let (label, source, why) = match states.get(&signal.warrant_id) {
            // A human voided after seeing this run: the work was discarded.
            Some(WarrantState::Void) => (Some(true), LabelSource::WarrantVoided, None),
            // A human settled after seeing this run: the work was released.
            Some(WarrantState::Settled) => (Some(false), LabelSource::WarrantSettled, None),
            Some(WarrantState::Open) => (
                None,
                LabelSource::Unlabelled,
                Some("the warrant is still open, so no human has decided about this run".to_string()),
            ),
            Some(WarrantState::Held) => (
                None,
                LabelSource::Unlabelled,
                Some(
                    "the warrant is held: the run ended on its deadline or budget and the decision \
                     is still waiting"
                        .to_string(),
                ),
            ),
            None => (
                None,
                LabelSource::Unlabelled,
                Some(
                    "this warrant's state could not be read, which is not the same as no decision \
                     having been made"
                        .to_string(),
                ),
            ),
        };

        rows.push(Row {
            format: CORPUS_ROW_FORMAT.to_string(),
            warrant_id: signal.warrant_id.clone(),
            tool: signal.tool.clone(),
            content_digest: signal.content_digest.clone(),
            content_bytes: signal.content_bytes,
            label,
            label_source: source,
            why_unlabelled: why,
            guard_said: Some(guard_said.to_string()),
            at: signal.at,
        });
    }
    rows
}

/// Summarise what a row set contains.
#[must_use]
pub fn summarise(rows: &[Row]) -> ExportSummary {
    let mut by_source: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut warrants = std::collections::BTreeSet::new();
    let mut labelled = 0;
    for row in rows {
        warrants.insert(row.warrant_id.clone());
        if row.label.is_some() {
            labelled += 1;
            *by_source.entry(row.label_source.word()).or_insert(0) += 1;
        }
    }
    ExportSummary {
        rows: rows.len(),
        labelled,
        unlabelled: rows.len() - labelled,
        by_source,
        warrants: warrants.len(),
    }
}

/// Write rows as JSONL.
///
/// # Errors
/// A sentence on serialisation or I/O failure.
pub fn write_jsonl(rows: &[Row], path: &Path) -> Result<(), String> {
    let mut out = String::new();
    for row in rows {
        let line = serde_json::to_string(row)
            .map_err(|e| format!("cannot serialise a corpus row: {e}"))?;
        out.push_str(&line);
        out.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, out).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Whether a row set is worth training on at all.
///
/// The four cold-start recipes are documented to return `insufficient_evidence` until real history
/// exists. This is the check that decides, and it is deliberately strict about *labelled* rows
/// rather than rows: a file of ten thousand unlabelled examples is a distribution sample and not a
/// training set, and reporting it as ready is how a recipe gets run on nothing.
///
/// # Errors
/// A sentence naming the shortfall and what actually closes it, which is using the product rather
/// than exporting more often.
pub fn sufficient_for_training(
    summary: &ExportSummary,
    minimum_labelled: usize,
) -> Result<(), String> {
    if summary.labelled >= minimum_labelled {
        return Ok(());
    }
    Err(format!(
        "insufficient evidence: {} labelled row(s), and a recipe wants at least {}. Labels here come \
         only from human decisions -- a settle or a void on a warrant a guard watched -- so this \
         number grows by USING the product, not by exporting more often. {} unlabelled row(s) are \
         also present; they are real distribution and they are not a training set.",
        summary.labelled, minimum_labelled, summary.unlabelled
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{GuardKnobs, GuardMode, GuardProvenance, GuardSignal};

    fn provenance() -> GuardProvenance {
        GuardProvenance {
            adapter: "test".into(),
            backend_kind: "ollama".into(),
            endpoint: "http://127.0.0.1:11434".into(),
            model: "m".into(),
            model_digest: "sha256:aa".into(),
            knobs: GuardKnobs::default(),
        }
    }

    fn signal(warrant: &str, outcome: GuardOutcome, at: u64) -> GuardSignal {
        GuardSignal {
            format: crate::guard::GUARD_SIGNAL_FORMAT.to_string(),
            warrant_id: warrant.to_string(),
            session_id: "s".to_string(),
            tool: "files.read".to_string(),
            content_digest: format!("digest-{at}"),
            content_bytes: 42,
            truncated: false,
            argument_names: vec!["text".to_string()],
            raw_excerpt: String::new(),
            count: 1,
            outcome,
            severity: "safe".to_string(),
            categories: Vec::new(),
            gated_by_category: false,
            mode: GuardMode::Observe,
            provenance: provenance(),
            at,
        }
    }

    fn log(signals: Vec<GuardSignal>) -> GuardLog {
        GuardLog {
            signals,
            sessions: Vec::new(),
            summaries: Vec::new(),
            unreadable_lines: 0,
        }
    }

    #[test]
    fn a_guard_verdict_is_never_written_into_the_label() {
        // The trap this module exists to avoid: exporting the guard's own opinion as ground truth
        // distils its misses into the next model as fact, and the miss becomes invisible because the
        // model and its labels agree.
        let rows = rows_from(
            &log(vec![signal("w1", GuardOutcome::Harmful, 10)]),
            &BTreeMap::new(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, None, "a flagged call is not a labelled call");
        assert_eq!(rows[0].guard_said.as_deref(), Some("harmful"));
        assert_eq!(rows[0].label_source, LabelSource::Unlabelled);
    }

    #[test]
    fn a_human_void_labels_harmful_and_a_settle_labels_benign() {
        let mut states = BTreeMap::new();
        states.insert("void".to_string(), WarrantState::Void);
        states.insert("settled".to_string(), WarrantState::Settled);
        let rows = rows_from(
            &log(vec![
                signal("void", GuardOutcome::Harmful, 10),
                signal("settled", GuardOutcome::Harmful, 20),
            ]),
            &states,
        );
        assert_eq!(rows[0].label, Some(true));
        assert_eq!(rows[0].label_source, LabelSource::WarrantVoided);
        assert_eq!(rows[1].label, Some(false));
        assert_eq!(rows[1].label_source, LabelSource::WarrantSettled);
        // And both say how weak that is.
        assert!(rows[0].label_source.granularity().contains("warrant-level"));
    }

    #[test]
    fn open_held_and_unreadable_are_three_different_reasons_for_no_label() {
        // Collapsing them would lose the distinction between "nobody has decided yet" and "we
        // cannot tell whether anybody decided", which is the same class of error as folding
        // `unknown` into `failed`.
        let mut states = BTreeMap::new();
        states.insert("open".to_string(), WarrantState::Open);
        states.insert("held".to_string(), WarrantState::Held);
        let rows = rows_from(
            &log(vec![
                signal("open", GuardOutcome::NotHarmful, 10),
                signal("held", GuardOutcome::NotHarmful, 20),
                signal("missing", GuardOutcome::NotHarmful, 30),
            ]),
            &states,
        );
        let reasons: Vec<&str> = rows
            .iter()
            .map(|r| r.why_unlabelled.as_deref().unwrap_or(""))
            .collect();
        assert!(reasons[0].contains("still open"), "{reasons:?}");
        assert!(reasons[1].contains("held"), "{reasons:?}");
        assert!(reasons[2].contains("could not be read"), "{reasons:?}");
        assert_eq!(
            reasons
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn a_signal_where_nothing_looked_is_not_a_row() {
        // A row whose only feature is "the backend was down" teaches nothing, and counting it would
        // inflate a corpus with the absence of observations.
        let rows = rows_from(
            &log(vec![
                signal("w", GuardOutcome::BackendUnavailable, 10),
                signal("w", GuardOutcome::SkippedOverBudget, 20),
                signal("w", GuardOutcome::Unparseable, 30),
                signal("w", GuardOutcome::NotHarmful, 40),
            ]),
            &BTreeMap::new(),
        );
        assert_eq!(rows.len(), 1, "only the classified call becomes a row");
        assert_eq!(rows[0].at, 40);
    }

    #[test]
    fn no_content_is_exported_only_a_digest_and_a_length() {
        // A guard log holds tool arguments; a corpus file gets copied to a training host. Carrying
        // the text would make every export a data-egress decision nobody was asked to make.
        let rows = rows_from(
            &log(vec![signal("w", GuardOutcome::Harmful, 10)]),
            &BTreeMap::new(),
        );
        let json = serde_json::to_string(&rows[0]).expect("serialise");
        assert!(json.contains("content_digest"), "{json}");
        assert!(json.contains("content_bytes"), "{json}");
        assert!(!json.contains("\"text\""), "{json}");
        assert!(!json.contains("arguments"), "{json}");
    }

    #[test]
    fn sufficiency_counts_labelled_rows_and_not_rows() {
        // A file of ten thousand unlabelled examples is a distribution sample, not a training set,
        // and reporting it as ready is how a recipe gets run on nothing.
        let unlabelled: Vec<Row> = (0..500)
            .map(|i| Row {
                format: CORPUS_ROW_FORMAT.to_string(),
                warrant_id: "w".into(),
                tool: "t".into(),
                content_digest: format!("d{i}"),
                content_bytes: 1,
                label: None,
                label_source: LabelSource::Unlabelled,
                why_unlabelled: Some("open".into()),
                guard_said: Some("not_harmful".into()),
                at: i,
            })
            .collect();
        let summary = summarise(&unlabelled);
        assert_eq!(summary.rows, 500);
        assert_eq!(summary.labelled, 0);
        let error = sufficient_for_training(&summary, 100).expect_err("refuses");
        assert!(error.contains("insufficient evidence"), "{error}");
        assert!(
            error.contains("grows by USING the product"),
            "the refusal must name what actually unblocks it: {error}"
        );
    }

    #[test]
    fn the_caveat_states_all_three_weaknesses() {
        let summary = summarise(&[]);
        let caveat = summary.caveat();
        assert!(caveat.contains("NO GUARD VERDICT IS A LABEL"), "{caveat}");
        assert!(caveat.contains("LABELS THAT EXIST ARE WEAK"), "{caveat}");
        assert!(caveat.contains("NO CONTENT IS EXPORTED"), "{caveat}");
    }

    #[test]
    fn a_summary_counts_distinct_warrants_rather_than_rows() {
        let mut states = BTreeMap::new();
        states.insert("a".to_string(), WarrantState::Void);
        states.insert("b".to_string(), WarrantState::Settled);
        let rows = rows_from(
            &log(vec![
                signal("a", GuardOutcome::Harmful, 10),
                signal("a", GuardOutcome::Harmful, 20),
                signal("b", GuardOutcome::NotHarmful, 30),
            ]),
            &states,
        );
        let summary = summarise(&rows);
        assert_eq!(summary.rows, 3);
        assert_eq!(summary.warrants, 2);
        assert_eq!(summary.labelled, 3);
        assert_eq!(summary.by_source["warrant_voided"], 2);
        assert_eq!(summary.by_source["warrant_settled"], 1);
    }
}
