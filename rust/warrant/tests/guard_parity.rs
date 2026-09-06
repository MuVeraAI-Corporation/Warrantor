//! The two guards must be the same guard: Rust's `GuardKnobs` against Python's `OllamaBackend`.
//!
//! # The defect this exists to make impossible
//!
//! This crate shipped `num_ctx: 4096` for eight releases while every published figure was measured
//! at 8192 by `python/warrantor_ml`. The consequence was not that the guard was worse — it was that
//! **nobody knew what it was**, because the configuration in production was not the configuration
//! any measurement was taken under, and the console, the roadmap and the CLI help all quoted the
//! measured numbers as though it were.
//!
//! It was fixed twice. First `MEASURED_NUM_CTX` replaced the literal in the library; then it turned
//! out the *binary* had its own `4096` fallback, so the fix had survived its own fix one layer up,
//! and only `warrantor guard bench` printing the running configuration caught that.
//!
//! Both fixes pin **one knob**. This test pins the *relationship*: it reads the Python evaluator's
//! own source and asserts that every sampling option it sends matches what `GuardKnobs::default()`
//! sends. The next divergence will not be `num_ctx` — it will be a knob nobody thought to pin, and
//! a test about one constant would not see it.
//!
//! # Why it reads the source rather than importing anything
//!
//! There is no Python in a `cargo test` run, no interpreter to call, and no shared schema between
//! the two implementations — the whole reason they could drift. `include_str!` makes the Python file
//! a compile-time input to a Rust test, so the two definitions are compared without either language
//! being able to run the other. The cost is that this test is coupled to the shape of a Python
//! literal; the assertions below say so, and fail with the line they could not read rather than
//! silently passing when the shape changes.

use warrantor_warrant::guard::{GuardKnobs, MEASURED_NUM_CTX};

/// The Python evaluator, as a compile-time string.
const EVALUATE_PY: &str = include_str!("../../../python/warrantor_ml/src/warrantor_ml/evaluate.py");

/// The declared deployed configuration, as a compile-time string.
///
/// Added when `evaluate.py` stopped carrying its own literals. Its dataclass defaults and its
/// `_options()` dict now read `serving.NUM_CTX`, `serving.TEMPERATURE` and so on, because four
/// places in that repository declared a serving configuration and only three were bound to each
/// other. These assertions must follow the VALUE, not the file it used to live in -- so the
/// readers below chase a `serving.NAME` indirection into this file rather than comparing against
/// the name of a constant. Deleting the chase would make every assertion here compare
/// `"serving.NUM_CTX"` against `"8192"` and fail on punctuation, which is how a parity test gets
/// deleted instead of fixed.
const SERVING_PY: &str = include_str!("../../../python/warrantor_ml/src/warrantor_ml/serving.py");

/// Resolve a `serving.NAME` indirection to the literal `serving.py` declares for `NAME`.
///
/// A value that is not an indirection is returned unchanged. An indirection naming a constant
/// `serving.py` does not declare returns `None`, so the caller fails naming the field rather than
/// comparing against the text `"serving.WHATEVER"` -- the failure mode this whole file exists to
/// prevent is a comparison that silently stops being made.
fn resolve_serving(value: &str) -> Option<String> {
    let Some(name) = value.strip_prefix("serving.") else {
        return Some(value.to_string());
    };
    for line in SERVING_PY.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(name) else {
            continue;
        };
        // `NUM_CTX: Final[int] = 8192` -- and not `NUM_CTX_SOMETHING`.
        if !rest.starts_with(':') {
            continue;
        }
        if let Some((_, literal)) = rest.split_once('=') {
            return Some(literal.trim().trim_end_matches(',').to_string());
        }
    }
    None
}

/// Read `name: type = value` out of the Python dataclass field list.
///
/// Returns `None` when the field is absent or not in that shape. Every caller turns `None` into a
/// failure naming the field, because a parity test that silently skips a field it could not find is
/// a parity test that passes while the two drift.
fn python_default(name: &str) -> Option<String> {
    python_default_in(EVALUATE_PY, name)
}

/// `python_default`, against an explicitly named source. `serving.py` declares its values as
/// `NAME: Final[int] = 8192`, which is the same `name: type = value` shape.
fn python_default_in(source: &str, name: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(name) else {
            continue;
        };
        // `num_ctx: int = 8192` — and not `num_ctx_something`.
        if !rest.starts_with(':') {
            continue;
        }
        if let Some((_, value)) = rest.split_once('=') {
            // A trailing comma is stripped because the same field shape appears both as a dataclass
            // default (`num_ctx: int = 8192`) and inside a call (`num_ctx=..., `). Leaving it on
            // made the comparison fail on punctuation rather than on a real divergence, which is
            // exactly the noise that gets a parity test deleted.
            return resolve_serving(value.trim().trim_end_matches(','));
        }
    }
    None
}

/// Read a value out of the pinned `_options()` dict: `"temperature": 0.0,`.
fn python_option(key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    for line in EVALUATE_PY.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&needle) {
            return resolve_serving(rest.trim().trim_end_matches(','));
        }
    }
    None
}

#[test]
fn the_context_window_is_the_same_on_both_sides() {
    // The one that shipped wrong. Compared against the Python source rather than against a Rust
    // constant, so the comparison is with the thing that actually produced the published figures.
    let python = python_default("num_ctx").expect("evaluate.py declares a num_ctx default");
    assert_eq!(
        python, "8192",
        "the Python evaluator's num_ctx default moved; every published figure was measured at the \
         old one, so either re-measure or do not move it"
    );
    assert_eq!(
        MEASURED_NUM_CTX.to_string(),
        python,
        "MEASURED_NUM_CTX must equal the Python evaluator's num_ctx: the figures this product \
         quotes were measured by that evaluator, and a Rust guard running at a different context \
         window is a guard nobody has measured"
    );
    assert_eq!(GuardKnobs::default().num_ctx, MEASURED_NUM_CTX);
}

#[test]
fn the_generated_token_cap_is_the_same_on_both_sides() {
    let python = python_default("num_predict").expect("evaluate.py declares a num_predict default");
    assert_eq!(
        GuardKnobs::default().num_predict.to_string(),
        python,
        "num_predict caps the verdict length. A cap that differs between the measured and the \
         shipped configuration truncates differently, and a truncated verdict is an unparseable one \
         -- which this system records as NO COVERAGE rather than as a miss, so the divergence would \
         show up as a coverage gap nobody could explain"
    );
}

#[test]
fn the_seed_is_the_same_on_both_sides() {
    let python = python_default("seed").expect("evaluate.py declares a seed default");
    assert_eq!(
        GuardKnobs::default().seed.to_string(),
        python,
        "the seed is part of the determinism contract on both sides"
    );
}

#[test]
fn every_sampling_option_python_pins_is_pinned_to_the_same_value_here() {
    // `_options()` is the dict Python actually sends to Ollama, which is the thing that has to
    // match — a dataclass default that never reaches the wire would prove nothing.
    let knobs = GuardKnobs::default();

    let temperature = python_option("temperature").expect("_options() pins temperature");
    assert_eq!(
        temperature, "0.0",
        "greedy decoding is the determinism contract; a non-zero temperature on either side makes \
         two runs of the same case two different measurements"
    );
    assert_eq!(knobs.temperature_milli, 0);

    let top_p = python_option("top_p").expect("_options() pins top_p");
    assert_eq!(top_p, "1.0");
    assert_eq!(
        knobs.top_p_milli, 1000,
        "top_p is carried in thousandths here and as a float there; 1000 IS 1.0, and this assertion \
         is the only place that equivalence is written down"
    );

    let top_k = python_option("top_k").expect("_options() pins top_k");
    assert_eq!(top_k, "1");
    assert_eq!(knobs.top_k, 1);
}

#[test]
fn the_controversial_policy_is_the_same_on_both_sides() {
    // The knob that silently became a no-op once a fine-tune extinguished the third severity class.
    // On the base model it moves recall 0.8488 -> 0.8011, so a default that differed between the
    // two implementations would be a several-point difference nobody attributed to configuration.
    let python = python_default("controversial_is_harmful")
        .expect("evaluate.py declares controversial_is_harmful");
    assert_eq!(python, "True");
    assert!(
        GuardKnobs::default().controversial_is_harmful,
        "ambiguity resolving towards the louder answer is the recall-preserving reading, and it has \
         to be the same reading on both sides"
    );
}

#[test]
fn the_python_source_is_still_shaped_the_way_these_assertions_read_it() {
    // The failure mode of a source-reading test: the file is reformatted, every `python_default`
    // returns None, every assertion above is skipped, and the suite goes green while the two
    // implementations drift. Each test above already `expect`s its field — this one states the
    // dependency plainly so a reformat fails with a message about the coupling rather than about a
    // missing field.
    assert!(
        EVALUATE_PY.contains("class OllamaBackend") || EVALUATE_PY.contains("num_ctx"),
        "evaluate.py no longer looks like the file these parity assertions read. They compare a \
         Rust struct against a Python literal by parsing the literal; if its shape changed, this \
         test has to change with it rather than silently checking nothing."
    );
    for field in ["num_ctx", "num_predict", "seed", "controversial_is_harmful"] {
        assert!(
            python_default(field).is_some(),
            "cannot read the Python default for {field}: the parity comparison is not being made"
        );
    }
    for option in ["temperature", "top_p", "top_k"] {
        assert!(
            python_option(option).is_some(),
            "cannot read the pinned Python option {option}: the parity comparison is not being made"
        );
    }
}

#[test]
fn the_quantization_the_python_side_declares_is_the_one_this_crate_serves() {
    // The axis nothing pinned. `num_ctx` was pinned twice and then measured inert -- 0 of 493
    // decision changes across a sixteenfold range, both models (`R23`). Quantization was pinned
    // nowhere and moves 4 to 18 verdicts per thousand at the deployed default, in a direction that
    // differs by model family (`R13`, `R32`, `R33`), so a deployer may assume neither that it errs
    // safe nor that it errs conservative.
    //
    // `GuardKnobs` has no quantization field, so there is no knob to compare. What this crate does
    // carry is the model tag it resolves by default, and an Ollama tag names its quantization after
    // the final colon. Asserting on the tag is the honest available binding: an unlabeled tag is a
    // configuration nobody can check, which is the state of all five 2026-08-22 candidate tags.
    let declared =
        python_default_in(SERVING_PY, "QUANTIZATION").expect("serving.py declares QUANTIZATION");
    assert_eq!(
        declared, "\"Q4_K_M\"",
        "serving.py's declared quantization moved. Every published guard figure was measured at \
         the old one, and the effect is not verdict-neutral: re-measure, or do not move it"
    );
    let unquoted = declared.trim_matches('"');
    assert!(
        warrantor_warrant::guard::DEFAULT_GUARD_MODEL.contains(unquoted),
        "the CLI's default guard model tag ({}) must name the quantization the Python side \
         declares it measured at ({unquoted}); a tag that does not name it is a configuration \
         nobody can check",
        warrantor_warrant::guard::DEFAULT_GUARD_MODEL
    );
}

/// The body of a `NAME: Final[...] = (` or `= {` block in `serving.py`, one trimmed line per entry.
///
/// Returns `None` when the block is absent or not in that shape, so a caller fails naming what it
/// could not read rather than looping over nothing and passing.
fn python_block_body(source: &str, name: &str) -> Option<Vec<String>> {
    let mut lines = source.lines();
    let mut closer = None;
    for line in lines.by_ref() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(name) else {
            continue;
        };
        if !rest.starts_with(':') {
            continue;
        }
        closer = match rest.trim_end().chars().last() {
            Some('(') => Some(')'),
            Some('{') => Some('}'),
            _ => None,
        };
        if closer.is_some() {
            break;
        }
    }
    let closer = closer?;
    let mut body = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with(closer) {
            return Some(body);
        }
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            body.push(trimmed.to_string());
        }
    }
    None
}

/// The keys `serving.REQUIRED_KEYS` lists, read out of the tuple literal.
fn python_required_keys() -> Option<Vec<String>> {
    Some(
        python_block_body(SERVING_PY, "REQUIRED_KEYS")?
            .iter()
            .map(|entry| entry.trim_end_matches(',').trim_matches('"').to_string())
            .collect(),
    )
}

/// `serving.DEPLOYED` as `(key, the NAME of the constant behind it)` pairs.
fn python_deployed_entries() -> Option<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for line in python_block_body(SERVING_PY, "DEPLOYED")? {
        let (key, value) = line.split_once(':')?;
        entries.push((
            key.trim().trim_matches('"').to_string(),
            value.trim().trim_end_matches(',').to_string(),
        ));
    }
    Some(entries)
}

#[test]
fn the_deployed_record_declares_every_key_the_python_gate_compares() {
    // `serving.REQUIRED_KEYS` is what the promotion gate refuses on. If a key could be listed
    // there without a constant behind it, `DEPLOYED` would carry a value this side cannot read and
    // the two implementations would be bound on a shorter list than the gate enforces.
    //
    // The list is READ from REQUIRED_KEYS rather than written out here. Spelled as a literal
    // array of seven names, this test asserted the seven it knew about and nothing about the list
    // itself, so an eighth key in REQUIRED_KEYS with no constant behind it left cargo green -- the
    // exact case the paragraph above claims to prevent. The Python suite catches a key added
    // everywhere, because the evaluator's descriptor would not carry it; only this side can catch
    // a key the record lists and declares nothing for.
    let required = python_required_keys().expect("serving.py declares REQUIRED_KEYS as a tuple");
    assert_eq!(
        required.len(),
        7,
        "serving.REQUIRED_KEYS is {required:?}; a key added or removed there changes what the \
         promotion gate refuses on, so it changes this binding too"
    );
    let deployed = python_deployed_entries().expect("serving.py declares DEPLOYED as a mapping");
    let mut declared: Vec<String> = deployed.iter().map(|(key, _)| key.clone()).collect();
    let mut compared = required.clone();
    declared.sort();
    compared.sort();
    assert_eq!(
        declared, compared,
        "serving.DEPLOYED and serving.REQUIRED_KEYS disagree on which keys exist. The gate \
         refuses on REQUIRED_KEYS and reads values out of DEPLOYED, so a key in one and not the \
         other is either a comparison against a missing value or a value nothing compares"
    );
    for (key, constant) in &deployed {
        assert!(
            python_default_in(SERVING_PY, constant).is_some(),
            "serving.DEPLOYED[{key:?}] is {constant}, which serving.py does not declare as a \
             constant this side can read. A key the gate refuses on must have a value both \
             implementations can see, or they are bound on a shorter list than the gate enforces"
        );
    }
    // The one that shipped wrong, asserted against the record rather than against evaluate.py.
    assert_eq!(
        python_default_in(SERVING_PY, "NUM_CTX").as_deref(),
        Some(MEASURED_NUM_CTX.to_string().as_str()),
        "MEASURED_NUM_CTX must equal the deployed record's num_ctx"
    );
}
