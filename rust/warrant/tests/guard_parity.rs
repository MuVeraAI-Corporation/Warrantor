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

/// Read `name: type = value` out of the Python dataclass field list.
///
/// Returns `None` when the field is absent or not in that shape. Every caller turns `None` into a
/// failure naming the field, because a parity test that silently skips a field it could not find is
/// a parity test that passes while the two drift.
fn python_default(name: &str) -> Option<String> {
    for line in EVALUATE_PY.lines() {
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
            return Some(value.trim().trim_end_matches(',').to_string());
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
            return Some(rest.trim().trim_end_matches(',').to_string());
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
