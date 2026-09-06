//! L4-01: the effect decomposition registry, and the strict mode that refuses what it cannot classify.

use std::collections::BTreeSet;

use warrantor_warrant::effects::{
    Classified, Decomposition, DecompositionRegistry, Syscall, UnclassifiedPolicy,
    EFFECT_REGISTRY_FORMAT,
};
use warrantor_warrant::SideEffectClass;

#[test]
fn there_are_nine_syscalls_and_every_one_round_trips_through_its_wire_word() {
    assert_eq!(
        Syscall::ALL.len(),
        9,
        "nine, not ninety: a tenth entry is a decomposition, not a syscall"
    );
    let words: BTreeSet<&str> = Syscall::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        words,
        ["net", "cred", "exec", "mutate", "msg", "spend", "delegate", "actuate", "attest"]
            .into_iter()
            .collect()
    );
    for syscall in Syscall::ALL {
        assert_eq!(Syscall::parse(syscall.as_str()), Some(syscall));
    }
    // The blueprint's wider vocabulary is not admitted as verbs: it lands on the table, it does
    // not grow it. "delete" is the one an operator will reach for first.
    for word in [
        "delete", "read", "write", "spawn", "stop", "restore", "NET", "",
    ] {
        assert_eq!(Syscall::parse(word), None, "{word:?} must not parse");
    }
}

#[test]
fn a_decomposition_is_a_tool_and_a_set_of_verbs_joined_with_plus() {
    let d = Decomposition::parse("deploy.to_prod=exec+net+mutate").expect("parses");
    assert_eq!(d.tool(), "deploy.to_prod");
    assert_eq!(
        d.syscalls(),
        &[Syscall::Exec, Syscall::Net, Syscall::Mutate]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    // Rendered in set order, so two operators declaring the same thing produce the same string.
    assert_eq!(d.render(), "net+exec+mutate");
    // Whitespace around the tool and around each verb is forgiven; a dot in the tool is the
    // <server>.<tool> shape the proxy publishes, and the LAST '=' splits.
    let spaced = Decomposition::parse("  files.write_file = mutate ").expect("parses");
    assert_eq!(spaced.tool(), "files.write_file");
}

#[test]
fn a_malformed_declaration_is_refused_rather_than_defaulted() {
    for (raw, needle) in [
        ("deploy.to_prod", "tool=verb+verb"),       // no '='
        ("=mutate", "names no tool"),               // no tool
        ("files.delete=", "decomposes to nothing"), // no verbs
        ("files.delete=delete", "not an effect syscall"),
        ("files.delete=mutate+mutate", "twice"),
        ("files.delete=write", "not an effect syscall"), // the OLD vocabulary
    ] {
        let error = Decomposition::parse(raw).expect_err(raw);
        assert!(error.contains(needle), "{raw:?}: {error}");
    }
    // The refusal names all nine, because the operator's next keystroke depends on it.
    let error = Decomposition::parse("x=delete").expect_err("refused");
    for verb in Syscall::ALL {
        assert!(error.contains(verb.as_str()), "{error}");
    }
}

#[test]
fn a_decomposition_projects_to_its_most_consequential_class_never_lower() {
    let class_of = |raw: &str| Decomposition::parse(raw).expect("parses").class();
    assert_eq!(class_of("t=net"), SideEffectClass::Read);
    assert_eq!(class_of("t=attest"), SideEffectClass::Read);
    assert_eq!(class_of("t=net+mutate"), SideEffectClass::Write);
    assert_eq!(class_of("t=exec+net+mutate"), SideEffectClass::Write);
    assert_eq!(class_of("t=net+spend"), SideEffectClass::Financial);
    assert_eq!(class_of("t=mutate+actuate"), SideEffectClass::Destructive);
    assert_eq!(class_of("t=spend+actuate"), SideEffectClass::Destructive);
    // Actuate is consequential under I-08 through its projection, not around it.
    assert!(class_of("t=actuate").is_consequential());
    // Nothing projects to Physical: the proxy does not block it in observe mode, so a projection
    // onto it would weaken a refusal that exists today.
    for syscall in Syscall::ALL {
        assert_ne!(
            syscall.projection(),
            SideEffectClass::Physical,
            "{syscall:?}"
        );
    }
}

#[test]
fn the_builtin_registry_declares_exactly_the_four_staged_github_tools_as_writes() {
    let registry = DecompositionRegistry::builtin();
    // Four GitHub tools plus the governed HTTP call (Task 2.5), which is `net` only.
    assert_eq!(registry.len(), 5);
    for tool in [
        "github.create_pr",
        "github.comment",
        "github.request_review",
        "github.add_label",
    ] {
        let d = registry
            .get(tool)
            .unwrap_or_else(|| panic!("{tool} is builtin"));
        // Every one is a network call; the projection is Write, which is what
        // EffectRegistry::github() implied before and what staged_classes stages.
        assert!(d.syscalls().contains(&Syscall::Net), "{tool}");
        assert_eq!(d.class(), SideEffectClass::Write, "{tool}");
    }
    // The HTTP call is net-only: it reads a response, so its projection is Read; the WRITE that
    // matters (an outbound POST) is bounded by the catalog's permitted methods at settle.
    let http = registry.get("http.call").expect("http.call is builtin");
    assert!(http.syscalls().contains(&Syscall::Net));
    assert_eq!(http.syscalls().len(), 1, "http.call is net only");
    assert_eq!(http.class(), SideEffectClass::Read, "http.call");
    assert!(
        registry.get("github.merge_pr").is_none(),
        "nothing the settle path cannot perform"
    );
}

#[test]
fn a_tool_declared_twice_is_refused_and_a_builtin_cannot_be_redeclared_differently() {
    let mut registry = DecompositionRegistry::new();
    registry
        .insert(Decomposition::parse("files.write_file=mutate").expect("parses"))
        .expect("first");
    let error = registry
        .insert(Decomposition::parse("files.write_file=net").expect("parses"))
        .expect_err("second");
    assert!(error.contains("declared twice"), "{error}");

    // Merging: identical is fine (two files may both state the obvious), different is refused.
    let mut base = DecompositionRegistry::builtin();
    let mut same = DecompositionRegistry::new();
    same.insert(Decomposition::parse("github.create_pr=net+mutate").expect("parses"))
        .expect("insert");
    base.merge(same)
        .expect("identical redeclaration is not a conflict");

    let mut weaker = DecompositionRegistry::new();
    weaker
        .insert(Decomposition::parse("github.create_pr=net").expect("parses"))
        .expect("insert");
    let error = base.merge(weaker).expect_err("a builtin redeclared weaker");
    assert!(error.contains("github.create_pr"), "{error}");
    assert!(
        error.contains("net+mutate"),
        "the existing decomposition is named: {error}"
    );
}

#[test]
fn a_registry_document_round_trips_and_a_foreign_format_is_refused_not_read() {
    let mut registry = DecompositionRegistry::new();
    registry
        .insert(Decomposition::parse("deploy.to_prod=exec+net+mutate").expect("parses"))
        .expect("insert");
    let body = registry.to_json().expect("serializes");
    assert!(body.contains(EFFECT_REGISTRY_FORMAT), "{body}");
    let back = DecompositionRegistry::from_json(&body).expect("reads its own output");
    assert_eq!(back, registry);

    let foreign = r#"{"format":"warrantor.effect-registry/2","tools":{"t":["net"]}}"#;
    let error = DecompositionRegistry::from_json(foreign).expect_err("refused");
    assert!(error.contains("warrantor.effect-registry/2"), "{error}");
    assert!(error.contains(EFFECT_REGISTRY_FORMAT), "{error}");

    let unversioned = r#"{"tools":{"t":["net"]}}"#;
    let error = DecompositionRegistry::from_json(unversioned).expect_err("refused");
    assert!(error.contains("format"), "{error}");

    // The old vocabulary inside a document is a refusal naming the word, not a silent Read.
    let old = format!(r#"{{"format":"{EFFECT_REGISTRY_FORMAT}","tools":{{"t":["write"]}}}}"#);
    let error = DecompositionRegistry::from_json(&old).expect_err("refused");
    assert!(error.contains("write"), "{error}");

    let empty = format!(r#"{{"format":"{EFFECT_REGISTRY_FORMAT}","tools":{{"t":[]}}}}"#);
    let error = DecompositionRegistry::from_json(&empty).expect_err("refused");
    assert!(error.contains("decomposes to nothing"), "{error}");
}

#[test]
fn strict_mode_refuses_an_undeclared_tool_and_permissive_mode_names_the_guess() {
    let registry = DecompositionRegistry::builtin();
    match registry.classify("github.create_pr", UnclassifiedPolicy::Refuse) {
        Ok(Classified::Declared(d)) => assert_eq!(d.render(), "net+mutate"),
        other => panic!("a builtin is declared: {other:?}"),
    }
    let refusal = registry
        .classify("files.write_file", UnclassifiedPolicy::Refuse)
        .expect_err("strict mode refuses");
    assert_eq!(refusal.tool, "files.write_file");
    let sentence = refusal.to_string();
    assert!(
        sentence.contains("no declared effect decomposition"),
        "{sentence}"
    );
    assert!(
        sentence.contains("--upstream-effects 'files.write_file="),
        "{sentence}"
    );
    assert!(sentence.contains(EFFECT_REGISTRY_FORMAT), "{sentence}");
    assert_eq!(
        registry.classify("files.write_file", UnclassifiedPolicy::GuessRead),
        Ok(Classified::Guessed),
        "permissive mode guesses, and says it is a guess"
    );
}

/// One row of the corpus. `expected` is a verb list for a declared tool or the word `refuse`.
#[derive(serde::Deserialize)]
struct CorpusRow {
    tool: String,
    #[allow(dead_code)]
    input_schema: serde_json::Value,
    expected: serde_json::Value,
}

/// The B-04 gate: present the registry with a corpus of tool schemas it has never seen the
/// schemas of; every declared tool classifies to exactly its declared verbs, every undeclared
/// tool is refused under strict mode, and nothing is defaulted. There is no classifier under
/// test: the schema column exists to prove that nothing in it is consulted, which is the point.
#[test]
fn the_corpus_classifies_by_declaration_and_refuses_every_unseen_tool_under_strict_mode() {
    let registry = DecompositionRegistry::from_json(include_str!("fixtures/effect-registry.json"))
        .expect("the fixture registry reads");
    let corpus = include_str!("fixtures/tool-schemas.jsonl");
    let mut declared = 0usize;
    let mut refused = 0usize;
    for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
        let row: CorpusRow = serde_json::from_str(line).expect(line);
        let verdict = registry.classify(&row.tool, UnclassifiedPolicy::Refuse);
        match row.expected {
            serde_json::Value::String(ref word) if word == "refuse" => {
                let refusal = verdict.expect_err(&row.tool);
                assert_eq!(refusal.tool, row.tool);
                refused += 1;
            }
            serde_json::Value::Array(ref verbs) => {
                let expected: BTreeSet<Syscall> = verbs
                    .iter()
                    .map(|v| Syscall::parse(v.as_str().expect("verb")).expect("a known verb"))
                    .collect();
                match verdict {
                    Ok(Classified::Declared(d)) => {
                        assert_eq!(d.syscalls(), &expected, "{}", row.tool)
                    }
                    other => panic!("{} should be declared: {other:?}", row.tool),
                }
                declared += 1;
            }
            other => panic!("{}: bad expectation {other}", row.tool),
        }
    }
    assert_eq!(
        (declared, refused),
        (20, 6),
        "the corpus shape is part of the test"
    );
    // Under the shipped policy the same six are guesses, and every guess is visible as one.
    let guessed = corpus
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<CorpusRow>(l).expect(l).tool)
        .filter(|t| registry.classify(t, UnclassifiedPolicy::GuessRead) == Ok(Classified::Guessed))
        .count();
    assert_eq!(guessed, 6);
    eprintln!(
        "effect-registry corpus: {declared} declared, {refused} refused under strict mode, 0 \
         defaulted"
    );
}
