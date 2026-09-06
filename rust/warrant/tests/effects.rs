//! L4-01: the effect decomposition registry, and the strict mode that refuses what it cannot classify.

use std::collections::BTreeSet;

use warrantor_warrant::effects::{Decomposition, Syscall};
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
