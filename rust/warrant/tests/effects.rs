//! L4-01: the effect decomposition registry, and the strict mode that refuses what it cannot classify.

use std::collections::BTreeSet;

use warrantor_warrant::effects::Syscall;

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
