//! Successful request keys span ordinary and target-derived entries and batches.
//! Every expected refusal is asserted independently, not inferred from agreement.

use super::*;
use fa_reference::{BatchVerdict, code as reference_code};

const MARCH: &str = "FY2026-P03";

struct History {
    kernel: Kernel,
    oracle: Oracle,
    periods: Vec<String>,
    usd: UnitId,
    refs: Vec<EntryRef>,
    publications: Vec<CommitSeq>,
}

impl History {
    fn new() -> Self {
        let (mut kernel, mut oracle, periods) = setup();
        open_period(&mut kernel, &mut oracle, MARCH, 0);
        let usd = kernel.book.units.lookup("USD").unwrap();
        Self {
            kernel,
            oracle,
            periods,
            usd,
            refs: Vec::new(),
            publications: Vec::new(),
        }
    }

    fn check_post(&mut self, intent: &Intent, expected: Verdict) {
        let before = self.kernel.db.frontier().unwrap();
        let count = self.oracle.journal_len();
        assert_eq!(self.oracle.post(intent), expected, "oracle: {intent:?}");
        let actual = kernel_post(&mut self.kernel, intent, self.usd, &self.refs);
        match (expected, actual) {
            (Verdict::Posted { index, .. }, Ok(posted @ Posted::Committed { .. })) => {
                assert_eq!(index, self.refs.len());
                assert_eq!(posted.recorded_at().0, before.0 + 1);
                self.refs.push(posted.entry_ref());
                self.publications.push(posted.recorded_at());
            }
            (Verdict::Recorded { index }, Ok(posted @ Posted::AlreadyRecorded { .. })) => {
                assert_eq!(posted.entry_ref(), self.refs[index]);
                assert_eq!(posted.recorded_at(), self.publications[index]);
                assert_eq!(self.kernel.db.frontier().unwrap(), before);
                assert_eq!(self.oracle.journal_len(), count);
            }
            (Verdict::Refused { code }, Err(refusal)) => {
                assert_eq!(refusal.code, code, "{intent:?}: {refusal}");
                assert_eq!(self.kernel.db.frontier().unwrap(), before);
                assert_eq!(self.oracle.journal_len(), count);
            }
            (expected, actual) => panic!("{intent:?}: expected {expected:?}, got {actual:?}"),
        }
        assert_eq!(self.oracle.journal_len(), self.refs.len());
    }

    fn post(&mut self, intent: &Intent) -> usize {
        let index = self.refs.len();
        self.check_post(
            intent,
            Verdict::Posted {
                index,
                period: MARCH.into(),
            },
        );
        index
    }

    fn replay(&mut self, intent: &Intent, index: usize) {
        self.check_post(intent, Verdict::Recorded { index });
    }

    fn refuse(&mut self, intent: &Intent, code: &'static str) {
        self.check_post(intent, Verdict::Refused { code });
    }

    fn check_batch(&mut self, key: &str, members: &[Intent], expected: BatchVerdict) {
        let before = self.kernel.db.frontier().unwrap();
        let count = self.oracle.journal_len();
        assert_eq!(
            self.oracle.post_batch(key.as_bytes(), members),
            expected,
            "oracle batch {key}: {members:?}"
        );
        let actual = kernel_batch(&mut self.kernel, key, members, self.usd, &self.refs);
        match (expected, actual) {
            (BatchVerdict::Posted { indices }, Ok(posted)) => {
                assert!(!posted.already_recorded);
                assert_eq!(indices, (count..count + members.len()).collect::<Vec<_>>());
                assert_eq!(posted.entries.len(), indices.len());
                assert_eq!(posted.recorded_at.0, before.0 + 1);
                self.publications
                    .extend(std::iter::repeat_n(posted.recorded_at, indices.len()));
                self.refs.extend(posted.entries);
            }
            (BatchVerdict::Recorded { indices }, Ok(posted)) => {
                assert!(posted.already_recorded);
                assert_eq!(
                    posted.entries,
                    indices
                        .iter()
                        .map(|index| self.refs[*index])
                        .collect::<Vec<_>>()
                );
                for index in indices {
                    assert_eq!(posted.recorded_at, self.publications[index]);
                }
                assert_eq!(self.kernel.db.frontier().unwrap(), before);
                assert_eq!(self.oracle.journal_len(), count);
            }
            (BatchVerdict::Refused { member, code }, Err(refusal)) => {
                assert_eq!(refusal.code, code, "batch {key}: {refusal}");
                if let Some(member) = member {
                    assert!(
                        refusal
                            .message
                            .starts_with(&format!("batch member {member}")),
                        "batch {key}: {refusal}"
                    );
                }
                assert_eq!(self.kernel.db.frontier().unwrap(), before);
                assert_eq!(self.oracle.journal_len(), count);
            }
            (expected, actual) => panic!("batch {key}: expected {expected:?}, got {actual:?}"),
        }
        assert_eq!(self.oracle.journal_len(), self.refs.len());
    }

    fn batch(&mut self, key: &str, members: &[Intent]) -> Vec<usize> {
        let indices: Vec<_> = (self.refs.len()..self.refs.len() + members.len()).collect();
        self.check_batch(
            key,
            members,
            BatchVerdict::Posted {
                indices: indices.clone(),
            },
        );
        indices
    }

    fn replay_batch(&mut self, key: &str, members: &[Intent], indices: &[usize]) {
        self.check_batch(
            key,
            members,
            BatchVerdict::Recorded {
                indices: indices.to_vec(),
            },
        );
    }

    fn refuse_batch(
        &mut self,
        key: &str,
        members: &[Intent],
        member: Option<usize>,
        code: &'static str,
    ) {
        self.check_batch(key, members, BatchVerdict::Refused { member, code });
    }

    fn verify(&self) {
        assert_registers_agree(
            &self.kernel,
            &self.oracle,
            &self.periods,
            &self.refs,
            "shared successful outcome keys",
        );
    }
}

fn ordinary(key: &str) -> Intent {
    maintenance_intent("Original", DateDay::parse("2026-03-15").unwrap(), 10, key)
}

fn pending(key: &str) -> Intent {
    Intent {
        class: "Pending".into(),
        ..ordinary(key)
    }
}

fn reversal(target: usize, key: &str) -> Intent {
    let mut intent = ordinary(key);
    intent.class = "Reversal".into();
    intent.reverses = Some(target);
    for leg in &mut intent.legs {
        leg.side = leg.side.flipped();
    }
    intent
}

fn release(target: usize, key: &str) -> Intent {
    let mut intent =
        maintenance_intent("Resolution", DateDay::parse("2026-03-15").unwrap(), 0, key);
    intent.resolves = Some(Resolve {
        target,
        posts: None,
    });
    intent
}

#[test]
fn shared_outcome_keys_cover_entry_and_batch_collisions() {
    // All sixteen owner/contender pairs, including two target-derived
    // entries with distinct targets. Fresh target identities do not create
    // a second caller-key namespace.
    for owner in ["Original", "Reversal", "Resolution", "Batch"] {
        let mut history = History::new();
        let original = history.post(&ordinary("source"));
        let other_original = history.post(&ordinary("other-source"));
        let hold = history.post(&pending("hold"));
        let other_hold = history.post(&pending("other-hold"));
        let owner_members = match owner {
            "Original" => vec![ordinary("shared")],
            "Reversal" => vec![reversal(original, "shared")],
            "Resolution" => vec![release(hold, "shared")],
            "Batch" => vec![ordinary("owner-member-0"), ordinary("owner-member-1")],
            _ => unreachable!(),
        };
        let owned = if owner == "Batch" {
            history.batch("shared", &owner_members)
        } else {
            vec![history.post(&owner_members[0])]
        };

        let mut changed = ordinary("shared");
        for leg in &mut changed.legs {
            leg.mantissa = 11;
        }
        for contender in [
            changed,
            reversal(other_original, "shared"),
            release(other_hold, "shared"),
        ] {
            history.refuse(&contender, reference_code::IDEMPOTENCY_CONFLICT);
        }
        history.refuse_batch(
            "shared",
            &[ordinary("fresh-batch-member")],
            None,
            reference_code::IDEMPOTENCY_CONFLICT,
        );
        // Preparing a member before discovering the occupied batch root
        // must not consume the member's otherwise unused key.
        history.post(&ordinary("fresh-batch-member"));

        if owner == "Batch" {
            history.replay_batch("shared", &owner_members, &owned);
        } else {
            history.replay(&owner_members[0], owned[0]);
        }
        // Refusing the shared key did not consume either fresh target.
        history.post(&reversal(other_original, "fresh-reversal"));
        history.post(&release(other_hold, "fresh-resolution"));
        history.verify();
    }
}

#[test]
fn shared_outcome_keys_preserve_authorization_and_atomic_refusals() {
    let mut history = History::new();
    let original = history.post(&ordinary("source"));
    let hold = history.post(&pending("hold"));
    let taken = ordinary("taken");
    let taken_index = history.post(&taken);

    let mut denied = taken.clone();
    denied.ops.clear();
    history.refuse(&denied, reference_code::CAPABILITY);
    denied.key = b"denied-new-key".to_vec();
    history.refuse(&denied, reference_code::CAPABILITY);
    history.post(&ordinary("denied-new-key"));
    let mut malformed = denied;
    malformed.key = taken.key.clone();
    malformed.legs[0].mantissa = 0;
    history.refuse(&malformed, reference_code::STRUCTURE);
    history.replay(&taken, taken_index);

    let reversed = reversal(original, "reversed");
    let reversed_index = history.post(&reversed);
    let resolved = release(hold, "resolved");
    let resolved_index = history.post(&resolved);
    // An unrelated successful key wins over an already-consumed target;
    // an unused key still reaches the target-specific refusal instead.
    history.refuse(
        &reversal(original, "taken"),
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.refuse(
        &release(hold, "taken"),
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.refuse(
        &reversal(original, "losing-reversal"),
        reference_code::ALREADY_REVERSED,
    );
    history.refuse(
        &release(hold, "losing-resolution"),
        reference_code::ALREADY_RESOLVED,
    );
    history.post(&ordinary("losing-reversal"));
    history.post(&ordinary("losing-resolution"));
    for (intent, index) in [(&reversed, reversed_index), (&resolved, resolved_index)] {
        let mut denied = intent.clone();
        denied.ops.clear();
        history.refuse(&denied, reference_code::CAPABILITY);
        history.replay(intent, index);
    }

    let members = vec![ordinary("member-0"), ordinary("member-1")];
    let indices = history.batch("outer", &members);
    let mut stronger_authority = members.clone();
    for member in &mut stronger_authority {
        member.ops.push("close".into());
    }
    history.replay_batch("outer", &stronger_authority, &indices);
    let mut denied = members.clone();
    for member in &mut denied {
        member.ops.clear();
    }
    history.refuse_batch("outer", &denied, Some(0), reference_code::CAPABILITY);
    history.refuse_batch("denied-outer", &denied, Some(0), reference_code::CAPABILITY);
    history.post(&ordinary("denied-outer"));
    let mut reordered = members.clone();
    reordered.reverse();
    history.refuse_batch(
        "outer",
        &reordered,
        None,
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.replay_batch("outer", &members, &indices);

    history.refuse_batch(
        "blocked-root",
        &[ordinary("outer")],
        Some(0),
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.post(&ordinary("blocked-root"));
    history.refuse_batch(
        "member-0",
        &[ordinary("staged-before-root-conflict")],
        None,
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.post(&ordinary("staged-before-root-conflict"));
    history.refuse_batch(
        "same-root-and-member",
        &[ordinary("same-root-and-member")],
        None,
        reference_code::IDEMPOTENCY_CONFLICT,
    );
    history.post(&ordinary("same-root-and-member"));

    let mut failed = vec![ordinary("aborted-first"), ordinary("aborted-second")];
    failed[1].legs[0].account = "missing".into();
    history.refuse_batch(
        "failed-outer",
        &failed,
        Some(1),
        reference_code::UNKNOWN_ACCOUNT,
    );
    // Correct the later failure and change the first member's content.
    // All three keys, and the first member's effects, must have rolled back.
    failed[1].legs[0].account = "6000".into();
    for leg in &mut failed[0].legs {
        leg.mantissa = 13;
    }
    let recovered = history.batch("failed-outer", &failed);
    history.replay_batch("failed-outer", &failed, &recovered);

    let source = history.post(&ordinary("atomic-target"));
    let competing = [
        reversal(source, "atomic-first"),
        reversal(source, "atomic-second"),
    ];
    history.refuse_batch(
        "atomic-outer",
        &competing,
        Some(1),
        reference_code::ALREADY_REVERSED,
    );
    history.post(&competing[0]);
    history.post(&ordinary("atomic-second"));
    history.post(&ordinary("atomic-outer"));

    let source = history.post(&ordinary("batch-reversal-source"));
    let hold = history.post(&pending("batch-resolution-hold"));
    let derived = [
        reversal(source, "derived-reversal"),
        release(hold, "derived-resolution"),
    ];
    let indices = history.batch("derived-outer", &derived);
    for key in ["derived-reversal", "derived-resolution"] {
        history.refuse(&ordinary(key), reference_code::IDEMPOTENCY_CONFLICT);
    }
    history.replay_batch("derived-outer", &derived, &indices);
    let mut changed = derived.clone();
    changed[1].key = b"changed-resolution".to_vec();
    history.refuse_batch(
        "derived-outer",
        &changed,
        Some(1),
        reference_code::ALREADY_RESOLVED,
    );
    history.post(&ordinary("changed-resolution"));
    history.verify();
}
