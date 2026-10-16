//! Admission (plan §5.1 step 1, FA-INV-10 "authorization before
//! observation"): decided from the capability and the intent's explicit
//! inputs alone, before the kernel reads anything from storage.
//!
//! **Scope caveats** (`accounts`, `periods`, `effective ≤ date`,
//! `known_at ≤ seq`, `branch`) are judged by [`reach`] against what an act
//! reaches, before any query is constructed and never by filtering a result
//! (plan §14.2, interim posture of Appendix H R-WARDEN). [`admit`] judges
//! an act on the whole book, so a scoped token is refused there; only acts
//! that name their accounts and periods (a post, a period transition, a
//! scoped read) call [`admit_within`] or [`reach`] with a narrower reach.

use std::collections::BTreeSet;

use fa_model::Id128;
use fa_money::UnitId;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::capability::{Capability, Profile};
use crate::denial::Denial;
use crate::op::Op;

/// Where an act observes the book's recorded history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observes {
    /// The head: every write, which reads and extends the current state.
    Head,
    /// A fixed recorded frontier a read selected (`AS KNOWN AT`).
    At(CommitSeq),
}

/// What an act reaches, judged against the scope caveats by [`reach`].
/// `None` in a dimension means the act reaches all of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reach<'a> {
    /// The branch acted on; `None` when the act names none.
    pub branch: Option<Id128>,
    pub observes: Observes,
    /// The periods reached, by code; `None` is every period.
    pub periods: Option<&'a [&'a str]>,
    /// The last effective day reached; `None` is unbounded, or not known
    /// before the read (fail closed under an `effective` caveat).
    pub through: Option<DateDay>,
    /// The accounts reached; `None` is every account.
    pub accounts: Option<&'a [VId]>,
}

impl Reach<'static> {
    /// The whole book at the head: every act that is not decomposed into
    /// accounts and periods (ticks, sweeps, approvals, attestations,
    /// evidence, checkpoints, revocations, activations).
    #[must_use]
    pub fn whole_book(trunk: bool) -> Self {
        Self {
            branch: trunk.then_some(Id128::TRUNK),
            observes: Observes::Head,
            periods: None,
            through: None,
            accounts: None,
        }
    }
}

/// The `accounts` caveat compiled for one book: each root's account vid and
/// every `CHILD_OF` descendant. The kernel compiles it from the caveat's own
/// roots downward, so compiling observes nothing outside the scope; an
/// unknown root contributes nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountScope {
    members: BTreeSet<VId>,
}

impl AccountScope {
    #[must_use]
    pub fn compiled(members: BTreeSet<VId>) -> Self {
        Self { members }
    }

    #[must_use]
    pub fn contains(&self, account: VId) -> bool {
        self.members.contains(&account)
    }

    #[must_use]
    pub fn members(&self) -> &BTreeSet<VId> {
        &self.members
    }
}

/// What admission sees of a write intent: who acts, where it writes, and
/// the explicit legs `(unit, mantissa)` in payload order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent<'a> {
    pub principal: VId,
    /// True when the intent writes trunk (the only writable coordinate
    /// until branches land; an Agent may never write it).
    pub trunk: bool,
    /// The op the write needs before any read: `post` for a posting entry,
    /// the control row's preparer op for a control.
    pub op: Op,
    /// The book the intent writes (the `books` caveat is judged against it).
    pub book: Id128,
    pub legs: &'a [(UnitId, i128)],
}

/// Admit or deny an act on the whole book before any storage observation.
/// Order: the capability is the actor's; an Agent never writes trunk; the
/// op is held; the book is in scope; every leg is within its unit's
/// ceiling; the scope caveats admit the whole book (a scoped token is
/// refused).
pub fn admit(cap: &Capability, intent: &Intent<'_>) -> Result<(), Denial> {
    admit_within(cap, intent, &Reach::whole_book(intent.trunk), None)
}

/// [`admit`] for an act that names what it reaches: [`admit_base`], then
/// [`reach`] over `r` with the compiled `accounts` scope.
pub fn admit_within(
    cap: &Capability,
    intent: &Intent<'_>,
    r: &Reach<'_>,
    accounts: Option<&AccountScope>,
) -> Result<(), Denial> {
    admit_base(cap, intent)?;
    reach(cap, r, accounts)
}

/// The checks that precede every reach: the capability is the actor's, an
/// Agent never writes trunk, the op is held, the book is in scope, and
/// every leg is within its unit's ceiling. A kernel that compiles the
/// `accounts` caveat (compiling reads the chart) runs this first, so
/// nothing is read for a token that may not act here at all, then [`reach`].
pub fn admit_base(cap: &Capability, intent: &Intent<'_>) -> Result<(), Denial> {
    admit_base_as(cap, intent, false)
}

/// [`admit_base`] for a dry run, which writes nothing: every check except
/// the Agent's trunk denial (plan §15.3, `fa post --dry-run` is implied for
/// Agent-profile capabilities). The plan binds this capability, and
/// committing it runs [`admit`] again, which still refuses an Agent on
/// trunk, so no Agent plan can publish.
pub fn admit_base_for_plan(cap: &Capability, intent: &Intent<'_>) -> Result<(), Denial> {
    admit_base_as(cap, intent, true)
}

fn admit_base_as(cap: &Capability, intent: &Intent<'_>, planning: bool) -> Result<(), Denial> {
    if cap.holder() != intent.principal {
        return Err(Denial::NotHolder {
            holder: cap.holder(),
            principal: intent.principal,
        });
    }
    if cap.profile() == Profile::Agent && intent.trunk && !planning {
        return Err(Denial::AgentOnTrunk);
    }
    require(
        cap,
        intent.op,
        &format!("writing this intent (`{}`)", intent.op),
    )?;
    scope(cap, intent.book)?;
    if !cap.ceilings().is_empty() {
        for (leg, (unit, mantissa)) in intent.legs.iter().enumerate() {
            match cap.ceilings().get(unit) {
                None => {
                    return Err(Denial::UnboundedUnit { leg, unit: *unit });
                }
                Some(ceiling) if mantissa > ceiling => {
                    return Err(Denial::CeilingExceeded {
                        leg,
                        unit: *unit,
                        mantissa: *mantissa,
                        ceiling: *ceiling,
                    });
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// The scope caveats admit `r` (plan §14.2): every caveat the capability
/// carries covers its dimension of the act. Decided from the request alone
/// (and the compiled `accounts` scope), before any query is constructed.
/// A capability with an `accounts` caveat and no compiled scope is refused.
pub fn reach(
    cap: &Capability,
    r: &Reach<'_>,
    accounts: Option<&AccountScope>,
) -> Result<(), Denial> {
    if let Some(held) = cap.branch()
        && r.branch != Some(held)
    {
        let value = match r.branch {
            Some(b) => format!("branch {}", b.to_hex()),
            None => "an act that names no branch".into(),
        };
        return Err(out_of_scope("branch", value));
    }
    if let Some(pin) = cap.known_at_pin() {
        match r.observes {
            Observes::Head => {
                return Err(out_of_scope(
                    "known_at",
                    format!(
                        "an act at the book head (the token is pinned at known-at <= {})",
                        pin.0
                    ),
                ));
            }
            Observes::At(seq) if seq > pin => {
                return Err(out_of_scope(
                    "known_at",
                    format!("known-at {} (the token is pinned at <= {})", seq.0, pin.0),
                ));
            }
            Observes::At(_) => {}
        }
    }
    if let Some(held) = cap.periods() {
        let Some(codes) = r.periods else {
            return Err(out_of_scope("periods", "every period of the book".into()));
        };
        if let Some(code) = codes.iter().find(|c| !held.contains(**c)) {
            return Err(out_of_scope("periods", format!("period `{code}`")));
        }
    }
    if let Some(bound) = cap.effective_bound() {
        match r.through {
            None => {
                return Err(out_of_scope(
                    "effective",
                    format!(
                        "an effective range not bounded before the read (the token reaches effective <= {})",
                        bound.render()
                    ),
                ));
            }
            Some(day) if day > bound => {
                return Err(out_of_scope(
                    "effective",
                    format!(
                        "effective date {} (the token reaches <= {})",
                        day.render(),
                        bound.render()
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    if cap.accounts().is_some() {
        let Some(reached) = r.accounts else {
            return Err(out_of_scope("accounts", "every account of the book".into()));
        };
        let Some(scope) = accounts else {
            return Err(out_of_scope(
                "accounts",
                "an act whose account scope was not compiled for this book".into(),
            ));
        };
        if let Some(v) = reached.iter().find(|v| !scope.contains(**v)) {
            return Err(out_of_scope("accounts", format!("account {:032x}", v.0)));
        }
    }
    Ok(())
}

/// Admit a read before any storage observation: the capability belongs to
/// the actor, holds `read`, and admits the book. Reading trunk is permitted
/// for an Agent; the trunk and amount laws govern writes only.
///
/// The kernel must then apply [`current`] at its current authority frontier
/// and check revocation before observing the requested data. Keeping those
/// checks separate lets a wrong actor, missing op, or excluded book refuse
/// before the kernel even reads its frontier. A historical report coordinate
/// never replaces the current authority frontier.
pub fn admit_read(cap: &Capability, principal: VId, book: Id128) -> Result<(), Denial> {
    if cap.holder() != principal {
        return Err(Denial::NotHolder {
            holder: cap.holder(),
            principal,
        });
    }
    require(cap, Op::Read, "reading this book")?;
    scope(cap, book)
}

fn out_of_scope(caveat: &'static str, value: String) -> Denial {
    Denial::OutOfScope { caveat, value }
}

/// The capability is current at the admission point `at` (plan §14.2): a
/// declared bound `expires_at = n` admits iff `at < n`. `at` is an explicit
/// input; this crate never reads a clock or the book.
pub fn current(cap: &Capability, at: CommitSeq) -> Result<(), Denial> {
    match cap.expires_at() {
        Some(expires_at) if at >= expires_at => Err(Denial::Expired { expires_at, at }),
        _ => Ok(()),
    }
}

/// The capability's `books` caveat admits `book` (plan §14.2): caveats are
/// conjunctive, so a token confined to other books authorizes nothing here.
pub fn scope(cap: &Capability, book: Id128) -> Result<(), Denial> {
    if cap.admits_book(book) {
        Ok(())
    } else {
        Err(Denial::OutOfScope {
            caveat: "books",
            value: book.to_hex(),
        })
    }
}

/// The capability holds `op`; `what` names the act for the refusal.
pub fn require(cap: &Capability, op: Op, what: &str) -> Result<(), Denial> {
    if cap.holds(op) {
        Ok(())
    } else {
        Err(Denial::MissingOp {
            op,
            what: what.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USD: UnitId = UnitId(0);
    const EUR: UnitId = UnitId(1);
    const BOOK: Id128 = Id128([4; 16]);

    fn intent(principal: VId, legs: &[(UnitId, i128)]) -> Intent<'_> {
        Intent {
            principal,
            trunk: true,
            op: Op::Post,
            book: BOOK,
            legs,
        }
    }

    #[test]
    fn admission_order_is_holder_then_agent_then_op_then_ceilings() {
        let legs = [(USD, 10), (USD, 10)];
        let human = Capability::embedded(VId(1), &["post"]).unwrap();
        assert_eq!(admit(&human, &intent(VId(1), &legs)), Ok(()));
        assert_eq!(
            admit(&human, &intent(VId(2), &legs)).unwrap_err().kind(),
            "not_holder"
        );
        let reader = Capability::embedded(VId(1), &["read"]).unwrap();
        let d = admit(&reader, &intent(VId(1), &legs)).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-011", "missing_op"));

        // An Agent holding `post` is still refused on trunk, before the op check.
        let agent = Capability::new(VId(5), Profile::Agent, &[Op::Read], VId(1)).unwrap();
        let d = admit(&agent, &intent(VId(5), &legs)).unwrap_err();
        assert_eq!((d.code(), d.exit()), ("FA-REF-013", 7));
        assert!(d.cite().contains("fa-s7x"), "{}", d.cite());
        assert!(!d.fix().contains("fa draft"), "{}", d.fix());
        let off_trunk = Intent {
            trunk: false,
            ..intent(VId(5), &legs)
        };
        assert_eq!(admit(&agent, &off_trunk).unwrap_err().kind(), "missing_op");
    }

    #[test]
    fn ceilings_bound_every_leg_and_a_bounded_token_admits_only_its_units() {
        let cap = Capability::embedded(VId(1), &["post"])
            .unwrap()
            .with_ceiling(USD, 100)
            .unwrap();
        assert_eq!(
            admit(&cap, &intent(VId(1), &[(USD, 100), (USD, 100)])),
            Ok(())
        );
        let d = admit(&cap, &intent(VId(1), &[(USD, 100), (USD, 101)])).unwrap_err();
        assert_eq!(
            d,
            Denial::CeilingExceeded {
                leg: 1,
                unit: USD,
                mantissa: 101,
                ceiling: 100
            }
        );
        assert_eq!(d.code(), "FA-REF-015");
        assert_eq!(
            admit(&cap, &intent(VId(1), &[(EUR, 1), (EUR, 1)])).unwrap_err(),
            Denial::UnboundedUnit { leg: 0, unit: EUR }
        );
    }

    #[test]
    fn a_books_caveat_refuses_other_books_after_the_op_check() {
        let legs = [(USD, 10), (USD, 10)];
        let scoped = Capability::embedded(VId(1), &["post"])
            .unwrap()
            .for_books(&[BOOK])
            .unwrap();
        assert_eq!(admit(&scoped, &intent(VId(1), &legs)), Ok(()));
        let elsewhere = Intent {
            book: Id128([5; 16]),
            ..intent(VId(1), &legs)
        };
        let d = admit(&scoped, &elsewhere).unwrap_err();
        assert_eq!(
            (d.code(), d.kind(), d.exit()),
            ("FA-REF-011", "out_of_scope", 7)
        );
        assert!(
            d.message().contains(&Id128([5; 16]).to_hex()),
            "{}",
            d.message()
        );
        // The op is judged first: a reader confined elsewhere is told about the op.
        let reader = Capability::embedded(VId(1), &["read"])
            .unwrap()
            .for_books(&[BOOK])
            .unwrap();
        assert_eq!(admit(&reader, &elsewhere).unwrap_err().kind(), "missing_op");
        assert_eq!(scope(&scoped, BOOK), Ok(()));
    }

    #[test]
    fn reach_judges_every_scope_caveat_from_the_request_alone() {
        let base = Capability::embedded(VId(1), &["read", "post"]).unwrap();
        let book_wide = Reach::whole_book(true);
        assert_eq!(reach(&base, &book_wide, None), Ok(()), "no scope caveat");
        let march = ["FY2026-P03"];
        let named = Reach {
            branch: Some(Id128::TRUNK),
            observes: Observes::At(CommitSeq(5)),
            periods: Some(&march),
            through: Some(DateDay(100)),
            accounts: None,
        };

        // known_at: an act at the head is refused (a write observes it); a
        // frontier at or below the pin admits.
        let pinned = base.clone().known_at_most(CommitSeq(5));
        let d = reach(&pinned, &book_wide, None).unwrap_err();
        assert_eq!(
            (d.code(), d.kind(), d.exit()),
            ("FA-REF-011", "out_of_scope", 7)
        );
        assert!(d.message().contains("`known_at` caveat"), "{}", d.message());
        assert!(d.fix().contains("--as-known-at <seq>"), "{}", d.fix());
        assert_eq!(reach(&pinned, &named, None), Ok(()));
        let later = Reach {
            observes: Observes::At(CommitSeq(6)),
            ..named
        };
        let d = reach(&pinned, &later, None).unwrap_err();
        assert!(d.message().contains("known-at 6"), "{}", d.message());

        // periods: named codes inside the caveat; the whole book is refused.
        let march_only = base.clone().for_periods(&["FY2026-P03"]).unwrap();
        assert_eq!(reach(&march_only, &named, None), Ok(()));
        let d = reach(&march_only, &book_wide, None).unwrap_err();
        assert!(d.message().contains("every period"), "{}", d.message());
        let april = ["FY2026-P04"];
        let d = reach(
            &march_only,
            &Reach {
                periods: Some(&april),
                ..named
            },
            None,
        )
        .unwrap_err();
        assert!(d.message().contains("`FY2026-P04`"), "{}", d.message());

        // effective: a bounded reach at or before the date; unbounded refuses.
        let through_100 = base.clone().effective_through(DateDay(100));
        assert_eq!(reach(&through_100, &named, None), Ok(()));
        for through in [Some(DateDay(101)), None] {
            let d = reach(&through_100, &Reach { through, ..named }, None).unwrap_err();
            assert!(
                d.message().contains("`effective` caveat"),
                "{}",
                d.message()
            );
        }

        // branch: the named branch only; a trunk-confined token reaches trunk.
        let drafted = base.clone().on_branch(Id128([7; 16])).unwrap();
        let d = reach(&drafted, &named, None).unwrap_err();
        assert!(d.fix().contains("fa-s7x"), "{}", d.fix());
        let on_draft = Reach {
            branch: Some(Id128([7; 16])),
            ..named
        };
        assert_eq!(reach(&drafted, &on_draft, None), Ok(()));
        assert!(
            reach(
                &drafted,
                &Reach {
                    branch: None,
                    ..named
                },
                None
            )
            .is_err()
        );
        let trunk_only = base.clone().on_branch(Id128::TRUNK).unwrap();
        assert_eq!(reach(&trunk_only, &book_wide, None), Ok(()));

        // accounts: judged against the compiled scope; uncompiled admits nothing.
        let tree = base.for_accounts(&["6100"]).unwrap();
        let scope = AccountScope::compiled([VId(61), VId(611)].into_iter().collect());
        let legs = [VId(611), VId(61)];
        let in_tree = Reach {
            accounts: Some(&legs),
            ..named
        };
        assert_eq!(reach(&tree, &in_tree, Some(&scope)), Ok(()));
        assert!(reach(&tree, &in_tree, None).is_err());
        let cross = [VId(611), VId(10)];
        let d = reach(
            &tree,
            &Reach {
                accounts: Some(&cross),
                ..named
            },
            Some(&scope),
        )
        .unwrap_err();
        assert!(
            d.message().contains(&format!("account {:032x}", 10)),
            "{}",
            d.message()
        );
        let d = reach(&tree, &named, Some(&scope)).unwrap_err();
        assert!(d.message().contains("every account"), "{}", d.message());
    }

    #[test]
    fn admit_refuses_a_scoped_token_on_the_whole_book_after_the_base_checks() {
        let legs = [(USD, 10), (USD, 10)];
        let scoped = Capability::embedded(VId(1), &["post"])
            .unwrap()
            .for_periods(&["FY2026-P03"])
            .unwrap();
        let d = admit(&scoped, &intent(VId(1), &legs)).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-011", "out_of_scope"));
        // The holder and the op are judged before the reach.
        assert_eq!(
            admit(&scoped, &intent(VId(2), &legs)).unwrap_err().kind(),
            "not_holder"
        );
        let march = ["FY2026-P03"];
        let r = Reach {
            branch: Some(Id128::TRUNK),
            observes: Observes::Head,
            periods: Some(&march),
            through: Some(DateDay(0)),
            accounts: None,
        };
        assert_eq!(
            admit_within(&scoped, &intent(VId(1), &legs), &r, None),
            Ok(())
        );
    }

    #[test]
    fn reads_are_admitted_for_the_holder_holding_read_in_its_books() {
        let reader = Capability::embedded(VId(1), &["read"]).unwrap();
        assert_eq!(admit_read(&reader, VId(1), BOOK), Ok(()));
        assert_eq!(
            admit_read(&reader, VId(2), BOOK).unwrap_err().kind(),
            "not_holder"
        );
        let poster = Capability::embedded(VId(1), &["post"]).unwrap();
        assert_eq!(
            admit_read(&poster, VId(1), BOOK).unwrap_err().kind(),
            "missing_op"
        );
        let elsewhere = reader.for_books(&[Id128([5; 16])]).unwrap();
        assert_eq!(
            admit_read(&elsewhere, VId(1), BOOK).unwrap_err().kind(),
            "out_of_scope"
        );
        // An Agent reads trunk: its confinement is on writes.
        let agent = Capability::new(VId(1), Profile::Agent, &[Op::Read], VId(9)).unwrap();
        assert_eq!(admit_read(&agent, VId(1), BOOK), Ok(()));
    }

    #[test]
    fn expiry_is_a_strict_commit_sequence_bound() {
        let cap = Capability::embedded(VId(1), &["post"])
            .unwrap()
            .expiring_at(CommitSeq(10));
        assert_eq!(current(&cap, CommitSeq(9)), Ok(()));
        let d = current(&cap, CommitSeq(10)).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-014", "expired"));
        assert!(current(&cap, CommitSeq(11)).is_err());
        let forever = Capability::embedded(VId(1), &["post"]).unwrap();
        assert_eq!(current(&forever, CommitSeq(u64::MAX)), Ok(()));
    }

    #[test]
    fn an_agent_can_read_trunk_but_still_cannot_write_it() {
        // A ceiling must be positive (`BadCeiling` otherwise); the trunk
        // refusal below is the Agent profile's, not the ceiling's.
        let agent = Capability::new(VId(5), Profile::Agent, &[Op::Read, Op::Post], VId(1))
            .unwrap()
            .for_books(&[BOOK])
            .unwrap()
            .with_ceiling(USD, 1)
            .unwrap();
        assert_eq!(admit_read(&agent, VId(5), BOOK), Ok(()));
        assert_eq!(current(&agent, CommitSeq(42)), Ok(()));
        assert_eq!(
            admit(&agent, &intent(VId(5), &[(USD, 1)])).unwrap_err(),
            Denial::AgentOnTrunk
        );
    }

    /// Planning lifts only the Agent's trunk denial (plan §15.3): the
    /// holder, op, book and ceiling checks still run in the same order, and
    /// committing re-admits through [`admit`], which still refuses.
    #[test]
    fn an_agent_may_plan_on_trunk_within_every_other_admission_check() {
        let agent = Capability::new(VId(5), Profile::Agent, &[Op::Read, Op::Post], VId(1))
            .unwrap()
            .for_books(&[BOOK])
            .unwrap()
            .with_ceiling(USD, 10)
            .unwrap();
        assert_eq!(
            admit_base_for_plan(&agent, &intent(VId(5), &[(USD, 10)])),
            Ok(())
        );
        assert_eq!(
            admit_base(&agent, &intent(VId(5), &[(USD, 10)])).unwrap_err(),
            Denial::AgentOnTrunk
        );
        assert_eq!(
            admit_base_for_plan(&agent, &intent(VId(6), &[(USD, 10)])).unwrap_err(),
            Denial::NotHolder {
                holder: VId(5),
                principal: VId(6),
            }
        );
        assert!(matches!(
            admit_base_for_plan(&agent, &intent(VId(5), &[(USD, 11)])).unwrap_err(),
            Denial::CeilingExceeded { leg: 0, .. }
        ));
        let reader = Capability::new(VId(5), Profile::Agent, &[Op::Read], VId(1))
            .unwrap()
            .for_books(&[BOOK])
            .unwrap();
        assert_eq!(
            admit_base_for_plan(&reader, &intent(VId(5), &[(USD, 1)]))
                .unwrap_err()
                .kind(),
            "missing_op"
        );
    }

    #[test]
    fn read_admission_requires_the_actor_read_op_and_book_in_that_order() {
        let other = Id128([5; 16]);
        let writer = Capability::new(VId(5), Profile::Agent, &[Op::Post], VId(1))
            .unwrap()
            .for_books(&[BOOK])
            .unwrap();
        assert_eq!(
            admit_read(&writer, VId(6), other).unwrap_err(),
            Denial::NotHolder {
                holder: VId(5),
                principal: VId(6),
            }
        );
        let missing = admit_read(&writer, VId(5), other).unwrap_err();
        assert_eq!(
            (missing.code(), missing.kind()),
            ("FA-REF-011", "missing_op")
        );
        let reader = Capability::new(VId(5), Profile::Agent, &[Op::Read], VId(1))
            .unwrap()
            .for_books(&[BOOK])
            .unwrap()
            .expiring_at(CommitSeq(10));
        assert_eq!(
            admit_read(&reader, VId(5), other).unwrap_err(),
            Denial::OutOfScope {
                caveat: "books",
                value: other.to_hex(),
            }
        );
        assert_eq!(admit_read(&reader, VId(5), BOOK), Ok(()));
        assert_eq!(current(&reader, CommitSeq(9)), Ok(()));
        assert_eq!(
            current(&reader, CommitSeq(10)).unwrap_err(),
            Denial::Expired {
                expires_at: CommitSeq(10),
                at: CommitSeq(10),
            }
        );
    }
}
