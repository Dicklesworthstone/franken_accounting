//! Admission (plan §5.1 step 1, FA-INV-10 "authorization before
//! observation"): decided from the capability and the intent's explicit
//! inputs alone, before the kernel reads anything from storage.

use fa_model::Id128;
use fa_money::UnitId;
use fgdb_types::{CommitSeq, VId};

use crate::capability::{Capability, Profile};
use crate::denial::Denial;
use crate::op::Op;

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

/// Admit or deny an intent before any storage observation. Order: the
/// capability is the actor's; an Agent never writes trunk; the op is held;
/// the book is in scope; every leg is within its unit's ceiling.
pub fn admit(cap: &Capability, intent: &Intent<'_>) -> Result<(), Denial> {
    if cap.holder() != intent.principal {
        return Err(Denial::NotHolder {
            holder: cap.holder(),
            principal: intent.principal,
        });
    }
    if cap.profile() == Profile::Agent && intent.trunk {
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
