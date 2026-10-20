/-
  FrankenAccounting Formal Anchor — Period State Machine (plan §7.2, §16.7, fa-8x9)
  Invariant mapping: FA-INV-03 (period state machine & admissibility)
  Evidence class: proof (Lean 4)
-/

namespace FrankenAccounting.Period

inductive PeriodState : Type
  | Future
  | Open
  | SoftClosed
  | Closed
  | Locked
  deriving DecidableEq, Repr

/-- Lawful single-step transitions of `fa-time/src/period.rs`. -/
inductive Step : PeriodState → PeriodState → Prop
  | openFuture : Step .Future .Open
  | softCloseOpen : Step .Open .SoftClosed
  | closeOpen : Step .Open .Closed
  | closeSoftClosed : Step .SoftClosed .Closed
  | lockClosed : Step .Closed .Locked
  | reopenSoftClosedToOpen : Step .SoftClosed .Open
  | reopenClosedToOpen : Step .Closed .Open
  | reopenClosedToSoftClosed : Step .Closed .SoftClosed
  | reopenLockedToOpen : Step .Locked .Open
  | reopenLockedToSoftClosed : Step .Locked .SoftClosed

/-- Theorem: `Future` is unreachable from any non-Future state (once opened, a period is never Future again). -/
theorem future_unreachable_from_non_future (s : PeriodState) :
    ¬ Step s .Future := by
  intro h
  cases h

/-- Theorem: `Future` cannot jump directly to `Locked` without passing through `Open` and `Closed`. -/
theorem no_direct_future_to_locked :
    ¬ Step .Future .Locked := by
  intro h
  cases h

/-- Theorem: `Open` cannot jump directly to `Locked` without first closing (`Closed`). -/
theorem no_direct_open_to_locked :
    ¬ Step .Open .Locked := by
  intro h
  cases h

end FrankenAccounting.Period
