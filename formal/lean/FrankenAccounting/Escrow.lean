/-
  FrankenAccounting Formal Anchor — Escrow & Reservation Bounds (plan §5.4, §16.7, fa-8x9)
  Invariant mapping: FA-INV-09 (reservation & escrow conservation)
  Evidence class: proof (Lean 4)
-/

namespace FrankenAccounting.Escrow

structure EscrowCell where
  postedBalance : Nat
  reservedHold : Nat
  deriving DecidableEq, Repr

def wellFormed (c : EscrowCell) : Prop :=
  c.reservedHold ≤ c.postedBalance

def available (c : EscrowCell) : Nat :=
  c.postedBalance - c.reservedHold

/-- Theorem: Available + ReservedHold equals PostedBalance for every well-formed escrow cell. -/
theorem escrow_conservation (c : EscrowCell) (h : wellFormed c) :
    available c + c.reservedHold = c.postedBalance := by
  unfold available wellFormed at *
  omega

/-- Admitting a hold of `amount ≤ available c` preserves well-formedness. -/
def admitHold (c : EscrowCell) (amount : Nat) : EscrowCell :=
  ⟨c.postedBalance, c.reservedHold + amount⟩

theorem admitHold_preserves_wellFormed (c : EscrowCell) (amount : Nat)
    (hWf : wellFormed c) (hAvail : amount ≤ available c) :
    wellFormed (admitHold c amount) := by
  unfold wellFormed admitHold available at *
  omega

end FrankenAccounting.Escrow
