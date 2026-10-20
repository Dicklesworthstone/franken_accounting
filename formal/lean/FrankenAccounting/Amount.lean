/-
  FrankenAccounting Formal Anchor — Amount Group Laws (plan §6.1, §16.7, fa-8x9)
  Invariant mapping: FA-INV-01 (per-unit balance), FA-INV-02 (exact fixed-scale Amount)
  Evidence class: proof (Lean 4)
  No-claim boundary: models exact integer mantissas at a fixed UnitId and checked i128 bounds;
  does not claim verification of the compiled Rust binary.
-/

namespace FrankenAccounting.Amount

structure UnitId where
  id : Nat
  deriving DecidableEq, Repr

/-- Unbounded mathematical Amount at a fixed unit scale for group-law proofs. -/
structure ExactAmount (u : UnitId) where
  mantissa : Int
  deriving DecidableEq, Repr

namespace ExactAmount

variable {u : UnitId}

def zero : ExactAmount u := ⟨0⟩

def add (a b : ExactAmount u) : ExactAmount u :=
  ⟨a.mantissa + b.mantissa⟩

def neg (a : ExactAmount u) : ExactAmount u :=
  ⟨-a.mantissa⟩

def sub (a b : ExactAmount u) : ExactAmount u :=
  ⟨a.mantissa - b.mantissa⟩

theorem add_assoc (a b c : ExactAmount u) :
    add (add a b) c = add a (add b c) := by
  cases a; cases b; cases c
  simp [add, Int.add_assoc]

theorem add_comm (a b : ExactAmount u) :
    add a b = add b a := by
  cases a; cases b
  simp [add, Int.add_comm]

theorem add_zero (a : ExactAmount u) :
    add a zero = a := by
  cases a
  simp [add, zero]

theorem zero_add (a : ExactAmount u) :
    add zero a = a := by
  cases a
  simp [add, zero]

theorem add_neg_cancel (a : ExactAmount u) :
    add a (neg a) = zero := by
  cases a
  simp [add, neg, zero, Int.add_right_neg]

theorem neg_add_cancel (a : ExactAmount u) :
    add (neg a) a = zero := by
  cases a
  simp [add, neg, zero, Int.add_left_neg]

end ExactAmount

/-- i128 representable range bounds: [-2^127, 2^127 - 1]. -/
def i128Min : Int := -(2 ^ 127 : Int)
def i128Max : Int := (2 ^ 127 : Int) - 1

def inI128Bounds (m : Int) : Bool :=
   decide (i128Min ≤ m ∧ m ≤ i128Max)

/-- Checked addition modeled as `Option`: returns `some` iff the exact sum lies within i128 bounds. -/
def checkedAdd {u : UnitId} (a b : ExactAmount u) : Option (ExactAmount u) :=
  let s := a.mantissa + b.mantissa
  if inI128Bounds s then some ⟨s⟩ else none

theorem checkedAdd_comm {u : UnitId} (a b : ExactAmount u) :
    checkedAdd a b = checkedAdd b a := by
  simp [checkedAdd, Int.add_comm]

theorem checkedAdd_exact_when_some {u : UnitId} (a b res : ExactAmount u)
    (h : checkedAdd a b = some res) :
    res = ExactAmount.add a b := by
  unfold checkedAdd at h
  split at h
  · injection h with h_eq
    exact h_eq.symm
  · contradiction

end FrankenAccounting.Amount
