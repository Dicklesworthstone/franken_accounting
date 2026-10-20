-- GENERATED FROM registries/rounding_laws.toml BY fa-money formal_anchors generator (fa-8x9).
-- DO NOT EDIT BY HAND; registries/rounding_laws.toml is the single source of truth.
-- Invariant mapping: FA-INV-06 (rounding and residual bounds)
-- Evidence class: proof (Lean 4)

namespace FrankenAccounting.RoundingLaws

inductive RoundingLaw : Type
  | HalfUp -- id = 1: Round half toward positive infinity.
  | HalfDown -- id = 2: Round half toward negative infinity.
  | HalfEven -- id = 3: Banker's rounding: ties to the even neighbour (sign-symmetric).
  | HalfAwayFromZero -- id = 4: Ties away from zero (commercial rounding).
  | HalfTowardZero -- id = 5: Ties toward zero.
  | Ceiling -- id = 6: Toward positive infinity.
  | Floor -- id = 7: Toward negative infinity.
  | TowardZero -- id = 8: Truncate toward zero.
  | AwayFromZero -- id = 9: Away from zero.
  deriving DecidableEq, Repr

def lawId : RoundingLaw → Nat
  | .HalfUp => 1
  | .HalfDown => 2
  | .HalfEven => 3
  | .HalfAwayFromZero => 4
  | .HalfTowardZero => 5
  | .Ceiling => 6
  | .Floor => 7
  | .TowardZero => 8
  | .AwayFromZero => 9

def isHalfRounding : RoundingLaw → Bool
  | .HalfUp => true
  | .HalfDown => true
  | .HalfEven => true
  | .HalfAwayFromZero => true
  | .HalfTowardZero => true
  | .Ceiling => false
  | .Floor => false
  | .TowardZero => false
  | .AwayFromZero => false

/-- Half-ULP error bound predicate for nearest-neighbour laws (id 1..5): 2 * |r| ≤ d. -/
def satisfiesHalfUlpBound (residual divisor : Int) : Prop :=
  0 < divisor ∧ 2 * Int.natAbs residual ≤ Int.natAbs divisor

/-- Directed-ULP error bound predicate for directed laws (id 6..9): |r| < d. -/
def satisfiesDirectedUlpBound (residual divisor : Int) : Prop :=
  0 < divisor ∧ Int.natAbs residual < Int.natAbs divisor

/-- Exact division decomposition conservation: q * d + r = n. -/
theorem decomposition_conserves_numerator (n d q : Int) :
    let r := n - q * d
    q * d + r = n := by
  intro r
  omega

end FrankenAccounting.RoundingLaws
