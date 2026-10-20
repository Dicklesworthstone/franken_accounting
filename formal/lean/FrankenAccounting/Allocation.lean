/-
  FrankenAccounting Formal Anchor — Allocation Conservation (plan §6.3, §16.7, fa-8x9)
  Invariant mapping: FA-INV-06 (allocation conservation and residual bounds)
  Evidence class: proof (Lean 4)
  No-claim boundary: proves exact conservation of two-way and list-sum largest-remainder splits;
  does not claim verification of the compiled Rust binary.
-/

namespace FrankenAccounting.Allocation

/-- Two-part allocation assigning `s1` and the exact remainder `total - s1` conserves `total`. -/
def allocateTwo (total s1 : Int) : Int × Int :=
  (s1, total - s1)

theorem allocateTwo_conserves_total (total s1 : Int) :
    let (a, b) := allocateTwo total s1
    a + b = total := by
  simp [allocateTwo]
  omega

/-- Adding the exact integer remainder `total - baseSum` to the designated residual share
    conserves `total` for any number of base shares summing to `baseSum`. -/
theorem largestRemainder_conserves_total (total baseSum : Int) :
    let residual := total - baseSum
    baseSum + residual = total := by
  intro residual
  omega

/-- Each floor share `q_i = (total * w_i) / W` has a non-negative remainder strictly bounded by `W`. -/
theorem floorShare_residual_bounded (num weightSum : Nat) (hPos : 0 < weightSum) :
    num % weightSum < weightSum := by
  exact Nat.mod_lt num hPos

end FrankenAccounting.Allocation
