/-
  FrankenAccounting Formal Anchor — Reversal Balance Preservation & Netting Laws
  (plan §5.5, §8.1, §16.7, fa-8x9)
  Invariant mapping: FA-INV-01 (double-entry balance), FA-INV-08 (supersession netting laws)
  Evidence class: proof (Lean 4)
-/

namespace FrankenAccounting.Supersession

structure EntryTotals where
  debits : Int
  credits : Int
  deriving DecidableEq, Repr

def isBalanced (e : EntryTotals) : Prop :=
  e.debits = e.credits

/-- A `Reverses` entry swaps debits and credits of every leg. -/
def reverseEntry (e : EntryTotals) : EntryTotals :=
  ⟨e.credits, e.debits⟩

def combineEntries (a b : EntryTotals) : EntryTotals :=
  ⟨a.debits + b.debits, a.credits + b.credits⟩

/-- Theorem (FA-INV-01 / FA-INV-08): Reversing a balanced entry produces a balanced entry. -/
theorem reverse_preserves_balance (e : EntryTotals) (h : isBalanced e) :
    isBalanced (reverseEntry e) := by
  unfold isBalanced reverseEntry at *
  exact h.symm

/-- Theorem (FA-INV-08 exact_annihilation): Net effect `(debit - credit)` of an entry and its
    side-swapped reversal is identically zero. -/
theorem exact_annihilation_net_zero (e : EntryTotals) :
    let combined := combineEntries e (reverseEntry e)
    combined.debits - combined.credits = 0 := by
  simp [combineEntries, reverseEntry]
  omega

/-- Theorem (FA-INV-08 replacement_chain): Original `orig` + Reversal `reverseEntry orig` +
    Replacement `rep` has net effect `(debit - credit)` equal to `rep` alone. -/
theorem replacement_chain_equals_replacement (orig rep : EntryTotals) :
    let chain := combineEntries (combineEntries orig (reverseEntry orig)) rep
    chain.debits - chain.credits = rep.debits - rep.credits := by
  simp [combineEntries, reverseEntry]
  omega

/-- Theorem (FA-INV-08 reclassification_zero_net): A balanced reclassification between accounts
    contributes zero aggregate net `(debit - credit)` across the book. -/
theorem reclassification_zero_aggregate_net (reclass : EntryTotals) (h : isBalanced reclass) :
    reclass.debits - reclass.credits = 0 := by
  unfold isBalanced at h
  omega

end FrankenAccounting.Supersession
