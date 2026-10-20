----------------------------- MODULE MergeTrain -----------------------------
(*
  FrankenAccounting Bounded Model — Batched Exact-Tree Merge Train
  (fa-6dw, fa-cat, fa-8x9)
  Invariant mapping:
    - Gate verdict contract: trunk only advances to a tree with a GREEN verdict;
      every queued candidate is eventually landed or ejected naming its failing step.
  Evidence class: bounded_model (TLA+ / TLC)
  Stated bounds:
    - Candidates = {1, 2, 3} (<= 5 candidates, <= 2 red)
    - RedCandidates \subseteq Candidates with Cardinality(RedCandidates) <= 2
*)
EXTENDS Naturals, FiniteSets

Candidates == {1, 2, 3}
RedCandidates == {2}

VARIABLES
  candState,        \* [Candidates -> {"queued", "stacked", "gating", "bisecting", "landed", "ejected"}]
  trunkVerdict,     \* "green" (trunk starts green and must remain green)
  gatedGreen        \* SUBSET Candidates proven green (individually or at batch tip)

vars == <<candState, trunkVerdict, gatedGreen>>

Init ==
  /\ candState = [c \in Candidates |-> "queued"]
  /\ trunkVerdict = "green"
  /\ gatedGreen = {}

StackCandidate(c) ==
  /\ candState[c] = "queued"
  /\ candState' = [candState EXCEPT ![c] = "stacked"]
  /\ UNCHANGED <<trunkVerdict, gatedGreen>>

StartGate(c) ==
  /\ candState[c] = "stacked"
  /\ candState' = [candState EXCEPT ![c] = "gating"]
  /\ UNCHANGED <<trunkVerdict, gatedGreen>>

GateGreen(c) ==
  /\ candState[c] = "gating"
  /\ c \notin RedCandidates
  /\ gatedGreen' = gatedGreen \cup {c}
  /\ candState' = [candState EXCEPT ![c] = "landed"]
  /\ trunkVerdict' = "green"

GateInfraUnrunRetry(c) ==
  /\ candState[c] = "gating"
  /\ candState' = [candState EXCEPT ![c] = "stacked"]
  /\ UNCHANGED <<trunkVerdict, gatedGreen>>

GateRedEnterBisect(c) ==
  /\ candState[c] = "gating"
  /\ c \in RedCandidates
  /\ candState' = [candState EXCEPT ![c] = "bisecting"]
  /\ UNCHANGED <<trunkVerdict, gatedGreen>>

BisectAndEject(c) ==
  /\ candState[c] = "bisecting"
  /\ c \in RedCandidates
  /\ candState' = [candState EXCEPT ![c] = "ejected"]
  /\ UNCHANGED <<trunkVerdict, gatedGreen>>

StutterWhenAllTerminal ==
  /\ \A c \in Candidates : candState[c] \in {"landed", "ejected"}
  /\ UNCHANGED vars

Next ==
  \/ \E c \in Candidates : StackCandidate(c)
  \/ \E c \in Candidates : StartGate(c)
  \/ \E c \in Candidates : GateGreen(c)
  \/ \E c \in Candidates : GateInfraUnrunRetry(c)
  \/ \E c \in Candidates : GateRedEnterBisect(c)
  \/ \E c \in Candidates : BisectAndEject(c)
  \/ StutterWhenAllTerminal

Spec == Init /\ [][Next]_vars

\* Safety 1: Trunk always has a green verdict.
TrunkAlwaysGreen ==
  trunkVerdict = "green"

\* Safety 2: Every landed candidate was proven green and is never a red candidate.
LandedCandidatesWereGatedGreen ==
  \A c \in Candidates : (candState[c] = "landed") => (c \in gatedGreen /\ c \notin RedCandidates)

=============================================================================
