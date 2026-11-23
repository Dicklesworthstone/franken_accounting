------------------- MODULE TwoPhaseMissingIdentityGuard -------------------
(*
  Planted Negative TLA+ Model (fa-8x9 acceptance):
  Identical to TwoPhaseWithExpiry EXCEPT the deterministic identity-uniqueness
  guard (`h \notin ResolvedHolds`) is removed from SweepExpire, allowing a race
  between CallerResolve(h, "Posts") and SweepExpire(h) to double-release hold `h`
  and violate `SingleResolutionPerHold`.
*)
EXTENDS Naturals

VARIABLES tick, resolutions
Base == INSTANCE TwoPhaseWithExpiry
vars == <<tick, resolutions>>

\* PLANTED DEFECT: missing `h \notin ResolvedHolds` identity-uniqueness guard!
SweepExpireBuggy(h) ==
  /\ tick >= Base!ExpiryTick
  /\ resolutions' = resolutions \cup {<<h, "Expires">>}
  /\ UNCHANGED tick

Next ==
  \/ Base!Next
  \/ \E h \in Base!Holds : SweepExpireBuggy(h)

Spec == Base!Init /\ [][Next]_vars

SingleResolutionPerHold == Base!SingleResolutionPerHold
ExpiryRespectsTimeEvidence == Base!ExpiryRespectsTimeEvidence

=============================================================================
