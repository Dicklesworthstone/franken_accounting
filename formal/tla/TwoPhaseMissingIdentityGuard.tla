------------------- MODULE TwoPhaseMissingIdentityGuard -------------------
(*
  Planted Negative TLA+ Model (fa-8x9 acceptance):
  Identical to TwoPhaseWithExpiry EXCEPT the deterministic identity-uniqueness
  guard (`h \notin ResolvedHolds`) is removed from SweepExpire, allowing a race
  between CallerResolve(h, "Posts") and SweepExpire(h) to double-release hold `h`
  and violate `SingleResolutionPerHold`.
*)
EXTENDS Naturals, FiniteSets

Holds == {1, 2}
ExpiryTick == 2
MaxTick == 3

VARIABLES
  tick,
  resolutions

vars == <<tick, resolutions>>

ResolvedHolds == { r[1] : r \in resolutions }

Init ==
  /\ tick = 0
  /\ resolutions = {}

AdvanceTimeTick ==
  /\ tick < MaxTick
  /\ tick' = tick + 1
  /\ UNCHANGED resolutions

CallerResolve(h, disp) ==
  /\ disp \in {"Posts", "Voids"}
  /\ h \notin ResolvedHolds
  /\ resolutions' = resolutions \cup {<<h, disp>>}
  /\ UNCHANGED tick

\* PLANTED DEFECT: missing `h \notin ResolvedHolds` identity-uniqueness guard!
SweepExpireBuggy(h) ==
  /\ tick >= ExpiryTick
  /\ resolutions' = resolutions \cup {<<h, "Expires">>}
  /\ UNCHANGED tick

Next ==
  \/ AdvanceTimeTick
  \/ \E h \in Holds, d \in {"Posts", "Voids"} : CallerResolve(h, d)
  \/ \E h \in Holds : SweepExpireBuggy(h)

Spec == Init /\ [][Next]_vars

SingleResolutionPerHold ==
  \A h \in Holds : Cardinality({ r \in resolutions : r[1] = h }) <= 1

=============================================================================
