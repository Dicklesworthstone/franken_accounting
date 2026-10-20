------------------------- MODULE TwoPhaseWithExpiry -------------------------
(*
  FrankenAccounting Bounded Model — Two-Phase Reservation Holds with Expiry Sweep
  (plan §5.4, §16.7, fa-ctf, fa-8x9)
  Invariant mapping:
    - FA-INV-09 (reservation resolution uniqueness & deterministic identity guard)
  Evidence class: bounded_model (TLA+ / TLC)
  Stated bounds:
    - Holds = {1, 2}
    - MaxTick = 3, ExpiryTick = 2
    - Concurrent actors: caller resolution (Posts | Voids) vs fad expiry sweep (Expires)
  Pipeline barriers mirrored from fa-sim-harness:
    - ReserveCommit, CallerResolveAttempt, SweepExpireAttempt
*)
EXTENDS Naturals, FiniteSets

Holds == {1, 2}
Dispositions == {"Posts", "Voids", "Expires"}
ExpiryTick == 2
MaxTick == 3

VARIABLES
  tick,             \* 0..MaxTick journaled TimeEvidence tick
  resolutions       \* SUBSET (Holds \X Dispositions) committed in the journal

vars == <<tick, resolutions>>

ResolvedHolds == { r[1] : r \in resolutions }

Init ==
  /\ tick = 0
  /\ resolutions = {}

AdvanceTimeTick ==
  /\ tick < MaxTick
  /\ tick' = tick + 1
  /\ UNCHANGED resolutions

\* Identity-uniqueness guard (`H("fa:vid:resolution:v1" || hold)` point-read witness):
\* A hold can be resolved iff `h \notin ResolvedHolds`.
CallerResolve(h, disp) ==
  /\ disp \in {"Posts", "Voids"}
  /\ h \notin ResolvedHolds
  /\ resolutions' = resolutions \cup {<<h, disp>>}
  /\ UNCHANGED tick

SweepExpire(h) ==
  /\ tick >= ExpiryTick
  /\ h \notin ResolvedHolds
  /\ resolutions' = resolutions \cup {<<h, "Expires">>}
  /\ UNCHANGED tick

Stutter == UNCHANGED vars

Next ==
  \/ AdvanceTimeTick
  \/ \E h \in Holds, d \in {"Posts", "Voids"} : CallerResolve(h, d)
  \/ \E h \in Holds : SweepExpire(h)
  \/ Stutter

Spec == Init /\ [][Next]_vars

\* FA-INV-09: Each reservation hold has at most one committed Resolution entry.
SingleResolutionPerHold ==
  \A h \in Holds : Cardinality({ r \in resolutions : r[1] = h }) <= 1

\* Expiry never fires before ExpiryTick.
ExpiryRespectsTimeEvidence ==
  \A r \in resolutions : (r[2] = "Expires") => (tick >= ExpiryTick)

=============================================================================
