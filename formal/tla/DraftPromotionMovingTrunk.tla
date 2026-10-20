--------------------- MODULE DraftPromotionMovingTrunk ---------------------
(*
  FrankenAccounting Bounded Model — Draft Promotion Against a Moving Trunk
  (plan §14.6, §16.7, fa-s7x, fa-8x9)
  Invariant mapping:
    - FA-INV-09 (intent-outcome & plan invalidation on conflicting trunk advance)
    - FA-INV-10 (agent work never touches trunk without independent human promotion)
  Evidence class: bounded_model (TLA+ / TLC)
  Stated bounds:
    - MaxTrunkSeq = 4
    - Principals = {"agent", "human_approver"}
  Pipeline barriers mirrored from fa-sim-harness:
    - DraftRecordIntent, ApproveDraftPlan, TrunkAdvancePeriodClose, PromoteDraftToTrunk
*)
EXTENDS Naturals

MaxTrunkSeq == 4

VARIABLES
  trunkSeq,         \* 1..MaxTrunkSeq
  trunkPeriodOpen,  \* BOOLEAN (whether target period on trunk is still Open)
  draftForkSeq,     \* 1..MaxTrunkSeq
  draftApprovedBy,  \* "None" | "agent" | "human_approver"
  draftState,       \* "Open" | "Promoted" | "RefusedStale"
  trunkPromotedBy   \* "None" | "human_approver"

vars == <<trunkSeq, trunkPeriodOpen, draftForkSeq, draftApprovedBy, draftState, trunkPromotedBy>>

Init ==
  /\ trunkSeq = 1
  /\ trunkPeriodOpen = TRUE
  /\ draftForkSeq = 1
  /\ draftApprovedBy = "None"
  /\ draftState = "Open"
  /\ trunkPromotedBy = "None"

TrunkAdvancePost ==
  /\ trunkSeq < MaxTrunkSeq
  /\ draftState = "Open"
  /\ trunkSeq' = trunkSeq + 1
  /\ UNCHANGED <<trunkPeriodOpen, draftForkSeq, draftApprovedBy, draftState, trunkPromotedBy>>

TrunkAdvancePeriodClose ==
  /\ trunkSeq < MaxTrunkSeq
  /\ trunkPeriodOpen = TRUE
  /\ draftState = "Open"
  /\ trunkSeq' = trunkSeq + 1
  /\ trunkPeriodOpen' = FALSE
  /\ UNCHANGED <<draftForkSeq, draftApprovedBy, draftState, trunkPromotedBy>>

ApproveDraftByHuman ==
  /\ draftState = "Open"
  /\ draftApprovedBy = "None"
  /\ draftApprovedBy' = "human_approver"
  /\ UNCHANGED <<trunkSeq, trunkPeriodOpen, draftForkSeq, draftState, trunkPromotedBy>>

PromoteDraftToTrunk ==
  /\ draftState = "Open"
  /\ draftApprovedBy = "human_approver"
  /\ trunkPeriodOpen = TRUE
  /\ trunkSeq < MaxTrunkSeq
  /\ trunkSeq' = trunkSeq + 1
  /\ draftState' = "Promoted"
  /\ trunkPromotedBy' = draftApprovedBy
  /\ UNCHANGED <<trunkPeriodOpen, draftForkSeq, draftApprovedBy>>

RefuseStaleDraftPromotion ==
  /\ draftState = "Open"
  /\ ~trunkPeriodOpen
  /\ draftState' = "RefusedStale"
  /\ UNCHANGED <<trunkSeq, trunkPeriodOpen, draftForkSeq, draftApprovedBy, trunkPromotedBy>>

Stutter == UNCHANGED vars

Next ==
  \/ TrunkAdvancePost
  \/ TrunkAdvancePeriodClose
  \/ ApproveDraftByHuman
  \/ PromoteDraftToTrunk
  \/ RefuseStaleDraftPromotion
  \/ Stutter

Spec == Init /\ [][Next]_vars

\* FA-INV-10: An agent can never promote a draft to trunk without human approval.
AgentNeverPromotesToTrunk ==
  (draftState = "Promoted") => (trunkPromotedBy = "human_approver")

\* FA-INV-09: A draft targeting an Open period cannot promote after trunk closes that period.
ClosedPeriodBlocksDraftPromotion ==
  (draftState = "Promoted") => trunkPeriodOpen

=============================================================================
