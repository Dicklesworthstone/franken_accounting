------------------------ MODULE RestatementLifecycle ------------------------
(*
  FrankenAccounting Bounded Model — RestatementCase Lifecycle Under Dual Control
  (plan §8.3, §16.7, fa-oz3, fa-75j4, fa-8x9)
  Invariant mapping:
    - FA-INV-03 (Locked period restatement requires authorized RestatementCase)
    - FA-INV-08 (restatement diff certificate bound before posting)
    - FA-INV-10 (SoD dual control: two distinct approvers required before Approved/Posted)
  Evidence class: bounded_model (TLA+ / TLC)
  Stated bounds:
    - Principals = {"p1", "p2", "p3"}
    - Lifecycle states: Proposed -> Determined -> Rehearsed -> Approved -> Posted -> Disclosed -> Closed
  Pipeline barriers mirrored from fa-sim-harness:
    - OpenCase, DetermineCase, RehearseCase, RecordApproval, PostRestatementBatch, DiscloseCase, CloseCase
*)
EXTENDS Naturals, FiniteSets

Principals == {"p1", "p2", "p3"}

VARIABLES
  caseState,        \* "Proposed" | "Determined" | "Rehearsed" | "Approved" | "Posted" | "Disclosed" | "Closed"
  preparer,         \* "p1"
  approvers,        \* SUBSET Principals
  hasDiffCert,      \* BOOLEAN
  hasDisclosure     \* BOOLEAN

vars == <<caseState, preparer, approvers, hasDiffCert, hasDisclosure>>

Init ==
  /\ caseState = "Proposed"
  /\ preparer = "p1"
  /\ approvers = {}
  /\ hasDiffCert = FALSE
  /\ hasDisclosure = FALSE

DetermineCase ==
  /\ caseState = "Proposed"
  /\ caseState' = "Determined"
  /\ UNCHANGED <<preparer, approvers, hasDiffCert, hasDisclosure>>

RehearseCase ==
  /\ caseState = "Determined"
  /\ hasDiffCert' = TRUE
  /\ caseState' = "Rehearsed"
  /\ UNCHANGED <<preparer, approvers, hasDisclosure>>

\* SoD guard: approver `p` must be distinct from `preparer`.
RecordApproval(p) ==
  /\ caseState = "Rehearsed"
  /\ p # preparer
  /\ approvers' = approvers \cup {p}
  /\ UNCHANGED <<caseState, preparer, hasDiffCert, hasDisclosure>>

ApproveCaseDualControl ==
  /\ caseState = "Rehearsed"
  /\ hasDiffCert = TRUE
  /\ Cardinality(approvers) >= 2
  /\ caseState' = "Approved"
  /\ UNCHANGED <<preparer, approvers, hasDiffCert, hasDisclosure>>

PostRestatementBatch ==
  /\ caseState = "Approved"
  /\ caseState' = "Posted"
  /\ UNCHANGED <<preparer, approvers, hasDiffCert, hasDisclosure>>

DiscloseCase ==
  /\ caseState = "Posted"
  /\ hasDisclosure' = TRUE
  /\ caseState' = "Disclosed"
  /\ UNCHANGED <<preparer, approvers, hasDiffCert>>

CloseCase ==
  /\ caseState = "Disclosed"
  /\ hasDisclosure = TRUE
  /\ caseState' = "Closed"
  /\ UNCHANGED <<preparer, approvers, hasDiffCert, hasDisclosure>>

Stutter == UNCHANGED vars

Next ==
  \/ DetermineCase
  \/ RehearseCase
  \/ \E p \in Principals : RecordApproval(p)
  \/ ApproveCaseDualControl
  \/ PostRestatementBatch
  \/ DiscloseCase
  \/ CloseCase
  \/ Stutter

Spec == Init /\ [][Next]_vars

\* FA-INV-10: Dual control requires at least 2 distinct approvers, neither of whom is the preparer.
DualControlEnforced ==
  (caseState \in {"Approved", "Posted", "Disclosed", "Closed"}) =>
    (Cardinality(approvers) >= 2 /\ preparer \notin approvers)

\* FA-INV-08: Restatement never posts without a rehearsal diff certificate.
PostedRequiresDiffCertificate ==
  (caseState \in {"Approved", "Posted", "Disclosed", "Closed"}) => hasDiffCert

\* Closed case requires disclosure attachment.
ClosedRequiresDisclosure ==
  (caseState = "Closed") => hasDisclosure

=============================================================================
