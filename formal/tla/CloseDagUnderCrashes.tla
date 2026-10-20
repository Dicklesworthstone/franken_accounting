------------------------- MODULE CloseDagUnderCrashes -------------------------
(*
  FrankenAccounting Bounded Model — Close DAG Under Crashes (plan §7.5, §16.7, fa-8x9)
  Invariant mapping:
    - FA-INV-03 (period close admissibility & checklist preconditions)
    - FA-INV-09 (idempotent deterministic task execution under crash/recovery)
  Evidence class: bounded_model (TLA+ / TLC)
  Stated bounds:
    - Tasks = {"cutoff", "reval", "accruals", "sweep"} (4 DAG tasks)
    - MaxCrashes = 2
  Pipeline barriers mirrored from fa-sim-harness:
    - BeforeWriteCommit, AfterWriteCommitBeforeCheckpoint, CrashAndRecover
*)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxCrashes

Tasks == {"cutoff", "reval", "accruals", "sweep"}

Prereqs(t) ==
  CASE t = "cutoff"   -> {}
    [] t = "reval"    -> {"cutoff"}
    [] t = "accruals" -> {"cutoff"}
    [] t = "sweep"    -> {"reval", "accruals"}

VARIABLES
  periodState,      \* "Open" | "SoftClosed" | "Closed" | "Locked"
  completedTasks,   \* SUBSET Tasks committed in the journal
  inFlightTask,     \* "None" \cup Tasks (staged beforeBeforeWriteCommit)
  crashCount,       \* 0..MaxCrashes
  emissionCount     \* [Tasks -> 0..1] number of committed entries per task

vars == <<periodState, completedTasks, inFlightTask, crashCount, emissionCount>>

Init ==
  /\ periodState = "SoftClosed"
  /\ completedTasks = {}
  /\ inFlightTask = "None"
  /\ crashCount = 0
  /\ emissionCount = [t \in Tasks |-> 0]

StageTaskBeforeWriteCommit(t) ==
  /\ periodState = "SoftClosed"
  /\ inFlightTask = "None"
  /\ t \notin completedTasks
  /\ Prereqs(t) \subseteq completedTasks
  /\ inFlightTask' = t
  /\ UNCHANGED <<periodState, completedTasks, crashCount, emissionCount>>

CommitTaskAtBarrier(t) ==
  /\ inFlightTask = t
  /\ t \notin completedTasks
  /\ completedTasks' = completedTasks \cup {t}
  /\ emissionCount' = [emissionCount EXCEPT ![t] = @ + 1]
  /\ inFlightTask' = "None"
  /\ UNCHANGED <<periodState, crashCount>>

CrashAndRecover ==
  /\ crashCount < MaxCrashes
  /\ inFlightTask # "None"
  /\ inFlightTask' = "None"
  /\ crashCount' = crashCount + 1
  /\ UNCHANGED <<periodState, completedTasks, emissionCount>>

TransitionPeriodClose ==
  /\ periodState = "SoftClosed"
  /\ inFlightTask = "None"
  /\ completedTasks = Tasks
  /\ periodState' = "Closed"
  /\ UNCHANGED <<completedTasks, inFlightTask, crashCount, emissionCount>>

TransitionPeriodLock ==
  /\ periodState = "Closed"
  /\ inFlightTask = "None"
  /\ completedTasks = Tasks
  /\ periodState' = "Locked"
  /\ UNCHANGED <<completedTasks, inFlightTask, crashCount, emissionCount>>

StutterWhenDone ==
  /\ periodState = "Locked"
  /\ UNCHANGED vars

Next ==
  \/ \E t \in Tasks : StageTaskBeforeWriteCommit(t)
  \/ \E t \in Tasks : CommitTaskAtBarrier(t)
  \/ CrashAndRecover
  \/ TransitionPeriodClose
  \/ TransitionPeriodLock
  \/ StutterWhenDone

Spec == Init /\ [][Next]_vars

\* FA-INV-03: Period never reaches Closed or Locked unless all close DAG tasks completed.
CloseRequiresCompleteDag ==
  (periodState \in {"Closed", "Locked"}) => (completedTasks = Tasks)

\* FA-INV-03: DAG topological order is respected at every reachable state.
DagOrderRespected ==
  \A t \in completedTasks : Prereqs(t) \subseteq completedTasks

\* FA-INV-09: No close task ever commits more than once despite crashes and retries.
AtMostOneCommitPerTask ==
  \A t \in Tasks : emissionCount[t] <= 1 /\ (t \in completedTasks <=> emissionCount[t] = 1)

=============================================================================
