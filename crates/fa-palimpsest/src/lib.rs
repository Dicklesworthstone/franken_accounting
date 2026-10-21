#![forbid(unsafe_code)]
//! Palimpsest — supersession lineage (`Reverse`, `Replace`, `Reclass`,
//! `Restate`), netting laws (`FA-INV-08.net-law`), paired replacement
//! (`FA-INV-08.replacement-paired`), restatement case lifecycle (`plan §8.4`),
//! migration run state/modes, and counterfactual scratch-book commit-sequence
//! translation (plan §8, §15.2; beads `fa-jgqi`, `fa-oz3`).

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{
    Disposition, EncodeError, Entry, EntryClass, EntryPayload, EntryRef, Id128, LegPayload, Oid,
    Pending, SupersessionKind, Writer, domain_digest,
};
use fa_money::{Side, UnitId};
use fa_registry::EntryClasses;
use fa_registry::g0::SupersessionKinds;
use fa_time::DateDay;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

/// `H(domain ‖ canonical SeqMap)`.
pub const SEQ_MAP_DOMAIN: &[u8] = b"fa:seq-map:v1";
pub const SEQ_MAP_VERSION: u16 = 1;
/// The scope a scratch book replays: accounting objects only (§15.2).
pub const SCOPE_ACCOUNTING_OBJECTS_ONLY: u8 = 1;
/// Domain tag for restatement diff certificates (plan §8.4).
pub const RESTATEMENT_DIFF_CERT_DOMAIN: &[u8] = b"fa:restatement-diff-cert:v1";

/// One replayed source commit and the scratch commit that reproduces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqPair {
    pub source_seq: CommitSeq,
    /// The source commit's marker object id (its place in the source chain).
    pub source_marker: [u8; 32],
    pub scratch_seq: CommitSeq,
}

/// Encode canonical `SeqMap` bytes.
pub fn encode_seq_map(
    source_book: Id128,
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.u16(SEQ_MAP_VERSION)
        .fixed(&source_book.0)
        .u64(source_prefix.0)
        .u8(SCOPE_ACCOUNTING_OBJECTS_ONLY)
        .list(pairs, |w, p| {
            w.u64(p.source_seq.0)
                .fixed(&p.source_marker)
                .u64(p.scratch_seq.0);
        });
    w.finish()
}

/// Compute the domain-separated `SeqMap` digest.
pub fn seq_map_digest(
    source_book: Id128,
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
) -> Result<[u8; 32], EncodeError> {
    Ok(domain_digest(
        SEQ_MAP_DOMAIN,
        &[&encode_seq_map(source_book, source_prefix, pairs)?],
    ))
}

/// Check that a sequence of `SeqPair`s is strictly increasing on both sides.
#[must_use]
pub fn seq_pairs_are_monotone(pairs: &[SeqPair]) -> bool {
    pairs
        .windows(2)
        .all(|w| w[0].source_seq < w[1].source_seq && w[0].scratch_seq < w[1].scratch_seq)
}

/// Translate `source_known_at` through `pairs` within `[0, source_prefix]`.
#[must_use]
pub fn translate_seq(
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
    source_known_at: CommitSeq,
) -> Option<CommitSeq> {
    if source_known_at > source_prefix {
        return None;
    }
    pairs
        .iter()
        .take_while(|p| p.source_seq <= source_known_at)
        .last()
        .map(|p| p.scratch_seq)
}

/// The migration run's declared mode (plan §8.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    OpeningOnly,
    PeriodBalances,
    FullDetail,
}

impl RunMode {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::OpeningOnly => 0,
            Self::PeriodBalances => 1,
            Self::FullDetail => 2,
        }
    }
}

/// The `state` projection of a migration run vertex (lifecycle-by-transition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Open,
    Finalized,
    Abandoned,
}

impl RunState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Finalized => 1,
            Self::Abandoned => 2,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Finalized => "Finalized",
            Self::Abandoned => "Abandoned",
        }
    }

    #[must_use]
    pub fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(0)) => Some(Self::Open),
            Some(CanonicalScalar::Int(1)) => Some(Self::Finalized),
            Some(CanonicalScalar::Int(2)) => Some(Self::Abandoned),
            _ => None,
        }
    }

    #[must_use]
    pub fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }
}

/// One declared line of the legacy trial balance: the account's net in
/// debit sign (`debits − credits`), never zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceLine {
    pub account_code: String,
    pub unit: UnitId,
    pub mantissa: i128,
}

/// One elapsed period of a `PeriodBalances` run (plan §8.6): the legacy
/// trial balance as of the period's end — cumulative from the run's opening
/// date — and the document that states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodBalance {
    pub period_code: String,
    pub trial_balance: Oid,
    /// Strictly ascending by `(account_code, unit)`, never zero.
    pub lines: Vec<TrialBalanceLine>,
}

/// One node in the journal's `SUPERSEDES` lineage graph (plan §8.1–§8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupersessionNode {
    pub vid: VId,
    pub class: EntryClass,
    pub supersedes: Option<VId>,
}

/// Validate that `target` has an unreversed ancestry chain in `nodes` before
/// admitting a new `Reversal` (plan §8.1, bead `fa-wck`):
/// returns `Err(ancestor_vid)` if `target` or any `SUPERSEDES` ancestor has
/// already been reversed by a committed `Reversal` entry.
pub fn validate_unreversed_ancestry(
    nodes: &BTreeMap<VId, SupersessionNode>,
    reversed_targets: &BTreeSet<VId>,
    target: VId,
) -> Result<(), VId> {
    let mut cursor = Some(target);
    let mut visited = BTreeSet::new();
    while let Some(v) = cursor {
        if !visited.insert(v) {
            break;
        }
        if reversed_targets.contains(&v) {
            return Err(v);
        }
        cursor = nodes.get(&v).and_then(|n| n.supersedes);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Netting laws and supersession validation (FA-INV-08.net-law, FA-INV-08.replacement-paired)
// ---------------------------------------------------------------------------

/// Registered netting law for a `SupersessionKind` (`registries/supersession_kinds.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NettingLaw {
    /// Exact side-swap negation (`Reverses`): target + reversal nets to zero.
    Negation,
    /// Paired `(Reversal, Replacement)` in one batch (`Replaces`): reversal zeroes
    /// the target and replacement supplies the corrected legs.
    PairedReplacement,
    /// Partial reclassification (`Reclassifies`): moves a subset of leg amounts
    /// to new accounts or dimensions without negating the entire target.
    PartialReclassification,
    /// Delta addition (`Revises`, `Restates`): target plus delta legs.
    Delta,
    /// Two-phase resolution (`Resolves`): releases pending hold and posts resolved
    /// sub-vector if `Disposition::Posts`.
    TwoPhaseResolution,
}

impl NettingLaw {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negation => "negation",
            Self::PairedReplacement => "paired_replacement",
            Self::PartialReclassification => "partial_reclassification",
            Self::Delta => "delta",
            Self::TwoPhaseResolution => "two_phase_resolution",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "negation" => Some(Self::Negation),
            "paired_replacement" => Some(Self::PairedReplacement),
            "partial_reclassification" => Some(Self::PartialReclassification),
            "delta" => Some(Self::Delta),
            "two_phase_resolution" => Some(Self::TwoPhaseResolution),
            _ => None,
        }
    }
}

/// Total mapping from `SupersessionKind` to its registered `NettingLaw` (`FA-INV-08.net-law`).
#[must_use]
pub fn netting_law_for(kind: SupersessionKind) -> NettingLaw {
    match kind {
        SupersessionKind::Reverses => NettingLaw::Negation,
        SupersessionKind::Replaces => NettingLaw::PairedReplacement,
        SupersessionKind::Reclassifies => NettingLaw::PartialReclassification,
        SupersessionKind::Revises | SupersessionKind::Restates => NettingLaw::Delta,
        SupersessionKind::Resolves => NettingLaw::TwoPhaseResolution,
    }
}

/// Errors returned by Palimpsest supersession / lineage / restatement validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PalimpsestError {
    /// Target class is not reversible under `supersession_kinds.toml`.
    TargetClassNotReversible {
        class: String,
        why: String,
        corrective_route: String,
    },
    /// Paired replacement failed validation (`FA-INV-08.replacement-paired`).
    InvalidReplacementPair(String),
    /// Partial reclassification failed validation.
    InvalidReclassification(String),
    /// Lineage cycle detected (`FA-INV-08.dag`).
    LineageCycle { vid: VId },
    /// Unpaired replacement detected in a lineage component (`FA-INV-08.replacement-paired`).
    UnpairedReplacement {
        replacement_vid: VId,
        target_vid: VId,
    },
    /// RestatementCase transition or SoD error.
    InvalidRestatementCase(String),
    /// Overflow while computing net positions.
    Overflow,
}

impl std::fmt::Display for PalimpsestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetClassNotReversible {
                class,
                why,
                corrective_route,
            } => write!(
                f,
                "class `{class}` is not reversible: {why} ({corrective_route})"
            ),
            Self::InvalidReplacementPair(m) => write!(f, "invalid replacement pair: {m}"),
            Self::InvalidReclassification(m) => write!(f, "invalid reclassification: {m}"),
            Self::LineageCycle { vid } => {
                write!(f, "supersession lineage cycle at {:032x}", vid.0)
            }
            Self::UnpairedReplacement {
                replacement_vid,
                target_vid,
            } => write!(
                f,
                "unpaired Replacement {:032x} targeting {:032x} without a paired Reversal",
                replacement_vid.0, target_vid.0
            ),
            Self::InvalidRestatementCase(m) => write!(f, "invalid restatement case: {m}"),
            Self::Overflow => write!(f, "arithmetic overflow in lineage fold"),
        }
    }
}

impl std::error::Error for PalimpsestError {}

/// Check whether `target` is reversible under `supersession_kinds.toml`.
///
/// The kernel's Reverses admission and lineage validation both judge here,
/// so the table has one reading (fa-s3wz).
pub fn check_target_reversible(target: &EntryPayload) -> Result<(), PalimpsestError> {
    static TABLE: std::sync::OnceLock<Result<SupersessionKinds, String>> =
        std::sync::OnceLock::new();
    let sup = TABLE
        .get_or_init(|| {
            let classes = EntryClasses::embedded().map_err(|e| e.to_string())?;
            SupersessionKinds::embedded(&classes).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| PalimpsestError::InvalidReplacementPair(e.clone()))?;
    let class_name = target.class.name().unwrap_or("?");
    let Some(row) = sup.target_class(class_name) else {
        return Err(PalimpsestError::TargetClassNotReversible {
            class: class_name.to_string(),
            why: "unregistered class".into(),
            corrective_route: "use a registered posting class".into(),
        });
    };
    match row.reversible.as_str() {
        "yes" => Ok(()),
        "posts_only" => {
            if matches!(
                target.pending,
                Some(Pending {
                    disposition: Some(Disposition::Posts { .. }),
                    ..
                })
            ) {
                Ok(())
            } else {
                Err(PalimpsestError::TargetClassNotReversible {
                    class: class_name.to_string(),
                    why: row.why.clone(),
                    corrective_route: row.corrective_route.clone(),
                })
            }
        }
        _ => Err(PalimpsestError::TargetClassNotReversible {
            class: class_name.to_string(),
            why: row.why.clone(),
            corrective_route: row.corrective_route.clone(),
        }),
    }
}

/// Check that `reversal_legs` is the exact side-swap of `target_legs`.
#[must_use]
pub fn is_exact_side_swap(target_legs: &[LegPayload], reversal_legs: &[LegPayload]) -> bool {
    !target_legs.is_empty()
        && target_legs.len() == reversal_legs.len()
        && target_legs.iter().zip(reversal_legs).all(|(o, r)| {
            o.account_ref == r.account_ref
                && o.amount == r.amount
                && o.dimension_set == r.dimension_set
                && matches!(
                    (o.side, r.side),
                    (Side::Debit, Side::Credit) | (Side::Credit, Side::Debit)
                )
        })
}

/// Validate a paired `(Reversal, Replacement)` batch (`FA-INV-08.replacement-paired`, plan §8.2).
///
/// Both entries must target `target_ref` (`Reversal` via `SupersessionKind::Reverses`,
/// `Replacement` via `SupersessionKind::Replaces`), `reversal` must be the exact
/// side-swap of `target`, and `replacement` must carry valid, balanced legs that
/// differ from `target`'s original legs.
pub fn validate_replacement_pair(
    target: &EntryPayload,
    target_ref: EntryRef,
    reversal: &EntryPayload,
    replacement: &EntryPayload,
) -> Result<(), PalimpsestError> {
    check_target_reversible(target)?;

    if reversal.class != EntryClass::REVERSAL {
        return Err(PalimpsestError::InvalidReplacementPair(format!(
            "first entry of replacement pair must be Reversal, found {:?}",
            reversal.class.name()
        )));
    }
    if replacement.class != EntryClass::REPLACEMENT {
        return Err(PalimpsestError::InvalidReplacementPair(format!(
            "second entry of replacement pair must be Replacement, found {:?}",
            replacement.class.name()
        )));
    }
    reversal
        .validate()
        .map_err(|e| PalimpsestError::InvalidReplacementPair(format!("reversal: {e}")))?;
    replacement
        .validate()
        .map_err(|e| PalimpsestError::InvalidReplacementPair(format!("replacement: {e}")))?;

    let [rev_sup] = reversal.supersession.as_slice() else {
        return Err(PalimpsestError::InvalidReplacementPair(
            "reversal must carry exactly one supersession".into(),
        ));
    };
    if rev_sup.kind != SupersessionKind::Reverses || rev_sup.target != target_ref {
        return Err(PalimpsestError::InvalidReplacementPair(
            "reversal supersession must be Reverses targeting the replaced entry".into(),
        ));
    }

    let [rep_sup] = replacement.supersession.as_slice() else {
        return Err(PalimpsestError::InvalidReplacementPair(
            "replacement must carry exactly one supersession".into(),
        ));
    };
    if rep_sup.kind != SupersessionKind::Replaces || rep_sup.target != target_ref {
        return Err(PalimpsestError::InvalidReplacementPair(
            "replacement supersession must be Replaces targeting the same entry as the paired reversal".into(),
        ));
    }

    if !is_exact_side_swap(&target.legs, &reversal.legs) {
        return Err(PalimpsestError::InvalidReplacementPair(
            "paired reversal legs are not the exact side-swap of the target entry".into(),
        ));
    }

    let same_as_target = target.legs.len() == replacement.legs.len()
        && target.legs.iter().zip(&replacement.legs).all(|(a, b)| {
            a.side == b.side
                && a.account_ref == b.account_ref
                && a.amount == b.amount
                && a.dimension_set == b.dimension_set
        });
    if same_as_target {
        return Err(PalimpsestError::InvalidReplacementPair(
            "replacement legs are identical to the target entry; nothing is replaced".into(),
        ));
    }

    Ok(())
}

type DimSet = Vec<(u32, VId)>;

/// Validate a partial `Reclassification` entry against `target` (plan §8.2,
/// `SupersessionKind::Reclassifies`).
///
/// A reclassification moves a positive subset of one or more legs of `target`
/// to new accounts or dimensions in the same unit without negating the entire
/// entry.
pub fn validate_reclassification(
    target: &EntryPayload,
    target_ref: EntryRef,
    reclass: &EntryPayload,
) -> Result<(), PalimpsestError> {
    check_target_reversible(target)?;
    if reclass.class != EntryClass::RECLASSIFICATION {
        return Err(PalimpsestError::InvalidReclassification(format!(
            "expected class Reclassification, found {:?}",
            reclass.class.name()
        )));
    }
    reclass
        .validate()
        .map_err(|e| PalimpsestError::InvalidReclassification(e.to_string()))?;

    let [sup] = reclass.supersession.as_slice() else {
        return Err(PalimpsestError::InvalidReclassification(
            "reclassification must carry exactly one Reclassifies supersession".into(),
        ));
    };
    if sup.kind != SupersessionKind::Reclassifies || sup.target != target_ref {
        return Err(PalimpsestError::InvalidReclassification(
            "reclassification must cite target with SupersessionKind::Reclassifies".into(),
        ));
    }

    let side_tag = |s: Side| match s {
        Side::Debit => 0u8,
        Side::Credit => 1u8,
    };
    // Aggregate target positions by (account_ref, unit, side_tag, dimension_set).
    let mut target_buckets: BTreeMap<(VId, UnitId, u8, DimSet), i128> = BTreeMap::new();
    for leg in &target.legs {
        let key = (
            leg.account_ref,
            leg.amount.unit,
            side_tag(leg.side),
            leg.dimension_set.clone(),
        );
        let slot = target_buckets.entry(key).or_insert(0);
        *slot = slot
            .checked_add(leg.amount.mantissa)
            .ok_or(PalimpsestError::Overflow)?;
    }

    let mut reduced_buckets: BTreeMap<(VId, UnitId, u8, DimSet), i128> = BTreeMap::new();
    let mut destination_legs = 0usize;

    for leg in &reclass.legs {
        let opposite = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        let target_key = (
            leg.account_ref,
            leg.amount.unit,
            side_tag(opposite),
            leg.dimension_set.clone(),
        );
        if let Some(&avail) = target_buckets.get(&target_key) {
            let slot = reduced_buckets.entry(target_key).or_insert(0);
            *slot = slot
                .checked_add(leg.amount.mantissa)
                .ok_or(PalimpsestError::Overflow)?;
            if *slot > avail {
                return Err(PalimpsestError::InvalidReclassification(format!(
                    "reclassification out of account {:032x} ({}) exceeds target amount ({} > {})",
                    leg.account_ref.0, leg.amount.unit.0, *slot, avail
                )));
            }
        } else {
            destination_legs += 1;
        }
    }

    if reduced_buckets.is_empty() {
        return Err(PalimpsestError::InvalidReclassification(
            "reclassification does not reduce any leg of the target entry".into(),
        ));
    }
    if destination_legs == 0 {
        return Err(PalimpsestError::InvalidReclassification(
            "reclassification must move amount to at least one new account or dimension".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Lineage chain, netting computation, and `fa explain lineage` (plan §8.1–§8.3)
// ---------------------------------------------------------------------------

/// One supersession link in a `LineageReport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageEdgeSummary {
    pub kind: SupersessionKind,
    pub netting_law: NettingLaw,
    pub target_vid: VId,
    pub reason_code: u16,
}

/// Summary of one entry in a `LineageReport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageEntrySummary {
    pub vid: VId,
    pub entry_digest: [u8; 32],
    pub class: EntryClass,
    pub effective_date: DateDay,
    pub effective_period: Option<String>,
    pub recorded_at: CommitSeq,
    pub live: bool,
    /// This entry reverses an entry that is itself a Reversal: it revives
    /// what that reversal negated, by parity (plan §8.2, flagged here).
    pub reverses_reversal: bool,
    pub supersedes: Vec<LineageEdgeSummary>,
}

/// Net economic position per `(account_ref, unit, dimension_set)` across a lineage chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPosition {
    pub account_ref: VId,
    pub unit: UnitId,
    pub dimension_set: DimSet,
    pub debits: i128,
    pub credits: i128,
    /// `debits - credits` (positive = net debit, negative = net credit, 0 = flat).
    pub net_debit: i128,
}

/// Complete lineage explanation for an entry (`fa explain lineage <entry-vid>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageReport {
    pub queried_vid: VId,
    pub root_vid: VId,
    pub known_at: Option<CommitSeq>,
    pub entries: Vec<LineageEntrySummary>,
    pub net_positions: Vec<NetPosition>,
    pub fully_reversed: bool,
    pub replaced_by: Option<VId>,
}

/// Compute the connected `SUPERSEDES` lineage component containing `queried_vid`
/// and fold its exact net economic effect under the registered `NettingLaw`s
/// (`FA-INV-08.net-law`, `FA-INV-08.replacement-paired`, `FA-INV-08.dag`).
pub fn explain_lineage(
    all_entries: &[(VId, Entry, CommitSeq)],
    queried_vid: VId,
    known_at: Option<CommitSeq>,
) -> Result<Option<LineageReport>, PalimpsestError> {
    let visible: Vec<&(VId, Entry, CommitSeq)> = all_entries
        .iter()
        .filter(|(_, _, seq)| known_at.is_none_or(|k| *seq <= k))
        .collect();

    let by_vid: BTreeMap<VId, (&Entry, CommitSeq)> =
        visible.iter().map(|(v, e, s)| (*v, (e, *s))).collect();

    if !by_vid.contains_key(&queried_vid) {
        return Ok(None);
    }

    // Build parent/child adjacency in the SUPERSEDES graph and check DAG acyclicity.
    let mut parents: BTreeMap<VId, Vec<VId>> = BTreeMap::new();
    let mut children: BTreeMap<VId, Vec<VId>> = BTreeMap::new();
    let mut reversed_by: BTreeMap<VId, VId> = BTreeMap::new();
    let mut replaced_by_map: BTreeMap<VId, VId> = BTreeMap::new();

    for (vid, (entry, _)) in &by_vid {
        for sup in &entry.proposal.supersession {
            if by_vid.contains_key(&sup.target.vid) {
                parents.entry(*vid).or_default().push(sup.target.vid);
                children.entry(sup.target.vid).or_default().push(*vid);
                if sup.kind == SupersessionKind::Reverses {
                    reversed_by.insert(sup.target.vid, *vid);
                }
                if sup.kind == SupersessionKind::Replaces {
                    replaced_by_map.insert(sup.target.vid, *vid);
                }
            }
        }
    }

    // Connected component discovery + cycle check.
    let mut component: BTreeSet<VId> = BTreeSet::new();
    let mut stack = vec![queried_vid];
    while let Some(cur) = stack.pop() {
        if !component.insert(cur) {
            continue;
        }
        if let Some(ps) = parents.get(&cur) {
            for &p in ps {
                stack.push(p);
            }
        }
        if let Some(cs) = children.get(&cur) {
            for &c in cs {
                stack.push(c);
            }
        }
    }

    for &node in &component {
        let mut visiting = BTreeSet::new();
        let mut dfs = vec![(node, false)];
        let mut visited = BTreeSet::new();
        while let Some((u, exiting)) = dfs.pop() {
            if exiting {
                visiting.remove(&u);
                visited.insert(u);
                continue;
            }
            if visited.contains(&u) {
                continue;
            }
            if !visiting.insert(u) {
                return Err(PalimpsestError::LineageCycle { vid: u });
            }
            dfs.push((u, true));
            if let Some(ps) = parents.get(&u) {
                for &p in ps {
                    if visiting.contains(&p) {
                        return Err(PalimpsestError::LineageCycle { vid: p });
                    }
                    if !visited.contains(&p) {
                        dfs.push((p, false));
                    }
                }
            }
        }
    }

    // Find the root (earliest ancestor in component with no parents in component).
    let mut root_vid = queried_vid;
    let mut walk_seen = BTreeSet::new();
    while let Some(ps) = parents.get(&root_vid) {
        let Some(&first_parent) = ps.first() else {
            break;
        };
        if !walk_seen.insert(root_vid) {
            return Err(PalimpsestError::LineageCycle { vid: root_vid });
        }
        root_vid = first_parent;
    }

    // Verify FA-INV-08.replacement-paired for every Replacement in the component:
    // a Replacement targeting T must have a paired Reversal targeting T committed
    // at or before the Replacement's CommitSeq.
    for &vid in &component {
        let (entry, rep_seq) = by_vid[&vid];
        if entry.proposal.class == EntryClass::REPLACEMENT {
            let [sup] = entry.proposal.supersession.as_slice() else {
                return Err(PalimpsestError::UnpairedReplacement {
                    replacement_vid: vid,
                    target_vid: root_vid,
                });
            };
            if sup.kind != SupersessionKind::Replaces {
                return Err(PalimpsestError::UnpairedReplacement {
                    replacement_vid: vid,
                    target_vid: sup.target.vid,
                });
            }
            let Some(&rev_vid) = reversed_by.get(&sup.target.vid) else {
                return Err(PalimpsestError::UnpairedReplacement {
                    replacement_vid: vid,
                    target_vid: sup.target.vid,
                });
            };
            let (_, rev_seq) = by_vid[&rev_vid];
            if rev_seq > rep_seq {
                return Err(PalimpsestError::UnpairedReplacement {
                    replacement_vid: vid,
                    target_vid: sup.target.vid,
                });
            }
        }
    }

    // Sort component entries by (recorded_at, vid).
    let mut ordered_vids: Vec<VId> = component.iter().copied().collect();
    ordered_vids.sort_by_key(|v| (by_vid[v].1, *v));

    let is_node_live = |mut cur: VId| -> Result<bool, PalimpsestError> {
        let mut live = true;
        let mut seen = BTreeSet::new();
        while let Some(&rev) = reversed_by.get(&cur) {
            if !seen.insert(cur) {
                return Err(PalimpsestError::LineageCycle { vid: cur });
            }
            live = !live;
            cur = rev;
        }
        Ok(live)
    };

    let mut summaries = Vec::with_capacity(ordered_vids.len());
    let mut net_map: BTreeMap<(VId, UnitId, DimSet), (i128, i128)> = BTreeMap::new();

    for vid in ordered_vids {
        let (entry, recorded_at) = by_vid[&vid];
        let live = is_node_live(vid)?;
        let supersedes = entry
            .proposal
            .supersession
            .iter()
            .map(|s| LineageEdgeSummary {
                kind: s.kind,
                netting_law: netting_law_for(s.kind),
                target_vid: s.target.vid,
                reason_code: s.reason_code,
            })
            .collect();
        let reverses_reversal = entry.proposal.supersession.iter().any(|s| {
            s.kind == SupersessionKind::Reverses
                && by_vid
                    .get(&s.target.vid)
                    .is_some_and(|(target, _)| target.proposal.class == EntryClass::REVERSAL)
        });

        summaries.push(LineageEntrySummary {
            vid,
            entry_digest: entry.entry_digest,
            class: entry.proposal.class,
            effective_date: entry.proposal.effective_date,
            effective_period: entry
                .proposal
                .effective_period
                .as_ref()
                .map(|p| p.code.clone()),
            recorded_at,
            live,
            reverses_reversal,
            supersedes,
        });

        // Pending holds reserve rather than post; every other monetary entry in
        // the lineage contributes its posted legs (so Original + Reversal cancels
        // to 0 debits-credits net, Replacement supplies the new legs, Reclassification
        // moves the reclassified slice, and Revision/Restatement adds the delta).
        if entry.proposal.class != EntryClass::PENDING {
            for leg in &entry.proposal.legs {
                let key = (leg.account_ref, leg.amount.unit, leg.dimension_set.clone());
                let slot = net_map.entry(key).or_insert((0, 0));
                match leg.side {
                    Side::Debit => {
                        slot.0 = slot
                            .0
                            .checked_add(leg.amount.mantissa)
                            .ok_or(PalimpsestError::Overflow)?;
                    }
                    Side::Credit => {
                        slot.1 = slot
                            .1
                            .checked_add(leg.amount.mantissa)
                            .ok_or(PalimpsestError::Overflow)?;
                    }
                }
            }
        }
    }

    let mut net_positions = Vec::with_capacity(net_map.len());
    for ((account_ref, unit, dimension_set), (debits, credits)) in net_map {
        let net_debit = debits
            .checked_sub(credits)
            .ok_or(PalimpsestError::Overflow)?;
        net_positions.push(NetPosition {
            account_ref,
            unit,
            dimension_set,
            debits,
            credits,
            net_debit,
        });
    }

    let root_live = is_node_live(root_vid)?;
    let replaced_by = replaced_by_map
        .get(&root_vid)
        .copied()
        .filter(|&rep_vid| is_node_live(rep_vid).unwrap_or(false));
    let fully_reversed = !root_live && replaced_by.is_none();

    Ok(Some(LineageReport {
        queried_vid,
        root_vid,
        known_at,
        entries: summaries,
        net_positions,
        fully_reversed,
        replaced_by,
    }))
}

// ---------------------------------------------------------------------------
// RestatementCase lifecycle, dual control, and diff certificates (plan §8.4)
// ---------------------------------------------------------------------------

/// Scope of a restatement case (`RestatementCase`, plan §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestatementScope {
    /// Immaterial revision (`Revision`, `SupersessionKind::Revises`): adjusts
    /// comparative figures without reopening a `Locked` period.
    ImmaterialRevision,
    /// Material prior-period restatement (`Restatement`, `SupersessionKind::Restates`):
    /// authorizes reopening `Closed` or `Locked` periods in `affected_periods`.
    PriorPeriodRestatement,
    /// Prior-period adjustment (`PriorPeriodAdjustment`): posts in the current
    /// `Open` or `SoftClosed` period against opening retained earnings.
    PriorPeriodAdjustment,
}

impl RestatementScope {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::ImmaterialRevision => 1,
            Self::PriorPeriodRestatement => 2,
            Self::PriorPeriodAdjustment => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ImmaterialRevision => "ImmaterialRevision",
            Self::PriorPeriodRestatement => "PriorPeriodRestatement",
            Self::PriorPeriodAdjustment => "PriorPeriodAdjustment",
        }
    }

    #[must_use]
    pub fn admits_class(self, class: EntryClass) -> bool {
        matches!(
            (self, class),
            (Self::ImmaterialRevision, EntryClass::REVISION)
                | (Self::PriorPeriodRestatement, EntryClass::RESTATEMENT)
                | (
                    Self::PriorPeriodAdjustment,
                    EntryClass::PRIOR_PERIOD_ADJUSTMENT
                )
        )
    }
}

/// Lifecycle state of a restatement case (`RestatementCase`, plan §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestatementCaseState {
    Open,
    Approved,
    Applied,
    Closed,
}

impl RestatementCaseState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Approved => 1,
            Self::Applied => 2,
            Self::Closed => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Approved => "Approved",
            Self::Applied => "Applied",
            Self::Closed => "Closed",
        }
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::Approved)
                | (Self::Approved, Self::Applied)
                | (Self::Applied, Self::Closed)
        )
    }
}

/// First-class `RestatementCase` governance object (plan §8.4).
///
/// Immutable per transition; every transition produces a new state with
/// monotone `CommitSeq` witnesses, enforces SoD (`case_preparer` exclusion),
/// and upon `Close` binds a replayable `RestatementDiffCertificate` between
/// `as_reported_seq` and `as_restated_seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestatementCase {
    pub case_id: Id128,
    pub book_id: Id128,
    pub vid: VId,
    pub scope: RestatementScope,
    pub reason_code: u16,
    pub affected_periods: Vec<String>,
    pub materiality_workpaper_oid: Oid,
    pub preparer: Id128,
    pub approvers: Vec<Id128>,
    pub state: RestatementCaseState,
    pub opened_at: CommitSeq,
    pub approved_at: Option<CommitSeq>,
    pub applied_at: Option<CommitSeq>,
    pub closed_at: Option<CommitSeq>,
    pub as_reported_seq: CommitSeq,
    pub as_restated_seq: Option<CommitSeq>,
    pub entry_vids: Vec<VId>,
}

/// Deterministic `VId` for a `RestatementCase`.
#[must_use]
pub fn restatement_case_vid(book_id: Id128, case_id: Id128) -> VId {
    let d = domain_digest(b"fa:vid:restatement-case:v1", &[&book_id.0, &case_id.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

impl RestatementCase {
    /// Open a new `RestatementCase` in `RestatementCaseState::Open`.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        case_id: Id128,
        book_id: Id128,
        scope: RestatementScope,
        reason_code: u16,
        affected_periods: Vec<String>,
        materiality_workpaper_oid: Oid,
        preparer: Id128,
        opened_at: CommitSeq,
        as_reported_seq: CommitSeq,
    ) -> Result<Self, PalimpsestError> {
        if affected_periods.is_empty() {
            return Err(PalimpsestError::InvalidRestatementCase(
                "affected_periods must not be empty".into(),
            ));
        }
        let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
            .map_err(|e| PalimpsestError::InvalidRestatementCase(e.to_string()))?;
        if reasons.get("supersession", reason_code).is_none() {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "unregistered supersession reason_code {reason_code}"
            )));
        }
        Ok(Self {
            case_id,
            book_id,
            vid: restatement_case_vid(book_id, case_id),
            scope,
            reason_code,
            affected_periods,
            materiality_workpaper_oid,
            preparer,
            approvers: Vec::new(),
            state: RestatementCaseState::Open,
            opened_at,
            approved_at: None,
            applied_at: None,
            closed_at: None,
            as_reported_seq,
            as_restated_seq: None,
            entry_vids: Vec::new(),
        })
    }

    /// Transition `Open -> Approved` under dual control (`sod_policy.toml` `case_preparer` exclusion).
    pub fn approve(
        &mut self,
        approvers: Vec<Id128>,
        required_approvers: usize,
        at: CommitSeq,
    ) -> Result<(), PalimpsestError> {
        if !self.state.can_transition_to(RestatementCaseState::Approved) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "cannot transition RestatementCase from {} to Approved",
                self.state.name()
            )));
        }
        if at < self.opened_at {
            return Err(PalimpsestError::InvalidRestatementCase(
                "approved_at precedes opened_at".into(),
            ));
        }
        let mut distinct = BTreeSet::new();
        for a in &approvers {
            if *a == self.preparer {
                return Err(PalimpsestError::InvalidRestatementCase(
                    "SoD violation (case_preparer): case preparer cannot approve their own RestatementCase".into(),
                ));
            }
            distinct.insert(*a);
        }
        if distinct.len() < required_approvers.max(1) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "RestatementCase requires at least {} distinct approvers, found {}",
                required_approvers.max(1),
                distinct.len()
            )));
        }
        self.approvers = approvers;
        self.state = RestatementCaseState::Approved;
        self.approved_at = Some(at);
        Ok(())
    }

    /// Validate that an entry is admissible under this `RestatementCase` and record its `VId`.
    pub fn record_entry(
        &mut self,
        entry_vid: VId,
        payload: &EntryPayload,
        effective_period: &str,
    ) -> Result<(), PalimpsestError> {
        if !matches!(
            self.state,
            RestatementCaseState::Approved | RestatementCaseState::Applied
        ) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "RestatementCase must be Approved before applying entries (current state: {})",
                self.state.name()
            )));
        }
        if !self.scope.admits_class(payload.class) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "RestatementCase scope `{}` does not admit entry class `{}`",
                self.scope.name(),
                payload.class.name().unwrap_or("?")
            )));
        }
        if self.scope != RestatementScope::PriorPeriodAdjustment
            && !self.affected_periods.iter().any(|p| p == effective_period)
        {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "period `{effective_period}` is not in RestatementCase affected_periods {:?}",
                self.affected_periods
            )));
        }
        self.entry_vids.push(entry_vid);
        Ok(())
    }

    /// Transition `Approved -> Applied` once all case entries are committed.
    pub fn mark_applied(&mut self, as_restated_seq: CommitSeq) -> Result<(), PalimpsestError> {
        if !self.state.can_transition_to(RestatementCaseState::Applied) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "cannot transition RestatementCase from {} to Applied",
                self.state.name()
            )));
        }
        if self.entry_vids.is_empty() {
            return Err(PalimpsestError::InvalidRestatementCase(
                "cannot mark RestatementCase Applied with zero committed entries".into(),
            ));
        }
        if as_restated_seq <= self.as_reported_seq {
            return Err(PalimpsestError::InvalidRestatementCase(
                "as_restated_seq must be strictly greater than as_reported_seq".into(),
            ));
        }
        self.state = RestatementCaseState::Applied;
        self.applied_at = Some(as_restated_seq);
        self.as_restated_seq = Some(as_restated_seq);
        Ok(())
    }

    /// Transition `Applied -> Closed` and emit the replayable `RestatementDiffCertificate`
    /// between the `as_reported` and `as_restated` period snapshots (plan §8.4).
    pub fn close(
        &mut self,
        closed_at: CommitSeq,
        as_reported_positions: &[PeriodPosition],
        as_restated_positions: &[PeriodPosition],
    ) -> Result<RestatementDiffCertificate, PalimpsestError> {
        if !self.state.can_transition_to(RestatementCaseState::Closed) {
            return Err(PalimpsestError::InvalidRestatementCase(format!(
                "cannot transition RestatementCase from {} to Closed",
                self.state.name()
            )));
        }
        let as_restated_seq = self.as_restated_seq.ok_or_else(|| {
            PalimpsestError::InvalidRestatementCase("missing as_restated_seq".into())
        })?;
        if closed_at < as_restated_seq {
            return Err(PalimpsestError::InvalidRestatementCase(
                "closed_at precedes as_restated_seq".into(),
            ));
        }
        self.state = RestatementCaseState::Closed;
        self.closed_at = Some(closed_at);
        RestatementDiffCertificate::compute(
            self.case_id,
            self.book_id,
            self.as_reported_seq,
            as_restated_seq,
            as_reported_positions,
            as_restated_positions,
        )
    }
}

/// One `(period, account, unit)` balance observation at a known-at coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodPosition {
    pub period_code: String,
    pub account_ref: VId,
    pub unit: UnitId,
    pub net_debit: i128,
}

/// One changed line in a `RestatementDiffCertificate` (plan §8.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestatementDiffLine {
    pub period_code: String,
    pub account_ref: VId,
    pub unit: UnitId,
    pub as_reported_net: i128,
    pub as_restated_net: i128,
    pub delta_net: i128,
}

/// Replayable certificate of the exact `as-originally-reported` vs `as-restated`
/// balance differences produced by a `RestatementCase` (plan §8.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestatementDiffCertificate {
    pub case_id: Id128,
    pub book_id: Id128,
    pub as_reported_seq: CommitSeq,
    pub as_restated_seq: CommitSeq,
    pub lines: Vec<RestatementDiffLine>,
    pub certificate_digest: [u8; 32],
}

impl RestatementDiffCertificate {
    pub fn compute(
        case_id: Id128,
        book_id: Id128,
        as_reported_seq: CommitSeq,
        as_restated_seq: CommitSeq,
        as_reported: &[PeriodPosition],
        as_restated: &[PeriodPosition],
    ) -> Result<Self, PalimpsestError> {
        let mut keys = BTreeSet::new();
        let mut rep_map = BTreeMap::new();
        let mut res_map = BTreeMap::new();
        for p in as_reported {
            let k = (p.period_code.clone(), p.account_ref, p.unit);
            keys.insert(k.clone());
            rep_map.insert(k, p.net_debit);
        }
        for p in as_restated {
            let k = (p.period_code.clone(), p.account_ref, p.unit);
            keys.insert(k.clone());
            res_map.insert(k, p.net_debit);
        }

        let mut lines = Vec::new();
        for (period_code, account_ref, unit) in keys {
            let before = rep_map
                .get(&(period_code.clone(), account_ref, unit))
                .copied()
                .unwrap_or(0);
            let after = res_map
                .get(&(period_code.clone(), account_ref, unit))
                .copied()
                .unwrap_or(0);
            let delta = after.checked_sub(before).ok_or(PalimpsestError::Overflow)?;
            if delta != 0 {
                lines.push(RestatementDiffLine {
                    period_code,
                    account_ref,
                    unit,
                    as_reported_net: before,
                    as_restated_net: after,
                    delta_net: delta,
                });
            }
        }

        let certificate_digest =
            Self::digest(case_id, book_id, as_reported_seq, as_restated_seq, &lines)
                .map_err(|e| PalimpsestError::InvalidRestatementCase(e.to_string()))?;

        Ok(Self {
            case_id,
            book_id,
            as_reported_seq,
            as_restated_seq,
            lines,
            certificate_digest,
        })
    }

    pub fn digest(
        case_id: Id128,
        book_id: Id128,
        as_reported_seq: CommitSeq,
        as_restated_seq: CommitSeq,
        lines: &[RestatementDiffLine],
    ) -> Result<[u8; 32], EncodeError> {
        let mut w = Writer::new();
        w.u16(1)
            .fixed(&case_id.0)
            .fixed(&book_id.0)
            .u64(as_reported_seq.0)
            .u64(as_restated_seq.0)
            .list(lines, |w, l| {
                w.str(&l.period_code)
                    .u128(l.account_ref.0)
                    .u32(l.unit.0)
                    .i128(l.as_reported_net)
                    .i128(l.as_restated_net)
                    .i128(l.delta_net);
            });
        Ok(domain_digest(RESTATEMENT_DIFF_CERT_DOMAIN, &[&w.finish()?]))
    }

    /// Recompute the diff from the two snapshots and verify the certificate digest byte-for-byte.
    pub fn verify_replay(
        &self,
        as_reported: &[PeriodPosition],
        as_restated: &[PeriodPosition],
    ) -> bool {
        let Ok(recomputed) = Self::compute(
            self.case_id,
            self.book_id,
            self.as_reported_seq,
            self.as_restated_seq,
            as_reported,
            as_restated,
        ) else {
            return false;
        };
        *self == recomputed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::entry::SCHEMA_MINOR;
    use fa_model::{EntryOrigin, Erasable, EvidenceRef, SealKey, Supersession};
    use fa_money::Amount;

    const KEY: SealKey = SealKey([7; 32]);

    fn sample_payload(
        class: EntryClass,
        legs: Vec<LegPayload>,
        supersession: Vec<Supersession>,
    ) -> EntryPayload {
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: SCHEMA_MINOR,
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            class,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(&"sample".to_string(), None, &KEY, [1; 32], [2; 24]),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: b"k".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([9; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(7),
            session_ref: None,
            evidence: vec![EvidenceRef {
                document_oid: Oid([2; 32]),
                doc_commit: [3; 32],
                role: 1,
            }],
            supersession,
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn palimpsest_seq_map_monotonicity_and_translation() {
        let pairs = vec![
            SeqPair {
                source_seq: CommitSeq(2),
                source_marker: [0x11; 32],
                scratch_seq: CommitSeq(1),
            },
            SeqPair {
                source_seq: CommitSeq(5),
                source_marker: [0x22; 32],
                scratch_seq: CommitSeq(2),
            },
        ];
        assert!(seq_pairs_are_monotone(&pairs));
        assert_eq!(translate_seq(CommitSeq(6), &pairs, CommitSeq(1)), None);
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(2)),
            Some(CommitSeq(1))
        );
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(4)),
            Some(CommitSeq(1))
        );
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(5)),
            Some(CommitSeq(2))
        );
        assert_eq!(translate_seq(CommitSeq(6), &pairs, CommitSeq(7)), None);
    }

    #[test]
    fn palimpsest_reversal_ancestry_detects_reversed_ancestor() {
        let e1 = VId(1);
        let e2 = VId(2);
        let mut nodes = BTreeMap::new();
        nodes.insert(
            e1,
            SupersessionNode {
                vid: e1,
                class: EntryClass::ORIGINAL,
                supersedes: None,
            },
        );
        nodes.insert(
            e2,
            SupersessionNode {
                vid: e2,
                class: EntryClass::RECLASSIFICATION,
                supersedes: Some(e1),
            },
        );
        let mut reversed = BTreeSet::new();
        assert_eq!(validate_unreversed_ancestry(&nodes, &reversed, e2), Ok(()));
        reversed.insert(e1);
        assert_eq!(validate_unreversed_ancestry(&nodes, &reversed, e2), Err(e1));
    }

    #[test]
    fn palimpsest_restatement_case_state_transitions_are_monotone() {
        assert!(RestatementCaseState::Open.can_transition_to(RestatementCaseState::Approved));
        assert!(RestatementCaseState::Approved.can_transition_to(RestatementCaseState::Applied));
        assert!(RestatementCaseState::Applied.can_transition_to(RestatementCaseState::Closed));
        assert!(!RestatementCaseState::Closed.can_transition_to(RestatementCaseState::Open));
    }

    #[test]
    fn every_supersession_kind_maps_to_registered_netting_law_and_computes_net_effect() {
        let classes = EntryClasses::embedded().expect("entry_classes.toml");
        let sup_reg = SupersessionKinds::embedded(&classes).expect("supersession_kinds.toml");
        for kind in [
            SupersessionKind::Reverses,
            SupersessionKind::Replaces,
            SupersessionKind::Reclassifies,
            SupersessionKind::Revises,
            SupersessionKind::Restates,
            SupersessionKind::Resolves,
        ] {
            let law = netting_law_for(kind);
            let row = sup_reg.by_tag(kind as u8).expect("registered kind");
            assert_eq!(row.netting_law, law.as_str());
        }

        // Build a lineage chain: E1 (Original: Dr 6000 100, Cr 1000 100)
        // -> E2 (Reversal of E1) + E3 (Replacement of E1: Dr 6100 100, Cr 1000 100)
        // -> E4 (Reclassification of E3: Cr 6100 40, Dr 6200 40)
        let usd = UnitId(1);
        let e1_vid = VId(10);
        let e1 = sample_payload(
            EntryClass::ORIGINAL,
            vec![
                LegPayload::simple(Side::Debit, VId(6000), Amount::new(usd, 100)),
                LegPayload::simple(Side::Credit, VId(1000), Amount::new(usd, 100)),
            ],
            Vec::new(),
        )
        .seal(Vec::new(), None)
        .unwrap();
        let e1_ref = e1.entry_ref(e1_vid);

        let e2_vid = VId(11);
        let e2 = sample_payload(
            EntryClass::REVERSAL,
            vec![
                LegPayload::simple(Side::Credit, VId(6000), Amount::new(usd, 100)),
                LegPayload::simple(Side::Debit, VId(1000), Amount::new(usd, 100)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Reverses,
                target: e1_ref,
                reason_code: 2,
            }],
        )
        .seal(Vec::new(), None)
        .unwrap();

        let e3_vid = VId(12);
        let e3 = sample_payload(
            EntryClass::REPLACEMENT,
            vec![
                LegPayload::simple(Side::Debit, VId(6100), Amount::new(usd, 100)),
                LegPayload::simple(Side::Credit, VId(1000), Amount::new(usd, 100)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Replaces,
                target: e1_ref,
                reason_code: 2,
            }],
        )
        .seal(Vec::new(), None)
        .unwrap();
        let e3_ref = e3.entry_ref(e3_vid);

        validate_replacement_pair(&e1.proposal, e1_ref, &e2.proposal, &e3.proposal)
            .expect("valid replacement pair");

        let e4_vid = VId(13);
        let e4 = sample_payload(
            EntryClass::RECLASSIFICATION,
            vec![
                LegPayload::simple(Side::Credit, VId(6100), Amount::new(usd, 40)),
                LegPayload::simple(Side::Debit, VId(6200), Amount::new(usd, 40)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Reclassifies,
                target: e3_ref,
                reason_code: 3,
            }],
        )
        .seal(Vec::new(), None)
        .unwrap();

        validate_reclassification(&e3.proposal, e3_ref, &e4.proposal)
            .expect("valid reclassification");

        let entries = vec![
            (e1_vid, e1, CommitSeq(1)),
            (e2_vid, e2, CommitSeq(2)),
            (e3_vid, e3, CommitSeq(2)),
            (e4_vid, e4, CommitSeq(3)),
        ];

        let report = explain_lineage(&entries, e1_vid, None)
            .expect("lineage ok")
            .expect("found");
        assert_eq!(report.root_vid, e1_vid);
        assert_eq!(report.replaced_by, Some(e3_vid));
        assert!(!report.fully_reversed);
        assert_eq!(report.entries.len(), 4);

        let by_acct: BTreeMap<VId, i128> = report
            .net_positions
            .iter()
            .map(|p| (p.account_ref, p.net_debit))
            .collect();
        assert_eq!(by_acct.get(&VId(1000)), Some(&-100));
        assert_eq!(by_acct.get(&VId(6000)), Some(&0));
        assert_eq!(by_acct.get(&VId(6100)), Some(&60));
        assert_eq!(by_acct.get(&VId(6200)), Some(&40));
        // No entry in this chain reverses a reversal.
        assert!(report.entries.iter().all(|e| !e.reverses_reversal));
    }

    /// Plan §8.2: reversing a Reversal revives the original by parity, and
    /// the lineage flags exactly that entry (fa-s3wz).
    #[test]
    fn lineage_flags_reverse_of_reverse() {
        let usd = UnitId(1);
        let rent = vec![
            LegPayload::simple(Side::Debit, VId(6000), Amount::new(usd, 100)),
            LegPayload::simple(Side::Credit, VId(1000), Amount::new(usd, 100)),
        ];
        let swapped = vec![
            LegPayload::simple(Side::Credit, VId(6000), Amount::new(usd, 100)),
            LegPayload::simple(Side::Debit, VId(1000), Amount::new(usd, 100)),
        ];
        let original = sample_payload(EntryClass::ORIGINAL, rent.clone(), Vec::new())
            .seal(Vec::new(), None)
            .unwrap();
        let reverses = |target, legs| {
            sample_payload(
                EntryClass::REVERSAL,
                legs,
                vec![Supersession {
                    kind: SupersessionKind::Reverses,
                    target,
                    reason_code: 2,
                }],
            )
            .seal(Vec::new(), None)
            .unwrap()
        };
        let reversal = reverses(original.entry_ref(VId(10)), swapped);
        let revival = reverses(reversal.entry_ref(VId(11)), rent);
        // The Reversal itself is a registered reversible target.
        check_target_reversible(&reversal.proposal).expect("a Reversal is reversible");
        let entries = vec![
            (VId(10), original, CommitSeq(1)),
            (VId(11), reversal, CommitSeq(2)),
            (VId(12), revival, CommitSeq(3)),
        ];
        let report = explain_lineage(&entries, VId(12), None)
            .expect("lineage ok")
            .expect("found");
        let flags: Vec<_> = report
            .entries
            .iter()
            .map(|e| (e.vid, e.live, e.reverses_reversal))
            .collect();
        assert_eq!(
            flags,
            [
                (VId(10), true, false),
                (VId(11), false, false),
                (VId(12), true, true),
            ]
        );
        assert!(!report.fully_reversed, "the original is live again");
        let net: BTreeMap<VId, i128> = report
            .net_positions
            .iter()
            .map(|p| (p.account_ref, p.net_debit))
            .collect();
        assert_eq!(net.get(&VId(6000)), Some(&100));
        assert_eq!(net.get(&VId(1000)), Some(&-100));
    }

    #[test]
    fn unpaired_replacement_and_over_reclassification_are_refused() {
        let usd = UnitId(1);
        let e1_vid = VId(10);
        let e1 = sample_payload(
            EntryClass::ORIGINAL,
            vec![
                LegPayload::simple(Side::Debit, VId(6000), Amount::new(usd, 100)),
                LegPayload::simple(Side::Credit, VId(1000), Amount::new(usd, 100)),
            ],
            Vec::new(),
        )
        .seal(Vec::new(), None)
        .unwrap();
        let e1_ref = e1.entry_ref(e1_vid);

        let e3_vid = VId(12);
        let e3 = sample_payload(
            EntryClass::REPLACEMENT,
            vec![
                LegPayload::simple(Side::Debit, VId(6100), Amount::new(usd, 100)),
                LegPayload::simple(Side::Credit, VId(1000), Amount::new(usd, 100)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Replaces,
                target: e1_ref,
                reason_code: 2,
            }],
        )
        .seal(Vec::new(), None)
        .unwrap();

        // Unpaired replacement in lineage (no Reversal of e1) is refused!
        let err = explain_lineage(
            &[
                (e1_vid, e1.clone(), CommitSeq(1)),
                (e3_vid, e3, CommitSeq(2)),
            ],
            e1_vid,
            None,
        )
        .expect_err("unpaired replacement must fail");
        assert!(matches!(
            err,
            PalimpsestError::UnpairedReplacement {
                replacement_vid: VId(12),
                target_vid: VId(10)
            }
        ));

        // Reclassification exceeding the target leg's amount is refused!
        let bad_reclass = sample_payload(
            EntryClass::RECLASSIFICATION,
            vec![
                LegPayload::simple(Side::Credit, VId(6000), Amount::new(usd, 150)),
                LegPayload::simple(Side::Debit, VId(6200), Amount::new(usd, 150)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Reclassifies,
                target: e1_ref,
                reason_code: 3,
            }],
        );
        let err = validate_reclassification(&e1.proposal, e1_ref, &bad_reclass)
            .expect_err("over-reclassification must fail");
        assert!(err.to_string().contains("exceeds target amount"), "{err}");
    }

    #[test]
    fn restatement_case_enforces_sod_and_emits_replayable_diff_certificate() {
        let usd = UnitId(1);
        let case_id = Id128([0xAA; 16]);
        let book_id = Id128([0xBB; 16]);
        let preparer = Id128([1; 16]);
        let approver1 = Id128([2; 16]);
        let approver2 = Id128([3; 16]);

        let mut rc = RestatementCase::open(
            case_id,
            book_id,
            RestatementScope::PriorPeriodRestatement,
            9, // MaterialMisstatement
            vec!["FY2026-P02".to_string()],
            Oid([0xCC; 32]),
            preparer,
            CommitSeq(10),
            CommitSeq(10),
        )
        .expect("open case");

        // Self-approval by preparer is refused (case_preparer exclusion).
        let err = rc
            .approve(vec![preparer, approver1], 2, CommitSeq(11))
            .expect_err("preparer self-approval must fail");
        assert!(err.to_string().contains("case_preparer"), "{err}");

        // Dual control with two distinct non-preparer approvers succeeds.
        rc.approve(vec![approver1, approver2], 2, CommitSeq(11))
            .expect("dual control approval");
        assert_eq!(rc.state, RestatementCaseState::Approved);

        let restate_entry = sample_payload(
            EntryClass::RESTATEMENT,
            vec![
                LegPayload::simple(Side::Debit, VId(6000), Amount::new(usd, 500)),
                LegPayload::simple(Side::Credit, VId(2000), Amount::new(usd, 500)),
            ],
            vec![Supersession {
                kind: SupersessionKind::Restates,
                target: EntryRef {
                    vid: VId(100),
                    entry_digest: [0x11; 32],
                },
                reason_code: 9,
            }],
        );
        rc.record_entry(VId(200), &restate_entry, "FY2026-P02")
            .expect("record restatement entry");
        rc.mark_applied(CommitSeq(12)).expect("mark applied");

        let before = vec![
            PeriodPosition {
                period_code: "FY2026-P02".into(),
                account_ref: VId(6000),
                unit: usd,
                net_debit: 1_000,
            },
            PeriodPosition {
                period_code: "FY2026-P02".into(),
                account_ref: VId(2000),
                unit: usd,
                net_debit: -1_000,
            },
        ];
        let after = vec![
            PeriodPosition {
                period_code: "FY2026-P02".into(),
                account_ref: VId(6000),
                unit: usd,
                net_debit: 1_500,
            },
            PeriodPosition {
                period_code: "FY2026-P02".into(),
                account_ref: VId(2000),
                unit: usd,
                net_debit: -1_500,
            },
        ];
        let cert = rc
            .close(CommitSeq(13), &before, &after)
            .expect("close case and emit diff certificate");
        assert_eq!(rc.state, RestatementCaseState::Closed);
        assert_eq!(cert.lines.len(), 2);
        assert!(cert.verify_replay(&before, &after));
        assert!(!cert.verify_replay(&before, &before));
    }
}
