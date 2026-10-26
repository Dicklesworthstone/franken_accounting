//! The seeded, tier-disciplined filler generator
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.5, §3.3, §3.7; bead fa-yugf.14,
//! A6).
//!
//! A D verdict is admissible only if unrelated data cannot move it, so every
//! book posts disciplined filler and A11a checks on K = 5 seeded variants,
//! the empty variant and one extremal variant per claimed tier that no
//! component moves. This module only generates the variants:
//!
//! - **Content is a pure function of the seed.** A variant's accounts,
//!   amounts, dates and keys are drawn in that order from the stream of
//!   SHA-256(case id ‖ variant id ‖ seed label) ([`super::stream`]).
//! - **Shape.** Book-variant intents (A1b): `fact = synthetic`, class
//!   Original (Migration on a migration book, staged before finalize, never
//!   a `PostBatch`), legs `amount_rule = synthetic` in the base unit, every
//!   intent balanced, each citing the variant's `filler:<variant>` document,
//!   and keyed `cf:` + the first 60 hex digits of SHA-256(case ‖ variant ‖
//!   seed ‖ chunk index ‖ member index). A variant posts as `PostBatch`
//!   chunks of at most `max_batch_entries` (8,190) entries.
//! - **Discipline.** Filler never touches what the documented history
//!   touches (every non-filler intent counts as a target, co-resident D
//!   cells included): L and C filler posts only to declared `9…` accounts
//!   no target uses; keys are disjoint by construction; S-acct, S-party and
//!   G content uses accounts and parties no target touches; O filler posts
//!   only at `filler_batch` steps before the first target step or after the
//!   last. A tier whose discipline needs what the case did not declare (two
//!   filler accounts, an S-acct sibling, a filler party, the filler
//!   document) is refused at generation, naming it.
//! - **Timing.** A variant's entries are dated in the periods Open at its
//!   `filler_batch` step (A1b refuses a step at which none is).
//! - **Statement and ledger stems** carry no declared filler ([`specs`]
//!   returns only the empty spec). [`generate`] can still emit a G or
//!   S-party extremal for a ledger book, on synthetic accounts and parties
//!   disjoint from every exhibit account, for A11a's harness-only copy.

use std::collections::BTreeSet;

use super::Case;
use super::book::{BookVariant, IntentDef, LegDef, StepKind, VariantKind};
use super::check::tier::claimed;
use super::error::{LoadError, LoadErrorKind};
use super::stream::Stream;
use super::tiers::{Tier, Tiers};
use crate::sha256;

/// Seeded variants per filler variant (§3.7 item 1).
pub const SEEDS: u32 = 5;

/// The extremal volume factor (§3.7: 10^3 × the target).
pub const EXTREMAL_FACTOR: usize = 1000;

/// What a spec generates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillerKind {
    Seeded(u32),
    Empty,
    Extremal(Tier),
}

/// One filler configuration of a book variant's filler variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillerSpec {
    pub case: String,
    /// The filler variant id (the `filler_batch` steps' `ref`, the
    /// `filler:<variant>` document).
    pub variant: String,
    pub kind: FillerKind,
    /// The discipline obeyed: the strictest claimed tier for a seeded
    /// spec, the extremal tier for an extremal one.
    pub tier: Tier,
}

impl FillerSpec {
    /// The seed label the stream and the keys read.
    #[must_use]
    pub fn seed_label(&self) -> String {
        match self.kind {
            FillerKind::Seeded(n) => n.to_string(),
            FillerKind::Empty => "empty".into(),
            FillerKind::Extremal(t) => format!("extremal-{}", t.as_str()),
        }
    }

    /// `<variant>@<seed label>`, the JSONL step record's `filler_variant`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}@{}", self.variant, self.seed_label())
    }
}

/// How a variant reaches the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posting {
    /// `fa batch` chunks.
    PostBatch,
    /// Migration chunks for `migrate_stage`, before `fa migrate finalize`.
    Staged,
}

/// One generated variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillerVariant {
    pub spec: FillerSpec,
    pub posting: Posting,
    /// The `[[document]] id` every member cites.
    pub document: String,
    pub principal: String,
    pub intents: Vec<IntentDef>,
    pub legs: Vec<LegDef>,
    /// The largest chunk this variant posts in (1 for O's extremal: one
    /// commit per entry).
    pub chunk_max: usize,
}

impl FillerVariant {
    /// SHA-256 (hex) of the variant's canonical intent bytes: per intent its
    /// id, class, date, key, principal and evidence, then its legs' ordinal,
    /// account, side, amount, unit and party, fields 0x00-separated.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut b = Vec::new();
        let mut put = |s: &str| {
            b.extend_from_slice(s.as_bytes());
            b.push(0);
        };
        for it in &self.intents {
            put(&it.id);
            put(&it.class);
            put(&it.effective_date);
            put(it.idempotency_key.as_deref().unwrap_or_default());
            put(&it.principal);
            put(it.evidence.as_deref().unwrap_or_default());
            for l in self.legs.iter().filter(|l| l.intent == it.id) {
                put(&l.ordinal.to_string());
                put(&l.account);
                put(&l.side);
                put(&l.amount_literal);
                put(&l.unit);
                put(l.party.as_deref().unwrap_or_default());
            }
        }
        sha256::hex(&sha256::digest(&b))
    }

    /// `FILLER <variant> tier=<T> entries=<n> chunks=<k> digest=<hex>`.
    #[must_use]
    pub fn summary(&self, max: usize) -> String {
        format!(
            "FILLER {} tier={} entries={} chunks={} digest={}",
            self.spec.label(),
            self.spec.tier.as_str(),
            self.intents.len(),
            chunks(self, max).len(),
            self.digest()
        )
    }
}

/// One `PostBatch` (or staged) chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub index: usize,
    pub key: String,
    /// Member intent ids, in order.
    pub intents: Vec<String>,
}

/// `cf:` plus the first 60 hex digits of SHA-256(case ‖ variant ‖ seed ‖
/// chunk ‖ member), fields 0x00-separated: 63 bytes, inside the 64-byte key
/// limit. A chunk's own key names its member slot `chunk`.
#[must_use]
pub fn key(spec: &FillerSpec, chunk: usize, member: Option<usize>) -> String {
    let member = member.map_or_else(|| "chunk".to_string(), |m| m.to_string());
    let mut b = Vec::new();
    for part in [
        spec.case.as_str(),
        spec.variant.as_str(),
        &spec.seed_label(),
        &chunk.to_string(),
        &member,
    ] {
        b.extend_from_slice(part.as_bytes());
        b.push(0);
    }
    format!("cf:{}", &sha256::hex(&sha256::digest(&b))[..60])
}

/// The registered `max_batch_entries` (8,190).
///
/// # Errors
///
/// When `registries/limits.toml` does not load or lacks the row.
pub fn max_batch_entries() -> Result<usize, String> {
    fa_registry::limits_embedded()
        .map_err(|e| format!("{e:?}"))?
        .get("max_batch_entries")
        .and_then(|v| usize::try_from(*v).ok())
        .ok_or_else(|| "registries/limits.toml has no max_batch_entries".into())
}

/// The variant's chunks of at most `max` (and its own `chunk_max`) members,
/// in order: a pure function of the variant.
#[must_use]
pub fn chunks(variant: &FillerVariant, max: usize) -> Vec<Chunk> {
    let size = max.min(variant.chunk_max).max(1);
    variant
        .intents
        .chunks(size)
        .enumerate()
        .map(|(index, members)| Chunk {
            index,
            key: key(&variant.spec, index, None),
            intents: members.iter().map(|i| i.id.clone()).collect(),
        })
        .collect()
}

fn refuse(book: &BookVariant, detail: String) -> LoadError {
    LoadError {
        file: format!("books/{}.toml", book.stem),
        line: None,
        kind: LoadErrorKind::MissingField,
        row: Some("filler".into()),
        detail,
    }
}

/// What the documented history touches, which filler never does.
#[derive(Clone, Debug, Default)]
pub struct Targets {
    pub accounts: BTreeSet<String>,
    pub parties: BTreeSet<String>,
    pub keys: BTreeSet<String>,
    /// The step positions of the first and last target intent step.
    pub span: Option<(i128, i128)>,
    /// The most legs any target carries.
    pub max_legs: usize,
}

/// Every non-filler intent of the book is a target.
#[must_use]
pub fn targets(book: &BookVariant) -> Targets {
    let mut t = Targets::default();
    for it in book.intents.iter().filter(|i| i.fact != "synthetic") {
        t.keys.insert(
            it.idempotency_key
                .clone()
                .unwrap_or_else(|| format!("case-{}", it.id)),
        );
        let legs: Vec<&LegDef> = book.legs.iter().filter(|l| l.intent == it.id).collect();
        t.max_legs = t.max_legs.max(legs.len());
        for l in legs {
            t.accounts.insert(l.account.clone());
            if let Some(p) = &l.party {
                t.parties.insert(p.clone());
            }
        }
        for a in [&it.allocation_source]
            .into_iter()
            .flatten()
            .chain(it.allocation_targets.iter().flatten())
        {
            t.accounts.insert(a.clone());
        }
    }
    // Parties related to a target party are in its component (G).
    let mut grew = true;
    while grew {
        grew = false;
        for p in &book.parties {
            let linked = p.relations.iter().any(|r| t.parties.contains(&r.to));
            if (linked || t.parties.contains(&p.id)) && t.parties.insert(p.id.clone()) {
                grew = true;
            }
            if t.parties.contains(&p.id) {
                for r in &p.relations {
                    if t.parties.insert(r.to.clone()) {
                        grew = true;
                    }
                }
            }
        }
    }
    let intents: BTreeSet<&str> = book
        .intents
        .iter()
        .filter(|i| i.fact != "synthetic")
        .map(|i| i.id.as_str())
        .collect();
    let seqs: Vec<i128> = book
        .steps
        .iter()
        .filter(|s| {
            matches!(
                s.step_kind(),
                Some(StepKind::Intent | StepKind::Allocate | StepKind::Batch)
            ) && s.reference.split("..").any(|r| intents.contains(r))
        })
        .map(|s| s.seq)
        .collect();
    if let (Some(a), Some(b)) = (seqs.iter().min(), seqs.iter().max()) {
        t.span = Some((*a, *b));
    }
    t
}

/// The book's filler variant ids: its `filler_batch` steps' refs, in step
/// order.
fn filler_variants(book: &BookVariant) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in &book.steps {
        if s.step_kind() == Some(StepKind::FillerBatch) && !out.contains(&s.reference) {
            out.push(s.reference.clone());
        }
    }
    out
}

/// The tiers of the procedures the case claims on this variant.
fn claimed_tiers(case: &Case, tiers: &Tiers) -> BTreeSet<Tier> {
    claimed(case)
        .keys()
        .filter_map(|p| tiers.get(p).map(|r| r.tier))
        .collect()
}

/// Every spec of a book variant: per filler variant the K = 5 seeded specs
/// (seeds 1–5) under the strictest claimed tier, the empty spec, and one
/// extremal spec per claimed tier. A statement or ledger stem, or a book
/// with no `filler_batch` step, gets only the empty spec.
///
/// # Errors
///
/// When an O-tier procedure is claimed and a `filler_batch` step sits
/// inside the target span.
pub fn specs(case: &Case, book: &BookVariant, tiers: &Tiers) -> Result<Vec<FillerSpec>, LoadError> {
    let claimed = claimed_tiers(case, tiers);
    let strictest = claimed.iter().max().copied().unwrap_or(Tier::L);
    let variants = filler_variants(book);
    let empty = |variant: &str| FillerSpec {
        case: case.header.id.clone(),
        variant: variant.to_string(),
        kind: FillerKind::Empty,
        tier: strictest,
    };
    if matches!(book.kind, VariantKind::Statement | VariantKind::Ledger) || variants.is_empty() {
        return Ok(vec![empty(variants.first().map_or("none", String::as_str))]);
    }
    if claimed.contains(&Tier::O) {
        let t = targets(book);
        if let Some((first, last)) = t.span
            && let Some(s) = book.steps.iter().find(|s| {
                s.step_kind() == Some(StepKind::FillerBatch) && s.seq > first && s.seq < last
            })
        {
            return Err(refuse(
                book,
                format!(
                    "an O-tier procedure is claimed, so filler posts before the first target step ({first}) or after the last ({last}); filler_batch step {} sits between",
                    s.seq
                ),
            ));
        }
    }
    let mut out = Vec::new();
    for v in &variants {
        for seed in 1..=SEEDS {
            out.push(FillerSpec {
                case: case.header.id.clone(),
                variant: v.clone(),
                kind: FillerKind::Seeded(seed),
                tier: strictest,
            });
        }
        out.push(empty(v));
        for t in &claimed {
            out.push(FillerSpec {
                case: case.header.id.clone(),
                variant: v.clone(),
                kind: FillerKind::Extremal(*t),
                tier: *t,
            });
        }
    }
    Ok(out)
}

/// A test-only plant that breaks the discipline, for the property test's
/// negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    None,
    /// The first entry's debit leg is drawn from a target account.
    TargetAccount,
    /// The first entry's key is a target's key.
    TargetKey,
}

/// Generates `spec`'s variant of `book`: pure, deterministic.
///
/// # Errors
///
/// When the tier's discipline needs what the case did not declare.
pub fn generate(
    case: &Case,
    book: &BookVariant,
    spec: &FillerSpec,
) -> Result<FillerVariant, LoadError> {
    generate_planted(case, book, spec, Plant::None)
}

fn unit_scale(unit: &str) -> u32 {
    fa_registry::units_embedded()
        .ok()
        .and_then(|units| units.into_iter().find(|u| u.code == unit))
        .map_or(2, |u| u32::from(u.scale))
}

/// `minor` minor units at `scale` as a decimal literal.
fn literal(minor: u64, scale: u32) -> String {
    if scale == 0 {
        return minor.to_string();
    }
    let p = 10u64.pow(scale);
    format!("{}.{:0w$}", minor / p, minor % p, w = scale as usize)
}

/// [`generate`] with a plant (tests only plant).
///
/// # Errors
///
/// As [`generate`].
#[allow(clippy::too_many_lines)]
pub fn generate_planted(
    _case: &Case,
    book: &BookVariant,
    spec: &FillerSpec,
    plant: Plant,
) -> Result<FillerVariant, LoadError> {
    let ledger_copy = book.kind == VariantKind::Ledger;
    let t = targets(book);
    let posting = if book.kind == VariantKind::Migration {
        Posting::Staged
    } else {
        Posting::PostBatch
    };
    let step = book
        .steps
        .iter()
        .find(|s| s.step_kind() == Some(StepKind::FillerBatch) && s.reference == spec.variant);
    let principal = step
        .and_then(|s| s.principal.clone())
        .or_else(|| book.principals.first().map(|p| p.label.clone()))
        .unwrap_or_default();
    let document = book
        .documents
        .iter()
        .find(|d| d.stub_of == format!("filler:{}", spec.variant))
        .map(|d| d.id.clone());
    let mut variant = FillerVariant {
        spec: spec.clone(),
        posting,
        document: document.clone().unwrap_or_default(),
        principal: principal.clone(),
        intents: Vec::new(),
        legs: Vec::new(),
        chunk_max: usize::MAX,
    };
    let count = match spec.kind {
        FillerKind::Empty => return Ok(variant),
        FillerKind::Seeded(_) => None,
        FillerKind::Extremal(tier) => Some(match tier {
            Tier::L | Tier::C => EXTREMAL_FACTOR * t.max_legs.max(1),
            _ => EXTREMAL_FACTOR,
        }),
    };
    let Some(document) = document else {
        return Err(refuse(
            book,
            format!(
                "filler variant {} cites one [[document]] stub_of = \"filler:{}\"; none is declared",
                spec.variant, spec.variant
            ),
        ));
    };
    // The periods Open at the variant's filler_batch step (A1b refuses a
    // step at which none is); a harness-only ledger copy uses every period.
    let periods: Vec<&super::book::PeriodDef> = match step {
        Some(s) if !ledger_copy => {
            let open = open_at(book, s.seq);
            book.periods
                .iter()
                .filter(|p| open.contains(&p.code))
                .collect()
        }
        _ => book.periods.iter().collect(),
    };
    if periods.is_empty() {
        return Err(refuse(
            book,
            format!(
                "filler variant {} has no Open period to post in",
                spec.variant
            ),
        ));
    }
    // The account universe.
    let filler_accounts: Vec<String> = if ledger_copy {
        (1..=2)
            .map(|n| {
                let mut code = format!("9F{n:02}");
                while book.accounts.iter().any(|a| a.code == code) {
                    code.push('X');
                }
                code
            })
            .collect()
    } else {
        book.accounts
            .iter()
            .filter(|a| a.code.starts_with('9') && !t.accounts.contains(&a.code))
            .map(|a| a.code.clone())
            .collect()
    };
    if filler_accounts.len() < 2 {
        return Err(refuse(
            book,
            format!(
                "{} filler posts on two declared filler accounts (`9…`, no target's); found {}",
                spec.tier.as_str(),
                filler_accounts.len()
            ),
        ));
    }
    let mut debit_accounts = filler_accounts.clone();
    if spec.kind == FillerKind::Extremal(Tier::SAcct) {
        // A sibling of a target account: same type and role, no target's.
        let sibling = book.accounts.iter().find(|a| {
            !t.accounts.contains(&a.code)
                && !a.code.starts_with('9')
                && book.accounts.iter().any(|x| {
                    t.accounts.contains(&x.code)
                        && x.account_type == a.account_type
                        && x.role == a.role
                })
        });
        let Some(sibling) = sibling else {
            let wanted: Vec<String> = book
                .accounts
                .iter()
                .filter(|a| t.accounts.contains(&a.code))
                .map(|a| {
                    format!(
                        "{} {}{}",
                        a.code,
                        a.account_type,
                        a.role
                            .as_deref()
                            .filter(|r| !r.is_empty())
                            .map_or_else(String::new, |r| format!(" role {r}"))
                    )
                })
                .collect();
            return Err(refuse(
                book,
                format!(
                    "the S-acct extremal posts on a declared sibling account (same type and role as a target account, used by no target) of one of [{}]; none is declared",
                    wanted.join(", ")
                ),
            ));
        };
        debit_accounts = vec![sibling.code.clone()];
    }
    let parties: Vec<String> = if matches!(spec.kind, FillerKind::Extremal(Tier::SParty | Tier::G))
    {
        if ledger_copy {
            vec!["FILLER-P1".into(), "FILLER-P2".into()]
        } else {
            let free: Vec<String> = book
                .parties
                .iter()
                .filter(|p| !t.parties.contains(&p.id) && p.relations.is_empty())
                .map(|p| p.id.clone())
                .collect();
            if free.is_empty() {
                return Err(refuse(
                    book,
                    format!(
                        "the {} extremal posts against a declared filler party (no target's, unrelated to any); none is declared",
                        spec.tier.as_str()
                    ),
                ));
            }
            free
        }
    } else {
        Vec::new()
    };
    if spec.kind == FillerKind::Extremal(Tier::O) {
        variant.chunk_max = 1;
    }
    let unit = book.book.base_unit.clone();
    let scale = unit_scale(&unit);
    let mut stream = Stream::from_parts(&[
        spec.case.as_bytes(),
        spec.variant.as_bytes(),
        spec.seed_label().as_bytes(),
    ]);
    let n = count.unwrap_or_else(|| 4 + usize::try_from(stream.below(13)).unwrap_or(0));
    let max = max_batch_entries()
        .unwrap_or(8190)
        .min(variant.chunk_max)
        .max(1);
    let target_accounts: Vec<&String> = t.accounts.iter().collect();
    let target_keys: Vec<&String> = t.keys.iter().collect();
    for i in 0..n {
        // Accounts, then amounts, then dates, then keys (the stream's order).
        let pick = |s: &mut Stream, v: &[String]| {
            v[usize::try_from(s.below(v.len() as u64)).unwrap_or(0)].clone()
        };
        let mut debit = pick(&mut stream, &debit_accounts);
        let credit = {
            let others: Vec<String> = filler_accounts
                .iter()
                .filter(|a| **a != debit)
                .cloned()
                .collect();
            pick(&mut stream, &others)
        };
        if plant == Plant::TargetAccount && i == 0 && !target_accounts.is_empty() {
            debit = target_accounts[0].clone();
        }
        let party = (!parties.is_empty()).then(|| pick(&mut stream, &parties));
        let minor = 1 + stream.below(1_000_000);
        let amount = literal(minor, scale);
        let period = periods[usize::try_from(stream.below(periods.len() as u64)).unwrap_or(0)];
        let date = match (
            super::date::Day::parse(&period.start),
            super::date::Day::parse(&period.end),
        ) {
            (Some(a), Some(b)) => {
                let span = u64::try_from(b.to_days() - a.to_days() + 1).unwrap_or(1);
                a.add_days(i64::try_from(stream.below(span)).unwrap_or(0))
                    .to_string()
            }
            _ => period.start.clone(),
        };
        let mut idempotency_key = key(spec, i / max, Some(i % max));
        if plant == Plant::TargetKey && i == 0 && !target_keys.is_empty() {
            idempotency_key = target_keys[0].clone();
        }
        let id = format!("filler-{}-{}-{i}", spec.variant, spec.seed_label());
        let class = if posting == Posting::Staged {
            "Migration"
        } else {
            "Original"
        };
        variant.intents.push(IntentDef {
            id: id.clone(),
            fact: "synthetic".into(),
            class: class.into(),
            principal: principal.clone(),
            effective_date: date,
            document_date: None,
            memo: Some(format!("filler {}", spec.label())),
            evidence: Some(document.clone()),
            idempotency_key: Some(idempotency_key),
            target: None,
            target_kind: None,
            reason: None,
            scenario: None,
            allocation_law: None,
            allocation_total: None,
            allocation_targets: None,
            allocation_source: None,
            allocation_source_side: None,
            source_entered_by: (posting == Posting::Staged).then(|| principal.clone()),
            source_approved_by: None,
            line: None,
        });
        for (ordinal, (account, side)) in [(debit, "Dr"), (credit, "Cr")].into_iter().enumerate() {
            variant.legs.push(LegDef {
                intent: id.clone(),
                ordinal: i128::try_from(ordinal).unwrap_or(0),
                account,
                side: side.into(),
                amount_literal: amount.clone(),
                amount_rule: "synthetic".into(),
                unit: unit.clone(),
                party: party.clone(),
                entity: None,
                line: None,
            });
        }
    }
    Ok(variant)
}

/// The `[[period]]` labels Open at step `seq`: opened by an earlier
/// `period_open` step and not yet soft-closed, closed or locked.
#[must_use]
pub fn open_at(book: &BookVariant, seq: i128) -> BTreeSet<String> {
    let mut open = BTreeSet::new();
    for s in book.steps.iter().filter(|s| s.seq < seq) {
        match s.step_kind() {
            Some(StepKind::PeriodOpen) => {
                open.insert(s.reference.clone());
            }
            Some(StepKind::PeriodSoftClose | StepKind::PeriodClose | StepKind::PeriodLock) => {
                open.remove(&s.reference);
            }
            _ => {}
        }
    }
    open
}

/// The discipline breaches of a generated variant (the property test's
/// predicate): a leg on a target account (L and C: on any account but a
/// declared `9…` one), a target's key, a target party or component, O
/// filler inside the target span.
#[must_use]
pub fn violations(book: &BookVariant, variant: &FillerVariant) -> Vec<String> {
    let t = targets(book);
    let mut out = Vec::new();
    let tier = variant.spec.tier;
    for l in &variant.legs {
        if t.accounts.contains(&l.account) {
            out.push(format!("leg on target account {}", l.account));
        } else if matches!(tier, Tier::L | Tier::C)
            && book.kind != VariantKind::Ledger
            && !l.account.starts_with('9')
        {
            out.push(format!("leg on non-filler account {}", l.account));
        }
        if let Some(p) = &l.party
            && t.parties.contains(p)
        {
            out.push(format!("leg on target party or component {p}"));
        }
    }
    for it in &variant.intents {
        if let Some(k) = &it.idempotency_key
            && t.keys.contains(k)
        {
            out.push(format!("key {k} is a target's"));
        }
    }
    if tier == Tier::O
        && let Some((first, last)) = t.span
    {
        for s in book.steps.iter().filter(|s| {
            s.step_kind() == Some(StepKind::FillerBatch) && s.reference == variant.spec.variant
        }) {
            if s.seq > first && s.seq < last {
                out.push(format!("O filler at step {} inside the target span", s.seq));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::book::LegDef;
    use super::super::tiers::tiers;
    use super::super::{CaseFiles, load};
    use super::*;

    const FILES: [(&str, &str); 4] = [
        (
            "case.toml",
            include_str!("../../tests/fixtures/filler/case.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../tests/fixtures/filler/roles.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../tests/fixtures/filler/facts.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../tests/fixtures/filler/books/native.toml"),
        ),
    ];

    fn fixture_with(book_edits: &[(&str, &str)]) -> Result<Case, Vec<LoadError>> {
        let mut book = FILES[3].1.to_string();
        for (old, new) in book_edits {
            assert_eq!(book.matches(old).count(), 1, "`{old}`");
            book = book.replacen(old, new, 1);
        }
        let files = [
            FILES[0],
            FILES[1],
            FILES[2],
            ("books/native.toml", book.as_str()),
        ];
        load(&CaseFiles {
            id: "filler",
            files: &files,
        })
    }

    fn fixture() -> Case {
        fixture_with(&[]).expect("the filler fixture loads")
    }

    fn native(case: &Case) -> &BookVariant {
        &case.books["native"]
    }

    fn spec(kind: FillerKind, tier: Tier) -> FillerSpec {
        FillerSpec {
            case: "filler".into(),
            variant: "fv1".into(),
            kind,
            tier,
        }
    }

    /// The property test's FAIL lines over every tier, seeds `seeds` and
    /// the extremal variant, under `plant`.
    fn property(case: &Case, book: &BookVariant, seeds: u32, plant: Plant) -> Vec<String> {
        let mut out = Vec::new();
        for tier in Tier::ALL {
            let kinds = (1..=seeds)
                .map(FillerKind::Seeded)
                .chain([FillerKind::Extremal(*tier)]);
            for kind in kinds {
                let s = spec(kind, *tier);
                let v = generate_planted(case, book, &s, plant).expect("generates");
                for why in violations(book, &v) {
                    out.push(format!(
                        "FAIL filler tier={} seed={}: {why}",
                        tier.as_str(),
                        s.seed_label()
                    ));
                }
            }
        }
        out
    }

    #[test]
    fn filler_never_touches_target_keys_accounts_or_components_per_tier() {
        let case = fixture();
        let fails = property(&case, native(&case), 256, Plant::None);
        assert!(fails.is_empty(), "{}", fails.join("\n"));
    }

    #[test]
    fn planted_draw_from_a_target_account_fails_the_property_test() {
        let case = fixture();
        let fails = property(&case, native(&case), 1, Plant::TargetAccount);
        assert!(
            fails.contains(&"FAIL filler tier=L seed=1: leg on target account 1000".to_string()),
            "{}",
            fails.join("\n")
        );
        let fails = property(&case, native(&case), 1, Plant::TargetKey);
        assert!(
            fails
                .iter()
                .any(|l| l.starts_with("FAIL filler tier=L seed=1: key ")
                    && l.ends_with(" is a target's")),
            "{}",
            fails.join("\n")
        );
    }

    #[test]
    fn same_seed_gives_byte_identical_filler() {
        let case = fixture();
        let a = generate(&case, native(&case), &spec(FillerKind::Seeded(3), Tier::C)).expect("a");
        let b = generate(&case, native(&case), &spec(FillerKind::Seeded(3), Tier::C)).expect("b");
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
        let c = generate(&case, native(&case), &spec(FillerKind::Seeded(4), Tier::C)).expect("c");
        assert_ne!(a.digest(), c.digest());
        println!("{}", a.summary(8190));
    }

    #[test]
    fn every_filler_intent_balances_per_unit() {
        let case = fixture();
        for kind in [FillerKind::Seeded(1), FillerKind::Extremal(Tier::G)] {
            let v = generate(&case, native(&case), &spec(kind, Tier::G)).expect("generates");
            for it in &v.intents {
                let legs: Vec<&LegDef> = v.legs.iter().filter(|l| l.intent == it.id).collect();
                let sum = |side: &str| -> u128 {
                    legs.iter()
                        .filter(|l| l.side == side)
                        .map(|l| {
                            l.amount_literal
                                .replace('.', "")
                                .parse::<u128>()
                                .expect("an amount")
                        })
                        .sum()
                };
                assert_eq!(sum("Dr"), sum("Cr"), "{}", it.id);
                assert!(sum("Dr") > 0, "{}", it.id);
                assert!(legs.iter().all(|l| l.unit == "USD"), "{}", it.id);
            }
        }
    }

    #[test]
    fn every_filler_intent_cites_the_variant_filler_document() {
        let case = fixture();
        let v = generate(&case, native(&case), &spec(FillerKind::Seeded(2), Tier::C)).expect("v");
        assert!(!v.intents.is_empty());
        assert!(
            v.intents
                .iter()
                .all(|i| i.evidence.as_deref() == Some("DOC-FILL")
                    && i.fact == "synthetic"
                    && i.class == "Original")
        );
        assert!(v.legs.iter().all(|l| l.amount_rule == "synthetic"));
        assert_eq!(v.posting, Posting::PostBatch);
    }

    #[test]
    fn filler_keys_fit_in_64_bytes() {
        let case = fixture();
        let v = generate(
            &case,
            native(&case),
            &spec(FillerKind::Extremal(Tier::C), Tier::C),
        )
        .expect("v");
        for it in &v.intents {
            let k = it.idempotency_key.as_deref().unwrap_or_default();
            assert_eq!(k.len(), 63, "{k}");
            assert!(k.starts_with("cf:"));
        }
        for c in chunks(&v, 8190) {
            assert_eq!(c.key.len(), 63);
        }
    }

    #[test]
    fn extremal_variant_above_8190_entries_is_chunked() {
        let mut case = fixture();
        // An 11-leg target (F6b as one compound entry, §6.4 W-D-03).
        let book = case.books.get_mut("native").expect("native");
        let template = book.legs[0].clone();
        for n in 2..11 {
            let mut l = template.clone();
            l.ordinal = n;
            book.legs.push(l);
        }
        let s = spec(FillerKind::Extremal(Tier::L), Tier::L);
        let v = generate(&case, native(&case), &s).expect("v");
        assert_eq!(v.intents.len(), 11_000);
        let c = chunks(&v, 8190);
        assert_eq!(
            c.iter().map(|c| c.intents.len()).collect::<Vec<_>>(),
            [8190, 2810]
        );
        let again = chunks(&generate(&case, native(&case), &s).expect("again"), 8190);
        assert_eq!(
            c, again,
            "the chunk sequence is a pure function of the seed"
        );
        assert_eq!(max_batch_entries(), Ok(8190));
    }

    #[test]
    fn migration_book_filler_is_staged_chunks_before_finalize() {
        let mut case = fixture();
        case.books.get_mut("native").expect("native").kind = VariantKind::Migration;
        let v = generate(&case, native(&case), &spec(FillerKind::Seeded(1), Tier::C)).expect("v");
        assert_eq!(v.posting, Posting::Staged);
        assert!(v.intents.iter().all(|i| i.class == "Migration"
            && i.source_entered_by.as_deref() == Some("selftest-preparer-1")));
    }

    #[test]
    fn s_acct_extremal_without_a_sibling_account_is_refused() {
        let mut case = fixture();
        case.books
            .get_mut("native")
            .expect("native")
            .accounts
            .retain(|a| a.code != "6001");
        let e = generate(
            &case,
            native(&case),
            &spec(FillerKind::Extremal(Tier::SAcct), Tier::SAcct),
        )
        .expect_err("no sibling");
        assert!(e.detail.contains("sibling account"), "{e}");
        assert!(e.detail.contains("6000 Expense"), "{e}");
        // With the sibling, the extremal posts on it.
        let case = fixture();
        let v = generate(
            &case,
            native(&case),
            &spec(FillerKind::Extremal(Tier::SAcct), Tier::SAcct),
        )
        .expect("v");
        assert!(v.legs.iter().any(|l| l.account == "6001"));
    }

    #[test]
    fn statement_and_ledger_stems_get_only_the_empty_spec() {
        let t = tiers().expect("tiers");
        for kind in [VariantKind::Statement, VariantKind::Ledger] {
            let mut case = fixture();
            case.books.get_mut("native").expect("native").kind = kind;
            let specs = specs(&case, native(&case), &t).expect("specs");
            assert_eq!(specs.len(), 1, "{kind:?}");
            assert_eq!(specs[0].kind, FillerKind::Empty);
        }
        // The native stem: 5 seeded, the empty, one extremal per claimed tier
        // (C for jet.round_amounts, S-rel for the SELF row).
        let case = fixture();
        let specs = specs(&case, native(&case), &t).expect("specs");
        let labels: Vec<String> = specs.iter().map(FillerSpec::label).collect();
        assert_eq!(
            labels,
            [
                "fv1@1",
                "fv1@2",
                "fv1@3",
                "fv1@4",
                "fv1@5",
                "fv1@empty",
                "fv1@extremal-C",
                "fv1@extremal-S-rel"
            ]
        );
    }

    #[test]
    fn ledger_extremal_copy_never_touches_an_exhibit_account() {
        let mut case = fixture();
        case.books.get_mut("native").expect("native").kind = VariantKind::Ledger;
        let book = native(&case);
        for tier in [Tier::SParty, Tier::G] {
            let v = generate(&case, book, &spec(FillerKind::Extremal(tier), tier)).expect("v");
            assert!(!v.legs.is_empty());
            for l in &v.legs {
                assert!(
                    !book.accounts.iter().any(|a| a.code == l.account),
                    "{}",
                    l.account
                );
                let p = l.party.as_deref().expect("a filler party");
                assert!(!book.parties.iter().any(|x| x.id == p), "{p}");
            }
        }
    }

    #[test]
    fn pilot_without_a_filler_batch_gets_only_the_empty_spec() {
        let case = super::super::tests::pilot_planted(&[]);
        let t = tiers().expect("tiers");
        let specs = specs(&case, &case.books["native"], &t).expect("specs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].kind, FillerKind::Empty);
    }

    #[test]
    fn filler_batch_before_its_periods_period_open_is_refused() {
        const FILLER: &str = "[[step]]\nseq = 2\nkind = \"filler_batch\"\nref = \"fv1\"\nprincipal = \"selftest-preparer-1\"\n\n";
        const OPEN: &str = "[[step]]\nseq = 1\nkind = \"period_open\"\nref = \"2026Q1\"";
        let errs = fixture_with(&[
            (FILLER, ""),
            (
                OPEN,
                "[[step]]\nseq = 1\nkind = \"filler_batch\"\nref = \"fv1\"\nprincipal = \"selftest-preparer-1\"\n\n[[step]]\nseq = 2\nkind = \"period_open\"\nref = \"2026Q1\"",
            ),
        ])
        .expect_err("a filler_batch before period_open is refused");
        assert!(
            errs.iter().any(|e| e.kind == LoadErrorKind::UnknownPeriod
                && e.detail
                    .starts_with("filler_batch step 1 posts while no period is Open")),
            "{errs:#?}"
        );
    }

    #[test]
    fn filler_batch_after_its_periods_first_soft_close_is_refused() {
        let errs = fixture_with(&[(
            "\n[[default]]",
            "\n[[step]]\nseq = 7\nkind = \"filler_batch\"\nref = \"fv1\"\nprincipal = \"selftest-preparer-1\"\n\n[[default]]",
        )])
        .expect_err("a filler_batch after the soft-close is refused");
        assert!(
            errs.iter().any(|e| e.kind == LoadErrorKind::UnknownPeriod
                && e.detail
                    .starts_with("filler_batch step 7 posts while no period is Open")),
            "{errs:#?}"
        );
    }
}
