//! `fa-gen`: seeded, deterministic synthetic-book and labeled forensic scenario
//! corpora (plan §11.10, §15.8, §18.1; bead `fa-8mae`).
//!
//! Generates the seven canonical scenarios with ground-truth [`PlantedFact`]
//! labels:
//! 1. [`ScenarioKind::CleanRetailer`] — clean retail ledger with Benford-distributed
//!    sales, purchases, expenses, and contiguous sequence numbers (zero planted
//!    fraud anomalies).
//! 2. [`ScenarioKind::ChannelStuffing`] — period-end cutoff straddles, post-closing
//!    top-side revenue entries, round-dollar revenue adjustments, and invoice
//!    sequence gaps.
//! 3. [`ScenarioKind::KitingBank`] — multi-bank check kiting round-trips near
//!    period end, cutoff straddle transfers, and weekend transfers.
//! 4. [`ScenarioKind::Ponzi`] — investor cohort inflows funding earlier cohort
//!    redemptions in round amounts, trust-account round-trips, self-approved
//!    distributions, and thin descriptions.
//! 5. [`ScenarioKind::ShellNetwork`] — sub-threshold structuring chains just
//!    below the $10,000 CTR threshold, intermediary clearing round-trips, and
//!    duplicate consulting payments.
//! 6. [`ScenarioKind::WorldComCapitalization`] — improper post-closing,
//!    round-dollar capitalization of operating line costs into network CapEx on
//!    weekends with self-approval and thin descriptions.
//! 7. [`ScenarioKind::GhostPayroll`] — duplicate net-pay disbursements on the
//!    same and adjacent payroll dates, payroll sequence gaps, and weekend
//!    self-approved off-cycle payments.
//!
//! Lives in the `verification` layer: never linked into production postures.

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeSet;

use fa_model::{AccountType, EntryClass, Oid};
use fa_money::Side;
use fa_time::{DateDay, PeriodTransition, Weekday};
use fgdb_crypto::Hasher;

/// Domain tag for deterministic `GeneratedCorpus` digests.
pub const CORPUS_DIGEST_DOMAIN: &[u8] = b"fa:gen:corpus:v1";

/// Expected Benford first-digit proportions at `10^9` scale (`d = 1..=9`),
/// matching `fa_lantern::digits::BENFORD_1E9`.
pub const BENFORD_WEIGHTS_1E9: [u64; 9] = [
    301_029_996,
    176_091_259,
    124_938_737,
    96_910_013,
    79_181_246,
    66_946_790,
    57_991_947,
    51_152_522,
    45_757_490,
];

/// Deterministic SplitMix64 pseudo-random generator (no external crate, no entropy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Seed from a scenario tag, caller seed, and scale knob.
    #[must_use]
    pub fn new(scenario_tag: u8, seed: u64, scale: usize) -> Self {
        let mut h = Hasher::new();
        h.update(b"fa:gen:rng-seed:v1");
        h.update(&[scenario_tag]);
        h.update(&seed.to_le_bytes());
        h.update(&(scale as u64).to_le_bytes());
        let digest = h.finalize().0;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Self {
            state: u64::from_le_bytes(bytes),
        }
    }

    /// Next 64-bit word via SplitMix64.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..bound` (`bound > 0`).
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "bound must be positive");
        self.next_u64() % bound
    }

    /// Generate a unique non-round USD cent amount whose leading decimal digit
    /// is `leading_digit` (`1..=9`), guaranteed not to be a multiple of
    /// `$1,000.00` (`100_000` cents) and not already in `used`.
    pub fn benford_cents(&mut self, leading_digit: u8, used: &mut BTreeSet<i128>) -> i128 {
        assert!((1..=9).contains(&leading_digit));
        loop {
            // Pick magnitude order: 4 digits ($10.00..$99.99), 5 digits ($100.00..$999.99),
            // or 6 digits ($1,000.00..$9,999.99) in cents.
            let pow10: i128 = match self.below(3) {
                0 => 1_000,
                1 => 10_000,
                _ => 100_000,
            };
            let tail = i128::from(self.below(pow10 as u64));
            let mut cents = i128::from(leading_digit) * pow10 + tail;
            // Ensure never a multiple of 100_000 ($1,000.00) or 100 ($1.00 round) so
            // jet.round_amounts never triggers on clean baseline entries.
            if cents % 100 == 0 {
                cents += 1 + i128::from(self.below(97));
            }
            // Keep leading digit intact after adjustment and stay well below the
            // $8,000.00 structuring floor (800_000 cents) so clean baseline flows
            // never accidentally form a sub-threshold structuring chain.
            if cents >= 750_000 {
                cents = i128::from(leading_digit) * 10_000
                    + i128::from(self.below(9_900))
                    + 13;
            }
            if cents % 100_000 != 0 && used.insert(cents) {
                return cents;
            }
        }
    }
}

/// The seven canonical synthetic scenarios of plan §11.10 / bead `fa-8mae`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScenarioKind {
    CleanRetailer,
    ChannelStuffing,
    KitingBank,
    Ponzi,
    ShellNetwork,
    WorldComCapitalization,
    GhostPayroll,
}

impl ScenarioKind {
    /// All seven canonical scenarios in deterministic registration order.
    pub const ALL: [Self; 7] = [
        Self::CleanRetailer,
        Self::ChannelStuffing,
        Self::KitingBank,
        Self::Ponzi,
        Self::ShellNetwork,
        Self::WorldComCapitalization,
        Self::GhostPayroll,
    ];

    /// Stable numeric tag for hashing and binary encoding.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::CleanRetailer => 1,
            Self::ChannelStuffing => 2,
            Self::KitingBank => 3,
            Self::Ponzi => 4,
            Self::ShellNetwork => 5,
            Self::WorldComCapitalization => 6,
            Self::GhostPayroll => 7,
        }
    }

    /// Canonical CLI/registry slug.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CleanRetailer => "clean-retailer",
            Self::ChannelStuffing => "channel-stuffing",
            Self::KitingBank => "kiting-bank",
            Self::Ponzi => "ponzi",
            Self::ShellNetwork => "shell-network",
            Self::WorldComCapitalization => "worldcom-capitalization",
            Self::GhostPayroll => "ghost-payroll",
        }
    }

    /// Short alias accepted by `fa demo init --scenario` and `fa-gen book --scenario`.
    #[must_use]
    pub const fn short_alias(self) -> &'static str {
        match self {
            Self::CleanRetailer => "retail",
            Self::ChannelStuffing => "stuffing",
            Self::KitingBank => "bank",
            Self::Ponzi => "ponzi",
            Self::ShellNetwork => "shell-network",
            Self::WorldComCapitalization => "worldcom",
            Self::GhostPayroll => "payroll",
        }
    }

    /// Human-readable scenario title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::CleanRetailer => "Clean Retailer (Baseline Control Book)",
            Self::ChannelStuffing => "Retailer with Channel Stuffing & Bill-and-Hold",
            Self::KitingBank => "Multi-Bank Check Kiting Across Three Instruments",
            Self::Ponzi => "Investment Vehicle Running a Cohort Ponzi Scheme",
            Self::ShellNetwork => "Shell Network with Layering, Structuring & Duplicate Billing",
            Self::WorldComCapitalization => "WorldCom-Style Operating Line-Cost Capitalization",
            Self::GhostPayroll => "Payroll Ledger with Ghost Employees & Off-Cycle Disbursements",
        }
    }

    /// One-sentence description of the scenario's accounting and forensic profile.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::CleanRetailer => {
                "Benford-distributed weekday retail sales, inventory purchases, and operating expenses with contiguous invoice/check numbers and zero planted anomalies."
            }
            Self::ChannelStuffing => {
                "Retail ledger with late-period round revenue pulls, next-period invoices back-dated across period boundaries, post-SoftClose top-side revenue entries, and omitted credit-memo sequence numbers."
            }
            Self::KitingBank => {
                "Treasury ledger with equal-amount inter-bank round-trip transfers near period end across three cash accounts, cross-period cutoff straddles, and weekend transfers."
            }
            Self::Ponzi => {
                "Commingled investment vehicle where new Cohort-B inflows fund round-dollar redemptions to Cohort-A investors, accompanied by trust round-trips, self-approved payouts, and thin descriptions."
            }
            Self::ShellNetwork => {
                "Intermediary clearing accounts with chains of sub-$10,000 structured transfers within 7 days, circular asset round-trips, and duplicate consulting invoice disbursements."
            }
            Self::WorldComCapitalization => {
                "Telecom ledger reclassifying operating line costs into network CapEx via round-dollar, post-SoftClose, weekend, self-approved journal entries with thin descriptions."
            }
            Self::GhostPayroll => {
                "Payroll ledger containing duplicate net-pay disbursements on the same and adjacent pay dates, missing check sequence numbers, and weekend self-approved off-cycle payouts."
            }
        }
    }

    /// Parse a scenario name by canonical slug or short alias.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "clean-retailer" | "clean_retailer" | "retail" => Some(Self::CleanRetailer),
            "channel-stuffing" | "channel_stuffing" | "stuffing" => Some(Self::ChannelStuffing),
            "kiting-bank" | "kiting_bank" | "bank" | "kiting" => Some(Self::KitingBank),
            "ponzi" => Some(Self::Ponzi),
            "shell-network" | "shell_network" | "shell" => Some(Self::ShellNetwork),
            "worldcom-capitalization" | "worldcom_capitalization" | "worldcom" => {
                Some(Self::WorldComCapitalization)
            }
            "ghost-payroll" | "ghost_payroll" | "payroll" => Some(Self::GhostPayroll),
            _ => None,
        }
    }
}

impl fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Configuration for generating a synthetic scenario corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenConfig {
    pub scenario: ScenarioKind,
    pub seed: u64,
    /// Volume multiplier (`>= 1`). `scale = 1` generates 18 baseline entries
    /// (36 legs) plus the scenario's planted entries; higher scales multiply
    /// the baseline population while preserving every planted fact.
    pub scale: usize,
}

impl GenConfig {
    #[must_use]
    pub fn new(scenario: ScenarioKind, seed: u64) -> Self {
        Self {
            scenario,
            seed,
            scale: 1,
        }
    }

    #[must_use]
    pub fn with_scale(mut self, scale: usize) -> Self {
        self.scale = scale.max(1);
        self
    }
}

/// One chart-of-accounts leaf specification in a generated book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenAccount {
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub normal_balance: u8,
}

impl GenAccount {
    #[must_use]
    pub fn new(code: &str, name: &str, account_type: AccountType, normal_balance: u8) -> Self {
        Self {
            code: code.to_string(),
            name: name.to_string(),
            account_type: account_type.0,
            normal_balance,
        }
    }
}

/// One labeled party in the scenario's party directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenParty {
    pub code: String,
    pub name: String,
    pub role: String,
    pub shared_bank_tag: Option<String>,
    pub shared_address_tag: Option<String>,
    pub planted_anomaly: bool,
}

/// One leg of a generated entry (in the book's base currency, USD at scale 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenLeg {
    pub account_code: String,
    pub side: Side,
    pub cents: i128,
}

impl GenLeg {
    #[must_use]
    pub fn debit(account_code: &str, cents: i128) -> Self {
        Self {
            account_code: account_code.to_string(),
            side: Side::Debit,
            cents,
        }
    }

    #[must_use]
    pub fn credit(account_code: &str, cents: i128) -> Self {
        Self {
            account_code: account_code.to_string(),
            side: Side::Credit,
            cents,
        }
    }
}

/// One period-lifecycle transition in the generated history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenTransition {
    pub period_code: String,
    pub transition: PeriodTransition,
    pub effective_date: DateDay,
    pub description: String,
}

/// One journal entry in the generated history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenEntry {
    /// Stable human-readable key within the scenario (e.g. `"base-0001"`, `"cs-cutoff-01"`).
    pub key: String,
    pub class: EntryClass,
    pub effective_date: DateDay,
    pub document_date: Option<DateDay>,
    pub description: String,
    pub legs: Vec<GenLeg>,
    pub external_ids: Vec<(String, String)>,
    pub party_code: Option<String>,
    /// Preparer approves their own proposal before posting (`jet.self_approved`).
    pub self_approve: bool,
    /// Independent reviewer approves the proposal before posting.
    pub review: bool,
    /// Posted after the period's `SoftClose` transition under `post_softclosed` (`jet.post_closing`).
    pub post_after_soft_close: bool,
}

impl GenEntry {
    /// Total debit cents (always equals total credit cents by construction).
    #[must_use]
    pub fn total_debit_cents(&self) -> i128 {
        self.legs
            .iter()
            .filter(|l| l.side == Side::Debit)
            .map(|l| l.cents)
            .sum()
    }

    /// Total credit cents.
    #[must_use]
    pub fn total_credit_cents(&self) -> i128 {
        self.legs
            .iter()
            .filter(|l| l.side == Side::Credit)
            .map(|l| l.cents)
            .sum()
    }
}

/// Ground-truth classification of a planted forensic fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactKind {
    CutoffStraddle,
    PostClosingTopSide,
    RoundAmountAnomaly,
    SequenceGap,
    RoundTripKiting,
    WeekendPosting,
    PonziCohortRedemption,
    SelfApprovedEntry,
    ThinDescriptionEntry,
    SubThresholdStructuring,
    DuplicateSameDay,
    DuplicateDifferentDay,
    ImproperCapitalization,
    GhostPayrollDisbursement,
}

impl FactKind {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CutoffStraddle => "cutoff_straddle",
            Self::PostClosingTopSide => "post_closing_top_side",
            Self::RoundAmountAnomaly => "round_amount_anomaly",
            Self::SequenceGap => "sequence_gap",
            Self::RoundTripKiting => "round_trip_kiting",
            Self::WeekendPosting => "weekend_posting",
            Self::PonziCohortRedemption => "ponzi_cohort_redemption",
            Self::SelfApprovedEntry => "self_approved_entry",
            Self::ThinDescriptionEntry => "thin_description_entry",
            Self::SubThresholdStructuring => "sub_threshold_structuring",
            Self::DuplicateSameDay => "duplicate_same_day",
            Self::DuplicateDifferentDay => "duplicate_different_day",
            Self::ImproperCapitalization => "improper_capitalization",
            Self::GhostPayrollDisbursement => "ghost_payroll_disbursement",
        }
    }
}

/// One ground-truth planted anomaly recorded in the scenario's labels manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantedFact {
    pub fact_id: String,
    pub kind: FactKind,
    /// Registered `fa-lantern` procedure IDs expected to cite the entries in `entry_indices`.
    pub procedures: Vec<String>,
    /// 0-based indices into [`GeneratedCorpus::entries`].
    pub entry_indices: Vec<usize>,
    /// Stable keys of the cited entries (`GenEntry::key`).
    pub entry_keys: Vec<String>,
    /// Account codes involved in the planted fact.
    pub account_codes: Vec<String>,
    /// Party codes involved in the planted fact.
    pub party_codes: Vec<String>,
    /// Auditable explanation of what was planted and why.
    pub rationale: String,
}

/// Complete, deterministic output of generating one scenario corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedCorpus {
    pub scenario: ScenarioKind,
    pub seed: u64,
    pub scale: usize,
    pub book_name: String,
    pub fiscal_year: i32,
    pub snapshot_cutoff: DateDay,
    pub accounts: Vec<GenAccount>,
    pub parties: Vec<GenParty>,
    /// Transitions executed after pre-close entries and before `post_after_soft_close` entries.
    pub transitions: Vec<GenTransition>,
    pub entries: Vec<GenEntry>,
    pub labels: Vec<PlantedFact>,
}

impl GeneratedCorpus {
    /// Domain-separated BLAKE3 digest over the entire generated corpus and its labels.
    #[must_use]
    pub fn corpus_digest(&self) -> Oid {
        let mut h = Hasher::new();
        h.update(CORPUS_DIGEST_DOMAIN);
        h.update(&[self.scenario.tag()]);
        h.update(&self.seed.to_le_bytes());
        h.update(&(self.scale as u64).to_le_bytes());
        h.update(self.book_name.as_bytes());
        h.update(&self.fiscal_year.to_le_bytes());
        h.update(&self.snapshot_cutoff.0.to_le_bytes());
        h.update(&(self.accounts.len() as u64).to_le_bytes());
        for a in &self.accounts {
            h.update(a.code.as_bytes());
            h.update(&[0]);
            h.update(a.name.as_bytes());
            h.update(&[a.account_type, a.normal_balance]);
        }
        h.update(&(self.parties.len() as u64).to_le_bytes());
        for p in &self.parties {
            h.update(p.code.as_bytes());
            h.update(&[0]);
            h.update(p.name.as_bytes());
            h.update(&[0]);
            h.update(p.role.as_bytes());
            h.update(&[u8::from(p.planted_anomaly)]);
        }
        h.update(&(self.transitions.len() as u64).to_le_bytes());
        for t in &self.transitions {
            h.update(t.period_code.as_bytes());
            let tag = match t.transition {
                PeriodTransition::Open => 1u8,
                PeriodTransition::SoftClose => 2,
                PeriodTransition::Close => 3,
                PeriodTransition::Lock => 4,
                PeriodTransition::Reopen { .. } => 5,
            };
            h.update(&[tag]);
            h.update(&t.effective_date.0.to_le_bytes());
        }
        h.update(&(self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            h.update(e.key.as_bytes());
            h.update(&e.class.0.to_le_bytes());
            h.update(&e.effective_date.0.to_le_bytes());
            h.update(&e.document_date.map_or(-1i32, |d| d.0).to_le_bytes());
            h.update(e.description.as_bytes());
            h.update(&[
                u8::from(e.self_approve),
                u8::from(e.review),
                u8::from(e.post_after_soft_close),
            ]);
            h.update(&(e.legs.len() as u64).to_le_bytes());
            for l in &e.legs {
                h.update(l.account_code.as_bytes());
                h.update(&[match l.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                }]);
                h.update(&l.cents.to_le_bytes());
            }
            h.update(&(e.external_ids.len() as u64).to_le_bytes());
            for (sys, id) in &e.external_ids {
                h.update(sys.as_bytes());
                h.update(&[0]);
                h.update(id.as_bytes());
            }
        }
        h.update(&(self.labels.len() as u64).to_le_bytes());
        for f in &self.labels {
            h.update(f.fact_id.as_bytes());
            h.update(f.kind.slug().as_bytes());
            for &idx in &f.entry_indices {
                h.update(&(idx as u64).to_le_bytes());
            }
            for proc_id in &f.procedures {
                h.update(proc_id.as_bytes());
            }
        }
        Oid(h.finalize().0)
    }

    /// Expected entry indices for a specific `fa-lantern` procedure ID from the
    /// ground-truth labels.
    #[must_use]
    pub fn expected_entries_for_procedure(&self, procedure_id: &str) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for label in &self.labels {
            if label.procedures.iter().any(|p| p == procedure_id) {
                out.extend(label.entry_indices.iter().copied());
            }
        }
        out
    }

    /// Render the ground-truth labels manifest as canonical JSON.
    #[must_use]
    pub fn render_labels_json(&self) -> String {
        let digest = oid_hex(self.corpus_digest());
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!(
            "  \"scenario\": \"{}\",\n  \"title\": \"{}\",\n  \"seed\": {},\n  \"scale\": {},\n  \"corpus_digest\": \"{}\",\n  \"entry_count\": {},\n  \"party_count\": {},\n  \"planted_fact_count\": {},\n  \"labels\": [\n",
            self.scenario.slug(),
            escape_json(self.scenario.title()),
            self.seed,
            self.scale,
            digest,
            self.entries.len(),
            self.parties.len(),
            self.labels.len(),
        ));
        for (i, f) in self.labels.iter().enumerate() {
            let procs: Vec<String> = f
                .procedures
                .iter()
                .map(|p| format!("\"{}\"", escape_json(p)))
                .collect();
            let idxs: Vec<String> = f.entry_indices.iter().map(usize::to_string).collect();
            let keys: Vec<String> = f
                .entry_keys
                .iter()
                .map(|k| format!("\"{}\"", escape_json(k)))
                .collect();
            let accts: Vec<String> = f
                .account_codes
                .iter()
                .map(|a| format!("\"{}\"", escape_json(a)))
                .collect();
            let parties: Vec<String> = f
                .party_codes
                .iter()
                .map(|p| format!("\"{}\"", escape_json(p)))
                .collect();
            out.push_str(&format!(
                "    {{\"fact_id\": \"{}\", \"kind\": \"{}\", \"procedures\": [{}], \"entry_indices\": [{}], \"entry_keys\": [{}], \"account_codes\": [{}], \"party_codes\": [{}], \"rationale\": \"{}\"}}{}\n",
                escape_json(&f.fact_id),
                f.kind.slug(),
                procs.join(", "),
                idxs.join(", "),
                keys.join(", "),
                accts.join(", "),
                parties.join(", "),
                escape_json(&f.rationale),
                if i + 1 < self.labels.len() { "," } else { "" }
            ));
        }
        out.push_str("  ]\n}\n");
        out
    }

    /// Render a human-readable `README.md` documenting the book and its planted facts.
    #[must_use]
    pub fn render_readme(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# {} (`{}`)\n\n",
            self.scenario.title(),
            self.scenario.slug()
        ));
        out.push_str(&format!(
            "- **Book Name:** `{}`\n- **Seed:** `{}`\n- **Scale:** `{}`\n- **Corpus Digest:** `{}`\n- **Entries:** `{}`\n- **Parties:** `{}`\n- **Planted Facts:** `{}`\n\n",
            self.book_name,
            self.seed,
            self.scale,
            oid_hex(self.corpus_digest()),
            self.entries.len(),
            self.parties.len(),
            self.labels.len()
        ));
        out.push_str(&format!("## Overview\n\n{}\n\n", self.scenario.summary()));
        out.push_str("## Ground-Truth Planted Facts\n\n");
        if self.labels.is_empty() {
            out.push_str(
                "No fraud or control anomalies are planted in this clean baseline book.\n",
            );
        } else {
            out.push_str("| Fact ID | Kind | Target Procedures | Entry Keys | Accounts | Rationale |\n");
            out.push_str("|---|---|---|---|---|---|\n");
            for f in &self.labels {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |\n",
                    f.fact_id,
                    f.kind.slug(),
                    f.procedures.join(", "),
                    f.entry_keys.join(", "),
                    f.account_codes.join(", "),
                    f.rationale
                ));
            }
        }
        out
    }
}

/// Format a 32-byte [`Oid`] as lowercase hexadecimal.
#[must_use]
pub fn oid_hex(oid: Oid) -> String {
    let mut out = String::with_capacity(64);
    for b in oid.0 {
        use core::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn day(y: i32, m: u8, d: u8) -> DateDay {
    DateDay::from_ymd(y, m, d).expect("valid calendar date")
}

/// Safe weekday dates inside the first 25 days of Jan, Feb, Mar 2026 (never within
/// the 3-day period-end window and never on Saturday/Sunday).
const SAFE_WEEKDAYS_Q1_2026: [(u8, u8); 18] = [
    (1, 5),
    (1, 6),
    (1, 7),
    (1, 8),
    (1, 9),
    (1, 12),
    (2, 2),
    (2, 3),
    (2, 4),
    (2, 5),
    (2, 6),
    (2, 9),
    (3, 2),
    (3, 3),
    (3, 4),
    (3, 5),
    (3, 6),
    (3, 9),
];

/// An exact 18-element Benford first-digit template (`[6, 3, 2, 2, 1, 1, 1, 1, 1]`)
/// whose MAD against `BENFORD_WEIGHTS_1E9` is `0.00568 < 0.006` (Nigrini close
/// conformity at every `scale >= 1`).
const BENFORD_TEMPLATE_18: [u8; 18] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 6, 7, 8, 9];

/// Standard chart of accounts covering all seven scenarios.
#[must_use]
pub fn standard_chart() -> Vec<GenAccount> {
    vec![
        GenAccount::new("1000", "Operating Cash", AccountType::ASSET, 0),
        GenAccount::new("1010", "Concentration Bank B", AccountType::ASSET, 0),
        GenAccount::new("1020", "Investor Trust & Clearing C", AccountType::ASSET, 0),
        GenAccount::new("1030", "Intermediary Clearing A", AccountType::ASSET, 0),
        GenAccount::new("1040", "Intermediary Clearing B", AccountType::ASSET, 0),
        GenAccount::new("1050", "Payroll Clearing", AccountType::ASSET, 0),
        GenAccount::new("1200", "Accounts Receivable", AccountType::ASSET, 0),
        GenAccount::new("1300", "Merchandise Inventory", AccountType::ASSET, 0),
        GenAccount::new("1500", "Network Property & CapEx", AccountType::ASSET, 0),
        GenAccount::new("2000", "Accounts Payable", AccountType::LIABILITY, 1),
        GenAccount::new("2100", "Accrued Line Costs", AccountType::LIABILITY, 1),
        GenAccount::new("2200", "Accrued Wages Payable", AccountType::LIABILITY, 1),
        GenAccount::new("2400", "Investor Capital Cohort A", AccountType::LIABILITY, 1),
        GenAccount::new("2410", "Investor Capital Cohort B", AccountType::LIABILITY, 1),
        GenAccount::new("3000", "Contributed Capital", AccountType::EQUITY, 1),
        GenAccount::new("4000", "Merchandise & Service Revenue", AccountType::REVENUE, 1),
        GenAccount::new("4100", "Advisory & Management Revenue", AccountType::REVENUE, 1),
        GenAccount::new("5000", "Cost of Goods Sold", AccountType::EXPENSE, 0),
        GenAccount::new("6000", "Store Rent Expense", AccountType::EXPENSE, 0),
        GenAccount::new("6100", "Network Line Cost Expense", AccountType::EXPENSE, 0),
        GenAccount::new("6200", "Consulting & Advisory Expense", AccountType::EXPENSE, 0),
        GenAccount::new("6300", "Wages & Salaries Expense", AccountType::EXPENSE, 0),
        GenAccount::new("6500", "Investor Redemption Distributions", AccountType::EXPENSE, 0),
        GenAccount::new("7000", "Utilities & Operations Expense", AccountType::EXPENSE, 0),
    ]
}

/// Generate a deterministic, labeled synthetic book corpus for `config`.
#[must_use]
pub fn generate(config: GenConfig) -> GeneratedCorpus {
    let scale = config.scale.max(1);
    let mut rng = DeterministicRng::new(config.scenario.tag(), config.seed, scale);
    let mut used_amounts = BTreeSet::new();
    let accounts = standard_chart();
    let mut parties = vec![
        GenParty {
            code: "CUST-01".into(),
            name: "Northwind Retail Buyers".into(),
            role: "customer".into(),
            shared_bank_tag: None,
            shared_address_tag: None,
            planted_anomaly: false,
        },
        GenParty {
            code: "VEND-01".into(),
            name: " Pacific Wholesale Supply".trim().into(),
            role: "vendor".into(),
            shared_bank_tag: None,
            shared_address_tag: None,
            planted_anomaly: false,
        },
        GenParty {
            code: "EMP-01".into(),
            name: "Alice Rivera".into(),
            role: "employee".into(),
            shared_bank_tag: Some("BANK-ACCT-101".into()),
            shared_address_tag: Some("ADDR-101".into()),
            planted_anomaly: false,
        },
    ];

    let mut entries = Vec::new();
    let mut transitions = Vec::new();
    let mut labels = Vec::new();

    // Generate `18 * scale` clean weekday baseline entries following the exact
    // 18-slot Benford first-digit template so every scenario has realistic background
    // volume and CleanRetailer has zero false positives.
    let mut inv_seq = 1u64;
    let mut chk_seq = 1001u64;
    let expense_accounts = ["5000", "6000", "7000"];
    for batch in 0..scale {
        for (slot, &leading_digit) in BENFORD_TEMPLATE_18.iter().enumerate() {
            let (m, d_base) = SAFE_WEEKDAYS_Q1_2026[slot];
            // Offset within the safe weekday range while staying on weekdays <= day 24.
            let mut date = day(2026, m, d_base + ((batch % 2) as u8) * 7);
            while matches!(date.weekday(), Weekday::Saturday | Weekday::Sunday) {
                date = DateDay(date.0 + 1);
            }
            let cents = rng.benford_cents(leading_digit, &mut used_amounts);
            let idx = entries.len() + 1;
            let is_sale = slot % 2 == 0;
            let (debit_acct, credit_acct, ext_sys, ext_id, party_code, desc) = if is_sale {
                let id = format!("INV-{inv_seq:04}");
                inv_seq += 1;
                (
                    "1200",
                    "4000",
                    "ar_invoice",
                    id,
                    "CUST-01",
                    format!("Retail merchandise invoice #{inv_seq}"),
                )
            } else {
                let id = format!("CHK-{chk_seq:04}");
                chk_seq += 1;
                let exp = expense_accounts[slot % expense_accounts.len()];
                (
                    exp,
                    "1000",
                    "ap_check",
                    id,
                    "VEND-01",
                    format!("Operating supplier payment #{chk_seq}"),
                )
            };
            entries.push(GenEntry {
                key: format!("base-{idx:04}"),
                class: EntryClass::ORIGINAL,
                effective_date: date,
                document_date: Some(date),
                description: desc,
                legs: vec![
                    GenLeg::debit(debit_acct, cents),
                    GenLeg::credit(credit_acct, cents),
                ],
                external_ids: vec![(ext_sys.into(), ext_id)],
                party_code: Some(party_code.into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
        }
    }

    // Plant scenario-specific forensic facts and ground-truth labels.
    match config.scenario {
        ScenarioKind::CleanRetailer => {
            // Append 22 additional clean weekday entries per scale batch so the 40-entry
            // CleanRetailer baseline has exact first-digit counts `[12, 7, 5, 4, 3, 3, 2, 2, 2]`
            // (Nigrini MAD = 0.00343 <= 0.006 close conformity).
            const CLEAN_RETAILER_EXTRA_22: [u8; 22] = [
                1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 8, 9,
            ];
            for batch in 0..scale {
                for (slot, &leading_digit) in CLEAN_RETAILER_EXTRA_22.iter().enumerate() {
                    let (m, d_base) = SAFE_WEEKDAYS_Q1_2026[slot % SAFE_WEEKDAYS_Q1_2026.len()];
                    let mut date = day(2026, m, d_base + ((batch % 2) as u8) * 7);
                    while matches!(date.weekday(), Weekday::Saturday | Weekday::Sunday) {
                        date = DateDay(date.0 + 1);
                    }
                    let cents = rng.benford_cents(leading_digit, &mut used_amounts);
                    let idx = entries.len() + 1;
                    let is_sale = slot % 2 == 0;
                    let (debit_acct, credit_acct, ext_sys, ext_id, party_code, desc) = if is_sale {
                        let id = format!("INV-{inv_seq:04}");
                        inv_seq += 1;
                        (
                            "1200",
                            "4000",
                            "ar_invoice",
                            id,
                            "CUST-01",
                            format!("Retail merchandise invoice #{inv_seq}"),
                        )
                    } else {
                        let id = format!("CHK-{chk_seq:04}");
                        chk_seq += 1;
                        let exp = expense_accounts[slot % expense_accounts.len()];
                        (
                            exp,
                            "1000",
                            "ap_check",
                            id,
                            "VEND-01",
                            format!("Operating supplier payment #{chk_seq}"),
                        )
                    };
                    entries.push(GenEntry {
                        key: format!("base-{idx:04}"),
                        class: EntryClass::ORIGINAL,
                        effective_date: date,
                        document_date: Some(date),
                        description: desc,
                        legs: vec![
                            GenLeg::debit(debit_acct, cents),
                            GenLeg::credit(credit_acct, cents),
                        ],
                        external_ids: vec![(ext_sys.into(), ext_id)],
                        party_code: Some(party_code.into()),
                        self_approve: false,
                        review: true,
                        post_after_soft_close: false,
                    });
                }
            }
            // Soft-close FY2026-P01 after all clean entries are recorded so
            // `jet.post_closing` sees a closed period with zero post-close entries.
            transitions.push(GenTransition {
                period_code: "FY2026-P01".into(),
                transition: PeriodTransition::SoftClose,
                effective_date: day(2026, 2, 1),
                description: "Routine period-01 soft close after all January postings".into(),
            });
        }
        ScenarioKind::ChannelStuffing => {
            parties.push(GenParty {
                code: "CUST-STUFF-01".into(),
                name: "Distributor Horizon LLC (Bill-and-Hold)".into(),
                role: "customer".into(),
                shared_bank_tag: None,
                shared_address_tag: None,
                planted_anomaly: true,
            });
            transitions.push(GenTransition {
                period_code: "FY2026-P01".into(),
                transition: PeriodTransition::SoftClose,
                effective_date: day(2026, 2, 1),
                description: "Soft-close FY2026-P01 prior to top-side channel-stuffing adjustment"
                    .into(),
            });

            // 1. Cutoff straddle + period-end timing + round amount: February shipment
            //    back-dated to January 30, 2026 (Friday, 1 day before period end) in a
            //    round $25,000.00 amount, skipping invoice number `inv_seq` (gap of 1).
            inv_seq += 1; // Omit one invoice number to create a deterministic sequence gap!
            let cutoff_idx = entries.len();
            let cutoff_key = "cs-cutoff-straddle-01".to_string();
            entries.push(GenEntry {
                key: cutoff_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 1, 30),
                document_date: Some(day(2026, 2, 3)),
                description: "Quarter-end distributor pull-in shipment".into(),
                legs: vec![
                    GenLeg::debit("1200", 2_500_000),
                    GenLeg::credit("4000", 2_500_000),
                ],
                external_ids: vec![("ar_invoice".into(), format!("INV-{inv_seq:04}"))],
                party_code: Some("CUST-STUFF-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let prev_inv_idx = entries
                .iter()
                .rposition(|e| {
                    e.key != cutoff_key
                        && e.external_ids.iter().any(|(s, _)| s == "ar_invoice")
                })
                .expect("prior invoice entry exists");
            labels.push(PlantedFact {
                fact_id: "CS-FACT-01".into(),
                kind: FactKind::CutoffStraddle,
                procedures: vec![
                    "cutoff.period_boundary".into(),
                    "jet.period_end_timing".into(),
                    "jet.round_amounts".into(),
                ],
                entry_indices: vec![cutoff_idx],
                entry_keys: vec![cutoff_key],
                account_codes: vec!["1200".into(), "4000".into()],
                party_codes: vec!["CUST-STUFF-01".into()],
                rationale: "February 3 bill-and-hold invoice back-dated to January 30 in a round $25,000.00 amount.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "CS-FACT-02".into(),
                kind: FactKind::SequenceGap,
                procedures: vec!["numbers.sequence_gaps".into()],
                entry_indices: vec![prev_inv_idx, cutoff_idx],
                entry_keys: vec![
                    entries[prev_inv_idx].key.clone(),
                    entries[cutoff_idx].key.clone(),
                ],
                account_codes: vec!["1200".into(), "4000".into()],
                party_codes: vec!["CUST-STUFF-01".into()],
                rationale: "Skipped invoice number between the last normal invoice and the back-dated channel-stuffing invoice.".into(),
            });

            // 2. Post-closing top-side round revenue entry recorded after FY2026-P01 SoftClose.
            let post_close_idx = entries.len();
            let post_close_key = "cs-post-close-topside-01".to_string();
            entries.push(GenEntry {
                key: post_close_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 1, 29),
                document_date: Some(day(2026, 1, 29)),
                description: "Top-side promotional revenue recognition accrual".into(),
                legs: vec![
                    GenLeg::debit("1200", 5_000_000),
                    GenLeg::credit("4000", 5_000_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("CUST-STUFF-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: true,
            });
            labels.push(PlantedFact {
                fact_id: "CS-FACT-03".into(),
                kind: FactKind::PostClosingTopSide,
                procedures: vec![
                    "jet.post_closing".into(),
                    "jet.period_end_timing".into(),
                    "jet.round_amounts".into(),
                ],
                entry_indices: vec![post_close_idx],
                entry_keys: vec![post_close_key],
                account_codes: vec!["1200".into(), "4000".into()],
                party_codes: vec!["CUST-STUFF-01".into()],
                rationale: "Top-side $50,000.00 revenue entry recorded into FY2026-P01 after SoftClose.".into(),
            });
        }
        ScenarioKind::KitingBank => {
            parties.push(GenParty {
                code: "BANK-KITE-01".into(),
                name: "Interbank Float Counterparty".into(),
                role: "bank".into(),
                shared_bank_tag: Some("FLOAT-RING".into()),
                shared_address_tag: None,
                planted_anomaly: true,
            });

            // 1. Round-trip kiting pair between 1000 (Operating Cash) and 1010 (Concentration Bank B)
            //    within the period-end window (Jan 29 -> Jan 30, 2026) for $45,000.00.
            let out_idx = entries.len();
            let out_key = "kb-roundtrip-out-01".to_string();
            entries.push(GenEntry {
                key: out_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 1, 29),
                document_date: Some(day(2026, 1, 29)),
                description: "Interbank concentration transfer outbound".into(),
                legs: vec![
                    GenLeg::debit("1010", 4_500_000),
                    GenLeg::credit("1000", 4_500_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("BANK-KITE-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let back_idx = entries.len();
            let back_key = "kb-roundtrip-back-01".to_string();
            entries.push(GenEntry {
                key: back_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 1, 30),
                document_date: Some(day(2026, 2, 2)), // Also a cutoff straddle!
                description: "Interbank concentration transfer return".into(),
                legs: vec![
                    GenLeg::debit("1000", 4_500_000),
                    GenLeg::credit("1010", 4_500_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("BANK-KITE-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "KB-FACT-01".into(),
                kind: FactKind::RoundTripKiting,
                procedures: vec![
                    "graph.round_trips".into(),
                    "jet.period_end_timing".into(),
                    "jet.round_amounts".into(),
                ],
                entry_indices: vec![out_idx, back_idx],
                entry_keys: vec![out_key, back_key.clone()],
                account_codes: vec!["1000".into(), "1010".into()],
                party_codes: vec!["BANK-KITE-01".into()],
                rationale: "Equal-amount $45,000.00 outbound and return transfer between asset cash accounts 1000 and 1010 within 1 day at period end.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "KB-FACT-02".into(),
                kind: FactKind::CutoffStraddle,
                procedures: vec!["cutoff.period_boundary".into()],
                entry_indices: vec![back_idx],
                entry_keys: vec![back_key],
                account_codes: vec!["1000".into(), "1010".into()],
                party_codes: vec!["BANK-KITE-01".into()],
                rationale: "Return kiting check cleared on February 2 (document date) but booked effective January 30 to conceal overdraft.".into(),
            });

            // 2. Weekend kiting leg between 1010 and 1020 on Saturday, February 14, 2026.
            let wk_idx = entries.len();
            let wk_key = "kb-weekend-float-01".to_string();
            entries.push(GenEntry {
                key: wk_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 14), // Saturday
                document_date: Some(day(2026, 2, 14)),
                description: "Weekend clearing sweep to cover float".into(),
                legs: vec![
                    GenLeg::debit("1020", 1_234_567),
                    GenLeg::credit("1010", 1_234_567),
                ],
                external_ids: Vec::new(),
                party_code: Some("BANK-KITE-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "KB-FACT-03".into(),
                kind: FactKind::WeekendPosting,
                procedures: vec!["jet.weekend".into()],
                entry_indices: vec![wk_idx],
                entry_keys: vec![wk_key],
                account_codes: vec!["1010".into(), "1020".into()],
                party_codes: vec!["BANK-KITE-01".into()],
                rationale: "Interbank float transfer dated on Saturday, February 14, 2026.".into(),
            });
        }
        ScenarioKind::Ponzi => {
            parties.push(GenParty {
                code: "INV-COHORT-A".into(),
                name: "Early Investor Cohort A LP".into(),
                role: "investor_cohort_a".into(),
                shared_bank_tag: None,
                shared_address_tag: None,
                planted_anomaly: true,
            });
            parties.push(GenParty {
                code: "INV-COHORT-B".into(),
                name: "New Investor Cohort B LP".into(),
                role: "investor_cohort_b".into(),
                shared_bank_tag: None,
                shared_address_tag: None,
                planted_anomaly: true,
            });

            // 1. Cohort-B new investor subscription inflow ($30,000.00 round) followed by
            //    self-approved, thin-description Cohort-A redemption payout ($30,000.00 round).
            let inflow_idx = entries.len();
            let inflow_key = "pz-cohort-b-inflow-01".to_string();
            entries.push(GenEntry {
                key: inflow_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 26),
                document_date: Some(day(2026, 2, 26)),
                description: "Cohort B subscription wire receipt".into(),
                legs: vec![
                    GenLeg::debit("1020", 3_000_000),
                    GenLeg::credit("2410", 3_000_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("INV-COHORT-B".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let payout_idx = entries.len();
            let payout_key = "pz-cohort-a-payout-01".to_string();
            entries.push(GenEntry {
                key: payout_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 27),
                document_date: Some(day(2026, 2, 27)),
                description: "pay".into(), // 3 chars < min_chars(4) -> thin_descriptions!
                legs: vec![
                    GenLeg::debit("6500", 3_000_000),
                    GenLeg::credit("1020", 3_000_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("INV-COHORT-A".into()),
                self_approve: true,
                review: false,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "PZ-FACT-01".into(),
                kind: FactKind::PonziCohortRedemption,
                procedures: vec![
                    "jet.round_amounts".into(),
                    "jet.period_end_timing".into(),
                ],
                entry_indices: vec![inflow_idx, payout_idx],
                entry_keys: vec![inflow_key, payout_key.clone()],
                account_codes: vec!["1020".into(), "2410".into(), "6500".into()],
                party_codes: vec!["INV-COHORT-A".into(), "INV-COHORT-B".into()],
                rationale: "New Cohort-B $30,000.00 inflow into commingled trust account 1020 immediately funds $30,000.00 Cohort-A redemption distribution at period end.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "PZ-FACT-02".into(),
                kind: FactKind::SelfApprovedEntry,
                procedures: vec![
                    "jet.self_approved".into(),
                    "jet.thin_descriptions".into(),
                ],
                entry_indices: vec![payout_idx],
                entry_keys: vec![payout_key],
                account_codes: vec!["1020".into(), "6500".into()],
                party_codes: vec!["INV-COHORT-A".into()],
                rationale: "Cohort-A distribution entry self-approved by the preparer with a 3-character description (`pay`).".into(),
            });

            // 2. Trust-to-operating cash round-trip ($15,432.10 non-round) within 2 days.
            let rt_out_idx = entries.len();
            let rt_out_key = "pz-trust-rt-out-01".to_string();
            entries.push(GenEntry {
                key: rt_out_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 3, 11),
                document_date: Some(day(2026, 3, 11)),
                description: "Temporary sweep from investor trust to operating cash".into(),
                legs: vec![
                    GenLeg::debit("1000", 1_543_210),
                    GenLeg::credit("1020", 1_543_210),
                ],
                external_ids: Vec::new(),
                party_code: Some("INV-COHORT-A".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let rt_back_idx = entries.len();
            let rt_back_key = "pz-trust-rt-back-01".to_string();
            entries.push(GenEntry {
                key: rt_back_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 3, 12),
                document_date: Some(day(2026, 3, 12)),
                description: "Return sweep from operating cash to investor trust".into(),
                legs: vec![
                    GenLeg::debit("1020", 1_543_210),
                    GenLeg::credit("1000", 1_543_210),
                ],
                external_ids: Vec::new(),
                party_code: Some("INV-COHORT-A".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "PZ-FACT-03".into(),
                kind: FactKind::RoundTripKiting,
                procedures: vec!["graph.round_trips".into()],
                entry_indices: vec![rt_out_idx, rt_back_idx],
                entry_keys: vec![rt_out_key, rt_back_key],
                account_codes: vec!["1000".into(), "1020".into()],
                party_codes: vec!["INV-COHORT-A".into()],
                rationale: "Commingled trust-to-operating cash round-trip of $15,432.10 within 1 day.".into(),
            });
        }
        ScenarioKind::ShellNetwork => {
            parties.push(GenParty {
                code: "SHELL-01".into(),
                name: "Apex Conduit Holdings LLC".into(),
                role: "shell_intermediary".into(),
                shared_bank_tag: Some("BANK-ACCT-SHELL-99".into()),
                shared_address_tag: Some("SUITE-400-WILMINGTON".into()),
                planted_anomaly: true,
            });
            parties.push(GenParty {
                code: "SHELL-02".into(),
                name: "Beacon Layering Partners Ltd".into(),
                role: "shell_intermediary".into(),
                shared_bank_tag: Some("BANK-ACCT-SHELL-99".into()),
                shared_address_tag: Some("SUITE-400-WILMINGTON".into()),
                planted_anomaly: true,
            });

            // 1. Sub-threshold structuring chain: 3 transfers from 1000 to 1030 in
            //    800_000..1_000_000 cents ($9,500.25, $9,610.50, $9,420.75) on consecutive
            //    weekdays summing to $28,531.50 >= $10,000.00 threshold.
            let mut struct_indices = Vec::new();
            let mut struct_keys = Vec::new();
            for (i, (d, cents)) in [(16u8, 950_025i128), (17, 961_050), (18, 942_075)]
                .into_iter()
                .enumerate()
            {
                let idx = entries.len();
                let key = format!("sn-structuring-0{}", i + 1);
                entries.push(GenEntry {
                    key: key.clone(),
                    class: EntryClass::ORIGINAL,
                    effective_date: day(2026, 2, d),
                    document_date: Some(day(2026, 2, d)),
                    description: format!("Intermediary clearing funding tranche #{}", i + 1),
                    legs: vec![
                        GenLeg::debit("1030", cents),
                        GenLeg::credit("1000", cents),
                    ],
                    external_ids: Vec::new(),
                    party_code: Some("SHELL-01".into()),
                    self_approve: false,
                    review: true,
                    post_after_soft_close: false,
                });
                struct_indices.push(idx);
                struct_keys.push(key);
            }
            labels.push(PlantedFact {
                fact_id: "SN-FACT-01".into(),
                kind: FactKind::SubThresholdStructuring,
                procedures: vec!["graph.structuring".into()],
                entry_indices: struct_indices,
                entry_keys: struct_keys,
                account_codes: vec!["1000".into(), "1030".into()],
                party_codes: vec!["SHELL-01".into()],
                rationale: "Three consecutive sub-$10,000 transfers ($9,500.25, $9,610.50, $9,420.75) from 1000 to shell clearing 1030 within 3 days.".into(),
            });

            // 2. Duplicate consulting payments on the same day (`duplicates.same_same_same`)
            //    and 4 days later (`duplicates.same_same_different`).
            let dup1_idx = entries.len();
            let dup1_key = "sn-dup-consult-01".to_string();
            entries.push(GenEntry {
                key: dup1_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 3, 16),
                document_date: Some(day(2026, 3, 16)),
                description: "Advisory retainer invoice disbursement A".into(),
                legs: vec![
                    GenLeg::debit("6200", 642_115),
                    GenLeg::credit("1000", 642_115),
                ],
                external_ids: Vec::new(),
                party_code: Some("SHELL-02".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let dup2_idx = entries.len();
            let dup2_key = "sn-dup-consult-02".to_string();
            entries.push(GenEntry {
                key: dup2_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 3, 16),
                document_date: Some(day(2026, 3, 16)),
                description: "Advisory retainer invoice disbursement B".into(),
                legs: vec![
                    GenLeg::debit("6200", 642_115),
                    GenLeg::credit("1000", 642_115),
                ],
                external_ids: Vec::new(),
                party_code: Some("SHELL-02".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let dup3_idx = entries.len();
            let dup3_key = "sn-dup-consult-03".to_string();
            entries.push(GenEntry {
                key: dup3_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 3, 20),
                document_date: Some(day(2026, 3, 20)),
                description: "Advisory retainer invoice repeat disbursement".into(),
                legs: vec![
                    GenLeg::debit("6200", 642_115),
                    GenLeg::credit("1000", 642_115),
                ],
                external_ids: Vec::new(),
                party_code: Some("SHELL-02".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "SN-FACT-02".into(),
                kind: FactKind::DuplicateSameDay,
                procedures: vec!["duplicates.same_same_same".into()],
                entry_indices: vec![dup1_idx, dup2_idx],
                entry_keys: vec![dup1_key.clone(), dup2_key.clone()],
                account_codes: vec!["1000".into(), "6200".into()],
                party_codes: vec!["SHELL-02".into()],
                rationale: "Two identical $6,421.15 consulting disbursements to SHELL-02 on 2026-03-16.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "SN-FACT-03".into(),
                kind: FactKind::DuplicateDifferentDay,
                procedures: vec!["duplicates.same_same_different".into()],
                entry_indices: vec![dup1_idx, dup2_idx, dup3_idx],
                entry_keys: vec![dup1_key, dup2_key, dup3_key],
                account_codes: vec!["1000".into(), "6200".into()],
                party_codes: vec!["SHELL-02".into()],
                rationale: "Repeat $6,421.15 consulting disbursement 4 days later on 2026-03-20.".into(),
            });
        }
        ScenarioKind::WorldComCapitalization => {
            parties.push(GenParty {
                code: "CARRIER-01".into(),
                name: "Interstate Fiber Carrier Corp".into(),
                role: "vendor".into(),
                shared_bank_tag: None,
                shared_address_tag: None,
                planted_anomaly: true,
            });
            transitions.push(GenTransition {
                period_code: "FY2026-P01".into(),
                transition: PeriodTransition::SoftClose,
                effective_date: day(2026, 2, 1),
                description: "Soft-close FY2026-P01 prior to top-side line-cost capitalization"
                    .into(),
            });

            // Improper capitalization entry: dated Saturday Jan 31, 2026 (period end + weekend),
            // posted after SoftClose, round $80,000.00 moving operating line costs (6100) to
            // network CapEx (1500), self-approved with thin description `"cap"`.
            let cap_idx = entries.len();
            let cap_key = "wc-capex-reclass-01".to_string();
            entries.push(GenEntry {
                key: cap_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 1, 31), // Saturday + last day of Jan!
                document_date: Some(day(2026, 2, 4)), // Cutoff straddle!
                description: "cap".into(), // 3 chars < 4 -> thin_descriptions!
                legs: vec![
                    GenLeg::debit("1500", 8_000_000),
                    GenLeg::credit("6100", 8_000_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("CARRIER-01".into()),
                self_approve: true,
                review: false,
                post_after_soft_close: true,
            });
            labels.push(PlantedFact {
                fact_id: "WC-FACT-01".into(),
                kind: FactKind::ImproperCapitalization,
                procedures: vec![
                    "jet.round_amounts".into(),
                    "jet.period_end_timing".into(),
                    "jet.post_closing".into(),
                    "jet.self_approved".into(),
                    "jet.thin_descriptions".into(),
                    "cutoff.period_boundary".into(),
                ],
                entry_indices: vec![cap_idx],
                entry_keys: vec![cap_key],
                account_codes: vec!["1500".into(), "6100".into()],
                party_codes: vec!["CARRIER-01".into()],
                rationale: "Post-SoftClose top-side $80,000.00 reclassification of operating line costs (6100) into network CapEx (1500) effective Jan 31 with Feb 4 document date, self-approval, and 3-char description (`cap`).".into(),
            });

            // Second weekend capitalization entry on Sunday Feb 22, 2026 (`jet.weekend`).
            let wk_cap_idx = entries.len();
            let wk_cap_key = "wc-weekend-capex-02".to_string();
            entries.push(GenEntry {
                key: wk_cap_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 22), // Sunday
                document_date: Some(day(2026, 2, 22)),
                description: "Sunday top-side prepaid capacity capitalization".into(),
                legs: vec![
                    GenLeg::debit("1500", 4_000_000),
                    GenLeg::credit("2100", 4_000_000),
                ],
                external_ids: Vec::new(),
                party_code: Some("CARRIER-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "WC-FACT-02".into(),
                kind: FactKind::WeekendPosting,
                procedures: vec!["jet.weekend".into(), "jet.round_amounts".into()],
                entry_indices: vec![wk_cap_idx],
                entry_keys: vec![wk_cap_key],
                account_codes: vec!["1500".into(), "2100".into()],
                party_codes: vec!["CARRIER-01".into()],
                rationale: "Sunday $40,000.00 capitalization of accrued line costs into network CapEx.".into(),
            });
        }
        ScenarioKind::GhostPayroll => {
            parties.push(GenParty {
                code: "EMP-GHOST-01".into(),
                name: "R. Phantom (Shared Deposit Account)".into(),
                role: "employee".into(),
                shared_bank_tag: Some("BANK-ACCT-101".into()),
                shared_address_tag: Some("ADDR-101".into()),
                planted_anomaly: true,
            });

            // 1. Two identical net-pay disbursements on the same payroll date (`duplicates.same_same_same`)
            //    plus a third on the next day (`duplicates.same_same_different`), with a skipped
            //    payroll check number (`PAY-2002` missing between `PAY-2001` and `PAY-2003`).
            let pay1_idx = entries.len();
            let pay1_key = "gp-payroll-run-01".to_string();
            entries.push(GenEntry {
                key: pay1_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 13),
                document_date: Some(day(2026, 2, 13)),
                description: "Biweekly payroll direct deposit — Alice Rivera".into(),
                legs: vec![
                    GenLeg::debit("6300", 384_512),
                    GenLeg::credit("1050", 384_512),
                ],
                external_ids: vec![("payroll_dd".into(), "PAY-2001".into())],
                party_code: Some("EMP-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let pay2_idx = entries.len();
            let pay2_key = "gp-payroll-ghost-same-day-02".to_string();
            entries.push(GenEntry {
                key: pay2_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 13),
                document_date: Some(day(2026, 2, 13)),
                description: "Biweekly payroll direct deposit — R. Phantom".into(),
                legs: vec![
                    GenLeg::debit("6300", 384_512),
                    GenLeg::credit("1050", 384_512),
                ],
                // Skips PAY-2002!
                external_ids: vec![("payroll_dd".into(), "PAY-2003".into())],
                party_code: Some("EMP-GHOST-01".into()),
                self_approve: false,
                review: true,
                post_after_soft_close: false,
            });
            let pay3_idx = entries.len();
            let pay3_key = "gp-payroll-ghost-offcycle-03".to_string();
            entries.push(GenEntry {
                key: pay3_key.clone(),
                class: EntryClass::ORIGINAL,
                effective_date: day(2026, 2, 15), // Sunday!
                document_date: Some(day(2026, 2, 15)),
                description: "dd".into(), // 2 chars < 4 -> thin_descriptions!
                legs: vec![
                    GenLeg::debit("6300", 384_512),
                    GenLeg::credit("1050", 384_512),
                ],
                external_ids: vec![("payroll_dd".into(), "PAY-2004".into())],
                party_code: Some("EMP-GHOST-01".into()),
                self_approve: true,
                review: false,
                post_after_soft_close: false,
            });
            labels.push(PlantedFact {
                fact_id: "GP-FACT-01".into(),
                kind: FactKind::DuplicateSameDay,
                procedures: vec!["duplicates.same_same_same".into()],
                entry_indices: vec![pay1_idx, pay2_idx],
                entry_keys: vec![pay1_key.clone(), pay2_key.clone()],
                account_codes: vec!["1050".into(), "6300".into()],
                party_codes: vec!["EMP-01".into(), "EMP-GHOST-01".into()],
                rationale: "Duplicate $3,845.12 payroll disbursement on 2026-02-13 to ghost employee sharing BANK-ACCT-101.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "GP-FACT-02".into(),
                kind: FactKind::SequenceGap,
                procedures: vec!["numbers.sequence_gaps".into()],
                entry_indices: vec![pay1_idx, pay2_idx],
                entry_keys: vec![pay1_key.clone(), pay2_key.clone()],
                account_codes: vec!["1050".into(), "6300".into()],
                party_codes: vec!["EMP-01".into(), "EMP-GHOST-01".into()],
                rationale: "Skipped payroll advice number PAY-2002 between PAY-2001 and PAY-2003.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "GP-FACT-03".into(),
                kind: FactKind::DuplicateDifferentDay,
                procedures: vec!["duplicates.same_same_different".into()],
                entry_indices: vec![pay1_idx, pay2_idx, pay3_idx],
                entry_keys: vec![pay1_key, pay2_key, pay3_key.clone()],
                account_codes: vec!["1050".into(), "6300".into()],
                party_codes: vec!["EMP-GHOST-01".into()],
                rationale: "Repeat $3,845.12 payroll disbursement 2 days later on 2026-02-15.".into(),
            });
            labels.push(PlantedFact {
                fact_id: "GP-FACT-04".into(),
                kind: FactKind::GhostPayrollDisbursement,
                procedures: vec![
                    "jet.weekend".into(),
                    "jet.self_approved".into(),
                    "jet.thin_descriptions".into(),
                ],
                entry_indices: vec![pay3_idx],
                entry_keys: vec![pay3_key],
                account_codes: vec!["1050".into(), "6300".into()],
                party_codes: vec!["EMP-GHOST-01".into()],
                rationale: "Off-cycle Sunday $3,845.12 payroll disbursement self-approved by preparer with 2-char description (`dd`).".into(),
            });
        }
    }

    GeneratedCorpus {
        scenario: config.scenario,
        seed: config.seed,
        scale,
        book_name: format!("{} (seed {})", config.scenario.title(), config.seed),
        fiscal_year: 2026,
        snapshot_cutoff: day(2026, 4, 30),
        accounts,
        parties,
        transitions,
        entries,
        labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_seven_scenarios_are_deterministic_and_balanced() {
        for scenario in ScenarioKind::ALL {
            let a = generate(GenConfig::new(scenario, 7));
            let b = generate(GenConfig::new(scenario, 7));
            assert_eq!(a, b, "{scenario}: same seed must produce identical corpus");
            assert_eq!(
                a.corpus_digest(),
                b.corpus_digest(),
                "{scenario}: corpus digest must be deterministic"
            );

            let c = generate(GenConfig::new(scenario, 8));
            assert_ne!(
                a.corpus_digest(),
                c.corpus_digest(),
                "{scenario}: distinct seeds must produce distinct digests"
            );

            for entry in &a.entries {
                assert_eq!(
                    entry.total_debit_cents(),
                    entry.total_credit_cents(),
                    "{scenario}/{}: entry must be balanced",
                    entry.key
                );
                assert!(
                    entry.total_debit_cents() > 0,
                    "{scenario}/{}: entry must have positive amount",
                    entry.key
                );
            }

            // Every label's entry indices and keys must point into `a.entries`.
            for label in &a.labels {
                assert_eq!(label.entry_indices.len(), label.entry_keys.len());
                for (&idx, key) in label.entry_indices.iter().zip(label.entry_keys.iter()) {
                    assert!(idx < a.entries.len(), "{scenario}: index {idx} out of bounds");
                    assert_eq!(&a.entries[idx].key, key);
                }
            }
        }
    }

    #[test]
    fn scale_knob_grows_baseline_monotonically_and_preserves_labels() {
        for scenario in ScenarioKind::ALL {
            let s1 = generate(GenConfig::new(scenario, 42).with_scale(1));
            let s3 = generate(GenConfig::new(scenario, 42).with_scale(3));
            let expected_delta = if scenario == ScenarioKind::CleanRetailer {
                40 * 2
            } else {
                18 * 2
            };
            assert_eq!(s3.entries.len() - s1.entries.len(), expected_delta);
            assert_eq!(s1.labels.len(), s3.labels.len());
        }
    }
}
