//! The frozen symbol table (plan §4.1 "Symbols", Appendix H R-SYM).
//!
//! The substrate has no symbol catalog: the host supplies label, property-key
//! and relation ids and a `GraphSymbolResolver` for GQL text. The table lives
//! in `registries/symbols.toml`; this module is its compiled form, and the
//! `code_table_matches_registry` test is the gate that keeps the two equal in
//! both directions. Ids are additive-only: a released id is never renumbered
//! or reused.

use std::collections::BTreeMap;

use fgdb_crypto::{Digest, Hasher};
use fgdb_delta_types::{LabelId, PropertyKeyId, RelationId};
use fgdb_gql::{GraphSymbol, GraphSymbolKind, GraphSymbolResolver, ReverseSymbolCatalog};

macro_rules! symbols {
    ($modname:ident, $idty:ident, [ $( ($konst:ident, $name:literal, $id:literal) ),* $(,)? ]) => {
        pub mod $modname {
            use fgdb_delta_types::$idty;
            $( pub const $konst: $idty = $idty($id); )*
            /// Every symbol of this kind as `(name, id)`, in registry order.
            pub const ALL: &[(&str, u64)] = &[ $( ($name, $id) ),* ];
        }
    };
}

symbols!(
    label,
    LabelId,
    [
        (BOOK, "Book", 1),
        (LEGAL_ENTITY, "LegalEntity", 2),
        (ACCOUNT, "Account", 3),
        (DIMENSION, "Dimension", 4),
        (DIMENSION_VALUE, "DimensionValue", 5),
        (UNIT, "Unit", 6),
        (FISCAL_CALENDAR, "FiscalCalendar", 7),
        (PERIOD, "Period", 8),
        (ENTRY, "Entry", 9),
        (LEG, "Leg", 10),
        (REGISTER, "Register", 11),
        (PARTY, "Party", 12),
        (INSTRUMENT, "Instrument", 13),
        (EVENT, "Event", 14),
        (SUBLEDGER, "Subledger", 15),
        (DOCUMENT, "Document", 16),
        (ATTESTATION, "Attestation", 17),
        (APPROVAL, "Approval", 18),
        (PRINCIPAL, "Principal", 19),
        (EXTERNAL_ID, "ExternalId", 20),
        (RESTATEMENT_CASE, "RestatementCase", 21),
        (DRAFT_SET, "DraftSet", 22),
        (CLOSE_RUN, "CloseRun", 23),
        (FINDING, "Finding", 24),
        (CERTIFICATE, "Certificate", 25),
        (TIME_EVIDENCE, "TimeEvidence", 26),
        (LIMIT_CELL, "LimitCell", 27),
        (MIGRATION_RUN, "MigrationRun", 28),
        (STATEMENT_ISSUANCE, "StatementIssuance", 29),
        (ENGAGEMENT, "Engagement", 30),
        (ACCUMULATOR_STATE, "AccumulatorState", 31),
    ]
);

symbols!(
    property,
    PropertyKeyId,
    [
        (FA_PAYLOAD, "_fa_payload", 1),
        (FA_DIGEST, "_fa_digest", 2),
        (FA_GRAPH, "_fa_graph", 3),
        (FA_EFFECTIVE_DAY, "_fa_effective_day", 4),
        (BOOK_ID, "book_id", 5),
        (CLASS, "class", 6),
        (IDEMPOTENCY_KEY, "idempotency_key", 7),
        (CODE, "code", 8),
        (NAME, "name", 9),
        (ACCOUNT_TYPE, "account_type", 10),
        (NORMAL_BALANCE, "normal_balance", 11),
        (POSTING, "posting", 12),
        (UNIT_POLICY, "unit_policy", 13),
        (SIDE, "side", 14),
        (ACCOUNT_REF, "account_ref", 15),
        (UNIT_ID, "unit_id", 16),
        (AMOUNT, "amount", 17),
        (AMOUNT_BYTES, "amount_bytes", 18),
        (ORDINAL, "ordinal", 19),
        (STATE, "state", 20),
        (FISCAL_YEAR, "fiscal_year", 21),
        (PERIOD_START, "period_start", 22),
        (PERIOD_END, "period_end", 23),
        (PERIOD_KIND, "period_kind", 24),
        (SCALE, "scale", 25),
        (VERSION, "version", 26),
        (FA_FOLD_DIGEST, "_fa_fold_digest", 27),
        (WATERMARK, "watermark", 28),
        (DEBITS_POSTED, "debits_posted", 29),
        (CREDITS_POSTED, "credits_posted", 30),
        (ENTRY_COUNT, "entry_count", 31),
        (SYMBOLS_DIGEST, "symbols_digest", 32),
        (BASE_UNIT, "base_unit", 33),
        (CALENDAR_ID, "calendar_id", 34),
        (EFFECTIVE_PERIOD, "effective_period", 35),
        (PROPOSAL_DIGEST, "proposal_digest", 36),
        (DEBITS_PENDING, "debits_pending", 37),
        (CREDITS_PENDING, "credits_pending", 38),
        (PENDING_COUNT, "pending_count", 39),
        (DISPOSITION, "disposition", 40),
        (APPLIED, "applied", 41),
        (LOWER_BOUND, "lower_bound", 42),
        (UPPER_BOUND, "upper_bound", 43),
        (GENERATION, "generation", 44),
        (SECURITY_POLICY_EPOCH, "security_policy_epoch", 45),
        (ACCUMULATOR_HEAD, "accumulator_head", 46),
        (LIMIT_SCOPE, "limit_scope", 56),
    ]
);

symbols!(
    relation,
    RelationId,
    [
        (HAS_LEG, "HAS_LEG", 1),
        (POSTS_TO, "POSTS_TO", 2),
        (FOR, "FOR", 3),
        (IN_UNIT, "IN_UNIT", 4),
        (CHILD_OF, "CHILD_OF", 5),
        (SUPERSEDES, "SUPERSEDES", 6),
        (RESOLVES, "RESOLVES", 7),
        (DERIVED_FROM, "DERIVED_FROM", 8),
        (GENERATED_BY, "GENERATED_BY", 9),
        (EVIDENCED_BY, "EVIDENCED_BY", 10),
        (PREPARED_BY, "PREPARED_BY", 11),
        (APPROVED_BY, "APPROVED_BY", 12),
        (REVIEWED_BY, "REVIEWED_BY", 13),
        (ATTESTS, "ATTESTS", 14),
        (SETTLES, "SETTLES", 15),
        (MATCHES, "MATCHES", 16),
        (OWNS, "OWNS", 17),
        (CONTROLS, "CONTROLS", 18),
        (RELATED_TO, "RELATED_TO", 19),
        (HELD_AT, "HELD_AT", 20),
        (MIRRORS, "MIRRORS", 21),
        (INTERCOMPANY_WITH, "INTERCOMPANY_WITH", 22),
        (CITES, "CITES", 23),
        (IN_CASE, "IN_CASE", 24),
        (READ, "READ", 25),
        (REPRESENTS, "REPRESENTS", 26),
        (IN_PERIOD, "IN_PERIOD", 27),
        (IN_BOOK, "IN_BOOK", 28),
        (UNSETTLES, "UNSETTLES", 29),
    ]
);

/// The domain string of the table digest a book journals at creation.
pub const SYMBOLS_DIGEST_DOMAIN: &[u8] = b"fa:symbols:v1";

/// The compiled table, resolvable by name in both directions.
#[derive(Clone, Debug, Default)]
pub struct SymbolTable {
    labels: BTreeMap<String, u64>,
    properties: BTreeMap<String, u64>,
    relations: BTreeMap<String, u64>,
}

impl SymbolTable {
    #[must_use]
    pub fn compiled() -> Self {
        let collect =
            |all: &[(&str, u64)]| all.iter().map(|(n, i)| ((*n).to_string(), *i)).collect();
        Self {
            labels: collect(label::ALL),
            properties: collect(property::ALL),
            relations: collect(relation::ALL),
        }
    }

    #[must_use]
    pub fn label(&self, name: &str) -> Option<LabelId> {
        self.labels.get(name).map(|i| LabelId(*i))
    }

    #[must_use]
    pub fn property(&self, name: &str) -> Option<PropertyKeyId> {
        self.properties.get(name).map(|i| PropertyKeyId(*i))
    }

    #[must_use]
    pub fn relation(&self, name: &str) -> Option<RelationId> {
        self.relations.get(name).map(|i| RelationId(*i))
    }

    /// The same canonical rendering `fa_registry::Symbols::canonical_bytes`
    /// produces, so the registry and the binary digest identically.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        for (section, map) in [
            ("label", &self.labels),
            ("property", &self.properties),
            ("relation", &self.relations),
        ] {
            for (name, id) in map {
                out.push_str(section);
                out.push(':');
                out.push_str(name);
                out.push('=');
                out.push_str(&id.to_string());
                out.push('\n');
            }
        }
        out.into_bytes()
    }

    /// `BLAKE3("fa:symbols:v1" ‖ canonical_bytes)` — journaled into the book
    /// at creation; `fa doctor` fails when the binary's and the book's differ.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut h = Hasher::new();
        h.update(SYMBOLS_DIGEST_DOMAIN);
        h.update(&self.canonical_bytes());
        h.finalize()
    }
}

impl GraphSymbolResolver for SymbolTable {
    fn resolve_symbol(&mut self, kind: GraphSymbolKind, name: &str) -> Option<GraphSymbol> {
        match kind {
            GraphSymbolKind::Relation => self.relation(name).map(GraphSymbol::Relation),
            GraphSymbolKind::Label => self.label(name).map(GraphSymbol::Label),
            GraphSymbolKind::Property => self.property(name).map(GraphSymbol::Property),
        }
    }

    fn reverse_catalog(&self) -> Option<ReverseSymbolCatalog> {
        let mut cat = ReverseSymbolCatalog::new();
        for (name, id) in &self.labels {
            cat.labels.insert(LabelId(*id), name.clone());
        }
        for (name, id) in &self.relations {
            cat.relations.insert(RelationId(*id), name.clone());
        }
        Some(cat)
    }

    fn reverse_label(&self, id: LabelId) -> Option<String> {
        self.labels
            .iter()
            .find(|(_, i)| **i == id.0)
            .map(|(n, _)| n.clone())
    }

    fn reverse_relation(&self, id: RelationId) -> Option<String> {
        self.relations
            .iter()
            .find(|(_, i)| **i == id.0)
            .map(|(n, _)| n.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry gate: `registries/symbols.toml` and this module agree in
    /// both directions, so neither can drift without failing CI.
    #[test]
    fn code_table_matches_registry() {
        let reg = fa_registry::Symbols::embedded().expect("symbols.toml loads");
        let t = SymbolTable::compiled();
        assert_eq!(t.labels, reg.labels, "labels");
        assert_eq!(t.properties, reg.properties, "properties");
        assert_eq!(t.relations, reg.relations, "relations");
        assert_eq!(t.canonical_bytes(), reg.canonical_bytes());
        // No id is shared inside a section (the registry refuses duplicates;
        // the constants must too).
        for all in [label::ALL, property::ALL, relation::ALL] {
            let mut ids: Vec<u64> = all.iter().map(|(_, i)| *i).collect();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), all.len());
        }
    }

    #[test]
    fn resolver_answers_by_kind_and_never_across_kinds() {
        let mut t = SymbolTable::compiled();
        assert_eq!(
            t.resolve_symbol(GraphSymbolKind::Label, "Entry"),
            Some(GraphSymbol::Label(label::ENTRY))
        );
        assert_eq!(
            t.resolve_symbol(GraphSymbolKind::Relation, "POSTS_TO"),
            Some(GraphSymbol::Relation(relation::POSTS_TO))
        );
        assert_eq!(
            t.resolve_symbol(GraphSymbolKind::Property, "_fa_payload"),
            Some(GraphSymbol::Property(property::FA_PAYLOAD))
        );
        assert_eq!(t.resolve_symbol(GraphSymbolKind::Relation, "Entry"), None);
        assert_eq!(t.resolve_symbol(GraphSymbolKind::Label, "no_such"), None);
        assert_eq!(t.reverse_label(label::LEG).as_deref(), Some("Leg"));
        assert_eq!(
            t.reverse_relation(relation::HAS_LEG).as_deref(),
            Some("HAS_LEG")
        );
        let cat = t.reverse_catalog().unwrap();
        assert_eq!(cat.labels.len(), label::ALL.len());
        assert_eq!(cat.relations.len(), relation::ALL.len());
    }

    #[test]
    fn digest_is_stable_across_instances() {
        assert_eq!(
            SymbolTable::compiled().digest(),
            SymbolTable::compiled().digest()
        );
    }
}
