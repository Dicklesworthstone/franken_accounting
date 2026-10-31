//! Size bounds every decoder enforces before allocating (plan Appendix A
//! "per-kind maximum sizes"; `registries/limits.toml` is the registry and the
//! `code_limits_match_registry` test keeps the two equal).

/// Hard bound on one `fa:entry:v1` payload; the substrate's scalar bound
/// (64 MiB) is the outer wall.
pub const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum nonnegative gross column of an account/unit stock register.
pub const MAX_REGISTER_MANTISSA: i128 = i128::MAX;
/// One document-commit Merkle leaf. Object storage uses one leaf per row.
/// 4 KiB plus the fixed three-property envelope fits the 16 KiB substrate row.
pub const OBJECT_CHUNK_BYTES: usize = 4096;
pub const MAX_LEGS_PER_ENTRY: usize = 4096;
pub const MAX_DESCRIPTION_BYTES: usize = 1024;
pub const MAX_MEMO_BYTES: usize = 512;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 64;
pub const MAX_SYSTEM_BYTES: usize = 64;
pub const MAX_EXTERNAL_ID_BYTES: usize = 256;
pub const MAX_EXTERNAL_IDS: usize = 256;
pub const MAX_TAG_KEY_BYTES: usize = 64;
pub const MAX_TAG_TEXT_BYTES: usize = 256;
pub const MAX_TAG_BYTES_VALUE: usize = 1024;
pub const MAX_TAGS: usize = 32;
pub const MAX_TAGS_BYTES: usize = 4096;
pub const MAX_PERIOD_REF_BYTES: usize = 32;
pub const MAX_EVIDENCE_PER_ENTRY: usize = 1024;
pub const MAX_SUPERSESSION_PER_ENTRY: usize = 1024;
pub const MAX_SETTLES_PER_LEG: usize = 1024;
pub const MAX_DIMENSIONS_PER_LEG: usize = 64;
pub const MAX_RATE_DOCS: usize = 64;
pub const MAX_APPROVALS: usize = 256;
pub const MAX_PROOF_REFS: usize = 256;
pub const MAX_FIELD_DIGESTS: usize = 4096;
pub const MAX_SCHEMA_CHANGE_BYTES: usize = 1024 * 1024;
/// Additive-minor extension entries per entry, and bytes per entry.
pub const MAX_EXTENSIONS: usize = 64;
pub const MAX_EXTENSION_BYTES: usize = 64 * 1024;
/// Entries one batch commits in one transaction; an expiry-sweep batch is
/// bounded by it (plan §5.4).
pub const MAX_BATCH_ENTRIES: usize = 8190;
/// Maximum canonical `LogicalDeltaTemplate` byte size of one substrate
/// transaction (`fgdb-chronicle` V1 capsule ceiling `56,403 * 256 = 14,439,168`
/// minus the 16-byte `XChaCha20Poly1305V1` tag at pinned rev `b323bd1`; fa-gbkc).
pub const MAX_BATCH_TEMPLATE_BYTES: usize = 56_403 * 256 - 16;
/// Text fields of an intake source (connector name and version, message id,
/// scanning device).
pub const MAX_INTAKE_TEXT_BYTES: usize = 256;
/// Documents in one import run (one transaction).
pub const MAX_IMPORT_DOCUMENTS: usize = 1024;
/// Subjects one legal hold pins (plan §8.5).
pub const MAX_LEGAL_HOLD_SUBJECTS: usize = 1024;
/// Legal holds active on one subject at once.
pub const MAX_ACTIVE_LEGAL_HOLDS: usize = 1024;
/// Upper bound on `TimeTick.observed_utc_ns` (`i64::MAX`, ~2262-04-11 UTC,
/// leaving headroom below `u64::MAX` for timeout and skew arithmetic).
pub const MAX_TICK_UTC_NS: u64 = 9_223_372_036_854_775_807;
/// Maximum forward step from the last corroborated tick (`366` days in ns)
/// before a tick without an in-process monotonic bracket is recorded
/// `monotonic_ok = false` (fa-psz).
pub const MAX_CLOCK_SKEW_NS: u64 = 31_622_400_000_000_000;
/// Concurrent `fad` client connections served at once (fa-een).
pub const MAX_DAEMON_CONNECTIONS: usize = 64;

/// Journaled issuances in a capability's authority chain, excluding its
/// embedded/launch root. Every ancestor is checked; truncation never admits.
pub const MAX_ISSUANCE_LINEAGE: usize = 16;

/// Maximum retained predecessor links verified for one bank statement chain.
/// An oversized chain refuses; a truncated chain never establishes continuity.
pub const MAX_BANK_PREDECESSOR_DEPTH: usize = 4096;

/// Canonical native-period checkpoint body, including both amount columns and
/// unresolved hold digests. Chunking preserves the substrate's row bound;
/// admission of the complete maintenance transaction still belongs to FGDB.
pub const MAX_REGISTER_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
/// Distinct account/unit/period keys across a checkpoint's posted and pending
/// columns. The byte bound is enforced independently before allocation.
pub const MAX_REGISTER_CHECKPOINT_CELLS: usize = 100_000;
/// One complete canonical company statement definition, before chunk storage.
pub const MAX_STATEMENT_DEFINITION_BYTES: usize = 64 * 1024;
/// Definition plus sealed description, caller key and fixed activation framing.
pub const MAX_STATEMENT_DEFINITION_PLAN_BYTES: usize =
    MAX_STATEMENT_DEFINITION_BYTES + MAX_DESCRIPTION_BYTES + MAX_IDEMPOTENCY_KEY_BYTES + 256;
/// Earnings and reserve buckets split across ownership links for one group
/// report, including both stock and period activity attribution. Inherited and
/// zero-cancelled buckets count; an exhausted budget refuses the entire report.
pub const MAX_CONSOLIDATION_NCI_ATTRIBUTION_CELLS: usize = 2_000_000;

/// Every limit as `(name, value)`, in registry order.
pub const ALL: &[(&str, u64)] = &[
    ("max_entry_bytes", MAX_ENTRY_BYTES as u64),
    ("object_chunk_bytes", OBJECT_CHUNK_BYTES as u64),
    ("max_legs_per_entry", MAX_LEGS_PER_ENTRY as u64),
    ("max_description_bytes", MAX_DESCRIPTION_BYTES as u64),
    ("max_memo_bytes", MAX_MEMO_BYTES as u64),
    (
        "max_idempotency_key_bytes",
        MAX_IDEMPOTENCY_KEY_BYTES as u64,
    ),
    ("max_system_bytes", MAX_SYSTEM_BYTES as u64),
    ("max_external_id_bytes", MAX_EXTERNAL_ID_BYTES as u64),
    ("max_external_ids", MAX_EXTERNAL_IDS as u64),
    ("max_tag_key_bytes", MAX_TAG_KEY_BYTES as u64),
    ("max_tag_text_bytes", MAX_TAG_TEXT_BYTES as u64),
    ("max_tag_bytes_value", MAX_TAG_BYTES_VALUE as u64),
    ("max_tags", MAX_TAGS as u64),
    ("max_tags_bytes", MAX_TAGS_BYTES as u64),
    ("max_period_ref_bytes", MAX_PERIOD_REF_BYTES as u64),
    ("max_evidence_per_entry", MAX_EVIDENCE_PER_ENTRY as u64),
    (
        "max_supersession_per_entry",
        MAX_SUPERSESSION_PER_ENTRY as u64,
    ),
    ("max_settles_per_leg", MAX_SETTLES_PER_LEG as u64),
    ("max_dimensions_per_leg", MAX_DIMENSIONS_PER_LEG as u64),
    ("max_rate_docs", MAX_RATE_DOCS as u64),
    ("max_approvals", MAX_APPROVALS as u64),
    ("max_proof_refs", MAX_PROOF_REFS as u64),
    ("max_field_digests", MAX_FIELD_DIGESTS as u64),
    ("max_schema_change_bytes", MAX_SCHEMA_CHANGE_BYTES as u64),
    ("max_extensions", MAX_EXTENSIONS as u64),
    ("max_extension_bytes", MAX_EXTENSION_BYTES as u64),
    ("max_batch_entries", MAX_BATCH_ENTRIES as u64),
    ("max_batch_template_bytes", MAX_BATCH_TEMPLATE_BYTES as u64),
    ("max_intake_text_bytes", MAX_INTAKE_TEXT_BYTES as u64),
    ("max_import_documents", MAX_IMPORT_DOCUMENTS as u64),
    ("max_legal_hold_subjects", MAX_LEGAL_HOLD_SUBJECTS as u64),
    ("max_active_legal_holds", MAX_ACTIVE_LEGAL_HOLDS as u64),
    ("max_tick_utc_ns", MAX_TICK_UTC_NS),
    ("max_clock_skew_ns", MAX_CLOCK_SKEW_NS),
    ("max_daemon_connections", MAX_DAEMON_CONNECTIONS as u64),
    ("max_issuance_lineage", MAX_ISSUANCE_LINEAGE as u64),
    (
        "max_bank_predecessor_depth",
        MAX_BANK_PREDECESSOR_DEPTH as u64,
    ),
    (
        "max_register_checkpoint_bytes",
        MAX_REGISTER_CHECKPOINT_BYTES as u64,
    ),
    (
        "max_register_checkpoint_cells",
        MAX_REGISTER_CHECKPOINT_CELLS as u64,
    ),
    (
        "max_statement_definition_bytes",
        MAX_STATEMENT_DEFINITION_BYTES as u64,
    ),
    (
        "max_statement_definition_plan_bytes",
        MAX_STATEMENT_DEFINITION_PLAN_BYTES as u64,
    ),
    (
        "max_consolidation_nci_attribution_cells",
        MAX_CONSOLIDATION_NCI_ATTRIBUTION_CELLS as u64,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_limits_match_registry() {
        assert_eq!(
            MAX_REGISTER_MANTISSA,
            fa_registry::register_capacity_embedded().expect("registered capacity")
        );
        let reg = fa_registry::limits_embedded().expect("limits.toml loads");
        let code: std::collections::BTreeMap<String, u64> =
            ALL.iter().map(|(n, v)| ((*n).to_string(), *v)).collect();
        assert_eq!(code.len(), ALL.len(), "duplicate limit name");
        assert_eq!(code, reg);
    }
}
