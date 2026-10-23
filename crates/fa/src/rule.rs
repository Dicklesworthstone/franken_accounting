//! Canon posting rules on the facade (plan §10.3, bead fa-c34). A rule is
//! compiled against the book's unit registry and evaluated over a recorded
//! REA event by [`fa_canon`], which is pure. A rule version is journaled by
//! `fa rule propose` ([`fa_journal::rule`]), addressed by its IR digest.
//!
//! A version is not activated by being proposed: `fa rule activate` plans
//! an activation from a date, two independent Human approvers approve its
//! proposal, and its commit binds the rule's name to the version from that
//! date ([`fa_journal::rule::activate_rule_version`]). No entry derives
//! from a version yet: rule-derived posting is a later slice of the bead.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::Refusal;
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome};

pub use fa_canon::{
    CanonError, CompiledRule, Dependencies, Derivation, DerivedLeg, EvalError, InputDecl,
    InputType, InputValue, Inputs, IrError, MAX_SOURCE_BYTES, evaluate,
};
pub use fa_journal::refusal::code::CANON_RULE;
pub use fa_journal::rule::{
    RULE_ACTIVATION_PLAN_DOMAIN, RuleActivated, RuleActivationPlan, RuleBinding, RuleBindings,
    RuleNameRow, RuleVersionRecorded, RuleVersionRow, RuleVersionSpec, evaluation_refusal,
    rule_refusal,
};

/// Compile `source` against this book's registered units.
pub fn compile_rule(context: &BookContext, source: &str) -> Result<CompiledRule, Refusal> {
    fa_canon::compile(source, &context.units).map_err(|error| rule_refusal(&error))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Admit `capability` to change rules before anything is observed.
    pub fn admit_rule_change(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
    ) -> Outcome<()> {
        self.query(cx, |db, book| {
            Ok(
                match fa_journal::rule::admit_rule_change(db, book, principal, capability)? {
                    Some(refusal) => Err(refusal),
                    None => Ok(()),
                },
            )
        })
    }

    /// Journal a rule version under `rule_change` authority; the kernel
    /// compiles the source itself. A retry of the key, or a source whose IR
    /// the book already holds, writes nothing.
    pub async fn propose_rule_version(
        &mut self,
        cx: &PurposeContexts,
        source: &str,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<RuleVersionRecorded> {
        let description = self.seal_text(cx, "propose rule version")?;
        Ok(fa_journal::rule::propose_rule_version(
            &mut self.db,
            cx,
            &self.context,
            source,
            principal,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// Plan activating the version `ir_digest` from `effective_from` under
    /// `capability`, with the description sealed once. Nothing is written.
    pub fn plan_rule_activation(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        ir_digest: &[u8; 32],
        effective_from: DateDay,
        key: &[u8],
    ) -> Outcome<RuleActivationPlan> {
        let description = self.seal_text(
            cx,
            &format!(
                "activate rule version {} from {}",
                fa_journal::evidence::hex(ir_digest),
                effective_from.render()
            ),
        )?;
        self.query(cx, |db, book| {
            Ok(fa_journal::rule::plan_rule_activation(
                db,
                book,
                capability,
                ir_digest,
                effective_from,
                key,
                description,
            )?)
        })
    }

    /// Commit a planned activation under `capability` and the cited
    /// `approvals` (the `rule-activate` SoD row: two independent Human
    /// approvers). The same plan committed again returns its record.
    pub async fn activate_rule_version(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        plan: RuleActivationPlan,
        approvals: Vec<fa_model::ApprovalRef>,
    ) -> Outcome<RuleActivated> {
        Ok(fa_journal::rule::activate_rule_version(
            &mut self.db,
            cx,
            &self.context,
            capability,
            plan,
            approvals,
        )
        .await?)
    }

    /// Every rule version at `known_at` (the head when `None`), under current
    /// whole-book read authority, with the prefix they were read at.
    pub fn rule_versions(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Vec<RuleVersionRow>)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((at, fa_journal::rule::rule_versions_at(db, book, at)?)))
        })
    }

    /// Every activated rule name and its bindings at `known_at`, under
    /// current whole-book read authority.
    pub fn rule_names(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Vec<RuleNameRow>)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((at, fa_journal::rule::rule_names_at(db, at)?)))
        })
    }

    /// The rule version addressed by `ir_digest` at `known_at`, if the book
    /// holds it, under current whole-book read authority.
    pub fn rule_version(
        &self,
        cx: &PurposeContexts,
        ir_digest: &[u8; 32],
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Option<RuleVersionRow>)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((
                at,
                fa_journal::rule::rule_version_at(db, book, ir_digest, at)?,
            )))
        })
    }
}
