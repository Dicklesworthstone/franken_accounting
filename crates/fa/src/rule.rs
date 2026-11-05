//! Canon posting rules on the facade (plan §10.3, bead fa-c34). A rule is
//! compiled against the book's unit registry and evaluated over a recorded
//! REA event by [`fa_canon`], which is pure. A rule version is journaled by
//! `fa rule propose` ([`fa_journal::rule`]), addressed by its IR digest.
//!
//! A version is not activated by being proposed: `fa rule activate` plans
//! an activation from a date, two independent Human approvers approve its
//! proposal, and its commit binds the rule's name to the version from that
//! date ([`fa_journal::rule::activate_rule_version`]). A derivation can be
//! prepared for ordinary posting review ([`AsyncBook::prepare_rule_entry`])
//! or posted immediately ([`AsyncBook::derive_rule_entry`]). The kernel
//! re-runs the version in force on the entry's date over the event and its
//! recorded inputs inside the commit, and posts only what it derives
//! (FA-INV-05 `rule-reproduction`).

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::Refusal;
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome};

pub use fa_canon::{
    AuthorityError, AuthorityGrant, CANON_INPUTS_DOMAIN, CanonError, CompiledRule, Dependencies,
    Derivation, DerivedLeg, EvalError, InputDecl, InputType, InputValue, Inputs, IrError,
    MAX_SOURCE_BYTES, Produces, RuleAuthority, decode_inputs, encode_inputs, evaluate,
    validate_authority,
};
pub use fa_journal::refusal::code::CANON_RULE;
pub use fa_journal::rule::{
    RULE_ACTIVATION_PLAN_DOMAIN, RuleActivated, RuleActivationPlan, RuleBinding, RuleBindings,
    RuleDerivation, RuleNameRow, RuleVersionRecorded, RuleVersionRow, RuleVersionSpec,
    derived_legs, evaluation_refusal, rule_derived_proposal, rule_refusal,
};

/// Compile `source` against this book's registered units.
pub fn compile_rule(context: &BookContext, source: &str) -> Result<CompiledRule, Refusal> {
    fa_canon::compile(source, &context.units).map_err(|error| rule_refusal(&error))
}

/// Display metadata for one member of a prepared automatic derivation.
/// The native batch carries and independently verifies the rule identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleBatchMember {
    pub name: String,
    pub ir_digest: [u8; 32],
}

/// Every applicable input-free rule over one recorded event, prepared at
/// one admitted book prefix. No entry has been published. Pass `batch` to
/// native batch planning or posting; the kernel rechecks complete selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRuleBatch {
    pub event_code: String,
    pub rules: Vec<RuleBatchMember>,
    pub batch: fa_intents::PostBatch,
}

/// Stable member identity shared by explicit and automatic derivation.
/// Preserve the existing CLI v1 domain and 64-byte hex keys so adopting
/// atomic derivation cannot duplicate earlier separately recorded entries.
pub fn default_derivation_key(
    rule: &CompiledRule,
    event: VId,
    inputs: &Inputs,
) -> Result<String, EvalError> {
    let encoded = encode_inputs(rule, inputs)?;
    let inputs_digest = fa_model::domain_digest(CANON_INPUTS_DOMAIN, &[&encoded]);
    Ok(fa_journal::evidence::hex(&fa_model::domain_digest(
        b"fa-cli:rule-derive-key:v1",
        &[&rule.ir_digest(), &event.0.to_le_bytes(), &inputs_digest],
    )))
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

    /// Prepare the exact entry the version `ir_digest` derives from the
    /// recorded `event` and `inputs`, under whole-book read authority.
    /// The sealed intent retains the rule's class, event evidence and inputs;
    /// nothing is journaled. Ordinary planning and commit independently check
    /// current posting authority, activation and reproduction of the rule.
    pub fn prepare_rule_entry(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        ir_digest: &[u8; 32],
        event: VId,
        inputs: &Inputs,
        key: &[u8],
    ) -> Outcome<fa_intents::PostIntent> {
        let built = self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, None)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let Some(version) = fa_journal::rule::rule_version_at(db, book, ir_digest, at)? else {
                return Ok(Err(fa_journal::rule::unknown_version(ir_digest)));
            };
            Ok(Ok(version))
        })?;
        let version = match built {
            Ok(version) => version,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(event_row) = self.read_event(cx, event, None)? else {
            return Ok(Err(fa_journal::refusal::Refusal::new(
                fa_journal::refusal::code::STRUCTURE,
                fa_journal::refusal::exit::USAGE,
                format!("no event {:032x} in this book", event.0),
                "plan §4.1 Event",
                "fa event list names the recorded events",
            )));
        };
        self.prepare_selected_rule_entry(cx, capability, &version.rule, &event_row, inputs, key)
    }

    /// Prepare all matching active rules as one atomic request. Matching
    /// rules that require explicit inputs refuse the whole request; nothing
    /// is skipped or published. The native selector is shared with batch
    /// verification, so a later activation cannot silently omit a member.
    pub fn prepare_rule_batch(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        event: VId,
    ) -> Outcome<PreparedRuleBatch> {
        let selected = self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, None)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(fa_journal::rule::automatic_rules_at(
                db, book, capability, event, at,
            )?)
        })?;
        let selected = match selected {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let inputs = Inputs::new();
        let mut members = Vec::with_capacity(selected.versions.len());
        let mut rules = Vec::with_capacity(selected.versions.len());
        let mut key_material = Vec::new();
        for version in &selected.versions {
            let rule = &version.rule;
            let key = match default_derivation_key(rule, selected.event.vid, &inputs) {
                Ok(key) => key,
                Err(error) => {
                    return Ok(Err(evaluation_refusal(
                        rule,
                        &selected.event.spec.code,
                        &error,
                    )));
                }
            };
            let intent = match self.prepare_selected_rule_entry(
                cx,
                capability,
                rule,
                &selected.event,
                &inputs,
                key.as_bytes(),
            )? {
                Ok(intent) => intent,
                Err(refusal) => return Ok(Err(refusal)),
            };
            // Each component has a fixed width: a 32-byte IR digest and
            // the preserved 64-byte member key. Sealing salts and the
            // observation sequence never change the logical request key.
            key_material.extend_from_slice(&rule.ir_digest());
            key_material.extend_from_slice(key.as_bytes());
            rules.push(RuleBatchMember {
                name: rule.name().to_string(),
                ir_digest: rule.ir_digest(),
            });
            members.push(intent);
        }
        let key = fa_journal::evidence::hex(&fa_model::domain_digest(
            b"fa:automatic-rule-batch-key:v1",
            &[&selected.event.vid.0.to_le_bytes(), &key_material],
        ));
        let batch =
            fa_intents::PostBatch::automatic_rules(selected.event.vid, key.into_bytes(), members)
                .map_err(|error| {
                fa_journal::KernelError::Corrupt(format!("automatic rule batch: {error}"))
            })?;
        Ok(Ok(PreparedRuleBatch {
            event_code: selected.event.spec.code,
            rules,
            batch,
        }))
    }

    fn prepare_selected_rule_entry(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        rule: &CompiledRule,
        event_row: &fa_journal::rea::EventRow,
        inputs: &Inputs,
        key: &[u8],
    ) -> Outcome<fa_intents::PostIntent> {
        let derived = fa_canon::encode_inputs(rule, inputs)
            .and_then(|bytes| Ok((bytes, fa_canon::evaluate(rule, &event_row.spec, inputs)?)));
        let (inputs_bytes, derivation) = match derived {
            Ok(derived) => derived,
            Err(error) => {
                return Ok(Err(evaluation_refusal(rule, &event_row.spec.code, &error)));
            }
        };
        let description = self.seal_text(
            cx,
            &format!(
                "rule {} v{} over event {}",
                rule.name(),
                rule.version(),
                event_row.spec.code
            ),
        )?;
        let proposal = match fa_journal::rule::rule_derived_proposal(
            &self.context,
            &fa_journal::rule::RuleDerivation {
                rule,
                event: event_row.vid,
                inputs: &inputs_bytes,
                derivation: &derivation,
                evidence: &event_row.spec.evidence,
            },
            capability.holder(),
            key,
            description,
        ) {
            Ok(proposal) => proposal,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let intent =
            fa_intents::PostIntent::rule_derived(proposal, Vec::new()).map_err(|error| {
                fa_journal::KernelError::Corrupt(format!("rule-derived posting intent: {error}"))
            })?;
        Ok(Ok(intent))
    }

    /// Derive and post the rule's entry over a recorded event, under
    /// `capability` (whole-book read, then post). Preparation is shared with
    /// the review path; the kernel re-runs the derivation in the commit and
    /// refuses a version not in force on the entry's date.
    pub async fn derive_rule_entry(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        ir_digest: &[u8; 32],
        event: VId,
        inputs: &Inputs,
        key: &[u8],
    ) -> Outcome<fa_journal::Posted> {
        let intent = match self.prepare_rule_entry(cx, capability, ir_digest, event, inputs, key)? {
            Ok(intent) => intent,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.post(
            cx,
            fa_journal::PostRequest {
                proposal: intent.proposal().clone(),
                approvals: intent.approvals().to_vec(),
                capability: capability.clone(),
                plan_certificate: None,
            },
        )
        .await
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
