//! Admission before a host reads evidence input (plan §9.3, §14.2).
//!
//! A host can check current authority before opening or consuming an upload
//! stream. This is not a prepared write, a capability, or a reservation of
//! authority: the ordinary upload/import kernel must still check every law
//! and retain its original witnesses at publication. Preflight reads neither
//! document identities nor their payloads and never advances the journal.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, policy};
use fa_policy::{Capability, Intent, Op};
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError, Outcome};

/// The act that will consume the supplied bytes. Uploading evidence does not
/// authorize an Agent to append an ImportControl or a monetary entry on trunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntakeAction {
    Upload,
    ImportRun,
    /// Bank parsing and account mapping also require read and reconcile.
    BankImport,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Check authority before the host consumes its input stream.
    ///
    /// Upload reaches the whole book at its current trunk head; unsupported
    /// scope caveats refuse before a host consumes evidence. Ordinary
    /// upload/import requires no read capability. Bank import also
    /// requires whole-book read and reconcile before source consumption. The
    /// admission frontier is the current book head, never a historical report
    /// coordinate. Success must not be cached or substituted for publication.
    pub fn preflight_intake(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        action: IntakeAction,
    ) -> Outcome<()> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let book = self.context();
        let admission = match action {
            IntakeAction::Upload => fa_policy::require(capability, Op::Post, "uploading evidence")
                .and_then(|()| fa_policy::scope(capability, book.book_id))
                .and_then(|()| {
                    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
                }),
            IntakeAction::ImportRun | IntakeAction::BankImport => {
                let key = fa_policy::sod::control_key("ImportControl", None, "Import");
                let op = policy::steward()?.preparer_op(&key).ok_or_else(|| {
                    KernelError::Corrupt("sod_policy.toml has no import-run rule".into())
                })?;
                fa_policy::admit(
                    capability,
                    &Intent {
                        principal: capability.holder(),
                        trunk: true,
                        op,
                        book: book.book_id,
                        legs: &[],
                    },
                )
            }
        };
        if let Err(denial) = admission {
            return Ok(Err(policy::refusal(&denial)));
        }
        if action == IntakeAction::BankImport {
            let bank_admission =
                fa_policy::admit_read(capability, capability.holder(), book.book_id)
                    .and_then(|()| {
                        fa_policy::require(capability, Op::Reconcile, "importing bank statements")
                    })
                    .and_then(|()| {
                        fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
                    });
            if let Err(denial) = bank_admission {
                return Ok(Err(policy::refusal(&denial)));
            }
        }
        query.with_restriction(|| -> Outcome<()> {
            Ok(policy::current_at(&self.db, book, capability)?.map(|_| ()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use asupersync::runtime::RuntimeBuilder;
    use fa_journal::{BookSpec, RevocationRequest};
    use fa_model::Id128;
    use fa_money::UnitRegistry;
    use fa_policy::Profile;
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb::MemVfs;
    use fgdb_types::{CommitSeq, VId};

    use crate::{BookKeys, Entropy, UploadRequest};

    fn capability(profile: Profile, holder: u128, ops: &[Op]) -> Capability {
        Capability::new(VId(holder), profile, ops, VId(1)).unwrap()
    }

    async fn create(cx: &PurposeContexts) -> AsyncBook<MemVfs> {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        AsyncBook::create_with_vfs(
            cx,
            vfs,
            Path::new("preflight-book"),
            BookKeys::for_development(211),
            BookSpec {
                book_id: Id128([211; 16]),
                name: "Intake admission".into(),
                base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("preflight", 1, 0).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(211),
        )
        .await
        .unwrap()
    }

    fn request() -> UploadRequest {
        UploadRequest {
            kind: 1,
            mime: "text/plain".into(),
            bytes: b"preflight is not a cached authorization".to_vec(),
            asserted_grade: None,
        }
    }

    #[test]
    fn preflight_is_read_only_and_needs_no_read_operation() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let book = create(&cx).await;
            let before = book.head(&cx).unwrap();
            for profile in [Profile::Human, Profile::Agent, Profile::System] {
                let cap = capability(profile, 41, &[Op::Post]);
                assert!(!cap.holds(Op::Read));
                book.preflight_intake(&cx, &cap, IntakeAction::Upload)
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn evidence_upload_does_not_authorize_agent_import_controls() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let book = create(&cx).await;
            let before = book.head(&cx).unwrap();
            let agent = capability(Profile::Agent, 42, &[Op::Post]);
            book.preflight_intake(&cx, &agent, IntakeAction::Upload)
                .unwrap()
                .unwrap();
            let refused = book
                .preflight_intake(&cx, &agent, IntakeAction::ImportRun)
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.code, "FA-REF-013");
            let human = capability(Profile::Human, 43, &[Op::Post]);
            book.preflight_intake(&cx, &human, IntakeAction::ImportRun)
                .unwrap()
                .unwrap();
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn missing_operations_excluded_books_and_current_expiry_refuse() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let book = create(&cx).await;
            let before = book.head(&cx).unwrap();
            let reader = capability(Profile::Human, 44, &[Op::Read]);
            let excluded = capability(Profile::Human, 44, &[Op::Post])
                .for_books(&[Id128([212; 16])])
                .unwrap();
            let expired = capability(Profile::Human, 44, &[Op::Post]).expiring_at(before);
            for action in [IntakeAction::Upload, IntakeAction::ImportRun] {
                let denied = book
                    .preflight_intake(&cx, &reader, action)
                    .unwrap()
                    .unwrap_err();
                assert_eq!(denied.code, "FA-REF-011");
                assert!(
                    book.preflight_intake(&cx, &excluded, action)
                        .unwrap()
                        .is_err()
                );
                let denied = book
                    .preflight_intake(&cx, &expired, action)
                    .unwrap()
                    .unwrap_err();
                assert!(denied.message.contains("expir"));
            }
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn a_preflight_success_never_outlives_current_authority() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let mut book = create(&cx).await;
            let next = CommitSeq(book.head(&cx).unwrap().0 + 1);
            let cap = capability(Profile::Human, 45, &[Op::Post]).expiring_at(next);
            book.preflight_intake(&cx, &cap, IntakeAction::Upload)
                .unwrap()
                .unwrap();
            let independent = capability(Profile::Human, 46, &[Op::Post]);
            book.upload_document(&cx, &independent, request())
                .await
                .unwrap()
                .unwrap();
            let before = book.head(&cx).unwrap();
            assert_eq!(before, next);
            assert!(
                book.preflight_intake(&cx, &cap, IntakeAction::Upload)
                    .unwrap()
                    .is_err()
            );
            // Even a duplicate cannot disclose its recorded outcome on old authority.
            assert!(
                book.upload_document(&cx, &cap, request())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn journaled_revocation_refuses_preflight_and_the_actual_upload() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let mut book = create(&cx).await;
            let cap = capability(Profile::Human, 47, &[Op::Post, Op::Read, Op::Reconcile]);
            book.preflight_intake(&cx, &cap, IntakeAction::Upload)
                .unwrap()
                .unwrap();
            let revocation = RevocationRequest {
                capability: capability(Profile::Human, 48, &[Op::IssueCapability]),
                revoked: cap.commitment().unwrap(),
                effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
                idempotency_key: b"revoke-input-reader".to_vec(),
                description: book.seal_text(&cx, "revoke uploader before input").unwrap(),
            };
            let context = book.context().clone();
            fa_journal::revoke_capability(&mut book.db, &cx, &context, revocation)
                .await
                .unwrap()
                .unwrap();
            let before = book.head(&cx).unwrap();
            for action in [
                IntakeAction::Upload,
                IntakeAction::ImportRun,
                IntakeAction::BankImport,
            ] {
                let refusal = book
                    .preflight_intake(&cx, &cap, action)
                    .unwrap()
                    .unwrap_err();
                assert!(refusal.message.contains("revok"));
            }
            assert!(
                book.upload_document(&cx, &cap, request())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn bank_preflight_checks_every_required_operation_and_whole_book_scope() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let book = create(&cx).await;
            let before = book.head(&cx).unwrap();
            for ops in [
                vec![Op::Read, Op::Reconcile],
                vec![Op::Post, Op::Reconcile],
                vec![Op::Post, Op::Read],
            ] {
                let cap = capability(Profile::Human, 49, &ops);
                assert!(
                    book.preflight_intake(&cx, &cap, IntakeAction::BankImport)
                        .unwrap()
                        .is_err()
                );
            }
            let full = capability(Profile::Human, 49, &[Op::Post, Op::Read, Op::Reconcile]);
            book.preflight_intake(&cx, &full, IntakeAction::BankImport)
                .unwrap()
                .unwrap();
            for narrowed in [
                full.clone().for_accounts(&["1000"]).unwrap(),
                full.clone().for_periods(&["2026-01"]).unwrap(),
                full.clone().effective_through(DateDay(0)),
                full.clone().known_at_most(before),
                full.clone().on_branch(Id128([42; 16])).unwrap(),
            ] {
                assert!(
                    book.preflight_intake(&cx, &narrowed, IntakeAction::BankImport)
                        .unwrap()
                        .is_err()
                );
            }
            let agent = capability(Profile::Agent, 50, &[Op::Post, Op::Read, Op::Reconcile]);
            assert!(
                book.preflight_intake(&cx, &agent, IntakeAction::BankImport)
                    .unwrap()
                    .is_err()
            );
            let expired = full.clone().expiring_at(before);
            let refusal = book
                .preflight_intake(&cx, &expired, IntakeAction::BankImport)
                .unwrap()
                .unwrap_err();
            assert!(refusal.message.contains("expir"));
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }

    #[test]
    fn bank_account_witness_refuses_changes_on_both_sides_of_preparation() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(async {
            let mut book = create(&cx).await;
            let day = DateDay::from_ymd(2026, 1, 1).unwrap();
            let cap = capability(Profile::Human, 51, &[Op::Post, Op::Read, Op::Reconcile]);
            book.install_chart(
                &cx,
                &[fa_journal::AccountSpec {
                    code: "1000".into(),
                    name: "Cash".into(),
                    account_type: fa_model::AccountType::ASSET.0,
                    normal_balance: 0,
                    is_leaf: true,
                    unit_policy: fa_journal::UnitPolicy::AnyCurrency,
                    parent_code: None,
                    limit: None,
                }],
                cap.holder(),
                day,
                b"bank-witness-chart",
                &fa_journal::Capability::embedded(cap.holder(), &["schema_change"]).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            let account = book
                .accounts(&cx)
                .unwrap()
                .into_iter()
                .find(|row| row.code == "1000")
                .unwrap();
            let context = book.context().clone();
            let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
            let document = fa_journal::Document {
                book_id: context.book_id,
                kind: policy.kind_by_name("BankStatement").unwrap().tag,
                mime: "text/plain".into(),
                grade: fa_journal::upload::upload_grade(&policy, Profile::Human).unwrap(),
                retrieved_by: cap.holder(),
                bytes: b"original statement held by the pending import".to_vec(),
            };
            let oid = document.oid();
            let request = fa_journal::ImportRequest {
                principal: cap.holder(),
                source: fa_model::IntakeSource::Upload {
                    principal: cap.holder(),
                },
                idempotency_key: b"bank-account-witness".to_vec(),
                effective_date: day,
                description: book.seal_text(&cx, "bank witness regression").unwrap(),
                documents: vec![document],
            };
            let fa_journal::import::ImportPreparation::Ready(mut prepared) =
                fa_journal::import::prepare_import(
                    &mut book.db,
                    &cx,
                    &context,
                    &cap,
                    request.clone(),
                )
                .unwrap()
                .unwrap()
            else {
                panic!("a fresh import must require publication");
            };
            prepared
                .witness_account(&book.db, &account)
                .unwrap()
                .unwrap();
            let run = prepared.run();
            // A competing native client changes the validated cash leaf AFTER
            // its witness was recorded, but before any import is published.
            let mut change = fgdb::WriteBatch::new(fa_model::symbols::relation::DERIVED_FROM);
            change.set_vertex_property(
                account.vid,
                fa_model::symbols::property::POSTING,
                Some(fgdb_types::CanonicalScalar::Int(0)),
            );
            book.db.write(&cx.commit(), change).await.unwrap();
            let after_change = book.head(&cx).unwrap();
            let refusal = prepared
                .commit(&mut book.db, &cx)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, fa_journal::refusal::code::CONFLICT);
            assert_eq!(book.head(&cx).unwrap(), after_change);
            assert!(
                book.query(&cx, |db, _| {
                    Ok(fa_journal::evidence::document_record(db, &oid)?.is_none()
                        && fa_journal::import::read_run(db, run)?.is_none())
                })
                .unwrap()
            );

            // The same stale validation must also refuse when the account
            // changed BEFORE the next import transaction was prepared.
            let fa_journal::import::ImportPreparation::Ready(mut prepared) =
                fa_journal::import::prepare_import(&mut book.db, &cx, &context, &cap, request)
                    .unwrap()
                    .unwrap()
            else {
                panic!("the refused import cannot have a recorded receipt");
            };
            let refusal = prepared
                .witness_account(&book.db, &account)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, fa_journal::refusal::code::CONFLICT);
            prepared.abort();
            assert_eq!(book.head(&cx).unwrap(), after_change);
            assert!(
                book.query(&cx, |db, _| {
                    Ok(fa_journal::evidence::document_record(db, &oid)?.is_none()
                        && fa_journal::import::read_run(db, run)?.is_none())
                })
                .unwrap()
            );
        });
    }
}
