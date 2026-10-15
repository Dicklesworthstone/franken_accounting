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
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Check authority before the host consumes its input stream.
    ///
    /// No read capability is implied or required: a write-only uploader may
    /// submit evidence but cannot use this method to look up documents. The
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
            IntakeAction::Upload => {
                fa_policy::require(capability, Op::Post, "uploading evidence")
                    .and_then(|()| fa_policy::scope(capability, book.book_id))
            }
            IntakeAction::ImportRun => {
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
                assert!(book.preflight_intake(&cx, &excluded, action).unwrap().is_err());
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
            assert!(book.preflight_intake(&cx, &cap, IntakeAction::Upload).unwrap().is_err());
            // Even a duplicate cannot disclose its recorded outcome on old authority.
            assert!(book.upload_document(&cx, &cap, request()).await.unwrap().is_err());
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
            let cap = capability(Profile::Human, 47, &[Op::Post]);
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
            for action in [IntakeAction::Upload, IntakeAction::ImportRun] {
                let refusal = book
                    .preflight_intake(&cx, &cap, action)
                    .unwrap()
                    .unwrap_err();
                assert!(refusal.message.contains("revok"));
            }
            assert!(book.upload_document(&cx, &cap, request()).await.unwrap().is_err());
            assert_eq!(book.head(&cx).unwrap(), before);
        });
    }
}
