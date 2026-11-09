# Scoped approval of a complete entry

A Human reviewer can approve a complete sealed entry under an issued capability
limited to particular account subtrees, fiscal periods, effective dates, entry
classes, branches and native-unit amount ceilings. The review supplies the
actual entry; caller-supplied descriptions of its scope do not grant authority.

This path supports trunk `Original` and `Adjusting` proposals with an `Intent`
origin. Narrowed account, period, date or amount authority cannot approve hidden
or nonlocal effects: control payloads, settlement applications, supersessions,
pending effects, extensions and other origins remain refused. Use the dedicated
workflow and sufficient authority for those operations.

## Review, approve and post

The preparer first retains the exact proposal and its independent review digest:

```bash
fa post --intent adjustment.json --review-out adjustment.review \
  --book ./book --json
```

The reviewer receives those bytes and the independently retained `review_digest`.
An issued Human token must contain both `read` and `approve`. Its account roots
must contain **every** leg, its periods must contain the effective period, and
its class, effective-date cutoff, branch and ceilings must admit the proposal.

```bash
fa approve --review - --digest <review_digest> \
  --token department-reviewer.token --sign-key department-reviewer.key \
  --book ./book --json < adjustment.review
```

The signing key must be the reviewer's registered current key. A principal with
a registered key cannot substitute an unsigned approval. The native preflight
checks current issuance, scope and amount authority before the CLI reads the
signing-key file; the approval transaction checks them again before publication.
Complete review hex may also be passed directly to `--review`.

The original preparer then supplies the returned `approval_vid` when posting the
unchanged review. For example, a closed-period adjustment also requires the
preparer's `post_closed` authority and explicit confirmation:

```bash
fa post --review adjustment.review --digest <review_digest> \
  --approval <approval_vid> --grant post_closed --yes \
  --book ./book --json
```

Approval is not a successful posting rehearsal. Posting still checks the
current posting capability, period law, source history, evidence, required
independence and all ordinary accounting laws.

## Retained authority and historical behavior

- Opaque `--proposal` and `--proposals` digest approval cannot establish entry
  scope. Tokens whose restrictions require the actual payload must use the
  complete canonical review.
- Approval is a write at the current book head. A token pinned to an earlier
  known-at prefix cannot create an approval, and non-trunk branch tokens are
  refused by this trunk-only path.
- An approval binds every proposal field. Changed amounts, accounts, dates,
  descriptions or other bytes require a new approval.
- Consumption checks the retained capability's holder, profile and operation
  against the approval's claims. A signature does not authorize mismatched
  identity or role claims.
- Account subtrees are interpreted at the approval's recorded sequence.
  Expanding a subtree later cannot retroactively authorize a formerly
  out-of-scope approval.
- Revocation prevents new approvals and retries under the revoked capability.
  It does not erase an otherwise valid historical approval. Security-policy
  epoch changes retain their existing stale-approval refusal.
- Exact retries under still-current authority recover the same approval;
  refused requests publish no approval.

Library callers use `Book::admit_entry_approval` for the same preflight, followed
by `approve_entry` or `approve_entry_signed`. `AsyncBook` exposes the equivalent
operations with explicit purpose contexts. The native record and posting paths
enforce the same checks even when the caller omits preflight.
