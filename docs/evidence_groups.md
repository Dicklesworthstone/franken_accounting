# Attach shared evidence to a bounded group of entries

`fa document attach --entries` attaches the same retained documents to several
committed entries while holding one open book. It uses the existing native
`AttachEvidence` transaction for each entry and prints one `evidence_attached`
receipt for each success, in the requested order. The entry's original payload,
amounts and original evidence citations remain unchanged.

This frontend is available to the CLI and to CLI requests forwarded through
`fad`. The MCP `fa.evidence.steward` tool's explicit flag list does **not** expose
`--entries`; adding equivalent per-target MCP controls is separate work.

## Request

Retain an ordered JSON array of entry VIDs:

```json
["E:0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"]
```

Then pass its bytes on stdin and cite the shared documents with the existing
repeatable evidence option:

```bash
fa --book ./book document attach --entries - \
  --evidence 'D:<original-source-document-oid>:Source' \
  --evidence 'D:<normalized-source-document-oid>:Source' \
  --evidence 'D:<source-manifest-document-oid>:Source' \
  --evidence 'D:<control-document-oid>:Source' \
  --json < entry-vids.json
```

The angle-bracket names stand for actual OIDs returned by `document add`; the
VIDs must come from native entry receipts. To use a held daemon, add `--via fad`
and the operator's issued token as appropriate. `--entries -` forwards the exact
stdin bytes, so it does not require a daemon `--files-root`. An inline JSON array
is also accepted. A host file path is not an `--entries` input format.

The group is bounded as follows:

| Limit | Meaning |
| --- | --- |
| 1 MiB | Maximum UTF-8 JSON bytes, including whitespace |
| 1–4,096 | Unique entry targets in one request |
| 1–1,024 | Shared evidence citations, subject to the ordinary native supplement limits |
| 16,384 | Maximum product of target count and shared citation count |

Thus four shared documents permit 4,096 targets. A five-document request permits
at most 3,276 targets. These bounds constrain work and output; they do not enlarge
the native per-supplement payload or storage limits. The public-data importer
uses four source/control citations per entry.

`--entries` occurs once and cannot be combined with the positional entry form.
Every target must be a string accepted by the ordinary entry VID parser. Hex
case and recognized VID prefixes do not create distinct targets: duplicates are
refused after canonical parsing. Every shared citation is parsed before the
first attachment. A document cited twice in the same role is refused; two
different registered roles are distinct citations. Citation order in each
receipt is the native canonical order, regardless of flag order.

## Authority, receipts and retry

The command validates the entire request's syntax, duplicate identities and
bounds before publishing anything. It then opens and admits the book once.
Before **each** target lookup it repeats current authorization and whole-entry
read-scope admission. The ordinary kernel independently checks the attacher's
current capability, target EntryRef, document commitments and custody witnesses
inside that target's transaction. Reusing an open book does not reuse an earlier
authorization decision.

Each success emits the existing `evidence_attached` event. Its data binds the
supplement VID and body digest, the exact target entry VID and entry digest,
the full document OID/commitment/role list, the original recorded sequence and
the `already_recorded` flag. The surrounding envelope binds the book, current
coordinate and actual principal. It is useful to retain these receipts alongside
the input array and source-document receipts.

A group is a sequence of ordinary atomic attachments. If a later target does not
exist, fails a native law, or is encountered after capability expiry, the command
stops with its usual nonzero exit and error event. Earlier successful receipts
describe a durable prefix. There is no group-wide rollback or implicit posting,
approval, finalization, or evidence-grade change.

An interrupted response may leave an attachment committed without its receipt
having reached the client. Retry the same complete request as the same principal
with current authority. Native content identity returns the original supplement
VID, body digest and recorded sequence for previously completed targets, with
`already_recorded: true`; those retries create no duplicate supplements. An
owner-mode retry, including tokenless CLI forwarding through `fad`, adds no
history. A bound document command preserves its ordinary `AccessEvent` on
admitted open, so a currently authorized token retry can advance the head for
that access audit while the supplement's recorded sequence stays unchanged.
Malformed group syntax and shared citations are refused before that open. An
expired or revoked capability cannot retrieve a success receipt merely because
an identical attachment already exists. A changed target, shared citation set
or principal describes a different native supplement, not the same retry.

## Native regression coverage

The attachment-group integration tests exercise ordered receipts and durable
reopen, the unchanged single-target identity, malformed later input and shared
citations, duplicate aliases, all request bounds, a committed prefix followed by
a missing target, and capability expiry between targets and before an exact
retry. They also run real process stdin at the exact byte limit and a group of
1,091 real committed fixture entries with four citations each, followed by exact
retries through one held-book command. The bound-token regression preserves and
checks the separate access audit when fresh authority retries an existing
supplement.

The response-bound regression uses the actual robot-envelope and daemon-response
serializers and `wire::encode` with 4,096 events and 16,384 citations. It includes
maximum recorded sequences, the longest encoded registered role, the finite
operation set, and a 256-byte issued principal with maximally expanding control
characters. It enforces substantial room inside the registered 64 MiB daemon
frame limit. This is a serialization/work bound, not a guarantee about execution
time or resident memory; capture, rendering and framing retain multiple buffers.

These are synthetic native fixtures. Their documents retain `AgentUpload`
custody with explicit reviews under a distinct fixture principal. The fixtures
do not represent an independent human audit or replace actual public-source
replay evidence.
