# Approving several reviewed proposals

`fa approve --proposals` records several approvals for one caller while opening
the book once. It uses the same native approval transaction as `--proposal`.
The input is an inline JSON array of proposal digests, or `-` for complete stdin:

```sh
fa approve --book ./book --proposals - --token reviewer-one.token --json < reviewed-digests.json
```

The array contains 1–4096 unique 64-hex digest strings and is limited to 1 MiB.
All syntax, members and digest uniqueness are checked before the first approval.
Uppercase and lowercase spellings of the same digest count as duplicates.
No file path is accepted as the value of `--proposals`; shell redirection and
forwarded stdin keep the reader at the client. MCP supplies the inline JSON array
through the `proposals` string; its approve tool has no stdin property. Daemon
requests use existing stdin forwarding.

Every member still checks the caller's current capability, revocation witnesses,
policy epoch and registered signing key in its own native transaction. A caller
with a registered key supplies its current `--sign-key` through the existing
direct-client signing path. Grouping does not authorize an Agent to approve or
create another principal. Two independent approvals require two independently
authorized callers to approve the reviewed digests.

Robot output contains the existing `approved` receipt for each successful member,
in input order. The first refusal stops the request and emits the existing error
envelope. Earlier successful approvals remain durable: this is not an atomic
group. Preserve each receipt's digest, approval VID and recorded sequence. An
unchanged retry under still-valid original authority returns those same receipts
with `already_recorded: true`; expiry and revocation still refuse a retry. An
authority change may require a separately reviewed recovery rather than reuse of
an old approval identity.

Use `--proposal` for one digest and `--review` for a retained review artifact.
`--proposals` is exclusive with those modes and with `--digest`, and may occur
only once. Repeated legacy `--proposal` flags retain their last-value behavior.
