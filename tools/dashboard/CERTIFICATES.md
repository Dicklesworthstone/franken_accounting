# Certificate desk

The local workbench now includes a **Certificate desk** for retained report
certificates. It is intentionally read-only and sits on top of the existing
native `certificate status` and `replay` commands.

Launch the dashboard normally and choose **Certificate desk**, or open
`/proofs.html` from the same private local session.

A retained certificate answers two different questions:

1. **What did this report say then?** Native replay evaluates the retained
   certificate's original selector and recorded prefix. The dashboard never
   substitutes the current frontier for that historical coordinate.
2. **Does that selector still have the same entry population now?** Certificate
   status checks the current book and reports `Current` or `SupersededBy`,
   together with later entry handles that affect the retained selector.

The desk presents those coordinates on one timeline so they are hard to confuse.
A superseded certificate is not erased or invalidated as historical evidence: its
original result remains replayable. Conversely, a current status is not a
third-party signature, physical timestamp, or proof that every source document
was economically truthful.

Supported native replay presentations are the certificate kinds already emitted
by FrankenAccounting: trial balance, registered statement, balance explanation,
and open items. The browser renders a bounded table and leaves the full native
artifact authoritative.

Later entry handles are clickable. Their inspector uses the existing current
entry/evidence API and labels that current observation separately from the
certificate's historical snapshot. No later review or evidence object is
backdated into the retained report.

## Security and exactness

Certificate ids are exact 64-hex retained artifact digests, with optional `C:`
prefix. Browser requests cannot choose another book, executable, key file,
principal, grant, path, or arbitrary command. The same loopback Host/Origin/token
checks and serialized native access used by the rest of the dashboard apply.

The replay route executes the native command once and accepts exactly one of the
four registered report events. It refuses a changed book or mismatched retained
certificate identity instead of guessing the intended result.

Recorded sequences still cross the Python/JavaScript boundary as decimal strings,
so values above JavaScript's safe-integer range remain exact. Amount strings are
displayed as supplied by the native robot contract; the certificate desk does
not recompute accounting balances.

The synthetic demo accepts a sample digest only to demonstrate the interaction.
It labels its status authority and replay warning as synthetic and makes no native
verification claim.

## Regression coverage

Run the certificate-specific standard-library tests with:

```sh
python3 -m unittest tools/dashboard/tests/test_certificates.py -v
```

They cover id validation, exact native command selection, one-shot multi-kind
replay, artifact identity mismatch, synthetic labeling, static asset delivery,
private HTTP routing, selector allowlists, and rejection of write methods.

This desk is not an independent offline verifier. For outsider verification,
export the relevant proof/bundle/checkpoint and use `fa-verify` with an
independently trusted checkpoint key under the native documented workflow.
