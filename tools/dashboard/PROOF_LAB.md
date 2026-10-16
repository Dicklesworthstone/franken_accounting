# Proof lab

The local dashboard includes a read-only **Proof lab** for FrankenAccounting's
recorded accumulator checkpoints and portable proof exports.

It deliberately follows the native trust model instead of reducing everything to
a green shield:

- **Checkpoint chain** calls `fa verify accumulator`. Each stored state names the
  entry prefix it covers, its leaf count, recording sequence, and recomputation
  finding. A red native verification remains red.
- **Signed checkpoint** exports the recorded TransparencyCheckpoint whose Ed25519
  signature is judged against the displayed checkpoint public key.
- **Raw checkpoint** exports the exact unsigned 80-byte statement; the UI labels
  that external trust is still required.
- **Prefix proof** proves prefix completeness relative to the chosen checkpoint.
- **Inclusion proof** proves membership of one exact entry handle, optionally with
  its canonical record.
- **Balance proof** recomputes one account/native-unit balance, optionally through
  an inclusive effective cutoff, against a recorded checkpoint.

The dashboard never creates a checkpoint, chooses a grant, writes an output path,
or changes the book. The browser can select only an existing checkpoint state and
the arguments that apply to the selected proof kind. All other parameters are
rejected.

Proof bytes are returned inline by the native CLI, remain bounded by the local
dashboard's subprocess/frame limits, and can be downloaded by the browser as a
binary file. The UI also renders the corresponding `fa-verify` command. That
command is the independent verification path; the browser is a presentation
surface, not an independent verifier or trust anchor.

Demo mode emits explicitly synthetic checkpoint/proof objects solely to exercise
the interaction. No synthetic proof should be interpreted as cryptographic
evidence.

Focused regression coverage:

```sh
python3 -m unittest tools/dashboard/tests/test_proof_lab.py -v
```

The tests cover per-kind selector admission, exact state selection, native verifier
routing, synthetic labeling, loopback asset delivery, private API routes, write
method refusal, and rejection of browser-supplied output paths or irrelevant
arguments.
