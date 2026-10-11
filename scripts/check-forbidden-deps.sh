#!/usr/bin/env bash
# Resolved production foundations (fa-lbh / fa-c23, plan §18.4).
# Retains metadata, per-posture trees and stderr in the supplied/new directory.
# No compiler is invoked. Do not combine -p selections or consume metadata's
# resolve.nodes.features: either can attribute feature unification to the wrong
# posture. The negative suite pins this behavior with real local Cargo trees.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"
gate_init "foundations"
[ "$#" -le 1 ] || gate_abort_unrun "foundations — usage: check-forbidden-deps.sh [receipts-dir]"
for tool in cargo python3; do
  command -v "$tool" >/dev/null 2>&1 || gate_abort_unrun "foundations — $tool is not installed"
done
python3 -c 'import tomllib' >/dev/null 2>&1 \
  || gate_abort_unrun "foundations — Python 3.11+ tomllib is required"
WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/fa-foundations.XXXXXX")}"
# Remove no files: every run's receipts remain available to the reviewer.
mkdir -p "$WORK" || gate_abort_unrun "foundations — cannot create receipt directory $WORK"
cd "$ROOT" || gate_abort_unrun "foundations — cannot enter workspace"
cargo -vV >"$WORK/cargo-version.txt" 2>"$WORK/cargo-version.stderr" \
  || gate_abort_unrun "foundations — Cargo version/host unavailable; see $WORK"
HOST="$(sed -n 's/^host: //p' "$WORK/cargo-version.txt")"
[ -n "$HOST" ] || gate_abort_unrun "foundations — Cargo did not name its host; see $WORK"
cargo metadata --locked --format-version 1 >"$WORK/metadata.json" 2>"$WORK/metadata.stderr" \
  || gate_abort_unrun "foundations — locked metadata resolution did not run; see $WORK/metadata.stderr"
for posture in fa fa-cli fad fa-mcp; do
  cargo tree --locked --package "$posture" --target "$HOST" \
    --edges normal,build --prefix none --color never --format '{p}|{f}' \
    >"$WORK/$posture.tree" 2>"$WORK/$posture.stderr" \
    || gate_abort_unrun "foundations — $posture production tree did not resolve; see $WORK/$posture.stderr"
done
gate_diag "foundation evidence: $WORK (target $HOST, separate default-feature postures)"
python3 -B "$ROOT/scripts/foundation_check.py" "$ROOT" "$WORK" >"$WORK/verdict.log" 2>"$WORK/verdict.stderr"
RC=$?
cat "$WORK/verdict.log"
if [ "$RC" -eq 0 ]; then
  gate_pass "foundations — resolved production identity/source/feature assertions executed"
else
  gate_fail "foundations — resolved checker exited $RC; see $WORK/verdict.log and $WORK/verdict.stderr"
fi
gate_verdict
