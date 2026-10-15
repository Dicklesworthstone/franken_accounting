#!/usr/bin/env bash
# =============================================================================
# scripts/invariants_check.sh — the runtime half of the invariant cross-check
# (bead fa-37f)
#
# Usage: scripts/invariants_check.sh <invariants.toml> <test-transcript>
#
# AGENTS.md: no subsystem ships against an unenforced invariant, and CI
# cross-checks that every live clause has a live checker. registries/
# invariants.toml names, per live clause, its checker and negative tests as
# `crate::target::path`. This gate reads the libtest transcript of the SAME
# gate run (scripts/check.sh step `test`) and requires every one of them to
# appear exactly once as `test <path> ... ok`. Without a second build, it
# proves the named tests exist and passed in the run that is being judged.
# fa-registry's own tests are the static half: each name resolves to a
# `#[test]` fn in the file it names.
#
# Verdicts, per the contract in scripts/lib/gate_verdict.sh:
#   PASS  a live clause whose every checker and negative ran and passed
#   FAIL  a named test that is missing (renamed, removed, never run), ignored,
#         or ambiguous (its path matches more than one test)
#   UNRUN the transcript is absent, holds no passing binary, or shows a failed
#         test run (fail-fast cargo stops at the first failing binary, so later
#         binaries' tests would be missing for reasons that are not this
#         gate's to judge)
#
# No-claim boundary: a PASS proves each checker exists, is referenced, and
# passed — not that it is sufficient for its clause.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

if [ "$#" -ne 2 ]; then
  printf 'FAIL invariants_check.sh: usage: invariants_check.sh <invariants.toml> <test-transcript>\n'
  exit 1
fi
REGISTRY="$1"
TRANSCRIPT="$2"

gate_init "invariants"

[ -r "$REGISTRY" ] || gate_abort_unrun "invariants — no registry at $REGISTRY"
[ -r "$TRANSCRIPT" ] || gate_abort_unrun "invariants — no test transcript at $TRANSCRIPT (the test step did not run)"

# libtest lines are plain; strip colour anyway so a coloured run reads the same.
CLEAN="$(sed 's/\x1b\[[0-9;]*m//g' "$TRANSCRIPT")"
if grep -Eq '^test result: FAILED|^error: test failed|^error: [0-9]+ targets? failed' <<<"$CLEAN"; then
  gate_abort_unrun "invariants — the test run failed, so its transcript may omit later binaries; checkers are judged only over a green run (the test step's own verdict is the failure)"
fi
if ! grep -q '^test result: ok\.' <<<"$CLEAN"; then
  gate_abort_unrun "invariants — the transcript holds no passing test binary; nothing to judge"
fi

# Every libtest outcome line: "<path> <status>".
OUTCOMES="$(sed -nE 's/^test ([^ ]+) \.\.\. (ok|FAILED|ignored)$/\1 \2/p' <<<"$CLEAN")"

# The registry's live clauses as "<clause-id> <strength> <role> <checker>" lines.
# The format is the TOML subset fa-registry validates: one key per line, flat
# single-line arrays of strings.
LIVE="$(awk '
  function str(line) { sub(/^[a-z_]+ = "/, "", line); sub(/"$/, "", line); return line }
  function emit(role, line,   n, parts, i, s, st) {
    st = (strength == "" ? "-" : strength)
    sub(/^[a-z_]+ = \[/, "", line); sub(/\]$/, "", line)
    if (line == "") { print inv "." id " " st " " role " -"; return }
    n = split(line, parts, /", "/)
    for (i = 1; i <= n; i++) { s = parts[i]; gsub(/"/, "", s); print inv "." id " " st " " role " " s }
  }
  function flush() {
    if (in_clause && status == "live") {
      if (checkers == "") checkers = "checkers = []"
      if (negatives == "") negatives = "negatives = []"
      emit("checker", checkers); emit("negative", negatives)
    }
  }
  /^\[\[clause\]\]/ { flush(); in_clause = 1; inv = ""; id = ""; status = ""; strength = ""; checkers = ""; negatives = ""; next }
  /^\[/ { flush(); in_clause = 0; next }
  in_clause && /^invariant = / { inv = str($0) }
  in_clause && /^id = / { id = str($0) }
  in_clause && /^status = / { status = str($0) }
  in_clause && /^checker_strength = / { strength = str($0) }
  in_clause && /^checkers = / { checkers = $0 }
  in_clause && /^negatives = / { negatives = $0 }
  END { flush() }
' "$REGISTRY")"

if [ -z "$LIVE" ]; then
  gate_fail "invariants — $REGISTRY has no live clause; nothing was cross-checked"
  gate_verdict
  exit $?
fi

CLAUSES="$(cut -d' ' -f1 <<<"$LIVE" | awk '!seen[$0]++')"
while read -r clause; do
  [ -n "$clause" ] || continue
  bad=0
  count=0
  clause_strength="-"
  while read -r _ strength role checker; do
    clause_strength="$strength"
    count=$((count + 1))
    if [ "$checker" = "-" ]; then
      gate_fail "$clause — a live clause names no $role"
      bad=1
      continue
    fi
    rest="${checker#*::}"
    path="${rest#*::}"
    if [ "$path" = "$rest" ] || [ "$rest" = "$checker" ]; then
      gate_fail "$clause — $role \`$checker\` is not crate::target::path"
      bad=1
      continue
    fi
    matches="$(awk -v p="$path" '$1 == p { print $2 }' <<<"$OUTCOMES")"
    n="$(grep -c . <<<"$matches")"
    if [ "$n" -eq 0 ]; then
      gate_fail "$clause — $role \`$checker\` is not in the test transcript (renamed, removed, or never run)"
      bad=1
    elif [ "$n" -gt 1 ]; then
      gate_fail "$clause — $role \`$checker\` is ambiguous: $n tests are named \`$path\`"
      bad=1
    elif [ "$matches" != "ok" ]; then
      gate_fail "$clause — $role \`$checker\` did not pass (status: $matches)"
      bad=1
    fi
  done < <(awk -v c="$clause" '$1 == c' <<<"$LIVE")
  if [ "$clause_strength" = "-" ] || [ "$clause_strength" = "smoke" ]; then
    gate_fail "$clause — live clause checker_strength must be > smoke (found: $clause_strength)"
    bad=1
  fi
  if [ "$bad" -eq 0 ]; then
    gate_pass "$clause (strength: $clause_strength) — $count checker and negative tests ran and passed"
  fi
done <<<"$CLAUSES"

# Gate G1 needs every clause whose first_gate is G1 live; a dormant one is not
# this gate's failure (each commit is not a G1 claim) but it is never hidden.
# Indented: column 0 of stdout belongs to the verdict vocabulary.
awk '
  function str(line) { sub(/^[a-z_]+ = "/, "", line); sub(/"$/, "", line); return line }
  function flush() {
    if (in_clause && status == "dormant" && gate == "G1") {
      sub(/^activating = \[/, "", activating); sub(/\]$/, "", activating); gsub(/"/, "", activating)
      printf "  note: gate G1 is blocked by %s.%s (dormant; activating %s)\n", inv, id, activating
    }
  }
  /^\[\[clause\]\]/ { flush(); in_clause = 1; inv = ""; id = ""; status = ""; gate = ""; activating = ""; next }
  /^\[/ { flush(); in_clause = 0; next }
  in_clause && /^invariant = / { inv = str($0) }
  in_clause && /^id = / { id = str($0) }
  in_clause && /^status = / { status = str($0) }
  in_clause && /^first_gate = / { gate = str($0) }
  in_clause && /^activating = / { activating = $0 }
  END { flush() }
' "$REGISTRY"

gate_verdict
