#!/usr/bin/env bash
# =============================================================================
# scripts/check.sh — the whole chain, under the verdict contract (bead fa-lbh)
#
# Consumer: every landing, and the merge train. Gate: nothing lands red.
# Observed defect class: a green `cargo test` in a dirty tree, and gates whose
# failures go to a stream nobody reads. Retire: never (it is the gate).
#
# Reading a gate: THE EXIT CODE IS THE VERDICT. Exit 0 iff every step ran and
# passed. Every failure is an anchored `FAIL ` line at column 0 of stdout;
# a step that could not execute (the rch fleet refused the offload, a tool is
# not installed) is `UNRUN` + `FAIL`, never a silent green. The contract is
# scripts/lib/gate_verdict.sh, adopted verbatim from FrankenGraphDB.
#
# STEPS (27 in full mode):
#   fmt, check, clippy (-D warnings), test-list + test, gate-evidence
#   (completion markers, test-inventory witness, per-crate ratchet, fa-czx)
#   and its planted negative, invariants (fa-37f) and its planted negative,
#   robot-schema (fa-12x), fuzz-smoke (fa-tre), bench-smoke (fa-tu58),
#   conformance-mutation (fa-zy1), deny, ubs, shellcheck, registries-embedded,
#   registry-check (tools/registry-check: schema validation, claims lint,
#   foundation API consumption, negative-checker disjointness, fa-szi / fa-r3d),
#   installer-integration (fa-o3zg), forbidden-deps, foundations (resolved-foundation-graph, fa-c23) and its
#   planted negative, doctrine (fa-598p) and its planted negative,
#   reference-boundary, and topology (fa-37f) and its planted negative.
#   Scoreboards (crates/fa-cli/tests/scoreboard.rs, fa-e9z / fa-7s6d) and verb
#   parity (verbs.toml vs CLI vs MCP: crates/fa-mcp/tests/parity.rs and
#   deny_rows.rs, fa-xex) run under `test`.
#   NOT IMPLEMENTED: earlier versions of this header also listed file-coverage
#   (every tracked file claimed by a gate or exempted with a reason),
#   readme-agents-sync, beads-cycles (br dep cycles) and tree-integrity. No
#   step has ever checked them; a green run says nothing about them.
#   Exact-tree proof manifests and merge-train scripts are tracked in fa-u7u.
#
# Usage: bash scripts/check.sh            # everything
#        bash scripts/check.sh --quick    # fmt, check, clippy, ubs (no tests, no deny)
#        bash scripts/check.sh --bench    # smoke benchmarks + manifest/witness checks (fa-tu58)
#        CHECK_LOG_DIR=<dir> keeps the per-step logs somewhere other than a temp dir.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

QUICK=0
BENCH_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --bench) BENCH_ONLY=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'FAIL check.sh: unknown argument %s\n' "$arg"; exit 2 ;;
  esac
done

LOG_DIR="${CHECK_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/fa-check.XXXXXX")}"
mkdir -p "$LOG_DIR"
STEP_MANIFEST="${CHECK_STEP_MANIFEST:-$LOG_DIR/step-verdicts.jsonl}"
: >"$STEP_MANIFEST"

CHECK_TREE_HASH="$(git rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
CHECK_TOOLCHAIN="$(rustc --version 2>/dev/null || echo unavailable)"

hash_file() {
  local f="$1"
  if [ ! -f "$f" ]; then
    printf 'none\n'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    printf 'unavailable\n'
  fi
}

extract_worker() {
  local f="$1"
  local w=""
  if [ -f "$f" ]; then
    w="$(sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' "$f" | tail -n 1)"
  fi
  printf '%s\n' "${w:-local}"
}

record_step_verdict() {
  local step="$1" status="$2" started="$3" finished="$4" duration="$5" log_file="${6:-}"
  local worker log_digest
  worker="$(extract_worker "$log_file")"
  log_digest="$(hash_file "$log_file")"
  printf '{"step":"%s","status":"%s","tree_hash":"%s","toolchain":"%s","worker":"%s","started":"%s","finished":"%s","duration_secs":%s,"log_digest":"%s"}\n' \
    "$step" "$status" "$CHECK_TREE_HASH" "$CHECK_TOOLCHAIN" "$worker" "$started" "$finished" "${duration:-0}" "$log_digest" \
    >>"$STEP_MANIFEST"
}

try_reuse_step() {
  local label="$1" log_dest="$2"
  [ -n "${CHECK_RESUME_FROM:-}" ] || return 1
  local prior_manifest="$CHECK_RESUME_FROM"
  local prior_dir=""
  if [ -d "$CHECK_RESUME_FROM" ]; then
    prior_dir="$CHECK_RESUME_FROM"
    if [ -f "$prior_dir/tree-before.txt" ] && [ "$(cat "$prior_dir/tree-before.txt")" != "$CHECK_TREE_HASH" ]; then
      return 1
    fi
    if [ -f "$prior_dir/check.stdout.log" ] && grep -Eq '^RED([[:space:]]|$)|: [0-9]+ passed, [1-9][0-9]* failed,' "$prior_dir/check.stdout.log"; then
      return 1
    fi
    prior_manifest="$prior_dir/step-verdicts.jsonl"
    if [ ! -f "$prior_manifest" ] && [ -f "$prior_dir/tools.txt" ]; then
      prior_manifest="$prior_dir/tools.txt"
    fi
  fi
  if [ -f "$prior_manifest" ]; then
    if grep -Fq '"status":"FAIL"' "$prior_manifest"; then
      return 1
    fi
    local line
    line="$(grep -F "\"step\":\"$label\"" "$prior_manifest" | grep -F "\"status\":\"PASS\"" | grep -F "\"tree_hash\":\"$CHECK_TREE_HASH\"" | grep -F "\"toolchain\":\"$CHECK_TOOLCHAIN\"" | tail -n 1 || true)"
    if [ -n "$line" ]; then
      line="${line#step_verdict=}"
      if [ -n "$prior_dir" ] && [ -n "$log_dest" ] && [ -f "$prior_dir/$(basename "$log_dest")" ]; then
        cp "$prior_dir/$(basename "$log_dest")" "$log_dest" 2>/dev/null || true
      fi
      printf '%s\n' "$line" >>"$STEP_MANIFEST"
      gate_pass "$label (reused from split-run for tree ${CHECK_TREE_HASH:0:12})"
      return 0
    fi
  fi
  if [ -n "$prior_dir" ] && [ -f "$prior_dir/check.stdout.log" ]; then
    if grep -Eq "^PASS ${label}([[:space:]]|\$)" "$prior_dir/check.stdout.log"; then
      local now_utc
      now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      record_step_verdict "$label" "PASS" "$now_utc" "$now_utc" 0 "$log_dest"
      gate_pass "$label (reused from split-run for tree ${CHECK_TREE_HASH:0:12})"
      return 0
    fi
  fi
  return 1
}

gate_init "check.sh"

# run_step <label> <command...>
# PASS when the command exits 0; UNRUN when it did not execute; FAIL
# otherwise. stdout+stderr of the step go to its log; only the verdict line
# goes to our stdout.
#
# "Did not execute" is decided conservatively from rch's own signals, never
# from the mere presence of an `[RCH]` line: a remote run that executed and
# failed also logs those, and rch passes the remote command's exit status
# through (observed: `Remote command finished: exit=101` with real rustc
# diagnostics). So:
#   exit 103 (rch refused to offload)                                → UNRUN
#   "[RCH] … refusing local fallback" or "… completion unconfirmed" (SSH
#   timeout, remote process killed) or exit 100 (network/SSH) with NO
#   "Remote command finished" line (nothing executed)                → UNRUN
#   anything else nonzero, including 101/102 after execution         → FAIL
run_step() {
  local label="$1"; shift
  local log="$LOG_DIR/${label//[^A-Za-z0-9_.-]/_}.log"
  if try_reuse_step "$label" "$log"; then
    return
  fi
  local started t0 finished t1 dur
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t0="$(date +%s)"
  if ! command -v "$1" >/dev/null 2>&1; then
    finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    record_step_verdict "$label" "UNRUN" "$started" "$finished" 0 "$log"
    gate_unrun "$label — $1 is not installed; did not run; log: $log"
    return
  fi
  "$@" >"$log" 2>&1
  local rc=$?
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t1="$(date +%s)"
  dur=$((t1 - t0))
  if [ "$rc" -eq 0 ]; then
    record_step_verdict "$label" "PASS" "$started" "$finished" "$dur" "$log"
    gate_pass "$label"
    return
  fi
  local executed=0
  grep -q 'Remote command finished' "$log" && executed=1
  if [ "$rc" -eq 103 ] \
    || { [ "$executed" -eq 0 ] && { [ "$rc" -eq 100 ] || grep -Eq '^\[RCH\] .*(refusing local fallback|completion unconfirmed)' "$log"; }; }; then
    record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
    gate_unrun "$label — the rch offloader did not run the command (exit $rc: refused, no admissible worker, or lost the worker before execution; retryable, not a product verdict); log: $log"
  else
    record_step_verdict "$label" "FAIL" "$started" "$finished" "$dur" "$log"
    gate_fail "$label (exit $rc); log: $log"
    gate_diag "---- $label: last 40 lines of $log"
    tail -n 40 "$log" >&2
  fi
}

# cargo_build <label> <subcommand> <args...>
# Every compiling cargo step goes through rch explicitly and only through
# rch (suite rule: builds are offloaded; a bare `cargo` in a non-login shell
# resolves to rustup's binary and would build on this box). No local lane:
# without rch the step is UNRUN, never a local build. CHECK_JOBS bounds -j.
#
# Since fa-czx: an exit-0 compiling step is PASS only when its log ALSO
# contains `Remote command finished: exit=0` and a step-specific completion
# marker (`Finished` for check/clippy; `: test$` for test-list; `>= 1`
# `test result: ok.` line with a positive passed count for test steps).
# Missing markers classify as UNRUN (retryable), never PASS.
CHECK_JOBS="${CHECK_JOBS:-2}"
cargo_build() {
  local label="$1" sub="$2"; shift 2
  local log="$LOG_DIR/${label//[^A-Za-z0-9_.-]/_}.log"
  if try_reuse_step "$label" "$log"; then
    return
  fi
  local started t0 finished t1 dur
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t0="$(date +%s)"
  if ! command -v rch >/dev/null 2>&1; then
    finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    record_step_verdict "$label" "UNRUN" "$started" "$finished" 0 "$log"
    gate_unrun "$label — rch is not installed; compiling steps go through rch (AGENTS.md); log: $log"
    return
  fi
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
    rch exec -- cargo "$sub" -j "$CHECK_JOBS" "$@" >"$log" 2>&1
  local rc=$?
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t1="$(date +%s)"
  dur=$((t1 - t0))
  if [ "$rc" -eq 0 ]; then
    if ! grep -Fq 'Remote command finished: exit=0' "$log"; then
      record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
      gate_unrun "$label — exit 0 without 'Remote command finished: exit=0' completion marker; log: $log"
      return
    fi
    case "$sub" in
      check|clippy)
        if ! grep -Eq '^[[:space:]]*Finished ' "$log"; then
          record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
          gate_unrun "$label — exit 0 without cargo 'Finished' completion marker; log: $log"
          return
        fi
        ;;
      test)
        if [ "$label" = "test-list" ]; then
          if ! grep -Eq ': test$' "$log"; then
            record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
            gate_unrun "$label — exit 0 with zero listed tests; log: $log"
            return
          fi
        else
          local passed_total
          passed_total="$(awk '/^test result: ok\./ { for (i = 1; i <= NF; i++) if ($i == "passed;") sum += $(i - 1) } END { print sum + 0 }' "$log")"
          if ! grep -Eq '^test result: ok\. ' "$log" || [ "${passed_total:-0}" -le 0 ]; then
            record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
            gate_unrun "$label — exit 0 without a positive 'test result: ok. N passed' completion marker (passed=${passed_total:-0}); log: $log"
            return
          fi
        fi
        ;;
    esac
    record_step_verdict "$label" "PASS" "$started" "$finished" "$dur" "$log"
    gate_pass "$label"
    return
  fi
  local executed=0
  grep -q 'Remote command finished' "$log" && executed=1
  if [ "$rc" -eq 103 ] \
    || { [ "$executed" -eq 0 ] && { [ "$rc" -eq 100 ] || grep -Eq '^\[RCH\] .*(refusing local fallback|completion unconfirmed)' "$log"; }; }; then
    record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
    gate_unrun "$label — the rch offloader did not run the command (exit $rc: refused, no admissible worker, or lost the worker before execution; retryable, not a product verdict); log: $log"
  else
    record_step_verdict "$label" "FAIL" "$started" "$finished" "$dur" "$log"
    gate_fail "$label (exit $rc); log: $log"
    gate_diag "---- $label: last 40 lines of $log"
    tail -n 40 "$log" >&2
  fi
}

# run_gate <label> <script> <args...>
# A sub-gate that reports under the verdict contract itself (bead fa-37f):
# exit 0 is PASS; exit 2 with an UNRUN line in its transcript is UNRUN;
# anything else is FAIL, with the sub-gate's FAIL lines on stderr. Its full
# transcript goes to the step log.
run_gate() {
  local label="$1"; shift
  local log="$LOG_DIR/${label//[^A-Za-z0-9_.-]/_}.log"
  if try_reuse_step "$label" "$log"; then
    return
  fi
  local started t0 finished t1 dur
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t0="$(date +%s)"
  bash "$@" >"$log" 2>&1
  local rc=$?
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t1="$(date +%s)"
  dur=$((t1 - t0))
  local tally
  tally="$(grep -E '^[a-z-]+: [0-9]+ passed, [0-9]+ failed, [0-9]+ unrun$' "$log" | tail -n 1)"
  if [ "$rc" -eq 0 ]; then
    record_step_verdict "$label" "PASS" "$started" "$finished" "$dur" "$log"
    gate_pass "$label ($tally)"
  elif [ "$rc" -eq 2 ] && grep -q '^UNRUN ' "$log"; then
    record_step_verdict "$label" "UNRUN" "$started" "$finished" "$dur" "$log"
    gate_unrun "$label — $(grep -m1 '^UNRUN ' "$log" | cut -c7-); log: $log"
  else
    record_step_verdict "$label" "FAIL" "$started" "$finished" "$dur" "$log"
    gate_fail "$label (exit $rc; $tally); log: $log"
    grep '^FAIL ' "$log" >&2 || true
  fi
}

# ---- Rust -------------------------------------------------------------------
if [ "$BENCH_ONLY" -eq 1 ]; then
  cargo_build "bench-smoke" run -p fa-bench --bin fa-bench -- --smoke --json
  gate_verdict
fi

run_step "fmt" cargo fmt --all --check
cargo_build "check" check --workspace --all-targets
cargo_build "clippy" clippy --workspace --all-targets -- -D warnings
if [ "$QUICK" -eq 0 ]; then
  cargo_build "test-list" test --workspace -- --list
  cargo_build "test" test --workspace
  # Gate evidence witness & per-crate ratchet (bead fa-czx): listed tests match
  # executed tests, no source test disappears without `Retired-tests:`, and
  # per-crate negative test / assert counts do not decrease without
  # `Weakened-tests:`.
  run_gate "gate-evidence" "$ROOT/scripts/gate_evidence_check.sh" \
    "$ROOT" "$LOG_DIR/test-list.log" "$LOG_DIR/test.log" "$LOG_DIR/gate-evidence"
  # Invariant cross-check (bead fa-37f): every live clause's checker and
  # negative tests ran and passed in THIS run's test transcript; then the
  # same gate is shown able to fail on a planted rename.
  run_gate "invariants" "$ROOT/scripts/invariants_check.sh" \
    "$ROOT/registries/invariants.toml" "$LOG_DIR/test.log"
  run_gate "invariants-negative" "$ROOT/scripts/tests/invariants_negative.sh" \
    "$ROOT/registries/invariants.toml" "$LOG_DIR/test.log" "$LOG_DIR/invariants-negative"
  # The robot-schema fixture pin (plan Appendix D, bead fa-12x): `fa
  # robot-docs schema --json` equals registries/robot_schema/<v>.jsonl byte
  # for byte. Its own target, so a missing pin is a failure, never zero
  # matched tests.
  cargo_build "robot-schema" test -p fa-cli --test robot_schema
  # Fuzz corpora and targets smoke campaign (plan §16.8, bead fa-tre):
  # replays every checked-in seed and synthesized golden vector with
  # deterministic PRNG mutations across all 7 live decoder/parser targets.
  cargo_build "fuzz-smoke" run -p fa-fuzz --bin fa-fuzz-smoke
  # Operation-cost witness gate (plan Appendix G, beads fa-tu58 / fa-i5s):
  # verifies the 19 §17 manifests and all 9 counted kernel operation
  # witnesses. It measures no §17 workload: every §17 benchmark reports
  # `bench_unmeasured` until fa-ykbp (fa-e75k withdrew the earlier timings).
  cargo_build "bench-smoke" run -p fa-bench --bin fa-bench -- --smoke --json
  # Substrate conformance mutation gate (plan §16.3, bead fa-zy1):
  # inverts each #[test] in crates/fa-conformance/tests/substrate.rs via
  # FA_CONFORMANCE_INVERT and proves that exactly that test fails.
  run_gate "conformance-mutation" "$ROOT/scripts/conformance_mutation.sh"
  if cargo deny --version >/dev/null 2>&1; then
    run_step "deny" cargo deny check
  else
    gate_unrun "deny — cargo-deny is not installed; the dependency allowlists in deny.toml were not checked"
  fi
fi

# ---- Non-Rust gates ----------------------------------------------------------
if [ "$QUICK" -eq 0 ]; then
  run_gate "installer-integration" "$ROOT/scripts/tests/installer_integration.sh"
fi

# ubs: the bug scanner as a whole-project STATIC scan. It compiles nothing
# (`--no-cargo`): the compiler, clippy, test and deny verdicts are the
# explicit steps above, so this step never launches a bare cargo. Scanning
# the project root (not a file list) keeps the Cargo context, under which
# the scanner classifies integration-test `panic!` as a warning while a
# production `panic!` stays critical (verified 2026-10-10, fa-lbh thread:
# project scan exit 0 / 0 critical; a fixture with a src panic exits 1 / 1
# critical). The verdict is the exit code AND the critical count, and a
# positive file count is required, because ubs exits 0 on "nothing checked".
UBS_LOG="$LOG_DIR/ubs.log"
if try_reuse_step "ubs" "$UBS_LOG"; then
  :
elif ! command -v ubs >/dev/null 2>&1; then
  record_step_verdict "ubs" "UNRUN" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$UBS_LOG"
  gate_unrun "ubs — ubs is not installed"
elif [ -z "$(git ls-files --cached --others --exclude-standard -- '*.rs')" ]; then
  record_step_verdict "ubs" "UNRUN" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$UBS_LOG"
  gate_unrun "ubs — no tracked Rust files; nothing was checked"
else
  UBS_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  UBS_T0="$(date +%s)"
  UBS_RC=0
  ubs --only=rust --no-cargo --no-color "$ROOT" >"$UBS_LOG" 2>&1 || UBS_RC=$?
  UBS_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  UBS_DUR=$(( $(date +%s) - UBS_T0 ))
  # A verdict needs a positive file count AND a numeric critical summary;
  # "Files scanned: 0" or a missing summary is "nothing was checked".
  if ! grep -Eq '^[[:space:]]*Files scanned:[[:space:]]*[1-9][0-9]*[[:space:]]*$' "$UBS_LOG" \
    || ! grep -Eq '^[[:space:]]*Critical issues:[[:space:]]*[0-9]+[[:space:]]*$' "$UBS_LOG"; then
    record_step_verdict "ubs" "UNRUN" "$UBS_STARTED" "$UBS_FINISHED" "$UBS_DUR" "$UBS_LOG"
    gate_unrun "ubs — no positive file count or no critical-issue summary in the scanner output (exit $UBS_RC); nothing was checked; log: $UBS_LOG"
  elif [ "$UBS_RC" -eq 0 ] && ! grep -Eq '^[[:space:]]*Critical issues:[[:space:]]*[1-9][0-9]*[[:space:]]*$' "$UBS_LOG"; then
    record_step_verdict "ubs" "PASS" "$UBS_STARTED" "$UBS_FINISHED" "$UBS_DUR" "$UBS_LOG"
    gate_pass "ubs (static scan of the project, 0 critical; $(grep -m1 'Files scanned:' "$UBS_LOG" | tr -s ' '))"
  else
    record_step_verdict "ubs" "FAIL" "$UBS_STARTED" "$UBS_FINISHED" "$UBS_DUR" "$UBS_LOG"
    gate_fail "ubs — critical findings or scanner failure (exit $UBS_RC); log: $UBS_LOG"
    grep -E 'CRITICAL|Critical issues' "$UBS_LOG" >&2 || true
  fi
fi

# Lint our scripts with shellcheck (the gate library is adopted verbatim and exempt).
mapfile -t SHELL_FILES < <(git ls-files --cached --others --exclude-standard -- 'scripts/*.sh' | grep -v 'scripts/lib/gate_verdict.sh')
SHELL_FILES=(install.sh "${SHELL_FILES[@]}")
if [ "${#SHELL_FILES[@]}" -gt 0 ]; then
  run_step "shellcheck" shellcheck -S warning "${SHELL_FILES[@]}"
fi
run_gate "gate-evidence-negative" "$ROOT/scripts/tests/gate_evidence_negative.sh" \
  "$ROOT" "$LOG_DIR/gate-evidence-negative"

# Registries: every TOML under registries/ is consumed by compiled code and
# validated by the fa-registry / fa-model tests, which `test` above ran. This
# step asserts the closure: a registry file nothing embeds is a dead artifact.
if ! try_reuse_step "registries" ""; then
  REG_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  REG_FAIL=0
  for f in registries/*.toml; do
    base="$(basename "$f")"
    if ! grep -rq "registries/$base" crates/ --include='*.rs'; then
      gate_fail "registry $base is not embedded by any crate (dead artifact)"
      REG_FAIL=1
    fi
  done
  REG_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$REG_FAIL" -eq 0 ]; then
    record_step_verdict "registries" "PASS" "$REG_STARTED" "$REG_FINISHED" 0 ""
    gate_pass "registries — every registries/*.toml is embedded by code"
  else
    record_step_verdict "registries" "FAIL" "$REG_STARTED" "$REG_FINISHED" 0 ""
  fi
fi
if [ "$QUICK" -eq 0 ]; then
  cargo_build "registry-check" test -p registry-check --bins
fi

# Forbidden dependencies (plan §1 constraint 1): every first-party crate may
# depend DIRECTLY only on first-party crates and the admitted foundations. The
# foundations' own transitive dependencies (serde, tokio, … inside asupersync,
# frankengraphdb, franken_networkx, fastmcp-rust, frankensympy) are confined to their pinned
# closures and are deny.toml's business (cargo deny), not this tripwire's.
# What this admits that a lockfile grep would not: foundation-transitive paths.
# What it still catches: any new direct dependency of fa-* on anything else.
DEPS_LOG="$LOG_DIR/forbidden-deps.log"
if try_reuse_step "forbidden-deps" "$DEPS_LOG"; then
  :
elif ! command -v jq >/dev/null 2>&1; then
  record_step_verdict "forbidden-deps" "UNRUN" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$DEPS_LOG"
  gate_unrun "forbidden-deps — jq is not installed; first-party direct dependencies were not checked"
else
  DEPS_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Two steps, each checked: a failed `cargo metadata` must not become an
  # empty edge list that jq turns into a green zero-edge verdict.
  if cargo metadata --no-deps --format-version 1 >"$DEPS_LOG.json" 2>>"$DEPS_LOG" \
    && jq -r '.packages[] | .name as $p | .dependencies[] | "\($p) \(.name)"' <"$DEPS_LOG.json" >"$DEPS_LOG.pairs" 2>>"$DEPS_LOG" \
    && [ -s "$DEPS_LOG.pairs" ]; then
    DEP_FAIL=0
    while read -r pkg dep; do
      case "$dep" in
        fa|fa-*|asupersync|fgdb|fgdb-*|fnx-*|fastmcp-rust|fastmcp-*|fsym-bigint|fsym-rational|fsym-budget) ;;
        *)
          gate_fail "forbidden-deps — $pkg depends directly on \`$dep\`, which is neither first-party nor a foundation"
          DEP_FAIL=1
          ;;
      esac
    done <"$DEPS_LOG.pairs"
    if [ "$DEP_FAIL" -eq 0 ]; then
      record_step_verdict "forbidden-deps" "PASS" "$DEPS_STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$DEPS_LOG"
      gate_pass "forbidden-deps — every first-party direct dependency is first-party or a foundation ($(wc -l <"$DEPS_LOG.pairs" | tr -d ' ') edges)"
    else
      record_step_verdict "forbidden-deps" "FAIL" "$DEPS_STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$DEPS_LOG"
    fi
  else
    record_step_verdict "forbidden-deps" "UNRUN" "$DEPS_STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$DEPS_LOG"
    gate_unrun "forbidden-deps — cargo metadata or jq did not produce the dependency edges (offloader, toolchain, or empty output); log: $DEPS_LOG"
  fi
fi

# Resolved foundation sources, singleton type identities and production feature
# ceilings, separately for each shipped posture. Metadata's workspace feature
# union is never attributed to one posture. Preserve the direct-name tripwire
# above; this gate adds resolved identities, not a replacement exception list.
run_gate "foundations" "$ROOT/scripts/check-forbidden-deps.sh" "$LOG_DIR/foundations"
run_step "foundations-negative" python3 -B "$ROOT/scripts/tests/foundation_negative.py" \
  "$LOG_DIR/foundations" "$LOG_DIR/foundations-negative"
run_gate "doctrine" "$ROOT/scripts/doctrine_check.sh" "$ROOT" "$LOG_DIR/foundations"
run_gate "doctrine-negative" "$ROOT/scripts/tests/doctrine_negative.sh" \
  "$LOG_DIR/foundations" "$LOG_DIR/doctrine-negative"

# The reference model must not reach the production arithmetic through a
# registry dependency. Observed before fa-pri: fa-reference -> fa-registry ->
# fa-money. Check the actual resolved normal closure, not just direct edges.
REFERENCE_LOG="$LOG_DIR/reference-boundary.log"
if try_reuse_step "reference-boundary" "$REFERENCE_LOG"; then
  :
elif cargo tree --locked -p fa-reference --edges normal --prefix none --format '{p}' >"$REFERENCE_LOG" 2>"$REFERENCE_LOG.stderr" \
  && [ -s "$REFERENCE_LOG" ]; then
  REFERENCE_FAIL=0
  while read -r pkg rest; do
    case "$pkg" in
      fa-reference|fa-registry|fa-time) ;;
      *) gate_fail "reference-boundary — production dependency in oracle closure: $pkg $rest"; REFERENCE_FAIL=1 ;;
    esac
  done <"$REFERENCE_LOG"
  if [ "$REFERENCE_FAIL" -eq 0 ]; then
    record_step_verdict "reference-boundary" "PASS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$REFERENCE_LOG"
    gate_pass "reference-boundary — oracle imports only registry data and calendar primitives"
  else
    record_step_verdict "reference-boundary" "FAIL" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$REFERENCE_LOG"
  fi
else
  record_step_verdict "reference-boundary" "UNRUN" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 "$REFERENCE_LOG"
  gate_unrun "reference-boundary — cargo tree did not resolve the oracle closure; log: $REFERENCE_LOG.stderr"
fi

# Workspace topology (bead fa-37f): the cargo graph obeys the layer order of
# registries/workspace_topology.toml (plan §18.1) and every crate has a row;
# then the same gate is shown able to fail on planted defects.
TOPOLOGY_META="$LOG_DIR/topology-metadata.json"
if ! command -v jq >/dev/null 2>&1; then
  gate_unrun "topology — jq is not installed; the cargo graph was not read"
elif cargo metadata --no-deps --format-version 1 >"$TOPOLOGY_META" 2>"$TOPOLOGY_META.stderr" \
  && [ -s "$TOPOLOGY_META" ]; then
  run_gate "topology" "$ROOT/scripts/topology_check.sh" \
    "$ROOT/registries/workspace_topology.toml" "$TOPOLOGY_META"
  run_gate "topology-negative" "$ROOT/scripts/tests/topology_negative.sh" \
    "$ROOT/registries/workspace_topology.toml" "$TOPOLOGY_META" "$LOG_DIR/topology-negative"
else
  gate_unrun "topology — cargo metadata did not produce the workspace graph; log: $TOPOLOGY_META.stderr"
fi

gate_verdict
