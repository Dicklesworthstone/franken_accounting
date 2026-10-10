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
# NOT COVERED YET (explicitly; a 0 exit here is not whole-chain G0 closure):
#   the AGENTS file-coverage closure, the claims lint, verb parity
#   (verbs.toml vs CLI vs MCP), the robot-schema fixture pin, a registry
#   schema checker (the registries are validated by the fa-registry and
#   fa-model tests, not by this script), and a forbidden-deps check that
#   distinguishes permitted foundation transitive paths from new paths
#   (cargo deny is the real gate; the grep below is a tripwire). Bead fa-lbh
#   stays open until those exist or are exempted with a reason.
#
# Usage: bash scripts/check.sh            # everything
#        bash scripts/check.sh --quick    # fmt, check, clippy, ubs (no tests, no deny)
#        CHECK_LOG_DIR=<dir> keeps the per-step logs somewhere other than a temp dir.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'FAIL check.sh: unknown argument %s\n' "$arg"; exit 2 ;;
  esac
done

LOG_DIR="${CHECK_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/fa-check.XXXXXX")}"
mkdir -p "$LOG_DIR"

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
#   "[RCH] … refusing local fallback" or exit 100 (network/SSH) with NO
#   "Remote command finished" line (nothing executed)                → UNRUN
#   anything else nonzero, including 101/102 after execution         → FAIL
run_step() {
  local label="$1"; shift
  local log="$LOG_DIR/${label//[^A-Za-z0-9_.-]/_}.log"
  if ! command -v "$1" >/dev/null 2>&1; then
    gate_unrun "$label — $1 is not installed; did not run; log: $log"
    return
  fi
  "$@" >"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    gate_pass "$label"
    return
  fi
  local executed=0
  grep -q 'Remote command finished' "$log" && executed=1
  if [ "$rc" -eq 103 ] \
    || { [ "$executed" -eq 0 ] && { [ "$rc" -eq 100 ] || grep -q '^\[RCH\] .*refusing local fallback' "$log"; }; }; then
    gate_unrun "$label — the rch offloader did not run the command (exit $rc: refused, no admissible worker, or lost the worker before execution; retryable, not a product verdict); log: $log"
  else
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
CHECK_JOBS="${CHECK_JOBS:-2}"
cargo_build() {
  local label="$1" sub="$2"; shift 2
  if command -v rch >/dev/null 2>&1; then
    RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
      run_step "$label" rch exec -- cargo "$sub" -j "$CHECK_JOBS" "$@"
  else
    gate_unrun "$label — rch is not installed; compiling steps go through rch (AGENTS.md)"
  fi
}

# ---- Rust -------------------------------------------------------------------
run_step "fmt" cargo fmt --all --check
cargo_build "check" check --workspace --all-targets
cargo_build "clippy" clippy --workspace --all-targets -- -D warnings
if [ "$QUICK" -eq 0 ]; then
  cargo_build "test" test --workspace
  if cargo deny --version >/dev/null 2>&1; then
    run_step "deny" cargo deny check
  else
    gate_unrun "deny — cargo-deny is not installed; the dependency allowlists in deny.toml were not checked"
  fi
fi

# ---- Non-Rust gates ----------------------------------------------------------
# ubs: the bug scanner as a whole-project STATIC scan. It compiles nothing
# (`--no-cargo`): the compiler, clippy, test and deny verdicts are the
# explicit steps above, so this step never launches a bare cargo. Scanning
# the project root (not a file list) keeps the Cargo context, under which
# the scanner classifies integration-test `panic!` as a warning while a
# production `panic!` stays critical (verified 2026-10-10, fa-lbh thread:
# project scan exit 0 / 0 critical; a fixture with a src panic exits 1 / 1
# critical). The verdict is the exit code AND the critical count, and a
# positive file count is required, because ubs exits 0 on "nothing checked".
if ! command -v ubs >/dev/null 2>&1; then
  gate_unrun "ubs — ubs is not installed"
elif [ -z "$(git ls-files --cached --others --exclude-standard -- '*.rs')" ]; then
  gate_unrun "ubs — no tracked Rust files; nothing was checked"
else
  UBS_LOG="$LOG_DIR/ubs.log"
  UBS_RC=0
  ubs --only=rust --no-cargo --no-color "$ROOT" >"$UBS_LOG" 2>&1 || UBS_RC=$?
  # A verdict needs a positive file count AND a numeric critical summary;
  # "Files scanned: 0" or a missing summary is "nothing was checked".
  if ! grep -Eq '^[[:space:]]*Files scanned:[[:space:]]*[1-9][0-9]*[[:space:]]*$' "$UBS_LOG" \
    || ! grep -Eq '^[[:space:]]*Critical issues:[[:space:]]*[0-9]+[[:space:]]*$' "$UBS_LOG"; then
    gate_unrun "ubs — no positive file count or no critical-issue summary in the scanner output (exit $UBS_RC); nothing was checked; log: $UBS_LOG"
  elif [ "$UBS_RC" -eq 0 ] && ! grep -Eq '^[[:space:]]*Critical issues:[[:space:]]*[1-9][0-9]*[[:space:]]*$' "$UBS_LOG"; then
    gate_pass "ubs (static scan of the project, 0 critical; $(grep -m1 'Files scanned:' "$UBS_LOG" | tr -s ' '))"
  else
    gate_fail "ubs — critical findings or scanner failure (exit $UBS_RC); log: $UBS_LOG"
    grep -E 'CRITICAL|Critical issues' "$UBS_LOG" >&2 || true
  fi
fi

# Lint our scripts with shellcheck (the gate library is adopted verbatim and exempt).
mapfile -t SHELL_FILES < <(git ls-files --cached --others --exclude-standard -- 'scripts/*.sh' | grep -v 'scripts/lib/gate_verdict.sh')
if [ "${#SHELL_FILES[@]}" -gt 0 ]; then
  run_step "shellcheck" shellcheck -S warning "${SHELL_FILES[@]}"
fi

# Registries: every TOML under registries/ is consumed by compiled code and
# validated by the fa-registry / fa-model tests, which `test` above ran. This
# step asserts the closure: a registry file nothing embeds is a dead artifact.
REG_FAIL=0
for f in registries/*.toml; do
  base="$(basename "$f")"
  if ! grep -rq "registries/$base" crates/ --include='*.rs'; then
    gate_fail "registry $base is not embedded by any crate (dead artifact)"
    REG_FAIL=1
  fi
done
[ "$REG_FAIL" -eq 0 ] && gate_pass "registries — every registries/*.toml is embedded by code"

# Forbidden dependencies (plan §1 constraint 1): every first-party crate may
# depend DIRECTLY only on first-party crates and the four foundations. The
# foundations' own transitive dependencies (serde, tokio, … inside asupersync,
# frankengraphdb, franken_networkx, fastmcp-rust) are confined to their pinned
# closures and are deny.toml's business (cargo deny), not this tripwire's.
# What this admits that a lockfile grep would not: foundation-transitive paths.
# What it still catches: any new direct dependency of fa-* on anything else.
if ! command -v jq >/dev/null 2>&1; then
  gate_unrun "forbidden-deps — jq is not installed; first-party direct dependencies were not checked"
else
  DEPS_LOG="$LOG_DIR/forbidden-deps.log"
  # Two steps, each checked: a failed `cargo metadata` must not become an
  # empty edge list that jq turns into a green zero-edge verdict.
  if cargo metadata --no-deps --format-version 1 >"$DEPS_LOG.json" 2>>"$DEPS_LOG" \
    && jq -r '.packages[] | .name as $p | .dependencies[] | "\($p) \(.name)"' <"$DEPS_LOG.json" >"$DEPS_LOG.pairs" 2>>"$DEPS_LOG" \
    && [ -s "$DEPS_LOG.pairs" ]; then
    DEP_FAIL=0
    while read -r pkg dep; do
      case "$dep" in
        fa|fa-*|asupersync|fgdb|fgdb-*|fnx-*|fastmcp-rust|fastmcp-*) ;;
        *)
          gate_fail "forbidden-deps — $pkg depends directly on \`$dep\`, which is neither first-party nor a foundation"
          DEP_FAIL=1
          ;;
      esac
    done <"$DEPS_LOG.pairs"
    if [ "$DEP_FAIL" -eq 0 ]; then
      gate_pass "forbidden-deps — every first-party direct dependency is first-party or a foundation ($(wc -l <"$DEPS_LOG.pairs" | tr -d ' ') edges)"
    fi
  else
    gate_unrun "forbidden-deps — cargo metadata or jq did not produce the dependency edges (offloader, toolchain, or empty output); log: $DEPS_LOG"
  fi
fi

gate_verdict
