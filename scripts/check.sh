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
# PASS when the command exits 0; UNRUN when it did not execute (the rch shim
# refused the offload — exit 103 or its marker in the log — or the tool is
# missing); FAIL otherwise. stdout+stderr of the step go to its log; only the
# verdict line goes to our stdout.
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
  elif [ "$rc" -eq 103 ] || grep -q '^\[RCH\]' "$log"; then
    gate_unrun "$label — the rch offloader did not run the command (refused or lost the worker; retryable, not a product verdict); log: $log"
  else
    gate_fail "$label (exit $rc); log: $log"
    gate_diag "---- $label: last 40 lines of $log"
    tail -n 40 "$log" >&2
  fi
}

# ---- Rust -------------------------------------------------------------------
run_step "fmt" cargo fmt --all --check
run_step "check" cargo check --workspace --all-targets
run_step "clippy" cargo clippy --workspace --all-targets -- -D warnings
if [ "$QUICK" -eq 0 ]; then
  run_step "test" cargo test --workspace
  if cargo deny --version >/dev/null 2>&1; then
    run_step "deny" cargo deny check
  else
    gate_unrun "deny — cargo-deny is not installed; the dependency allowlists in deny.toml were not checked"
  fi
fi

# ---- Non-Rust gates ----------------------------------------------------------
# ubs: the bug scanner over every tracked Rust file. ubs exits 0 on "nothing
# checked", so an empty file list is UNRUN here, not a pass.
mapfile -t RUST_FILES < <(git ls-files --cached --others --exclude-standard -- '*.rs')
if [ "${#RUST_FILES[@]}" -eq 0 ]; then
  gate_unrun "ubs — no tracked Rust files; nothing was checked"
elif ! command -v ubs >/dev/null 2>&1; then
  gate_unrun "ubs — ubs is not installed"
else
  UBS_LOG="$LOG_DIR/ubs.log"
  if ubs "${RUST_FILES[@]}" >"$UBS_LOG" 2>&1 && ! grep -q 'Critical issues:  *[1-9]' "$UBS_LOG"; then
    gate_pass "ubs (${#RUST_FILES[@]} files, 0 critical)"
  else
    gate_fail "ubs — critical findings or scanner failure; log: $UBS_LOG"
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
  if cargo metadata --no-deps --format-version 1 2>>"$DEPS_LOG" \
    | jq -r '.packages[] | .name as $p | .dependencies[] | "\($p) \(.name)"' >"$DEPS_LOG.pairs" 2>>"$DEPS_LOG"; then
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
    gate_unrun "forbidden-deps — cargo metadata did not run (offloader or toolchain); log: $DEPS_LOG"
  fi
fi

gate_verdict
