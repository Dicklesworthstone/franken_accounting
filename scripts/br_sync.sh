#!/usr/bin/env bash
# =============================================================================
# br_sync.sh — the one tracked Beads-export and attribution path (bead fa-u7u)
# =============================================================================
# Adopted from frankengraphdb. Flushes and verifies the exact expected bead ID
# set against HEAD:.beads/issues.jsonl before staging JSONL.
#
# Usage:
#   bash scripts/br_sync.sh fa-123 [fa-456 ...]
# =============================================================================

set -uo pipefail

if [ "$#" -eq 0 ]; then
  printf 'usage: bash scripts/br_sync.sh <expected-bead-id> [<expected-bead-id> ...]\n' >&2
  printf 'No export ran: the whole-file exporter requires an explicit record-id intent.\n' >&2
  exit 64
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANDING_LIB="${FA_LANDING_LIB:-${FGDB_LANDING_LIB:-$ROOT/scripts/lib/landing_lease.sh}}"
BR_BIN="${FA_BR_BIN:-${FGDB_BR_BIN:-br}}"
EXPORT_HOLDER="br-sync-$$"
EXPORT_LEASE_HELD=0
EXPORT_INTENT_RC=65
JSONL_REL=".beads/issues.jsonl"
EXPECTED_IDS=""
EXPORT_ROOT=""
EXPORT_BASE_HEAD=""
EXPORT_BASE_HAS_JSONL=0

print_id_set() {
  [ -n "$1" ] && printf '%s\n' "$1"
}

id_set_count() {
  if [ -z "$1" ]; then
    printf '0\n'
  else
    printf '%s\n' "$1" | wc -l | tr -d ' '
  fi
}

format_id_set() {
  if [ -z "$1" ]; then
    printf '    (none)\n'
  else
    local id
    while IFS= read -r id; do
      printf '    %s\n' "$id"
    done <<<"$1"
  fi
}

prepare_expected_ids() {
  local id supplied_count unique_count

  for id in "$@"; do
    case "$id" in
      "" | *[!A-Za-z0-9._-]* | [!A-Za-z0-9]*)
        printf 'BEADS EXPORT INTENT INVALID — not a Bead id: %s\n' "$id" >&2
        return 64
        ;;
    esac
  done

  supplied_count="$#"
  EXPECTED_IDS="$(printf '%s\n' "$@" | LC_ALL=C sort -u)"
  unique_count="$(id_set_count "$EXPECTED_IDS")"
  if [ "$unique_count" -ne "$supplied_count" ]; then
    printf 'BEADS EXPORT INTENT INVALID — duplicate record ids were supplied.\n' >&2
    format_id_set "$EXPECTED_IDS" >&2
    return 64
  fi
  return 0
}

resolve_export_tree() {
  local base_entry

  command -v git >/dev/null 2>&1 || {
    printf 'BEADS EXPORT INTENT UNCHECKED — git is unavailable; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }
  command -v jq >/dev/null 2>&1 || {
    printf 'BEADS EXPORT INTENT UNCHECKED — jq is unavailable; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }

  EXPORT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    printf 'BEADS EXPORT INTENT UNCHECKED — not inside a Git worktree; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }
  EXPORT_BASE_HEAD="$(git -C "$EXPORT_ROOT" rev-parse HEAD 2>/dev/null)" || {
    printf 'BEADS EXPORT INTENT UNCHECKED — HEAD does not resolve; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }

  if git -C "$EXPORT_ROOT" cat-file -e "$EXPORT_BASE_HEAD:$JSONL_REL" 2>/dev/null; then
    EXPORT_BASE_HAS_JSONL=1
    if [ ! -f "$EXPORT_ROOT/$JSONL_REL" ] || [ ! -r "$EXPORT_ROOT/$JSONL_REL" ]; then
      printf 'BEADS EXPORT INTENT UNCHECKED — base commit tracks %s, but the worktree copy is absent or unreadable; no export ran.\n' \
        "$JSONL_REL" >&2
      return "$EXPORT_INTENT_RC"
    fi
  else
    base_entry="$(git -C "$EXPORT_ROOT" ls-tree --name-only "$EXPORT_BASE_HEAD" -- "$JSONL_REL" 2>/dev/null)" || {
      printf 'BEADS EXPORT INTENT UNCHECKED — the base tree could not prove whether %s exists; no export ran.\n' \
        "$JSONL_REL" >&2
      return "$EXPORT_INTENT_RC"
    }
    if [ -n "$base_entry" ]; then
      printf 'BEADS EXPORT INTENT UNCHECKED — the base tree contains %s but its object is unreadable; no export ran.\n' \
        "$JSONL_REL" >&2
      return "$EXPORT_INTENT_RC"
    fi
    EXPORT_BASE_HAS_JSONL=0
    if [ -e "$EXPORT_ROOT/$JSONL_REL" ] || [ -L "$EXPORT_ROOT/$JSONL_REL" ]; then
      if [ ! -f "$EXPORT_ROOT/$JSONL_REL" ] || [ ! -r "$EXPORT_ROOT/$JSONL_REL" ]; then
        printf 'BEADS EXPORT INTENT UNCHECKED — first-export candidate %s is not a readable regular file; no export ran.\n' \
          "$JSONL_REL" >&2
        return "$EXPORT_INTENT_RC"
      fi
    fi
  fi
  return 0
}

validated_record_ids() {
  jq -r '
      if type == "object"
        and (.id | type == "string")
        and (.id | test("^[A-Za-z0-9][A-Za-z0-9._-]*$"))
      then .id
      else error("changed issues.jsonl row has no valid string id")
      end
    ' \
    | LC_ALL=C sort -u
}

changed_record_ids() {
  local base="$1"

  if [ "$EXPORT_BASE_HAS_JSONL" -eq 0 ]; then
    if [ ! -e "$EXPORT_ROOT/$JSONL_REL" ] && [ ! -L "$EXPORT_ROOT/$JSONL_REL" ]; then
      return 0
    fi
    if [ ! -f "$EXPORT_ROOT/$JSONL_REL" ] || [ ! -r "$EXPORT_ROOT/$JSONL_REL" ]; then
      printf 'first-export candidate %s stopped being a readable regular file\n' \
        "$JSONL_REL" >&2
      return 1
    fi
    validated_record_ids <"$EXPORT_ROOT/$JSONL_REL"
    return $?
  fi

  git -C "$EXPORT_ROOT" diff --no-ext-diff --unified=0 "$base" -- "$JSONL_REL" \
    | awk '
        /^(diff --git |index |--- |\+\+\+ |@@ )/ { next }
        /^\\ No newline at end of file$/ { next }
        /^[+-]\{/ { print substr($0, 2); next }
        {
          print "unexpected non-record line in issues.jsonl diff: " $0 >"/dev/stderr"
          bad = 1
        }
        END { exit bad }
      ' \
    | validated_record_ids
}

dirty_record_count() {
  local status
  status="$("$BR_BIN" sync --status --json)" || return 1
  printf '%s\n' "$status" | jq -er '
    if (.dirty_count | type) == "number"
      and .dirty_count >= 0
      and .dirty_count == (.dirty_count | floor)
    then .dirty_count
    else error("sync status omitted a non-negative integer dirty_count")
    end
  '
}

refuse_existing_foreign_ids() {
  local existing unexpected
  existing="$(changed_record_ids "$EXPORT_BASE_HEAD")" || {
    printf 'BEADS EXPORT INTENT UNCHECKED — existing JSONL delta could not be parsed; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }
  if ! unexpected="$(
    LC_ALL=C comm -23 \
      <(print_id_set "$existing") \
      <(print_id_set "$EXPECTED_IDS")
  )"; then
    printf 'BEADS EXPORT INTENT UNCHECKED — record-id set comparison failed; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  fi
  if [ -n "$unexpected" ]; then
    {
      printf 'BEADS EXPORT INTENT REFUSED — the existing JSONL delta contains undeclared record ids.\n'
      printf '  expected:\n'
      format_id_set "$EXPECTED_IDS"
      printf '  undeclared:\n'
      format_id_set "$unexpected"
      printf 'No export ran. Coordinate with the record owners or declare an explicit co-landing.\n'
    } >&2
    return "$EXPORT_INTENT_RC"
  fi
  return 0
}

refuse_impossible_dirty_count() {
  local dirty expected_count
  dirty="$(dirty_record_count)" || {
    printf 'BEADS EXPORT INTENT UNCHECKED — br sync status could not report dirty_count; no export ran.\n' >&2
    return "$EXPORT_INTENT_RC"
  }
  expected_count="$(id_set_count "$EXPECTED_IDS")"
  if [ "$dirty" -gt "$expected_count" ]; then
    {
      printf 'BEADS EXPORT INTENT REFUSED — %s dirty DB records cannot fit the %s declared id(s).\n' \
        "$dirty" "$expected_count"
      printf '  expected:\n'
      format_id_set "$EXPECTED_IDS"
      printf 'No export ran. Inspect the pending record owners before widening the intent.\n'
    } >&2
    return "$EXPORT_INTENT_RC"
  fi
  return 0
}

verify_exported_ids() {
  local observed head_after missing_declared unexpected_observed
  observed="$(changed_record_ids "$EXPORT_BASE_HEAD")" || {
    printf 'BEADS EXPORT ATTRIBUTION FAILED — the resulting JSONL delta could not be parsed.\n' >&2
    return "$EXPORT_INTENT_RC"
  }
  head_after="$(git -C "$EXPORT_ROOT" rev-parse HEAD 2>/dev/null)" || {
    printf 'BEADS EXPORT ATTRIBUTION FAILED — HEAD stopped resolving after export.\n' >&2
    return "$EXPORT_INTENT_RC"
  }

  if [ "$head_after" != "$EXPORT_BASE_HEAD" ]; then
    {
      printf 'BEADS EXPORT ATTRIBUTION FAILED — HEAD moved during the export window.\n'
      printf '  HEAD before: %s\n' "$EXPORT_BASE_HEAD"
      printf '  HEAD after:  %s\n' "$head_after"
      printf 'Do not stage the JSONL until its record-id delta is re-audited.\n'
    } >&2
    return "$EXPORT_INTENT_RC"
  fi

  if [ "$observed" != "$EXPECTED_IDS" ]; then
    if ! missing_declared="$(
      LC_ALL=C comm -13 \
        <(print_id_set "$observed") \
        <(print_id_set "$EXPECTED_IDS")
    )"; then
      printf 'BEADS EXPORT ATTRIBUTION FAILED — missing-id set comparison failed.\n' >&2
      return "$EXPORT_INTENT_RC"
    fi
    if ! unexpected_observed="$(
      LC_ALL=C comm -23 \
        <(print_id_set "$observed") \
        <(print_id_set "$EXPECTED_IDS")
    )"; then
      printf 'BEADS EXPORT ATTRIBUTION FAILED — unexpected-id set comparison failed.\n' >&2
      return "$EXPORT_INTENT_RC"
    fi
    {
      printf 'BEADS EXPORT ATTRIBUTION FAILED — exported record ids differ from the declared intent.\n'
      printf '  expected:\n'
      format_id_set "$EXPECTED_IDS"
      printf '  observed:\n'
      format_id_set "$observed"
      printf '  missing declared ids:\n'
      format_id_set "$missing_declared"
      printf '  undeclared observed ids:\n'
      format_id_set "$unexpected_observed"
      printf 'The JSONL may have moved, but no commit is authorized. Re-run only after coordinating every observed id.\n'
    } >&2
    return "$EXPORT_INTENT_RC"
  fi

  printf 'BEADS EXPORT RECORD IDS (exact):\n'
  format_id_set "$observed"
  return 0
}

flush_export() {
  refuse_existing_foreign_ids || return $?
  refuse_impossible_dirty_count || return $?
  "$BR_BIN" sync --flush-only || return $?
  verify_exported_ids
}

release_export_lease() {
  [ "$EXPORT_LEASE_HELD" -eq 1 ] || return 0
  EXPORT_LEASE_HELD=0
  landing_lease_release "$EXPORT_HOLDER" || true
}

defer_export() {
  {
    printf 'DEFERRED BEADS EXPORT — a live gate owns the landing lease.\n\n'
    printf '  holder  : %s\n' "${LANDING_HOLDER:-?}"
    printf '  pid     : %s (%s)\n' \
      "${LANDING_PID:-none recorded}" "${LANDING_LIVENESS:-?}"
    printf '  held for: %s minute(s) (ttl label %s)\n' \
      "${LANDING_AGE_MIN:-?}" "${LANDING_TTL_MIN:-?}"
    printf '  evidence: %s\n\n' "${LANDING_EVIDENCE:-none recorded}"
    printf 'No tracked file was written. Beads mutations remain live in the shared DB.\n'
    printf 'Retry the same explicit record-id set after the gate exits.\n'
  } >&2
  return 75
}

warn_and_flush() {
  local state="$1"
  local detail="$2"
  {
    printf 'BEADS EXPORT LEASE WARNING — proceeding under fail-open policy.\n\n'
    printf '  state   : %s\n' "$state"
    printf '  holder  : %s\n' "${LANDING_HOLDER:-?}"
    printf '  pid     : %s (%s)\n' \
      "${LANDING_PID:-none recorded}" "${LANDING_LIVENESS:-?}"
    printf '  evidence: %s\n\n' "$detail"
  } >&2
  flush_export
}

prepare_expected_ids "$@" || exit $?
resolve_export_tree || exit $?

if [ ! -r "$LANDING_LIB" ]; then
  warn_and_flush UNREADABLE "landing-lease library is missing or unreadable at $LANDING_LIB"
  exit $?
fi

# shellcheck source=lib/landing_lease.sh
if ! . "$LANDING_LIB" 2>/dev/null; then
  warn_and_flush UNREADABLE "landing-lease library at $LANDING_LIB could not be sourced"
  exit $?
fi

landing_lease_acquire "$EXPORT_HOLDER" 2
acquire_rc=$?
if [ "$acquire_rc" -eq 0 ]; then
  EXPORT_LEASE_HELD=1
  trap release_export_lease EXIT
  flush_export
  flush_rc=$?
  release_export_lease
  trap - EXIT
  exit "$flush_rc"
fi

if ! landing_lease_state >/dev/null 2>&1; then
  warn_and_flush UNREADABLE \
    "atomic landing-lease acquire failed with exit $acquire_rc, and landing_lease_state failed"
  exit $?
fi

case "${LANDING_STATE:-}" in
  FREE)
    warn_and_flush UNAVAILABLE \
      "atomic landing-lease acquire failed with exit $acquire_rc while the state reads FREE"
    exit $?
    ;;
  BINDING)
    defer_export
    exit $?
    ;;
  BREAKABLE)
    warn_and_flush BREAKABLE "${LANDING_EVIDENCE:-the recorded holder is gone}"
    exit $?
    ;;
  UNREADABLE)
    warn_and_flush UNREADABLE "${LANDING_EVIDENCE:-the lease could not be read}"
    exit $?
    ;;
  *)
    warn_and_flush UNKNOWN "unrecognised lease state '${LANDING_STATE:-}'"
    exit $?
    ;;
esac
