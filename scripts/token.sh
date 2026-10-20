#!/usr/bin/env bash
# =============================================================================
# token.sh — dependency-free advisory tokens for the franken_accounting swarm
# =============================================================================
# Adopted from frankengraphdb (bead fa-u7u).
#
# Usage:
#   token.sh acquire <token> <your-name> [ttl_minutes] [holder_pid] -> exit 0 = you hold it
#   token.sh renew   <token> <your-name> [ttl_minutes] [holder_pid] # your OWN hold only
#   token.sh release <token> <your-name>
#   token.sh status  [token]
#   token.sh steal   <token> <your-name>   # liveness-gated
# =============================================================================

set -uo pipefail

DIR="${FA_TOKEN_DIR:-${FGDB_TOKEN_DIR:-${TMPDIR:-/tmp}/fa_swarm/tokens}}"
mkdir -p "$DIR"

cmd="${1:-status}"
tok="${2:-}"
who="${3:-unknown}"
ttl="${4:-45}"
holder_pid="${5:-$PPID}"

lock="$DIR/$tok.lock"
meta="$lock/holder"

now() { date +%s; }

pid_starttime() {
  local pid="$1" stat rest
  [ -r "/proc/$pid/stat" ] || return 1
  stat="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  rest="${stat##*) }"
  # shellcheck disable=SC2086
  set -- $rest
  [ "$#" -ge 20 ] || return 1
  printf '%s\n' "${20}"
}

read_meta() {
  M_WHO="$(sed -n 1p "$meta" 2>/dev/null)"
  M_EPOCH="$(sed -n 2p "$meta" 2>/dev/null)"
  M_TTL="$(sed -n 3p "$meta" 2>/dev/null)"
  M_PID="$(sed -n 4p "$meta" 2>/dev/null)"
  M_START="$(sed -n 5p "$meta" 2>/dev/null)"
}

torn_meta() {
  [ -z "${M_WHO:-}" ] || [ -z "${M_EPOCH:-}" ] || [ -z "${M_TTL:-}" ]
}

write_meta() {
  local tmp
  tmp="$meta.$$.tmp"
  if ! printf '%s\n%s\n%s\n%s\n%s\n' \
      "$who" "$(now)" "$ttl" "$holder_pid" "$(pid_starttime "$holder_pid")" \
      >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  if [ "$(wc -l <"$tmp" 2>/dev/null || echo 0)" -ne 5 ]; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv -f "$tmp" "$meta" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  return 0
}

publish_or_release() {
  if write_meta; then
    return 0
  fi
  rm -f "$meta" 2>/dev/null
  rmdir "$lock" 2>/dev/null
  return 1
}

verdict() {
  case "$M_PID" in
    ''|*[!0-9]*)
      LIVENESS=indeterminate
      EVIDENCE="no holder pid recorded, so the liveness test cannot run"
      return 0
      ;;
  esac
  if [ ! -d "/proc/$M_PID" ]; then
    LIVENESS=dead
    EVIDENCE="/proc/$M_PID does not exist: the holder's process is gone"
    return 0
  fi
  if [ -n "$M_START" ]; then
    local cur
    cur="$(pid_starttime "$M_PID" 2>/dev/null)"
    if [ -n "$cur" ] && [ "$cur" != "$M_START" ]; then
      LIVENESS=dead
      EVIDENCE="pid $M_PID exists but its start time is $cur, not the recorded $M_START — the pid was REUSED"
      return 0
    fi
  fi
  LIVENESS=alive
  EVIDENCE="/proc/$M_PID exists (ownership-independent) and its start time matches the recording"
  return 0
}

hold_line() {
  local age
  age=$(( ( $(now) - ${M_EPOCH:-0} ) / 60 ))
  if [ -n "${M_EPOCH:-}" ] && [ "$age" -gt "$(( ${M_TTL:-45} + 20 ))" ]; then
    printf 'for %sm (ttl %sm) — STALE past ttl+20m grace (advisory only)' "$age" "${M_TTL:-?}"
  else
    printf 'for %sm (ttl %sm)' "$age" "${M_TTL:-?}"
  fi
}

take_after_clearing() {
  rm -f "$meta"
  rmdir "$lock" 2>/dev/null
  if mkdir "$lock" 2>/dev/null; then
    publish_or_release || return 1
    return 0
  fi
  return 1
}

case "$cmd" in
  acquire)
    [ -z "$tok" ] && { echo "usage: token.sh acquire <token> <agent> [ttl_min] [holder_pid]" >&2; exit 2; }
    if mkdir "$lock" 2>/dev/null; then
      if ! publish_or_release; then
        echo "FAILED to record the hold for $tok (could not publish the holder file; the filesystem may be full). The lock was released, so no torn lease remains — check disk space and retry." >&2
        exit 1
      fi
      echo "ACQUIRED $tok by $who (ttl ${ttl}m, holder pid $holder_pid)"
      exit 0
    fi
    read_meta
    if torn_meta; then
      echo "TORN $tok: a lock directory exists but its holder record is incomplete (who=${M_WHO:-<empty>} epoch=${M_EPOCH:-<empty>} ttl=${M_TTL:-<empty>})." >&2
      exit 1
    fi
    verdict
    case "$LIVENESS" in
      dead)
        if take_after_clearing; then
          echo "ACQUIRED $tok by $who (ttl ${ttl}m, holder pid $holder_pid) — REAPED a dead hold from ${M_WHO:-?}: $EVIDENCE"
          exit 0
        fi
        echo "HELD: $tok was re-taken while the dead hold was being reaped; retry or run: token.sh status $tok" >&2
        exit 1
        ;;
      alive)
        echo "HELD by ${M_WHO:-?} $(hold_line) — holder pid $M_PID alive ($EVIDENCE). Do NOT edit those files."
        exit 1
        ;;
      *)
        echo "HELD by ${M_WHO:-?} $(hold_line) — $EVIDENCE; cannot prove the holder is gone."
        echo "If you have confirmed the holder is gone, run: token.sh steal $tok $who"
        exit 1
        ;;
    esac
    ;;
  release)
    [ -z "$tok" ] && { echo "usage: token.sh release <token> <agent>" >&2; exit 2; }
    if [ ! -d "$lock" ]; then echo "NOT HELD: $tok"; exit 0; fi
    read_meta
    if [ "$M_WHO" != "$who" ]; then
      echo "REFUSED: $tok is held by ${M_WHO:-?}, not $who. Only the holder may release." >&2
      exit 1
    fi
    rm -f "$meta"; rmdir "$lock" 2>/dev/null
    echo "RELEASED $tok (was ${M_WHO:-?})"
    ;;
  renew)
    [ -z "$tok" ] && { echo "usage: token.sh renew <token> <agent> [ttl_min] [holder_pid]" >&2; exit 2; }
    if [ ! -d "$lock" ]; then echo "NOT HELD: $tok — use acquire" >&2; exit 1; fi
    read_meta
    if [ "$M_WHO" != "$who" ]; then
      echo "REFUSED: $tok is held by ${M_WHO:-?}, not $who. You may only renew your own hold." >&2
      exit 1
    fi
    write_meta
    echo "RENEWED $tok for $who (fresh ttl ${ttl}m, holder pid $holder_pid)"
    ;;
  steal)
    [ -z "$tok" ] && { echo "usage: token.sh steal <token> <agent>" >&2; exit 2; }
    if [ ! -d "$lock" ]; then
      if mkdir "$lock" 2>/dev/null; then
        write_meta
        echo "ACQUIRED $tok by $who (ttl ${ttl}m, holder pid $holder_pid) — it was free"
        exit 0
      fi
    fi
    read_meta
    verdict
    case "$LIVENESS" in
      alive)
        echo "REFUSED: $tok holder ${M_WHO:-?} is alive (pid $M_PID: $EVIDENCE)." >&2
        exit 1
        ;;
      dead)
        if take_after_clearing; then
          echo "STOLEN $tok from ${M_WHO:-?} by $who — the hold was provably dead: $EVIDENCE."
          exit 0
        fi
        echo "HELD: $tok was re-taken while the dead hold was being cleared; retry or run: token.sh status $tok" >&2
        exit 1
        ;;
      *)
        if take_after_clearing; then
          echo "STOLEN $tok from ${M_WHO:-?} by $who — $EVIDENCE; you vouched the holder is gone."
          exit 0
        fi
        echo "HELD: $tok was re-taken while the hold was being cleared; retry or run: token.sh status $tok" >&2
        exit 1
        ;;
    esac
    ;;
  status)
    if [ -n "$tok" ]; then set -- "$DIR/$tok.lock"; else set -- "$DIR"/*.lock; fi
    any=0
    for L in "$@"; do
      [ -d "$L" ] || continue
      any=1
      n=$(basename "$L" .lock)
      lock="$L"
      meta="$L/holder"
      read_meta
      if torn_meta; then
        echo "$n: TORN — lock directory exists but the holder record is incomplete (who=${M_WHO:-<empty>} epoch=${M_EPOCH:-<empty>} ttl=${M_TTL:-<empty>})."
        continue
      fi
      verdict
      case "$LIVENESS" in
        dead)      v="; holder pid $M_PID DEAD ($EVIDENCE) — reapable on next acquire" ;;
        alive)     v="; holder pid $M_PID alive" ;;
        *)         v="; liveness indeterminate ($EVIDENCE)" ;;
      esac
      echo "$n: HELD by ${M_WHO:-?} $(hold_line)$v"
    done
    if [ "$any" -eq 0 ]; then echo "no tokens held"; fi
    exit 0
    ;;
  *) echo "usage: token.sh {acquire|renew|release|steal|status} <token> <agent> [ttl_min] [holder_pid]" >&2; exit 2 ;;
esac
