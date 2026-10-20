# shellcheck shell=bash
# =============================================================================
# landing_lease.sh — the LANDING lease: hold landings, never hold panes
# =============================================================================
# Adopted from frankengraphdb (bead fa-u7u).

FA_TOKEN_SH="${FA_TOKEN_SH:-${FGDB_TOKEN_SH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/token.sh}}"
FA_TOKEN_DIR="${FA_TOKEN_DIR:-${FGDB_TOKEN_DIR:-${TMPDIR:-/tmp}/fa_swarm/tokens}}"

LANDING_LOCK="$FA_TOKEN_DIR/landing.lock"
LANDING_META="$LANDING_LOCK/holder"

# shellcheck disable=SC2034
LANDING_STATE=""
LANDING_HOLDER=""
LANDING_AGE_MIN=""
LANDING_TTL_MIN=""
LANDING_PID=""
LANDING_LIVENESS=""
LANDING_EVIDENCE=""

_ll_starttime() {
  local pid="$1" stat rest
  [ -r "/proc/$pid/stat" ] || return 1
  stat="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  rest="${stat##*) }"
  # shellcheck disable=SC2086
  set -- $rest
  [ "$#" -ge 20 ] || return 1
  printf '%s\n' "${20}"
}

# shellcheck disable=SC2034
landing_lease_state() {
  LANDING_STATE=""; LANDING_HOLDER=""; LANDING_AGE_MIN=""; LANDING_TTL_MIN=""
  LANDING_PID=""; LANDING_LIVENESS=""; LANDING_EVIDENCE=""

  if [ ! -d "$LANDING_LOCK" ]; then
    LANDING_STATE=FREE; printf 'FREE\n'; return 0
  fi
  if [ ! -r "$LANDING_META" ]; then
    LANDING_STATE=UNREADABLE
    LANDING_EVIDENCE="lock directory exists at $LANDING_LOCK but its holder file is unreadable"
    printf 'UNREADABLE\n'; return 0
  fi

  local who epoch ttl pid start now age cur
  who="$(sed -n 1p "$LANDING_META" 2>/dev/null)"
  epoch="$(sed -n 2p "$LANDING_META" 2>/dev/null)"
  ttl="$(sed -n 3p "$LANDING_META" 2>/dev/null)"
  pid="$(sed -n 4p "$LANDING_META" 2>/dev/null)"
  start="$(sed -n 5p "$LANDING_META" 2>/dev/null)"

  case "$epoch" in ''|*[!0-9]*) epoch=0 ;; esac
  now="$(date +%s)"
  if [ "$epoch" -gt 0 ]; then age=$(( ( now - epoch ) / 60 )); else age="?"; fi

  LANDING_HOLDER="${who:-?}"
  LANDING_AGE_MIN="$age"
  LANDING_TTL_MIN="${ttl:-?}"
  LANDING_PID="${pid:-}"

  case "$pid" in
    ''|*[!0-9]*)
      LANDING_LIVENESS=indeterminate
      LANDING_EVIDENCE="no pid recorded in the holder file, so the liveness test cannot be run"
      LANDING_STATE=BINDING; printf 'BINDING\n'; return 0
      ;;
  esac

  if [ ! -d "/proc/$pid" ]; then
    LANDING_LIVENESS=dead
    LANDING_EVIDENCE="/proc/$pid does not exist: the holder's process is gone"
    LANDING_STATE=BREAKABLE; printf 'BREAKABLE\n'; return 0
  fi
  if [ -n "$start" ]; then
    cur="$(_ll_starttime "$pid" 2>/dev/null)"
    if [ -n "$cur" ] && [ "$cur" != "$start" ]; then
      LANDING_LIVENESS=dead
      LANDING_EVIDENCE="pid $pid exists but its start time is $cur, not the recorded $start — the pid was REUSED"
      LANDING_STATE=BREAKABLE; printf 'BREAKABLE\n'; return 0
    fi
  fi

  LANDING_LIVENESS=alive
  LANDING_EVIDENCE="/proc/$pid exists (ownership-independent) and its start time matches the recorded $start; the holder is running"
  LANDING_STATE=BINDING; printf 'BINDING\n'; return 0
}

landing_lease_acquire() {
  local who="$1" ttl="${2:-45}"
  [ -x "$FA_TOKEN_SH" ] || return 1
  "$FA_TOKEN_SH" acquire landing "$who" "$ttl" "$$" >/dev/null 2>&1 || return 1
  export FA_LANDING_HOLDER="$who"
  return 0
}

landing_lease_release() {
  local who="$1"
  [ -x "$FA_TOKEN_SH" ] || return 0
  "$FA_TOKEN_SH" release landing "$who" >/dev/null 2>&1 || true
  unset FA_LANDING_HOLDER
  return 0
}
