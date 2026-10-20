#!/usr/bin/env bash
# =============================================================================
# FrankenAccounting (fa / fad / fa-mcp / fa-verify) installer (bead fa-eqk)
#
# Universal, evidence-native, double-entry accounting system of record in Rust.
# Releases ship through the suite's self-releaser (dsr), never GitHub Actions.
#
# Usage:
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_accounting/main/install.sh" | bash
#
# Options:
#   --version vX.Y.Z   Install specific version (default: latest)
#   --dest DIR         Install to DIR (default: ~/.local/bin)
#   --system           Install to /usr/local/bin (requires sudo)
#   --from-source      Build from local source or git checkout
#   --verify           Run `fa --version`, `fad --version`, and `fa-verify --help`
#   --offline          Install from pre-downloaded archive via --artifact-dir
#   --artifact-dir DIR Directory containing release binaries and SHA256SUMS
#   --no-verify        Skip SHA256SUMS verification (NOT recommended)
#   --quiet, -q        Suppress non-error output
#   --help, -h         Print usage and exit
# =============================================================================
set -euo pipefail
umask 022

VERSION="${FA_VERSION:-latest}"
DEST="${FA_INSTALL_DIR:-$HOME/.local/bin}"
FROM_SOURCE=0
RUN_VERIFY=0
OFFLINE=0
ARTIFACT_DIR=""
SKIP_HASH_CHECK="${FA_SKIP_VERIFY:-0}"
QUIET=0

log() {
  if [ "$QUIET" -eq 0 ]; then
    printf '[fa-install] %s\n' "$*"
  fi
}

err() {
  printf '[fa-install] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,22s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || err "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --dest)
      [ "$#" -ge 2 ] || err "--dest requires a directory"
      DEST="$2"
      shift 2
      ;;
    --system)
      DEST="/usr/local/bin"
      shift
      ;;
    --from-source)
      FROM_SOURCE=1
      shift
      ;;
    --verify)
      RUN_VERIFY=1
      shift
      ;;
    --offline)
      OFFLINE=1
      shift
      ;;
    --artifact-dir)
      [ "$#" -ge 2 ] || err "--artifact-dir requires a directory"
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --no-verify)
      SKIP_HASH_CHECK=1
      shift
      ;;
    --quiet|-q)
      QUIET=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      err "unknown option: $1 (run with --help)"
      ;;
  esac
done

mkdir -p "$DEST"

if [ -n "$ARTIFACT_DIR" ]; then
  [ -d "$ARTIFACT_DIR" ] || err "artifact directory does not exist: $ARTIFACT_DIR"
  if [ "$SKIP_HASH_CHECK" -eq 0 ] && [ -f "$ARTIFACT_DIR/SHA256SUMS" ]; then
    log "verifying SHA256SUMS in $ARTIFACT_DIR"
    (cd "$ARTIFACT_DIR" && sha256sum -c SHA256SUMS)
  fi
  for bin in fa fad fa-mcp fa-verify; do
    if [ -f "$ARTIFACT_DIR/$bin" ]; then
      install -m 0755 "$ARTIFACT_DIR/$bin" "$DEST/$bin"
      log "installed $DEST/$bin"
    fi
  done
elif [ "$FROM_SOURCE" -eq 1 ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  log "building fa, fad, fa-mcp, and fa-verify from source at $ROOT"
  (
    cd "$ROOT" || exit 1
    cargo build --release --locked --bins
    for bin in fa fad fa-mcp fa-verify; do
      if [ -f "target/release/$bin" ]; then
        install -m 0755 "target/release/$bin" "$DEST/$bin"
        log "installed $DEST/$bin"
      fi
    done
  )
else
  if [ "$OFFLINE" -eq 1 ]; then
    err "--offline requires --artifact-dir <dir> or --from-source"
  fi
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "unsupported architecture: $ARCH" ;;
  esac
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/fa-install.XXXXXX")"
  trap 'rm -rf "$WORK"' EXIT
  BASE_URL="https://github.com/Dicklesworthstone/franken_accounting/releases"
  if [ "$VERSION" = "latest" ]; then
    URL_PREFIX="$BASE_URL/latest/download"
  else
    URL_PREFIX="$BASE_URL/download/$VERSION"
  fi
  ARCHIVE="franken_accounting-${OS}-${ARCH}.tar.gz"
  log "downloading $URL_PREFIX/$ARCHIVE"
  curl -fsSL "$URL_PREFIX/$ARCHIVE" -o "$WORK/$ARCHIVE"
  if [ "$SKIP_HASH_CHECK" -eq 0 ]; then
    curl -fsSL "$URL_PREFIX/SHA256SUMS" -o "$WORK/SHA256SUMS"
    (cd "$WORK" && grep " $ARCHIVE\$" SHA256SUMS | sha256sum -c -)
  fi
  tar -xzf "$WORK/$ARCHIVE" -C "$WORK"
  for bin in fa fad fa-mcp fa-verify; do
    if [ -f "$WORK/$bin" ]; then
      install -m 0755 "$WORK/$bin" "$DEST/$bin"
      log "installed $DEST/$bin"
    fi
  done
fi

if [ "$RUN_VERIFY" -eq 1 ]; then
  if [ -x "$DEST/fa" ]; then
    "$DEST/fa" --version
  fi
  if [ -x "$DEST/fad" ]; then
    "$DEST/fad" --version
  fi
  if [ -x "$DEST/fa-verify" ]; then
    "$DEST/fa-verify" --help >/dev/null
  fi
  log "self-verification passed"
fi
