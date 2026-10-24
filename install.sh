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
#   --verify           Repeat all four executable probes after installation
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
BINS=(fa fad fa-mcp fa-verify)
USER_AGENT='franken_accounting-installer (+https://github.com/Dicklesworthstone/franken_accounting)'

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

case "$SKIP_HASH_CHECK" in
  0|1) ;;
  *) err "FA_SKIP_VERIFY must be 0 or 1" ;;
esac
[ "$FROM_SOURCE" -eq 0 ] || [ -z "$ARTIFACT_DIR" ] || err "choose --from-source or --artifact-dir, not both"
if [ "$OFFLINE" -eq 1 ] && [ -z "$ARTIFACT_DIR" ] && [ "$FROM_SOURCE" -eq 0 ]; then
  err "--offline requires --artifact-dir <dir> or --from-source"
fi

# Keep staging evidence on failure and success. Never remove a caller's files.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fa-install.XXXXXX")"
STAGE="$WORK/candidate"
mkdir "$STAGE"
log "staging retained at $WORK"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "SHA-256 requires sha256sum or shasum"
  fi
}

check_digest() {
  local manifest="$1" name="$2" path="$3" expected actual
  [ -f "$manifest" ] && [ -r "$manifest" ] || err "missing readable SHA256SUMS: $manifest"
  # Check only the named artifact; never execute paths supplied by a manifest.
  # Reject duplicate rows as well as missing rows, even if their hashes agree.
  expected="$(awk -v name="$name" '
    { file = $2; sub(/^\*/, "", file) }
    file == name { count++; hash = $1; if (NF != 2) bad = 1 }
    END { if (count != 1 || bad) exit 1; print hash }
  ' "$manifest")" || err "SHA256SUMS must contain exactly one valid row for $name"
  [ "${#expected}" -eq 64 ] || err "invalid SHA-256 for $name"
  case "$expected" in *[!0-9a-fA-F]*) err "invalid SHA-256 for $name" ;; esac
  expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  actual="$(digest "$path")"
  [ "$expected" = "$actual" ] || err "SHA-256 mismatch for $name"
  log "checksum passed: $name sha256=$actual"
}

stage_binaries() {
  local source="$1" bin
  for bin in "${BINS[@]}"; do
    [ -f "$source/$bin" ] && [ ! -L "$source/$bin" ] && [ -x "$source/$bin" ] \
      || err "missing regular executable: $source/$bin"
    cp "$source/$bin" "$STAGE/$bin"
  done
}

probe_binaries() {
  local dir="$1" phase="$2" bin flag output
  for bin in "${BINS[@]}"; do
    flag=--version
    [ "$bin" != fa-verify ] || flag=--help
    output="$WORK/$phase-$bin.stdout"
    "$dir/$bin" "$flag" >"$output" \
      || err "executable probe failed: $bin $flag (stdout retained at $output)"
    if [ "$QUIET" -eq 0 ] && [ "$bin" != fa-verify ]; then
      cat "$output"
    fi
    log "probe passed: $bin $flag"
  done
}

if [ -n "$ARTIFACT_DIR" ]; then
  [ -d "$ARTIFACT_DIR" ] || err "artifact directory does not exist: $ARTIFACT_DIR"
  stage_binaries "$ARTIFACT_DIR"
  for bin in "${BINS[@]}"; do
    if [ "$SKIP_HASH_CHECK" -eq 0 ]; then
      check_digest "$ARTIFACT_DIR/SHA256SUMS" "$bin" "$STAGE/$bin"
    fi
  done
elif [ "$FROM_SOURCE" -eq 1 ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  command -v python3 >/dev/null 2>&1 || err "--from-source requires python3 to read Cargo artifact messages"
  log "building fa, fad, fa-mcp, and fa-verify from source at $ROOT"
  (
    cd "$ROOT" || exit 1
    cargo build --release --locked --bins --message-format=json-render-diagnostics
  ) >"$WORK/cargo-build.jsonl"
  # Cargo reports the executable selected by THIS invocation, including fresh
  # cache hits, configured targets and CARGO_TARGET_DIR. Never guess a path or
  # fall back to possibly stale repo-local binaries. Retain the whole stream.
  python3 -B - "$ROOT" "$WORK/cargo-build.jsonl" "$STAGE" <<'PY'
import json
import pathlib
import shutil
import sys

root, messages, stage = map(pathlib.Path, sys.argv[1:])
packages = {"fa": "fa-cli", "fad": "fad", "fa-mcp": "fa-mcp", "fa-verify": "fa-verify"}
selected = {}
finished = []

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate Cargo message key: {key}")
        result[key] = value
    return result

try:
    for line in messages.read_text().splitlines():
        # Other build tools can write diagnostics to Cargo's stdout. JSON-looking
        # lines must parse; plain diagnostics are retained but never evidence.
        if not line.lstrip().startswith("{"):
            continue
        message = json.loads(line, object_pairs_hook=strict_object)
        if finished:
            raise ValueError("Cargo messages follow build-finished")
        if message.get("reason") == "build-finished":
            finished.append(message.get("success"))
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {})
        name = target.get("name")
        if name not in packages or target.get("kind") != ["bin"]:
            continue
        if name in selected:
            raise ValueError(f"duplicate source artifact: {name}")
        expected_manifest = root / "crates" / packages[name] / "Cargo.toml"
        if pathlib.Path(message.get("manifest_path", "")).resolve() != expected_manifest.resolve():
            raise ValueError(f"unexpected source package for {name}")
        if message.get("profile", {}).get("test") is not False:
            raise ValueError(f"test artifact cannot be installed: {name}")
        executable = message.get("executable")
        if not isinstance(executable, str) or not pathlib.Path(executable).is_absolute():
            raise ValueError(f"missing absolute source executable: {name}")
        path = pathlib.Path(executable)
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing regular source executable: {name}")
        selected[name] = path
    if finished != [True]:
        raise ValueError("Cargo did not report one successful build-finished")
    if set(selected) != set(packages):
        raise ValueError("missing source artifacts: " + ", ".join(sorted(set(packages) - set(selected))))
    # Validate the complete selection before staging; publication is still
    # guarded by the existing four executable probes below.
    for name, path in selected.items():
        shutil.copy2(path, stage / name)
        print(f"[fa-install] source artifact: {name} <- {path}")
except (OSError, ValueError, TypeError, AttributeError) as error:
    print(f"[fa-install] ERROR: source artifact selection: {error}", file=sys.stderr)
    sys.exit(1)
PY
else
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$OS" in linux|darwin) ;; *) err "unsupported operating system: $OS" ;; esac
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "unsupported architecture: $ARCH" ;;
  esac
  BASE_URL="https://github.com/Dicklesworthstone/franken_accounting/releases"
  if [ "$VERSION" = "latest" ]; then
    URL_PREFIX="$BASE_URL/latest/download"
  else
    URL_PREFIX="$BASE_URL/download/$VERSION"
  fi
  ARCHIVE="franken_accounting-${OS}-${ARCH}.tar.gz"
  log "downloading $URL_PREFIX/$ARCHIVE"
  curl -fsSL --user-agent "$USER_AGENT" "$URL_PREFIX/$ARCHIVE" -o "$WORK/$ARCHIVE"
  if [ "$SKIP_HASH_CHECK" -eq 0 ]; then
    curl -fsSL --user-agent "$USER_AGENT" "$URL_PREFIX/SHA256SUMS" -o "$WORK/SHA256SUMS"
    check_digest "$WORK/SHA256SUMS" "$ARCHIVE" "$WORK/$ARCHIVE"
  fi
  mkdir "$WORK/extracted"
  tar -xzf "$WORK/$ARCHIVE" -C "$WORK/extracted" -- "${BINS[@]}"
  stage_binaries "$WORK/extracted"
fi

# Wrong-target and broken binaries must fail before changing the destination,
# even without --verify. Checksums alone cannot establish executability.
if [ "$SKIP_HASH_CHECK" -eq 1 ]; then
  printf '[fa-install] UNVERIFIED: SHA256SUMS checks explicitly disabled\n' >&2
fi
probe_binaries "$STAGE" candidate

# Preflight the whole destination before replacing any member. Publication is
# four ordinary installs, not an atomic multi-file upgrade or rollback.
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  [ -d "$DEST" ] && [ -w "$DEST" ] || err "destination is not a writable directory: $DEST"
fi
for bin in "${BINS[@]}"; do
  if [ -e "$DEST/$bin" ] || [ -L "$DEST/$bin" ]; then
    [ -f "$DEST/$bin" ] && [ ! -L "$DEST/$bin" ] && [ -w "$DEST/$bin" ] \
      || err "destination member is not a writable regular file: $DEST/$bin"
  fi
done
mkdir -p "$DEST"
for bin in "${BINS[@]}"; do
  install -m 0755 "$STAGE/$bin" "$DEST/$bin"
  log "installed $DEST/$bin"
done

if [ "$RUN_VERIFY" -eq 1 ]; then
  probe_binaries "$DEST" installed
  if [ "$SKIP_HASH_CHECK" -eq 1 ]; then
    log "UNVERIFIED installation: all four executable probes passed; checksums were skipped"
  elif [ "$FROM_SOURCE" -eq 1 ]; then
    log "source installation: all four executable probes passed (no release checksum claim)"
  else
    log "self-verification passed: fa fad fa-mcp fa-verify (checksums and executable probes)"
  fi
fi
