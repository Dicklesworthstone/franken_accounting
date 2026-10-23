#!/usr/bin/env bash
# Real-process installer mechanics, bead fa-o3zg. Fixture executables are shell
# programs: this does not qualify Rust artifacts, linkage, or accounting.
# Usage: bash scripts/tests/installer_integration.sh [installer [new-workdir]]
# Every case, destination, stdout and stderr is retained; no cleanup/deletion.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"
INSTALLER="${1:-$ROOT/install.sh}"
WORK="${2:-$(mktemp -d "${TMPDIR:-/tmp}/fa-installer-tests.XXXXXX")}"
gate_init installer-integration
[ "$#" -le 2 ] || gate_abort_unrun "usage: installer_integration.sh [installer [new-workdir]]"
mkdir -p "$WORK" || gate_abort_unrun "cannot create $WORK"
WORK="$(cd "$WORK" && pwd)"
printf 'installer fixtures and transcripts retained: %s\n' "$WORK"
BINS=(fa fad fa-mcp fa-verify)

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

new_case() {
  CASE="$WORK/$1"
  # Refuse reused workdirs rather than overwriting an earlier test's evidence.
  mkdir "$CASE" || gate_abort_unrun "case already exists or cannot be created: $CASE"
  SRC="$CASE/release artifacts"
  DEST="$CASE/existing destination"
  mkdir "$SRC" "$DEST" "$CASE/tmp"
  : >"$CASE/probes"
  : >"$CASE/requests"
  local bin
  for bin in "${BINS[@]}"; do
    printf 'preserve original %s\n' "$bin" >"$DEST/$bin"
    cat >"$SRC/$bin" <<'FIXTURE'
#!/usr/bin/env bash
set -eu
bin="${0##*/}"
flag=--version
[ "$bin" != fa-verify ] || flag=--help
[ "$#" -eq 1 ] && [ "$1" = "$flag" ] || exit 2
printf '%s %s\n' "$bin" "$1" >>"$INSTALLER_TEST_PROBES"
printf 'installer fixture %s %s\n' "$bin" "$1"
FIXTURE
    chmod 0755 "$SRC/$bin"
  done
  printf 'keep unrelated file\n' >"$DEST/unrelated"
  manifest
  destination_snapshot >"$CASE/before"
}

manifest() {
  local bin
  : >"$SRC/SHA256SUMS"
  for bin in "${BINS[@]}"; do
    if [ -f "$SRC/$bin" ]; then
      printf '%s  %s\n' "$(hash_file "$SRC/$bin")" "$bin" >>"$SRC/SHA256SUMS"
    fi
  done
}

destination_snapshot() {
  local bin
  for bin in "${BINS[@]}" unrelated; do
    if [ -L "$DEST/$bin" ]; then
      printf '%s symlink %s\n' "$bin" "$(readlink "$DEST/$bin")"
    elif [ -d "$DEST/$bin" ]; then
      printf '%s directory\n' "$bin"
    else
      printf '%s %s\n' "$bin" "$(hash_file "$DEST/$bin")"
    fi
  done
}

run_install() {
  INSTALLER_TEST_PROBES="$CASE/probes" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=0 \
    bash "$INSTALLER" --offline --artifact-dir "$SRC" --dest "$DEST" "$@" \
    >"$CASE/stdout" 2>"$CASE/stderr"
  RC=$?
  destination_snapshot >"$CASE/after"
}

# Exercise archive selection/extraction using a fixture transport, never the
# real release service. This proves download-path mechanics and User-Agent
# propagation, not HTTP/TLS, release availability or artifact authenticity.
prepare_download() {
  DOWNLOADS="$CASE/downloads"
  mkdir "$DOWNLOADS" "$CASE/transport"
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
  ARCHIVE="franken_accounting-$os-$arch.tar.gz"
  tar -czf "$DOWNLOADS/$ARCHIVE" -C "$SRC" "${BINS[@]}"
  printf '%s  %s\n' "$(hash_file "$DOWNLOADS/$ARCHIVE")" "$ARCHIVE" >"$DOWNLOADS/SHA256SUMS"
  cat >"$CASE/transport/curl" <<'TRANSPORT'
#!/usr/bin/env bash
set -eu
agent= output= url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -fsSL) shift ;;
    --user-agent) agent="$2"; shift 2 ;;
    -o) output="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) exit 2 ;;
  esac
done
[ "$agent" = 'franken_accounting-installer (+https://github.com/Dicklesworthstone/franken_accounting)' ] || exit 3
case "$url" in "$INSTALLER_TEST_URL"/*) ;; *) exit 4 ;; esac
printf '%s %s\n' "$agent" "$url" >>"$INSTALLER_TEST_REQUESTS"
cp "$INSTALLER_TEST_DOWNLOADS/${url##*/}" "$output"
TRANSPORT
  chmod 0755 "$CASE/transport/curl"
}

run_download() {
  INSTALLER_TEST_PROBES="$CASE/probes" INSTALLER_TEST_DOWNLOADS="$DOWNLOADS" \
    INSTALLER_TEST_REQUESTS="$CASE/requests" \
    INSTALLER_TEST_URL='https://github.com/Dicklesworthstone/franken_accounting/releases/download/v0.fixture' \
    TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=0 PATH="$CASE/transport:$PATH" \
    bash "$INSTALLER" --version v0.fixture --dest "$DEST" --verify "$@" \
    >"$CASE/stdout" 2>"$CASE/stderr"
  RC=$?
  destination_snapshot >"$CASE/after"
}

# The cargo stand-in only tests installer control flow. No compilation claim.
prepare_source() {
  SOURCE_ROOT="$CASE/source"
  mkdir -p "$SOURCE_ROOT/target/release" "$CASE/build-tool"
  cp "$INSTALLER" "$SOURCE_ROOT/install.sh"
  local bin
  for bin in "${BINS[@]}"; do
    cp "$SRC/$bin" "$SOURCE_ROOT/target/release/$bin"
  done
  cat >"$CASE/build-tool/cargo" <<'BUILD'
#!/usr/bin/env bash
set -eu
[ "$*" = 'build --release --locked --bins' ] || exit 2
printf '%s\n' "$*" >>"$INSTALLER_TEST_BUILD_REQUESTS"
exit "${INSTALLER_TEST_BUILD_EXIT:-0}"
BUILD
  chmod 0755 "$CASE/build-tool/cargo"
}

run_source() {
  INSTALLER_TEST_PROBES="$CASE/probes" INSTALLER_TEST_BUILD_REQUESTS="$CASE/build-requests" \
    INSTALLER_TEST_BUILD_EXIT="${BUILD_EXIT:-0}" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=0 \
    PATH="$CASE/build-tool:$PATH" bash "$SOURCE_ROOT/install.sh" --from-source \
    --dest "$DEST" --verify >"$CASE/stdout" 2>"$CASE/stderr"
  RC=$?
  destination_snapshot >"$CASE/after"
}

expect_refusal() {
  local name="$1" message="$2"
  if [ "$RC" -ne 0 ] && cmp -s "$CASE/before" "$CASE/after" \
    && grep -Fq -- "$message" "$CASE/stderr" \
    && ! grep -Fq 'self-verification passed' "$CASE/stdout"; then
    gate_pass "$name (exit=$RC; existing destination preserved)"
  else
    gate_fail "$name (exit=$RC; see $CASE)"
  fi
}

expect_success() {
  local name="$1" count="$2" preserve_unrelated="${3:-1}" bin ok=1 actual
  [ "$RC" -eq 0 ] || ok=0
  for bin in "${BINS[@]}"; do
    [ -x "$DEST/$bin" ] && cmp -s "$SRC/$bin" "$DEST/$bin" || ok=0
    actual="$(grep -c "^$bin --" "$CASE/probes")"
    [ "$actual" -eq "$count" ] || ok=0
  done
  if [ "$preserve_unrelated" -eq 1 ]; then
    grep -Fxq 'keep unrelated file' "$DEST/unrelated" || ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    gate_pass "$name (all four installed byte-for-byte; $count probe(s) per binary)"
  else
    gate_fail "$name (exit=$RC; see $CASE)"
  fi
}

new_case empty
mkdir "$CASE/empty"
SRC="$CASE/empty"
run_install --verify
expect_refusal 'empty_artifacts_refuse_before_install' 'missing regular executable:'

new_case missing-manifest
mv "$SRC/SHA256SUMS" "$CASE/retained-manifest"
run_install --verify
expect_refusal 'missing_manifest_refuses_without_explicit_opt_out' 'missing readable SHA256SUMS:'

for member in "${BINS[@]}"; do
  new_case "missing-$member"
  mv "$SRC/$member" "$CASE/retained-$member"
  run_install --verify
  expect_refusal "missing_member_preserves_destination:$member" 'missing regular executable:'

  new_case "missing-row-$member"
  awk -v member="$member" '$2 != member' "$SRC/SHA256SUMS" >"$CASE/partial-manifest"
  mv "$SRC/SHA256SUMS" "$CASE/full-manifest"
  cp "$CASE/partial-manifest" "$SRC/SHA256SUMS"
  run_install --verify
  expect_refusal "missing_checksum_row_preserves_destination:$member" 'exactly one valid row'
done

new_case wrong-digest
printf '\n# tampered after checksumming\n' >>"$SRC/fa-verify"
run_install --verify
expect_refusal 'bad_digest_preserves_destination' 'SHA-256 mismatch for fa-verify'

new_case duplicate-row
head -n 1 "$SRC/SHA256SUMS" >"$CASE/duplicate-row"
cat "$CASE/duplicate-row" >>"$SRC/SHA256SUMS"
run_install --verify
expect_refusal 'duplicate_checksum_row_refuses' 'exactly one valid row for fa'

new_case malformed-digest
printf 'not-a-sha256  fa\n' >"$SRC/SHA256SUMS"
run_install --verify
expect_refusal 'malformed_digest_refuses' 'invalid SHA-256 for fa'

new_case non-executable
chmod 0644 "$SRC/fa-verify"
run_install --verify
expect_refusal 'non_executable_member_preserves_destination' 'missing regular executable:'

new_case wrong-target
printf '#!/no/such/fa-target-loader\n' >"$SRC/fa-verify"
manifest
run_install --verify
expect_refusal 'wrong_target_preserves_destination' 'executable probe failed: fa-verify --help'

new_case broken-mcp
printf '#!/usr/bin/env bash\nexit 42\n' >"$SRC/fa-mcp"
manifest
run_install --verify
expect_refusal 'mcp_probe_failure_preserves_destination' 'executable probe failed: fa-mcp --version'

new_case artifact-symlink
mv "$SRC/fa-mcp" "$CASE/retained-fa-mcp"
ln -s "$CASE/retained-fa-mcp" "$SRC/fa-mcp"
run_install --verify
expect_refusal 'symlink_artifact_refuses' 'missing regular executable:'

new_case destination-directory
mv "$DEST/fa-mcp" "$CASE/retained-old-mcp"
mkdir "$DEST/fa-mcp"
destination_snapshot >"$CASE/before"
run_install --verify
expect_refusal 'destination_directory_preserves_other_members' 'destination member is not a writable regular file:'

new_case destination-symlink
mv "$DEST/fa" "$CASE/retained-old-fa"
ln -s "$CASE/retained-old-fa" "$DEST/fa"
destination_snapshot >"$CASE/before"
run_install --verify
expect_refusal 'destination_symlink_refuses' 'destination member is not a writable regular file:'

new_case verified-complete
run_install --verify
expect_success 'success_requires_the_complete_executed_probe_set' 2
if grep -Fq 'self-verification passed: fa fad fa-mcp fa-verify' "$CASE/stdout"; then
  gate_pass 'verified_completion_names_exact_checked_set'
else
  gate_fail 'verified_completion_names_exact_checked_set'
fi

new_case without-verify
run_install
expect_success 'candidate_probes_execute_even_without_verify_flag' 1

new_case fresh-destination-success
DEST="$CASE/new destination"
INSTALLER_TEST_PROBES="$CASE/probes" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=0 \
  bash "$INSTALLER" --offline --artifact-dir "$SRC" --dest "$DEST" --verify \
  >"$CASE/stdout" 2>"$CASE/stderr"
RC=$?
expect_success 'complete_candidate_installs_to_a_new_destination' 2 0

new_case opt-out
mv "$SRC/SHA256SUMS" "$CASE/retained-manifest"
run_install --verify --no-verify
expect_success 'explicit_checksum_opt_out_installs_complete_candidate' 2
if grep -Fq 'UNVERIFIED:' "$CASE/stderr" \
  && ! grep -Fq 'self-verification passed' "$CASE/stdout"; then
  gate_pass 'opt_out_never_claims_checksum_verification'
else
  gate_fail 'opt_out_never_claims_checksum_verification'
fi

new_case quiet-opt-out
run_install --verify --no-verify --quiet
expect_success 'quiet_opt_out_still_installs_and_probes' 2
if grep -Fq 'UNVERIFIED:' "$CASE/stderr" && [ ! -s "$CASE/stdout" ]; then
  gate_pass 'quiet_suppresses_probe_stdout_but_cannot_hide_unverified_warning'
else
  gate_fail 'quiet_suppresses_probe_stdout_but_cannot_hide_unverified_warning'
fi

new_case broken-opt-out
printf '#!/usr/bin/env bash\nexit 42\n' >"$SRC/fa-mcp"
run_install --no-verify
expect_refusal 'opt_out_cannot_bypass_executable_probes' 'executable probe failed: fa-mcp --version'

new_case env-opt-out
mv "$SRC/SHA256SUMS" "$CASE/retained-manifest"
INSTALLER_TEST_PROBES="$CASE/probes" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=1 \
  bash "$INSTALLER" --offline --artifact-dir "$SRC" --dest "$DEST" --verify \
  >"$CASE/stdout" 2>"$CASE/stderr"
RC=$?
expect_success 'explicit_environment_checksum_opt_out' 2
if grep -Fq 'UNVERIFIED:' "$CASE/stderr" \
  && ! grep -Fq 'self-verification passed' "$CASE/stdout"; then
  gate_pass 'environment_opt_out_never_claims_checksum_verification'
else
  gate_fail 'environment_opt_out_never_claims_checksum_verification'
fi

new_case invalid-env-opt-out
INSTALLER_TEST_PROBES="$CASE/probes" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=typo \
  bash "$INSTALLER" --offline --artifact-dir "$SRC" --dest "$DEST" --verify \
  >"$CASE/stdout" 2>"$CASE/stderr"
RC=$?
destination_snapshot >"$CASE/after"
expect_refusal 'invalid_environment_cannot_accidentally_skip_checksums' 'FA_SKIP_VERIFY must be 0 or 1'

new_case fresh-destination-failure
DEST="$CASE/not-created"
mkdir "$CASE/empty"
SRC="$CASE/empty"
INSTALLER_TEST_PROBES="$CASE/probes" TMPDIR="$CASE/tmp" FA_SKIP_VERIFY=0 \
  bash "$INSTALLER" --offline --artifact-dir "$SRC" --dest "$DEST" --verify \
  >"$CASE/stdout" 2>"$CASE/stderr"
RC=$?
if [ "$RC" -ne 0 ] && [ ! -e "$DEST" ]; then
  gate_pass 'invalid_candidate_does_not_create_destination'
else
  gate_fail 'invalid_candidate_does_not_create_destination'
fi

new_case download-complete
prepare_download
run_download
expect_success 'download_complete_archive_mechanics_fixture_transport' 2
if [ "$(wc -l <"$CASE/requests" | tr -d ' ')" -eq 2 ]; then
  gate_pass 'both_download_requests_identify_the_project'
else
  gate_fail 'both_download_requests_identify_the_project'
fi

new_case download-corrupt
prepare_download
printf 'corrupt downloaded archive\n' >>"$DOWNLOADS/$ARCHIVE"
run_download
expect_refusal 'download_bad_archive_digest_preserves_destination' 'SHA-256 mismatch for'

new_case download-missing-row
prepare_download
: >"$DOWNLOADS/SHA256SUMS"
run_download
expect_refusal 'download_missing_archive_row_refuses' 'exactly one valid row for'

new_case download-incomplete
prepare_download
# Replace only this fresh fixture archive, retaining the complete archive.
mv "$DOWNLOADS/$ARCHIVE" "$CASE/complete-archive"
tar -czf "$DOWNLOADS/$ARCHIVE" -C "$SRC" fa fad fa-mcp
printf '%s  %s\n' "$(hash_file "$DOWNLOADS/$ARCHIVE")" "$ARCHIVE" >"$DOWNLOADS/SHA256SUMS"
run_download
if [ "$RC" -ne 0 ] && cmp -s "$CASE/before" "$CASE/after" \
  && [ ! -s "$CASE/probes" ]; then
  gate_pass 'download_incomplete_archive_refuses_before_probes_or_publication'
else
  gate_fail 'download_incomplete_archive_refuses_before_probes_or_publication'
fi

new_case download-opt-out
prepare_download
mv "$DOWNLOADS/SHA256SUMS" "$CASE/retained-manifest"
run_download --no-verify
expect_success 'download_explicit_opt_out_mechanics_fixture_transport' 2
if [ "$(wc -l <"$CASE/requests" | tr -d ' ')" -eq 1 ] \
  && grep -Fq 'UNVERIFIED:' "$CASE/stderr" \
  && ! grep -Fq 'self-verification passed' "$CASE/stdout"; then
  gate_pass 'download_opt_out_is_explicit_and_does_not_fetch_manifest'
else
  gate_fail 'download_opt_out_is_explicit_and_does_not_fetch_manifest'
fi

new_case source-complete
prepare_source
run_source
expect_success 'source_install_control_flow_fixture_build_only' 2
if grep -Fxq 'build --release --locked --bins' "$CASE/build-requests" \
  && grep -Fq 'no release checksum claim' "$CASE/stdout" \
  && ! grep -Fq 'self-verification passed' "$CASE/stdout"; then
  gate_pass 'source_build_is_locked_and_never_claims_release_checksums'
else
  gate_fail 'source_build_is_locked_and_never_claims_release_checksums'
fi

new_case source-missing-member
prepare_source
mv "$SOURCE_ROOT/target/release/fa-verify" "$CASE/retained-built-verifier"
run_source
expect_refusal 'source_missing_member_preserves_destination' 'missing regular executable:'

new_case source-build-failure
prepare_source
BUILD_EXIT=42
run_source
BUILD_EXIT=0
if [ "$RC" -eq 42 ] && cmp -s "$CASE/before" "$CASE/after" && [ ! -s "$CASE/probes" ]; then
  gate_pass 'source_build_failure_preserves_destination_and_exit_code'
else
  gate_fail 'source_build_failure_preserves_destination_and_exit_code'
fi

gate_verdict
