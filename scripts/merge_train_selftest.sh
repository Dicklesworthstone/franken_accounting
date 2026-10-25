#!/usr/bin/env bash
# Wrapper delegating to scripts/tests/merge_train_selftest.sh (beads fa-u7u, fa-aj8, fa-j1fc).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT/scripts/tests/merge_train_selftest.sh" "$@"
