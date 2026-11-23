#!/usr/bin/env bash
# Run each planted fault in a fresh model directory and require the named TLC trace.
set -eu
exec python3 -B "$(dirname "$0")/../tlc_models.py" --negative-only
