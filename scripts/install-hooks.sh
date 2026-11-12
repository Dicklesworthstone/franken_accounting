#!/usr/bin/env bash
# =============================================================================
# scripts/install-hooks.sh — Install git hooks for one-writer discipline (fa-7dx)
# =============================================================================
# Usage:
#   bash scripts/install-hooks.sh [--repository DIR] [--strict]
# =============================================================================

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$root"
strict=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      repo="$2"
      shift 2
      ;;
    --strict)
      strict=1
      shift
      ;;
    *)
      printf 'install-hooks: unknown argument %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

git_dir="$(git -C "$repo" rev-parse --git-dir)"
case "$git_dir" in
  /*) ;;
  *) git_dir="$repo/$git_dir" ;;
esac

mkdir -p "$git_dir/hooks"
cp "$root/scripts/hooks/pre-push" "$git_dir/hooks/pre-push"
chmod +x "$git_dir/hooks/pre-push"

if git -C "$repo" config --get remote.origin.url >/dev/null 2>&1; then
  if ! git -C "$repo" config --get-all remote.origin.fetch 2>/dev/null | grep -Fq 'refs/notes/'; then
    git -C "$repo" config --add remote.origin.fetch '+refs/notes/*:refs/notes/*'
  fi
fi

if [ "$strict" -eq 1 ]; then
  git -C "$repo" config fa.prePushStrict true
fi

printf 'INSTALLED pre-push hook into %s/hooks/pre-push (strict=%s)\n' "$git_dir" "$strict"
