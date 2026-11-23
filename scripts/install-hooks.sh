#!/usr/bin/env bash
# =============================================================================
# scripts/install-hooks.sh — Install git hooks for one-writer discipline (fa-7dx)
# =============================================================================
# Install the push guard and keep default fetches from replacing local evidence.
# Use --sync-notes to fetch and merge origin's verification notes into this clone.
# Git reports conflicts on the same object for explicit resolution.
# Usage: bash scripts/install-hooks.sh [--repository DIR] [--strict] [--sync-notes]
# =============================================================================

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$root"
strict=0
sync_notes=0

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
    --sync-notes)
      sync_notes=1
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

if git -C "$repo" config --get remote.origin.url >/dev/null 2>&1; then
  incoming='refs/fa-remote-notes/origin/'
  tracking="+refs/notes/*:${incoming}*"
  legacy='+refs/notes/*:refs/notes/*'
  # Migrate only the wildcard this installer previously added.
  if git -C "$repo" config --local --fixed-value --get-all remote.origin.fetch "$legacy" >/dev/null; then
    git -C "$repo" config --local --fixed-value --unset-all remote.origin.fetch "$legacy"
  fi
  if ! git -C "$repo" config --local --fixed-value --get-all remote.origin.fetch "$tracking" >/dev/null; then
    git -C "$repo" config --local --add remote.origin.fetch "$tracking"
  fi
  if [ "$sync_notes" -eq 1 ]; then
    git -C "$repo" fetch --no-tags --no-recurse-submodules --refmap='' origin "$tracking"
    tips=$(git -C "$repo" for-each-ref --format='%(refname) %(objectname)' "$incoming")
    while read -r ref tip; do
      [ -n "$ref" ] || continue
      dest="refs/notes/${ref#"$incoming"}"
      if git -C "$repo" show-ref --verify --quiet "$dest"; then
        git -C "$repo" notes --ref="$dest" merge -s manual "$tip"
      else
        git -C "$repo" update-ref "$dest" "$tip" ''
      fi
    done <<< "$tips"
  fi
elif [ "$sync_notes" -eq 1 ]; then
  printf 'install-hooks: --sync-notes requires remote origin\n' >&2
  exit 2
fi

if [ "$sync_notes" -eq 1 ] && [ "$strict" -eq 0 ]; then
  printf 'Synchronized verification notes from origin\n'
  exit 0
fi
mkdir -p "$git_dir/hooks"
cp "$root/scripts/hooks/pre-push" "$git_dir/hooks/pre-push"
chmod +x "$git_dir/hooks/pre-push"

if [ "$strict" -eq 1 ]; then
  git -C "$repo" config fa.prePushStrict true
fi

printf 'INSTALLED pre-push hook into %s/hooks/pre-push (strict=%s)\n' "$git_dir" "$strict"
