#!/usr/bin/env bash
# EN/KO documentation drift check.
#
# GitBook's built-in per-page language switcher (Variants) is a paid feature, so
# we manage EN (docs/*.md) and KO (docs/ko/*.md) as parallel trees under one free
# space. This guards the pair:
#   - every English doc must have a Korean counterpart (and vice versa),
#   - warns when a Korean page's last commit predates its English source, i.e.
#     English changed but the translation wasn't updated.
#
# Missing/orphan files fail the check (exit 1). Staleness only warns, so an
# English-only edit doesn't hard-block a PR — it flags the translation as TODO.
#
# Pairing rule: same basename, case-insensitive (English on-disk `database.md`
# pairs with Korean `DATABASE.md`). The repo README.md pairs with docs/ko/README.md.
# Portable: no GNU-only `find -printf`, no bash-4 features (macOS ships bash 3.2).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

status=0

lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
# Last-commit epoch, or 0 when the file has no commit yet (git prints nothing).
commit_time() { local t; t=$(git log -1 --format=%ct -- "$1" 2>/dev/null || true); echo "${t:-0}"; }

# Case-insensitive lookup of <basename> in <dir>; prints the actual filename.
find_ci() {
  local dir="$1" base f
  base=$(lc "$2")
  for f in "$dir"/*.md; do
    [ -e "$f" ] || continue
    [ "$(lc "$(basename "$f")")" = "$base" ] && { basename "$f"; return; }
  done
}

# --- forward: every EN doc needs a KO counterpart -------------------------
for en in docs/*.md; do
  base=$(basename "$en")
  ko=$(find_ci docs/ko "$base" || true)
  if [ -z "$ko" ]; then
    echo "MISSING KO: docs/ko/$base (translate docs/$base)"
    status=1
    continue
  fi
  en_t=$(commit_time "$en"); ko_t=$(commit_time "docs/ko/$ko")
  if [ "$ko_t" -ne 0 ] && [ "$en_t" -gt "$ko_t" ]; then
    echo "STALE KO: docs/ko/$ko is older than docs/$base — retranslate"
  fi
done

# repo README ↔ docs/ko/README.md
if [ ! -f docs/ko/README.md ]; then
  echo "MISSING KO: docs/ko/README.md (translate README.md)"
  status=1
else
  en_t=$(commit_time README.md); ko_t=$(commit_time docs/ko/README.md)
  if [ "$ko_t" -ne 0 ] && [ "$en_t" -gt "$ko_t" ]; then
    echo "STALE KO: docs/ko/README.md is older than README.md — retranslate"
  fi
fi

# --- reverse: every KO doc needs an EN source -----------------------------
for ko in docs/ko/*.md; do
  base=$(basename "$ko")
  [ "$base" = "README.md" ] && continue   # paired with the repo README
  en=$(find_ci docs "$base" || true)
  if [ -z "$en" ]; then
    echo "ORPHAN KO: docs/ko/$base has no English source"
    status=1
  fi
done

[ $status -eq 0 ] && echo "i18n: EN/KO doc sets are in parity."
exit $status
