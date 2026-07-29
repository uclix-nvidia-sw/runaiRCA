#!/usr/bin/env bash
# Fail when docs backtick a TypeDB entity, relation, attribute, or function that
# existed in the repository history but has since been removed. This does NOT
# catch current-but-wrong names, unbackticked prose, typos, or names absent from
# the available git history.
#
# The history walk is deliberately bounded to revisions that changed schema.tql
# or functions.tql. Requires full history (the workflow uses fetch-depth: 0).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

schema=agent/ontology/schema.tql
functions=agent/ontology/functions.tql
allowlist=scripts/check-removed-ontology-docs.allowlist
status=0
tick=$(printf '\140')

removed_names() {
  comm -23 \
    <({
      while IFS= read -r revision; do
        git show "$revision:$schema" | sed -nE 's/^[[:space:]]*(entity|relation|attribute)[[:space:]]+([[:alnum:]_]+).*/\2/p'
      done < <(git log --format=%H -- "$schema")
      while IFS= read -r revision; do
        git show "$revision:$functions" | sed -nE 's/^[[:space:]]*fun[[:space:]]+([[:alnum:]_]+)\(.*/\1/p'
      done < <(git log --format=%H -- "$functions")
    } | sort -u) \
    <({
      sed -nE 's/^[[:space:]]*(entity|relation|attribute)[[:space:]]+([[:alnum:]_]+).*/\2/p' "$schema"
      sed -nE 's/^[[:space:]]*fun[[:space:]]+([[:alnum:]_]+)\(.*/\1/p' "$functions"
    } | sort -u)
}

allowed() {
  grep -Fqx -- "$1" "$allowlist" || grep -Fqx -- "$2" "$allowlist"
}

while IFS= read -r name; do
  needle="$tick$name$tick"
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file=${hit%%:*}
    if ! allowed "$file:$name" "$name"; then
      echo "REMOVED ONTOLOGY NAME: $hit"
      status=1
    fi
  done < <(find docs -type f -name '*.md' -exec grep -n -F "$needle" {} + || true)
done < <(removed_names)

[ "$status" -eq 0 ] && echo "ontology docs: no removed names referenced."
exit "$status"
