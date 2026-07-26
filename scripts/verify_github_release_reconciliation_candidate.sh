#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: verify_github_release_reconciliation_candidate.sh <owner/repository> <tag> <source-commit>" >&2
  exit 2
fi

repository=$1
tag=$2
source_commit=$3

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]
: "${GH_TOKEN:?GH_TOKEN is required}"

pages=$(mktemp "${RUNNER_TEMP:-/tmp}/redevplugin-release-pages.XXXXXX")
release=$(mktemp "${RUNNER_TEMP:-/tmp}/redevplugin-release.XXXXXX")
trap 'rm -f "$pages" "$release"' EXIT

gh api --paginate --slurp "repos/${repository}/releases?per_page=100" > "$pages"
jq -e 'type == "array" and all(.[]; type == "array" and length <= 100)' "$pages" > /dev/null
match_count=$(jq --arg tag "$tag" '[.[][] | select(.tag_name == $tag)] | length' "$pages")
case "$match_count" in
  0) exit 0 ;;
  1) ;;
  *) echo "release preflight found multiple exact-tag matches" >&2; exit 1 ;;
esac

release_id=$(jq -r --arg tag "$tag" '.[][] | select(.tag_name == $tag) | .id' "$pages")
[[ "$release_id" =~ ^[1-9][0-9]*$ ]]
gh api "repos/${repository}/releases/${release_id}" > "$release"
marker="<!-- redevplugin-release-transaction-v1 source_commit=${source_commit} -->"
jq -e --argjson id "$release_id" --arg tag "$tag" --arg marker "$marker" '
  .id == $id and
  .tag_name == $tag and
  .prerelease == false and
  (.draft | type == "boolean") and
  ((.body // "") | contains($marker))
' "$release" > /dev/null || {
  echo "existing release is not an exact reconciliation candidate" >&2
  exit 1
}
