#!/usr/bin/env bash
set -euo pipefail

REQUIRE_RELEASE=0

usage() {
  cat <<'USAGE'
Usage: scripts/verify_github_release_identity.sh [--require-release] <owner/repo> <tag> <expected-commit>

Resolves the public GitHub tag through annotated tags to its commit and checks
that it matches the expected immutable source coordinate. --require-release
also requires a published, non-draft GitHub Release for the same tag.
USAGE
}

if [[ "${1:-}" == "--require-release" ]]; then
  REQUIRE_RELEASE=1
  shift
fi
if [[ $# -ne 3 ]]; then
  usage >&2
  exit 2
fi

REPOSITORY=$1
TAG=$2
EXPECTED_COMMIT=$3

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ || ! "$TAG" =~ ^v[0-9A-Za-z._-]+$ || ! "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  usage >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to verify the public GitHub release identity" >&2
  exit 1
fi

read -r object_type object_sha < <(
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "repos/$REPOSITORY/git/ref/tags/$TAG" \
    --jq '.object.type + " " + .object.sha'
)

for _ in 1 2 3 4; do
  case "$object_type" in
    commit)
      break
      ;;
    tag)
      read -r object_type object_sha < <(
        gh api \
          -H "Accept: application/vnd.github+json" \
          -H "X-GitHub-Api-Version: 2022-11-28" \
          "repos/$REPOSITORY/git/tags/$object_sha" \
          --jq '.object.type + " " + .object.sha'
      )
      ;;
    *)
      echo "GitHub tag $TAG resolves to unsupported object type $object_type" >&2
      exit 1
      ;;
  esac
done

if [[ "$object_type" != "commit" || "$object_sha" != "$EXPECTED_COMMIT" ]]; then
  echo "GitHub tag $TAG resolves to $object_type $object_sha, want commit $EXPECTED_COMMIT" >&2
  exit 1
fi

if [[ "$REQUIRE_RELEASE" -eq 1 ]]; then
  read -r release_tag release_draft < <(
    gh api \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "repos/$REPOSITORY/releases/tags/$TAG" \
      --jq '.tag_name + " " + (.draft | tostring)'
  )
  if [[ "$release_tag" != "$TAG" || "$release_draft" != "false" ]]; then
    echo "GitHub Release identity mismatch for $TAG" >&2
    exit 1
  fi
fi

echo "GitHub release identity verified: $REPOSITORY@$TAG -> $EXPECTED_COMMIT"
