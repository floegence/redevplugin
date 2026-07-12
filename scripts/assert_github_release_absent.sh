#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: assert_github_release_absent.sh <owner/repository> <tag>" >&2
  exit 2
fi

REPOSITORY=$1
TAG=$2
API_BASE=${GITHUB_API_URL:-https://api.github.com}
: "${GH_TOKEN:?GH_TOKEN is required}"

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid GitHub repository: $REPOSITORY" >&2
  exit 2
fi
if [[ ! "$TAG" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
  echo "invalid release tag: $TAG" >&2
  exit 2
fi

response=$(mktemp "${TMPDIR:-/tmp}/redevplugin-release-check.XXXXXX")
trap 'rm -f "$response"' EXIT

status=$(curl \
  --silent \
  --show-error \
  --location \
  --retry 3 \
  --retry-delay 2 \
  --retry-all-errors \
  --connect-timeout 10 \
  --max-time 30 \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer $GH_TOKEN" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  --output "$response" \
  --write-out '%{http_code}' \
  "$API_BASE/repos/$REPOSITORY/releases/tags/$TAG")

case "$status" in
  404)
    exit 0
    ;;
  200)
    echo "GitHub Release $TAG already exists; releases are immutable" >&2
    exit 1
    ;;
  *)
    echo "GitHub release lookup failed with HTTP $status" >&2
    sed -n '1,20p' "$response" >&2
    exit 1
    ;;
esac
