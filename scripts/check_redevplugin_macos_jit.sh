#!/usr/bin/env bash
set -euo pipefail

# Qualify the product signing profile, not just an unsigned Cargo executable.
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS hardened-runtime qualification is only applicable on Darwin"
  exit 0
fi
ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
cd "$ROOT_DIR"
export GOWORK=off
cargo build --locked -p redevplugin-runtime
qualification_root=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-macos-jit.XXXXXX")
trap 'rm -rf "$qualification_root"' EXIT
install -m 0755 "${CARGO_TARGET_DIR:-target}/debug/redevplugin-runtime" "$qualification_root/redevplugin-runtime"
cat > "$qualification_root/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
</dict></plist>
PLIST
codesign --force --options runtime --sign - --entitlements "$qualification_root/entitlements.plist" "$qualification_root/redevplugin-runtime"
codesign --verify --strict --verbose=2 "$qualification_root/redevplugin-runtime"
REDEVPLUGIN_PERFORMANCE_RUNTIME="$qualification_root/redevplugin-runtime" \
  go test ./pkg/host -run '^TestPerformanceRuntime(ProductionWorkload|IsolationAndCancellation|SaturatedPluginPreservesOtherPluginCapacity)$' -count=1 -v
