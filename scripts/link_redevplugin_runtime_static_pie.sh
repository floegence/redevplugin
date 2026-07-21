#!/usr/bin/env bash

set -euo pipefail

# Rust 1.88 downgrades static PIE to StaticNoPicExe for the built-in Linux GNU
# targets. Remove the resulting driver flags so GCC selects the static PIE CRT
# objects and linker mode consistently.
link_args=()
for argument in "$@"; do
  case "$argument" in
    -static|-no-pie)
      ;;
    *)
      link_args+=("$argument")
      ;;
  esac
done

exec "${REDEVPLUGIN_STATIC_PIE_CC:-cc}" "${link_args[@]}" -static-pie
