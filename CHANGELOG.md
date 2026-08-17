# Changelog

## v3.0.0

- Replace the compatibility matrix, contract registry, package-set publication,
  and public runtime/performance version axes with one current plugin API, one
  internal runtime wire, and one externally staged platform release manifest.
- Use `VERSION` as the platform release source and align the Go `/v3` module,
  npm packages, Rust crates, and canonical OpenAPI projection to `3.0.0`.
- Make manifest v9 the only accepted plugin package format and install verified
  plugins directly as enabled while keeping permission readiness Host-derived.
- Use a fresh, explicitly selected `redevplugin_control_v3` state root. ReDevPlugin
  does not discover, import, migrate, mutate, or delete a 2.x state root.

Earlier release history remains available from Git tags. It is intentionally not
maintained here as a current contract or compatibility promise.
