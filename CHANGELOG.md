# Changelog

## v3.0.5

- Validate execution authorization snapshots using the security facts they
  carry, so externally uploaded plugins remain runnable after explicit grants.

## v3.0.4

- Preserve manifest-declared worker permissions in execution bindings so
  authorized worker calls remain valid through runtime execution validation.

## v3.0.3

- Preserve remote release asset missing, integrity, and resolver failures as
  stable platform errors instead of collapsing them into an internal failure.

## v3.0.2

- Derive final public release-manifest verification from the canonical contract
  artifact list so the complete signed release manifest is verified after
  publication.

## v3.0.1

- Publish the filesystem-path canonicalization security fix from the current
  v3 main line as a complete Go, npm, Rust source-crate, and contract package
  set.

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
