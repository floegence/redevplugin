# Changelog

## v3.0.10

- Add direct official-market installation with stable download, verification,
  install, and enable progress events; market installs no longer require a
  package inspection transaction.
- Bind market install declarations to the exact release and verified package
  evidence while retaining inspection for external package sources.

## v3.0.9

- Preserve the instance revoke epoch across retained-data and delete-data
  reinstalls so a freshly installed plugin can mint new surface credentials in
  the same Host session without reviving credentials revoked by uninstall.
- Remove the obsolete control-store external-install bypass so every fresh and
  repeated install commits through the same plugin-data and tombstone
  transaction; the remaining external-package control path is update-only.

## v3.0.8

- Make official release inspection the single installation entry point, reuse
  its short-lived owner-bound verified package during commit, and remove the
  obsolete synchronous release-install route.
- Fetch the release signature and package concurrently after metadata
  verification, keep inspection free of lifecycle and runtime preflight work,
  and derive permission review from verified capability contracts without
  requiring a live business adapter.
- Preserve stable inspection, package, trust, runtime, and retained-data errors
  with the exact failed installation phase.

## v3.0.7

- Add an environment-level reset API with a canonical ownership manifest,
  exact platform-owned paths, preflight, idempotent cleanup, and a cross-process
  Host lock. Reset fails closed for a live Host, a tampered manifest, unsafe
  roots, symlinks, or unrecognized data categories.

## v3.0.6

- Allow reinstall after deleting plugin data and expose a stable error when
  retained plugin data is incompatible with the package being installed.

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
