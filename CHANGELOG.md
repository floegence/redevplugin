# Changelog

## v3.0.20

- Keep sealed runtime launch compatible with Linux 5.9 and 5.10 by falling
  back to segmented descriptor closure only when `CLOSE_RANGE_CLOEXEC` is not
  supported.

## v3.0.19

- Admit the verified runtime through the historical executable-memfd default
  when a Linux kernel rejects the newer explicit execution flag, while keeping
  the existing digest, ELF, sealing, and containment checks unchanged.
- Start, bind, and prewarm worker runtimes through one enabled-state activation
  path for installs, updates, enablement, downgrades, and startup recovery.

## v3.0.18

- Allow canonical non-negative `maxlength` values on sandboxed input elements.
- Preserve the first renderer failure through opening revocation and local teardown.
- Report one authoritative opening error instead of replacing it with a disposal error.

## v3.0.17

- Resolve each pinned capability contract once while projecting plugin action state and permission requirements.
- Keep exact contract validation while removing method-count-dependent inventory latency.

## v3.0.16

- Treat canceled enabled-plugin recovery as request control flow instead of a cached plugin failure.
- Do not publish or retain a recovery snapshot when the recovery request is canceled.

## v3.0.15

- Classify non-JSON HTTP failures as transport rejections with their HTTP status instead of reporting invalid JSON.
- Preserve invalid JSON diagnostics for successful responses and keep valid platform error envelopes mapped to stable error codes.

## v3.0.14

- Publish explicit release-install failure retryability with each failed progress event.
- Export the canonical TypeScript progress type and decoder so hosts do not recreate the platform event contract.
- Add a closed release-install Execution filter so hosts recover tasks without guessing from general operations.
- Preserve interrupted installation failure semantics across Host restarts.
- Classify unknown internal install failures and temporarily unavailable runtimes as retryable while keeping version incompatibility terminal.

## v3.0.13

- Remove the production dynamic-import CSP probe so normal plugin startup does not emit an expected Console violation.
- Keep strict sandbox enforcement and move the one-time dynamic-import denial check into the browser security harness.

## v3.0.12

- Bind official market installation to a canonical release identity digest and reject tampered release references.
- Remove the obsolete official-install inspection phase while retaining inspection for external package sources.

## v3.0.11

- Let verified presentation icon extraction consume the same exact capability
  contract artifacts as release verification, so capability-backed releases
  retain one fail-closed evidence path through market ingest.

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
