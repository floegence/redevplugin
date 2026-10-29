# Changelog

## v3.3.2

- Validate rooted file descriptors before truncating bytes, preserving both paths when a hard-linked file is rejected.
- Reject copy-overwrite onto the same file, including a rooted symlink alias, before modifying the destination.
- Cover refused writes, copy-overwrite, legitimate truncation, append, and exclusive creation with file-integrity regression tests.

## v3.3.1

- Use a native modal dialog for Showcase app details, keeping background plugin frames out of modal focus and restoring the invoking control on close.
- Preserve newly reopened details when an earlier close event arrives, and cover Escape, backdrop dismissal, and mobile interaction.
- Remove decorative iframe admission animation that interfered with the first plugin click during modal transitions.

## v3.3.0

- Apply Web confinement headers to all responses, including rejected or expired origin routing.
- Correct the even-sized route performance order-bias median, record sustained
  warmup evidence, preallocate complete sample buffers, and lengthen short
  sampling windows without changing
  regression or noise thresholds.

- Expose a trusted-parent origin preparation adapter before child navigation, with aggregate opening deadlines, surface-lifetime cancellation, exact routing metadata, and no token or bootstrap override.
- Replace the virtual-node surface contract with one ordinary Web application runtime. Remove custom JSX, UI patches, rendering proxies, retired asset routes, and legacy package exports. Existing plugin packages must rebuild for the current Web manifest.
- Serve verified HTML, modules, styles, Workers, Canvas, WebGL, and WASM on independent per-container origins with one-use admission, source-bound ports, revocable resource leases, and browser-enforced outbound confinement. Unsupported browsers fail before application code executes.
- Preserve native application routing and Unicode resources; bind each document reconnection to a fresh identity and reject overlapping or stale handshakes.
- Add bounded unsaved-close negotiation and deterministic test clocks while keeping forced revocation independent of application confirmation.
- Migrate all platform examples and author scaffolds to native DOM applications with published Floe styling, light/dark themes, and responsive interactions.
- Validate packed SDK entrypoints in an independent consumer and cover real browser network receivers, lifecycle races, author workflows, and native application performance.

## v3.2.0

- Add the explicit local author project contract and init/dev/test workflow with isolated real Host preview, bounded builds, immutable package updates, explicit grants, and process cleanup.
- Publish production-bridge author fixtures through the UI testing entrypoint and a minimal read-only host embedding example.
- Include canonical project and test-report schemas in the platform release artifact set and real browser author acceptance in the local gate.
- Keep source-built Go platform identity anchored to VERSION when Go adds VCS pseudo-versions or dirty metadata. Published host dependencies retain their exact module identity.

## v3.1.0

- Upgrade golang.org/x/net to 0.62.0 to address reachable HTML parsing and rendering advisories GO-2026-6860 and GO-2026-6866.
- Add explicit Worker permission ceilings and surface startup requirements under authorization.scoped.v1, preserving absent-field package semantics and signed canonical content.
- Enforce the exact method ceiling in Host authorization, execution evidence, runtime I/O brokers, installation review, and permission discovery. Project independent surface availability through the released SDK.
- Add explicit background method and argument declarations under background.method.v1. Apply method policy, confirmation, request/response validation, and the existing execution lifecycle without overriding execution or cancellation behavior.

## v3.0.37

- Compare immutable process launch requests by field instead of hashing environment values and secret references; reject argument/environment boundary collisions and retain the original request after caller mutations.
- Raise the existing fast-uri override to 3.1.9 to address URI normalization advisories.
- Update the Go, npm, Rust, and GitHub Actions dependency groups from Dependabot PRs #38, #40, #41, #42, #43, and #44, including SQLite 1.61.0 and parse 2.8.20, and pin Go 1.27.3 with its matching official Linux validation image.

## v3.0.36

- Upgrade to Go 1.27.2 and golang.org/x/net 0.60.0 to clear the release security audit; pin the matching official Linux validation image and Go-compatible golangci-lint 2.15.0.

- Reuse validated method-schema content in one bounded concurrent compilation cache across manifest decoding and Host calls, preserving complete validation and resource identity.

- Support WebGL and WebGL2 on SDK-transferred canvases through the generated context allowlist while retaining opaque-origin, Worker, network, and canvas-budget restrictions.
- Verify real sandbox rendering, resize, context loss/restoration, close/reopen, native availability semantics, sealed APIs, and rejected resource limits.

## v3.0.35

- Add Host-owned headless background Worker lifecycle management with idempotent startup, cancellation, recovery, and shutdown cleanup.
- Bind process sessions to the originating plugin session/channel, expose bounded list and stream helpers, and release completed background sessions for recovery.
- Project local-process and background declarations in installation security reviews without exposing process handles, credentials, or plugin business state.

## v3.0.34

- Add generic local-process broker access with opaque handles, bounded binary streams, owner isolation, secret references, and process-tree cleanup.
- Add declarative process permissions, resource limits, headless background-entry lifecycle management, and Worker SDK process calls.

## v3.0.33

- Upgrade the Go, npm, GitHub Actions, and Rust dependency groups, including
  stable wasmi 2.0.0 and SQLite 1.59.0. Align the in-process engine identity and
  verified upstream license-source record with the released wasmi crates.
- Retain canvas backing stores on unchanged layout notifications, and verify
  hidden/visible transitions without duplicate initial repaint events.
- Reuse the validated canonical manifest bytes during registry reads and package
  admission instead of normalizing the same JSON twice. Preserve strict manifest
  validation and the original signed wire representation.

## v3.0.32

- Verify trusted-parent handshake transcripts and sandboxed asset bytes on HTTP
  origins using standard SHA-256 without requiring SubtleCrypto. Preserve exact
  transcript encoding, byte limits, digest checks, and sandbox restrictions.
- Generate the embedded renderer hash implementation from the pinned
  `@noble/hashes` dependency, retaining license and reproducible build evidence.
- Verify real network HTTP plugin startup and valid assets in Chromium, and
  reject same-length tampering without weakening browser security settings.

## v3.0.31

- Accept startup Worker prewarming diagnostics in the closed observability
  presentation contract so successful compilation and catalog, runtime, or
  module preparation failures reach durable and host-projected sinks.
- Verify successful and failed sessionless startup using the real SQLite sink,
  including reopen validation and rejection of arbitrary diagnostic content.

- Make examples UI weather reads deterministic while retaining real surface
  startup, Worker UI, WASM persistence, and independent network conformance.

## v3.0.30

- Start bounded worker compilation prewarming when a process Host opens before
  its first user session. Reuse the existing verified runtime lifecycle and
  module cache without creating sessions, leases, invocations or permissions.

- Add an optional bounded persistent release-document byte cache so installed
  plugin recovery does not repeat network downloads on every runtime restart.
  Current projection hashes, signatures, expiry and revocations are revalidated;
  cache failures fall back to the existing verified remote transport.
- Publish the disposable cache's initial SQLite schema and cover restart,
  corruption, changed projections, trust failures, cancellation and quotas.

## v3.0.29

- Open hidden, offscreen, and zero-size plugin surfaces without waiting for
  browser animation frames, while requiring verified initialization, worker
  readiness, and the first validated DOM commit.
- Start bounded lazy asset loading independently of browser paint and keep
  exact-surface cancellation, revocation, and retry behavior.
- Report bounded opening-stage progress and timeout diagnostics without
  exposing credentials or plugin content. Replace the private first-paint
  startup signal with renderer readiness in the current platform contract.
- Cover visibility transitions, suppressed animation frames, and each blocked
  opening milestone with real-browser and contract regression tests.

## v3.0.28

- Wait for the Host runtime, worker modules, and connectivity policy before
  dispatching an authorized worker call, while sharing preparation across
  concurrent calls and never retrying an executed method.

## v3.0.27

- Keep canvas CSS layout separate from backing pixels so hidden surfaces do not
  multiply their device pixel ratio again when a host switches views.
- Defer canvas transfer until layout is measurable, retain hidden canvas pixel
  reservations, and clean up pending opens on surface disposal.
- Validate DPR-scaled dimensions before delivering canvas metrics while retaining
  the existing worker dimension, count, and aggregate pixel limits.
- Update SQLite to 1.57.0, wasmparser/wat to the 0.258/1.258 family, CodeQL to
  4.37.9, ESLint to 10.9.1, and typescript-eslint to 8.68.0.

## v3.0.26

- Preserve the owning button's value when a plugin action is triggered by a
  nested label or icon, so selection controls respond across their full area.

## v3.0.25

- Let sandboxed plugin Surfaces export bounded PNG, JPEG, WebP, SVG, and text
  files through a Host-owned adapter after a current click or submit action.
- Allow sealed plugin OffscreenCanvas instances to encode image bytes while
  keeping constructors, direct downloads, and network escape paths blocked.

## v3.0.24

- Preserve the latest focus and text selection when a controlled Surface input
  receives another edit before its queued DOM patch commits.

## v3.0.23

- Deliver complete `keydown` and `keyup` input from the focused plugin Surface,
  including Canvas, editable controls, buttons, modifier keys, repeat state,
  IME composition state, and keyed target metadata.
- Let plugins install bounded exact keyboard bindings so the sandbox can
  synchronously prevent declared browser defaults without suppressing unbound
  control input.

## v3.0.22

- Deliver bounded wheel input to sandboxed plugin canvases with canvas-local
  coordinates, standard delta modes, and modifier keys.
- Keep wheel ownership on the canvas so zoom gestures do not also scroll the
  containing host surface.

## v3.0.21

- Keep retained plugin surfaces responsive when their host view is not rendered,
  while preserving animation-frame commits for visible surfaces.
- Cancel pending renderer commits during surface teardown so delayed callbacks
  cannot mutate a closed surface or advance its UI revision.

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
