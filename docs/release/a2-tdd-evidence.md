# A2 Opaque Plugin Surface TDD Evidence

This document records the test-driven evidence for the A2 opaque plugin
surface host implemented from ReDevPlugin v0.2.0 and first completely published
in v0.2.2. A2 owns the host-neutral iframe,
asset session, transferred `MessageChannel`, trusted renderer, plugin worker,
surface lifecycle, and release-gate behavior. Product navigation, Electron
policy, and business capability adapters remain host-product responsibilities.

## Recorded Red Signals And Executable Regression Evidence

This record does not reconstruct a Git commit sequence. The A2 feature remained
uncommitted while its TDD slices were exercised, so the table distinguishes
observed red signals from executable negative fixtures instead of claiming a
commit order that does not exist. The opening-deadline test was run against the
pre-fix implementation and failed with `Missing expected rejection`; the
published-release and npm provenance rows are enforced by deterministic mutation
fixtures that must be rejected on every run.

| Area | Regression evidence | Observed baseline or executable negative signal | Passing command and enforced behavior |
| --- | --- | --- | --- |
| Opaque browser proof | `internal/browserharness/opaque-surface-contract.test.mjs` and browser acceptance probes | The retired v1 browser fixture loaded plugin pages from a sandbox origin, used `allow-same-origin`, and had no opaque `srcdoc` worker path | `npm run test:browser-harness:smoke` proves exact `sandbox="allow-scripts"`, opaque origin, strict CSP, both credentialless branches, blocked parent DOM/storage/network access, classic worker execution, and deterministic disposal |
| SDK-owned iframe | `packages/redevplugin-ui/test/opaque-surface.test.ts` | `PluginSurfaceHost`, closed preparation documents, frame-generation acknowledgement, and parent-only transport did not exist | `npm --prefix packages/redevplugin-ui test` proves fresh SDK-owned iframe creation, immutable placement element, secret-free port transfer, prepare/ack/token ordering, lease renewal, reload limits, and fail-closed teardown |
| Plugin entrypoint isolation | `packages/redevplugin-ui/test/entrypoints.test.ts` | The package root mixed trusted-parent management and plugin bridge APIs | `npm --prefix packages/redevplugin-ui test` proves `/plugin` exports only `PluginBridgeClient`, the root is the trusted-parent allowlist, and the internal bootstrap factory is not public |
| Token and ticket contract | `pkg/protocol/token_ticket_schema_test.go` plus `testdata/contracts/tokens/asset-ticket-v2.json` | The v1 fixture did not bind the opaque asset session and did not reject unknown fields through a typed round trip | `GOWORK=off go test -count=1 ./pkg/protocol ./pkg/version` proves JSON Schema validation, closed typed decoding, canonical round trip, required `asset_session_nonce`, and unknown-field rejection |
| Host surface lifecycle | `pkg/bridge/surface_test.go`, `pkg/host/surface_cache_test.go`, and `pkg/httpadapter/httpadapter_test.go` | The v1 host exposed origin/cookie asset routes and lacked prepare, parent-only asset read, scope revoke, and revision-bound disposal semantics | `GOWORK=off go test -count=1 ./pkg/bridge ./pkg/host ./pkg/httpadapter` proves bounded sessions, single-use credentials, prepared-document and generation gates, digest revalidation, stale revision rejection, scope revocation, and side-effect-free failures |
| Package render policy | `pkg/pluginpkg/surface_document_test.go`, `pkg/manifest/method_schema_test.go`, and malicious generated fixtures | Plugin HTML and method schemas were not constrained by one generated closed policy | `GOWORK=off go test -count=1 ./pkg/pluginpkg ./pkg/manifest` proves one classic worker, closed DOM/CSS/asset policy, compiled closed request/response schemas, and rejection of executable or dependency-bearing package content |
| Renderer resource budgets | `opaque-surface.test.ts`, Canvas/image browser smoke, and generated render-policy checks | Canvas transfer, decoded image area, pointer traffic, and worker-created graphics resources were not one closed budget | `npm run test:ui` and browser smoke prove four-canvas, dimension, aggregate-pixel, 120 Hz pointer, 32-image, pre-decode dimension, `OffscreenCanvas`, and `createImageBitmap` enforcement |
| Worker liveness and quiesce | Async lifecycle and non-responsive close tests in `opaque-surface.test.ts` | Immediate teardown could race plugin persistence, while a stalled worker had no private renderer liveness proof | `npm run test:ui` proves async observers settle before quiesce ACK, close remains bounded at 1.5 seconds, and the 10-second ping/5-second pong deadline fails closed |
| Bridge source scan | Extended `scripts/check_redevplugin_ui_bridge.sh` | Generated examples, scaffold assets, browser-harness fixtures, and generated-plugin fixtures were outside the wildcard-message scan | `./scripts/check_redevplugin_ui_bridge.sh` allows only the secret-free internal bootstrap transfer and rejects trusted-parent imports or wildcard `postMessage` in plugin code |
| Real runtime integration | `internal/browserharness/examples-server-smoke.mjs` and `opaque-surface-smoke.mjs` | The retired v1 runtime fixture depended on plugin pages, subdomain/cookie bootstrap, and direct route-shaped plugin logic | `npm run test:browser-harness:smoke` runs the Go Host, HTTP adapter, Rust runtime, opaque iframe, classic worker, parent-only assets/streams, storage broker, and network broker together; it verifies Memos autosave, stale-search rejection, pinning, quiesce persistence, modal focus containment, delete-failure recovery, failed-save recovery, and desktop/mobile product layouts; Weather saved-location/network flows and navigation focus; Sky Strike canvas pixels/animation/accessibility/FPS behavior, deterministic score persistence and reload; and compact 320 px containment |
| Memos product contract | `examples/memos_product_test.go` | The previous example mixed dashboard summaries, a permanent metadata rail, duplicated save/pin controls, and presentation-specific implementation assumptions | `GOWORK=off go test ./examples -run '^TestMemos' -count=1` proves one autosave/pin model, consumer library/editor state, cancellable search sequencing, modal background isolation, bounded storage paging, complete compact editing, and removal of the retired dashboard structures |
| Bounded opening | `surface opening deadline revokes server state, tears down locally, and remains retryable` in `opaque-surface.test.ts` | Before the total deadline was implemented, the test failed with `Missing expected rejection` because individually bounded prepare/token stages could exceed the aggregate opening budget | `npm run test:ui` proves timeout error identity, server revoke, local iframe/port teardown, one bounded retry charge, and healthy retry reset |
| Release identity | Release artifact fixtures plus `test_published_release_verifier.mjs` and `test_npm_registry_release_verifier.mjs` | The valid npm 11 fixture deliberately omits optional `gitHead`; mutation fixtures alter target sets, extra assets, npm tarball bytes, worker SDK crate bytes, a supplied `gitHead`, SLSA subject digest, repository, workflow path/ref, and source commit; every conflicting mutation must fail | The runtime contract gate verifies the exact four-target signed asset set, identical embedded npm and Worker SDK bytes, npm export set, compatibility/license evidence, actual registry tarball SHA-512, optional metadata consistency, and mandatory SLSA DSSE source identity |
| Release version closure | `check_redevplugin_release_metadata.mjs` and `test_redevplugin_release_metadata.mjs` | Mutation fixtures drift the tag coordinate, Go compatibility floor, first changelog release, Worker SDK version, and canonical Cargo manifest path | `npm run release-metadata:check` proves source metadata agrees on one release version, while tagged preflight repeats the check against the actual Git tag before any package job starts |

## Contract And Generated Artifact Evidence

A2 updates the following public sources and their generated identities together:

- `spec/openapi/plugin-platform-v3.yaml`;
- `spec/plugin/bridge-v3.schema.json`;
- `spec/plugin/token-ticket-v2.schema.json`;
- `spec/plugin/opaque-surface-document-v2.schema.json`;
- `spec/plugin/opaque-surface-transport-v2.schema.json`;
- `spec/plugin/wasm-worker-v2.schema.json`;
- `spec/plugin/compatibility-manifest-v3.schema.json`;
- `spec/plugin/release-manifest-v3.schema.json`;
- `spec/plugin/contract-registry-v1.json`;
- generated Go version/contract registries and TypeScript contract/render-policy
  registries;
- route, token, generated-plugin, browser, and release verifier fixtures.

`npm run contracts:generate` is the only generation path. `npm run
contracts:check`, Go protocol tests, runtime/platform contract scripts, and the
release bundle verifier reject stale generated files or mismatched hashes.

## Release Gate Evidence

The tagged workflow blocks every immutable package or publication operation on
all of the following independent gates:

- `quality-release`: Go format/test/lint, TypeScript lint/typecheck/build/unit/
  Examples/browser-harness tests, bridge boundary checks, Rust format/clippy/test/deny,
  and
  both runtime and platform contract suites;
- `audit-release`: npm, Go vulnerability, and Rust dependency audit;
- `stress-release`: release-mode race, lifecycle, broker, browser, runtime,
  release-bundle, and A2 screenshot/evidence checks.

The SDK pack job installs the WASM target, builds the npm tarball and Rust
Worker SDK crate once, and compiles the extracted `.crate` with its locked
dependencies. Every
native runtime bundle job, npm trusted publication, and GitHub Release
publication explicitly depends on `quality-release`. The release then downloads
the public npm tarball, recomputes SHA-512, validates the SLSA
DSSE subject/repository/workflow/tag/source commit, and verifies GitHub tag/release identity,
four runtime targets, identical embedded Worker SDK crate bytes,
signatures/checksums, compatibility hashes, Go direct and proxy module identity,
and the exact npm export surface from public coordinates.

## Boundary Result

- Host products mount the read-only iframe element and supply host-neutral
  transport/session policy; they do not construct plugin frames or bootstrap
  documents.
- Plugin workers import only `@floegence/redevplugin-ui/plugin` and receive no
  management client, asset ticket, stream ticket, gateway credential, parent
  origin, or host storage access.
- Trusted parent code imports the root or `/trusted-parent`; raw package import
  remains isolated under `/local-import`.
- Surface disable, uninstall, update, downgrade, scope revoke, runtime stop, and
  local update close matching ports, frames, requests, streams, and server
  sessions without switching to another runtime path.
- Active v1 sandbox-origin, cookie bootstrap, plugin page, direct asset/stream,
  and browser-site storage code is removed rather than retained as a fallback.
