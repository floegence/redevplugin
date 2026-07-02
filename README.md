# ReDevPlugin

ReDevPlugin is the reusable plugin platform intended to be consumed by host
products through published Go, TypeScript, Rust runtime, and
machine-contract artifacts.

This repository owns the host-neutral plugin platform core. Host products own
their product policy, UI shell integration, session adapters, and business
capabilities.

## Current Platform Snapshot

- Go module: `github.com/floegence/redevplugin`
- TypeScript package: `@floegence/redevplugin-ui`
- Rust workspace: `redevplugin-runtime` and support crates
- Contracts: OpenAPI, manifest schema, package-signature schema, token/ticket
  schema, iframe bridge schema, compatibility manifest schema, IPC schema,
  WASM ABI schema, worker invocation payload schema, stable error-code schema,
  and target classifier fixture
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, storage, runtime supervision, grants, cleanup,
  capability adapters, HTTP routes, session context, and web security.
- Storage brokers include both an in-memory test broker and a filesystem-backed
  broker that creates per-plugin-instance namespace directories under a
  host-selected state root, enforces quota accounting, rejects symlink escape
  attempts, supports export/import archives, and makes uninstall data deletion
  or retention observable on disk.
- Stream stores include both in-memory and SQLite-backed implementations. The
  SQLite store persists stream records and buffered events, enforces the same
  backpressure behavior, drains read events from the buffer, marks streams
  orphaned during plugin disable/uninstall transitions, and uses a package-local
  schema migration marker with newer-schema fail-closed behavior.
- Settings stores include both in-memory and SQLite-backed implementations. The
  SQLite store persists setting records and export archives, reuses the shared
  validation/default/secret-redaction lifecycle, restores settings across
  process restarts, and keeps retained bind/import behavior durable without
  storing secret plaintext.
- Browser-site origin stores include both in-memory and SQLite-backed
  implementations. The SQLite store persists sandbox origin registrations,
  keep-data retention, delete-data cleanup completion, retryable cleanup
  failures, and require-retained guards across host restarts.
- Observability stores include both in-memory and SQLite-backed implementations.
  The SQLite store persists audit and diagnostic events, preserves the same
  filtering, defaults, newest-first ordering, retention limits, and generated
  event IDs as the in-memory store, and uses a package-local schema migration
  marker with newer-schema fail-closed behavior.
- Secret binding stores include both in-memory and SQLite-backed
  implementations. They persist only plugin-instance, scope, secret-ref, bound
  state, and test/delete metadata, never secret plaintext, so hosts can keep the
  actual vault implementation product-owned while reusing common lifecycle
  state, filtering, cleanup, and newer-schema fail-closed behavior.
- Host lifecycle APIs include `RefreshEnabledPlugins`, which lets an embedding
  product restore enabled plugin runtime state after restart by replaying
  storage/settings initialization, connectivity policy installation, and
  surface publication from the durable registry without re-enabling plugins.
  The mountable HTTP adapter exposes the same behavior at
  `POST /_redevplugin/api/plugins/runtime/refresh-enabled`, so hosts can keep
  route mounting thin instead of reimplementing the refresh loop.
- Plugin package IO keeps deterministic canonical package hashes separate from
  detached `signatures/package.sig` metadata. Signature files are retained for
  trust verification but are excluded from canonical package entries, asset
  serving, and the package hash to avoid self-referential signatures.
- Install and update flows treat `trust_state` in management requests as a
  requested outcome, not as proof. Runnable verified/bundled trust states require
  a host-provided `PackageTrustVerifier`, while unsigned local and review states
  can be installed for developer or review flows without becoming runnable unless
  later policy permits it.
- The host-neutral `pkg/trust` package provides an Ed25519 verifier and keyring
  interface for package signatures. Hosts still decide which keys, publishers,
  registries, or enterprise policies are trusted, but they can reuse the common
  canonical signature payload and verification checks.
- The CLI can generate local Ed25519 signing keys and produce signed package
  artifacts without placing private keys in shell arguments. Start with
  `redevplugin scaffold <plugin-id> <display-name> <out-dir>`, package the
  generated UI plus WASM backend worker skeleton, including a second brokered
  worker that demonstrates Host-owned storage and network access, then sign it:
  `redevplugin keygen <key-id> <private.json> <public.json>` followed by
  `redevplugin sign <unsigned.redevplugin> <private.json> <signed.redevplugin>`.
  Development harnesses can then run
  `redevplugin install-verified <signed.redevplugin> <public.json>` to prove
  the Host trust-verifier path accepts the signed package.
- Mountable HTTP routes can call a host-provided `websecurity.Guard` for origin
  and CSRF policy while keeping the concrete session and token semantics in the
  host product.
- The CSP report endpoint accepts only CSP/browser JSON content types, limits
  report bodies to 32 KiB and JSON depth 16, and applies a host-replaceable
  per sandbox origin, active fingerprint, and source IP rate limiter before
  appending diagnostics.
- Sandboxed plugin package assets are served with CSP, reporting, permissions,
  referrer, CORP, nosniff, and service-worker scope headers; hosts pass exact
  frame ancestors when embedding the sandbox iframe.
- Contract tests that keep the Go HTTP route set, OpenAPI paths, route fixture,
  and TypeScript SDK route coverage aligned. Browser-owned protocol endpoints
  such as asset bootstrap, asset fetches, and CSP reports must be explicitly
  classified when they intentionally do not expose a management SDK wrapper.
- Stable error-code contract tests keep the Go `pkg/security` catalog, OpenAPI
  envelope enum, iframe bridge schema, TypeScript SDK exports, and Rust IPC
  runtime-origin error constants aligned. The catalog separates server platform
  codes, bridge response codes, TypeScript client-only fallback codes, and Rust
  IPC codes so product shells can branch on stable values without scraping
  localized messages.
- Bridge contract checks that keep sandbox iframe message names, exact-origin
  messaging, UI protocol version, and parent-only token boundaries aligned with
  the TypeScript SDK.
- The TypeScript package includes both sandbox iframe bridge helpers and a
  host-side `PluginPlatformClient` for existing platform management routes:
  compatibility manifest read, install/update/downgrade,
  enable/disable/uninstall, surface open,
  runtime start/health/refresh-enabled/stop, settings schema/read/patch,
  operation list/get/cancel, data export/import, permission grant/revoke/list,
  secret bind/test/delete, host-mediated intent list/invoke, and
  audit/diagnostic event list. List helpers preserve the same data wrapper fields
  returned by the Go HTTP adapter, such as `operations`, `permissions`,
  `audit_events`, and `diagnostic_events`, so host products can consume the SDK
  and raw HTTP contract consistently. The browser demo uses this client from the
  host page to exercise settings management without exposing management
  credentials to the sandboxed iframe.
- `redevplugin version` emits a host-consumable compatibility manifest with the
  current platform version matrix plus SHA-256 hashes for the released OpenAPI,
  manifest, signature, token/ticket, bridge, IPC, WASM, network-grant, and
  worker invocation, error-code, and target-classifier contracts.
- Mounted hosts can also expose the same compatibility manifest through
  `GET /_redevplugin/api/plugins/platform/compatibility`, allowing a product to
  verify the loaded platform artifact set without shelling out to the CLI; the
  TypeScript `PluginPlatformClient.getCompatibility()` helper reads the same
  endpoint for browser-hosted product shells.
- `redevplugin verify-compatibility <compatibility.json> <artifact-root>` checks
  a released compatibility manifest against the current version matrix and the
  referenced contract artifact hashes. Host products can use this command before
  upgrading a published ReDevPlugin dependency set.
- Connectivity brokers compile manifest-declared HTTP, WebSocket, TCP, and UDP
  connectors into grantable policies. The host-neutral network executor now
  consumes short-lived connection grants and performs bounded HTTP
  request/response calls plus WebSocket, TCP, and UDP round trips with explicit
  timeout, request-size, and response-size limits. It revalidates grant expiry,
  transport, destination, and the target classifier at execution time so UI
  bridge calls and backend worker hostcalls can share the same fail-closed
  network boundary. Long-lived WebSocket subscriptions remain tied to the
  streaming envelope contract instead of the one-shot round trip API.
- Host tests include a black-box runtime subprocess path that invokes a worker
  method, has the helper runtime request `network_execute` over IPC, mints the
  grant through the Host connectivity broker, and records HTTP, WebSocket, TCP,
  and UDP executor request/response paths before returning the worker result.
- The Rust runtime now performs the first executable worker slice: it requests
  the bound WASM artifact from the Host over IPC, validates the WASM binary
  header and required function export through `redevplugin-wasm-abi`, executes
  the exported no-argument worker entrypoint with the embedded Wasmi engine, and
  returns a successful scaffold worker result over `invoke_worker_result`. It
  also exposes brokered storage and network hostcalls. Generated plugins now use
  the real linear-memory ABI by default:
  `redevplugin.storage/files(req_ptr, req_len, out_ptr, out_len) -> i32`,
  `redevplugin.storage/kv(req_ptr, req_len, out_ptr, out_len) -> i32`,
  `redevplugin.storage/sqlite(req_ptr, req_len, out_ptr, out_len) -> i32`, and
  `redevplugin.network/execute(req_ptr, req_len, out_ptr, out_len) -> i32`.
  The worker writes bounded JSON broker requests into WASM memory, the Rust
  runtime injects Host-owned identity, policy, grant, and revoke context,
  executes the requests through the `storage_file`, `storage_kv`,
  `storage_sqlite`, and `network_execute` IPC paths, and writes JSON responses
  back into worker-provided output buffers. The earlier fixed
  `*_demo` imports and `redevplugin.network/http_request` alias remain covered only as legacy runtime compatibility fixtures,
  not as the scaffolded plugin backend contract. Host integration tests build
  and exercise the real Rust runtime whenever a local Cargo toolchain is
  available, including FileBroker file writes, KV writes, SQLite DDL through the
  filesystem-backed broker, generated scaffold broker workers using the memory
  ABI, HTTP/WebSocket/TCP/UDP network memory hostcalls, and linear-memory HTTP
  executor paths.
- `redevplugin inspect-storage <storage-root> [plugin-instance-id]` reports
  filesystem broker namespaces, quota, and usage without dumping plugin file
  contents. Host products can wrap this for diagnostics while keeping the
  storage root selection in their own adapter layer.
- Host data export/import keeps storage archives and settings archives as
  separate refs. Settings imports validate non-secret fields against the target
  manifest schema and never restore secret plaintext or a bound-secret state;
  users must rebind secret refs after moving plugin data to another environment.
- `redevplugin dev-install <state-root> <package>` creates a persistent local
  development state root for Flower-generated plugins. The matching
  `dev-enable`, `dev-open <surface-id> [sandbox-origin]`, `dev-disable`,
  `dev-secret-bind <secret-ref> [user|environment]`,
  `dev-secret-test <secret-ref> [user|environment]`,
  `dev-secret-delete <secret-ref> [user|environment]`,
  `dev-permission-grant <permission-id> [granted-by]`,
  `dev-permission-revoke <permission-id> [reason]`,
  `dev-permission-list [--active-only]`,
  `dev-export-data [--include-secrets]`,
  `dev-import-data [--archive-ref <ref>] [--settings-archive-ref <ref>] [--delete-existing|--merge]`,
  `dev-uninstall [--delete-data|--keep-data]`, and `dev-status` commands replay
  the saved package through the real Host lifecycle APIs while keeping the
  copied package, filesystem storage root, manifest-level settings, redacted
  secret-ref binding/test state, permission grant/revoke records, and sandbox
  browser-origin records under the same state root. Dev secret commands never
  store secret plaintext; they only persist the declared `secret_ref`, scope,
  bound flag, and test status that the Host settings API can expose as redacted
  state. Dev permission commands call the Host permission APIs, so policy
  revisions and revoke epochs move exactly as they do in an embedded host
  product. Dev data export/import commands call the Host data lifecycle APIs and
  persist returned storage/settings archive refs under the same state root;
  settings archives never restore secret plaintext, so secret refs must still be
  rebound after moving data between environments. This gives generated plugins a local, auditable
  install -> enable -> open -> disable -> uninstall flow without importing any
  host-product internals. Uninstall removes the copied package; `--delete-data`
  also removes plugin storage namespaces, manifest settings, dev secret-ref
  state, permission grants, and marks browser-origin data cleanup complete,
  while `--keep-data` marks declared plugin data retained and preserves redacted
  dev secret-ref state for the local developer profile. Permission grants are
  removed on every uninstall, including `--keep-data`, because authorization is
  tied to the installed plugin lifecycle rather than retained user data.
- The browser demo under `demo/browser/` runs a real host page plus sandboxed
  iframe plugin page using the built `@floegence/redevplugin-ui` bridge package.
  Start it with `npm run demo:browser`, open the printed host URL, then exercise
  handshake, lifecycle, ordinary RPC, storage-list RPC, streaming,
  dangerous-confirmation, and richer plugin surfaces. The host and plugin page
  are served from separate localhost origins to exercise exact-origin sandbox
  bridge behavior. The demo picker includes a workspace tools plugin, an
  animated canvas bouncer game with particles, trails, power-ups, score saving,
  achievements, replay file exports, stored challenge snapshots, and a
  host-backed leaderboard; a schedule planner that lists/adds/toggles/deletes
  host-backed stored items, displays storage revision/quota/timeline metadata,
  inspects the demo SQLite schema, backs up and restores stored items through
  the file broker, and keeps data through host-page reloads;
  and a weather plugin that saves the current location, requests a
  host-network-backed HTTP forecast payload through the demo network broker,
  parses the raw JSON response inside the sandboxed plugin UI, and renders
  current, hourly, forecast, broker endpoint, response headers, parser
  field-mapping diagnostics, saved-location comparison, and network-history
  views.
  For the Flower-generated plugin path, run `npm run demo:browser:generated`.
  That launcher scaffolds a plugin with a backend worker skeleton, packages it,
  installs it into a temporary dev state root, enables it, opens its activity
  surface, prints a browser URL, and cleans up by disabling and uninstalling the
  plugin with data deletion when the process exits. For the real runtime path,
  run `npm run demo:browser:real`. That launcher builds `redevplugin-runtime`,
  starts the host-neutral Go demo server, prints a browser URL, serves the plugin
  through the sandbox asset-session protocol, and deletes the temporary demo
  state when the process exits.
  `npm run test:demo` covers the fake platform API and static sandbox contract;
  `npm run test:demo:browser` launches a real browser, clicks through the iframe
  demo flow, generates a fresh plugin with `redevplugin scaffold`, packages it,
  installs, enables, and opens it through the persistent dev lifecycle harness,
  serves that generated plugin from the sandbox origin, verifies its backend call
  UI end to end, then disables and uninstalls it with data deletion. The same
  browser smoke now also starts `redevplugin demo-real-server`, which wires a
  scaffolded plugin through the real Go Host library, the HTTP adapter, a
  fresh asset-ticket/bootstrap exchange, a sandboxed iframe, and the built Rust
  runtime process. In that real-server path the host page and plugin sandbox use
  separate `*.redevplugin.localhost` origins, the parent exchanges the asset
  ticket through the sandbox `/_redevplugin/bootstrap` endpoint, the iframe loads
  packaged UI through `/_redevplugin/assets/{asset_session_id}/ui/index.html`,
  and the smoke asserts the path-scoped HttpOnly asset-session cookie plus
  absence of legacy `/ui/index.html` static loading. The generated plugin UI is
  clicked in the browser and must
  receive a `worker.echo` result whose transport is `rust runtime ipc`. It also
  clicks a `worker.brokerDemo` flow that routes through the Rust runtime and a
  WASM worker into the Storage Broker and Network Broker, proving the backend
  worker can persist a file and request host-mediated HTTP without exposing
  parent-only grants to the iframe. The same real-runtime surface now includes
  a schedule planner flow whose `worker.schedulePlan` method refreshes
  parent-only storage grants in the Host page, executes a WASM worker through
  the Rust runtime, writes file/KV data, creates and queries a plugin SQLite
  schedule table, and renders the stored schedule row inside the sandboxed
  iframe without leaking those grants. The real runtime browser smoke also clicks
  the generated plugin's Network matrix flow, which routes HTTP, WebSocket, TCP,
  and UDP requests through the same WASM worker -> Rust runtime -> Host Network
  Broker boundary.
- Host-mediated plugin intents are exposed end to end through the Go Host
  library, HTTP adapter, OpenAPI route contract, and `PluginPlatformClient`.
  Host products can list enabled runnable intents and invoke a chosen intent
  without iframe gateway tokens while still preserving local policy evaluation,
  permission grants, audit events, and dangerous-method fail-closed behavior.

ReDevPlugin intentionally does not import Redeven internals and does not
provide a local sibling integration path for host products.

## Release Integrity

Tagged GitHub releases build a platform-specific release bundle for each
supported runtime target only after release audit and stress gates pass. The
published evidence includes `redevplugin-release-stress.json`, `SHA256SUMS`, and
the runtime `.tar.gz` bundles. `SHA256SUMS` covers the runtime bundles and the
stress summary, and every `.tar.gz`, the stress summary, and `SHA256SUMS` are
signed with Sigstore keyless `cosign sign-blob`. Each signed artifact is
uploaded with a detached `.sig` file and a `.bundle` transparency-log bundle.
Host products should verify the checksum, the stress evidence, and the cosign
bundle before consuming a ReDevPlugin runtime artifact. Use
`scripts/verify_redevplugin_release_artifacts.sh <artifact-dir>` after
downloading a release artifact set; the GitHub Release workflow runs the same
verifier before publishing.

## Local Checks

```bash
go test ./...
npm install
npm run check
npx playwright install chromium
npm run demo:browser
npm run demo:browser:real
npm run test:demo:browser
./scripts/check_redevplugin_runtime_contract.sh
./scripts/check_redevplugin_platform.sh
REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh
./scripts/check_redevplugin_stress.sh --fast --summary dist/redevplugin-stress-fast.json
```

Rust checks require a local Rust toolchain:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

When Rust is unavailable, `check_redevplugin_runtime_contract.sh` still validates
the Go/OpenAPI route contracts and reports that the Rust portion was skipped.

`check_redevplugin_stress.sh` always emits a JSON summary. The `stress_evidence`
field records structured counters from `pkg/stress`, including stream
backpressure denials, connectivity grant/classifier denials, and storage quota
pressure. CI uploads that summary as release evidence for host-neutral
broker/backpressure behavior.
