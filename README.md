# ReDevPlugin

ReDevPlugin is the reusable plugin platform intended to be consumed by host
products such as Redeven through published Go, TypeScript, Rust runtime, and
machine-contract artifacts.

This repository owns the host-neutral plugin platform core. Host products own
their product policy, UI shell integration, session adapters, and business
capabilities.

## Current Skeleton

- Go module: `github.com/floegence/redevplugin`
- TypeScript package: `@floegence/redevplugin-ui`
- Rust workspace: `redevplugin-runtime` and support crates
- Contracts: OpenAPI, manifest schema, package-signature schema, token/ticket
  schema, iframe bridge schema, compatibility manifest schema, IPC schema,
  WASM ABI schema, worker invocation payload schema, and target classifier
  fixture
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, storage, runtime supervision, grants, cleanup,
  capability adapters, HTTP routes, session context, and web security.
- Storage brokers include both an in-memory test broker and a filesystem-backed
  broker that creates per-plugin-instance namespace directories under a
  host-selected state root, enforces quota accounting, rejects symlink escape
  attempts, supports export/import archives, and makes uninstall data deletion
  or retention observable on disk.
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
  generated UI plus WASM backend worker skeleton, then sign it:
  `redevplugin keygen <key-id> <private.json> <public.json>` followed by
  `redevplugin sign <unsigned.redeven-plugin> <private.json> <signed.redeven-plugin>`.
  Development harnesses can then run
  `redevplugin install-verified <signed.redeven-plugin> <public.json>` to prove
  the Host trust-verifier path accepts the signed package.
- Mountable HTTP routes can call a host-provided `websecurity.Guard` for origin
  and CSRF policy while keeping the concrete session and token semantics in the
  host product.
- Contract tests that keep the Go HTTP route set, OpenAPI paths, and route
  fixture aligned.
- Bridge contract checks that keep sandbox iframe message names, exact-origin
  messaging, UI protocol version, and parent-only token boundaries aligned with
  the TypeScript SDK.
- `redevplugin version` emits a host-consumable compatibility manifest with the
  current platform version matrix plus SHA-256 hashes for the released OpenAPI,
  manifest, signature, token/ticket, bridge, IPC, WASM, network-grant, and
  worker invocation, target-classifier contracts.
- Mounted hosts can also expose the same compatibility manifest through
  `GET /_redeven_proxy/api/plugins/platform/compatibility`, allowing a product
  such as Redeven to verify the loaded platform artifact set without shelling out
  to the CLI.
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
  grant through the Host connectivity broker, and records the HTTP executor
  request/response before returning the worker result.
- The Rust runtime now performs the first executable worker slice: it requests
  the bound WASM artifact from the Host over IPC, validates the WASM binary
  header and required function export through `redevplugin-wasm-abi`, executes
  the exported no-argument worker entrypoint with the embedded Wasmi engine, and
  returns a successful scaffold worker result over `invoke_worker_result`. It
  also exposes the first brokered hostcall slices. The early
  `redeven.storage/files_write_demo` and `redeven.network/http_request_demo`
  imports prove storage and network broker routing. The newer
  `redeven.network/http_request(req_ptr, req_len, out_ptr, out_len) -> i32`
  import is the first linear-memory ABI slice: the worker writes a bounded JSON
  network request into WASM memory, the Rust runtime injects Host-owned
  identity, policy, and revoke context, executes the request through the
  `network_execute` IPC path, and writes the JSON response back into the
  worker-provided output buffer. Host integration tests build and exercise the
  real Rust runtime whenever a local Cargo toolchain is available, including
  FileBroker, fixed network demo, and linear-memory HTTP executor paths.
- `redevplugin inspect-storage <storage-root> [plugin-instance-id]` reports
  filesystem broker namespaces, quota, and usage without dumping plugin file
  contents. Host products can wrap this for diagnostics while keeping the
  storage root selection in their own adapter layer.
- `redevplugin dev-install <state-root> <package>` creates a persistent local
  development state root for Flower-generated plugins. The matching
  `dev-enable`, `dev-open <surface-id> [sandbox-origin]`, `dev-disable`,
  `dev-uninstall [--delete-data|--keep-data]`, and `dev-status` commands replay
  the saved package through the real Host lifecycle APIs while keeping the
  copied package, filesystem storage root, and sandbox browser-origin records
  under the same state root. This gives generated plugins a local, auditable
  install -> enable -> open -> disable -> uninstall flow without importing any
  host-product internals. Uninstall removes the copied package; `--delete-data`
  also removes plugin storage namespaces and marks browser-origin data cleanup
  complete, while `--keep-data` marks declared plugin data retained.
- The browser demo under `demo/browser/` runs a real host page plus sandboxed
  iframe plugin page using the built `@floegence/redevplugin-ui` bridge package.
  Start it with `npm run demo:browser`, open the printed host URL, then exercise
  handshake, lifecycle, ordinary RPC, storage-list RPC, and
  dangerous-confirmation flows. The host and plugin page are served from
  separate localhost origins to exercise exact-origin sandbox bridge behavior.
  For the Flower-generated plugin path, run `npm run demo:browser:generated`.
  That launcher scaffolds a plugin with a backend worker skeleton, packages it,
  installs it into a temporary dev state root, enables it, opens its activity
  surface, prints a browser URL, and cleans up by disabling and uninstalling the
  plugin with data deletion when the process exits.
  `npm run test:demo` covers the fake platform API and static sandbox contract;
  `npm run test:demo:browser` launches a real browser, clicks through the iframe
  demo flow, generates a fresh plugin with `redevplugin scaffold`, packages it,
  installs, enables, and opens it through the persistent dev lifecycle harness,
  serves that generated plugin from the sandbox origin, verifies its backend call
  UI end to end, then disables and uninstalls it with data deletion.

This skeleton intentionally does not import Redeven internals and does not
provide a local sibling integration path for host products.

## Local Checks

```bash
go test ./...
npm install
npm run check
npx playwright install chromium
npm run demo:browser
npm run test:demo:browser
./scripts/check_redevplugin_runtime_contract.sh
./scripts/check_redevplugin_platform.sh
```

Rust checks require a local Rust toolchain:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

When Rust is unavailable, `check_redevplugin_runtime_contract.sh` still validates
the Go/OpenAPI route contracts and reports that the Rust portion was skipped.
