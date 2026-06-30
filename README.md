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
  WASM ABI schema, and target classifier fixture
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, storage, runtime supervision, grants, cleanup,
  capability adapters, HTTP routes, session context, and web security.
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
  target-classifier contracts.
- Mounted hosts can also expose the same compatibility manifest through
  `GET /_redeven_proxy/api/plugins/platform/compatibility`, allowing a product
  such as Redeven to verify the loaded platform artifact set without shelling out
  to the CLI.
- `redevplugin verify-compatibility <compatibility.json> <artifact-root>` checks
  a released compatibility manifest against the current version matrix and the
  referenced contract artifact hashes. Host products can use this command before
  upgrading a published ReDevPlugin dependency set.

This skeleton intentionally does not import Redeven internals and does not
provide a local sibling integration path for host products.

## Local Checks

```bash
go test ./...
npm install
npm run check
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
