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
- Contracts: OpenAPI, manifest schema, token/ticket schema, IPC schema, WASM ABI
  schema, and target classifier fixture
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, storage, runtime supervision, grants, cleanup,
  capability adapters, HTTP routes, session context, and web security.
- Mountable HTTP routes can call a host-provided `websecurity.Guard` for origin
  and CSRF policy while keeping the concrete session and token semantics in the
  host product.
- Contract tests that keep the Go HTTP route set, OpenAPI paths, and route
  fixture aligned.

This skeleton intentionally does not import Redeven internals and does not
provide a local sibling integration path for host products.

## Local Checks

```bash
go test ./...
npm install
npm run typecheck
./scripts/check_redevplugin_runtime_contract.sh
```

Rust checks require a local Rust toolchain:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

When Rust is unavailable, `check_redevplugin_runtime_contract.sh` still validates
the Go/OpenAPI route contracts and reports that the Rust portion was skipped.
