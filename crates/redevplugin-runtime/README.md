# redevplugin-runtime

`redevplugin-runtime` is the sandboxed ReDevPlugin backend execution process.
It executes validated WASM actors and jobs, speaks the released IPC protocol,
and enforces runtime limits, leases, revocation, streams, and hostcall routing.

Host products build this source crate for their supported targets, verify the
compiled runtime identity, and own product signing, packaging, and installation.

## Execution and resource limits

The released runtime uses Wasmtime 50.0.1 with fuel and epoch interruption.
Build the source crates with Rust 1.98.0. Validated modules and their Engine are
shared through the bounded, single-flight module cache. Each invocation receives
a fresh Store, instance, linear memory and hostcall state. No serialized native
module supplied by a plugin is accepted; there is no interpreter fallback.

The signed Host lease remains authoritative. A positive timeout bounds the
execution from its issued time; zero uses the lease expiry. Execution uses the
remaining duration, at one million engine fuel units per millisecond, capped at
ten billion. Fuel is never replenished and is not a portable CPU-time estimate.
A 10 ms epoch timer independently checks the deadline, cancellation and current
revocation authority. Host I/O retains its own cancellation and lease checks.
The signed memory cap, one memory/instance/table and 65,536 table elements remain
enforced. Compilation is bounded by the existing worker admission/module cache.

Failures distinguish WASM_WORKER_BUDGET_EXCEEDED, WASM_WORKER_MEMORY_LIMIT and
RUNTIME_INVOCATION_TIMEOUT from malformed modules and cancellation. The HTTP/SDK
projections are PLUGIN_WORKER_BUDGET_EXCEEDED, PLUGIN_WORKER_MEMORY_LIMIT and
PLUGIN_WORKER_TIMEOUT. Callers retain edits and offer smaller batches or an
explicitly authorized longer operation; they must not automatically replay a
mutation whose outcome is unknown. Exact constants and packaged fixtures are
bound by the canonical WASM ABI metadata and platform release manifest.
