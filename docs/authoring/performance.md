# Bounded responsive plugin work

Use ordinary browser bundles for local rendering and interaction. Keep state
updates local to the changed controls and use browser Workers for CPU work that
would block input. Package scripts, CSS, fonts and Worker assets; normal Surface
CSP, dedicated origins and network confinement still apply.

Pure Web applications access declared private resources directly with the
Surface SDK. Do not add a forwarding Worker for storage alone. The data template
saves one user action, retains edits made during a save, checks the expected
ETag and never retries an unknown mutation. It does not write on every keystroke.

Use KV batch and SQLite transaction APIs for one logical action. A batch has one
atomic commit, unlike a sequence of independent commits. Bound transactions to
64 statements, preserve conditional-write checks, and report conflicts without
discarding the draft. Memos initializes its six schema statements atomically.
Do not combine operations that require independent confirmations or durability.

Fetch the first bounded page and continue only when requested. Memos uses a
filter-bound cursor and a ten-item page. Private files use writeFrom/readable
and binary streams; the files template verifies by reading bounded chunks,
shows progress and supports cancellation while preserving completed files.
Avoid complete-file JSON or base64 buffers. Larger payloads belong in resource
streams, not the 256 KiB Worker invocation request or 512 KiB response.

Workers execute with the released engine's finite fuel ceiling, a signed memory
limit and a wall deadline. Rust crates must compile to the supported Wasm target
and use the platform ABI for I/O. Runtime and author toolchains are pinned to
Rust 1.98.0. Computation-budget, memory-limit and deadline errors are distinct;
keep input available and let the user reduce the operation or choose a longer
Host-approved job. Never assume a resource error makes a write safe to retry.

Use the existing process.local.v1 capability for explicitly authorized tools
already installed in the environment. Check dependencies and permissions before
starting. Native binaries, dynamic libraries and install hooks inside a plugin
package remain outside the backend contract.

Qualification uses the canonical workload Worker, public Host-owned control,
session and confirmation stores, real IPC/runtime processes and checked results.
The fixture still uses fake policy/business adapters and in-memory diagnostics;
it is not a full product deployment. Separate cold preparation, warm invocation,
client admission wait, streams and browser interaction measurements. Run the
same artifacts in alternating rounds and retain raw data and exact hashes.

The canonical acceptance Worker checks native reference results for no-op,
integer mixing, sorting, a 2,000-object JSON fixture, 1/10 MiB JSON and depth-16
JSON at a declared 256 MiB memory tier. Each case executes 100 times, followed
by another ordinary call. The release performance gate also checks that a
64-write KV batch crosses the Host resource API once, preserves every value
and rolls back a conflict. File acceptance transfers 1/32 MiB through 64 KiB
buffers and checks hashes and released reservations.

Cold compilation is separate from warm execution: Wasmtime trades a larger
compiler and a more expensive cold compile for faster repeated CPU work. Keep
the existing bounded install/startup prewarm and single-flight module cache.
The module cache byte metric counts Wasm source, not total process RSS or
compiled code. Do not interpret that metric as a process memory ceiling.
Persistent native-code caches, pooled Stores and larger database connection
pools are not enabled by this release; they require independent evidence and
security/lifecycle qualification.
