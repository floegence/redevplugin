# redevplugin-runtime

`redevplugin-runtime` is the sandboxed ReDevPlugin backend execution process.
It executes validated WASM actors and jobs, speaks the released IPC protocol,
and enforces runtime limits, leases, revocation, streams, and hostcall routing.

Host products build this source crate for their supported targets, verify the
compiled runtime identity, and own product signing, packaging, and installation.
