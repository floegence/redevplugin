# ReDevPlugin Worker SDK

`redevplugin-worker-sdk` is the Rust SDK for backend workers that run inside the
sandboxed ReDevPlugin WASM runtime. It owns ABI v2 request decoding, canonical
success and error responses, buffer allocation, worker exports, and brokered
storage and network hostcalls.

## Versioned Dependency

Pin the SDK to the same immutable ReDevPlugin release used by the host:

```toml
[dependencies]
redevplugin-worker-sdk = "=0.6.14"
serde_json = "1.0"
```

Resolve the crate from the same formal registry publication and platform
package set as the Host, contracts, IPC, WASM ABI, classifier, and runtime
source crates. Do not substitute a Git checkout or local path dependency.

## Worker Entry Point

```rust
use redevplugin_worker_sdk::{WorkerRequest, WorkerResult, export_worker};
use serde_json::json;

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "example.greet" => Ok(json!({ "message": "Hello from WASM" })),
        _ => Err(redevplugin_worker_sdk::WorkerError::invalid_request(
            "unsupported method",
        )),
    }
}

export_worker!(handle);
```

Compile the worker for `wasm32-unknown-unknown`. The generated module exports
the allocator, deallocator, and invocation functions required by
`redevplugin-wasm-worker-v2`.

## Hostcalls

- `storage::files`, `storage::kv`, and `storage::sqlite` use Host-minted storage
  grants for stores declared by the plugin manifest.
- `network::execute` uses a declared connector and the Host-controlled network
  broker.
- Workers never receive bearer credentials, raw sockets, ambient filesystem
  access, or direct network access.

The SDK returns structured `WorkerError` values. Hostcall failures retain their
stable platform code and user-safe message instead of exposing transport or
credential details.
