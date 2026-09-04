# ReDevPlugin Worker SDK

`redevplugin-worker-sdk` is the Rust SDK for backend workers that run inside the
sandboxed ReDevPlugin WASM runtime. It owns the `plugin_api=1` WASM request decoding, canonical
success and error responses, buffer allocation, worker exports, and brokered
storage, filesystem, and network APIs over the single `redevplugin.io` import
module.

## Versioned Dependency

Pin the SDK to the same immutable ReDevPlugin release used by the host:

```toml
[dependencies]
redevplugin-worker-sdk = "=3.0.24"
serde_json = "1.0"
```

Resolve the crate from the same formal registry publication indexed by the
platform release manifest as the Host and runtime source crate. Do not substitute a Git
checkout or local path dependency.

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
the allocator, deallocator, and invocation functions required by the current
`plugin_api=1` WASM ABI.

## Brokered APIs

- `storage::files`, `storage::kv`, and `storage::sqlite` use Host-minted storage
  grants for stores declared by the plugin manifest.
- `http`, `websocket`, `tcp`, and `udp` expose the current Host-controlled
  network APIs without a second network dispatcher.
- Workers never receive bearer credentials, raw sockets, ambient filesystem
  access, or direct network access.

The SDK exposes these high-level APIs through `rdp_call_v1`, `rdp_read_v1`,
`rdp_write_v1`, `rdp_seek_v1`, `rdp_close_v1`, and `rdp_last_error_v1`. Worker
code does not import separate storage or network modules.

The SDK returns structured `WorkerError` values. Broker failures retain their
stable platform code and user-safe message instead of exposing transport or
credential details.
