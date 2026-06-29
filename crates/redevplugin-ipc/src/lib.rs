pub const RUST_IPC_VERSION: &str = "rust-ipc-v1";
pub const WASM_ABI_VERSION: &str = "redeven-wasm-worker-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Hello,
    Heartbeat,
    LeaseGrant,
    InvokeWorker,
    OpenHandle,
    CloseHandle,
    RevokeEpoch,
    Diagnostic,
}

