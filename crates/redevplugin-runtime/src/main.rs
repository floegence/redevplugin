fn main() {
    println!(
        "redevplugin-runtime {} {} {}",
        env!("CARGO_PKG_VERSION"),
        redevplugin_ipc::RUST_IPC_VERSION,
        redevplugin_ipc::WASM_ABI_VERSION
    );
}

