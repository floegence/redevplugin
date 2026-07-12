# Rust Legal Text Overrides

The crates.io archives listed below omit legal-text files that are present in
their pinned upstream source commits. Release bundle generation uses these exact
upstream files only for the affected packages and records every redistributed
file hash in `notices/THIRD_PARTY_LICENSES.json`.

| Packages | Upstream source commit | Files |
| --- | --- | --- |
| `wasmi`, `wasmi_collections`, `wasmi_core`, `wasmi_ir` `2.0.0-beta.3` | `wasmi-labs/wasmi@e6189ed21faf57c5b94f5ec7408933d3d63e1576` | `wasmi/LICENSE-APACHE`, `wasmi/LICENSE-MIT` |
| `wasmparser` `0.228.0` | `bytecodealliance/wasm-tools@e66235859a6ec0502bf6f9dcc358953eda4cafcc` | `wasm-tools/LICENSE-APACHE`, `wasm-tools/LICENSE-Apache-2.0_WITH_LLVM-exception`, `wasm-tools/LICENSE-MIT` |

The files must not be edited locally. An upstream dependency upgrade must
refresh the source commit, legal texts, and generated release evidence together.
