# redevplugin-wasm-abi

`redevplugin-wasm-abi` validates ReDevPlugin WASM worker modules before
execution. It enforces the published import, export, memory, table, and opcode
contract without providing ambient filesystem, process, or network access.
