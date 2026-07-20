# redevplugin-ipc

`redevplugin-ipc` defines the closed JSON frame protocol shared by the Go Host
and the Rust ReDevPlugin runtime. It owns validated hello, worker, hostcall,
lease, stream, revocation, and runtime-limit types and builders.

The crate contains protocol mechanics only. Product sessions, policies,
business capabilities, and process placement remain host responsibilities.
