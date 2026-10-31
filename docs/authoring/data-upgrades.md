# Plugin data upgrades

An application that keeps the same settings and storage shape needs no converter.
For a shape change, declare `data.upgrade.v1` in `api.required_features` and add
`data_upgrade` with `from` (exact `version` and `shape_sha256` pairs), `method`,
`max_bytes`, and `max_runtime_ms`. Run `redevplugin validate previous.redevplugin` and copy its
`data_shape_sha256` into the predecessor declaration. The Go API exposes the
same result through `plugindata.ShapeFromManifest` and `plugindata.HashShape`.
Target settings and storage already define the output shape.

An explicitly matched converter runs even when both shapes are equal, allowing
application content changes. An unmatched shape change fails before conversion.
The method must be a synchronous write method on an environment-scoped job
Worker. Its closed request schema accepts `from_version`, `to_version`, and
`scope` (`environment` or `user`). When the package declares permissions, give
the converter an explicit empty permission list with `authorization.scoped.v1`.
It cannot require confirmation, preflight, ordinary broker access, an intent, a
background entry or surface startup. A surface or Agent cannot call it.

## Author SDK

Use `redevplugin_worker_sdk::data_upgrade` in the declared Worker.
`read_settings(Dataset::Input)` reads original non-secret values;
`write_settings(values)` replaces the output scope's values. `files`, `kv` and
`sqlite` reuse ordinary storage request/response types. Reads select
`Dataset::Input` or `Dataset::Output`; writes always address output.

The platform invokes the method separately for each existing environment and
user scope. Calls cannot select another user, instance or generation. Worker
parameters identify the scope kind, not a user identifier. Ordinary resources,
network, credentials, processes, selected files and binary I/O are denied.

Output starts with matching store IDs/kinds/scopes copied from input. New stores
start empty; removed stores remain in the retained input generation. Compatible
settings carry forward; incompatible/new fields use target defaults. Original
values remain readable through input. Preserve values you need before replacing
output settings. `internal/dataupgradeworker` demonstrates settings, files, KV
and SQLite conversion against the real Host and WASM runtime.

## Commit, limits and recovery

The existing update API owns conversion. It fences new ordinary executions,
revokes old leases, drains data accesses, closes databases and snapshots input.
The converter sees only unpublished output. After validation, one control-store
transaction switches package identity and data binding and retains the previous
generation. Ordinary execution cannot pair a package with the wrong data shape.

The manifest limits the whole conversion to at most 300 seconds and each input
snapshot/output generation to at most 4 GiB. `max_bytes` includes database and
metadata bytes. Checks run before conversion, after output writes and before
publication; a limit failure remains fatal even if Worker code ignores it. This
is not an OS disk reservation. Temporary files, SQLite journals and an in-flight
write can need extra space. Per-store quotas also apply.

Cancellation and conversion failure leave the old package and data active.
Cancellation cannot undo a committed transaction. A lost commit acknowledgement
returns `mutation_outcome=unknown`: reconcile inventory/version before proposing
another update; never automatically replay. Errors after the atomic switch are
committed outcomes and never roll the package back over new data.

Restart reads atomic catalog state. Uncommitted staging and unreferenced
published generations use existing safe collection; referenced history cannot
be collected. Each historical package records its last data generation. Same-shape versions
can share one generation; an explicit converter creates a separate generation
even when shapes are equal. Downgrade restores that exact generation and retains
the one it replaces. Revisited packages use the most recent visit's data.
Import replaces the shared active dataset for every version using it, while
independently retained generations remain unchanged. Inconsistent history fails
closed.
No reverse converter is inferred.

Synchronous conversion creates no second durable progress job. Hosts use their
existing update progress and reconcile uncertain results. The Worker uses the
existing execution lease, cancellation and audit path. Control schema 4 migrates
schemas 1–3 transactionally without changing existing plugin data or grants.
