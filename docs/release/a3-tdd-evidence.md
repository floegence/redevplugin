# A3 Host Capability Contract TDD Evidence

This document records the test-driven evidence for the first complete A3 host
capability contract release in ReDevPlugin v0.3.2. A3 owns external host capability
artifact verification, exact contract pins, generated plugin-side clients,
typed invocation bindings, Host-owned operation and stream handles, execution
leases, cancellation ownership, and negative audit/diagnostic behavior.

The `v0.3.2` release is the complete cross-artifact coordinate intended for host
consumption. Its evidence covers the immutable npm package, signed GitHub
Release, four runtime bundles, exact generated stress summary, self-contained
TypeScript dependency verification, and registry readback.

A3 is host-neutral. Its published sample uses an `example.documents.v1`
contract and contains no Redeven, container-engine, product-shell, or local
sibling repository dependency.

## Recorded Red Signals And Passing Regressions

The feature remained uncommitted while each focused TDD slice was exercised.
The following red signals were observed before the matching implementation was
completed, and the same focused commands now pass.

| Area | Initial failing signal | Passing command and enforced behavior |
| --- | --- | --- |
| Verified client generation | Client generation accepts only a verified signed bundle and checks generated output freshness | `GOWORK=off go test ./cmd/redevplugin -run 'TestCLIHostCapabilityGenerateClientRequiresVerifiedBundleAndDetectsStaleOutput' -count=1` proves generation only reads a verified bundle and `--check` rejects stale output |
| Artifact filesystem safety | Hard-linked artifact bytes were accepted as regular files | `GOWORK=off go test ./cmd/redevplugin -run 'TestCLIHostCapabilityVerifyRejectsLinkedArtifacts' -count=1` proves symlink and hardlink rejection under an `os.Root`-confined read path |
| Atomic dev install | Capability verification failure left the pre-created state directory behind | `GOWORK=off go test ./cmd/redevplugin -run 'TestCLIDevInstallCapabilityFailureLeavesNoState' -count=1` proves validation precedes staging and failure removes the complete staging tree |
| Artifact trust | Wrong key, publisher identity, compatibility floor, and per-file mutations lacked one focused matrix | `GOWORK=off go test ./pkg/capabilitycontract -count=1` proves exact file sets, hashes, Ed25519 signature, publisher/key epochs, compatibility, schema, and generated client identity fail closed |
| Artifact machine contracts | The contract schema existed, but pin, manifest, compatibility, signature, and notices artifacts had only Go structs | `GOWORK=off go test ./pkg/protocol ./pkg/version -count=1` proves all six closed draft 2020-12 schemas validate the signed sample and are present in the generated registry, compatibility matrix, and release required-file set |
| Cross-language schema semantics | Go and plugin-side validation had separate examples for restricted schemas | `GOWORK=off go test ./pkg/capabilitycontract -run TestRestrictedSchemaConformanceFixture -count=1` and `npm --prefix packages/redevplugin-ui test` consume the same fixture and agree on objects, unions, arrays, bounds, constants, and all five published string formats |
| External ingestion | Release capability ingestion requires a signed bundle resolver with source-policy and exact-pin verification | `GOWORK=off go test ./pkg/host -run 'TestResolveAndVerifyExternalHostCapabilityContract' -count=1` proves source-policy key usage/hash binding, no redirects, resolver/key separation, and exact pin verification |
| Host-owned handles | The Host allocates operation and stream ids before dispatch and keeps adapters behind scoped sinks | `GOWORK=off go test ./pkg/host ./pkg/operation ./pkg/stream -count=1` proves pre-dispatch Host allocation, scoped sinks, duplicate terminal rejection, route-local cancellation, revoke fencing, and durable cancel ownership |
| Stable business errors | Business error codes were typed, but capability identity and details-schema identity were not one generated union | `GOWORK=off go test ./pkg/capabilitycontract ./pkg/protocol ./pkg/httpadapter -count=1` proves generated unions, bridge responses, and HTTP envelopes bind capability id, capability version, details-schema SHA-256, code, and schema-validated details |
| Immutable store boundaries | Nested registry records and returned stream event bytes could share caller-owned memory | `GOWORK=off go test ./pkg/registry ./pkg/operation ./pkg/stream -count=1` proves input, write, get, list, terminal-operation, and stream-event return values cannot mutate stored execution or registry state |
| Runtime stream ownership | A real WASM `http_stream` hostcall omitted `stream_id`, while the Rust runtime only read that field from plugin request JSON and the Host broker rejected the call | `cargo test -p redevplugin-runtime network_execute_request_` and `GOWORK=off go test ./pkg/host -run 'TestCallPluginMethodWorkerHTTPStreamMemoryHostcallThroughBuiltRustRuntime' -count=1` prove the runtime injects the Host invocation id, rejects plugin-selected or missing Host ids, and completes the real Rust IPC stream path |
| Stream ticket commit | A drained terminal stream still performed next-ticket capacity checks and failed with `ErrTokenCapacity`; byte-only drain detection also dropped a next ticket while zero-payload events remained | `GOWORK=off go test ./pkg/bridge ./pkg/host -run 'TestCommitSingleUseDoesNotReserveReplacementCapacity|TestReadTerminalStreamDoesNotRequireNextTicketCapacity|TestReadTerminalStreamKeepsTicketUntilZeroPayloadEventsAreDrained|TestReadStreamFailureKeepsCurrentTicketAndEvents|TestReadStreamSerializesConcurrentUseOfOneTicket|TestReadStreamLongPollRevalidatesPluginRevision' -count=1` proves terminal commit does not reserve a replacement, event-count pagination retains a next ticket, failed reads remain retryable, concurrent reads serialize, and post-wait authorization is current |
| Durable terminal reconciliation | Operation and stream terminal states could be written independently, leaving a partial pair after a store failure or process restart | `GOWORK=off go test ./pkg/host ./pkg/operation ./pkg/stream -run 'Terminal|Reconcile|SQLite' -count=1` proves either terminal side repairs the other on construction and before later execution, including after closing and reopening SQLite stores |
| Runtime lease self-defense | Rust verified the Ed25519 signature but did not bind the actual worker parameters or complete invocation target, and its replay cache was unbounded | `cargo test -p redevplugin-ipc validates_worker_runtime_lease_expiry_and_execution_binding` and `cargo test -p redevplugin-runtime 'worker_invocation_rejects_|runtime_lease_replay_cache_'` prove exact `params_sha256`, fixed-order invocation target binding, expiry-aware replay pruning, hard capacity, and audience mismatches fail before artifact open |
| npm release surface | The release verifier checked runtime imports but did not compile a standalone consumer against the packed declarations | `./scripts/build_redevplugin_release.sh --version 0.3.2` proves the immutable npm tarball exposes exactly `PluginBridgeClient`, `PluginBridgeError`, the three typed capability calls, and the business-error guard, then installs that tarball and compiles the published sample without source aliases |
| Release provenance timestamp | The first dynamic signed sample used the release manifest's millisecond timestamp while capability artifact canonicalization emitted second precision | `./scripts/build_redevplugin_release.sh --version 0.3.2` and `node scripts/test_published_release_verifier.mjs ./dist/redevplugin-release 0.3.2 "$(git rev-parse HEAD)"` prove the outer manifest and signed sample share one canonical `generated_at` and that provenance mismatch mutations fail closed |
| Release smoke identity | Ordinary CI reused a formal release identity even though no tag was being released | The CI bundle smoke builds `0.0.0-ci.<run-number>` while tagged release jobs alone own the tag-derived immutable identity; both keep signed sample compatibility and full bundle verification enabled |
| Release evidence contract | The `v0.3.0` workflow signed a stress summary whose counter set differed from the verifier fixture | `./scripts/check_redevplugin_stress.sh --release --summary dist/redevplugin-release-stress.json` starts from `npm ci` and validates the exact required category and step sets through `scripts/verify_redevplugin_release_stress.mjs`; omission and failed-status fixtures prove `published_release_verifier` cannot disappear from signed evidence, and `GOWORK=off go test ./pkg/host -run TestCallPluginMethodRegistersStream -count=1` proves the scoped Host stream sink emits `plugin.stream.closed` |
| Published verifier isolation | The `v0.3.1` final readback job verified signatures and checksums, then failed because standalone TypeScript compilation resolved `node_modules/typescript` from the checkout root even though that job intentionally did not run `npm ci` | Normal branch release-bundle CI and `node scripts/test_published_release_verifier.mjs ./dist/redevplugin-release 0.3.2 "$(git rev-parse HEAD)"` copy both verifier scripts into an isolated temporary root with no `node_modules`, poison the ambient registry, install the exact compiler recorded in each bundle's `notices/package-lock.json` inside the temporary consumer, compile the sample, and reject version ranges, malformed SemVer, non-official registry URLs, invalid or mismatched SRI, and missing toolchain entries |
| Confirmation TOCTOU | Confirmation did not have a focused test for a trusted target descriptor changing after approval | `GOWORK=off go test ./pkg/host -run 'TestConfirmationIntentRejectsChangedResolvedTargetAndCannotReplay' -count=1` proves the re-resolved descriptor hash must match and the consumed confirmation cannot be replayed |
| Confirmation rejection | Parent UI rejection only returned `PLUGIN_CONFIRMATION_REJECTED` to plugin code; the Host did not atomically consume the pending intent or record the negative decision | `GOWORK=off go test ./pkg/security ./pkg/host ./pkg/httpadapter -run 'TestConfirmationIntentStoreRejectsOnlyMatchingScope|TestRejectMethodConfirmationConsumesIntentWithoutDispatch|TestHandlerRPCConfirmationRejectionFlow' -count=1` plus `npm --prefix packages/redevplugin-ui test` prove wrong-scope rejection preserves the intent, valid rejection consumes it once, records `confirmation_rejected`, and reaches no business adapter |
| Quota and ticket cleanup | Concurrent quota and stream-ticket mint failure did not have handle-closure regressions | `GOWORK=off go test ./pkg/host -run 'TestCapabilityExecutionEnforcesConcurrentAndDurationQuota|TestCallPluginMethodClosesStreamWhenTicketMintFails' -count=1` proves adapter zero-call on concurrency denial, timeout fencing, and deterministic stream failure when ticket minting fails |
| Negative observability | Request and adapter-panic rejection were covered, but permission, policy, audience, confirmation, quota, response, and revoke paths were not one stable set | `GOWORK=off go test ./pkg/host -count=1` proves `plugin.method.rejected` audit and diagnostic events carry stable reason values and rejected calls do not enter business adapters |
| Review closure: SDK stream ownership | A direct typed `read()` did not cancel an operation after event-schema mismatch, while an explicit Host read rejection destroyed a still-valid opaque handle | `npm --prefix packages/redevplugin-ui test` proves schema mismatch cancels once with `stream_contract_mismatch`, explicit Host rejection preserves the renewable credential, and transport/contract uncertainty still invalidates it |
| Review closure: target and duration | Target input was validated against the final host-derived descriptor schema, and a sync adapter could ignore context cancellation then return success after `max_duration_ms` | `GOWORK=off go test ./pkg/host -run 'TestCapabilityTargetProjectorMayAddHostDerivedFields|TestCapabilityExecutionRejectsSuccessReturnedAfterDurationQuota' -count=1` proves request schema owns plugin input, target schema owns projector output, and late success is rejected with quota expiry |
| Review closure: execution records | Worker/core records serialized an invalid zero contract pin and nullable permission arrays | `GOWORK=off go test ./pkg/host ./pkg/operation ./pkg/stream ./pkg/protocol -count=1` proves explicit `route_kind`, capability-only contract pins, closed OpenAPI conditions, and non-null permission evidence |
| Review closure: durable convergence | Concurrent close/fail calls could commit conflicting terminal states, startup retained ownerless operations, and uninstall blocking did not notify a live adapter | `GOWORK=off go test ./pkg/host -run 'Terminal|StartupTerminates|UninstallDeleteDataDispatches' -count=1` proves first-intent latching, fail-closed contradictory pairs, restart termination, route-local cancellation dispatch, and detached acknowledgement timeout |
| Review closure: resolver policy | Global-unicast checks still admitted RFC 6890 special-use networks, and same-epoch source policy content could be replaced when assessment timestamps changed | `GOWORK=off go test ./pkg/host ./pkg/registry -run 'ArtifactFetch|SourcePolicySnapshotHash|SourceSecurityFloor' -count=1` proves explicit IPv4/IPv6 special-use denial, dynamic timestamp exclusion, and same-epoch content immutability in memory and SQLite stores |
| Review closure: negative evidence durability | A failed audit sink silently discarded a pre-dispatch rejection event | `GOWORK=off go test ./pkg/host -run TestCapabilityRejectionFailsClosedWhenAuditPersistenceFails -count=1` proves the original contract rejection and `ErrSecurityEventPersistence` are both returned while the adapter remains untouched |

## Published Contract And Sample

The v0.3.2 compatibility manifest includes the complete machine contract set
under the generated contract registry:

- `host-capability-contract-v1.schema.json`;
- `host-capability-pin-v1.schema.json`;
- `host-capability-manifest-v1.schema.json`;
- `host-capability-compatibility-v1.schema.json`;
- `host-capability-signature-v1.schema.json`;
- `host-capability-notices-v1.schema.json`.

The release bundle also contains the complete published-style sample at
`examples/host-capability/sample-documents-v1/`:

- exact `host-capability.pin.json`;
- contract schema, compatibility metadata, deterministic generated TypeScript
  client, notices, signed manifest, and Ed25519 signature envelope;
- the public verification key only; no private key is distributed.

`scripts/verify_redevplugin_release_bundle.mjs` recomputes every pinned SHA-256,
verifies the signed manifest with the sample public key, scans the sample for
host-product terminology, runs `redevplugin host-capability verify`, and runs
`redevplugin host-capability generate-client ... --check` with the binary from
the bundle.

## Invocation And Ownership Result

- The Host freezes plugin, surface, owner/session, capability contract,
  permission, confirmation, revision, quota, target descriptor, and audit
  correlation evidence into one `ExecutionBinding` immediately before dispatch.
  `route_kind` is always explicit; only capability routes retain a contract pin.
- Operation and subscription ids are allocated and registered before the
  adapter executes. Adapters receive scoped sinks and cannot choose ids or
  mutate global stores.
- A subscription always owns both an operation id and a stream id. Worker
  invocation, runtime lease, stream ticket, HTTP result, trusted-parent result,
  and plugin-side opaque stream handle all preserve that paired lifecycle.
- Host business errors use the ReDevPlugin stable envelope. Generated clients
  require the published capability identity and details-schema SHA-256 before
  narrowing a business error to its host-owned code and details type.
- Runtime-origin `http_stream` hostcalls inherit the subscription id from the
  Host invocation. Plugin request JSON cannot provide or override that id.
- A live execution lease revalidates policy, permission, plugin state, active
  fingerprint, management revision, revoke epoch, and duration before every
  sink mutation.
- Every process supervisor owns an ephemeral Ed25519 keypair. Rust requires the
  startup public key, verifies the signed canonical lease, and independently
  checks expiry, exact parameter bytes, the complete fixed-order invocation
  target, and the overlapping worker audience before replay consumption or
  artifact access.
- Stream long polling is non-destructive until the final authorized mutation.
  The ticket and event queue commit together; terminal reads do not mint a next
  ticket, and read failure preserves the current ticket and buffered events.
- Operation and stream terminal records reconcile in both directions after
  partial writes and after durable store reopen, then release the live lease.
- Cancellation hooks are captured from the route-local adapter, core action, or
  runtime supervisor when the live lease is created. Persisted inactive
  operations retain `cancel_requested` without registry redispatch.
- Trusted-parent confirmation rejection validates the live surface gateway,
  owner/session and bridge scope, fingerprint, revisions, and revoke epoch,
  then atomically consumes the pending intent before returning the stable
  plugin-side rejection error. Scope mismatch and replay fail closed.
- Adapter errors, panics, response-contract rejection, ticket mint failure,
  timeout, disable, and revoke deterministically close Host-owned handles.

## Release Gate

The repository gate for A3 is the same immutable release train used by the Go
module, npm package, Rust runtime, schemas, compatibility manifest, and runtime
bundles:

```text
GOWORK=off go list ./cmd/... ./examples/... ./pkg/...
GOWORK=off go test ./cmd/... ./examples/... ./pkg/...
GOWORK=off go test -race ./pkg/bridge ./pkg/connectivity ./pkg/host ./pkg/httpadapter ./pkg/operation ./pkg/registry ./pkg/runtimeclient ./pkg/storage ./pkg/stream ./pkg/stress
npm ci
npm run check
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
./scripts/check_redevplugin_runtime_contract.sh --ci
./scripts/check_redevplugin_platform.sh --ci
./scripts/check_redevplugin_stress.sh --release --summary dist/redevplugin-release-stress.json
./scripts/build_redevplugin_release.sh --version 0.3.2
```

The tagged workflow repeats the complete quality, audit, stress, native runtime
matrix, npm provenance, signed GitHub Release, Go module, and public readback
gates before v0.3.2 is consumable by a host product.
