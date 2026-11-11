# Host scheduled work and Agent capabilities

`pkg/schedule` owns a separate exclusively opened local schedule database. It
serves verified host-owned work and does not turn built-in tasks into installed
plugins. Existing plugin interval plans keep their original synchronous Worker
contract and control-store lineage. This additive package owns cadence, durable
intentions and admission receipts; hosts own business graphs, authorization,
Agent execution and report artifacts. The database is initialized atomically at
schema 2. The exact released schema 1 is verified and atomically upgraded without
rewriting plans or receipts. Unknown, drifted or future stores are rejected before mutation.

A trusted host resolves an `Owner`, writes a versioned `Plan` with compare-and-swap,
and runs `Store.Run` with a `Dispatcher`. `Submit` must reauthorize and use
`Claim.ID` as the downstream idempotency identity. It returns a prompt admission
receipt, never waits for an entire Agent task. `Inspect` reauthorizes observation
and reconciles that original identity. No transport error proves non-commitment.
Interrupted dispatches become unknown after restart and occupy capacity;
they are inspected but never resubmitted automatically. Accepted target work
survives scheduler restart and continues under its own authority.

Cadences include elapsed intervals, completion delays and local daily time with
an IANA zone. A missing wall time uses the first later valid minute that date; a
repeated time runs at its first occurrence only. Overlap policies skip, keep the
latest pending occurrence, maintain a bounded chronological queue, or allow
concurrent occurrences. `MaxConcurrent` bounds unresolved claims to 1–16
(zero preserves the original capacity of one). Unknown receipts consume a slot.
The `allow` policy drops an occurrence at capacity; `queue` retains bounded FIFO
work. Completion cadence requires capacity one, preserving a single chain. Missed
periods after restart skip or coalesce to the latest occurrence. Updating a plan
discards unclaimed old-version occurrences and preserves dispatched snapshots.
Disabling a plan prevents future dispatch; canceling actual work is a separate
host operation. A wall-clock change never rewrites retained claim identities.

`pkg/agentwork.Contract()` publishes the host-neutral `agent.work` capability.
The matching client is exported as `@floegence/redevplugin-ui/agent-work`. Plugins
bind this exact capability through ordinary manifest capability routes and use
the existing authenticated bridge, permission, confirmation and execution path.
No new iframe channel, HTTP bypass, model credential, or plugin-native executor
is introduced. The host adapter resolves `work_id` under the platform-verified
plugin installation and environment, and supplies a concrete Agent runtime.

Submit, input and cancel are short capability calls returning references and
state. They do not make the capability invocation last as long as Agent work.
Submit binds a stable request ID and payload; get observes the same request.
Context JSON is bounded, untrusted application material, never a system prompt
or permission. `result_json` is only the authorized business result, not a full
conversation. Revocation and uninstall must block subsequent work and reads;
hosts register the existing lifecycle hooks to cancel corresponding Agent work.

The Agent contract and generated client are produced from
`spec/plugin/agent-work-contract.json` by `go generate ./pkg/agentwork` and
verified by its public contract tests. The platform release manifest includes
that exact artifact. No runtime wire or WASM ABI change is required: invocation
uses the already released capability adapter mechanism.

## Retained capability work

A trusted adapter may retain the exact platform-issued `ExecutionBinding` and
call `Host.ValidateCapabilityContinuation` before continuing or exposing work.
The Host rechecks instance, fingerprint, policy/management/revoke revisions,
permissions and quota expiry. This is observation of the original authority,
not a new execution or an extension of its duration. Plugin arguments must
never provide this binding. Product-owned longer-lived delegation requires its
own explicit authorization and must not reinterpret a synchronous capability
invocation as an unlimited background grant.
