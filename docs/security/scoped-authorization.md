# Scoped Worker And Surface Authorization

Plugins may require `authorization.scoped.v1` in manifest v9 to declare a
Worker method's `permissions` as a subset of package permissions. An absent
field retains the published package-wide ceiling. An explicit empty array
grants no filesystem, network, or process permissions. Unknown, duplicate,
null, or out-of-package declarations are rejected. Capability methods continue
to derive requirements only from the Host-verified capability contract.

The Host uses the same ceiling for permission discovery, installation review,
method authorization, execution evidence, and the runtime I/O registration. A
package grant does not widen a method ceiling. Existing broker operation scopes,
resource leases, policy caps, generation binding, and revocation still apply.
No new Rust wire or WASM ABI is introduced: filesystem/network calls continue
through the Host-owned I/O broker, which enforces the exact invocation ceiling.

A surface may declare `required_methods` with the same required feature. This
lists startup requirements, not callable methods. An explicit empty array allows
the UI to open without unrelated method grants; every method call still checks
its own authority. An absent field retains aggregate authorization. Missing
permissions never change the user's enabled intent.
An opt-in surface starts an on-demand background entry only when its
required methods include that entry's selected method. Independent pages do not
trigger unrelated background work or inherit its authorization failures.

Inventory `action_state.surfaces` provides the authoritative availability of
each surface for packages opting into surface requirements. Aggregate `can_open`
means at least one surface can open. The SDK's `getPluginSurfaceActionState`
selects that projection and fails closed for a missing projected surface. Hosts
must use the selected surface state rather than recomputing permission rules.
Permission requirements additionally expose the effective method mapping, bound
to the plugin instance, active fingerprint, version, and management revision.

Original canonical manifest bytes remain the signature authority. Optional
fields are not inserted into existing manifests, and existing package hashes
and capability pins remain unchanged. Revoking a grant invalidates existing
surface gateways; a freshly opened local surface cannot restore the revoked
method authority.

## Background Method Dispatch

`background.method.v1` allows a background entry to name an exact Worker
`method` and fixed `params`. The method must belong to its environment-scoped
Worker, accept those parameters, and require no interactive confirmation.
Existing entries without a method retain their original first-method selection,
but no background entry may bypass method policy, confirmation, request/response
validation, or execution semantics. The runner uses the existing method dispatch
and event lifecycle without overriding execution mode or cancellation policy.
Explicit entries authorize only the selected method; existing entries retain
their aggregate startup requirement. This feature does not add timers or services.
