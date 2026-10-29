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

## Selected File Resources

The optional FilesModule supplies a trusted FileSelectionAdapter. The adapter
returns an absolute path from product selection UI; only the Host opens it,
validates object identity, and creates authority. Hosts register the module and
mount the released HTTP adapter. They do not parse paths from plugin messages,
issue resource IDs, duplicate the approval state machine, or grant a whole root.

Packages requiring this API declare fs.selected.v1 plus fs.selected.read and/or
fs.selected.write. These permissions are capability ceilings, not boolean
grants. The permission inventory marks resource selection separately. The normal
grant API rejects them. A Worker method uses its exact declared ceiling; the Web
surface uses the package's selected-resource ceiling. Both share the Host's
resource table and per-operation authorization. A package declaring only selected
access cannot open home, workspace, environment, or private-storage roots.

Selection creates a five-minute, session-bound review. Approval checks the exact
owner, current plugin revisions, live originating surface, session read/write
caps, object identity, and 24-hour resource expiry before persisting authority.
A persistence attempt consumes the review, including unknown commit outcomes.
After a lost response or audit completion failure, query resource inventory;
do not replay approval. Cancellation produces no durable authorization. The
plugin receives only an opaque redevfs://selected-<id>/ URI, never host paths,
review credentials, gateway tokens, or object identity evidence.

Each user/plugin has at most 128 active resources and 256 retained rows. Older
inactive rows may be pruned; audit history is separate. Listing is authoritative
for current inventory, not an unlimited audit log. Revoke binds the exact
resource revision and is idempotent while that retained row exists. An absent
row has no authority. Adding or revoking one resource does not reload unrelated
surfaces. Disable, version and policy changes retain the global revoke chain.
Removing the Files module prevents use of retained grants; list/revoke remain
available for management.

A selected file grants no parent-directory authority. Rename/remove of that
file are unsupported. A nonrecursive directory permits its root and direct
children; recursive access remains within the opened root. Symlinks are never
followed, hard-linked regular files are rejected, and device/special files are
not opened as ordinary files. Every read/write/seek/control rechecks expiry,
owner, active fingerprint, revisions and object identity. Restart reopens only
an exact identity match; replacement requires a new selection. Open descriptors
are not a promise that an external process can never move the selected object.

Control schema 2 adds selected_file_resources via one transactional migration
from the exact schema 1. Existing registry, grants and settings remain intact.
Unknown, future or drifted schemas are rejected without mutation. The Host owns
migration and cleanup; product code selects only its state root.

Copy and recursive mutations are not filesystem transactions. Admission errors
must precede truncation. Failure after effects may have occurred reports an
unknown mutation outcome; callers inspect the result before retrying. Dispatched
raw Worker write failures are nonretryable and report unknown through last_error.
Rust File::write_all adds acknowledged_bytes for earlier completed chunks, while
Web PluginFileWriteError.bytesWritten carries the same lower-bound meaning.
Selected resource watches are unsupported.


## Controlled connections

Control schema 3 transactionally extends both released predecessors (schema 1
and 2) with owner-scoped network connection approvals. Upgrade preserves registry,
grants, settings and selected-file authority; interrupted transactions roll back
and unknown schema drift fails closed without changing the state root.

A configurable connector declares transport and resource scope. Review binds an
exact destination, HTTP method set, optional approved private CIDRs and secret
reference to the current plugin fingerprint and authenticated session. Approval
consumes that review once and uses a durable revision compare-and-swap. Inspect
ListConnections after a lost approval result; never replay a network mutation.
Replacing or revoking approval cancels its active streams; a stale revision
cannot cancel the current generation. Session close removes pending reviews and
cancels only that session's streams, without revoking another session's durable
owner-scoped configuration.

Web applications declare web.network separately from Worker broker_access. The
plugin SDK exposes openPluginConnection to obtain a connector-scoped baseURL on
the allocated child origin. Applications use ordinary fetch, Request, Response,
AbortSignal and streams. The child session cookie authenticates each request;
the URL is a locator, not a bearer credential. Remote data routes accept only
same-origin fetch metadata, never script, navigation, Worker or image requests.
The adapter does not forward host cookies, proxy headers, response cookies,
authentication challenges, redirects or security-policy response headers.
Redirects fail without replaying a dispatched write.

All Worker client opens name a declared connector. HTTP, WebSocket, TCP and UDP
share the platform target classifier, pinned address resolution, scoped grants,
limits, cancellation and revocation. A read-only session cannot open a mutating
HTTP method or an arbitrary socket. NetworkPolicy adds product constraints;
it never substitutes for platform declarations or grants. Private targets need
explicit CIDRs and PrivateNetworkPolicy approval. Public package downloads do
not receive those approvals and remain public-HTTPS-only.

NetworkSecretResolver resolves approved secret references to credential headers
inside the trusted Host. Values are never returned to the plugin. Auth accepts
only a secret_ref for HTTP and WebSocket; protocol-specific TCP authentication
is application protocol behavior, not HTTP header injection. NetworkTLSResolver
resolves authored TLS declarations. The platform rejects missing adapters,
plaintext/UDP TLS, insecure verification and mismatched server names, and enforces
TLS 1.2 or newer. TCP supports TLS and mutual TLS; ordinary HTTPS/WSS use normal
certificate verification without requiring an adapter. Custom credential
transports share the executor's bounded pool admission and shutdown drain.
