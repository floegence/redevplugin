# Embedded author environments

`pkg/authoring` is the reusable author pipeline used by the CLI and embedding
products. Product drafts and conversations remain product-owned. A draft stores
one opaque platform workspace ID, never an archive path or self-reported digest.

## Ownership and source execution

Open `WorkspaceStore` at an explicit platform-owned directory. Derive `Owner`
from `sessionctx.Context` with `OwnerFromContext`, never from browser JSON.
`Create` binds an idempotency key to this stable user/environment. `Initialize`
uses the same published templates as `redevplugin init`. `Build` invokes the
existing `authorproject` pipeline and therefore requires the product's normal
command execution approval. Opening, listing, capturing, previewing, inspecting,
and deleting do not execute author commands. `Capture` validates existing output
and source-manifest equality; its package stage is not evidence that tests ran.

`BuildReport` retains the latest attempt, actual stages and bounded command output
separately from the last successful artifact. Restart marks an unfinished build
interrupted; a failed build never replaces the preview or reports stale success.

Each artifact contains immutable package bytes, package hash, source snapshot,
and actual stage results. Later source edits do not invalidate it. Readback
revalidates package integrity and identity. The source hash describes provenance;
it is not execution permission. A workspace retains at most 256 artifacts and
an owner at most 10,000 workspace creation receipts. Capacity exhaustion is an
explicit failure, never implicit eviction of the displayed version.

## Isolated preview

`OpenEnvironment` constructs an ordinary Host in the workspace's development
root and owns its package assets. `EnvironmentOptions.Configure` supplies the
same host policy, session, runtime, storage, diagnostics and network adapters as
any other platform integration, plus cleanup for caller-owned resources. The
callback must leave `StateRoot` and `Core.Assets` empty. It must create isolated
resource modules; do not transfer the production Host's modules into a preview.

Mount `Environment.Handler` below a product-selected route, stripping only that
product prefix. The handler applies the normal platform origin, CSRF, route and
owner checks. Use the released parent Surface SDK with this route as its base.
`SurfaceRouter` routes only origins allocated by live preview environments and
falls through to the existing production Web handler. Products supply trusted
DNS/TLS routing and the usual origin allocator; there is no localhost proxy or
alternate renderer. Preview requests retain the authenticated user/environment.

`Apply` selects retained bytes and performs normal Host import/update without
implicit grants. Persisted selection intent and registry commit evidence restore
the exact applied artifact after restart, including when another capture has
identical package bytes but different source. Tokens and frame authority are
never persisted as draft metadata. Close each authenticated session through
`Environment.CloseSession`, using normal platform session teardown. Close the
environment before removing its workspace; product source tools must also stop.

## Review, installation, and deletion

`InspectArtifact` derives the current authenticated owner and passes the retained
bytes into the production Host's external-package inspection. Inspection expiry
requires a new review, not a new build. `StartInspectedInstall` accepts that exact
review and a stable request ID. `GetInspectedInstall` queries the original result
across session renewal and process restart. An absent operation returns the public
`ErrInspectedInstallNotFound` and HTTP `execution_not_found`. Both are available in the HTTP
adapter and generated TypeScript client. A lost response must be followed by
querying the same request, never a fresh installation request.

The operation uses the existing Execution authority. Control schema 6 migrates
schemas 1–5 transactionally and adds a unique user/environment/inspection claim.
Terminal receipts remain durable to prevent delayed replay; the owner may not
replace a request's inspected identity. A running operation reports unknown
outcome until completion. Restart recovery requires the exact operation ID in
committed execution approval evidence, not just equal package bytes. Missing
proof remains unknown and never causes automatic reinstallation. Packages require no signature or publisher trust. Missing grants still require
explicit authorization after installation.

`Remove` deletes only generated workspace resources and retains a creation
receipt, preventing a delayed create retry from resurrecting a deleted draft.
Interrupted removal resumes through the same call. Product-owned conversation
cleanup and its durable operation surround this platform operation. Installed
plugins are independent and are never removed with an author workspace.

The author store is a new, separately selected `redevplugin_author` schema 1.
Unknown, future and drifted schemas are rejected read-only. Initial publication
uses a durable staged database; recognized completed staging recovers on open.
There is no import of arbitrary directories or another product's state.
