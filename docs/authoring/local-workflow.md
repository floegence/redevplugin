# Local author workflow

Create a project with `redevplugin init <plugin-id> <display-name> <directory>`.
The default is a pure Web Surface. Choose `--template data` for a multi-window
editor, `files` for streaming imports, `monitor` for a controlled WebSocket
dashboard, or `worker` for a WASM job. The older scaffold command retains its
Worker starter. Only Workers need the pinned Rust 1.98.0 toolchain.
Templates use exact published SDK dependencies; install them before building.

## First working preview

Install the CLI for the platform release used by your host:

```bash
go install github.com/floegence/redevplugin/v3/cmd/redevplugin@v3.16.0
redevplugin init dev.example.notes "Notes" notes --template data
cd notes
npm install
redevplugin doctor .
redevplugin check .
redevplugin dev . --state ../notes-development --manual
```

Open the local URL printed by the command. Edit the application, save the source,
and wait for **Apply update**. Your open frame and drafts stay available until you
approve the update. The new frame loads the saved application data. Automatic
updates remain available by omitting `--manual`; they open a fresh frame after
each successful build. There is no transparent preservation of arbitrary DOM
state. Reload and update are deliberate frame-lifetime boundaries.

The persistent directory is explicitly chosen, exclusively locked, and bound to
one canonical project path. It must be outside the source directory. Restart
preserves data and owner-scoped grants, rotates session/channel authority, and
closes the exact previous session through the Host maintenance APIs. Unknown,
foreign, corrupt, and future state are rejected without replacing their bytes.
A complete interrupted marker publication is recovered atomically. Temporary
previews remain the default and remove their own state on exit.

**Reset development data** asks for confirmation, uninstalls the preview through
the ordinary lifecycle API with data deletion, and builds a fresh instance. It
does not recursively remove an arbitrary user directory. A failed or unknown
lifecycle result remains visible and is never retried automatically.

## One build contract

The manifest is the single author contract. Run
`redevplugin generate manifest.json generated` after changing public actions.
It generates canonical metadata, typed TypeScript clients/Surface registration,
Rust DTOs/dispatch, and JSON-pointer source mappings. Use --check to detect drift
without writing. Host validation remains authoritative; complex Rust schemas
use lossless serde_json::Value and unsupported TS references use PluginJSONValue.

`redevplugin doctor .` checks project/manifest validity, installed dependencies, Node 26,
Worker Rust 1.98.0 and wasm32 target readiness, and existing bindings without
running author commands. Generation is optional for existing projects; an
existing generated directory must match. New templates declare a tool-owned bindings directory. Dev regenerates it;
check and test reject drift rather than modifying it. `redevplugin check .` also runs the selected
build/tests, compares source and packaged manifests, and validates the package.
Both commands emit structured diagnostics with codes and source paths. Installed
exact dependency versions must match the declaration. Custom non-npm commands
remain executable checks; doctor cannot certify their arbitrary dependency graph.

The shared pipeline runs optional preparation, snapshots the source, validates the
manifest and bindings, runs optional type checks, builds, runs declared tests for
check/test, validates the package, and verifies source consistency. Worker
preparation creates its initial Cargo.lock before the source snapshot. Build
output is never published after a failed stage or source change. Stage reports
separate passed, failed, and not-run checks; business tests are not browser or
runtime evidence. New Web templates test a real application snapshot function,
while Worker templates execute their Rust business tests.

`redevplugin.project.json` is a closed local-source configuration. Its canonical
schema is `spec/plugin/author-project-v1.schema.json`. The public Go
`pkg/authorproject` package validates it, scans bounded source inputs, executes
argv directly, and builds immutable packages through the platform package
validator. Duplicate fields, traversal, symlinks, output/watch overlap, empty
commands, and excessive input budgets fail explicitly. Changes to the project
configuration require restarting the command. Downloaded packages never invoke
this workflow or execute these commands.

Run `redevplugin dev .` for Web/data/files applications. Worker applications
require `--runtime <executable> --runtime-sha256 <expected-digest>`.
The executable identity must come from independently verified build evidence for
the current platform and target. The supervisor verifies that identity before
launch; the command does not establish trust by hashing arbitrary executables.
The developer Host uses a temporary or explicitly selected development root, a
random loopback port, fresh session scope and CSRF token, exact Host/Origin checks,
and an HttpOnly session cookie. Only the embedded preview assets and platform HTTP
adapter are served. Source files are not exposed by a static file server.

The preview uses the released surface slot, sandbox bootstrap, MessagePort
bridge, lifecycle, and permission APIs. Missing permissions remain explicit;
Allow/Revoke controls mutate the real Host grants. Build failure retains the
previous successful preview. Successful builds create immutable package bytes,
use normal local import/update with the current management revision, and open a
fresh surface authority. Builds are single-flight. Filesystem events debounce for
250 ms, with a ten-second
reconciliation scan for missed events. Content hashes still gate admission, and
changes during a build produce one subsequent build. Ctrl-C cancels commands,
closes the server and Host runtime, and removes only the temporary state owned
by the invocation.

`redevplugin test .` runs the configured build and business tests, then validates
the resulting package. Its JSON report identifies that mode explicitly. Add
`--runtime`, `--runtime-sha256`, `--surface`, `--method`, and optional `--params`
to install into an isolated real Host, prepare a surface, mint the normal bridge
authority, and invoke a real WASM method. Missing runtime or grants fail; there is
no automatic fixture fallback or automatic permission grant.

## Prepare a verified Worker runtime

```bash
redevplugin runtime prepare ../notes-runtime
```

This opt-in command requires Node 26, authenticated GitHub CLI, Rustup, and tar.
It verifies the exact release workflow, tag, source commit and signed provenance
of the platform manifest, verifies both published crate checksums and Cargo VCS
identity, extracts only validated source archives, and builds with Rust 1.98.0 and
the released lockfile. It prints the executable path and expected SHA-256 for
`--runtime` and `--runtime-sha256`. Keep the JSON evidence with the build; an
arbitrary executable's self-computed hash does not establish trust.

The cache key binds platform manifest, toolchain and target. Compiler or integrity
failures do not fall back to a fixture. Preparation publishes a new complete output
directory only after success. Repeating preparation into an existing output is
rejected; a new output can reuse the exact compiler cache. These are local
development artifacts, not platform-distributed OS executables or host release
signatures. Production hosts retain ownership of binary signing, SBOM and bundling.

## Preview resources and operations

The resources panel shows verified storage declarations and connection inventory.
For a configurable connector, enter a destination, choose **Review connection**,
and approve the Host's exact review. Local services require the explicit loopback
checkbox; arbitrary private networks remain denied by the development policy.
Plugin `network.client` permission must also be explicitly granted. Revoke stops
existing authority; failed or uncertain operations are inspected rather than replayed.

The action panel generates simple scalar fields from intent payload schemas and
keeps a JSON editor for complex inputs. Surface writes use declared confirmation
policy and exact live receiver targeting. Worker write actions that require a
separate confirmation path remain in the plugin UI. Task inspection reads existing
executions and events; cancellation is explicit and never resubmits an operation.

## Test evidence

The npm `@floegence/redevplugin-ui/testing` entrypoint provides
`createPluginTestHarness` and `createPluginTestContext`. The fixture uses the
production PluginBridgeClient, validators, request cancellation, and stable error
handling. Its BridgeClient constructor can be injected into a plugin UI test;
call responses remain under the test's control. This is a business/bridge
fixture, not evidence of Host authorization, real DOM rendering,
resource brokers, or WASM execution. Those boundaries require the real preview
and browser/runtime acceptance tests.

The maintained minimal embedding example in
examples/embedding/example_test.go opens a real control-plane Host with explicit
adapters and permits only inventory reads. Run it with the example package's Go
tests. It requires neither a Redeven checkout nor a second lifecycle store.
The developer command is the fuller reference for runtime admission, route
mounting, and surface slots; product shells supply their own session and policy
adapters at those same public boundaries.

Test reports use the closed redevplugin.author-test.v1 schema, including failures
before building or runtime admission. The package_hash retains the platform's
sha256: prefix. Reports distinguish business/package checks from real-runtime
execution; the command's exit status remains nonzero after a failed check.
Configuration edits require a restart and preserve the last valid preview.
Confirmation dialogs default to Cancel, restore keyboard focus, and close on
request invalidation. The CLI author workflow supports the platform's current
Darwin and Linux runtime targets.

## Public Go test host

Import github.com/floegence/redevplugin/v3/pkg/testhost to compose the real Host,
HTTP adapter, and Web surface loader. Open(ctx, Options{}) owns a temporary root
and grants no management, filesystem, or network access. List each permitted
host.ManagementAction explicitly. AllowLocalPackages permits the development
provenance path only; it never grants plugin permissions. Use ordinary import,
grant, revoke, and execution APIs through Harness.Host() and Harness.Context().
The CLI explicitly supplies a writable development session and permits private
storage-handle issuance, so declared plugin storage works in dev and test. This
does not expose host filesystem mounts or automatically grant plugin permissions.
The reusable harness keeps its denying defaults.

Supply explicit Capability, IO, Connectivity, Secrets, CoreAction, or Background
modules where a test needs product resources. An optional MethodPolicy can deny
methods in addition to the production permission checks. Runtime accepts only
the verified module constructor; no fake-manager injection or automatic runtime
fallback exists. Harness.Events() exposes the existing bounded observability
store. Pure bridge fixtures and real runtime evidence remain separate.

For persistence tests, pass StateRoot and reuse Harness.Session() on reopen.
The real file asset store persists packages alongside the control state. Explicit
roots survive Close; only the harness's own temporary root is removed. Invalid
control state is admitted before asset-store creation. Close denies new requests,
closes Host/runtime resources, and then removes owned temporary state. It is
idempotent. Open takes responsibility for closing an unconsumed RuntimeModule
on failure and never stops a module already consumed by another Host.

For HTTP tests, bind your own loopback listener, then provide its exact
http://localhost:<port> ParentOrigin. Harness.Handler(parent) reserves production
platform routes and serves child origins only through NewWebSurfaceHandler.
Mount Harness.SessionHandler() on an explicit test-page route to exchange the
per-instance BrowserToken for an HttpOnly host-only cookie. Harness.NewRequest
adds the cookie, Origin, and CSRF only for that exact parent origin; it rejects
external URLs and does not send requests or follow redirects. A browser test
page obtains CSRFToken() from its parent-owned authenticated bootstrap. Never
expose these credentials to plugin documents. No handler listens by itself.

The CLI dev/test commands reuse this harness. CLI retains source builds,
watching, listener ownership, preview UI, and verified runtime admission; the
shared package owns their test-session and HTTP assembly. The defaults remain
deny-by-default when the package is imported independently.

## Inspecting a running application

The preview shows the verified contract, tests declared read intents, and lists
existing executions and diagnostics on explicit refresh. Observation never
starts or retries a job. Permission controls remain explicit. The standard
preview does not configure external connections for the monitor template;
bind them through the existing host connectivity adapters.

Reloading a Surface preserves data. Stopping and restarting dev explicitly
resets its temporary data and grants. Build failures keep the last valid
preview. No production data or unowned directory is reset.

See [author resources](resources.md) for ceilings, streams, cancellation,
conflict handling, and the reference applications' guarantees.

The author-browser gate compiles all five original templates against packed npm
artifacts and an isolated candidate Cargo registry. It does not add source aliases
or replace the source build commands. It covers manual apply/cancel, unsaved draft
retention, failed-typecheck retention, a fresh Surface after apply, persistent
restart, explicit reset, and configurable live monitor connections. Timings are
machine observations, not a claim that a human usability study has been completed.
