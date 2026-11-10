# Local author workflow

Create a project with `redevplugin init <slug> <display-name> <directory>`.
The default is a pure Web Surface with no declared host actions. Choose
`--template data` for a multi-window editor, `files` for streaming imports,
`monitor` for a controlled WebSocket dashboard, or `worker` for a WASM job.
The older scaffold command retains its Worker starter. Only Workers need the
pinned Rust 1.98.0 toolchain.
Templates use exact published SDK dependencies; install them before building.
They begin with a flat content surface, 13px body text, 16px headings and compact
desktop controls. Touch input retains 44px targets. Adapt spacing and hierarchy to
the application's purpose rather than wrapping the entire view in another card.
All templates apply the current host color scheme through the surface context.

## First working preview

Install the CLI for the platform release used by your host, then start the
default Web preview:

```bash
go install github.com/floegence/redevplugin/v3/cmd/redevplugin@v3.24.0
redevplugin init notes "Notes" notes
cd notes
npm install
redevplugin dev . --state ../notes-development --manual
```

`dev` checks the tools and dependencies used for its build and reports actionable
readiness diagnostics before opening its development environment. Project-relative
commands such as `./scripts/build` resolve from the project directory, including
when the CLI is launched from another directory. It then runs
the declared checks and builds the first candidate. Use `redevplugin doctor .`
when diagnosing a tool or dependency issue,
and `redevplugin check .` before sharing or publishing a package.

Open the local URL printed by the command. Edit the application, save the source,
and wait for **Apply update**. Your open frame and drafts stay available until you
approve the update. The new frame loads the saved application data. Automatic
updates remain available by omitting `--manual`; they open a fresh frame after
each successful build. There is no transparent preservation of arbitrary DOM
state. Reload and update are deliberate frame-lifetime boundaries.

The persistent directory is explicitly chosen, exclusively locked, and bound to
one canonical project path. The lock belongs only to the owning process; executed
children do not retain it after that owner exits. It must be outside the source
directory. Restart
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

`redevplugin doctor .` checks project/manifest validity, installed dependencies,
generated template toolchain requirements, and existing bindings without
running author commands. Generation is optional for existing projects; an
existing generated directory must match. New templates declare a tool-owned bindings directory. Dev regenerates it;
check and test reject drift rather than modifying it. `redevplugin check .` also runs the selected
build/tests, compiles author identity and compares the resulting canonical package manifest, and validates the package.
Both commands emit structured diagnostics with codes and source paths. For npm
projects without a preparation command, installed exact dependency versions must
match the declaration. A preparation command can install dependencies before the
build, so dependency availability is checked by the build itself. Custom commands
and toolchain declarations remain executable checks; doctor cannot certify their
arbitrary dependency graph.

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

The action panel generates simple scalar fields from intent payload schemas
(or the method request schema when absent) and keeps a JSON editor for complex
inputs. Refresh preserves the selected action, fields, and JSON draft, including
unfinished JSON. A pending action remains single-flight across refresh. An
unknown result stays blocked until **Review uncertain result** is explicitly
acknowledged after inspecting the application; this never replays the action. Surface writes use declared confirmation
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

`examples/embedding/lifecycle_test.go` is an executable reference for an
explicit persistent root, narrowly allowed management actions, authenticated
catalog HTTP, package installation, Surface preparation and disposal, and
inventory reconciliation after restart. Run it with
`GOWORK=off go test ./examples/embedding -run '^Example_referenceLifecycle$'`.
`examples/embedding/resources_test.go` demonstrates explicit storage admission,
independent Surface authority, a targeted action, and session teardown against
the same real Host. Its manually simulated entry and handshake are test-only;
browser hosts use the published Surface SDK. Run it with
`GOWORK=off go test ./examples/embedding -run '^TestReferenceResourcesAndSession$'`.
The test harness supplies fake product adapters; a production host replaces
those session, authorization, origin, and observability integrations. For a live
browser, use the slot-based parent in `examples/showcase/app.ts` with the
`examples-server` command. Worker execution additionally requires the verified
runtime preparation described above.

`examples/embedding/browser` is a runnable loopback reference using the Go Host
and HTTP adapter with the npm Surface SDK. Its browser acceptance covers two
independent origins, authenticated inventory, private resource writes, exact
method targeting, sibling closure, and persistence after host restart without a
Worker runtime. The reference uses explicit test policies, not production auth.
The candidate browser gate consumes packed npm artifacts. After the checked-out
release has completed public verification, run
`node scripts/embedding_browser_smoke.mjs --published "$(cat VERSION)"` from
the repository root to install the CLI and reference host from the Go registry
and both SDK packages from npm into an isolated temporary consumer; no sibling
checkout wiring is used.

## Inspecting a running application

The preview shows the verified contract and lets you explicitly invoke declared
read intents and Surface actions. It lists existing executions and diagnostics
on explicit refresh; observation never starts or retries a job. Permission
controls remain explicit. Resources and connections presents declared connectors
and lets you review and approve configurable destinations, including the monitor
template's WebSocket connection. These controls use the normal Host connection
review and approval lifecycle; they do not grant undeclared network access.

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

Local preview selection binds immutable artifact IDs and exact package hashes,
independently of release SemVer. An author can select an earlier artifact, a
same-version edit, or an unvisited build. Exact retained packages use the existing
version-switch lifecycle to restore their verified data generation; other candidates
still require the normal compatible data shape or declared migration. Selection
never rewrites project source or a package manifest. Each successful apply advances
the preview generation, including identical bytes. Restart recovers the selected
artifact rather than guessing from the newest build or the version string.

This behavior is confined to `local_package` installations. A host authoring UI
may follow successful builds or pin a historical artifact, while respecting live
Surface closure and pending review. It does not enable production automatic
updates. External inspection/installation retains immutable release versions,
source confirmation, explicit downgrade and data-retention rules.

## Embedded visual review

A trusted parent may pass `onContextMenu` to `openSurfaceInSlot`. This opts the
exact live surface into host context menus. The SDK returns bounded target text,
tag, role, a structural selector hint, normalized viewport geometry, and the
current frame generation and surface handle. Its local `isCurrent()` check becomes
false after navigation or retirement; it is a freshness hint, not authorization. It never exports HTML or form values.
Without the callback, native application menus are unchanged.

The host owns comment UI, the artifact/version binding, user submission and
agent orchestration. A new preview generation invalidates prior targeting; retain
unsent text and require reselection instead of silently targeting the replacement.
Treat all visual metadata as untrusted quotation. A selector is a source-finding
hint, not authorization or an instruction to evaluate in a document. Comments do
not bypass the normal permission, confirmation, build or installation lifecycle.

## Author and publication identity

`manifest.json` is editable `redevplugin.source.v1` input with a short
`plugin.slug`. Authors never configure numeric repository IDs or publisher IDs.
The generated `manifest.json` is an installable v9 document; generated bindings,
source maps and build output all use that exact compiled identity.

`npm run build` invokes the platform build pipeline. Project build commands only
build assets and copy `generated/manifest.json`; they must not invoke the platform
pipeline recursively. `npm run build:release` resolves the Git origin through
GitHub before generating bindings and building. Local builds and previews remain
offline. Use `redevplugin build . --release --repository https://github.com/owner/repo`
only when source has no Git origin. See [repository discovery](repository-index.md).

Managed initialization validates the complete slug, display name, template and generated
manifest before reserving the draft. Rejected input leaves the empty draft unchanged,
and a corrected request can initialize it immediately or after a Host restart.

## Discovery category

Set `presentation.category` in `manifest.json` to one primary category: `development`,
`infrastructure`, `utilities`, `data`, `collaboration`, `productivity`, or `other`.
New scaffolds explicitly start with `other`. Omission also means `other`; empty,
null, unknown, and non-string values are invalid. Categories are not localized
identifiers and confer no permissions or official status. Labels belong to the host.

The source compiler preserves this field in the package manifest. Verified package
inspection and installed presentation expose the same value; changing it requires
a new package release. Neither repository names nor keywords infer categories.
Omitted category fields remain omitted in canonical bytes and hashed presentation
evidence. Consumers use the released `resolvePluginCategory` helper (or Go
`PluginCategory.Effective`) to display `other`.
