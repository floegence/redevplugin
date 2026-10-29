# Local author workflow

Create a project with `redevplugin init <plugin-id> <display-name> <directory>`.
The generated source uses exact published npm and Cargo SDK versions. Install
its source dependencies and WASM target before building.

`redevplugin.project.json` is a closed local-source configuration. Its canonical
schema is `spec/plugin/author-project-v1.schema.json`. The public Go
`pkg/authorproject` package validates it, scans bounded source inputs, executes
argv directly, and builds immutable packages through the platform package
validator. Duplicate fields, traversal, symlinks, output/watch overlap, empty
commands, and excessive input budgets fail explicitly. Changes to the project
configuration require restarting the command. Downloaded packages never invoke
this workflow or execute these commands.

Run `redevplugin dev . --runtime <executable> --runtime-sha256 <expected-digest>`.
The executable identity must come from independently verified build evidence for
the current platform and target. The supervisor verifies that identity before
launch; the command does not establish trust by hashing arbitrary executables.
The developer Host uses a private temporary state root, random loopback port,
random owner/session scope and CSRF token, exact Host/Origin checks, and an
HttpOnly session cookie. Only the embedded preview assets and platform HTTP
adapter are served. Source files are not exposed by a static file server.

The preview uses the released surface slot, sandbox bootstrap, MessagePort
bridge, lifecycle, and permission APIs. Missing permissions remain explicit;
Allow/Revoke controls mutate the real Host grants. Build failure retains the
previous successful preview. Successful builds create immutable package bytes,
use normal local import/update with the current management revision, and open a
fresh surface authority. Builds are single-flight, source changes debounce, and
changes during a build produce one subsequent build. Ctrl-C cancels commands,
closes the server and Host runtime, and removes only the temporary state owned
by the invocation.

`redevplugin test .` runs the configured build and business tests, then validates
the resulting package. Its JSON report identifies that mode explicitly. Add
`--runtime`, `--runtime-sha256`, `--surface`, `--method`, and optional `--params`
to install into an isolated real Host, prepare a surface, mint the normal bridge
authority, and invoke a real WASM method. Missing runtime or grants fail; there is
no automatic fixture fallback or automatic permission grant.

The npm `@floegence/redevplugin-ui/testing` entrypoint provides
`createPluginTestHarness` and `createPluginTestContext`. The fixture uses the
production PluginBridgeClient, validators, request cancellation, and stable error
handling. Its BridgeClient constructor can be injected into a plugin UI test;
call responses and actions remain under the test's control. Render snapshots are
accepted only after the real client's render acknowledgement. This is a
business/bridge fixture, not evidence of Host authorization, real DOM rendering,
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
