# ReDevPlugin Repository Guide

This file is the repository-level operating guide for `redevplugin/`.

Goals:

- keep ReDevPlugin usable as an independent, reusable plugin platform;
- keep host-product boundaries explicit and auditable;
- never develop directly on `main`;
- preserve intentional commit history;
- keep the Git workflow self-contained here instead of depending on another
  repository's guide for day-to-day development;
- publish versioned Go modules, npm packages, Rust source crates, and
  machine-contract artifacts that host products such as Redeven can consume
  without local checkout wiring.

## Repository Scope

`redevplugin` owns the reusable plugin platform as an independently released
library/runtime repository. Host products import it; they do not vendor, copy,
or partially reimplement it. It must stay host-neutral and must not import
Redeven internal packages, Env App internals, Flower/Floret internals,
Workbench components, or Redeven business adapters.

This repository owns:

- the embeddable Go Host library, adapter interfaces, registry, lifecycle APIs,
  package/manifest/signature validation, permissions, confirmations, audit
  contracts, runtime manager/supervisor, and mountable HTTP adapter;
- the TypeScript UI package for sandboxed plugin surfaces, bridge SDK, generated
  clients, settings/intent helpers, and host-neutral developer utilities;
- the Rust `redevplugin-runtime` process plus the host-neutral process lifecycle
  contract used to start, stop, health-check, restart, and observe that process;
- the Rust IPC protocol, WASM actor/job execution, storage/network hot paths,
  target classifier enforcement, quotas, stream handling, revocation handling,
  and runtime diagnostics;
- OpenAPI specs, JSON schemas, Rust IPC schemas, WASM ABI schemas,
  token/ticket schemas, target-classifier fixtures, generated DTOs, and contract
  hashes;
- CLI commands, plugin templates, host-neutral Flower-generation-compatible scaffolds,
  package/validate/dev-harness tools, replay fixtures, and cross-language tests;
- package publication evidence, registry checksums and provenance, license
  notices, and compatibility manifests for all published platform components.

The repository must be usable as a library/runtime product, not just as a
collection of specifications. When a platform feature is declared supported, it
must provide the host-importable implementation surface that products need:

- Go packages that expose stable constructors, adapter interfaces, DTOs,
  lifecycle services, and mountable HTTP handlers;
- TypeScript packages that expose the sandbox surface host, bridge SDK,
  generated clients, and host-neutral helpers needed by plugin UIs and product
  shells;
- published Rust source crates for `redevplugin-runtime` and its support crates,
  plus a Go-managed supervisor contract for admission, launch, health, shutdown,
  restart, and diagnostics;
- generated contracts, fixtures, compatibility hashes, and release metadata that
  let host products validate the exact behavior they are consuming.

The Go, TypeScript, and Rust pieces are one platform contract. ReDevPlugin
publishes the Rust runtime as source crates. A host product must be able to
import the Go library, mount the HTTP adapter, use the TypeScript surface/bridge
package, and build the runtime binary from exact published Rust source crates
without sibling wiring or a host-local protocol. Keep APIs embeddable,
versioned, and generated where practical.

ReDevPlugin must provide the full front-end and back-end platform implementation
surface that a host imports:

- Front-end platform implementation lives in released npm packages: sandbox
  surface host, iframe bootstrap helpers, asset-ticket/session client pieces,
  bridge SDK, settings and intent helpers, generated clients, replay/dev-harness
  utilities, and host-neutral UI primitives required by plugin UIs and product
  shells.
- Host/back-end platform implementation lives in released Go packages:
  lifecycle services, registry and staged-package state, manifest/package/signature
  validators, permission and confirmation pipeline, token/ticket issuance,
  broker contracts, operation/stream envelopes, runtime manager/supervisor,
  stable errors, audit DTOs, HTTP adapter, and adapter interfaces.
- Plugin backend execution lives in the published Rust source crates for
  `redevplugin-runtime`: WASM actor/job execution, IPC, hostcall contracts,
  storage/network hot paths, target classification, stream handling, leases,
  quotas, revoke epochs, generation IDs, and diagnostics. Host products build
  the executable bytes but do not own or fork these runtime semantics.
- Host products provide concrete adapters and product policy. They should never
  be asked to implement a second manifest parser, lifecycle state machine,
  sandbox bridge, token issuer, storage/network broker, operation stream,
  runtime process supervisor, IPC protocol, or WASM executor to make
  ReDevPlugin usable.

Public ReDevPlugin behavior must be expressed as released contracts before a
host product depends on it. A feature that changes plugin lifecycle behavior,
manifest shape, bridge messages, token/ticket semantics, runtime IPC, WASM ABI,
broker behavior, operation/stream envelopes, registry state, stable errors, or
generated SDK calls is not complete until the Go API, TypeScript API, Rust
runtime contract, machine-readable schema, fixtures, compatibility metadata,
and tests are updated together.

Host products own their own product policy and adapters. For Redeven, that means
Redeven owns session metadata mapping, Local UI/AppServer route mounting,
Env App/Activity Bar/Workbench/Settings integration, Flower/Floret tool wiring,
Desktop/installer bundling, state-root selection, audit sink adapters,
diagnostics sink adapters, secret adapters, and business capabilities such as
container resource management.

ReDevPlugin APIs must expose explicit adapter interfaces and host-neutral DTOs.
If a feature requires a Redeven-specific type or policy decision, keep that
logic in Redeven and pass it through an adapter boundary instead of moving
Redeven internals into this repository.

Do not add a host-specific "convenience" path that bypasses the reusable
contract. For example, a host product may provide a vault adapter or a Docker
capability adapter, but the plugin lifecycle, sandbox bootstrap, bridge tokens,
operation/stream envelopes, storage/network/runtime brokers, and runtime
supervisor remain ReDevPlugin responsibilities.

Do not leave platform behavior as "the host should implement this later" unless
it is deliberately represented as an adapter interface. A host adapter may
provide policy decisions or concrete resources, but ReDevPlugin must own the
common lifecycle around that adapter: validation, request context, permission
checks, confirmation, token/ticket issuance, lease/quota enforcement, revocation
handling, audit/error shape, and generated client/contract behavior.

The intended host integration shape is:

- the host imports released ReDevPlugin Go and TypeScript packages;
- the host pins the released ReDevPlugin package set and builds the runtime
  binary from verified published source crates with a fixed product toolchain;
- the host verifies, signs, and bundles that product-owned runtime binary;
- the host mounts ReDevPlugin HTTP handlers or calls the embeddable lifecycle
  APIs instead of reimplementing endpoint behavior;
- the host registers explicit adapters for sessions, origin/CSRF policy,
  storage roots, vault access, audit sinks, diagnostics sinks, release-artifact
  resolution, and business capabilities;
- the host product decides where surfaces appear and who may operate them, while
  ReDevPlugin keeps ownership of sandbox bootstrap, bridge handshake, lifecycle
  state, permission evaluation, tokens/tickets, leases, quotas, revoke epochs,
  and runtime execution.

If a host integration needs more than adapter registration, route mounting,
artifact selection, product UI, or business capability implementation, treat the
missing piece as a ReDevPlugin platform requirement and add it here first.

Use this placement rule when designing a new package:

- Platform library: belongs here. It defines reusable plugin package,
  lifecycle, registry, bridge, sandbox, broker, runtime, operation/stream,
  permission, signing, generated SDK, CLI validator, template, or compatibility
  behavior.
- Host adapter contract: belongs here as an interface, DTO, schema, callback, or
  fixture when the concept is reusable across host products.
- Host adapter implementation: belongs in the host product when it talks to a
  product session model, Env App route, Workbench surface, Desktop installer,
  secret vault, Docker/Podman daemon, shell, cloud account, database server, or
  other product/business resource.
- Reference or fake host implementation: allowed here only for tests, examples,
  conformance harnesses, and developer documentation, and it must not import a
  real host product.

The clean architectural rule is dependency direction:

- host products import released ReDevPlugin artifacts;
- ReDevPlugin never imports host-product code;
- ReDevPlugin owns generic extension mechanics, while host products own the
  concrete business capability adapters registered into those mechanics.

When a new requirement is ambiguous, place it in ReDevPlugin only if it can be
used by multiple host products without knowing Redeven concepts, product UI,
session semantics, or business entities. Otherwise define an adapter interface in
ReDevPlugin and implement the policy or capability in the host product.

## Redeven Host Boundary

Redeven is the first host product, not the owner of the plugin platform. The
boundary must stay explicit in both directions:

- ReDevPlugin defines the plugin package format, manifest schema, signature
  model, trust and enable state machines, lifecycle API, sandbox bootstrap,
  bridge protocol, token/ticket rules, permission evaluation, confirmation
  intents, storage/network broker contracts, runtime manager/supervisor, Rust
  runtime IPC, WASM ABI, CLI validators, templates, and compatibility manifests.
- Redeven defines product policy and host adapters: session metadata mapping,
  CSRF/origin enforcement, local policy caps, state-root selection, audit and
  diagnostics sinks, secret vault integration, Env App placement, Workbench and
  Settings presentation, Desktop packaging, installer wiring, Flower/Floret
  orchestration, and Redeven-owned business capabilities.
- ReDevPlugin may provide host-neutral UI SDK pieces and reference components,
  but it must not contain Redeven navigation, Activity Bar layout, Workbench
  chrome, product copy, or Flower-specific interaction logic.
- Manifest surfaces use only host-neutral `view`, `command`, or `background`
  kinds plus optional semantic intent. Host products map those declarations to
  navigation, workspace, settings, modal, or command placement.
- Redeven may wrap ReDevPlugin routes, commands, and generated clients to fit
  its product shell, but it must not carry a second manifest parser, weaker
  validator, alternate package builder, independent registry lifecycle, forked
  bridge protocol, or separate runtime execution model.
- Redeven may expose product-specific CLI commands or UI routes, but the
  platform-management behavior behind them must still be ReDevPlugin library or
  HTTP-adapter behavior.
- Business capabilities such as container management are host adapters
  registered by Redeven. They are not plugin runtime mechanisms and must not be
  implemented as generic ReDevPlugin core unless the capability becomes
  host-neutral by design.
- ReDevPlugin may define the generic capability registration contract, request
  context, permission hooks, stream/operation envelope, and audit/error shapes;
  Redeven owns the adapter implementation that talks to Docker, Podman, local
  files, shells, cloud APIs, or any other Redeven-specific resource.
- Flower-generated plugins are supported through host-neutral templates,
  validators, SDKs, replay harnesses, and lifecycle APIs in ReDevPlugin.
  Redeven/Flower owns user intent collection, approval UX, environment selection,
  prompt orchestration, and any product-specific generation policy.

Use this responsibility matrix as the default decision rule:

| Area | ReDevPlugin owns | Host product owns |
| --- | --- | --- |
| Package and trust | Package layout, canonical hashes, signing rules, manifest validation, trust state contracts, compatibility manifests | Which registries or local sources are allowed, product review UX, enterprise policy caps |
| Lifecycle | Install, enable, open, disable, uninstall, update, downgrade, export/import, diagnostics, and data-retention APIs | Where those actions appear in product UI, who may invoke them, and how they are audited in the host product |
| UI runtime | Sandboxed iframe bootstrap, asset ticket/session protocol, bridge SDK, opaque-origin-safe source/port-bound MessageChannel messaging, settings and intent contracts | Activity Bar, Workbench, Settings, Desktop shell, route mounting, native product chrome, and product copy |
| Backend runtime | Rust `redevplugin-runtime` source crates, runtime admission and manager/supervisor, WASM actor/job model, IPC, leases, quotas, revocation, hostcall contracts, stream envelopes | Fixed package coordinates and toolchain, verified source build, product binary/SBOM/provenance/signature, process placement, and diagnostics presentation |
| Storage, network, and secrets | Host-neutral broker contracts, request contexts, target classifiers, quotas, secret reference contracts, and stable errors | Concrete vault, filesystem root, environment policy, allowlists, proxy settings, and product-specific grant UX |
| Business capabilities | Generic capability adapter interface, permission hooks, operation/stream envelope, and audit DTOs | Docker/Podman, files, shells, cloud services, database access, local product APIs, and any domain-specific adapter |
| Plugin generation | Templates, validators, package builder, replay harness, generated SDK clients, and example fixtures | Flower prompt orchestration, user intent collection, environment selection, review/approval UX, and generated-plugin install flow |

If the right column is needed before the left column has a stable contract, add
or fix the ReDevPlugin contract first and release it before asking a host product
to depend on the behavior.

Any platform bug found while integrating Redeven must be fixed in ReDevPlugin
first, released as a versioned artifact, and then consumed by Redeven. Temporary
Redeven-side workarounds are allowed only inside an unmerged feature branch and
must not become the committed integration contract.

## Boundary Enforcement Checklist

Use this checklist whenever adding or reviewing ReDevPlugin code:

- If the code imports Redeven, Env App, Workbench, Flower, Floret, Desktop, or a
  Redeven business package, the boundary is wrong. Replace the import with a
  host-neutral adapter interface, DTO, schema, or callback.
- If the feature mentions a concrete product route, menu, Activity Bar position,
  Workbench layout, Flower prompt, local installer path, or Redeven session
  field, it belongs in the host product unless it can be expressed as a generic
  adapter contract.
- If the feature talks to Docker, Podman, shells, files outside a plugin storage
  namespace, cloud-provider APIs, database servers, or any other business
  resource, ReDevPlugin may own the permission/operation/stream envelope, but the
  concrete adapter must live in the host product.
- If a plugin UI document is loaded, the loading path must remain the
  ReDevPlugin sandbox bootstrap, asset-ticket/session validation, and
  opaque-origin-safe source/port-bound MessageChannel bridge handshake path.
  For opaque sandbox iframes, `event.origin` is diagnostic context only and is
  not an authorization input. Authorization must bind the window source,
  transferred `MessagePort`, asset session, surface instance, bridge nonce,
  active fingerprint, session hash, management revision, and revoke epoch. Host UI
  chrome may surround the surface but must not replace that path.
- If a plugin backend executes, it must execute through the Rust
  `redevplugin-runtime` WASM actor/job model. Third-party native processes,
  container images, shell hooks, dynamic libraries, and postinstall scripts are
  not plugin backend mechanisms.
- If runtime process lifecycle code is needed, it belongs in ReDevPlugin as a
  host-neutral admission layer and manager/supervisor with explicit hooks for a
  host-provided trusted directory handle, expected descriptor, logging, health
  reporting, and shutdown deadlines. Host products build the product binary and
  may call those hooks, but must not implement a parallel supervisor.
- If a contract is observable by a host product or plugin author, update the
  schema, generated types, fixtures, compatibility manifest, release metadata,
  and tests in the same change.
- Tests for host integration should use a small fake host adapter inside this
  repository. Do not import Redeven tests, fixtures, package paths, or product
  configuration as the ReDevPlugin test oracle.

## Cross-Repository Dependency Boundary

Host products consume ReDevPlugin through published artifacts only:

- Go module versions;
- npm package versions;
- Rust source crate versions and registry checksums for `redevplugin-runtime`
  and its support crates;
- package publication evidence and the exact Cargo dependency closure;
- released OpenAPI/schema/IPC/WASM ABI/token/classifier contract hashes.

Do not require host products to use local `../redevplugin` checkouts. Do not
document or support `go.work`, `go.work.sum`, `replace`, `file:`, `link:`,
`workspace:`, `portal:`, Rust path overrides, absolute paths, relative sibling
paths, copied source trees, or build aliases as a host-product integration path.
Run dependency and contract checks that touch Go with `GOWORK=off`.

When ReDevPlugin changes a public contract, update the schema, generated types,
fixtures, compatibility manifest, release notes, and tests in the same feature
change. Host products should be able to validate compatibility from released
artifact versions and contract hashes without reading this repository's source.

Do not publish a feature as "implemented" for a host product until the Go/npm
libraries, Rust source crates, generated SDKs, contracts, compatibility
metadata, and package publication evidence that the host consumes are released
together. The host-built OS runtime binary is a product artifact and is not a
ReDevPlugin release artifact.

## Durable Schema Migration

ReDevPlugin owns the migration lifecycle for every durable schema and on-disk
layout that ReDevPlugin defines. Host products select the state root and invoke
released migration APIs, but they must not copy ReDevPlugin schemas, SQL, file
layout rules, or migration state machines into host code.

- Every change to a released ReDevPlugin-owned durable schema or layout must
  include an automatic, versioned, idempotent, and crash-recoverable migration
  path from every supported released predecessor before new readers or writers
  open that state.
- A normal upgrade from recognized supported state must not fail with an error
  that requires the user to delete a database, run SQL manually, or reinstall.
  Startup errors are reserved for unknown, corrupt, ambiguous, tampered, or
  future state that cannot be migrated without violating ownership or security.
- Migrations must preserve user data whenever ownership and semantics are
  provable. State whose owner cannot be proven must be retained in an atomic
  quarantine and replaced with a fresh owner-scoped generation; automatic
  migration must never silently assign ambiguous state or delete quarantine.
- Migration entrypoints must recover safely from every persisted intermediate
  state and return the active durable root only after the committed generation
  has been verified. Repeated startup must reuse that generation without
  rewriting or discarding data created after migration.
- Tests must cover fresh install, each supported historical schema or fixture,
  interruption recovery, idempotent restart, data preservation, and fail-closed
  handling that leaves unknown or corrupt state unchanged.
- ReDevPlugin must not inspect, migrate, or delete schemas owned by a host
  product or another component. Those repositories own their own migrations;
  the cross-repository boundary remains explicit even when their state roots are
  colocated by a product.
- Migration behavior is a released platform contract. Update the public Go API,
  machine contracts and fixtures when observable, compatibility metadata,
  release notes, and package-set evidence together before a host consumes it.

## Git Workflow (Worktree, Required)

This section is the authoritative ReDevPlugin copy of the Git workflow. It
mirrors the generally applicable parts of Redeven's public runtime repository
rules, adjusted for this repository's package names, worktree names, and release
artifacts. Developers should be able to follow this file alone for day-to-day
ReDevPlugin work.

When Redeven changes its public runtime Git discipline, review this section in
the same cross-repository change and copy over any generally applicable rule.
When this repository changes its plugin-platform boundary, review Redeven's
`AGENTS.md` in the same change so both sides continue to describe the same
dependency direction and ownership split.

Generally applicable Redeven rules include worktree-only development, clean
`main`, full-tip `main` pushes, private feature branches, fast-forward
integration, no routine backup branches, short-lived stash use, `go.work`
prohibition, published-dependency consumption, conflict resolution in feature
worktrees, English maintained docs/comments, Conventional Commit messages,
local gate before commit, and `AGENTS.md` as the repository rule source. Do not
copy Redeven product-specific UI, OKF, release, Desktop, Flower, or installer
rules unless they are rewritten as host-neutral ReDevPlugin rules.

The ReDevPlugin copy of the Git discipline must stay self-contained. A developer
working only in this repository should not need to open Redeven's guide to know
how to create a worktree, sync a feature, resolve conflicts, run local gates,
preserve meaningful commits, avoid local sibling wiring, or integrate back to
`main`. When Redeven adds a generally applicable Git rule, copy the rule here in
ReDevPlugin terms instead of linking to it as an external prerequisite.

Do not replace the concrete procedure below with a pointer to Redeven's
`AGENTS.md`. ReDevPlugin contributors must have the full day-to-day Git
procedure in this repository, including worktree naming, branch naming, rebase
sync, fast-forward integration, conflict handling, stash cleanup, no-backup-branch
discipline, `go.work` prohibition, released-artifact dependency policy, and
local quality gates. Redeven's guide may be the source of a generally useful
rule, but this file is the rule that governs this repository.

If a rule cannot be copied because it depends on Redeven product concepts, do
not import the product rule by name. Either omit it or rewrite the durable
host-neutral invariant that applies to ReDevPlugin. Examples of rules that must
not be copied verbatim include Redeven Desktop verification, Workbench
interaction contracts, Flower UI projection, OKF maintenance, installer routes,
and Redeven runtime release tags.

When copying a generally applicable Git rule from Redeven, make it actionable in
ReDevPlugin terms in this file: include the concrete `../redevplugin-feat-*`
worktree naming, the release-artifact dependency constraints, the local gate
expectations for Go/TypeScript/Rust/contracts, and the forbidden local wiring
forms. Do not add a sentence that merely tells contributors to "see Redeven" for
the actual procedure.

- Never develop directly on `main`.
- The only direct-`main` exception is the first repository bootstrap commit that
  creates this guide before a usable `origin/main` exists. After that commit, all
  changes must use the worktree flow below.
- Every change must be done in a dedicated worktree plus feature branch.
- `main` is only for `pull --ff-only` and final integration.
- Do not leave uncommitted changes in the `main` worktree.
- Before creating a feature worktree, synchronize `main` with
  `git fetch origin`, `git switch main`, and `git pull --ff-only`. If this is a
  fresh bootstrap and `origin/main` does not exist yet, finish publishing the
  bootstrap `main` before starting normal feature work.
- `main` and `origin/main` may only be exact matches, or local `main` may be
  ahead with the intent to push the complete current local tip. Do not maintain a
  plan where only some local `main` commits are pushed and newer local `main`
  commits remain unpublished.
- Do not create routine `backup/*` branches. If recovery is needed, abort the
  rebase, inspect the feature worktree, and use explicit user-approved branches
  only when the branch itself has a real collaboration purpose.
- `git stash` is allowed only as a short-term safety rope before rebasing or
  switching context. Every stash must be applied back and continued, or dropped
  once it is confirmed obsolete. Do not leave stale stashes as hidden work.
- Never introduce or rely on `go.work` or `go.work.sum` in this repository,
  sibling repositories, or their shared parent directory as a cross-repo
  development shortcut.
- Do not wire local sibling repositories into builds, tests, examples, fixtures,
  docs, generated contracts, or release validation.
- If local `main` is pushed, push the full current local `main` tip together with
  all of its latest commits.
- Do not partial-push `main`, and do not update `origin/main` through another
  branch while newer local `main` commits remain unpublished.
- One feature equals one dedicated worktree plus one local private branch.
- Do not mix independent topics in one feature branch. If two pieces of work can
  ship or be reviewed separately, they should use separate worktrees.
- Feature worktree directories live next to the repository and use the
  `../redevplugin-feat-<topic>` naming pattern. Feature branches use
  `feat-<topic>` unless the user explicitly requests a different name.
- Keep feature branches private until they are merged into `main`.
- Do not push feature branches or create pull requests unless the user explicitly
  asks for that collaboration path.
- Do not create a pull request merely to trigger CI; by default, fast-forward the
  ready feature into `main`, push `main`, and verify the `main` Actions run.
  Run the local gate first and use CI as confirmation, not as the first
  validator.
- Default sync strategy for a feature branch: `git rebase origin/main`.
- Do not merge `origin/main` into a feature branch in the normal flow.
- If a feature worktree needs to catch up with `main`, rebase it on
  `origin/main` from inside that feature worktree and resolve any conflicts
  there.
- Preserve intentional commit history when integrating:
  - use `git merge --ff-only "$BR"` on `main` once the feature branch history is
    ready;
  - if the feature branch history is too noisy, clean it inside the feature
    branch before integration instead of hiding it behind `--squash`.
- Do not use `git merge --squash` as the default integration path. This
  repository preserves meaningful commits the same way Redeven does; noisy
  feature history should be cleaned before the fast-forward merge.
- Resolve conflicts only inside the feature worktree, never on `main`.
- Do not merge feature branches into each other.
- Do not use local sibling repositories as an unpublished integration surface
  during development. When a change needs an upstream fix, land and release that
  upstream artifact first, then consume the released version here or in the host
  product.
- Do not commit changes that make this repository require a Redeven checkout to
  build, test, validate contracts, generate SDKs, or run examples. A fake host
  adapter inside this repository is acceptable; a real Redeven package import,
  path alias, fixture dependency, or local runtime lookup is not.

Recommended setup:

```bash
git fetch origin
git switch main
git pull --ff-only

BR=feat-<topic>
WT=../redevplugin-feat-<topic>
git worktree add -b "$BR" "$WT" origin/main
```

## Feature Sync

Inside the feature worktree:

```bash
git status
# The worktree must be clean before rebasing.

git fetch origin
BASE=$(git rev-parse HEAD)
git rebase origin/main
```

If conflicts happen:

```bash
git add <resolved-files>
git rebase --continue
```

If you are unsure:

```bash
git rebase --abort
```

After every rebase:

```bash
git range-diff "$BASE"...HEAD
git diff origin/main...HEAD
```

Then rerun the relevant local quality gate from this file. For public contracts,
also inspect the generated contract diff and compatibility manifest so the
feature still represents the intended API surface after replaying on latest
`main`.

Do not continue after a failed or uncertain rebase by manually deleting conflict
markers until the tree compiles. Abort, reassess the latest `main` shape, and
replay the feature intent deliberately.

If `git stash` was used before the rebase, immediately apply or drop the exact
stash after the rebase decision. Do not leave the repository with hidden pending
work.

## Integration Back To Main

Once the feature branch is ready:

```bash
git switch main
git fetch origin
git pull --ff-only

# If local main is already ahead of origin/main, publish the full local main tip first.
# Do not keep older local main commits unpublished while only pushing the new feature result.
# git push origin main

git merge --ff-only "$BR"
git push origin main
```

Cleanup:

```bash
git worktree remove "$WT"
git branch -d "$BR"
```

If the feature branch was pushed:

```bash
git push origin --delete "$BR"
```

Additional rules:

- Remote `main` should always move directly to the latest local `main` tip
  whenever `main` is pushed.
- Do not discard, collapse, or silently rewrite meaningful feature commits during
  integration.
- Integration and conflict resolution must preserve the semantic intent of all
  involved branches, not just produce text that compiles.
- Before resolving merge or rebase conflicts, review the substantive commits on
  each side for new features, bug fixes, behavior changes, tests, and
  user-facing workflows.
- Do not drop, overwrite, or silently weaken current or historical functionality
  unless the user explicitly approves that product decision.
- If two branches introduce incompatible behavior, surface the product or
  architecture tradeoff instead of choosing one side silently.
- After resolving conflicts, run focused checks for the affected behavior in
  addition to the repository quality gate.
- If a feature branch has already been pushed and someone depends on it, switch
  to a conservative coordination flow instead of freely rewriting history.
- Do not integrate a feature branch that depends on unpublished sibling
  repository state. ReDevPlugin should be independently buildable, testable, and
  releasable from its own checkout.

Recommended Git configuration:

```bash
git config --global rerere.enabled true
git config --global merge.conflictstyle zdiff3
```

### Commit Messages

Use Conventional Commit style for every commit:

```text
<type>(<scope>): <summary>
```

Rules:

- Use a lowercase type. Prefer `feat`, `fix`, `docs`, `test`, `refactor`,
  `chore`, `build`, or `ci`.
- Always include a concise lowercase scope that names the affected area, for
  example `host`, `runtime`, `ipc`, `wasm`, `ui`, `sdk`, `contracts`, `cli`,
  `templates`, `release`, or `repo`.
- Keep the summary in imperative mood, start it lowercase, and omit a trailing
  period.
- Use English for commit messages.
- Examples:
  - `feat(runtime): add wasm actor lease renewal`
  - `fix(contracts): reject stale bridge tickets`
  - `docs(repo): document host adapter boundary`

## Conflict Resolution Principles

- Resolve conflicts only in the feature worktree.
- If a conflict happens on `main`, abort and go back to the feature branch.
- During `git rebase origin/main`, do not use `--ours` and `--theirs` blindly:
  - `--ours` usually means the rebasing target (`origin/main`);
  - `--theirs` usually means the replayed feature commit.
- Start from the latest `main` structure and then re-apply the real feature
  intent on top of it.
- For renames, file moves, formatting changes, or import reshuffles:
  - keep the latest `main` layout first;
  - then restore the feature logic in the new location.
- For generated files, snapshots, and lockfiles:
  - prefer regeneration over manual conflict stitching.
- For shared contracts, schemas, and cross-repo payload fields:
  - align semantics manually instead of blindly taking one side.
- For generated SDKs, lockfiles, package metadata, contract hashes, and release
  manifests:
  - prefer regenerating from the authoritative source after resolving the source
    conflict.
- For delete/modify conflicts:
  - first verify whether `main` intentionally removed or migrated the surface;
    do not mechanically restore deleted platform code.
- For behavior conflicts that are not obvious from conflict markers, inspect the
  relevant commit history and tests so fixes and existing product behavior are
  not regressed.
- If you are not confident about the resolution, abort the rebase and reassess.

## Temporary Work Documents

Temporary design notes, investigation scratchpads, review checklists, and
handoff notes must not be committed as maintained repository documents. Prefer
placing them outside the repository. If a temporary file must live inside the
repository while a feature is in progress, put it under an ignored path and
remove it before integration.

Maintained documentation for ReDevPlugin belongs in intentional repository files
such as `README.md`, `AGENTS.md`, public specs, generated contracts, release
notes, or future canonical docs. Do not leave stale planning drafts that compete
with machine-readable schemas or the released compatibility manifest.

## Cross-Repository Rule Synchronization

`AGENTS.md` is part of the public host/platform contract. Keep it synchronized
with Redeven at the responsibility-boundary level:

- If ReDevPlugin changes what the platform owns, what the host owns, how released
  artifacts are consumed, or how the Rust runtime boundary works, update
  Redeven's `AGENTS.md` in the corresponding Redeven worktree before asking
  Redeven to consume the new behavior.
- If Redeven changes its ReDevPlugin boundary, review this file and copy the
  matching host-neutral rule here before landing ReDevPlugin work that depends on
  the new interpretation.
- If the two files disagree, treat the disagreement as a review blocker and fix
  both files before landing dependent integration. For ReDevPlugin work, this
  file remains the local authority; do not resolve the disagreement by adding a
  convenience path in either repository.
- Treat boundary changes like contract changes: update tests, fixtures,
  compatibility metadata, and release notes when the rule implies an observable
  platform behavior.

## Cross-Repository Release Discipline

ReDevPlugin is an upstream dependency for host products. A change is not
host-consumable until it has been released as versioned artifacts with the
matching contract metadata.

Release-bound changes must keep these artifacts aligned:

- Go module version for embeddable host libraries and DTOs;
- npm package versions for UI SDKs, generated clients, bridge helpers, and
  templates;
- Rust source crate versions, registry checksums, Cargo dependency closure, and
  packaged-source conformance for `redevplugin-runtime` and support crates;
- OpenAPI, JSON schema, IPC, WASM ABI, token/ticket, and classifier contract
  hashes;
- compatibility manifest, release notes, package publication evidence, registry
  provenance, and third-party notices.

ReDevPlugin publishes versioned source crates, not OS runtime binaries. Host
products build the runtime binary from exact published crates, then own the
resulting binary, SBOM, provenance, signature, installer, and product archive.
This artifact boundary does not transfer runtime admission, supervisor, IPC,
WASM, lease, quota, revocation, or hostcall semantics to the host product.

Do not instruct Redeven or another host product to consume unreleased local
behavior. If an integration needs a fix, land and release it here first, then
upgrade the host product to the published artifact.

## Repository Language Policy

- English is the default language for all maintained repository content.
- Use English for source comments, developer-facing Markdown, generated contract
  descriptions, CLI help, script output, test names, fixture descriptions,
  release notes, commit messages, and PR-facing text.
- Non-English text is allowed only when necessary for product
  internationalization, locale fixtures, Unicode validation, or generated sample
  plugins that explicitly test localization.
- When non-English text is added for i18n, keep it scoped to the relevant locale,
  resource, or test file and document the reason in English when the purpose is
  not obvious.

## Security Boundary

Third-party plugins are untrusted.

ReDevPlugin must treat every plugin package, manifest, iframe, WASM module,
network target, storage request, and generated plugin as untrusted input until it
passes the relevant host-controlled validation, policy, quota, and lifecycle
checks.

Core invariants:

- third-party plugins must not ship native backends, dynamic libraries,
  postinstall scripts, shell backend hooks, or container-image backends;
- plugin UI must run inside sandboxed iframes through the ReDevPlugin bridge and
  asset-ticket/session protocol;
- plugin backend code must run through the Rust `redevplugin-runtime` WASM
  actor/job model and hostcall contracts;
- storage, networking, streaming, secrets, confirmations, and privileged host
  capabilities must go through ReDevPlugin brokers and host adapters;
- Rust runtime hot paths enforce signed grants, leases, quotas, revoke epochs,
  generation IDs, and target-classifier decisions, but host policy remains
  authoritative in the Go Host library;
- host products may register business capabilities, but they must not bypass the
  ReDevPlugin permission, confirmation, token, lease, audit, or lifecycle chain.

## Quality Gates

Keep local checks aligned with CI. As the repository is bootstrapped, add the
exact scripts and workflows here when they land.

Before pushing `main`, configure the tracked hook with:

```bash
git config core.hooksPath .githooks
```

`.githooks/pre-push` invokes `scripts/check_redevplugin_pre_push.sh` only for a
clean, fast-forward update of `refs/heads/main` from the checked-out `main`
branch whose `HEAD` matches the pushed object. That script is the authoritative
local equivalent of every CI check that does not require GitHub credentials,
artifact storage, tag/ref identity, registry readback, Sigstore signing, or a
hosted multi-platform runner. It includes Go, TypeScript, browser, canonical
WASM, bridge, performance, Rust, audit, stress, property, contract, platform,
and platform-package publication smoke gates. The hook behavior itself is
covered by
`scripts/test_redevplugin_pre_push_hook.sh`. The main-branch CI workflow
invokes the same gate in its `Main Pre-Push Equivalent` job. Do not add a
repository gate to a workflow without adding it to this script and running it
before the next main push.

Run the relevant gate before creating any commit that another person or host
product may build on. Do not commit or push first and use CI as the first place
that discovers broken formatting, stale generated contracts, incompatible
schemas, or missing release metadata.

Expected gates for platform changes:

- Go: formatting, `GOWORK=off go list ./cmd/... ./examples/... ./pkg/...`, unit tests, race-sensitive lifecycle tests where practical,
  linting, SQLite schema initialization and reopen tests, HTTP adapter contract tests, and generated DTO
  checks.
- TypeScript: clean install, typecheck, lint, unit tests, SDK contract tests,
  bridge replay tests, and build output checks.
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, license/advisory audit, IPC fixture tests, WASM ABI
  tests, classifier tests, and runtime smoke tests for supported targets.
- Contracts: OpenAPI/schema validation, generated Go/TS/Rust type sync, golden
  fixture decode/encode, token/ticket fixture validation, stable error-code
  coverage, and contract hash generation.
- Release: registry package closure and readback, package checksums/provenance,
  packaged-source extraction and conformance, reproducible source builds,
  third-party notices, exact-one `platform-package-publication-v1` completion
  evidence, version matrix consistency, and host-consumable compatibility
  manifest validation.

The complete main-push gate is:

```bash
./scripts/check_redevplugin_pre_push.sh
```

Dependency-boundary checks must prove that the repository builds without sibling
workspace wiring:

- Go commands that can be affected by a workspace must run with `GOWORK=off`.
- Package-manager installs must use registry-resolved package versions rather
  than local links.
- Rust runtime checks must not rely on path overrides to host-product source
  trees.

Do not ship a public contract change without tests that prove the current
contract accepts valid inputs, rejects invalid and out-of-bound inputs with
fail-closed behavior, and produces stable diagnostic errors.

## Repository Rule File

- `AGENTS.md` is the canonical repository rule file for this repository.
- Do not add or keep a committed repository-level `.develop.md` here.
