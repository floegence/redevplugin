# ReDevPlugin Repository Guide

This file is the repository-level operating guide for `redevplugin/`.

Goals:

- keep ReDevPlugin usable as an independent, reusable plugin platform;
- keep host-product boundaries explicit and auditable;
- never develop directly on `main`;
- preserve intentional commit history;
- publish versioned Go, TypeScript, Rust runtime, and machine-contract artifacts
  that host products such as Redeven can consume without local checkout wiring.

## Repository Scope

`redevplugin` owns the reusable plugin platform. It must be host-neutral and must
not import Redeven internal packages, Env App internals, Flower/Floret internals,
Workbench components, or Redeven business adapters.

This repository owns:

- the embeddable Go Host library, adapter interfaces, registry, lifecycle APIs,
  package/manifest/signature validation, permissions, confirmations, audit
  contracts, and HTTP adapter;
- the TypeScript UI package for sandboxed plugin surfaces, bridge SDK, generated
  clients, settings/intent helpers, and host-neutral developer utilities;
- the Rust `redevplugin-runtime` process, IPC protocol, WASM actor/job execution,
  storage/network hot paths, target classifier enforcement, quotas, stream
  handling, revocation handling, and runtime diagnostics;
- OpenAPI specs, JSON schemas, Rust IPC schemas, WASM ABI schemas,
  token/ticket schemas, target-classifier fixtures, generated DTOs, and contract
  hashes;
- CLI commands, plugin templates, Flower-generation-compatible scaffolds,
  package/validate/dev-harness tools, replay fixtures, and cross-language tests;
- release artifacts, checksums, signatures, license notices, and compatibility
  manifests for all published platform components.

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

## Cross-Repository Dependency Boundary

Host products consume ReDevPlugin through published artifacts only:

- Go module versions;
- npm package versions;
- signed `redevplugin-runtime` binaries for supported targets;
- released OpenAPI/schema/IPC/WASM ABI/token/classifier contract hashes.

Do not require host products to use local `../redevplugin` checkouts. Do not
document or support `go.work`, `go.work.sum`, `replace`, `file:`, `link:`,
`workspace:`, `portal:`, Rust path overrides, absolute paths, relative sibling
paths, copied source trees, or build aliases as a host-product integration path.

When ReDevPlugin changes a public contract, update the schema, generated types,
fixtures, compatibility manifest, release notes, and tests in the same feature
change. Host products should be able to validate compatibility from released
artifact versions and contract hashes without reading this repository's source.

## Git Workflow (Worktree, Required)

- Never develop directly on `main`.
- The only direct-`main` exception is the first repository bootstrap commit that
  creates this guide before a usable `origin/main` exists. After that commit, all
  changes must use the worktree flow below.
- Every change must be done in a dedicated worktree plus feature branch.
- `main` is only for `pull --ff-only` and final integration.
- Do not leave uncommitted changes in the `main` worktree.
- Do not create routine `backup/*` branches. If recovery is needed, abort the
  rebase, inspect the feature worktree, and use explicit user-approved branches
  only when the branch itself has a real collaboration purpose.
- Never introduce or rely on `go.work` or `go.work.sum` in this repository,
  sibling repositories, or their shared parent directory as a cross-repo
  development shortcut.
- Do not wire local sibling repositories into builds, tests, examples, fixtures,
  or release validation.
- If local `main` is pushed, push the full current local `main` tip together with
  all of its latest commits.
- Do not partial-push `main`, and do not update `origin/main` through another
  branch while newer local `main` commits remain unpublished.
- One feature equals one dedicated worktree plus one local private branch.
- Keep feature branches private until they are merged into `main`.
- Do not push feature branches or create pull requests unless the user explicitly
  asks for that collaboration path.
- Default sync strategy for a feature branch: `git rebase origin/main`.
- Do not merge `origin/main` into a feature branch in the normal flow.
- Preserve intentional commit history when integrating:
  - use `git merge --ff-only "$BR"` on `main` once the feature branch history is
    ready;
  - if the feature branch history is too noisy, clean it inside the feature
    branch before integration instead of hiding it behind `--squash`.
- Resolve conflicts only inside the feature worktree, never on `main`.
- Do not merge feature branches into each other.

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
git diff origin/main...HEAD
```

Then rerun the relevant local quality gate from this file.

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
- For behavior conflicts that are not obvious from conflict markers, inspect the
  relevant commit history and tests so fixes and existing product behavior are
  not regressed.
- If you are not confident about the resolution, abort the rebase and reassess.

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

Expected gates for platform changes:

- Go: formatting, unit tests, race-sensitive lifecycle tests where practical,
  linting, schema migration tests, HTTP adapter contract tests, and generated DTO
  checks.
- TypeScript: clean install, typecheck, lint, unit tests, SDK contract tests,
  bridge replay tests, and build output checks.
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, license/advisory audit, IPC fixture tests, WASM ABI
  tests, classifier tests, and runtime smoke tests for supported targets.
- Contracts: OpenAPI/schema validation, generated Go/TS/Rust type sync, golden
  fixture decode/encode, token/ticket fixture validation, stable error-code
  coverage, and contract hash generation.
- Release: runtime artifact presence, checksums, signatures, third-party notices,
  platform matrix coverage, version matrix consistency, and host-consumable
  compatibility manifest validation.

Do not ship a public contract change without tests that prove old/new failure
modes fail closed and produce stable diagnostic errors.

## Repository Rule File

- `AGENTS.md` is the canonical repository rule file for this repository.
- Do not add or keep a committed repository-level `.develop.md` here.
