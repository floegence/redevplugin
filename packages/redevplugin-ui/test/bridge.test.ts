import assert from "node:assert/strict";
import { test } from "node:test";
import {
  defaultPluginSurfaceReloadMax,
  defaultPluginSurfaceReloadWindowMs,
  pluginBridgeErrorCodes,
  pluginClientErrorCodes,
  pluginPlatformErrorCodes,
  PluginPlatformClient,
  PluginPlatformRequestError,
  PluginSurfaceReloadLimiter,
  redevPluginContractArtifacts,
  type FetchInitLike,
  type FetchLike,
  type FetchResponseLike,
  type PluginRuntimeHealth,
} from "../src/trusted-parent.js";
import { PluginMutationLifecycleError, PluginTransportError } from "../src/errors.js";
import { PluginLocalImportClient } from "../src/local-import.js";
import { createPluginSurfaceScope, registerPluginSurface } from "../src/surface-scope.js";

type FetchCall = {
  input: string;
  init: Omit<FetchInitLike, "body"> & { body?: any };
};

class FakeFetch {
  readonly calls: FetchCall[] = [];
  #responses: Array<{ body: unknown; status: number }> = [];

  push(response: unknown, status?: number): void {
    const inferredStatus = typeof response === "object" && response !== null && "ok" in response && response.ok === false ? 400 : 200;
    this.#responses.push({ body: response, status: status ?? inferredStatus });
  }

  fetch = async (input: string, init: FetchInitLike): Promise<FetchResponseLike> => {
    this.calls.push({ input, init });
    const response = this.#responses.shift() ?? { body: undefined, status: 500 };
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      json: async () => response.body,
    };
  };
}

function sessionScopeRevokeResult(state: "fenced" | "draining" | "incomplete" | "complete" = "complete") {
  return {
    state,
    fenced: true as const,
    complete: state === "complete",
    counts: {
      surfaces: 3,
      asset_tickets: 1,
      asset_sessions: 1,
      plugin_gateway_tokens: 1,
      confirmation_tokens: 0,
      stream_tickets: 0,
      handle_grants: 0,
      confirmations: 0,
      operations: 0,
      streams: 0,
      runtime_executions: 0,
      active_network_requests: 0,
      sockets: 0,
      network_streams: 0,
      storage_hostcalls: 0,
    },
  };
}

test("stable error-code exports separate platform, bridge, and client-only codes", () => {
  assert.equal(pluginPlatformErrorCodes.includes("PLUGIN_JSON_LIMIT_EXCEEDED"), true);
  assert.equal(pluginPlatformErrorCodes.includes("PLUGIN_AUTHORIZATION_REVISION_MISMATCH"), true);
  assert.equal(pluginBridgeErrorCodes.includes("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED"), true);
  assert.equal(pluginBridgeErrorCodes.includes("PLUGIN_BRIDGE_CANCELLED"), true);
  assert.equal(pluginClientErrorCodes.includes("PLUGIN_PLATFORM_REQUEST_FAILED"), true);
  assert.equal((pluginPlatformErrorCodes as readonly string[]).includes("PLUGIN_PLATFORM_REQUEST_FAILED"), false);
  assert.equal((pluginBridgeErrorCodes as readonly string[]).includes("PLUGIN_STREAM_FAILED"), false);
});

test("generated contract registry exports immutable artifact hashes", () => {
  assert.equal(redevPluginContractArtifacts.length > 0, true);
  assert.equal(new Set(redevPluginContractArtifacts.map((artifact) => artifact.id)).size, redevPluginContractArtifacts.length);
  assert.equal(new Set(redevPluginContractArtifacts.map((artifact) => artifact.path)).size, redevPluginContractArtifacts.length);
  for (const artifact of redevPluginContractArtifacts) {
    assert.equal(/^[a-z][a-z0-9-]+$/.test(artifact.id), true);
    assert.equal(/^(spec\/openapi|spec\/plugin)\/[A-Za-z0-9._/-]+$/.test(artifact.path), true);
    assert.equal(artifact.version.length > 0, true);
    assert.equal(/^[a-f0-9]{64}$/.test(artifact.sha256), true);
  }
});

test("platform client revokes the authenticated session scope without caller-supplied identity", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: sessionScopeRevokeResult() });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const result = await client.revokeSessionScope();

  assert.equal(result.state, "complete");
  assert.equal(result.counts.surfaces, 3);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/session/revoke-scope");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {});
  assert.equal("revokeSurfaceScope" in client, false);
});

test("successful envelope cannot report an incomplete session revoke", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: sessionScopeRevokeResult("incomplete") });
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(() => client.revokeSessionScope(), (error: unknown) => error instanceof PluginTransportError);
  assert.equal(invalidated, 1);
  assert.equal(unknown, 1);
});

test("committed session teardown failure invalidates locally without reporting unknown outcome", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_SESSION_TEARDOWN_INCOMPLETE",
      message: "plugin session teardown is incomplete",
      details: { session_scope: sessionScopeRevokeResult("incomplete") },
      mutation_outcome: "committed",
    },
  }, 503);
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(() => client.revokeSessionScope(), (error: unknown) => {
    assert.equal(error instanceof PluginPlatformRequestError, true);
    assert.equal((error as PluginPlatformRequestError).mutationOutcome, "committed");
    return true;
  });
  assert.equal(invalidated, 1);
  assert.equal(unknown, 0);
  assert.equal(fetch.calls.length, 1);
});

test("committed session teardown failure requires exact incomplete scope details", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_SESSION_TEARDOWN_INCOMPLETE",
      message: "plugin session teardown is incomplete",
      details: {},
      mutation_outcome: "committed",
    },
  }, 503);
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(() => client.revokeSessionScope(), (error: unknown) =>
    error instanceof PluginTransportError && error.mutationOutcome === "unknown"
  );
  assert.equal(invalidated, 1);
  assert.equal(unknown, 1);
});

test("not-committed session revoke preserves local surfaces without unknown notification", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_ADAPTER_FAILURE",
      message: "session close was rejected before commit",
      details: {},
      mutation_outcome: "not_committed",
    },
  }, 503);
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(() => client.revokeSessionScope(), (error: unknown) =>
    error instanceof PluginPlatformRequestError && error.mutationOutcome === "not_committed"
  );
  assert.equal(invalidated, 0);
  assert.equal(unknown, 0);
  unregister();
});

test("post-dispatch session revoke abort invalidates locally and reports unknown once", async () => {
  const controller = new AbortController();
  let calls = 0;
  const fetch: FetchLike = (_input, init) => new Promise((_resolve, reject) => {
    calls += 1;
    init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
  });
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });
  const revocation = client.revokeSessionScope({ signal: controller.signal });
  assert.equal(calls, 1);
  controller.abort("session closed while request was in flight");

  await assert.rejects(revocation, (error: unknown) =>
    error instanceof PluginTransportError && error.mutationOutcome === "unknown"
  );
  assert.equal(invalidated, 1);
  assert.equal(unknown, 1);
});

test("pre-aborted session revoke remains not committed and preserves local surfaces", async () => {
  const fetch = new FakeFetch();
  const controller = new AbortController();
  controller.abort("session close cancelled before dispatch");
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(client.revokeSessionScope({ signal: controller.signal }), (error: unknown) =>
    error instanceof PluginTransportError && error.mutationOutcome === "not_committed"
  );
  assert.equal(fetch.calls.length, 0);
  assert.equal(invalidated, 0);
  assert.equal(unknown, 0);
  unregister();
});

test("invalid session revoke result is unknown and invalidates local surfaces", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { ...sessionScopeRevokeResult(), unexpected: true } });
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(client.revokeSessionScope(), (error: unknown) =>
    error instanceof PluginTransportError && error.mutationOutcome === "unknown"
  );
  assert.equal(invalidated, 1);
  assert.equal(unknown, 1);
});

test("session revoke result validation is exact and JavaScript-safe", async () => {
	const withoutStreams = sessionScopeRevokeResult() as Record<string, any>;
	const incompleteCounts = { ...withoutStreams.counts };
	delete incompleteCounts.streams;
  const invalidResults = [
    { ...sessionScopeRevokeResult(), state: "active", complete: false },
    { ...sessionScopeRevokeResult(), complete: false },
    { ...sessionScopeRevokeResult(), counts: incompleteCounts },
    { ...sessionScopeRevokeResult(), counts: { ...sessionScopeRevokeResult().counts, streams: -1 } },
    { ...sessionScopeRevokeResult(), counts: { ...sessionScopeRevokeResult().counts, streams: Number.MAX_SAFE_INTEGER + 1 } },
  ];

  for (const data of invalidResults) {
    const fetch = new FakeFetch();
    fetch.push({ ok: true, data });
    let invalidated = 0;
    let unknown = 0;
    const scope = createPluginSurfaceScope();
    registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
    const client = new PluginPlatformClient({
      fetch: fetch.fetch,
      surfaceScope: scope,
      onMutationOutcomeUnknown: () => { unknown += 1; },
    });

    await assert.rejects(client.revokeSessionScope(), (error: unknown) =>
      error instanceof PluginTransportError && error.mutationOutcome === "unknown"
    );
    assert.equal(invalidated, 1);
    assert.equal(unknown, 1);
  }
});

test("invalid session revoke envelope is unknown and invalidates local surfaces", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: sessionScopeRevokeResult(), unexpected: true });
  let invalidated = 0;
  let unknown = 0;
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated += 1; });
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknown += 1; },
  });

  await assert.rejects(client.revokeSessionScope(), (error: unknown) =>
    error instanceof PluginTransportError && error.mutationOutcome === "unknown"
  );
  assert.equal(invalidated, 1);
  assert.equal(unknown, 1);
});

test("concurrent session revokes invalidate each local surface exactly once", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: sessionScopeRevokeResult() });
  fetch.push({ ok: true, data: sessionScopeRevokeResult() });
  const invalidated: string[] = [];
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => undefined, () => { invalidated.push("one"); });
  registerPluginSurface(scope, "plugin_instance_2", () => undefined, () => { invalidated.push("two"); });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await Promise.all([client.revokeSessionScope(), client.revokeSessionScope()]);

  assert.deepEqual(invalidated.sort(), ["one", "two"]);
  assert.equal(fetch.calls.length, 2);
});

test("surface reload limiter caps consecutive automatic reloads", () => {
  let now = 1_000;
  const limiter = new PluginSurfaceReloadLimiter({ now: () => now });

  assert.equal(defaultPluginSurfaceReloadMax, 2);
  assert.equal(defaultPluginSurfaceReloadWindowMs, 30_000);
  assert.deepEqual(limiter.recordCrash(), {
    allowed: true,
    attempt: 1,
    remaining: 1,
    windowStartedAtMs: 1_000,
  });
  now += 1_000;
  assert.deepEqual(limiter.recordCrash(), {
    allowed: true,
    attempt: 2,
    remaining: 0,
    windowStartedAtMs: 1_000,
  });
  assert.deepEqual(limiter.state, {
    reloads: 2,
    remaining: 0,
    windowStartedAtMs: 1_000,
    nextRetryAtMs: 31_000,
  });
  now += 1_000;
  assert.deepEqual(limiter.recordCrash(), {
    allowed: false,
    attempt: 3,
    remaining: 0,
    windowStartedAtMs: 1_000,
    nextRetryAtMs: 31_000,
    reason: "reload_limit_exceeded",
  });
});

test("surface reload limiter resets on healthy load or a new window", () => {
  const limiter = new PluginSurfaceReloadLimiter({ maxReloads: 1, windowMs: 100 });

  assert.deepEqual(limiter.recordCrash(10), {
    allowed: true,
    attempt: 1,
    remaining: 0,
    windowStartedAtMs: 10,
  });
  assert.equal(limiter.recordCrash(99).allowed, false);
  assert.deepEqual(limiter.recordCrash(110), {
    allowed: true,
    attempt: 1,
    remaining: 0,
    windowStartedAtMs: 110,
  });

  limiter.recordHealthyLoad();
  assert.deepEqual(limiter.state, {
    reloads: 0,
    remaining: 1,
    windowStartedAtMs: undefined,
    nextRetryAtMs: undefined,
  });
  assert.deepEqual(limiter.recordCrash(120), {
    allowed: true,
    attempt: 1,
    remaining: 0,
    windowStartedAtMs: 120,
  });

  limiter.reset();
  assert.equal(limiter.state.reloads, 0);
});

test("surface reload limiter supports fail-closed zero cap", () => {
  const limiter = new PluginSurfaceReloadLimiter({ maxReloads: 0, windowMs: 500 });

  assert.deepEqual(limiter.recordCrash(50), {
    allowed: false,
    attempt: 1,
    remaining: 0,
    windowStartedAtMs: 50,
    nextRetryAtMs: 550,
    reason: "reload_limit_exceeded",
  });
  assert.deepEqual(limiter.state, {
    reloads: 0,
    remaining: 0,
    windowStartedAtMs: 50,
    nextRetryAtMs: 550,
  });
});

test("surface reload limiter rejects invalid timing options", () => {
  assert.throws(() => new PluginSurfaceReloadLimiter({ maxReloads: -1 }), /maxReloads/);
  assert.throws(() => new PluginSurfaceReloadLimiter({ maxReloads: 1.5 }), /maxReloads/);
  assert.throws(() => new PluginSurfaceReloadLimiter({ windowMs: 0 }), /windowMs/);
  assert.throws(() => new PluginSurfaceReloadLimiter({ windowMs: Number.POSITIVE_INFINITY }), /windowMs/);
  const limiter = new PluginSurfaceReloadLimiter();
  assert.throws(() => limiter.recordCrash(Number.NaN), /nowMs/);
});

test("platform client reads compatibility manifest through host API", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      schema_version: "redevplugin.compatibility.v7",
      matrix: {
        redevplugin_go_version: "0.0.0-dev",
        redevplugin_ui_version: "0.0.0-dev",
        redevplugin_runtime_version: "0.0.0-dev",
        plugin_ui_protocol_version: "plugin-ui-v5",
        plugin_host_protocol_version: "plugin-host-v5",
        rust_ipc_version: "rust-ipc-v5",
        wasm_abi_version: "redevplugin-wasm-worker-v2",
        manifest_schema_version: "manifest-v5",
        package_signature_schema_version: "package-signature-v1",
        release_metadata_schema_version: "release-metadata-v5",
        source_policy_schema_version: "source-policy-v1",
        source_revocations_schema_version: "source-revocations-v1",
        token_ticket_schema_version: "token-ticket-v4",
        bridge_schema_version: "bridge-v5",
        opaque_surface_document_schema_version: "opaque-surface-document-v3",
        opaque_surface_transport_schema_version: "opaque-surface-transport-v4",
        target_classifier_version: "target-classifier-v2",
        network_grant_schema_version: "network-grant-v2",
        resource_scope_schema_version: "resource-scope-v1",
        plugin_platform_openapi_version: "plugin-platform-v7",
        compatibility_schema_version: "compatibility-manifest-v7",
        release_manifest_schema_version: "release-manifest-v4",
        worker_invocation_schema_version: "worker-invocation-v3",
        host_capability_contract_schema_version: "host-capability-contract-v1",
        host_capability_pin_schema_version: "host-capability-pin-v1",
        host_capability_manifest_schema_version: "host-capability-manifest-v1",
        host_capability_compatibility_schema_version: "host-capability-compatibility-v1",
        host_capability_signature_schema_version: "host-capability-signature-v1",
        host_capability_notices_schema_version: "host-capability-notices-v1",
        error_codes_schema_version: "error-codes-v5",
        performance_evidence_schema_version: "performance-evidence-v2",
        contract_registry_version: "contract-registry-v1",
      },
      contracts: [
        {
          id: "plugin-platform-openapi",
          path: "spec/openapi/plugin-platform-v7.yaml",
          version: "plugin-platform-v7",
          sha256: "sha256-openapi",
        },
        {
          id: "rust-ipc-schema",
          path: "spec/plugin/ipc-v5.schema.json",
          version: "rust-ipc-v5",
          sha256: "sha256-ipc",
        },
      ],
    },
  });
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
  });

  const compatibility = await client.getCompatibility();

  assert.equal(compatibility.schema_version, "redevplugin.compatibility.v7");
  assert.equal(compatibility.matrix.plugin_platform_openapi_version, "plugin-platform-v7");
  assert.equal(compatibility.matrix.release_metadata_schema_version, "release-metadata-v5");
  assert.equal(compatibility.matrix.source_policy_schema_version, "source-policy-v1");
  assert.equal(compatibility.matrix.source_revocations_schema_version, "source-revocations-v1");
  assert.equal(compatibility.matrix.resource_scope_schema_version, "resource-scope-v1");
  assert.equal(compatibility.matrix.host_capability_contract_schema_version, "host-capability-contract-v1");
  assert.equal(compatibility.matrix.host_capability_pin_schema_version, "host-capability-pin-v1");
  assert.equal(compatibility.matrix.host_capability_manifest_schema_version, "host-capability-manifest-v1");
  assert.equal(compatibility.matrix.host_capability_compatibility_schema_version, "host-capability-compatibility-v1");
  assert.equal(compatibility.matrix.host_capability_signature_schema_version, "host-capability-signature-v1");
  assert.equal(compatibility.matrix.host_capability_notices_schema_version, "host-capability-notices-v1");
  assert.deepEqual(compatibility.contracts.map((contract) => contract.id), ["plugin-platform-openapi", "rust-ipc-schema"]);
  assert.equal(compatibility.contracts[0]?.sha256, "sha256-openapi");
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/platform/compatibility/query");
  assert.equal(fetch.calls[0]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {});
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], undefined);
});

test("platform client forwards per-call abort signals without changing absolute API bases", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugins: [] } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "enabled" } });
  const controller = new AbortController();
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/plugin-api/",
    fetch: fetch.fetch,
  });

  await client.catalog({ signal: controller.signal });
  await client.enablePlugin({ plugin_instance_id: "plugin_instance_1", expected_management_revision: 3 }, { signal: controller.signal });

  assert.equal(fetch.calls[0]?.input, "https://host.example/plugin-api/_redevplugin/api/plugins/catalog/query");
  assert.equal(fetch.calls[1]?.input, "https://host.example/plugin-api/_redevplugin/api/plugins/enable");
  assert.equal(fetch.calls[0]?.init.signal, controller.signal);
  assert.equal(fetch.calls[1]?.init.signal, controller.signal);
});

test("platform client sends reads through closed POST query bodies", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugins: [] } });
  fetch.push({ ok: true, data: ["release"] });
  fetch.push({ ok: true, data: { operations: [] } });
  fetch.push({ ok: true, data: { operation_id: "operation_1" } });
  fetch.push({ ok: true, data: {
    plugin_instance_id: "plugin_instance_1",
    scope: "user",
    schema_version: 1,
    values_revision: 1,
    values: {},
    secret_metadata: [],
  } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const controller = new AbortController();

  await client.catalog();
  await client.features({ signal: controller.signal });
  await client.listOperations({ plugin_instance_id: "plugin_instance_1", limit: 25 });
  await client.getOperation("operation/1", { signal: controller.signal });
  await client.getSettings("plugin instance/1", "user");

  assert.deepEqual(fetch.calls.map((call) => ({
    input: call.input,
    method: call.init.method,
    contentType: call.init.headers["Content-Type"],
    body: JSON.parse(call.init.body ?? "null"),
  })), [
    {
      input: "/_redevplugin/api/plugins/catalog/query",
      method: "POST",
      contentType: "application/json",
      body: {},
    },
    {
      input: "/_redevplugin/api/plugins/features/query",
      method: "POST",
      contentType: "application/json",
      body: {},
    },
    {
      input: "/_redevplugin/api/plugins/operations/query",
      method: "POST",
      contentType: "application/json",
      body: { plugin_instance_id: "plugin_instance_1", limit: 25 },
    },
    {
      input: "/_redevplugin/api/plugins/operations/operation%2F1/query",
      method: "POST",
      contentType: "application/json",
      body: {},
    },
    {
      input: "/_redevplugin/api/plugins/plugin%20instance%2F1/settings/query",
      method: "POST",
      contentType: "application/json",
      body: { scope: "user" },
    },
  ]);
  assert.equal(fetch.calls[1]?.init.signal, controller.signal);
  assert.equal(fetch.calls[3]?.init.signal, controller.signal);
});

test("pre-aborted platform queries do not dispatch or report mutation outcome", async () => {
  const calls: FetchCall[] = [];
  const fetch: FetchLike = async (input, init) => {
    calls.push({ input, init });
    throw init.signal?.reason ?? new Error("aborted");
  };
  const controller = new AbortController();
  controller.abort("cancel query");
  const client = new PluginPlatformClient({ fetch });

  await assert.rejects(
    client.catalog({ signal: controller.signal }),
    (error) => error instanceof PluginTransportError && error.mutationOutcome === undefined,
  );
  assert.equal(calls.length, 0);
});

test("in-flight platform query abort remains safe and preserves surface scope", async () => {
  const calls: FetchCall[] = [];
  const fetch: FetchLike = (input, init) => new Promise((_resolve, reject) => {
    calls.push({ input, init });
    init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
  });
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  let unknownOutcomes = 0;
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  const client = new PluginPlatformClient({
    fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { unknownOutcomes += 1; },
  });
  const controller = new AbortController();
  const pending = client.catalog({ signal: controller.signal });
  controller.abort("cancel in-flight query");

  await assert.rejects(
    pending,
    (error) => error instanceof PluginTransportError && error.mutationOutcome === undefined,
  );
  assert.equal(calls.length, 1);
  assert.equal(disposed, 0);
  assert.equal(unknownOutcomes, 0);
  unregister();
});

test("platform client reads and patches plugin settings through host API", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      scope: "user",
      schema_version: 1,
      fields: [{ key: "default_engine", type: "select", label: "Default engine", scope: "user", options: ["docker", "podman"] }],
      values_revision: 7,
    },
  });
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      scope: "environment",
      schema_version: 1,
      values_revision: 4,
      values: { default_engine: "docker" },
      secret_metadata: [],
    },
  });
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      scope: "user",
      schema_version: 1,
      values_revision: 8,
      values: { default_engine: "podman" },
      secret_metadata: [{ key: "registry_token", secret_ref: "registry_token", scope: "user", bound: true, updated_at: "2026-06-30T00:00:00Z" }],
    },
  });
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
  });

  const schema = await client.getSettingsSchema("plugin instance/1", "user");
  const snapshot = await client.getSettings("plugin instance/1", "environment");
  const patched = await client.patchSettings("plugin instance/1", {
    scope: "user",
    expected_values_revision: 7,
    set: { default_engine: "podman" },
    remove: ["unused_setting"],
  });

  assert.equal(schema.fields[0]?.key, "default_engine");
  assert.equal(snapshot.scope, "environment");
  assert.equal(patched.values.default_engine, "podman");
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings/schema/query");
  assert.equal(fetch.calls[0]?.init.method, "POST");
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { scope: "user" });
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], undefined);
  assert.equal(fetch.calls[1]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings/query");
  assert.equal(fetch.calls[1]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { scope: "environment" });
  assert.equal(fetch.calls[2]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings");
  assert.equal(fetch.calls[2]?.init.method, "PATCH");
  assert.equal(fetch.calls[2]?.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {
    scope: "user",
    expected_values_revision: 7,
    set: { default_engine: "podman" },
    remove: ["unused_setting"],
  });
});

test("platform client manages plugin lifecycle routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.1.0", active_fingerprint: "sha256:b", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "enabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled", disabled_reason: "admin" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const localImportClient = new PluginLocalImportClient({ fetch: fetch.fetch });
  const uploadController = new AbortController();

  assert.equal("importLocalPackage" in client, false);
  assert.equal("updateLocalPackage" in client, false);

	const installed = await localImportClient.importLocalPackage("plugin_instance_1", new Blob(["pkg"]), {
		signal: uploadController.signal,
  });
  const updated = await localImportClient.updateLocalPackage("plugin_instance_1", 1, new Blob(["pkg2"]));
  const downgraded = await client.downgradePlugin({ plugin_instance_id: "plugin_instance_1", version: "1.0.0", expected_management_revision: 2 });
  const enabled = await client.enablePlugin({ plugin_instance_id: "plugin_instance_1", expected_management_revision: 3 });
  const disabled = await client.disablePlugin({ plugin_instance_id: "plugin_instance_1", expected_management_revision: 4, reason: "admin" });
  const uninstalled = await client.uninstallPlugin({ plugin_instance_id: "plugin_instance_1", expected_management_revision: 5, delete_data: true });

  assert.equal(installed.enable_state, "disabled");
  assert.equal(updated.version, "1.1.0");
  assert.equal(downgraded.version, "1.0.0");
  assert.equal(enabled.enable_state, "enabled");
  assert.equal(disabled.disabled_reason, "admin");
  assert.equal(uninstalled.enable_state, "disabled");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/plugin_instance_1/local-import");
  assert.equal(fetch.calls[0]?.init.body instanceof Blob, true);
  assert.equal(fetch.calls[0]?.init.signal, uploadController.signal);
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], "application/vnd.redevplugin.package+zip");
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Expected-Management-Revision"], undefined);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/plugin_instance_1/local-import");
  assert.equal(fetch.calls[1]?.init.body instanceof Blob, true);
  assert.equal(fetch.calls[1]?.init.headers["X-ReDevPlugin-Expected-Management-Revision"], "1");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/downgrade");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", version: "1.0.0", expected_management_revision: 2 });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/enable");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", expected_management_revision: 3 });
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/disable");
  assert.deepEqual(JSON.parse(fetch.calls[4]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", expected_management_revision: 4, reason: "admin" });
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/uninstall");
  assert.deepEqual(JSON.parse(fetch.calls[5]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", expected_management_revision: 5, delete_data: true });
});

test("local import update canonicalizes identity for transport and teardown", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.1.0", active_fingerprint: "sha256:b", trust_state: "verified", enable_state: "disabled" } });
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  const client = new PluginLocalImportClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.updateLocalPackage("  plugin_instance_1  ", 7, new Blob(["pkg"]));

  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/plugin_instance_1/local-import");
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Expected-Management-Revision"], "7");
  assert.equal(disposed, 1);
  await assert.rejects(
    client.updateLocalPackage("   ", 7, new Blob(["pkg"])),
    (error: unknown) => error instanceof TypeError && error.message === "pluginInstanceId is required",
  );
  await assert.rejects(
    client.updateLocalPackage("plugin_instance_1", 0, new Blob(["pkg"])),
    (error: unknown) => error instanceof TypeError && error.message === "expectedManagementRevision must be a positive safe integer",
  );
  await assert.rejects(
    client.updateLocalPackage("plugin_instance_1", Number.MAX_SAFE_INTEGER + 1, new Blob(["pkg"])),
    (error: unknown) => error instanceof TypeError && error.message === "expectedManagementRevision must be a positive safe integer",
  );
  assert.equal(fetch.calls.length, 1);

  const unknownScope = createPluginSurfaceScope();
  let unknownDisposed = 0;
  let unknownPluginInstanceId: string | undefined;
  registerPluginSurface(unknownScope, "plugin_instance_1", () => { unknownDisposed += 1; }, () => undefined);
  const failingClient = new PluginLocalImportClient({
    fetch: async () => { throw new Error("private network failure"); },
    surfaceScope: unknownScope,
    onMutationOutcomeUnknown: (pluginInstanceId) => { unknownPluginInstanceId = pluginInstanceId; },
  });

  await assert.rejects(
    failingClient.updateLocalPackage("  plugin_instance_1  ", 8, new Blob(["pkg"])),
    (error: unknown) => error instanceof PluginTransportError,
  );
  assert.equal(unknownDisposed, 1);
  assert.equal(unknownPluginInstanceId, "plugin_instance_1");
});

test("pre-aborted platform mutations remain not committed without surface teardown", async () => {
  const fetch = new FakeFetch();
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  const unknown: Array<string | undefined> = [];
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: (pluginInstanceId) => unknown.push(pluginInstanceId),
  });
  const controller = new AbortController();
  controller.abort("cancelled before dispatch");

  await assert.rejects(
    client.disablePlugin({
      plugin_instance_id: "plugin_instance_1",
      expected_management_revision: 7,
    }, { signal: controller.signal }),
    (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "not_committed",
  );

  assert.equal(fetch.calls.length, 0);
  assert.equal(disposed, 0);
  assert.deepEqual(unknown, []);
  unregister();
});

test("synchronous mutation fetch failures remain not committed", async () => {
  let fetchCalls = 0;
  const fetch = (() => {
    fetchCalls += 1;
    throw new Error("synchronous fetch rejection");
  }) as FetchLike;
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  let notified = false;
  const client = new PluginPlatformClient({
    fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { notified = true; },
  });

  await assert.rejects(
    client.disablePlugin({
      plugin_instance_id: "plugin_instance_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "not_committed",
  );

  assert.equal(fetchCalls, 1);
  assert.equal(disposed, 0);
  assert.equal(notified, false);
  unregister();
});

test("mutation serialization failures remain not committed", async () => {
  const fetch = new FakeFetch();
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  let notified = false;
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { notified = true; },
  });
  const request: Record<string, unknown> = {
    plugin_instance_id: "plugin_instance_1",
    expected_management_revision: 7,
  };
  request.circular = request;

  await assert.rejects(
    client.disablePlugin(request as Parameters<PluginPlatformClient["disablePlugin"]>[0]),
    (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "not_committed",
  );

  assert.equal(fetch.calls.length, 0);
  assert.equal(disposed, 0);
  assert.equal(notified, false);
  unregister();
});

test("pre-aborted local updates remain not committed without surface teardown", async () => {
  const fetch = new FakeFetch();
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  const unregister = registerPluginSurface(scope, "plugin_instance_1", () => { disposed += 1; }, () => undefined);
  let notified = false;
  const client = new PluginLocalImportClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { notified = true; },
  });
  const controller = new AbortController();
  controller.abort("cancelled before upload");

  await assert.rejects(
    client.updateLocalPackage("plugin_instance_1", 7, new Blob(["pkg"]), { signal: controller.signal }),
    (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "not_committed",
  );

  assert.equal(fetch.calls.length, 0);
  assert.equal(disposed, 0);
  assert.equal(notified, false);
  unregister();
});

test("post-dispatch local abort preserves unknown outcome through cleanup failures", async () => {
  let fetchCalls = 0;
  const fetch: FetchLike = (_input, init) => {
    fetchCalls += 1;
    return new Promise<FetchResponseLike>((_resolve, reject) => {
      const signal = init.signal;
      if (!signal) throw new TypeError("test mutation requires an abort signal");
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  };
  const cleanupFailure = new Error("surface cleanup failed");
  const observerFailure = new Error("unknown outcome observer failed");
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  registerPluginSurface(scope, "plugin_instance_1", () => {
    disposed += 1;
    throw cleanupFailure;
  }, () => undefined);
  let observedPluginInstanceId: string | undefined;
  const client = new PluginLocalImportClient({
    fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: (pluginInstanceId) => {
      observedPluginInstanceId = pluginInstanceId;
      throw observerFailure;
    },
  });
  const controller = new AbortController();

  const update = client.updateLocalPackage("plugin_instance_1", 7, new Blob(["pkg"]), { signal: controller.signal });
  assert.equal(fetchCalls, 1);
  controller.abort("cancelled after dispatch");

  await assert.rejects(
    update,
    (error: unknown) => error instanceof PluginMutationLifecycleError &&
      error.mutationOutcome === "unknown" &&
      error.errors.length === 3 &&
      error.errors[0] instanceof PluginTransportError &&
      error.errors[0].mutationOutcome === "unknown" &&
      error.errors.includes(cleanupFailure) &&
      error.errors.includes(observerFailure),
  );
  assert.equal(disposed, 1);
  assert.equal(observedPluginInstanceId, "plugin_instance_1");
});

test("platform cleanup failures preserve the original unknown mutation outcome", async () => {
  const fetch: FetchLike = async () => {
    await Promise.resolve();
    throw new Error("connection closed after dispatch");
  };
  const cleanupFailure = new Error("surface cleanup failed");
  const observerFailure = new Error("unknown outcome observer failed");
  const scope = createPluginSurfaceScope();
  registerPluginSurface(scope, "plugin_instance_1", () => { throw cleanupFailure; }, () => undefined);
  const client = new PluginPlatformClient({
    fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: () => { throw observerFailure; },
  });

  await assert.rejects(
    client.disablePlugin({
      plugin_instance_id: "plugin_instance_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginMutationLifecycleError &&
      error.mutationOutcome === "unknown" &&
      error.errors.length === 3 &&
      error.errors[0] instanceof PluginTransportError &&
      error.errors[0].mutationOutcome === "unknown" &&
      error.errors.includes(cleanupFailure) &&
      error.errors.includes(observerFailure),
  );
});

test("platform client installs and updates plugin release refs without package bytes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.1.0", active_fingerprint: "sha256:b", trust_state: "verified", enable_state: "disabled" } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const releaseRef = {
    source_id: "official",
    release_metadata_ref: "plugins/com.example/com.example.plugin/1.0.0/release.json",
    release_metadata_sha256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    publisher_id: "com.example",
    plugin_id: "com.example.plugin",
    version: "1.0.0",
    expected_hashes: {
      package_sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      manifest_sha256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      entries_sha256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    },
  };

	await client.installReleaseRef({ plugin_instance_id: "plugin_instance_1", release_ref: releaseRef });
  await client.updateReleaseRef({ plugin_instance_id: "plugin_instance_1", release_ref: { ...releaseRef, version: "1.1.0" }, expected_management_revision: 1 });

  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/install-release-ref");
	assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", release_ref: releaseRef });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/update-release-ref");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", release_ref: { ...releaseRef, version: "1.1.0" }, expected_management_revision: 1 });
});

test("platform client manages runtime lifecycle routes", async () => {
  const fetch = new FakeFetch();
  const descriptor = {
    version: "0.5.0",
    target: { os: "darwin", arch: "arm64" },
    ipc_version: "rust-ipc-v5",
    wasm_abi_version: "redevplugin-wasm-worker-v2",
    artifact_sha256: "a".repeat(64),
  } as const;
  const runtimeHealth = {
    ready: true,
    descriptor,
    shards: [{
      runtime_shard_id: "runtime_shard_00",
      runtime_instance_id: "runtime_1",
      runtime_generation_id: "gen_1",
      descriptor,
      ready: true,
      active_invocations: 0,
      queued_invocations: 0,
      limits: { worker_count: 8, queue_capacity: 32, per_plugin_concurrency: 4, module_cache_entries: 64, module_cache_source_bytes: 134217728 },
      module_cache: { hits: 0, misses: 0, compiles: 0, entries: 0, source_bytes: 0 },
    }],
  } satisfies PluginRuntimeHealth;
  fetch.push({ ok: true, data: runtimeHealth });
  fetch.push({ ok: true, data: runtimeHealth });
  fetch.push({ ok: true, data: { results: [
    { plugin_instance_id: "plugin_instance_1", status: "refreshed" },
    { plugin_instance_id: "plugin_instance_2", status: "failed", error: { code: "PLUGIN_RUNTIME_UNAVAILABLE", message: "Plugin runtime state could not be refreshed" } },
  ] } });
  fetch.push({ ok: true, data: { stopped: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const started = await client.startRuntime({ target: { os: "darwin", arch: "arm64" } });
  const health = await client.runtimeHealth();
  const refreshed = await client.refreshEnabledRuntimeState();
  const stopped = await client.stopRuntime();

  assert.equal(started.ready, true);
  assert.equal(health.shards[0]?.runtime_generation_id, "gen_1");
  assert.equal(refreshed.results[0]?.plugin_instance_id, "plugin_instance_1");
  assert.equal(refreshed.results[0]?.status, "refreshed");
  const failedRefresh = refreshed.results[1];
  assert.equal(failedRefresh?.status, "failed");
  if (failedRefresh?.status !== "failed") throw new Error("expected failed runtime refresh result");
  assert.deepEqual(failedRefresh.error, { code: "PLUGIN_RUNTIME_UNAVAILABLE", message: "Plugin runtime state could not be refreshed" });
  assert.equal(stopped.stopped, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/runtime/start");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { target: { os: "darwin", arch: "arm64" } });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/runtime/health/query");
  assert.equal(fetch.calls[1]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {});
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/runtime/refresh-enabled");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {});
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/runtime/stop");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {});
});

test("platform client covers operation and data lifecycle routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      operations: [{
        invocation_id: "invoke_1",
        audit_correlation_id: "audit_1",
        operation_id: "op 1",
        plugin_instance_id: "plugin_instance_1",
        method: "worker.long",
        execution: "operation",
        status: "running",
        cancelable: true,
        cancel_ack_timeout_ms: 5000,
        created_at: "2026-06-30T00:00:00Z",
        updated_at: "2026-06-30T00:00:00Z",
      }],
      next_cursor: "cursor_2",
    },
  });
  fetch.push({
    ok: true,
    data: {
      invocation_id: "invoke_1",
      audit_correlation_id: "audit_1",
      operation_id: "op 1",
      plugin_instance_id: "plugin_instance_1",
      method: "worker.long",
      execution: "operation",
      status: "cancel_requested",
      cancelable: true,
      cancel_ack_timeout_ms: 5000,
      created_at: "2026-06-30T00:00:00Z",
      updated_at: "2026-06-30T00:00:02Z",
    },
  });
  fetch.push({ ok: true, data: { bundle_ref: "bundle_ref_1" } });
  fetch.push({ ok: true, data: { deleted: true } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { retained_data: [{ plugin_instance_id: "plugin_instance_1", generation_id: "generation_1", state: "retained", revision: 3, shape_hash: "a".repeat(64) }] } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", generation_id: "generation_1", state: "retained", revision: 3, shape_hash: "a".repeat(64) } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_2", generation_id: "generation_1", state: "active", revision: 1, shape_hash: "a".repeat(64) } });
  fetch.push({ ok: true, data: { deleted: [{ plugin_instance_id: "plugin_instance_3", generation_id: "generation_3", state: "retained", revision: 4, shape_hash: "b".repeat(64) }] } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const operations = await client.listOperations({ plugin_instance_id: "plugin_instance_1", cursor: "cursor_1", limit: 25 });
  const canceled = await client.cancelOperation("op 1", "user canceled");
  const exported = await client.exportData({ plugin_instance_id: "plugin_instance_1" });
  const exportDeletion = await client.deleteDataExport({ plugin_instance_id: "plugin_instance_1", bundle_ref: exported.bundle_ref });
  const imported = await client.importData({
    plugin_instance_id: "plugin_instance_1",
    bundle_ref: exported.bundle_ref,
    expected_management_revision: 7,
  });
  const retained = await client.listRetainedData({ plugin_instance_id: "plugin_instance_1" });
  const deleted = await client.deleteRetainedData({ plugin_instance_id: "plugin_instance_1", expected_binding_revision: 3 });
  const bound = await client.bindRetainedData({
    source_plugin_instance_id: "plugin_instance_1",
    expected_source_binding_revision: 3,
    target_plugin_instance_id: "plugin_instance_2",
    target_expected_management_revision: 5,
  });
  const cleanup = await client.cleanupExpiredRetainedData({});

  assert.equal(operations.operations?.[0]?.status, "running");
  assert.equal(operations.operations?.[0]?.audit_correlation_id, "audit_1");
  assert.equal(operations.operations?.[0]?.cancel_ack_timeout_ms, 5000);
  assert.equal(operations.next_cursor, "cursor_2");
  assert.equal(canceled.status, "cancel_requested");
  assert.equal(exported.bundle_ref, "bundle_ref_1");
  assert.equal(exportDeletion.deleted, true);
  assert.equal(imported.plugin_instance_id, "plugin_instance_1");
  assert.equal(retained.retained_data[0]?.generation_id, "generation_1");
  assert.equal(deleted.revision, 3);
  assert.equal(bound.plugin_instance_id, "plugin_instance_2");
  assert.equal(cleanup.deleted[0]?.generation_id, "generation_3");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/operations/query");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", cursor: "cursor_1", limit: 25 });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/operations/op%201/cancel");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { reason: "user canceled" });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/data/export");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/data/export/delete");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    bundle_ref: "bundle_ref_1",
  });
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/data/import");
  assert.deepEqual(JSON.parse(fetch.calls[4]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    bundle_ref: "bundle_ref_1",
    expected_management_revision: 7,
  });
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/retained-data/query");
  assert.deepEqual(JSON.parse(fetch.calls[5]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[6]?.input, "/_redevplugin/api/plugins/retained-data/delete");
  assert.deepEqual(JSON.parse(fetch.calls[6]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", expected_binding_revision: 3 });
  assert.equal(fetch.calls[7]?.input, "/_redevplugin/api/plugins/retained-data/bind");
  assert.deepEqual(JSON.parse(fetch.calls[7]?.init.body ?? ""), {
    source_plugin_instance_id: "plugin_instance_1",
    expected_source_binding_revision: 3,
    target_plugin_instance_id: "plugin_instance_2",
    target_expected_management_revision: 5,
  });
  assert.equal(fetch.calls[8]?.input, "/_redevplugin/api/plugins/retained-data/cleanup-expired");
  assert.deepEqual(JSON.parse(fetch.calls[8]?.init.body ?? ""), {});
});

test("platform client lists and invokes host-mediated intents", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      intents: [{
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        publisher_id: "example",
        display_name: "Intent plugin",
        version: "1.0.0",
        active_fingerprint: "sha256:intent",
        intent_id: "example.echo",
        method: "echo.ping",
        effect: "read",
        execution: "sync",
        payload_schema: { type: "object" },
      }],
    },
  });
  fetch.push({ ok: true, data: { data: { ok: true } } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const listed = await client.listIntents({ intent_id: "example.echo", plugin_instance_id: "plugin_instance_1" });
  const result = await client.invokeIntent<{ ok: boolean }>({
    plugin_instance_id: "plugin_instance_1",
    intent_id: "example.echo",
    params: { message: "hello" },
  });

  assert.equal(listed.intents?.[0]?.method, "echo.ping");
  assert.equal(result.data?.ok, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/intents/query");
  assert.equal(fetch.calls[0]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { intent_id: "example.echo", plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], undefined);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/intents/invoke");
  assert.equal(fetch.calls[1]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    intent_id: "example.echo",
    params: { message: "hello" },
  });
});

test("platform client maps dangerous intent confirmation requirement", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error: { code: "PLUGIN_CONFIRMATION_REQUIRED", message: "plugin method confirmation required", details: {}, mutation_outcome: "not_committed" } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.invokeIntent({ plugin_instance_id: "plugin_instance_1", intent_id: "example.danger", params: { target: "db" } }),
    (err) => err instanceof PluginPlatformRequestError && err.errorCode === "PLUGIN_CONFIRMATION_REQUIRED" && err.message === "plugin method confirmation required",
  );
});

test("platform client exposes closed plugin data revision conflicts", async () => {
  const binding = new FakeFetch();
  binding.push({
    ok: false,
    error: {
      code: "PLUGIN_BINDING_REVISION_MISMATCH",
      message: "plugin data binding revision changed",
      details: {
        plugin_instance_id: "plugin_instance_1",
        expected_binding_revision: 3,
        actual_binding_revision: 4,
      },
      mutation_outcome: "not_committed",
    },
  }, 409);

  await assert.rejects(
    new PluginPlatformClient({ fetch: binding.fetch }).deleteRetainedData({ plugin_instance_id: "plugin_instance_1", expected_binding_revision: 3 }),
    (err) => err instanceof PluginPlatformRequestError &&
      err.errorCode === "PLUGIN_BINDING_REVISION_MISMATCH" &&
      err.details.actual_binding_revision === 4,
  );

  const settings = new FakeFetch();
  settings.push({
    ok: false,
    error: {
      code: "PLUGIN_VALUES_REVISION_MISMATCH",
      message: "plugin settings values revision changed",
      details: {
        plugin_instance_id: "plugin_instance_1",
        expected_values_revision: 7,
        actual_values_revision: 8,
      },
      mutation_outcome: "not_committed",
    },
  }, 409);
  await assert.rejects(
    new PluginPlatformClient({ fetch: settings.fetch }).patchSettings("plugin_instance_1", { scope: "environment", expected_values_revision: 7, set: { engine: "podman" } }),
    (err) => err instanceof PluginPlatformRequestError &&
      err.errorCode === "PLUGIN_VALUES_REVISION_MISMATCH" &&
      err.details.actual_values_revision === 8,
  );
});

test("platform client exposes host error details separately from data", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_JSON_LIMIT_EXCEEDED",
      message: "JSON payload exceeds the maximum allowed depth",
      details: { reason: "json_depth" },
      mutation_outcome: "not_committed",
    },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.enablePlugin({ plugin_instance_id: "plugin_instance_1", expected_management_revision: 1 }),
    (err) => err instanceof PluginPlatformRequestError &&
      err.errorCode === "PLUGIN_JSON_LIMIT_EXCEEDED" &&
      (err.details as { reason?: string }).reason === "json_depth",
  );
});

test("platform client rejects unknown error codes and mismatched closed details", async () => {
  const unknownCode = new FakeFetch();
  unknownCode.push({ ok: false, error: { code: "PLUGIN_UNKNOWN", message: "unknown", details: {} } });
  await assert.rejects(
    new PluginPlatformClient({ fetch: unknownCode.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );

  const mismatchedDetails = new FakeFetch();
  mismatchedDetails.push({
    ok: false,
    error: {
      code: "PLUGIN_MANAGEMENT_REVISION_MISMATCH",
      message: "revision changed",
      details: {
        plugin_instance_id: "plugin_instance_1",
        expected_management_revision: 1,
        actual_management_revision: 2,
        unexpected: true,
      },
    },
  });
  await assert.rejects(
    new PluginPlatformClient({ fetch: mismatchedDetails.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );

  const genericWithTypedDetails = new FakeFetch();
  genericWithTypedDetails.push({
    ok: false,
    error: {
      code: "PLUGIN_RUNTIME_UNAVAILABLE",
      message: "runtime unavailable",
      details: { plugin_instance_id: "plugin_instance_1" },
    },
  });
  await assert.rejects(
    new PluginPlatformClient({ fetch: genericWithTypedDetails.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );

  const malformedRevisionDetails = new FakeFetch();
  malformedRevisionDetails.push({
    ok: false,
    error: {
      code: "PLUGIN_VALUES_REVISION_MISMATCH",
      message: "settings changed",
      details: {
        plugin_instance_id: "plugin_instance_1",
        expected_values_revision: 1,
      },
    },
  });
  await assert.rejects(
    new PluginPlatformClient({ fetch: malformedRevisionDetails.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );

  const successWithErrorStatus = new FakeFetch();
  successWithErrorStatus.push({ ok: true, data: { plugins: [] } }, 500);
  await assert.rejects(
    new PluginPlatformClient({ fetch: successWithErrorStatus.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );

  const errorWithSuccessStatus = new FakeFetch();
  errorWithSuccessStatus.push({ ok: false, error: { code: "PLUGIN_RUNTIME_UNAVAILABLE", message: "unavailable", details: {} } }, 200);
  await assert.rejects(
    new PluginPlatformClient({ fetch: errorWithSuccessStatus.fetch }).catalog(),
    (err) => err instanceof PluginTransportError,
  );
});

test("platform client manages permissions and secret refs without exposing local contracts", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { permissions: [{ plugin_instance_id: "plugin_instance_1", permission_id: "network.http", effect: "grant", granted_at: "2026-07-17T00:00:00Z" }] } });
  fetch.push({ ok: true, data: { permission: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", effect: "grant", granted_at: "2026-07-17T00:00:00Z" }, revisions: { policy_revision: 2, management_revision: 2, revoke_epoch: 0 } } });
  fetch.push({ ok: true, data: { permission: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", effect: "deny", granted_at: "2026-07-17T00:00:00Z" }, revisions: { policy_revision: 3, management_revision: 2, revoke_epoch: 1 } } });
  fetch.push({ ok: true, data: { bound: true } });
  fetch.push({ ok: true, data: { tested: true } });
  fetch.push({ ok: true, data: { deleted: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const grants = await client.listPermissions({ plugin_instance_id: "plugin_instance_1", active_only: true });
  const grant = await client.grantPermission({
    plugin_instance_id: "plugin_instance_1",
    permission_id: "network.http",
    expected_policy_revision: 1,
    expected_management_revision: 2,
    expected_revoke_epoch: 0,
  });
  const revoke = await client.revokePermission({
    plugin_instance_id: "plugin_instance_1",
    permission_id: "network.http",
    expected_policy_revision: 2,
    expected_management_revision: 2,
    expected_revoke_epoch: 1,
    reason: "rotation",
  });
  const bound = await client.bindSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const tested = await client.testSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const deleted = await client.deleteSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });

  assert.equal(grants.permissions[0]?.permission_id, "network.http");
  assert.equal(grant.permission.permission_id, "network.http");
  assert.equal(grant.revisions.policy_revision, 2);
  assert.equal(revoke.permission.effect, "deny");
  assert.equal(revoke.revisions.revoke_epoch, 1);
  assert.equal(bound.bound, true);
  assert.equal(tested.tested, true);
  assert.equal(deleted.deleted, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/permissions/query");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", active_only: true });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/permissions/grant");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    permission_id: "network.http",
    expected_policy_revision: 1,
    expected_management_revision: 2,
    expected_revoke_epoch: 0,
  });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/permissions/revoke");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    permission_id: "network.http",
    expected_policy_revision: 2,
    expected_management_revision: 2,
    expected_revoke_epoch: 1,
    reason: "rotation",
  });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/secrets/bind");
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/secrets/test");
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/secrets/delete");
});

test("platform client preserves the secret test mutation outcome", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_PERMISSION_DENIED",
      message: "secret operation failed",
      details: {},
      mutation_outcome: "unknown",
    },
  }, 403);
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.testSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" }),
    (err) => err instanceof PluginPlatformRequestError &&
      err.errorCode === "PLUGIN_PERMISSION_DENIED" &&
      err.mutationOutcome === "unknown",
  );
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/secrets/test");
  assert.equal(fetch.calls[0]?.init.method, "POST");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], "application/json");
});

test("platform client manages security policies through the current REST contract", async () => {
  const policy = {
    plugin_instance_id: "plugin_instance_1",
    allowed_permissions: ["network.http"],
    denied_methods: ["container.delete"],
    policy_revision: 3,
    management_revision: 5,
    revoke_epoch: 2,
    updated_at: "2026-07-17T00:00:00Z",
  };
  const updatedPolicy = { ...policy, policy_revision: 4, revoke_epoch: 3, updated_at: "2026-07-17T00:01:00Z" };
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { security_policies: [policy] } });
  fetch.push({ ok: true, data: policy });
  fetch.push({ ok: true, data: updatedPolicy });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", deleted: true, policy_revision: 5, management_revision: 5, revoke_epoch: 4 } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const putRequest = {
    expected_policy_revision: 3,
    expected_management_revision: 5,
    expected_revoke_epoch: 2,
    allowed_permissions: ["network.http"],
    denied_methods: ["container.delete"],
  };
  const deleteRequest = {
    expected_policy_revision: 4,
    expected_management_revision: 5,
    expected_revoke_epoch: 3,
  };

  const listed = await client.listSecurityPolicies();
  const read = await client.getSecurityPolicy("plugin_instance_1");
  const updated = await client.putSecurityPolicy("plugin_instance_1", putRequest);
  const deleted = await client.deleteSecurityPolicy("plugin_instance_1", deleteRequest);

  assert.equal(listed.security_policies[0]?.plugin_instance_id, "plugin_instance_1");
  assert.equal(read.denied_methods?.[0], "container.delete");
  assert.equal(updated.allowed_permissions?.[0], "network.http");
  assert.equal(updated.policy_revision, 4);
  assert.equal(deleted.deleted, true);
  assert.equal(deleted.revoke_epoch, 4);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/security-policies/query");
  assert.equal(fetch.calls[0]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {});
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/security-policies/plugin_instance_1/query");
  assert.equal(fetch.calls[1]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {});
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/security-policies/plugin_instance_1");
  assert.equal(fetch.calls[2]?.init.method, "PUT");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), putRequest);
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/security-policies/plugin_instance_1");
  assert.equal(fetch.calls[3]?.init.method, "DELETE");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), deleteRequest);
});

test("platform client exposes closed authorization revision conflict details", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_AUTHORIZATION_REVISION_MISMATCH",
      message: "authorization revisions changed",
      details: {
        plugin_instance_id: "plugin_instance_1",
        expected_policy_revision: 3,
        actual_policy_revision: 4,
        expected_management_revision: 5,
        actual_management_revision: 5,
        expected_revoke_epoch: 2,
        actual_revoke_epoch: 3,
      },
      mutation_outcome: "not_committed",
    },
  }, 409);
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.deleteSecurityPolicy("plugin_instance_1", {
      expected_policy_revision: 3,
      expected_management_revision: 5,
      expected_revoke_epoch: 2,
    }),
    (err) => err instanceof PluginPlatformRequestError &&
      err.errorCode === "PLUGIN_AUTHORIZATION_REVISION_MISMATCH" &&
      err.mutationOutcome === "not_committed" &&
      err.details.actual_policy_revision === 4 &&
      err.details.actual_revoke_epoch === 3,
  );
});

test("platform client reads owner-scoped diagnostic events", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      diagnostic_events: [{
        type: "plugin.http.operation_failed",
        severity: "warning",
        message: "plugin HTTP operation failed",
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        surface_instance_id: "surface_1",
        correlation_id: "correlation_1",
        mutation_outcome: "unknown",
        occurred_at: "2026-06-30T00:00:01Z",
        details: { operation: "runtime.start", code: "PLUGIN_RUNTIME_UNAVAILABLE" },
      }],
    },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const diagnostics = await client.listDiagnosticEvents({ plugin_id: "com.example.intent", severity: "warning", limit: 10 });

  assert.equal(diagnostics.diagnostic_events?.[0]?.correlation_id, "correlation_1");
  assert.equal(diagnostics.diagnostic_events?.[0]?.mutation_outcome, "unknown");
  assert.equal(diagnostics.diagnostic_events?.[0]?.details?.operation, "runtime.start");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/diagnostics/query");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { plugin_id: "com.example.intent", severity: "warning", limit: 10 });
});

test("platform client maps management envelope errors", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error: { code: "PLUGIN_INVALID_REQUEST", message: "plugin settings are not declared", details: {} } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.getSettings("plugin_instance_missing", "user"),
    (err) => err instanceof PluginPlatformRequestError && err.errorCode === "PLUGIN_INVALID_REQUEST" && err.message === "plugin settings are not declared",
  );
});
