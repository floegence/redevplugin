import assert from "node:assert/strict";
import { test } from "node:test";
import {
  defaultPluginSurfaceReloadMax,
  defaultPluginSurfaceReloadWindowMs,
  pluginBridgeErrorCodes,
  pluginClientErrorCodes,
  pluginPlatformErrorCodes,
  PluginBridgeError,
  PluginPlatformClient,
  PluginSurfaceReloadLimiter,
  redevPluginContractArtifacts,
  toPluginSurfaceHostBootstrap,
  type FetchInitLike,
  type FetchResponseLike,
} from "../src/trusted-parent.js";
import { PluginLocalImportClient } from "../src/local-import.js";

type FetchCall = {
  input: string;
  init: FetchInitLike;
};

class FakeFetch {
  readonly calls: FetchCall[] = [];
  #responses: unknown[] = [];

  push(response: unknown): void {
    this.#responses.push(response);
  }

  fetch = async (input: string, init: FetchInitLike): Promise<FetchResponseLike> => {
    this.calls.push({ input, init });
    const body = this.#responses.shift();
    return {
      ok: true,
      status: 200,
      json: async () => body,
    };
  };
}

test("stable error-code exports separate platform, bridge, and client-only codes", () => {
  assert.equal(pluginPlatformErrorCodes.includes("PLUGIN_JSON_LIMIT_EXCEEDED"), true);
  assert.equal(pluginBridgeErrorCodes.includes("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED"), true);
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

test("platform client revokes the authenticated surface scope without caller-supplied identity", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { revoked_surface_count: 3 } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const result = await client.revokeSurfaceScope();

  assert.deepEqual(result, { revoked_surface_count: 3 });
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/surfaces/revoke-scope");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {});
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
      schema_version: "redevplugin.compatibility.v4",
      matrix: {
        redevplugin_go_version: "0.0.0-dev",
        redevplugin_ui_version: "0.0.0-dev",
        redevplugin_runtime_version: "0.0.0-dev",
        plugin_ui_protocol_version: "plugin-ui-v4",
        plugin_host_protocol_version: "plugin-host-v2",
        rust_ipc_version: "rust-ipc-v2",
        wasm_abi_version: "redevplugin-wasm-worker-v2",
        manifest_schema_version: "manifest-v4",
        package_signature_schema_version: "package-signature-v1",
        release_metadata_schema_version: "release-metadata-v4",
        source_policy_schema_version: "source-policy-v1",
        source_revocations_schema_version: "source-revocations-v1",
        token_ticket_schema_version: "token-ticket-v2",
        bridge_schema_version: "bridge-v4",
        opaque_surface_document_schema_version: "opaque-surface-document-v2",
        opaque_surface_transport_schema_version: "opaque-surface-transport-v3",
        target_classifier_version: "target-classifier-v1",
        network_grant_schema_version: "network-grant-v1",
        plugin_platform_openapi_version: "plugin-platform-v4",
        compatibility_schema_version: "compatibility-manifest-v4",
        release_manifest_schema_version: "release-manifest-v3",
        worker_invocation_schema_version: "worker-invocation-v2",
        host_capability_contract_schema_version: "host-capability-contract-v1",
        host_capability_pin_schema_version: "host-capability-pin-v1",
        host_capability_manifest_schema_version: "host-capability-manifest-v1",
        host_capability_compatibility_schema_version: "host-capability-compatibility-v1",
        host_capability_signature_schema_version: "host-capability-signature-v1",
        host_capability_notices_schema_version: "host-capability-notices-v1",
        error_codes_schema_version: "error-codes-v2",
        contract_registry_version: "contract-registry-v1",
      },
      contracts: [
        {
          id: "plugin-platform-openapi",
          path: "spec/openapi/plugin-platform-v4.yaml",
          version: "plugin-platform-v4",
          sha256: "sha256-openapi",
        },
        {
          id: "rust-ipc-schema",
          path: "spec/plugin/ipc-v2.schema.json",
          version: "rust-ipc-v2",
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

  assert.equal(compatibility.schema_version, "redevplugin.compatibility.v4");
  assert.equal(compatibility.matrix.plugin_platform_openapi_version, "plugin-platform-v4");
  assert.equal(compatibility.matrix.release_metadata_schema_version, "release-metadata-v4");
  assert.equal(compatibility.matrix.source_policy_schema_version, "source-policy-v1");
  assert.equal(compatibility.matrix.source_revocations_schema_version, "source-revocations-v1");
  assert.equal(compatibility.matrix.host_capability_contract_schema_version, "host-capability-contract-v1");
  assert.equal(compatibility.matrix.host_capability_pin_schema_version, "host-capability-pin-v1");
  assert.equal(compatibility.matrix.host_capability_manifest_schema_version, "host-capability-manifest-v1");
  assert.equal(compatibility.matrix.host_capability_compatibility_schema_version, "host-capability-compatibility-v1");
  assert.equal(compatibility.matrix.host_capability_signature_schema_version, "host-capability-signature-v1");
  assert.equal(compatibility.matrix.host_capability_notices_schema_version, "host-capability-notices-v1");
  assert.deepEqual(compatibility.contracts.map((contract) => contract.id), ["plugin-platform-openapi", "rust-ipc-schema"]);
  assert.equal(compatibility.contracts[0]?.sha256, "sha256-openapi");
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/platform/compatibility");
  assert.equal(fetch.calls[0]?.init.method, "GET");
  assert.equal(fetch.calls[0]?.init.body, undefined);
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], undefined);
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], undefined);
});

test("platform client reads and patches plugin settings through host API", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      schema_version: 1,
      fields: [{ key: "default_engine", type: "select", label: "Default engine", scope: "user", options: ["docker", "podman"] }],
      settings_revision: 7,
    },
  });
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      schema_version: 1,
      settings_revision: 8,
      values: { default_engine: "podman" },
      updated_at: "2026-06-30T00:00:00Z",
    },
  });
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
  });

  const schema = await client.getSettingsSchema("plugin instance/1");
  const patched = await client.patchSettings("plugin instance/1", { default_engine: "podman" });

  assert.equal(schema.fields[0]?.key, "default_engine");
  assert.equal(patched.values.default_engine, "podman");
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings/schema");
  assert.equal(fetch.calls[0]?.init.method, "GET");
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], undefined);
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], undefined);
  assert.equal(fetch.calls[1]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings");
  assert.equal(fetch.calls[1]?.init.method, "PATCH");
  assert.equal(fetch.calls[1]?.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { values: { default_engine: "podman" } });
});

test("platform client manages plugin lifecycle and surface opening routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.1.0", active_fingerprint: "sha256:b", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "enabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled", disabled_reason: "admin" } });
  fetch.push({
    ok: true,
    data: {
      plugin_id: "com.example.plugin",
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      active_fingerprint: "sha256:a",
      plugin_version: "1.0.0",
      entry_path: "ui/index.html",
      entry_sha256: "sha256:b",
      asset_session_nonce: "asset_session_nonce_1",
      plugin_state_version: 1,
      revoke_epoch: 1,
      runtime_generation_id: "runtime_gen_1",
      asset_ticket: "asset_ticket_1",
      asset_ticket_id: "asset_ticket_id_1",
      bridge_nonce: "bridge_nonce_1",
      issued_at: "2026-06-30T00:00:00Z",
      expires_at: "2026-06-30T00:05:00Z",
    },
  });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled", retained_data_state: "deleted" } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const localImportClient = new PluginLocalImportClient({ fetch: fetch.fetch });

  assert.equal("importLocalPackage" in client, false);
  assert.equal("updateLocalPackage" in client, false);

  const installed = await localImportClient.importLocalPackage({ package_base64: "cGtn", plugin_instance_id: "plugin_instance_1", plugin_state_version: 0 });
  const updated = await localImportClient.updateLocalPackage({ plugin_instance_id: "plugin_instance_1", package_base64: "cGtnMg", plugin_state_version: 1 });
  const downgraded = await client.downgradePlugin({ plugin_instance_id: "plugin_instance_1", version: "1.0.0", plugin_state_version: 2 });
  const enabled = await client.enablePlugin({ plugin_instance_id: "plugin_instance_1", plugin_state_version: 3 });
  const disabled = await client.disablePlugin({ plugin_instance_id: "plugin_instance_1", plugin_state_version: 4, reason: "admin" });
  const surface = await client.openSurface({
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    plugin_state_version: 5,
  });
  const uninstalled = await client.uninstallPlugin({ plugin_instance_id: "plugin_instance_1", plugin_state_version: 5, delete_data: true });

  assert.equal(installed.enable_state, "disabled");
  assert.equal(updated.version, "1.1.0");
  assert.equal(downgraded.version, "1.0.0");
  assert.equal(enabled.enable_state, "enabled");
  assert.equal(disabled.disabled_reason, "admin");
  assert.equal(surface.asset_ticket, "asset_ticket_1");
  assert.equal(toPluginSurfaceHostBootstrap(surface).runtimeGenerationId, "runtime_gen_1");
  assert.equal(uninstalled.retained_data_state, "deleted");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/local-import/install");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { package_base64: "cGtn", plugin_instance_id: "plugin_instance_1", plugin_state_version: 0 });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/local-import/update");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", package_base64: "cGtnMg", plugin_state_version: 1 });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/downgrade");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", version: "1.0.0", plugin_state_version: 2 });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/enable");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", plugin_state_version: 3 });
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/disable");
  assert.deepEqual(JSON.parse(fetch.calls[4]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", plugin_state_version: 4, reason: "admin" });
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/surfaces/open");
  assert.deepEqual(JSON.parse(fetch.calls[5]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    plugin_state_version: 5,
  });
  assert.equal(fetch.calls[6]?.input, "/_redevplugin/api/plugins/uninstall");
  assert.deepEqual(JSON.parse(fetch.calls[6]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", plugin_state_version: 5, delete_data: true });
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

  await client.installReleaseRef({ release_ref: releaseRef, plugin_state_version: 0 });
  await client.updateReleaseRef({ plugin_instance_id: "plugin_instance_1", release_ref: { ...releaseRef, version: "1.1.0" }, plugin_state_version: 1 });

  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/install-release-ref");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { release_ref: releaseRef, plugin_state_version: 0 });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/update-release-ref");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", release_ref: { ...releaseRef, version: "1.1.0" }, plugin_state_version: 1 });
});

test("platform client manages runtime lifecycle routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { runtime_instance_id: "runtime_1", runtime_generation_id: "gen_1", runtime_version: "0.0.0-dev", rust_ipc_version: "rust-ipc-v2", wasm_abi_version: "redevplugin-wasm-worker-v2", ready: true } });
  fetch.push({ ok: true, data: { runtime_instance_id: "runtime_1", runtime_generation_id: "gen_1", ready: true } });
  fetch.push({ ok: true, data: { refreshed_plugins: [{ plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "enabled" }] } });
  fetch.push({ ok: true, data: { stopped: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const started = await client.startRuntime({ target: { os: "darwin", arch: "arm64" } });
  const health = await client.runtimeHealth();
  const refreshed = await client.refreshEnabledRuntimeState();
  const stopped = await client.stopRuntime();

  assert.equal(started.ready, true);
  assert.equal(health.runtime_generation_id, "gen_1");
  assert.equal(refreshed.refreshed_plugins[0]?.plugin_instance_id, "plugin_instance_1");
  assert.equal(stopped.stopped, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/runtime/start");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { target: { os: "darwin", arch: "arm64" } });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/runtime/health");
  assert.equal(fetch.calls[1]?.init.method, "GET");
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
  fetch.push({ ok: true, data: { archive_ref: "archive/plugin_instance_1.zip", settings_archive_ref: "archive/plugin_instance_1.settings.json" } });
  fetch.push({ ok: true, data: { imported: true } });
  fetch.push({ ok: true, data: { retained_data: [{ retained_id: "retained_1", source_plugin_instance_id: "plugin_instance_1", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "retained" }] } });
  fetch.push({ ok: true, data: { retained_id: "retained_1", source_plugin_instance_id: "plugin_instance_1", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "deleted" } });
  fetch.push({ ok: true, data: { retained_id: "retained_3", source_plugin_instance_id: "plugin_instance_1", bound_plugin_instance_id: "plugin_instance_2", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "bound" } });
  fetch.push({ ok: true, data: { deleted: [{ retained_id: "retained_2", source_plugin_instance_id: "plugin_instance_1", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "deleted" }], failed: [] } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const operations = await client.listOperations("plugin_instance_1");
  const canceled = await client.cancelOperation("op 1", "user canceled");
  const exported = await client.exportData({ plugin_instance_id: "plugin_instance_1" });
  const imported = await client.importData({
    plugin_instance_id: "plugin_instance_1",
    archive_ref: exported.archive_ref,
    settings_archive_ref: exported.settings_archive_ref,
    delete_existing: true,
  });
  const retained = await client.listRetainedData({ source_plugin_instance_id: "plugin_instance_1", state: "retained" });
  const deleted = await client.deleteRetainedData("retained_1");
  const bound = await client.bindRetainedData({ retained_id: "retained_3", target_plugin_instance_id: "plugin_instance_2" });
  const cleanup = await client.cleanupExpiredRetainedData({ retry_failed: true, max_records: 10 });

  assert.equal(operations.operations?.[0]?.status, "running");
  assert.equal(operations.operations?.[0]?.audit_correlation_id, "audit_1");
  assert.equal(operations.operations?.[0]?.cancel_ack_timeout_ms, 5000);
  assert.equal(canceled.status, "cancel_requested");
  assert.equal(exported.archive_ref, "archive/plugin_instance_1.zip");
  assert.equal(exported.settings_archive_ref, "archive/plugin_instance_1.settings.json");
  assert.equal(imported.imported, true);
  assert.equal(retained.retained_data?.[0]?.retained_id, "retained_1");
  assert.equal(deleted.state, "deleted");
  assert.equal(bound.bound_plugin_instance_id, "plugin_instance_2");
  assert.equal(cleanup.deleted?.[0]?.retained_id, "retained_2");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/operations?plugin_instance_id=plugin_instance_1");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/operations/op%201/cancel");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { reason: "user canceled" });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/data/export");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/data/import");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    archive_ref: "archive/plugin_instance_1.zip",
    settings_archive_ref: "archive/plugin_instance_1.settings.json",
    delete_existing: true,
  });
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/retained-data?source_plugin_instance_id=plugin_instance_1&state=retained");
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/retained-data/delete");
  assert.deepEqual(JSON.parse(fetch.calls[5]?.init.body ?? ""), { retained_id: "retained_1" });
  assert.equal(fetch.calls[6]?.input, "/_redevplugin/api/plugins/retained-data/bind");
  assert.deepEqual(JSON.parse(fetch.calls[6]?.init.body ?? ""), { retained_id: "retained_3", target_plugin_instance_id: "plugin_instance_2" });
  assert.equal(fetch.calls[7]?.input, "/_redevplugin/api/plugins/retained-data/cleanup-expired");
  assert.deepEqual(JSON.parse(fetch.calls[7]?.init.body ?? ""), { retry_failed: true, max_records: 10 });
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
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/intents?intent_id=example.echo&plugin_instance_id=plugin_instance_1");
  assert.equal(fetch.calls[0]?.init.method, "GET");
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
  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "plugin method confirmation required" });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.invokeIntent({ plugin_instance_id: "plugin_instance_1", intent_id: "example.danger", params: { target: "db" } }),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_CONFIRMATION_REQUIRED" && err.message === "plugin method confirmation required",
  );
});

test("platform client exposes retained cleanup partial result on failure", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error_code: "PLUGIN_RETAINED_DATA_CLEANUP_FAILED",
    error: "retained data cleanup failed",
    data: {
      deleted: [{ retained_id: "retained_deleted", source_plugin_instance_id: "plugin_instance_1", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "deleted" }],
      failed: [{ retained_id: "retained_failed", source_plugin_instance_id: "plugin_instance_2", publisher_id: "example", plugin_id: "com.example.plugin", version: "1.0.0", package_hash: "sha256:p", manifest_hash: "sha256:m", state: "delete_failed_retryable" }],
    },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.cleanupExpiredRetainedData({ retry_failed: true }),
    (err) => err instanceof PluginBridgeError &&
      err.errorCode === "PLUGIN_RETAINED_DATA_CLEANUP_FAILED" &&
      (err.data as { failed?: Array<{ retained_id?: string }> }).failed?.[0]?.retained_id === "retained_failed",
  );
});

test("platform client exposes host error details separately from data", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error_code: "PLUGIN_JSON_LIMIT_EXCEEDED",
    error: "JSON payload exceeds the maximum allowed depth",
    error_details: { reason: "json_depth" },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.enablePlugin({ plugin_instance_id: "plugin_instance_1", plugin_state_version: 1 }),
    (err) => err instanceof PluginBridgeError &&
      err.errorCode === "PLUGIN_JSON_LIMIT_EXCEEDED" &&
      err.data === undefined &&
      (err.details as { reason?: string }).reason === "json_depth",
  );
});

test("platform client manages permissions and secret refs without exposing local contracts", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { permissions: [{ plugin_instance_id: "plugin_instance_1", permission_id: "network.http" }] } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", granted_by: "admin" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", revoked_by: "admin" } });
  fetch.push({ ok: true, data: { bound: true } });
  fetch.push({ ok: true, data: { passed: true } });
  fetch.push({ ok: true, data: { deleted: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const grants = await client.listPermissions("plugin_instance_1", true);
  const grant = await client.grantPermission({ plugin_instance_id: "plugin_instance_1", permission_id: "network.http", granted_by: "admin" });
  const revoke = await client.revokePermission({ plugin_instance_id: "plugin_instance_1", permission_id: "network.http", revoked_by: "admin", reason: "rotation" });
  const bound = await client.bindSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const tested = await client.testSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const deleted = await client.deleteSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });

  assert.equal(grants.permissions?.[0]?.permission_id, "network.http");
  assert.equal(grant.granted_by, "admin");
  assert.equal(revoke.revoked_by, "admin");
  assert.equal(bound.bound, true);
  assert.equal(tested.passed, true);
  assert.equal(deleted.deleted, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/permissions?plugin_instance_id=plugin_instance_1&active_only=true");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/permissions/grant");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/permissions/revoke");
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/secrets/bind");
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/secrets/test");
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/secrets/delete");
});

test("platform client reads host audit and diagnostic events", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      audit_events: [{
        type: "plugin.intent.invoked",
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        occurred_at: "2026-06-30T00:00:00Z",
        details: { intent_id: "example.echo" },
      }],
    },
  });
  fetch.push({
    ok: true,
    data: {
      diagnostic_events: [{
        type: "plugin.csp.violation",
        severity: "warning",
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        surface_instance_id: "surface_1",
        occurred_at: "2026-06-30T00:00:01Z",
        details: { effective_directive: "script-src" },
      }],
    },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const audit = await client.listAuditEvents({ plugin_instance_id: "plugin_instance_1", type: "plugin.intent.invoked", limit: 5 });
  const diagnostics = await client.listDiagnosticEvents({ plugin_id: "com.example.intent", severity: "warning", limit: 10 });

  assert.equal(audit.audit_events?.[0]?.details?.intent_id, "example.echo");
  assert.equal(diagnostics.diagnostic_events?.[0]?.details?.effective_directive, "script-src");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/audit?plugin_instance_id=plugin_instance_1&type=plugin.intent.invoked&limit=5");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/diagnostics?plugin_id=com.example.intent&severity=warning&limit=10");
});

test("platform client maps management envelope errors", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error_code: "PLUGIN_INVALID_REQUEST", error: "plugin settings are not declared" });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.getSettings("plugin_instance_missing"),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_INVALID_REQUEST" && err.message === "plugin settings are not declared",
  );
});
