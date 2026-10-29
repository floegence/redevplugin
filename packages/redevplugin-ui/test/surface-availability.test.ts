import assert from "node:assert/strict";
import { test } from "node:test";
import { getPluginSurfaceActionState, type PluginCatalogRecord } from "../src/platform.js";

test("surface availability uses only the Host projection", () => {
  const record: Pick<PluginCatalogRecord, "action_state"> = {
    action_state: {
      can_open: true, can_enable: false, can_disable: true, can_uninstall: true,
      surfaces: [
        { surface_id: "local", can_open: true },
        { surface_id: "remote", can_open: false, blocked_reason: "permission_required" },
      ],
    },
  };
  assert.equal(getPluginSurfaceActionState(record, "local").can_open, true);
  assert.equal(getPluginSurfaceActionState(record, "remote").blocked_reason, "permission_required");
  assert.deepEqual(getPluginSurfaceActionState(record, "missing"), { surface_id: "missing", can_open: false, blocked_reason: "incompatible" });
});

test("packages without scoped surfaces retain aggregate authorization", () => {
  const record: Pick<PluginCatalogRecord, "action_state"> = {
    action_state: { can_open: false, can_enable: false, can_disable: true, can_uninstall: true, blocked_reason: "permission_required" },
  };
  assert.deepEqual(getPluginSurfaceActionState(record, "view"), { surface_id: "view", can_open: false, blocked_reason: "permission_required" });
});
