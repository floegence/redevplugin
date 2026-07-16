import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PluginUIReconcileError,
  reconcilePluginUITrees,
  validatePluginUITree,
  type PluginUIElementVNode,
} from "../src/ui-reconciler.js";

const element = (
  key: string,
  tag: PluginUIElementVNode["tag"] = "div",
  children: PluginUIElementVNode["children"] = [],
  attributes?: PluginUIElementVNode["attributes"],
): PluginUIElementVNode => ({ type: "element", key, tag, ...(attributes ? { attributes } : {}), children });

test("keyed reconciliation emits only closed incremental operations", () => {
  const current = element("root", "main", [
    element("title", "h1", ["Memos"], { class: "old" }),
    element("editor", "input", [], { value: "before" }),
    element("remove", "p", ["remove"]),
  ]);
  const next = element("root", "main", [
    element("editor", "input", [], { value: "after" }),
    element("title", "h1", ["Notes"], { class: "new", title: "Notebook" }),
    element("insert", "p", ["insert"]),
  ]);

  assert.deepEqual(reconcilePluginUITrees(current, next, {
    controlEditRevisions: new Map([["editor", 7]]),
  }), [
    { type: "move_child", parent_key: "root", child_key: "editor", from_index: 1, to_index: 0 },
    { type: "patch_control", target_key: "editor", edit_revision: 7, value: "after" },
    { type: "patch_attributes", target_key: "title", set: { class: "new", title: "Notebook" }, remove: [] },
    { type: "set_text", parent_key: "title", child_index: 0, text: "Notes" },
    { type: "insert_child", parent_key: "root", child_index: 2, node: element("insert", "p", ["insert"]) },
    { type: "remove_child", parent_key: "root", child_index: 3, child_key: "remove" },
  ]);
});

test("UI trees require one immutable root and globally unique explicit keys", () => {
  assert.throws(
    () => validatePluginUITree({ type: "element", tag: "main", key: "", children: [] }),
    PluginUIReconcileError,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [element("same"), element("same")])),
    /duplicated/,
  );
  assert.throws(
    () => reconcilePluginUITrees(element("root", "main"), element("other", "main")),
    /root key and tag are immutable/,
  );
  assert.throws(
    () => reconcilePluginUITrees(element("root", "main"), element("root", "section")),
    /root key and tag are immutable/,
  );
});

test("declarative button values do not use editable-control revisions", () => {
  const current = element("root", "main", [element("location", "button", ["Berlin"], { value: "berlin" })]);
  const next = element("root", "main", [element("location", "button", ["Paris"], { value: "paris" })]);
  assert.deepEqual(reconcilePluginUITrees(current, next), [
    { type: "patch_attributes", target_key: "location", set: { value: "paris" }, remove: [] },
    { type: "set_text", parent_key: "location", child_index: 0, text: "Paris" },
  ]);
});

test("transferred canvas identity cannot be removed, moved, or replaced", () => {
  const current = element("root", "main", [element("canvas", "canvas"), element("panel")]);
  const transferredCanvasKeys = new Set(["canvas"]);
  assert.throws(
    () => reconcilePluginUITrees(current, element("root", "main", [element("panel")]), { transferredCanvasKeys }),
    /Transferred canvas canvas cannot be removed/,
  );
  assert.throws(
    () => reconcilePluginUITrees(current, element("root", "main", [element("panel"), element("canvas", "canvas")]), { transferredCanvasKeys }),
    /Transferred canvas canvas cannot be moved/,
  );
});

test("1000-node single-field reconciliation stays within one frame at p95", () => {
  const rows = Array.from({ length: 999 }, (_, index) => element(`row-${index}`, "p", [`Row ${index}`], { class: "row" }));
  const current = element("root", "main", rows);
  const nextRows = [...rows];
  nextRows[500] = element("row-500", "p", ["Updated"], { class: "row" });
  const next = element("root", "main", nextRows);
  const timings: number[] = [];
  for (let iteration = 0; iteration < 30; iteration += 1) {
    const startedAt = performance.now();
    const operations = reconcilePluginUITrees(current, next);
    timings.push(performance.now() - startedAt);
    assert.deepEqual(operations, [{ type: "set_text", parent_key: "row-500", child_index: 0, text: "Updated" }]);
  }
  timings.sort((left, right) => left - right);
  const p95 = timings[Math.ceil(timings.length * 0.95) - 1] ?? Infinity;
  assert.equal(p95 < 16, true, `p95 ${p95.toFixed(2)}ms exceeded the 16ms frame budget`);
});
