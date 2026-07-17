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
    { type: "remove_child", parent_key: "root", child_index: 2, child_key: "remove" },
    { type: "insert_child", parent_key: "root", child_index: 2, node: element("insert", "p", ["insert"]) },
    { type: "move_child", parent_key: "root", child_key: "editor", from_index: 1, to_index: 0 },
    { type: "patch_control", target_key: "editor", edit_revision: 7, value: "after" },
    { type: "patch_attributes", target_key: "title", set: { class: "new", title: "Notebook" }, remove: [] },
    { type: "set_text", parent_key: "title", child_index: 0, text: "Notes" },
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

test("UI tree validation applies the opaque renderer tag and attribute policy", () => {
  assert.throws(
    () => validatePluginUITree({ type: "element", key: "root", tag: "a", children: [] } as never),
    /tag is not allowed/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [], { onclick: "run" })),
    /attribute onclick is not allowed/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [element("search", "input", [], { type: "file" })])),
    /attribute type is not allowed/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [], { title: "x".repeat(4097) })),
    /attribute title is not allowed/,
  );
  validatePluginUITree(element("root", "main", [
    element("search", "input", [], { type: "search", "aria-label": "Search", "data-redevplugin-action": "search" }),
  ]));
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

test("1000-node single-field reconciliation emits one bounded operation", () => {
  const rows = Array.from({ length: 999 }, (_, index) => element(`row-${index}`, "p", [`Row ${index}`], { class: "row" }));
  const current = element("root", "main", rows);
  const nextRows = [...rows];
  nextRows[500] = element("row-500", "p", ["Updated"], { class: "row" });
  const next = element("root", "main", nextRows);
  assert.deepEqual(reconcilePluginUITrees(current, next), [
    { type: "set_text", parent_key: "row-500", child_index: 0, text: "Updated" },
  ]);
});

test("4096-node reverse cannot raise the closed operation bound", () => {
  const rows = Array.from({ length: 4095 }, (_, index) => element(`row-${index}`, "p"));
  const current = element("root", "main", rows);
  const next = element("root", "main", [...rows].reverse());
  assert.throws(
    () => reconcilePluginUITrees(current, next),
    /operation limit/,
  );
  assert.throws(
    () => reconcilePluginUITrees(current, next, { maxOperations: 4094 }),
    /integer between 1 and 1024/,
  );
});

test("custom operation limits can only tighten the closed bound", () => {
  const current = element("root", "main", [element("a"), element("b")]);
  const next = element("root", "main", [element("b"), element("a")]);
  assert.equal(reconcilePluginUITrees(current, next, { maxOperations: 1 }).length, 1);
  for (const maxOperations of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1025]) {
    assert.throws(
      () => reconcilePluginUITrees(current, next, { maxOperations }),
      /integer between 1 and 1024/,
    );
  }
});

test("1024-node reverse remains a closed bounded patch", () => {
  const rows = Array.from({ length: 1023 }, (_, index) => element(`row-${index}`, "p"));
  const operations = reconcilePluginUITrees(element("root", "main", rows), element("root", "main", [...rows].reverse()));
  assert.equal(operations.length, 1022);
  assert.equal(operations.every((operation) => operation.type === "move_child"), true);
});

test("large keyed lists still allow one bounded head insertion", () => {
  const rows = Array.from({ length: 4094 }, (_, index) => element(`row-${index}`, "p"));
  assert.deepEqual(
    reconcilePluginUITrees(
      element("root", "main", rows),
      element("root", "main", [element("new", "p"), ...rows]),
    ),
    [{ type: "insert_child", parent_key: "root", child_index: 0, node: element("new", "p") }],
  );
});

test("keyed left rotation emits the single minimum move", () => {
  const rows = ["a", "b", "c", "d"].map((key) => element(key, "p"));
  assert.deepEqual(
    reconcilePluginUITrees(
      element("root", "main", rows),
      element("root", "main", [...rows.slice(1), rows[0]]),
    ),
    [{ type: "move_child", parent_key: "root", child_key: "a", from_index: 0, to_index: 3 }],
  );
});

test("4096-node keyed left rotation remains one deterministic operation", () => {
  const rows = Array.from({ length: 4095 }, (_, index) => element(`row-${index}`, "p"));
  const current = element("root", "main", rows);
  const next = element("root", "main", [...rows.slice(1), rows[0]]);
  const first = reconcilePluginUITrees(current, next);
  const second = reconcilePluginUITrees(current, next);
  assert.deepEqual(first, [
    { type: "move_child", parent_key: "root", child_key: "row-0", from_index: 0, to_index: 4094 },
  ]);
  assert.deepEqual(second, first);
});

test("4096-node keyed head removal emits no meaningless moves", () => {
  const rows = Array.from({ length: 4095 }, (_, index) => element(`row-${index}`, "p"));
  assert.deepEqual(
    reconcilePluginUITrees(
      element("root", "main", rows),
      element("root", "main", rows.slice(1)),
    ),
    [{ type: "remove_child", parent_key: "root", child_index: 0, child_key: "row-0" }],
  );
});
