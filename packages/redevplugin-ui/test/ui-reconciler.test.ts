import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PluginUIReconcileError,
  reconcilePluginUITrees,
  validatePluginUITree,
  type PluginUIElementVNode,
  type PluginUITextVNode,
} from "../src/ui-reconciler.js";

const text = (key: string, value: string): PluginUITextVNode => ({ type: "text", key, text: value });

const element = (
  key: string,
  tag: PluginUIElementVNode["tag"] = "div",
  children: PluginUIElementVNode["children"] = [],
  attributes?: PluginUIElementVNode["attributes"],
): PluginUIElementVNode => ({ type: "element", key, tag, ...(attributes ? { attributes } : {}), children });

test("keyed reconciliation emits only closed v5 anchor operations", () => {
  const current = element("root", "main", [
    element("title", "h1", [text("title-text", "Memos")], { class: "old" }),
    element("editor", "input", [], { value: "before" }),
    element("remove", "p", [text("remove-text", "remove")]),
  ]);
  const inserted = element("insert", "p", [text("insert-text", "insert")]);
  const next = element("root", "main", [
    element("editor", "input", [], { value: "after" }),
    element("title", "h1", [text("title-text", "Notes")], { class: "new", title: "Notebook" }),
    inserted,
  ]);

  assert.deepEqual(reconcilePluginUITrees(current, next, {
    controlEditRevisions: new Map([["editor", 7]]),
  }), [
    { type: "remove_child", target_key: "remove" },
    { type: "patch_control", target_key: "editor", edit_revision: 7, value: "after" },
    { type: "patch_attributes", target_key: "title", set: { class: "new", title: "Notebook" }, remove: [] },
    { type: "set_text", target_key: "title-text", text: "Notes" },
    { type: "insert_child", parent_key: "root", before_key: null, node: inserted },
    { type: "move_child", target_key: "editor", parent_key: "root", before_key: "title" },
  ]);
});

test("UI trees require explicit globally unique keys for elements and text", () => {
  assert.throws(
    () => validatePluginUITree({ type: "element", tag: "main", key: "", children: [] }),
    PluginUIReconcileError,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", ["raw text" as never])),
    /plain keyed/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [{ type: "text", text: "missing" } as never])),
    /plain keyed/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [text("same", "one"), element("same")])),
    /duplicated/,
  );
  assert.throws(
    () => validatePluginUITree(element("root", "main", [{ ...text("copy", "value"), extra: true } as never])),
    /plain keyed/,
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
  const current = element("root", "main", [element("location", "button", [text("location-text", "Berlin")], { value: "berlin" })]);
  const next = element("root", "main", [element("location", "button", [text("location-text", "Paris")], { value: "paris" })]);
  assert.deepEqual(reconcilePluginUITrees(current, next), [
    { type: "patch_attributes", target_key: "location", set: { value: "paris" }, remove: [] },
    { type: "set_text", target_key: "location-text", text: "Paris" },
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
  assert.throws(
    () => reconcilePluginUITrees(current, element("root", "main", [element("canvas", "div"), element("panel")]), { transferredCanvasKeys }),
    /Transferred canvas canvas cannot be replaced/,
  );
});

test("nodes can move across parents with one anchored operation", () => {
  const moving = element("moving", "p", [text("moving-text", "Move")]);
  const current = element("root", "main", [element("left", "section", [moving]), element("right", "section")]);
  const next = element("root", "main", [element("left", "section"), element("right", "section", [moving])]);
  assert.deepEqual(reconcilePluginUITrees(current, next), [
    { type: "move_child", target_key: "moving", parent_key: "right", before_key: null },
  ]);
});

test("1000-node single-field reconciliation emits one bounded operation", () => {
  const rows = Array.from({ length: 999 }, (_, index) => element(`row-${index}`, "p", [text(`row-${index}-text`, `Row ${index}`)], { class: "row" }));
  const current = element("root", "main", rows);
  const nextRows = [...rows];
  nextRows[500] = element("row-500", "p", [text("row-500-text", "Updated")], { class: "row" });
  const next = element("root", "main", nextRows);
  assert.deepEqual(reconcilePluginUITrees(current, next), [
    { type: "set_text", target_key: "row-500-text", text: "Updated" },
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

test("1000 keyed children reverse with exactly 999 LIS moves", () => {
  const rows = Array.from({ length: 1000 }, (_, index) => element(`row-${index}`, "p"));
  const operations = reconcilePluginUITrees(element("root", "main", rows), element("root", "main", [...rows].reverse()));
  assert.equal(operations.length, 999);
  assert.equal(operations.every((operation) => operation.type === "move_child"), true);
});

test("large keyed lists still allow one bounded head insertion", () => {
  const rows = Array.from({ length: 4094 }, (_, index) => element(`row-${index}`, "p"));
  assert.deepEqual(
    reconcilePluginUITrees(
      element("root", "main", rows),
      element("root", "main", [element("new", "p"), ...rows]),
    ),
    [{ type: "insert_child", parent_key: "root", before_key: "row-0", node: element("new", "p") }],
  );
});

test("keyed left rotation emits the single minimum move", () => {
  const rows = ["a", "b", "c", "d"].map((key) => element(key, "p"));
  assert.deepEqual(
    reconcilePluginUITrees(
      element("root", "main", rows),
      element("root", "main", [...rows.slice(1), rows[0]]),
    ),
    [{ type: "move_child", target_key: "a", parent_key: "root", before_key: null }],
  );
});

test("4096-node keyed left rotation remains one deterministic operation", () => {
  const rows = Array.from({ length: 4095 }, (_, index) => element(`row-${index}`, "p"));
  const current = element("root", "main", rows);
  const next = element("root", "main", [...rows.slice(1), rows[0]]);
  const first = reconcilePluginUITrees(current, next);
  const second = reconcilePluginUITrees(current, next);
  assert.deepEqual(first, [
    { type: "move_child", target_key: "row-0", parent_key: "root", before_key: null },
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
    [{ type: "remove_child", target_key: "row-0" }],
  );
});
