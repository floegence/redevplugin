import assert from "node:assert/strict";
import { test } from "node:test";

import { Fragment, jsx, jsxDEV, jsxs } from "../src/jsx-runtime.js";
import { validatePluginUITree } from "../src/ui-reconciler.js";

test("restricted JSX creates deterministic keyed plugin VNodes", () => {
  const tree = jsxs("main", {
    className: "plugin-surface",
    children: [
      jsx("h1", { children: "Hello" }, "title"),
      jsxs("p", { children: ["Count: ", 3, false, null] }, "count"),
    ],
  }, "root");

  assert.deepEqual(tree, {
    type: "element",
    key: "root",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      {
        type: "element",
        key: "title",
        tag: "h1",
        children: [{ type: "text", key: "title.text.0", text: "Hello" }],
      },
      {
        type: "element",
        key: "count",
        tag: "p",
        children: [
          { type: "text", key: "count.text.0", text: "Count: " },
          { type: "text", key: "count.text.1", text: "3" },
        ],
      },
    ],
  });
  assert.equal(validatePluginUITree(tree), tree);
});

test("restricted JSX rejects unsupported execution and markup paths", () => {
  assert.throws(() => jsx("main", {}, undefined), /stable key/);
  assert.throws(() => jsx(Fragment, { children: [] }, "fragment"), /Fragment/);
  assert.throws(() => jsx("button", { onclick: () => undefined }, "button"), /attribute onclick/);
  assert.throws(() => jsx("div", { dangerouslySetInnerHTML: { __html: "unsafe" } }, "html"), /attribute dangerouslySetInnerHTML/);
  assert.throws(() => jsxDEV(() => null, {}, "component"), /intrinsic elements/);
});

test("automatic JSX typing produces a plugin element tree", () => {
  const label = "Send";
  const tree = (
    <main key="typed-root" className="surface">
      <button key="typed-button" type="button" data-redevplugin-action="send">
        {label}
      </button>
    </main>
  );
  assert.equal(tree.key, "typed-root");
  assert.equal(tree.children?.[0]?.key, "typed-button");
});

function typecheckMissingStableKey(): void {
  // @ts-expect-error every JSX element requires an explicit stable key
  const missingKey = <div />;
  void missingKey;
}
void typecheckMissingStableKey;
