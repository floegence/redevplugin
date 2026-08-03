import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

async function loadMarkdownModule() {
  const result = await build({
    entryPoints: ["examples/plugin-ui/memos-markdown.ts"],
    bundle: true,
    format: "esm",
    platform: "node",
    write: false,
  });
  const source = result.outputFiles[0].text;
  return import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
}

function vnodeKeys(nodes) {
  const keys = [];
  const visit = (node) => {
    keys.push(node.key);
    if (node.type === "element") node.children.forEach(visit);
  };
  nodes.forEach(visit);
  return keys;
}

function walk(nodes, visit) {
  for (const node of nodes) {
    visit(node);
    if (node.type === "element") walk(node.children, visit);
  }
}

test("markdown text edits preserve caller-owned VNode identity", async () => {
  const { createMarkdownIdentity, renderMarkdown } = await loadMarkdownModule();
  const identity = createMarkdownIdentity("memo-42-markdown");
  const before = renderMarkdown(
    "# Release notes\n\nShip **version 4** safely.\n\n- [ ] verify package",
    identity,
    { taskMemoId: "memo-42", interactiveTasks: true },
  );
  const after = renderMarkdown(
    "# Release notes\n\nShip **version 5** safely.\n\n- [x] verify artifact",
    identity,
    { taskMemoId: "memo-42", interactiveTasks: true },
  );

  assert.deepEqual(vnodeKeys(after.nodes), vnodeKeys(before.nodes));
});

test("restricted markdown tokenization keeps HTML as text", async () => {
  const { createMarkdownIdentity, renderMarkdown } = await loadMarkdownModule();
  const identity = createMarkdownIdentity("memo-safe-markdown");
  const result = renderMarkdown(
    "<SCRIPT>alert(1)</SCRIPT>\n\n- [x] reviewed\n\n| Name | State |\n| --- | --- |\n| package | ready |",
    identity,
    { taskMemoId: "memo-safe", interactiveTasks: true },
  );
  const tags = [];
  const text = [];
  walk(result.nodes, (node) => {
    if (node.type === "element") tags.push(node.tag);
    if (node.type === "text") text.push(node.text);
  });
  assert.equal(tags.includes("script"), false);
  assert.equal(tags.includes("table"), true);
  assert.equal(tags.includes("input"), true);
  assert.equal(text.some((value) => value.includes("<SCRIPT>alert(1)</SCRIPT>")), true);
});
