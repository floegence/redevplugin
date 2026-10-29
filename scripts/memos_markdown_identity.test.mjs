import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { build } from "esbuild";
import { chromium } from "playwright";

let browser, source;
before(async () => {
  const result = await build({ entryPoints: ["examples/plugin-ui/memos-markdown.ts"], bundle: true, format: "iife", globalName: "markdown", platform: "browser", write: false });
  source = result.outputFiles[0].text;
  browser = await chromium.launch({ headless: true });
});
after(async () => { await browser?.close(); });

async function documentTest(run) {
  const page = await browser.newPage();
  try { await page.addScriptTag({ content: source }); return await page.evaluate(run); }
  finally { await page.close(); }
}

test("markdown edits retain actual DOM nodes and unchanged text selection", async () => {
  const result = await documentTest(() => {
    const identity = markdown.createMarkdownIdentity("memo-42-markdown");
    const before = markdown.renderMarkdown("# Release notes\n\nShip **version 4** safely.\n\n- [ ] verify package", identity, { taskMemoId: "memo-42", interactiveTasks: true });
    document.body.replaceChildren(...before.nodes);
    const all = [...document.querySelectorAll("[data-markdown-key]")];
    const text = document.querySelector("h1,h2,h3,h4,h5,h6").firstChild;
    const range = document.createRange(); range.setStart(text, 1); range.setEnd(text, 7);
    getSelection().addRange(range);
    const after = markdown.renderMarkdown("# Release notes\n\nShip **version 5** safely.\n\n- [x] verify artifact", identity, { taskMemoId: "memo-42", interactiveTasks: true });
    return { roots: before.nodes.every((node, i) => node === after.nodes[i]), children: all.every(node => node === document.querySelector('[data-markdown-key="' + node.dataset.markdownKey + '"]')), selection: getSelection().toString(), anchor: getSelection().anchorNode === text, checked: document.querySelector("input").checked, text: document.body.textContent };
  });
  assert.equal(result.roots, true); assert.equal(result.children, true);
  assert.equal(result.selection, "elease"); assert.equal(result.anchor, true);
  assert.equal(result.checked, true); assert.match(result.text, /version 5/u);
});

test("markdown keeps authored HTML as text and exposes native task controls", async () => {
  const result = await documentTest(() => {
    const result = markdown.renderMarkdown("<SCRIPT>alert(1)</SCRIPT>\n\n- [x] reviewed\n\n| Name | State |\n| --- | --- |\n| package | ready |", markdown.createMarkdownIdentity("memo-safe"), { taskMemoId: "memo-safe", interactiveTasks: true });
    document.body.replaceChildren(...result.nodes);
    return { scripts: document.body.querySelectorAll("script").length, table: !!document.querySelector("table"), task: document.querySelector("input")?.dataset.memoTask, text: document.body.textContent };
  });
  assert.equal(result.scripts, 0); assert.equal(result.table, true);
  assert.equal(result.task, "true"); assert.match(result.text, /<SCRIPT>alert\(1\)<\/SCRIPT>/u);
});

test("task edits target source markers without changing fenced examples", async () => {
  const result = await documentTest(() => {
    const fence = String.fromCharCode(96).repeat(3);
    const source = "- [ ] first\n" + fence + "\n- [ ] example\n" + fence + "\n- [ ] second";
    return markdown.toggleTaskMarker(source, 1, true);
  });
  assert.match(result, /- \[ \] first/u); assert.match(result, /- \[ \] example/u); assert.match(result, /- \[x\] second/u);
});
