import { marked, type Token, type Tokens } from "marked";
import type { PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

export type MarkdownRenderResult = {
  nodes: PluginUIVNode[];
  truncated: boolean;
};

export type MarkdownIdentity = Readonly<{
  rootKey: string;
  keyForSlot(slot: string): string;
}>;

type RenderContext = {
  budget: number;
  blockLimit: number;
  blockCount: number;
  identity: MarkdownIdentity;
  taskMemoId: string;
  taskIndex: number;
  interactiveTasks: boolean;
  truncated: boolean;
};

const MARKDOWN_IDENTITY_ROOT = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const MAX_IDENTITY_ROOT_LENGTH = 112;
const MAX_IDENTITY_SLOTS = 4096;

function textNode(key: string, value: string): PluginUIVNode {
  return { type: "text", key, text: value };
}

export function renderMarkdown(
  content: string,
  identity: MarkdownIdentity,
  options: { expanded?: boolean; taskMemoId?: string; interactiveTasks?: boolean } = {},
): MarkdownRenderResult {
  const context: RenderContext = {
    budget: options.expanded ? 320 : 180,
    blockLimit: options.expanded ? 48 : 16,
    blockCount: 0,
    identity,
    taskMemoId: options.taskMemoId ?? "",
    taskIndex: 0,
    interactiveTasks: options.interactiveTasks === true,
    truncated: false,
  };
  const tokens = marked.lexer(content, { gfm: true, breaks: true });
  return { nodes: renderBlocks(tokens, context, "root"), truncated: context.truncated };
}

export function createMarkdownIdentity(rootKey: string): MarkdownIdentity {
  if (rootKey.length === 0 || rootKey.length > MAX_IDENTITY_ROOT_LENGTH || !MARKDOWN_IDENTITY_ROOT.test(rootKey)) {
    throw new TypeError("markdown identity root must be a valid UI identifier of at most 112 characters");
  }
  const keys = new Map<string, string>();
  let next = 0;
  return Object.freeze({
    rootKey,
    keyForSlot(slot: string): string {
      const existing = keys.get(slot);
      if (existing !== undefined) return existing;
      if (keys.size >= MAX_IDENTITY_SLOTS) throw new RangeError("markdown identity slot capacity exceeded");
      const key = `${rootKey}-${next.toString(36)}`;
      next += 1;
      keys.set(slot, key);
      return key;
    },
  });
}

export function toggleTaskMarker(content: string, targetIndex: number, checked: boolean): string {
  const lines = content.split("\n");
  let current = 0;
  let fence: "`" | "~" | "" = "";
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trimStart();
    const marker = trimmed.startsWith("```") ? "`" : trimmed.startsWith("~~~") ? "~" : "";
    if (marker) {
      fence = fence === marker ? "" : fence === "" ? marker : fence;
      continue;
    }
    if (fence) continue;
    const match = /^(\s*[-*+]\s+\[)([ xX])(\]\s+)/.exec(lines[index]);
    if (!match) continue;
    if (current === targetIndex) {
      lines[index] = `${match[1]}${checked ? "x" : " "}${match[3]}${lines[index].slice(match[0].length)}`;
      return lines.join("\n");
    }
    current += 1;
  }
  return content;
}

function renderBlocks(tokens: Token[], context: RenderContext, scope: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  const entries = slotEntries(context, scope, "block", tokens.filter((token) => token.type !== "space" && token.type !== "def"));
  for (const { item: token, key } of entries) {
    if (context.blockCount >= context.blockLimit || context.budget <= 0) {
      context.truncated = true;
      break;
    }
    context.blockCount += 1;
    const node = renderBlock(token, context, key);
    if (node !== undefined) output.push(node);
  }
  return output;
}

function renderBlock(token: Token, context: RenderContext, key: string): PluginUIVNode | undefined {
  if (!claim(context)) return undefined;
  switch (token.type) {
    case "heading": {
      const heading = token as Tokens.Heading;
      const tag = heading.depth <= 1 ? "h2" : heading.depth === 2 ? "h3" : "h4";
      return { type: "element", key, tag, attributes: { class: `markdown-heading level-${Math.min(heading.depth, 4)}` }, children: renderInline(heading.tokens, context, key) };
    }
    case "paragraph": {
      const paragraph = token as Tokens.Paragraph;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: renderInline(paragraph.tokens, context, key) };
    }
    case "code": {
      const code = token as Tokens.Code;
      return { type: "element", key, tag: "pre", attributes: { class: "markdown-code-block" }, children: [
        { type: "element", key: `${key}-code`, tag: "code", attributes: code.lang ? { class: "markdown-code", title: code.lang } : { class: "markdown-code" }, children: [textNode(`${key}-code-text`, code.text)] },
      ] };
    }
    case "blockquote": {
      const quote = token as Tokens.Blockquote;
      return { type: "element", key, tag: "div", attributes: { class: "markdown-quote" }, children: renderBlocks(quote.tokens, context, key) };
    }
    case "hr":
      return { type: "element", key, tag: "div", attributes: { class: "markdown-rule", role: "separator" }, children: [] };
    case "list":
      return renderList(token as Tokens.List, context, key);
    case "table":
      return renderTable(token as Tokens.Table, context, key);
    case "html": {
      const html = token as Tokens.HTML;
      return { type: "element", key, tag: "code", attributes: { class: "markdown-raw" }, children: [textNode(`${key}-text`, html.text)] };
    }
    case "text": {
      const text = token as Tokens.Text;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: text.tokens ? renderInline(text.tokens, context, key) : [textNode(`${key}-text`, text.text)] };
    }
    default: {
      throw new TypeError(`unsupported markdown block token: ${token.type}`);
    }
  }
}

function renderList(token: Tokens.List, context: RenderContext, key: string): PluginUIVNode {
  const items = slotEntries(context, key, "item", token.items).map(({ item, key: itemKey }) => {
    if (!claim(context)) return textNode(`${itemKey}-empty`, "");
    const children: PluginUIVNode[] = [];
    if (item.task) {
      const taskIndex = context.taskIndex++;
      children.push({
        type: "element",
        key: `${itemKey}-task`,
        tag: "input",
        attributes: {
          class: "markdown-task",
          type: "checkbox",
          checked: item.checked === true,
          disabled: !context.interactiveTasks,
          value: `${context.taskMemoId}:${taskIndex}`,
          title: item.checked ? "Mark incomplete" : "Mark complete",
          "data-redevplugin-action": "toggle-task",
        },
        children: [],
      });
    }
    const bodyTokens = item.task ? item.tokens.filter((token) => token.type !== "checkbox") : item.tokens;
    children.push({ type: "element", key: `${itemKey}-body`, tag: "div", attributes: { class: "markdown-list-copy" }, children: renderBlocks(bodyTokens, context, itemKey) });
    return { type: "element", key: itemKey, tag: "li", attributes: item.task ? { class: "markdown-list-item task-item" } : { class: "markdown-list-item" }, children } satisfies PluginUIVNode;
  });
  return { type: "element", key, tag: token.ordered ? "ol" : "ul", attributes: { class: token.ordered ? "markdown-list ordered" : "markdown-list" }, children: items };
}

function renderTable(token: Tokens.Table, context: RenderContext, key: string): PluginUIVNode {
  const header = slotEntries(context, key, "head", token.header).map(({ item: cell, key: cellKey }) => ({
    type: "element",
    key: cellKey,
    tag: "th",
    attributes: { scope: "col" },
    children: renderInline(cell.tokens, context, cellKey),
  }) satisfies PluginUIVNode);
  const body = slotEntries(context, key, "row", token.rows)
    .map(({ item: row, key: rowKey }) => ({
    type: "element",
    key: rowKey,
    tag: "tr",
    children: slotEntries(context, rowKey, "cell", row).map(({ item: cell, key: cellKey }) => ({
      type: "element",
      key: cellKey,
      tag: "td",
      children: renderInline(cell.tokens, context, cellKey),
    })),
  }) satisfies PluginUIVNode);
  return { type: "element", key, tag: "div", attributes: { class: "markdown-table-wrap" }, children: [
    { type: "element", key: `${key}-table`, tag: "table", attributes: { class: "markdown-table" }, children: [
      { type: "element", key: `${key}-thead`, tag: "thead", children: [{ type: "element", key: `${key}-head-row`, tag: "tr", children: header }] },
      { type: "element", key: `${key}-tbody`, tag: "tbody", children: body },
    ] },
  ] };
}

function renderInline(tokens: Token[], context: RenderContext, scope: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  const entries = slotEntries(context, scope, "inline", tokens);
  for (const { item: token, key } of entries) {
    if (!claim(context)) break;
    switch (token.type) {
      case "text": {
        const text = token as Tokens.Text;
        output.push(...(text.tokens ? renderInline(text.tokens, context, key) : [textNode(key, text.text)]));
        break;
      }
      case "escape":
        output.push(textNode(key, (token as Tokens.Escape).text));
        break;
      case "strong":
        output.push({ type: "element", key, tag: "strong", children: renderInline((token as Tokens.Strong).tokens, context, key) });
        break;
      case "em":
        output.push({ type: "element", key, tag: "em", children: renderInline((token as Tokens.Em).tokens, context, key) });
        break;
      case "del":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-strike" }, children: renderInline((token as Tokens.Del).tokens, context, key) });
        break;
      case "codespan":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-inline-code" }, children: [textNode(`${key}-text`, (token as Tokens.Codespan).text)] });
        break;
      case "br":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-break", "aria-hidden": true }, children: [] });
        break;
      case "link": {
        const link = token as Tokens.Link;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-link", title: link.href }, children: renderInline(link.tokens, context, key) });
        break;
      }
      case "image": {
        const image = token as Tokens.Image;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-image-reference", title: image.href }, children: [textNode(`${key}-text`, `[Image: ${image.text || "untitled"}]`)] });
        break;
      }
      case "html":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-raw inline" }, children: [textNode(`${key}-text`, (token as Tokens.HTML).text)] });
        break;
      default:
        throw new TypeError(`unsupported markdown inline token: ${token.type}`);
    }
  }
  return output;
}

function claim(context: RenderContext): boolean {
  if (context.budget <= 0) {
    context.truncated = true;
    return false;
  }
  context.budget -= 1;
  return true;
}

function slotEntries<T>(
  context: RenderContext,
  scope: string,
  kind: string,
  items: readonly T[],
): Array<{ item: T; key: string }> {
  return items.map((item, index) => {
    const slot = `${scope}/${kind}:${index}`;
    return { item, key: context.identity.keyForSlot(slot) };
  });
}
