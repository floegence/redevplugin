import { marked, type Token, type Tokens } from "marked";
import type { PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

export type MarkdownRenderResult = {
  nodes: PluginUIVNode[];
  truncated: boolean;
};

type RenderContext = {
  budget: number;
  blockLimit: number;
  blockCount: number;
  keyPrefix: string;
  taskMemoId: string;
  taskIndex: number;
  interactiveTasks: boolean;
  truncated: boolean;
};

export function renderMarkdown(
  content: string,
  keyPrefix: string,
  options: { expanded?: boolean; taskMemoId?: string; interactiveTasks?: boolean } = {},
): MarkdownRenderResult {
  const context: RenderContext = {
    budget: options.expanded ? 320 : 180,
    blockLimit: options.expanded ? 48 : 16,
    blockCount: 0,
    keyPrefix,
    taskMemoId: options.taskMemoId ?? "",
    taskIndex: 0,
    interactiveTasks: options.interactiveTasks === true,
    truncated: false,
  };
  try {
    const tokens = marked.lexer(content, { gfm: true, breaks: true });
    return { nodes: renderBlocks(tokens, context, "b"), truncated: context.truncated };
  } catch {
    return {
      nodes: [{ type: "element", key: `${keyPrefix}-plain-text`, tag: "p", attributes: { class: "markdown-paragraph" }, children: [content] }],
      truncated: false,
    };
  }
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

function renderBlocks(tokens: Token[], context: RenderContext, path: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (context.blockCount >= context.blockLimit || context.budget <= 0) {
      context.truncated = true;
      break;
    }
    const token = tokens[index];
    if (token.type === "space" || token.type === "def") continue;
    context.blockCount += 1;
    const key = keyFor(context, `${path}-${index}`);
    const node = renderBlock(token, context, key, `${path}-${index}`);
    if (node !== undefined) output.push(node);
  }
  return output;
}

function renderBlock(token: Token, context: RenderContext, key: string, path: string): PluginUIVNode | undefined {
  if (!claim(context)) return undefined;
  switch (token.type) {
    case "heading": {
      const heading = token as Tokens.Heading;
      const tag = heading.depth <= 1 ? "h2" : heading.depth === 2 ? "h3" : "h4";
      return { type: "element", key, tag, attributes: { class: `markdown-heading level-${Math.min(heading.depth, 4)}` }, children: renderInline(heading.tokens, context, `${path}-i`) };
    }
    case "paragraph": {
      const paragraph = token as Tokens.Paragraph;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: renderInline(paragraph.tokens, context, `${path}-i`) };
    }
    case "code": {
      const code = token as Tokens.Code;
      return { type: "element", key, tag: "pre", attributes: { class: "markdown-code-block" }, children: [
        { type: "element", key: `${key}-code`, tag: "code", attributes: code.lang ? { class: "markdown-code", title: code.lang } : { class: "markdown-code" }, children: [code.text] },
      ] };
    }
    case "blockquote": {
      const quote = token as Tokens.Blockquote;
      return { type: "element", key, tag: "div", attributes: { class: "markdown-quote" }, children: renderBlocks(quote.tokens, context, `${path}-q`) };
    }
    case "hr":
      return { type: "element", key, tag: "div", attributes: { class: "markdown-rule", role: "separator" }, children: [] };
    case "list":
      return renderList(token as Tokens.List, context, key, path);
    case "table":
      return renderTable(token as Tokens.Table, context, key, path);
    case "html": {
      const html = token as Tokens.HTML;
      return { type: "element", key, tag: "code", attributes: { class: "markdown-raw" }, children: [html.text] };
    }
    case "text": {
      const text = token as Tokens.Text;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: text.tokens ? renderInline(text.tokens, context, `${path}-i`) : [text.text] };
    }
    default: {
      const nestedTokens = "tokens" in token && Array.isArray(token.tokens) ? token.tokens : undefined;
      const nested = nestedTokens ? renderInline(nestedTokens, context, `${path}-n`) : [token.raw];
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: nested };
    }
  }
}

function renderList(token: Tokens.List, context: RenderContext, key: string, path: string): PluginUIVNode {
  const items = token.items.map((item, index) => {
    const itemKey = `${key}-item-${index}`;
    if (!claim(context)) return "";
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
    children.push({ type: "element", key: `${itemKey}-body`, tag: "div", attributes: { class: "markdown-list-copy" }, children: renderBlocks(bodyTokens, context, `${path}-item-${index}`) });
    return { type: "element", key: itemKey, tag: "li", attributes: item.task ? { class: "markdown-list-item task-item" } : { class: "markdown-list-item" }, children } satisfies PluginUIVNode;
  });
  return { type: "element", key, tag: token.ordered ? "ol" : "ul", attributes: { class: token.ordered ? "markdown-list ordered" : "markdown-list" }, children: items };
}

function renderTable(token: Tokens.Table, context: RenderContext, key: string, path: string): PluginUIVNode {
  const header = token.header.map((cell, index) => ({
    type: "element",
    key: `${key}-head-${index}`,
    tag: "th",
    attributes: { scope: "col" },
    children: renderInline(cell.tokens, context, `${path}-head-${index}`),
  }) satisfies PluginUIVNode);
  const body = token.rows.map((row, rowIndex) => ({
    type: "element",
    key: `${key}-row-${rowIndex}`,
    tag: "tr",
    children: row.map((cell, cellIndex) => ({
      type: "element",
      key: `${key}-cell-${rowIndex}-${cellIndex}`,
      tag: "td",
      children: renderInline(cell.tokens, context, `${path}-cell-${rowIndex}-${cellIndex}`),
    })),
  }) satisfies PluginUIVNode);
  return { type: "element", key, tag: "div", attributes: { class: "markdown-table-wrap" }, children: [
    { type: "element", key: `${key}-table`, tag: "table", attributes: { class: "markdown-table" }, children: [
      { type: "element", key: `${key}-thead`, tag: "thead", children: [{ type: "element", key: `${key}-head-row`, tag: "tr", children: header }] },
      { type: "element", key: `${key}-tbody`, tag: "tbody", children: body },
    ] },
  ] };
}

function renderInline(tokens: Token[], context: RenderContext, path: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (!claim(context)) break;
    const token = tokens[index];
    const key = keyFor(context, `${path}-${index}`);
    switch (token.type) {
      case "text": {
        const text = token as Tokens.Text;
        output.push(...(text.tokens ? renderInline(text.tokens, context, `${path}-${index}-t`) : [text.text]));
        break;
      }
      case "escape":
        output.push((token as Tokens.Escape).text);
        break;
      case "strong":
        output.push({ type: "element", key, tag: "strong", children: renderInline((token as Tokens.Strong).tokens, context, `${path}-${index}-s`) });
        break;
      case "em":
        output.push({ type: "element", key, tag: "em", children: renderInline((token as Tokens.Em).tokens, context, `${path}-${index}-e`) });
        break;
      case "del":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-strike" }, children: renderInline((token as Tokens.Del).tokens, context, `${path}-${index}-d`) });
        break;
      case "codespan":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-inline-code" }, children: [(token as Tokens.Codespan).text] });
        break;
      case "br":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-break", "aria-hidden": true }, children: [] });
        break;
      case "link": {
        const link = token as Tokens.Link;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-link", title: link.href }, children: renderInline(link.tokens, context, `${path}-${index}-l`) });
        break;
      }
      case "image": {
        const image = token as Tokens.Image;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-image-reference", title: image.href }, children: [`[Image: ${image.text || "untitled"}]`] });
        break;
      }
      case "html":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-raw inline" }, children: [(token as Tokens.HTML).text] });
        break;
      default:
        output.push(token.raw);
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

function keyFor(context: RenderContext, suffix: string): string {
  return `${context.keyPrefix}-${suffix}`;
}
