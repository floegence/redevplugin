import type { PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

type BlockToken =
  | { type: "heading"; depth: number; tokens: InlineToken[] }
  | { type: "paragraph"; tokens: InlineToken[] }
  | { type: "code"; text: string; lang?: string }
  | { type: "blockquote"; tokens: BlockToken[] }
  | { type: "hr" }
  | { type: "list"; ordered: boolean; items: ListItemToken[] }
  | { type: "table"; header: TableCellToken[]; rows: TableCellToken[][] }
  | { type: "html"; text: string }
  | { type: "text"; text: string; tokens?: InlineToken[] };

type ListItemToken = { task: boolean; checked?: boolean; tokens: BlockToken[] };
type TableCellToken = { tokens: InlineToken[] };

type InlineToken =
  | { type: "text"; text: string; tokens?: InlineToken[] }
  | { type: "escape"; text: string }
  | { type: "strong" | "em" | "del"; tokens: InlineToken[] }
  | { type: "codespan"; text: string }
  | { type: "br" }
  | { type: "link"; href: string; tokens: InlineToken[] }
  | { type: "image"; href: string; text: string }
  | { type: "html"; text: string };

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
  const tokens = parseBlocks(content);
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

function parseBlocks(content: string): BlockToken[] {
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  return parseBlockRange(lines, 0, lines.length).tokens;
}

function parseBlockRange(lines: string[], start: number, end: number): { tokens: BlockToken[]; index: number } {
  const tokens: BlockToken[] = [];
  let index = start;
  while (index < end) {
    const line = lines[index];
    if (line.trim() === "") {
      index += 1;
      continue;
    }

    const fence = readFence(line);
    if (fence) {
      const codeLines: string[] = [];
      index += 1;
      while (index < end && !isClosingFence(lines[index], fence.marker)) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < end) index += 1;
      tokens.push({ type: "code", text: codeLines.join("\n"), ...(fence.language ? { lang: fence.language } : {}) });
      continue;
    }

    const heading = readHeading(line);
    if (heading) {
      tokens.push({ type: "heading", depth: heading.depth, tokens: parseInline(heading.text) });
      index += 1;
      continue;
    }
    if (isHorizontalRule(line)) {
      tokens.push({ type: "hr" });
      index += 1;
      continue;
    }

    if (line.trimStart().startsWith(">")) {
      const quoteLines: string[] = [];
      while (index < end && lines[index].trimStart().startsWith(">")) {
        const value = lines[index].trimStart().slice(1);
        quoteLines.push(value.startsWith(" ") ? value.slice(1) : value);
        index += 1;
      }
      tokens.push({ type: "blockquote", tokens: parseBlocks(quoteLines.join("\n")) });
      continue;
    }

    const list = readListItem(line);
    if (list) {
      const items: ListItemToken[] = [];
      const ordered = list.ordered;
      while (index < end) {
        const item = readListItem(lines[index]);
        if (!item || item.ordered !== ordered) break;
        let body = item.text;
        let task = false;
        let checked = false;
        if (body.startsWith("[ ] ") || body.startsWith("[x] ") || body.startsWith("[X] ")) {
          task = true;
          checked = body[1].toLowerCase() === "x";
          body = body.slice(4);
        }
        items.push({ task, ...(task ? { checked } : {}), tokens: parseBlocks(body) });
        index += 1;
      }
      tokens.push({ type: "list", ordered, items });
      continue;
    }

    if (index + 1 < end && line.includes("|") && isTableSeparator(lines[index + 1])) {
      const header = splitTableRow(line);
      index += 2;
      const rows: TableCellToken[][] = [];
      while (index < end && lines[index].trim() !== "" && lines[index].includes("|")) {
        rows.push(splitTableRow(lines[index]));
        index += 1;
      }
      tokens.push({ type: "table", header, rows });
      continue;
    }

    if (line.trimStart().startsWith("<") && line.includes(">")) {
      tokens.push({ type: "html", text: line.trim() });
      index += 1;
      continue;
    }

    const paragraph: string[] = [line];
    index += 1;
    while (index < end && lines[index].trim() !== "" && !isBlockStart(lines, index, end)) {
      paragraph.push(lines[index]);
      index += 1;
    }
    tokens.push({ type: "paragraph", tokens: parseInline(paragraph.join("\n")) });
  }
  return { tokens, index };
}

function isBlockStart(lines: string[], index: number, end: number): boolean {
  const line = lines[index];
  return Boolean(readFence(line) || readHeading(line) || isHorizontalRule(line) || line.trimStart().startsWith(">") || readListItem(line) || (index + 1 < end && line.includes("|") && isTableSeparator(lines[index + 1])) || (line.trimStart().startsWith("<") && line.includes(">")));
}

function readFence(line: string): { marker: "`" | "~"; language: string } | undefined {
  const value = line.slice(0, line.length - line.trimStart().length);
  if (value.length > 3) return undefined;
  const trimmed = line.trimStart();
  const marker = trimmed.startsWith("```") ? "`" : trimmed.startsWith("~~~") ? "~" : undefined;
  if (!marker) return undefined;
  const rest = trimmed.slice(3).trim();
  return { marker, language: rest.slice(0, 64) };
}

function isClosingFence(line: string, marker: "`" | "~"): boolean {
  const trimmed = line.trimStart();
  return trimmed.length >= 3 && trimmed[0] === marker && trimmed[1] === marker && trimmed[2] === marker;
}

function readHeading(line: string): { depth: number; text: string } | undefined {
  const trimmed = line.trimStart();
  const indentation = line.length - trimmed.length;
  if (indentation > 3 || !trimmed.startsWith("#")) return undefined;
  let depth = 0;
  while (depth < trimmed.length && trimmed[depth] === "#") depth += 1;
  if (depth > 6 || (trimmed.length > depth && trimmed[depth] !== " " && trimmed[depth] !== "\t")) return undefined;
  return { depth, text: trimmed.slice(depth).trim() };
}

function isHorizontalRule(line: string): boolean {
  const value = line.replace(/[ \t]/g, "");
  if (value.length < 3) return false;
  const marker = value[0];
  return (marker === "-" || marker === "_" || marker === "*") && [...value].every((character) => character === marker);
}

function readListItem(line: string): { ordered: boolean; text: string } | undefined {
  const trimmed = line.trimStart();
  if (trimmed.length < 3) return undefined;
  if ((trimmed[0] === "-" || trimmed[0] === "*" || trimmed[0] === "+") && (trimmed[1] === " " || trimmed[1] === "\t")) return { ordered: false, text: trimmed.slice(2).trim() };
  let index = 0;
  while (index < trimmed.length && index < 9 && trimmed.charCodeAt(index) >= 48 && trimmed.charCodeAt(index) <= 57) index += 1;
  if (index > 0 && (trimmed[index] === "." || trimmed[index] === ")") && (trimmed[index + 1] === " " || trimmed[index + 1] === "\t")) return { ordered: true, text: trimmed.slice(index + 2).trim() };
  return undefined;
}

function isTableSeparator(line: string): boolean {
  if (!line.includes("|")) return false;
  return splitTableParts(line).every((part) => {
    const value = part.replace(/[ \t]/g, "");
    if (value.length < 3) return false;
    const start = value[0] === ":" ? 1 : 0;
    const finish = value[value.length - 1] === ":" ? value.length - 1 : value.length;
    return finish - start >= 3 && [...value.slice(start, finish)].every((character) => character === "-");
  });
}

function splitTableRow(line: string): TableCellToken[] {
  return splitTableParts(line).map((part) => ({ tokens: parseInline(part.trim()) }));
}

function splitTableParts(line: string): string[] {
  const value = line.trim();
  const withoutStart = value.startsWith("|") ? value.slice(1) : value;
  const withoutEnd = withoutStart.endsWith("|") ? withoutStart.slice(0, -1) : withoutStart;
  return withoutEnd.split("|");
}

function parseInline(value: string): InlineToken[] {
  const tokens: InlineToken[] = [];
  let plain = "";
  const flush = () => {
    if (plain) tokens.push({ type: "text", text: plain });
    plain = "";
  };
  let index = 0;
  while (index < value.length) {
    if (value[index] === "\\" && index + 1 < value.length) {
      flush();
      tokens.push({ type: "escape", text: value[index + 1] });
      index += 2;
      continue;
    }
    if (value[index] === "\n") {
      flush();
      tokens.push({ type: "br" });
      index += 1;
      continue;
    }
    const codeEnd = value.indexOf("`", index + 1);
    if (value[index] === "`" && codeEnd > index + 1) {
      flush();
      tokens.push({ type: "codespan", text: value.slice(index + 1, codeEnd).trim() });
      index = codeEnd + 1;
      continue;
    }
    const imageOrLink = readLink(value, index);
    if (imageOrLink) {
      flush();
      tokens.push(imageOrLink.token);
      index = imageOrLink.next;
      continue;
    }
    const styled = readStyled(value, index);
    if (styled) {
      flush();
      tokens.push(styled.token);
      index = styled.next;
      continue;
    }
    if (value[index] === "<") {
      const htmlEnd = value.indexOf(">", index + 1);
      if (htmlEnd > index + 1) {
        flush();
        tokens.push({ type: "html", text: value.slice(index, htmlEnd + 1) });
        index = htmlEnd + 1;
        continue;
      }
    }
    plain += value[index];
    index += 1;
  }
  flush();
  return tokens;
}

function readLink(value: string, index: number): { token: InlineToken; next: number } | undefined {
  const image = value[index] === "!";
  const open = image ? index + 1 : index;
  if (value[open] !== "[") return undefined;
  const closeLabel = value.indexOf("](", open + 1);
  if (closeLabel < 0) return undefined;
  const closeTarget = value.indexOf(")", closeLabel + 2);
  if (closeTarget < 0) return undefined;
  const label = value.slice(open + 1, closeLabel);
  const href = value.slice(closeLabel + 2, closeTarget).trim().slice(0, 2048);
  return image
    ? { token: { type: "image", href, text: label.slice(0, 512) }, next: closeTarget + 1 }
    : { token: { type: "link", href, tokens: parseInline(label) }, next: closeTarget + 1 };
}

function readStyled(value: string, index: number): { token: InlineToken; next: number } | undefined {
  const markers: Array<{ marker: string; type: "strong" | "em" | "del" }> = [
    { marker: "**", type: "strong" },
    { marker: "__", type: "strong" },
    { marker: "~~", type: "del" },
    { marker: "*", type: "em" },
    { marker: "_", type: "em" },
  ];
  for (const { marker, type } of markers) {
    if (!value.startsWith(marker, index)) continue;
    const end = value.indexOf(marker, index + marker.length);
    if (end <= index + marker.length) continue;
    return { token: { type, tokens: parseInline(value.slice(index + marker.length, end)) }, next: end + marker.length };
  }
  return undefined;
}

function renderBlocks(tokens: BlockToken[], context: RenderContext, scope: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  const entries = slotEntries(context, scope, "block", tokens);
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

function renderBlock(token: BlockToken, context: RenderContext, key: string): PluginUIVNode | undefined {
  if (!claim(context)) return undefined;
  switch (token.type) {
    case "heading": {
      const heading = token;
      const tag = heading.depth <= 1 ? "h2" : heading.depth === 2 ? "h3" : "h4";
      return { type: "element", key, tag, attributes: { class: `markdown-heading level-${Math.min(heading.depth, 4)}` }, children: renderInline(heading.tokens, context, key) };
    }
    case "paragraph": {
      const paragraph = token;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: renderInline(paragraph.tokens, context, key) };
    }
    case "code": {
      const code = token;
      return { type: "element", key, tag: "pre", attributes: { class: "markdown-code-block" }, children: [
        { type: "element", key: `${key}-code`, tag: "code", attributes: code.lang ? { class: "markdown-code", title: code.lang } : { class: "markdown-code" }, children: [textNode(`${key}-code-text`, code.text)] },
      ] };
    }
    case "blockquote": {
      const quote = token;
      return { type: "element", key, tag: "div", attributes: { class: "markdown-quote" }, children: renderBlocks(quote.tokens, context, key) };
    }
    case "hr":
      return { type: "element", key, tag: "div", attributes: { class: "markdown-rule", role: "separator" }, children: [] };
    case "list":
      return renderList(token, context, key);
    case "table":
      return renderTable(token, context, key);
    case "html": {
      const html = token;
      return { type: "element", key, tag: "code", attributes: { class: "markdown-raw" }, children: [textNode(`${key}-text`, html.text)] };
    }
    case "text": {
      const text = token;
      return { type: "element", key, tag: "p", attributes: { class: "markdown-paragraph" }, children: text.tokens ? renderInline(text.tokens, context, key) : [textNode(`${key}-text`, text.text)] };
    }
    default: {
      throw new TypeError("unsupported markdown block token");
    }
  }
}

function renderList(token: Extract<BlockToken, { type: "list" }>, context: RenderContext, key: string): PluginUIVNode {
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
    const bodyTokens = item.tokens;
    children.push({ type: "element", key: `${itemKey}-body`, tag: "div", attributes: { class: "markdown-list-copy" }, children: renderBlocks(bodyTokens, context, itemKey) });
    return { type: "element", key: itemKey, tag: "li", attributes: item.task ? { class: "markdown-list-item task-item" } : { class: "markdown-list-item" }, children } satisfies PluginUIVNode;
  });
  return { type: "element", key, tag: token.ordered ? "ol" : "ul", attributes: { class: token.ordered ? "markdown-list ordered" : "markdown-list" }, children: items };
}

function renderTable(token: Extract<BlockToken, { type: "table" }>, context: RenderContext, key: string): PluginUIVNode {
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

function renderInline(tokens: InlineToken[], context: RenderContext, scope: string): PluginUIVNode[] {
  const output: PluginUIVNode[] = [];
  const entries = slotEntries(context, scope, "inline", tokens);
  for (const { item: token, key } of entries) {
    if (!claim(context)) break;
    switch (token.type) {
      case "text": {
        const text = token;
        output.push(...(text.tokens ? renderInline(text.tokens, context, key) : [textNode(key, text.text)]));
        break;
      }
      case "escape":
        output.push(textNode(key, token.text));
        break;
      case "strong":
        output.push({ type: "element", key, tag: "strong", children: renderInline(token.tokens, context, key) });
        break;
      case "em":
        output.push({ type: "element", key, tag: "em", children: renderInline(token.tokens, context, key) });
        break;
      case "del":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-strike" }, children: renderInline(token.tokens, context, key) });
        break;
      case "codespan":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-inline-code" }, children: [textNode(`${key}-text`, token.text)] });
        break;
      case "br":
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-break", "aria-hidden": true }, children: [] });
        break;
      case "link": {
        const link = token;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-link", title: link.href }, children: renderInline(link.tokens, context, key) });
        break;
      }
      case "image": {
        const image = token;
        output.push({ type: "element", key, tag: "span", attributes: { class: "markdown-image-reference", title: image.href }, children: [textNode(`${key}-text`, `[Image: ${image.text || "untitled"}]`)] });
        break;
      }
      case "html":
        output.push({ type: "element", key, tag: "code", attributes: { class: "markdown-raw inline" }, children: [textNode(`${key}-text`, token.text)] });
        break;
      default:
        throw new TypeError("unsupported markdown inline token");
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
