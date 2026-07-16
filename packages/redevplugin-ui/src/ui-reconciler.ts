import type { OpaqueSurfaceAllowedTag } from "./opaque-surface-policy.gen.js";

export type PluginUIAttributeValue = string | number | boolean;

export type PluginUITextVNode = string;

export type PluginUIElementVNode = {
  type: "element";
  key: string;
  tag: OpaqueSurfaceAllowedTag;
  attributes?: Record<string, PluginUIAttributeValue>;
  children?: PluginUIVNode[];
};

export type PluginUIVNode = PluginUITextVNode | PluginUIElementVNode;

export type PluginUISetTextOperation = {
  type: "set_text";
  parent_key: string;
  child_index: number;
  text: string;
};

export type PluginUIPatchAttributesOperation = {
  type: "patch_attributes";
  target_key: string;
  set: Record<string, PluginUIAttributeValue>;
  remove: string[];
};

export type PluginUIPatchControlOperation = {
  type: "patch_control";
  target_key: string;
  edit_revision: number;
  value?: string | null;
  checked?: boolean | null;
};

export type PluginUIInsertChildOperation = {
  type: "insert_child";
  parent_key: string;
  child_index: number;
  node: PluginUIVNode;
};

export type PluginUIRemoveChildOperation = {
  type: "remove_child";
  parent_key: string;
  child_index: number;
  child_key?: string;
};

export type PluginUIMoveChildOperation = {
  type: "move_child";
  parent_key: string;
  child_key: string;
  from_index: number;
  to_index: number;
};

export type PluginUIPatchOperation =
  | PluginUISetTextOperation
  | PluginUIPatchAttributesOperation
  | PluginUIPatchControlOperation
  | PluginUIInsertChildOperation
  | PluginUIRemoveChildOperation
  | PluginUIMoveChildOperation;

export type PluginUIMountMessage = {
  type: "redevplugin.ui.mount";
  id: string;
  revision: 1;
  tree: PluginUIElementVNode;
};

export type PluginUIPatchMessage = {
  type: "redevplugin.ui.patch";
  id: string;
  base_revision: number;
  revision: number;
  operations: PluginUIPatchOperation[];
};

export type PluginUIReconcileOptions = {
  controlEditRevisions?: ReadonlyMap<string, number>;
  transferredCanvasKeys?: ReadonlySet<string>;
  maxOperations?: number;
};

const keyPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
const editableValueTags = new Set<OpaqueSurfaceAllowedTag>(["input", "textarea", "select", "option"]);

export class PluginUIReconcileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PluginUIReconcileError";
  }
}

export function validatePluginUITree(tree: PluginUIVNode): PluginUIElementVNode {
  if (!isElement(tree)) {
    throw new PluginUIReconcileError("Plugin UI root must be one keyed element");
  }
  const keys = new Set<string>();
  const seen = new Set<object>();
  let nodes = 0;

  const visit = (node: PluginUIVNode, depth: number): void => {
    nodes += 1;
    if (nodes > 4096 || depth > 32) {
      throw new PluginUIReconcileError("Plugin UI tree exceeds structural limits");
    }
    if (typeof node === "string") {
      if (node.length > 65_536) throw new PluginUIReconcileError("Plugin UI text exceeds limits");
      return;
    }
    if (!isElement(node) || seen.has(node)) {
      throw new PluginUIReconcileError("Plugin UI tree must contain plain acyclic VNodes");
    }
    seen.add(node);
    try {
      if (!keyPattern.test(node.key) || keys.has(node.key)) {
        throw new PluginUIReconcileError(`Plugin UI key is invalid or duplicated: ${String(node.key)}`);
      }
      keys.add(node.key);
      if (node.attributes !== undefined) {
        if (!isPlainRecord(node.attributes) || Object.keys(node.attributes).length > 64) {
          throw new PluginUIReconcileError(`Plugin UI attributes are invalid for ${node.key}`);
        }
        for (const value of Object.values(node.attributes)) {
          if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
            throw new PluginUIReconcileError(`Plugin UI attribute is invalid for ${node.key}`);
          }
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new PluginUIReconcileError(`Plugin UI attribute must be finite for ${node.key}`);
          }
        }
      }
      if (node.children !== undefined) {
        if (!Array.isArray(node.children)) throw new PluginUIReconcileError(`Plugin UI children are invalid for ${node.key}`);
        for (const child of node.children) visit(child, depth + 1);
      }
    } finally {
      seen.delete(node);
    }
  };

  visit(tree, 1);
  return tree;
}

export function reconcilePluginUITrees(
  current: PluginUIElementVNode,
  next: PluginUIElementVNode,
  options: PluginUIReconcileOptions = {},
): PluginUIPatchOperation[] {
  validatePluginUITree(current);
  validatePluginUITree(next);
  if (current.key !== next.key || current.tag !== next.tag) {
    throw new PluginUIReconcileError("Plugin UI root key and tag are immutable");
  }

  const operations: PluginUIPatchOperation[] = [];
  const transferredCanvasKeys = options.transferredCanvasKeys ?? new Set<string>();
  const maxOperations = options.maxOperations ?? 4096;
  const append = (operation: PluginUIPatchOperation): void => {
    if (operations.length >= maxOperations) {
      throw new PluginUIReconcileError("Plugin UI patch exceeds the operation limit");
    }
    operations.push(operation);
  };

  const ensureCanvasStable = (node: PluginUIVNode, action: string): void => {
    if (typeof node === "string") return;
    if (transferredCanvasKeys.has(node.key)) {
      throw new PluginUIReconcileError(`Transferred canvas ${node.key} cannot be ${action}`);
    }
    for (const child of node.children ?? []) ensureCanvasStable(child, action);
  };

  const reconcileElement = (left: PluginUIElementVNode, right: PluginUIElementVNode): void => {
    if (left.key !== right.key || left.tag !== right.tag) {
      throw new PluginUIReconcileError(`Plugin UI element identity changed for ${left.key}`);
    }
    reconcileAttributes(left, right, options.controlEditRevisions, append);

    const working = [...(left.children ?? [])];
    const desired = right.children ?? [];
    for (let index = 0; index < working.length; index += 1) {
      const child = working[index];
      if (typeof child !== "string" && transferredCanvasKeys.has(child.key)) {
        const nextIndex = desired.findIndex((candidate) => typeof candidate !== "string" && candidate.key === child.key);
        if (nextIndex === -1) throw new PluginUIReconcileError(`Transferred canvas ${child.key} cannot be removed`);
        if (nextIndex !== index) throw new PluginUIReconcileError(`Transferred canvas ${child.key} cannot be moved`);
      }
    }
    for (let index = 0; index < desired.length; index += 1) {
      const wanted = desired[index];
      const present = working[index];
      if (typeof wanted === "string") {
        if (typeof present === "string") {
          if (present !== wanted) append({ type: "set_text", parent_key: left.key, child_index: index, text: wanted });
          working[index] = wanted;
        } else {
          append({ type: "insert_child", parent_key: left.key, child_index: index, node: wanted });
          working.splice(index, 0, wanted);
        }
        continue;
      }

      const foundIndex = typeof present !== "string" && present?.key === wanted.key
        ? index
        : working.findIndex((candidate) => typeof candidate !== "string" && candidate.key === wanted.key);
      if (foundIndex === -1) {
        append({ type: "insert_child", parent_key: left.key, child_index: index, node: wanted });
        working.splice(index, 0, wanted);
        continue;
      }
      const found = working[foundIndex];
      if (typeof found === "string") throw new PluginUIReconcileError("Plugin UI keyed lookup became inconsistent");
      if (found.tag !== wanted.tag) {
        ensureCanvasStable(found, "replaced");
        append({ type: "remove_child", parent_key: left.key, child_index: foundIndex, child_key: found.key });
        working.splice(foundIndex, 1);
        append({ type: "insert_child", parent_key: left.key, child_index: index, node: wanted });
        working.splice(index, 0, wanted);
        continue;
      }
      if (foundIndex !== index) {
        ensureCanvasStable(found, "moved");
        append({ type: "move_child", parent_key: left.key, child_key: found.key, from_index: foundIndex, to_index: index });
        working.splice(foundIndex, 1);
        working.splice(index, 0, found);
      }
      reconcileElement(found, wanted);
      working[index] = wanted;
    }

    for (let index = working.length - 1; index >= desired.length; index -= 1) {
      const removed = working[index];
      ensureCanvasStable(removed, "removed");
      append({
        type: "remove_child",
        parent_key: left.key,
        child_index: index,
        ...(typeof removed === "string" ? {} : { child_key: removed.key }),
      });
      working.splice(index, 1);
    }
  };

  reconcileElement(current, next);
  return operations;
}

function reconcileAttributes(
  current: PluginUIElementVNode,
  next: PluginUIElementVNode,
  controlEditRevisions: ReadonlyMap<string, number> | undefined,
  append: (operation: PluginUIPatchOperation) => void,
): void {
  const left = current.attributes ?? {};
  const right = next.attributes ?? {};
  const set: Record<string, PluginUIAttributeValue> = {};
  const remove: string[] = [];

  for (const [name, value] of Object.entries(right)) {
    if (!isEditableControlAttribute(current.tag, name) && left[name] !== value) set[name] = value;
  }
  for (const name of Object.keys(left)) {
    if (!isEditableControlAttribute(current.tag, name) && !(name in right)) remove.push(name);
  }
  if (Object.keys(set).length > 0 || remove.length > 0) {
    append({ type: "patch_attributes", target_key: current.key, set, remove });
  }

  const valueChanged = editableValueTags.has(current.tag) && left.value !== right.value;
  const checkedChanged = current.tag === "input" && left.checked !== right.checked;
  if (valueChanged || checkedChanged) {
    append({
      type: "patch_control",
      target_key: current.key,
      edit_revision: controlEditRevisions?.get(current.key) ?? 0,
      ...(valueChanged ? { value: right.value === undefined ? null : String(right.value) } : {}),
      ...(checkedChanged ? { checked: right.checked === undefined ? null : Boolean(right.checked) } : {}),
    });
  }
}

function isEditableControlAttribute(tag: OpaqueSurfaceAllowedTag, name: string): boolean {
  const normalized = name.toLowerCase();
  return (normalized === "value" && editableValueTags.has(tag)) ||
    (normalized === "checked" && tag === "input");
}

function isElement(value: unknown): value is PluginUIElementVNode {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => ["type", "key", "tag", "attributes", "children"].includes(key)) &&
    value.type === "element" && typeof value.key === "string" && typeof value.tag === "string";
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
