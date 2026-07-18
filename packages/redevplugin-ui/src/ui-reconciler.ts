import { opaqueSurfaceRenderLimits, type OpaqueSurfaceAllowedTag } from "./opaque-surface-policy.gen.js";
import {
  PluginUIReconcileError,
  validatePluginUITree,
  type PluginUIAttributeValue,
  type PluginUIElementVNode,
  type PluginUIPatchOperation,
  type PluginUIVNode,
} from "./ui-patch-validator.js";

export { PluginUIReconcileError, validatePluginUITree } from "./ui-patch-validator.js";
export type {
  PluginUIAttributeValue,
  PluginUIElementVNode,
  PluginUIInsertChildOperation,
  PluginUIMountMessage,
  PluginUIMoveChildOperation,
  PluginUIPatchAttributesOperation,
  PluginUIPatchControlOperation,
  PluginUIPatchMessage,
  PluginUIPatchOperation,
  PluginUIRemoveChildOperation,
  PluginUISetTextOperation,
  PluginUITextVNode,
  PluginUIVNode,
} from "./ui-patch-validator.js";

export type PluginUIReconcileOptions = {
  controlEditRevisions?: ReadonlyMap<string, number>;
  transferredCanvasKeys?: ReadonlySet<string>;
  maxOperations?: number;
};

type IndexedNode = {
  node: PluginUIVNode;
  parentKey?: string;
  childIndex: number;
  childKeys?: string[];
  depth: number;
};

type TreeIndex = {
  byKey: Map<string, IndexedNode>;
  order: string[];
};

const editableValueTags = new Set<OpaqueSurfaceAllowedTag>(["input", "textarea", "select", "option"]);
const emptyAttributes: Readonly<Record<string, PluginUIAttributeValue>> = {};
const maxPluginUIPatchOperations = opaqueSurfaceRenderLimits.max_patch_operations;

export function reconcilePluginUITrees(
  current: PluginUIElementVNode,
  next: PluginUIElementVNode,
  options: PluginUIReconcileOptions = {},
): PluginUIPatchOperation[] {
  validatePluginUITree(current);
  validatePluginUITree(next);
  return reconcileValidatedPluginUITrees(current, next, options);
}

// Internal fast path for callers that retain trees returned by validatePluginUITree.
export function reconcileValidatedPluginUITrees(
  current: PluginUIElementVNode,
  next: PluginUIElementVNode,
  options: PluginUIReconcileOptions = {},
): PluginUIPatchOperation[] {
  if (current.key !== next.key || current.tag !== next.tag) {
    throw new PluginUIReconcileError("Plugin UI root key and tag are immutable");
  }

  const currentIndex = indexTree(current);
  const nextIndex = indexTree(next);
  const transferredCanvasKeys = options.transferredCanvasKeys ?? new Set<string>();
  for (const key of transferredCanvasKeys) {
    const left = currentIndex.byKey.get(key);
    const right = nextIndex.byKey.get(key);
    if (!left || !right) {
      throw new PluginUIReconcileError(`Transferred canvas ${key} cannot be removed`);
    }
    if (!sameNodeIdentity(left.node, right.node)) {
      throw new PluginUIReconcileError(`Transferred canvas ${key} cannot be replaced`);
    }
    if (left.parentKey !== right.parentKey || left.childIndex !== right.childIndex) {
      throw new PluginUIReconcileError(`Transferred canvas ${key} cannot be moved`);
    }
    if (left.node.type !== "element" || right.node.type !== "element" || !sameAttributes(left.node.attributes, right.node.attributes)) {
      throw new PluginUIReconcileError(`Transferred canvas ${key} cannot be patched`);
    }
  }

  const maxOperations = options.maxOperations ?? maxPluginUIPatchOperations;
  if (!Number.isSafeInteger(maxOperations) || maxOperations < 1 || maxOperations > maxPluginUIPatchOperations) {
    throw new PluginUIReconcileError(`Plugin UI maxOperations must be an integer between 1 and ${maxPluginUIPatchOperations}`);
  }
  const operations: PluginUIPatchOperation[] = [];
  const append = (operation: PluginUIPatchOperation): void => {
    if (operations.length >= maxOperations) {
      throw new PluginUIReconcileError("Plugin UI patch exceeds the operation limit");
    }
    operations.push(operation);
  };

  let structurallyChanged = currentIndex.byKey.size !== nextIndex.byKey.size;
  const contentOperations: PluginUIPatchOperation[] = [];
  const replacementKeys = new Set<string>();
  for (const key of nextIndex.order) {
    const leftInfo = currentIndex.byKey.get(key);
    const rightInfo = nextIndex.byKey.get(key);
    const left = leftInfo?.node;
    const right = rightInfo?.node;
    if (!left || !right) {
      structurallyChanged = true;
      continue;
    }
    if (!sameNodeIdentity(left, right)) {
      replacementKeys.add(key);
      structurallyChanged = true;
      continue;
    }
    if (leftInfo.parentKey !== rightInfo.parentKey || leftInfo.childIndex !== rightInfo.childIndex) {
      structurallyChanged = true;
    }
    if (left.type === "text" && right.type === "text") {
      if (left.text !== right.text) contentOperations.push({ type: "set_text", target_key: key, text: right.text });
    } else if (left.type === "element" && right.type === "element") {
      reconcileAttributes(left, right, options.controlEditRevisions, (operation) => contentOperations.push(operation));
    }
  }
  if (replacementKeys.has(current.key)) {
    throw new PluginUIReconcileError("Plugin UI root key and tag are immutable");
  }
  if (!structurallyChanged) {
    if (contentOperations.length > maxOperations) {
      throw new PluginUIReconcileError("Plugin UI patch exceeds the operation limit");
    }
    return contentOperations;
  }

  const removedRoots: string[] = [];
  for (const key of currentIndex.order) {
    if (key === current.key) continue;
    if (nextIndex.byKey.has(key) && !replacementKeys.has(key)) continue;
    let ancestorKey = currentIndex.byKey.get(key)?.parentKey;
    let coveredByRemovedAncestor = false;
    while (ancestorKey) {
      if (!nextIndex.byKey.has(ancestorKey) || replacementKeys.has(ancestorKey)) {
        coveredByRemovedAncestor = true;
        break;
      }
      ancestorKey = currentIndex.byKey.get(ancestorKey)?.parentKey;
    }
    if (!coveredByRemovedAncestor) removedRoots.push(key);
  }

  const removedCoverage = new Set<string>();
  for (const key of removedRoots) {
    collectSubtreeKeys(currentIndex, key, removedCoverage);
    ensureCanvasStable(currentIndex, key, transferredCanvasKeys, "removed or replaced");
    append({ type: "remove_child", target_key: key });
  }

  for (const operation of contentOperations) {
    const targetKey = "target_key" in operation ? operation.target_key : undefined;
    if (!targetKey || !removedCoverage.has(targetKey)) append(operation);
  }

  const coveredByFullInsertion = new Set<string>();
  for (const parentKey of nextIndex.order) {
    if (coveredByFullInsertion.has(parentKey)) continue;
    const parent = nextIndex.byKey.get(parentKey)?.node;
    if (!parent || parent.type !== "element") continue;
    const desiredKeys = nextIndex.byKey.get(parentKey)?.childKeys ?? [];
    const currentSequence = desiredKeys.map((key) => {
      const currentInfo = currentIndex.byKey.get(key);
      if (!currentInfo || removedCoverage.has(key) || currentInfo.parentKey !== parentKey) return -1;
      return currentInfo.childIndex;
    });
    const stablePositions = longestIncreasingSubsequencePositions(currentSequence);
    for (let index = desiredKeys.length - 1; index >= 0; index -= 1) {
      const key = desiredKeys[index];
      const beforeKey = desiredKeys[index + 1] ?? null;
      const currentInfo = currentIndex.byKey.get(key);
      const isAvailable = Boolean(currentInfo && !removedCoverage.has(key));
      if (!isAvailable) {
        const node = nextIndex.byKey.get(key)?.node;
        if (!node) throw new PluginUIReconcileError("Plugin UI insertion index is inconsistent");
        const canInsertFullSubtree = !subtreeContainsAvailableKey(nextIndex, key, currentIndex, removedCoverage);
        const insertion = canInsertFullSubtree ? node : shallowNode(node);
        append({ type: "insert_child", parent_key: parentKey, before_key: beforeKey, node: insertion });
        if (canInsertFullSubtree) collectSubtreeKeys(nextIndex, key, coveredByFullInsertion);
        continue;
      }
      if (currentInfo?.parentKey !== parentKey || !stablePositions.has(index)) {
        ensureCanvasStable(currentIndex, key, transferredCanvasKeys, "moved");
        append({ type: "move_child", target_key: key, parent_key: parentKey, before_key: beforeKey });
      }
    }
  }

  return operations;
}

function indexTree(root: PluginUIElementVNode): TreeIndex {
  const byKey = new Map<string, IndexedNode>();
  const order: string[] = [];
  const visit = (node: PluginUIVNode, parentKey: string | undefined, childIndex: number, depth: number): void => {
    const children = node.type === "element" ? node.children ?? [] : [];
    const childKeys = children.length > 0 ? children.map((child) => child.key) : undefined;
    byKey.set(node.key, { node, parentKey, childIndex, ...(childKeys ? { childKeys } : {}), depth });
    order.push(node.key);
    for (let index = 0; index < children.length; index += 1) {
      visit(children[index], node.key, index, depth + 1);
    }
  };
  visit(root, undefined, 0, 1);
  return { byKey, order };
}

function reconcileAttributes(
  current: PluginUIElementVNode,
  next: PluginUIElementVNode,
  controlEditRevisions: ReadonlyMap<string, number> | undefined,
  append: (operation: PluginUIPatchOperation) => void,
): void {
  const left = current.attributes;
  const right = next.attributes;
  let set: Record<string, PluginUIAttributeValue> | undefined;
  let remove: string[] | undefined;

  for (const name in right) {
    const value = right[name];
    if (!isEditableControlAttribute(current.tag, name) && left?.[name] !== value) {
      (set ??= {})[name] = value;
    }
  }
  for (const name in left) {
    if (!isEditableControlAttribute(current.tag, name) && !(name in (right ?? emptyAttributes))) {
      (remove ??= []).push(name);
    }
  }
  if (set || remove) {
    append({ type: "patch_attributes", target_key: current.key, set: set ?? {}, remove: remove ?? [] });
  }

  const valueChanged = editableValueTags.has(current.tag) && left?.value !== right?.value;
  const checkedChanged = current.tag === "input" && left?.checked !== right?.checked;
  if (valueChanged || checkedChanged) {
    append({
      type: "patch_control",
      target_key: current.key,
      edit_revision: controlEditRevisions?.get(current.key) ?? 0,
      ...(valueChanged ? { value: right?.value === undefined ? null : String(right.value) } : {}),
      ...(checkedChanged ? { checked: right?.checked === undefined ? null : Boolean(right.checked) } : {}),
    });
  }
}

function longestIncreasingSubsequencePositions(values: readonly number[]): Set<number> {
  const tails: number[] = [];
  const predecessors = new Array<number>(values.length).fill(-1);
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value < 0) continue;
    let low = 0;
    let high = tails.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if ((values[tails[middle]] ?? Infinity) < value) low = middle + 1;
      else high = middle;
    }
    if (low > 0) predecessors[index] = tails[low - 1] ?? -1;
    tails[low] = index;
  }
  const positions = new Set<number>();
  let cursor = tails[tails.length - 1] ?? -1;
  while (cursor >= 0) {
    positions.add(cursor);
    cursor = predecessors[cursor] ?? -1;
  }
  return positions;
}

function collectSubtreeKeys(index: TreeIndex, rootKey: string, output: Set<string>): void {
  const stack = [rootKey];
  while (stack.length > 0) {
    const key = stack.pop();
    if (!key || output.has(key)) continue;
    output.add(key);
    stack.push(...(index.byKey.get(key)?.childKeys ?? []));
  }
}

function subtreeContainsAvailableKey(
  nextIndex: TreeIndex,
  rootKey: string,
  currentIndex: TreeIndex,
  removedCoverage: ReadonlySet<string>,
): boolean {
  const stack = [...(nextIndex.byKey.get(rootKey)?.childKeys ?? [])];
  while (stack.length > 0) {
    const key = stack.pop();
    if (!key) continue;
    if (currentIndex.byKey.has(key) && !removedCoverage.has(key)) return true;
    stack.push(...(nextIndex.byKey.get(key)?.childKeys ?? []));
  }
  return false;
}

function shallowNode(node: PluginUIVNode): PluginUIVNode {
  if (node.type === "text") return node;
  return {
    type: "element",
    key: node.key,
    tag: node.tag,
    ...(node.attributes ? { attributes: node.attributes } : {}),
    children: [],
  };
}

function ensureCanvasStable(
  index: TreeIndex,
  rootKey: string,
  transferredCanvasKeys: ReadonlySet<string>,
  action: string,
): void {
  const stack = [rootKey];
  while (stack.length > 0) {
    const key = stack.pop();
    if (!key) continue;
    if (transferredCanvasKeys.has(key)) {
      throw new PluginUIReconcileError(`Transferred canvas ${key} cannot be ${action}`);
    }
    stack.push(...(index.byKey.get(key)?.childKeys ?? []));
  }
}

function sameNodeIdentity(left: PluginUIVNode, right: PluginUIVNode): boolean {
  return left.type === right.type && (left.type === "text" || (right.type === "element" && left.tag === right.tag));
}

function sameAttributes(
  left: Readonly<Record<string, PluginUIAttributeValue>> | undefined,
  right: Readonly<Record<string, PluginUIAttributeValue>> | undefined,
): boolean {
  const leftEntries = Object.entries(left ?? emptyAttributes);
  const rightEntries = Object.entries(right ?? emptyAttributes);
  return leftEntries.length === rightEntries.length && leftEntries.every(([name, value]) => right?.[name] === value);
}

function isEditableControlAttribute(tag: OpaqueSurfaceAllowedTag, name: string): boolean {
  const normalized = name.toLowerCase();
  return (normalized === "value" && editableValueTags.has(tag)) ||
    (normalized === "checked" && tag === "input");
}
