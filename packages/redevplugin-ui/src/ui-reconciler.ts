import type { OpaqueSurfaceAllowedTag } from "./opaque-surface-policy.gen.js";
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

const editableValueTags = new Set<OpaqueSurfaceAllowedTag>(["input", "textarea", "select", "option"]);
const maxPluginUIPatchOperations = 1024;

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
  const maxOperations = options.maxOperations ?? maxPluginUIPatchOperations;
  if (!Number.isSafeInteger(maxOperations) || maxOperations < 1 || maxOperations > maxPluginUIPatchOperations) {
    throw new PluginUIReconcileError(`Plugin UI maxOperations must be an integer between 1 and ${maxPluginUIPatchOperations}`);
  }
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
    if (operations.length + estimateKeyedStructuralOperations(working, desired) > maxOperations) {
      throw new PluginUIReconcileError("Plugin UI patch exceeds the operation limit");
    }
    const desiredIndexByKey = keyedChildIndexes(desired);
    for (let index = working.length - 1; index >= 0; index -= 1) {
      const child = working[index];
      if (typeof child === "string") continue;
      const desiredIndex = desiredIndexByKey.get(child.key);
      const desiredChild = desiredIndex === undefined ? undefined : desired[desiredIndex];
      if (typeof desiredChild !== "string" && desiredChild?.tag === child.tag) continue;
      ensureCanvasStable(child, desiredIndex === undefined ? "removed" : "replaced");
      append({ type: "remove_child", parent_key: left.key, child_index: index, child_key: child.key });
      working.splice(index, 1);
    }
    const workingIndexByKey = keyedChildIndexes(working);
    const refreshWorkingIndexes = (start: number, end = working.length - 1): void => {
      for (let index = Math.max(0, start); index <= Math.min(end, working.length - 1); index += 1) {
        const child = working[index];
        if (typeof child !== "string") workingIndexByKey.set(child.key, index);
      }
    };
    for (let index = 0; index < working.length; index += 1) {
      const child = working[index];
      if (typeof child !== "string" && transferredCanvasKeys.has(child.key)) {
        const nextIndex = desiredIndexByKey.get(child.key) ?? -1;
        if (nextIndex === -1) throw new PluginUIReconcileError(`Transferred canvas ${child.key} cannot be removed`);
        if (nextIndex !== index) throw new PluginUIReconcileError(`Transferred canvas ${child.key} cannot be moved`);
      }
    }
    if (fullyKeyed(working) && fullyKeyed(desired)) {
      reconcileKeyedChildren(left.key, working, desired, ensureCanvasStable, append);
      for (let index = 0; index < desired.length; index += 1) {
        const present = working[index];
        const wanted = desired[index];
        if (present === undefined || present.key !== wanted.key || present.tag !== wanted.tag) {
          throw new PluginUIReconcileError("Plugin UI keyed reconciliation became inconsistent");
        }
        reconcileElement(present, wanted);
        working[index] = wanted;
      }
      return;
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
          refreshWorkingIndexes(index);
        }
        continue;
      }

      const foundIndex = typeof present !== "string" && present?.key === wanted.key
        ? index
        : workingIndexByKey.get(wanted.key) ?? -1;
      if (foundIndex === -1) {
        append({ type: "insert_child", parent_key: left.key, child_index: index, node: wanted });
        working.splice(index, 0, wanted);
        refreshWorkingIndexes(index);
        continue;
      }
      const found = working[foundIndex];
      if (typeof found === "string") throw new PluginUIReconcileError("Plugin UI keyed lookup became inconsistent");
      if (found.tag !== wanted.tag) {
        ensureCanvasStable(found, "replaced");
        append({ type: "remove_child", parent_key: left.key, child_index: foundIndex, child_key: found.key });
        working.splice(foundIndex, 1);
        workingIndexByKey.delete(found.key);
        refreshWorkingIndexes(foundIndex);
        append({ type: "insert_child", parent_key: left.key, child_index: index, node: wanted });
        working.splice(index, 0, wanted);
        refreshWorkingIndexes(index);
        continue;
      }
      if (foundIndex !== index) {
        ensureCanvasStable(found, "moved");
        append({ type: "move_child", parent_key: left.key, child_key: found.key, from_index: foundIndex, to_index: index });
        working.splice(foundIndex, 1);
        working.splice(index, 0, found);
        refreshWorkingIndexes(Math.min(foundIndex, index), Math.max(foundIndex, index));
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
      if (typeof removed !== "string") workingIndexByKey.delete(removed.key);
    }
  };

  reconcileElement(current, next);
  return operations;
}

function keyedChildIndexes(children: readonly PluginUIVNode[]): Map<string, number> {
  const indexes = new Map<string, number>();
  for (let index = 0; index < children.length; index += 1) {
    const child = children[index];
    if (typeof child !== "string") indexes.set(child.key, index);
  }
  return indexes;
}

function fullyKeyed(children: PluginUIVNode[]): children is PluginUIElementVNode[];
function fullyKeyed(children: readonly PluginUIVNode[]): children is readonly PluginUIElementVNode[];
function fullyKeyed(children: readonly PluginUIVNode[]): children is readonly PluginUIElementVNode[] {
  return children.every((child) => typeof child !== "string");
}

function reconcileKeyedChildren(
  parentKey: string,
  working: PluginUIElementVNode[],
  desired: readonly PluginUIElementVNode[],
  ensureCanvasStable: (node: PluginUIVNode, action: string) => void,
  append: (operation: PluginUIPatchOperation) => void,
): void {
  const workingIndexByKey = keyedChildIndexes(working);
  const retainedDesiredIndexes: number[] = [];
  const retainedWorkingIndexes: number[] = [];
  for (let desiredIndex = 0; desiredIndex < desired.length; desiredIndex += 1) {
    const currentIndex = workingIndexByKey.get(desired[desiredIndex].key);
    if (currentIndex !== undefined) {
      retainedDesiredIndexes.push(desiredIndex);
      retainedWorkingIndexes.push(currentIndex);
    }
  }
  const stableDesiredIndexes = new Set(
    longestIncreasingSubsequenceIndexes(retainedWorkingIndexes).map((retainedIndex) => retainedDesiredIndexes[retainedIndex]),
  );
  const refreshWorkingIndexes = (start: number): void => {
    for (let index = Math.max(0, start); index < working.length; index += 1) {
      workingIndexByKey.set(working[index].key, index);
    }
  };

  for (let desiredIndex = desired.length - 1; desiredIndex >= 0; desiredIndex -= 1) {
    const wanted = desired[desiredIndex];
    const foundIndex = workingIndexByKey.get(wanted.key);
    const anchor = desired[desiredIndex + 1];
    const anchorIndex = anchor === undefined ? working.length : workingIndexByKey.get(anchor.key);
    if (anchorIndex === undefined) {
      throw new PluginUIReconcileError("Plugin UI keyed anchor became inconsistent");
    }
    if (foundIndex === undefined) {
      append({ type: "insert_child", parent_key: parentKey, child_index: anchorIndex, node: wanted });
      working.splice(anchorIndex, 0, wanted);
      refreshWorkingIndexes(anchorIndex);
      continue;
    }
    if (stableDesiredIndexes.has(desiredIndex)) continue;

    const toIndex = foundIndex < anchorIndex ? anchorIndex - 1 : anchorIndex;
    if (foundIndex === toIndex) continue;
    const found = working[foundIndex];
    ensureCanvasStable(found, "moved");
    append({
      type: "move_child",
      parent_key: parentKey,
      child_key: found.key,
      from_index: foundIndex,
      to_index: toIndex,
    });
    working.splice(foundIndex, 1);
    working.splice(toIndex, 0, found);
    refreshWorkingIndexes(Math.min(foundIndex, toIndex));
  }
}

function estimateKeyedStructuralOperations(
  current: readonly PluginUIVNode[],
  next: readonly PluginUIVNode[],
): number {
  const currentIndexes = keyedChildIndexes(current);
  const currentByKey = keyedChildren(current);
  const nextByKey = keyedChildren(next);
  const retainedIndexes: number[] = [];
  let inserted = 0;
  for (const child of next) {
    if (typeof child === "string") continue;
    const currentIndex = currentIndexes.get(child.key);
    const currentChild = currentByKey.get(child.key);
    if (currentIndex === undefined || currentChild?.tag !== child.tag) inserted += 1;
    else retainedIndexes.push(currentIndex);
  }
  let removed = 0;
  for (const [key, child] of currentByKey) {
    const nextChild = nextByKey.get(key);
    if (!nextChild || nextChild.tag !== child.tag) removed += 1;
  }
  return inserted + removed + retainedIndexes.length - longestIncreasingSubsequenceIndexes(retainedIndexes).length;
}

function keyedChildren(children: readonly PluginUIVNode[]): Map<string, PluginUIElementVNode> {
  const keyed = new Map<string, PluginUIElementVNode>();
  for (const child of children) {
    if (typeof child !== "string") keyed.set(child.key, child);
  }
  return keyed;
}

function longestIncreasingSubsequenceIndexes(values: readonly number[]): number[] {
  const predecessors = new Array<number>(values.length).fill(-1);
  const tailIndexes: number[] = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    let low = 0;
    let high = tailIndexes.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if ((values[tailIndexes[middle]] ?? Infinity) < value) low = middle + 1;
      else high = middle;
    }
    if (low > 0) predecessors[index] = tailIndexes[low - 1] ?? -1;
    tailIndexes[low] = index;
  }

  const indexes = new Array<number>(tailIndexes.length);
  let cursor = tailIndexes[tailIndexes.length - 1] ?? -1;
  for (let index = indexes.length - 1; index >= 0; index -= 1) {
    indexes[index] = cursor;
    cursor = predecessors[cursor] ?? -1;
  }
  return indexes;
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
