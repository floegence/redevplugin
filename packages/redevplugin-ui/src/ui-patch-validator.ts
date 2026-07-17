import {
  opaqueSurfaceAllowedTags,
  opaqueSurfaceGlobalAttributes,
  opaqueSurfaceRenderLimits,
  opaqueSurfaceSafeInputTypes,
  opaqueSurfaceTagAttributes,
  type OpaqueSurfaceAllowedTag,
} from "./opaque-surface-policy.gen.js";

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

export class PluginUIReconcileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PluginUIReconcileError";
  }
}

const keyPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
const identifierPattern = new RegExp("^[A-Za-z0-9._:-]{1,128}$");
const opaqueHandlePattern = new RegExp("^[A-Za-z0-9_-]{8,160}$");
const allowedTags = new Set<string>(opaqueSurfaceAllowedTags);
const globalAttributes = new Set<string>(opaqueSurfaceGlobalAttributes);
const safeInputTypes = new Set<string>(opaqueSurfaceSafeInputTypes);
const tagAttributes = new Map<string, ReadonlySet<string>>(
  Object.entries(opaqueSurfaceTagAttributes).map(([tag, attributes]) => [tag, new Set<string>(attributes)]),
);

export function validatePluginUITree(tree: PluginUIVNode): PluginUIElementVNode {
  if (!isElement(tree)) {
    throw new PluginUIReconcileError("Plugin UI root must be one keyed element");
  }
  const keys = new Set<string>();
  const ancestors = new Set<object>();
  let nodes = 0;

  const visit = (node: PluginUIVNode, depth: number): void => {
    nodes += 1;
    if (nodes > opaqueSurfaceRenderLimits.max_render_nodes || depth > opaqueSurfaceRenderLimits.max_render_depth) {
      throw new PluginUIReconcileError("Plugin UI tree exceeds structural limits");
    }
    if (typeof node === "string") {
      if (node.length > opaqueSurfaceRenderLimits.max_text_length) throw new PluginUIReconcileError("Plugin UI text exceeds limits");
      return;
    }
    if (!isElement(node) || ancestors.has(node)) {
      throw new PluginUIReconcileError("Plugin UI tree must contain plain acyclic VNodes");
    }
    ancestors.add(node);
    try {
      if (!keyPattern.test(node.key) || keys.has(node.key)) {
        throw new PluginUIReconcileError(`Plugin UI key is invalid or duplicated: ${String(node.key)}`);
      }
      keys.add(node.key);
      if (!allowedTags.has(node.tag)) {
        throw new PluginUIReconcileError(`Plugin UI tag is not allowed for ${node.key}`);
      }
      if (node.attributes !== undefined) {
        if (!isPlainRecord(node.attributes) || Object.keys(node.attributes).length > opaqueSurfaceRenderLimits.max_attributes_per_element) {
          throw new PluginUIReconcileError(`Plugin UI attributes are invalid for ${node.key}`);
        }
        for (const [name, value] of Object.entries(node.attributes)) {
          if (!validAttribute(node.tag, name, value)) {
            throw new PluginUIReconcileError(`Plugin UI attribute ${name} is not allowed for ${node.key}`);
          }
        }
      }
      if (node.children !== undefined) {
        if (!Array.isArray(node.children)) throw new PluginUIReconcileError(`Plugin UI children are invalid for ${node.key}`);
        for (const child of node.children) visit(child, depth + 1);
      }
    } finally {
      ancestors.delete(node);
    }
  };

  visit(tree, 1);
  return tree;
}

function isElement(value: unknown): value is PluginUIElementVNode {
  if (!isPlainRecord(value)) return false;
  return Object.keys(value).every((key) => ["type", "key", "tag", "attributes", "children"].includes(key)) &&
    value.type === "element" && typeof value.key === "string" && typeof value.tag === "string";
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validAttribute(tag: string, name: string, value: unknown): value is PluginUIAttributeValue {
  const normalized = name.toLowerCase();
  if (normalized.startsWith("on") || ["style", "src", "srcset", "href", "srcdoc", "action", "formaction"].includes(normalized)) {
    return false;
  }
  if (!globalAttributes.has(normalized) && !normalized.startsWith("aria-") && !tagAttributes.get(tag)?.has(normalized)) {
    return false;
  }
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") return false;
  if (typeof value === "number" && !Number.isFinite(value)) return false;
  const serialized = String(value);
  if (normalized === "data-redevplugin-action" || normalized === "data-redevplugin-escape-action") {
    if (!identifierPattern.test(serialized)) return false;
  }
  if (normalized === "data-redevplugin-asset-binding") {
    if (!serialized.startsWith("asset_") || !opaqueHandlePattern.test(serialized)) return false;
  }
  if (normalized === "data-redevplugin-asset-attr" && serialized !== "src" && serialized !== "poster") return false;
  if (normalized === "data-redevplugin-canvas" && (tag !== "canvas" || !keyPattern.test(serialized))) return false;
  if (tag === "canvas" && (normalized === "width" || normalized === "height") &&
      (!/^[1-9][0-9]{0,4}$/.test(serialized) || Number(serialized) > opaqueSurfaceRenderLimits.max_canvas_dimension)) return false;
  if (tag === "input" && normalized === "type" && !safeInputTypes.has(serialized.trim().toLowerCase() || "text")) return false;
  return serialized.length <= opaqueSurfaceRenderLimits.max_attribute_value_length;
}
