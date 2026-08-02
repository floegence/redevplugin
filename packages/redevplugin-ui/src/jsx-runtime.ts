import type { OpaqueSurfaceAllowedTag } from "./opaque-surface-policy.gen.js";
import {
  validatePluginUITree,
  type PluginUIAttributeValue,
  type PluginUIElementVNode,
  type PluginUIVNode,
} from "./ui-reconciler.js";

export const Fragment = Symbol("ReDevPlugin.Fragment");

export type PluginUIJSXChild = PluginUIVNode | string | number | boolean | null | undefined | readonly PluginUIJSXChild[];

export type PluginUIJSXProps = {
  children?: PluginUIJSXChild;
  [name: string]: unknown;
};

type PluginUIJSXType = OpaqueSurfaceAllowedTag | typeof Fragment | ((props: PluginUIJSXProps) => unknown);

const keyPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
const attributeAliases = new Map([
  ["autoComplete", "autocomplete"],
  ["className", "class"],
  ["htmlFor", "for"],
  ["maxLength", "maxlength"],
  ["readOnly", "readonly"],
  ["tabIndex", "tabindex"],
]);

export function jsx(type: PluginUIJSXType, props: PluginUIJSXProps | null, key?: string): PluginUIElementVNode {
  return createElement(type, props, key);
}

export function jsxs(type: PluginUIJSXType, props: PluginUIJSXProps | null, key?: string): PluginUIElementVNode {
  return createElement(type, props, key);
}

export function jsxDEV(
  type: PluginUIJSXType,
  props: PluginUIJSXProps | null,
  key?: string,
  _isStaticChildren?: boolean,
  _source?: unknown,
  _self?: unknown,
): PluginUIElementVNode {
  return createElement(type, props, key);
}

function createElement(type: PluginUIJSXType, props: PluginUIJSXProps | null, key: string | undefined): PluginUIElementVNode {
  if (type === Fragment) throw new TypeError("ReDevPlugin JSX does not support Fragment; use one keyed intrinsic element");
  if (typeof type !== "string") throw new TypeError("ReDevPlugin JSX supports intrinsic elements only");
  if (typeof key !== "string" || !keyPattern.test(key)) {
    throw new TypeError("ReDevPlugin JSX elements require a valid stable key");
  }

  const attributes: Record<string, PluginUIAttributeValue> = {};
  const source = props ?? {};
  for (const [rawName, value] of Object.entries(source)) {
    if (rawName === "children" || rawName === "key" || value === undefined) continue;
    const name = attributeAliases.get(rawName) ?? rawName;
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
      throw new TypeError(`ReDevPlugin JSX attribute ${rawName} must be a string, number, or boolean`);
    }
    attributes[name] = value;
  }

  const children: PluginUIVNode[] = [];
  appendChildren(children, source.children, key, []);
  const tree: PluginUIElementVNode = {
    type: "element",
    key,
    tag: type,
    ...(Object.keys(attributes).length > 0 ? { attributes } : {}),
    ...(children.length > 0 ? { children } : {}),
  };
  return validatePluginUITree(tree);
}

function appendChildren(target: PluginUIVNode[], value: PluginUIJSXChild, parentKey: string, path: number[]): void {
  if (value === null || value === undefined || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    value.forEach((child, index) => appendChildren(target, child, parentKey, [...path, index]));
    return;
  }
  if (typeof value === "string" || typeof value === "number") {
    const textPath = path.length > 0 ? path : [0];
    target.push({ type: "text", key: textKey(parentKey, textPath), text: String(value) });
    return;
  }
  if (typeof value === "object") {
    target.push(value as PluginUIVNode);
    return;
  }
  throw new TypeError("ReDevPlugin JSX children must be VNodes or renderable primitive values");
}

function textKey(parentKey: string, path: number[]): string {
  const suffix = `.text.${path.join(".")}`;
  const candidate = parentKey + suffix;
  if (candidate.length <= 128) return candidate;
  const hashSuffix = `.text.${fnv1a(candidate)}`;
  return parentKey.slice(0, 128 - hashSuffix.length) + hashSuffix;
}

function fnv1a(value: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

// TypeScript requires this exact namespace export for automatic JSX typing.
// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace JSX {
  export type Element = PluginUIElementVNode;
  export interface ElementChildrenAttribute {
    children: unknown;
  }
  export interface IntrinsicAttributes {
    key: string;
  }
  export type IntrinsicElements = {
    [Tag in OpaqueSurfaceAllowedTag]: PluginUIJSXProps & { key: string };
  };
}
