#!/usr/bin/env node

import { appendFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const options = parseArgs(process.argv.slice(2));
const reconciler = await import(pathToFileURL(resolve("packages/redevplugin-ui/dist/ui-reconciler.js")));

const element = (key, tag = "div", children = [], attributes) => ({
  type: "element",
  key,
  tag,
  ...(attributes ? { attributes } : {}),
  children,
});

const rows = Array.from({ length: 4095 }, (_, index) => element(`row-${index}`, "p", [], { class: "row" }));
const currentLeaf = reconciler.validatePluginUITree(element("root", "main", rows));
const nextRows = [...rows];
nextRows[2048] = element("row-2048", "p", [], { class: "row", title: "Updated" });
const nextLeaf = reconciler.validatePluginUITree(element("root", "main", nextRows));
const leafDurations = measure(40, () => {
  const operations = reconciler.reconcilePluginUITrees(currentLeaf, nextLeaf);
  if (operations.length !== 1 || operations[0]?.type !== "patch_attributes" || operations[0]?.target_key !== "row-2048") {
    throw new Error("single-leaf reconciliation emitted an unexpected patch");
  }
});
const leafP95 = percentile(leafDurations, 95);
if (leafP95 > 16) {
  throw new Error(`4096-node single-leaf reconciliation p95 ${leafP95.toFixed(3)}ms exceeds 16ms`);
}
record({
  id: "ui.single-leaf-reconciliation",
  gate: options.gate,
  status: "pass",
  sample_count: leafDurations.length,
  metrics: [
    metric("p95", "milliseconds", leafP95, 16, "lte"),
    metric("max", "milliseconds", Math.max(...leafDurations), 50, "lte"),
  ],
});

const keyedChildren = Array.from({ length: 1000 }, (_, index) => element(`item-${index}`));
const currentReverse = reconciler.validatePluginUITree(element("root", "main", keyedChildren));
const nextReverse = reconciler.validatePluginUITree(element("root", "main", [...keyedChildren].reverse()));
const reverseDurations = measure(30, () => {
  const operations = reconciler.reconcilePluginUITrees(currentReverse, nextReverse);
  if (operations.length !== 999 || operations.some((operation) => operation.type !== "move_child")) {
    throw new Error("keyed reversal did not emit the minimal LIS move set");
  }
});
const reverseP95 = percentile(reverseDurations, 95);
if (reverseP95 > 50) {
  throw new Error(`1000-child keyed reversal p95 ${reverseP95.toFixed(3)}ms exceeds 50ms`);
}
record({
  id: "ui.keyed-reversal",
  gate: options.gate,
  status: "pass",
  sample_count: reverseDurations.length,
  metrics: [
    metric("moves", "count", 999, 999, "eq"),
    metric("p95", "milliseconds", reverseP95, 50, "lte"),
  ],
});

function measure(iterations, operation) {
  for (let index = 0; index < 5; index += 1) operation();
  const durations = [];
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now();
    operation();
    durations.push(performance.now() - started);
  }
  return durations;
}

function percentile(values, target) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * target / 100) - 1)] ?? Infinity;
}

function metric(name, unit, observed, limit, comparator) {
  return { name, unit, observed, limit, comparator };
}

function record(scenario) {
  appendFileSync(options.output, `${JSON.stringify(scenario)}\n`, { mode: 0o600 });
}

function parseArgs(args) {
  let output = "";
  let gate = "full";
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--output") output = args[++index] ?? "";
    else if (args[index] === "--gate") gate = args[++index] ?? "";
    else throw new Error(`unknown argument: ${args[index]}`);
  }
  if (!output) throw new Error("--output is required");
  if (!["fast", "weekly", "full", "release"].includes(gate)) throw new Error(`invalid gate: ${gate}`);
  return { output, gate };
}
