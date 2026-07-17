#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { readPerformanceContract, validatePerformanceEvidence } from "./performance_contract.mjs";

const options = parseArgs(process.argv.slice(2));
const inputBytes = readFileSync(resolve(options.input));
const evidence = JSON.parse(inputBytes.toString("utf8"));
const compatibility = JSON.parse(readFileSync(resolve(options.compatibility), "utf8"));
const contract = readPerformanceContract(resolve(options.contract));
validatePerformanceEvidence(evidence, contract, {
  expectedGate: "release",
  releaseVersion: options.version,
  sourceCommit: options.sourceCommit,
  generatedAt: options.generatedAt,
  contractHashes: compatibility.contracts,
});
writeFileSync(resolve(options.output), inputBytes, { mode: 0o600 });

function parseArgs(args) {
  const options = {
    input: "",
    output: "",
    contract: "",
    compatibility: "",
    version: "",
    sourceCommit: "",
    generatedAt: "",
  };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[++index] ?? "";
    if (flag === "--input") options.input = value;
    else if (flag === "--output") options.output = value;
    else if (flag === "--contract") options.contract = value;
    else if (flag === "--compatibility") options.compatibility = value;
    else if (flag === "--version") options.version = value;
    else if (flag === "--source-commit") options.sourceCommit = value;
    else if (flag === "--generated-at") options.generatedAt = value;
    else throw new Error(`unknown argument: ${flag}`);
  }
  for (const [key, value] of Object.entries(options)) {
    if (!value) throw new Error(`--${key.replaceAll(/[A-Z]/g, (match) => `-${match.toLowerCase()}`)} is required`);
  }
  return options;
}
