#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseDocument } from "yaml";

export const pinnedCheckoutAction = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5";
export const completeHistoryJobs = Object.freeze([
  "pre-push-main-equivalent",
  "release-bundle-smoke",
]);
const root = resolve(import.meta.dirname, "..");
export const requiredWorkflowJobs = Object.freeze([
  Object.freeze({ path: ".github/workflows/ci.yml", jobIDs: completeHistoryJobs }),
  Object.freeze({ path: ".github/workflows/stress.yml", jobIDs: Object.freeze(["stress-full"]) }),
  Object.freeze({
    path: ".github/workflows/release.yml",
    jobIDs: Object.freeze(["stress-release", "performance-release"]),
  }),
]);

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const workflow of requiredWorkflowJobs) {
    verifyWorkflowCheckoutHistory(
      readFileSync(join(root, workflow.path), "utf8"),
      workflow.jobIDs,
      workflow.path,
    );
  }
}

export function verifyCICheckoutHistory(source) {
  verifyWorkflowCheckoutHistory(source, completeHistoryJobs, ".github/workflows/ci.yml");
}

export function verifyWorkflowCheckoutHistory(source, jobIDs, workflowPath) {
  if (!Array.isArray(jobIDs) || jobIDs.length === 0) {
    throw new Error(`${workflowPath} must declare at least one complete-history job`);
  }
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length > 0) {
    throw new Error(`${workflowPath} YAML is invalid: ${document.errors[0].message}`);
  }
  const workflow = document.toJS();
  if (!isRecord(workflow) || !isRecord(workflow.jobs)) {
    throw new Error(`${workflowPath} must define a jobs mapping`);
  }

  for (const jobID of jobIDs) {
    const job = workflow.jobs[jobID];
    if (!isRecord(job) || !Array.isArray(job.steps)) {
      throw new Error(`${jobID} must define a steps sequence`);
    }
    const checkoutSteps = job.steps.filter((step) =>
      isRecord(step) && typeof step.uses === "string" && step.uses.startsWith("actions/checkout@"));
    if (checkoutSteps.length !== 1) {
      throw new Error(`${jobID} must define exactly one checkout step`);
    }
    const checkout = checkoutSteps[0];
    if (checkout.uses !== pinnedCheckoutAction) {
      throw new Error(`${jobID} must use the pinned checkout action ${pinnedCheckoutAction}`);
    }
    if (!isRecord(checkout.with) || checkout.with["fetch-depth"] !== 0) {
      throw new Error(`${jobID} checkout must set fetch-depth: 0`);
    }
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
