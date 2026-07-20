import assert from "node:assert/strict";
import test from "node:test";

import {
  requiredWorkflowJobs,
  verifyCICheckoutHistory,
  verifyWorkflowCheckoutHistory,
} from "./verify_ci_checkout_history.mjs";

const checkout = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5";

test("required CI jobs fetch complete history through the pinned checkout step", () => {
  assert.doesNotThrow(() => verifyCICheckoutHistory(workflow(`
      - uses: ${checkout}
        with:
          fetch-depth: 0
  `, `
      - uses: ${checkout}
        with:
          fetch-depth: 0
  `)));
});

test("checkout history verification rejects comments and unrelated action inputs", () => {
  assert.throws(() => verifyCICheckoutHistory(workflow(`
      - uses: ${checkout}
        # fetch-depth: 0
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff
        with:
          fetch-depth: 0
  `, validCheckout())), /pre-push-main-equivalent.*fetch-depth/);
});

test("checkout history verification cannot match a following job", () => {
  assert.throws(() => verifyCICheckoutHistory(`${workflow(`
      - uses: ${checkout}
  `, validCheckout())}
  later-job:
    steps:
      - uses: ${checkout}
        with:
          fetch-depth: 0
`), /pre-push-main-equivalent.*fetch-depth/);
});

test("checkout history verification rejects unpinned or duplicate checkout steps", () => {
  assert.throws(() => verifyCICheckoutHistory(workflow(`
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
  `, validCheckout())), /pre-push-main-equivalent.*pinned checkout/);
  assert.throws(() => verifyCICheckoutHistory(workflow(`
      - uses: ${checkout}
        with:
          fetch-depth: 0
      - uses: ${checkout}
        with:
          fetch-depth: 0
  `, validCheckout())), /pre-push-main-equivalent.*exactly one checkout/);
});

test("full stress workflow requires complete history for release performance measurement", () => {
  const shallowStress = `
name: Stress Gate
jobs:
  stress-full:
    steps:
      - uses: ${checkout}
`;
  assert.throws(
    () => verifyWorkflowCheckoutHistory(shallowStress, ["stress-full"], ".github/workflows/stress.yml"),
    /stress-full.*fetch-depth/,
  );
  assert.doesNotThrow(() => verifyWorkflowCheckoutHistory(`
name: Stress Gate
jobs:
  stress-full:
    steps:
${validCheckout()}
`, ["stress-full"], ".github/workflows/stress.yml"));
});

test("formal release performance jobs are part of the complete-history closed set", () => {
  const releaseWorkflow = requiredWorkflowJobs.find((workflow) =>
    workflow.path === ".github/workflows/release.yml");
  assert.deepEqual(releaseWorkflow?.jobIDs, ["stress-release", "performance-release"]);

  const shallowRelease = `
name: Release
jobs:
  stress-release:
    steps:
${validCheckout()}
  performance-release:
    steps:
      - uses: ${checkout}
`;
  assert.throws(
    () => verifyWorkflowCheckoutHistory(shallowRelease, releaseWorkflow.jobIDs, releaseWorkflow.path),
    /performance-release.*fetch-depth/,
  );
});

function validCheckout() {
  return `
      - uses: ${checkout}
        with:
          fetch-depth: 0
  `;
}

function workflow(prePushSteps, releaseSteps) {
  return `
name: CI
jobs:
  pre-push-main-equivalent:
    steps:
${prePushSteps}
  release-bundle-smoke:
    steps:
${releaseSteps}
`;
}
