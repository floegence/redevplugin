import assert from "node:assert/strict";
import test from "node:test";

import {
  requiredWorkflowJobs,
  verifyWorkflowCheckoutHistory,
} from "./verify_ci_checkout_history.mjs";

const checkout = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5";

test("formal release history jobs are the complete-history closed set", () => {
  assert.deepEqual(requiredWorkflowJobs, [{
    path: ".github/workflows/release.yml",
    jobIDs: ["preflight"],
  }]);
});

test("formal release preflight requires pinned complete-history checkout", () => {
  const shallowRelease = `
name: Release
jobs:
  preflight:
    steps:
      - uses: ${checkout}
`;
  assert.throws(
    () => verifyWorkflowCheckoutHistory(
      shallowRelease,
      requiredWorkflowJobs[0].jobIDs,
      requiredWorkflowJobs[0].path,
    ),
    /preflight.*fetch-depth/,
  );
});

test("complete-history verification rejects unpinned checkout", () => {
  const workflow = `
name: Release
jobs:
  release:
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
`;
  assert.throws(
    () => verifyWorkflowCheckoutHistory(workflow, ["release"], ".github/workflows/release.yml"),
    /pinned checkout/,
  );
});

function validCheckout() {
  return `
      - uses: ${checkout}
        with:
          fetch-depth: 0
  `;
}
