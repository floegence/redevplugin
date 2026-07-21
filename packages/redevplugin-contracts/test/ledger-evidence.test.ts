import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  decodeSigningLedgerEvidence,
  type SigningLedgerEvidenceV1,
} from "../src/index.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../../testdata/contracts/release-signing-ledger-evidence-v1.json", import.meta.url),
  "utf8",
)) as SigningLedgerEvidenceV1;

test("signing ledger evidence projection is closed and canonical", () => {
  const canonical = JSON.stringify(fixture, Object.keys(fixture).sort());
  assert.deepEqual(decodeSigningLedgerEvidence(canonical), fixture);
  assert.throws(
    () => decodeSigningLedgerEvidence(JSON.stringify({ ...fixture, unknown: true }, Object.keys({ ...fixture, unknown: true }).sort())),
    /release contract document is invalid/,
  );
  assert.throws(
    () => decodeSigningLedgerEvidence(JSON.stringify({ ...fixture, consistency_proof_sha256: undefined }, Object.keys(fixture).sort())),
    /release contract document is invalid/,
  );
});
