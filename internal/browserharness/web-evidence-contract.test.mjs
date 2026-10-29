import assert from "node:assert/strict";
import test from "node:test";
import { validateWebEvidence, webEvidenceChecks } from "../../scripts/verify_web_evidence.mjs";
const fixture = () => ({ schema_version: "redevplugin.web_acceptance.v1", evidence_source: "go-host-http-adapter-chromium", browser: "156.0", checks: Object.fromEntries(webEvidenceChecks.map(key => [key, true])) });
test("Web evidence requires every browser acceptance outcome", () => {
 assert.doesNotThrow(() => validateWebEvidence(fixture()));
 for (const key of webEvidenceChecks) { const report = fixture(); report.checks[key] = false; assert.throws(() => validateWebEvidence(report), /missing Web evidence/); }
});
test("Web evidence does not relabel mocked or retired evidence", () => {
 for (const evidence_source of ["go-host-http-adapter-rust-runtime-chromium", "mock-host", undefined]) assert.throws(() => validateWebEvidence({ ...fixture(), evidence_source }), /identity/);
 const report = fixture(); report.checks.opaque_origin = true; assert.throws(() => validateWebEvidence(report), /checks/);
});
