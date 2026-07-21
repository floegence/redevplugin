import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
	canonicalSignatureEnvelope,
	canonicalSigningLedgerEntry,
	canonicalSigningSubject,
	decodeSignatureEnvelope,
	decodeSigningLedgerEntry,
  decodeSigningLedgerEvidence,
	decodeSigningSubject,
	type SignatureEnvelopeV1,
	type SigningLedgerEntryV1,
  type SigningLedgerEvidenceV1,
	type SigningSubjectV1,
	verifySigningLedgerEntryBindings,
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

test("signing ledger subject, envelope, and entry projections are closed and canonical", async () => {
	const wires = JSON.parse(readFileSync(
		new URL("../../../../testdata/contracts/release-signing-ledger-wire-v1.json", import.meta.url),
		"utf8",
	)) as { subject: SigningSubjectV1; envelope: SignatureEnvelopeV1; reserved_entry: SigningLedgerEntryV1 };

	assert.deepEqual(decodeSigningSubject(canonicalSigningSubject(wires.subject)), wires.subject);
	assert.deepEqual(decodeSignatureEnvelope(canonicalSignatureEnvelope(wires.envelope)), wires.envelope);
	assert.deepEqual(decodeSigningLedgerEntry(canonicalSigningLedgerEntry(wires.reserved_entry)), wires.reserved_entry);
	await verifySigningLedgerEntryBindings(wires.reserved_entry);
	let rejected = false;
	try {
		await verifySigningLedgerEntryBindings({ ...wires.reserved_entry, subject_identity_sha256: "0".repeat(64) });
	} catch (error) {
		rejected = true;
		assert.match(String(error), /release contract document is invalid/);
	}
	assert.equal(rejected, true);
	assert.throws(
		() => decodeSigningLedgerEntry(new TextDecoder().decode(canonicalSigningLedgerEntry({
			...wires.reserved_entry,
			state: "finalized",
		}))),
		/release contract document is invalid/,
	);
});
