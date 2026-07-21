import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  InvalidReleaseDocumentError,
  buildPackageSignature,
  buildReleaseMetadata,
  buildRevocation,
  buildRevocationPointer,
  buildRootDelegation,
  buildSourcePolicy,
  buildSourcePolicyPointer,
  canonicalPackageSignature,
  canonicalReleaseMetadata,
  canonicalRevocation,
  canonicalRevocationPointer,
  canonicalRootDelegation,
  canonicalSourcePolicy,
  canonicalSourcePolicyPointer,
  createEd25519Verifier,
  decodePackageSignature,
  decodeReleaseMetadata,
  decodeRevocation,
  decodeRevocationPointer,
  decodeRootDelegation,
  decodeSourcePolicy,
  decodeSourcePolicyPointer,
  packageSigningPreimage,
  releaseMetadataSigningPreimage,
  revocationPointerSigningPreimage,
  revocationSigningPreimage,
  rootDelegationSigningPreimage,
  signingUsages,
  sourcePolicyPointerSigningPreimage,
  sourcePolicySigningPreimage,
  verifyPackageSignature,
  verifyReleaseMetadata,
  verifyRevocation,
  verifyRevocationPointer,
  verifyRootDelegation,
  verifySourcePolicy,
  verifySourcePolicyPointer,
  type PackageSignatureV1,
  type PackageVerificationContext,
  type ReleaseMetadataV5,
  type RevocationPointerV1,
  type RevocationV2,
  type RootDelegationV1,
  type SigningUsage,
  type SourcePolicyPointerV1,
  type SourcePolicyV2,
} from "../src/index.js";

type Fixture = Readonly<{
  public_key_base64: string;
  release_metadata_channel: string;
  package_context: PackageVerificationContext;
  documents: Readonly<{
    root_delegation: RootDelegationV1;
    package_signature: PackageSignatureV1;
    release_metadata: ReleaseMetadataV5;
    source_policy: SourcePolicyV2;
    source_policy_pointer: SourcePolicyPointerV1;
    revocation: RevocationV2;
    revocation_pointer: RevocationPointerV1;
  }>;
  detached_signatures: Readonly<{ release_metadata: string }>;
  preimages: Readonly<Record<SigningUsage, string>>;
  signatures: Readonly<Record<SigningUsage, string>>;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../../testdata/contracts/release-signing-v1.json", import.meta.url),
  "utf8",
)) as Fixture;
const publicKey = decodeBase64(fixture.public_key_base64);
const verifier = createEd25519Verifier({ test_signing_key: publicKey });
const usageOrder = [
  signingUsages.rootDelegation,
  signingUsages.package,
  signingUsages.releaseMetadata,
  signingUsages.sourcePolicy,
  signingUsages.sourcePolicyPointer,
  signingUsages.revocation,
  signingUsages.revocationPointer,
] as const;

test("release signing projection matches every shared canonical preimage", () => {
  const documents = fixture.documents;
  const preimages = new Map<SigningUsage, Uint8Array>([
    [signingUsages.rootDelegation, rootDelegationSigningPreimage(withoutSignature(documents.root_delegation))],
    [signingUsages.package, packageSigningPreimage({
      ...fixture.package_context,
      algorithm: documents.package_signature.algorithm,
      key_id: documents.package_signature.key_id,
      publisher_id: documents.package_signature.publisher_id!,
      plugin_id: documents.package_signature.plugin_id!,
      package_hash: documents.package_signature.package_hash,
      manifest_hash: documents.package_signature.manifest_hash,
      entries_hash: documents.package_signature.entries_hash,
      signed_at: documents.package_signature.signed_at!,
    })],
    [signingUsages.releaseMetadata, releaseMetadataSigningPreimage(fixture.release_metadata_channel, documents.release_metadata)],
    [signingUsages.sourcePolicy, sourcePolicySigningPreimage(withoutSignature(documents.source_policy))],
    [signingUsages.sourcePolicyPointer, sourcePolicyPointerSigningPreimage(withoutSignature(documents.source_policy_pointer))],
    [signingUsages.revocation, revocationSigningPreimage(withoutSignature(documents.revocation))],
    [signingUsages.revocationPointer, revocationPointerSigningPreimage(withoutSignature(documents.revocation_pointer))],
  ]);

  for (const usage of usageOrder) {
    assert.equal(encodeBase64(preimages.get(usage)!), fixture.preimages[usage], usage);
  }
});

test("release signing projection verifies all domains and rejects the 7x6 substitution matrix", async () => {
  const documents = fixture.documents;
  await verifyRootDelegation(documents.root_delegation, verifier);
  await verifyPackageSignature(fixture.package_context, documents.package_signature, verifier);
  await verifyReleaseMetadata(fixture.release_metadata_channel, documents.release_metadata, decodeBase64(fixture.detached_signatures.release_metadata), verifier);
  await verifySourcePolicy(documents.source_policy, verifier);
  await verifySourcePolicyPointer(documents.source_policy_pointer, verifier);
  await verifyRevocation(documents.revocation, verifier);
  await verifyRevocationPointer(documents.revocation_pointer, verifier);

  for (const signedUsage of usageOrder) {
    for (const verifiedUsage of usageOrder) {
      const valid = await verifier({
        usage: verifiedUsage,
        keyID: "test_signing_key",
        signingPreimageSHA256: new Uint8Array(await globalThis.crypto.subtle.digest(
          "SHA-256",
          Uint8Array.from(decodeBase64(fixture.preimages[verifiedUsage])).buffer,
        )),
        signature: decodeBase64(fixture.signatures[signedUsage]),
      });
      assert.equal(valid, signedUsage === verifiedUsage, `${signedUsage} as ${verifiedUsage}`);
    }
  }
});

test("release signing builders and strict decoders preserve canonical documents", () => {
  const documents = fixture.documents;
  const signature = (value: string) => decodeBase64(value);
  assert.deepEqual(buildRootDelegation(withoutSignature(documents.root_delegation), signature(documents.root_delegation.signature)), documents.root_delegation);
  assert.deepEqual(buildPackageSignature({
    ...fixture.package_context,
    algorithm: documents.package_signature.algorithm,
    key_id: documents.package_signature.key_id,
    publisher_id: documents.package_signature.publisher_id!,
    plugin_id: documents.package_signature.plugin_id!,
    package_hash: documents.package_signature.package_hash,
    manifest_hash: documents.package_signature.manifest_hash,
    entries_hash: documents.package_signature.entries_hash,
    signed_at: documents.package_signature.signed_at!,
  }, signature(documents.package_signature.signature)), documents.package_signature);
  assert.deepEqual(buildReleaseMetadata(documents.release_metadata), documents.release_metadata);
  assert.deepEqual(buildSourcePolicy(withoutSignature(documents.source_policy), signature(documents.source_policy.signature)), documents.source_policy);
  assert.deepEqual(buildSourcePolicyPointer(withoutSignature(documents.source_policy_pointer), signature(documents.source_policy_pointer.signature)), documents.source_policy_pointer);
  assert.deepEqual(buildRevocation(withoutSignature(documents.revocation), signature(documents.revocation.signature)), documents.revocation);
  assert.deepEqual(buildRevocationPointer(withoutSignature(documents.revocation_pointer), signature(documents.revocation_pointer.signature)), documents.revocation_pointer);

  const cases: readonly [Uint8Array, (raw: Uint8Array | string) => unknown][] = [
    [canonicalRootDelegation(documents.root_delegation), decodeRootDelegation],
    [canonicalPackageSignature(fixture.package_context, documents.package_signature), (raw) => decodePackageSignature(raw, fixture.package_context)],
    [canonicalReleaseMetadata(documents.release_metadata), decodeReleaseMetadata],
    [canonicalSourcePolicy(documents.source_policy), decodeSourcePolicy],
    [canonicalSourcePolicyPointer(documents.source_policy_pointer), decodeSourcePolicyPointer],
    [canonicalRevocation(documents.revocation), decodeRevocation],
    [canonicalRevocationPointer(documents.revocation_pointer), decodeRevocationPointer],
  ];
  const decoder = new TextDecoder();
  for (const [raw, decode] of cases) {
    assert.ok(decode(raw));
    const source = decoder.decode(raw);
    for (const invalid of [
      ` ${source}`,
      `${source} true`,
      `${source.slice(0, -1)},"unknown":true}`,
      `${source.slice(0, -1)},"schema_version":"duplicate"}`,
    ]) {
      assert.throws(() => decode(invalid), InvalidReleaseDocumentError);
    }
  }
});

test("root delegation keeps source-wide and channel-scoped usages disjoint", () => {
  const key = fixture.documents.root_delegation.delegated_keys[0]!;
  const sourceWide: RootDelegationV1 = {
    ...fixture.documents.root_delegation,
    delegated_keys: [{ ...key, usages: ["signing_ledger", "trusted_time"], channels: [] }],
  };
  canonicalRootDelegation(sourceWide);
  assert.throws(
    () => canonicalRootDelegation({ ...sourceWide, delegated_keys: [{ ...sourceWide.delegated_keys[0]!, channels: ["stable"] }] }),
    InvalidReleaseDocumentError,
  );
  assert.throws(
    () => canonicalRootDelegation({
      ...sourceWide,
      delegated_keys: [{ ...sourceWide.delegated_keys[0]!, usages: ["package", "signing_ledger"], channels: ["stable"] }],
    }),
    InvalidReleaseDocumentError,
  );
});

test("release signing APIs reject runtime shape coercion and schema limit drift", () => {
  const documents = fixture.documents;
  const signature = decodeBase64(documents.root_delegation.signature);
  const rootInput = withoutSignature(documents.root_delegation);

  assert.throws(() => buildRootDelegation({ ...rootInput, unknown: true } as never, signature), InvalidReleaseDocumentError);

  const numericEpoch = new TextDecoder()
    .decode(canonicalRootDelegation(documents.root_delegation))
    .replace('"root_epoch":"1"', '"root_epoch":1');
  assert.throws(() => decodeRootDelegation(numericEpoch), InvalidReleaseDocumentError);

  assert.throws(() => buildReleaseMetadata({
    ...documents.release_metadata,
    distribution_ref: null,
  } as never), InvalidReleaseDocumentError);
  assert.throws(() => buildReleaseMetadata({
    ...documents.release_metadata,
    metadata: { invalid: "\ud800" },
  }), InvalidReleaseDocumentError);

  const artifactHosts = Array.from({ length: 1025 }, (_, index) => `host-${index.toString().padStart(4, "0")}.example`);
  assert.throws(() => buildSourcePolicy({
    ...withoutSignature(documents.source_policy),
    allowed_artifact_hosts: artifactHosts,
  }, decodeBase64(documents.source_policy.signature)), InvalidReleaseDocumentError);
});

function withoutSignature<T extends Readonly<{ schema_version: string; signature: string }>>(
  value: T,
): Omit<T, "schema_version" | "signature"> {
  const input = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
  delete input.schema_version;
  delete input.signature;
  return input as Omit<T, "schema_version" | "signature">;
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (item) => item.charCodeAt(0));
}

function encodeBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}
