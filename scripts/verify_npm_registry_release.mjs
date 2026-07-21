#!/usr/bin/env node

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const repositoryURL = "https://github.com/floegence/redevplugin";
const workflowPath = ".github/workflows/release.yml";
const slsaPredicateType = "https://slsa.dev/provenance/v1";
const workflowBuildType = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1";
const packages = Object.freeze({
  "@floegence/redevplugin-contracts": Object.freeze({
    encodedName: "@floegence%2fredevplugin-contracts",
    repositoryDirectory: "packages/redevplugin-contracts",
    tarballFilename: "redevplugin-contracts",
    purlName: "%40floegence/redevplugin-contracts",
  }),
  "@floegence/redevplugin-ui": Object.freeze({
    encodedName: "@floegence%2fredevplugin-ui",
    repositoryDirectory: "packages/redevplugin-ui",
    tarballFilename: "redevplugin-ui",
    purlName: "%40floegence/redevplugin-ui",
  }),
});

export async function verifyNpmRegistryRelease({
  packageName = "@floegence/redevplugin-ui",
  version,
  sourceCommit,
  expectedIntegrity,
  registryBaseURL = "https://registry.npmjs.org",
  fetchImpl = globalThis.fetch,
}) {
  validateInputs(packageName, version, sourceCommit, expectedIntegrity, registryBaseURL, fetchImpl);
  const packageConfig = packages[packageName];
  const registry = new URL(registryBaseURL);
  const registryOrigin = registry.origin;
  const packageMetadataURL = new URL(`/${packageConfig.encodedName}/${version}`, registryOrigin);
  const metadata = await fetchJSON(fetchImpl, packageMetadataURL, "npm package metadata");

  assertRecord(metadata, "npm package metadata");
  assertEqual(metadata.name, packageName, "npm package name");
  assertEqual(metadata.version, version, "npm package version");
  if (metadata.gitHead !== undefined) {
    assertEqual(metadata.gitHead, sourceCommit, "npm package gitHead");
  }
  assertRecord(metadata.repository, "npm repository metadata");
  assertEqual(metadata.repository.type, "git", "npm repository type");
  assertEqual(metadata.repository.url, `git+${repositoryURL}.git`, "npm repository URL");
  assertEqual(metadata.repository.directory, packageConfig.repositoryDirectory, "npm repository directory");

  const dist = metadata.dist;
  assertRecord(dist, "npm dist metadata");
  assertEqual(dist.integrity, expectedIntegrity, "npm dist integrity");
  const tarballURL = assertRegistryURL(
    dist.tarball,
    registryOrigin,
    `/${packageName}/-/${packageConfig.tarballFilename}-${version}.tgz`,
    "npm tarball URL",
  );
  const tarballBytes = await fetchBytes(fetchImpl, tarballURL, "npm tarball");
  const actualIntegrity = `sha512-${createHash("sha512").update(tarballBytes).digest("base64")}`;
  assertEqual(actualIntegrity, expectedIntegrity, "downloaded npm tarball integrity");
  const tarballSHA512 = createHash("sha512").update(tarballBytes).digest("hex");

  assertRecord(dist.attestations, "npm dist attestations");
  assertRecord(dist.attestations.provenance, "npm provenance metadata");
  assertEqual(dist.attestations.provenance.predicateType, slsaPredicateType, "npm provenance predicate type");
  const attestationURL = assertRegistryURL(
    dist.attestations.url,
    registryOrigin,
    `/-/npm/v1/attestations/${packageName}@${version}`,
    "npm attestation URL",
  );
  const attestationResponse = await fetchJSON(fetchImpl, attestationURL, "npm attestations");
  verifySLSAAttestation(attestationResponse, { packageName, packageConfig, version, sourceCommit, tarballSHA512 });

  return { packageName, version, sourceCommit, integrity: actualIntegrity, tarballSHA512 };
}

function verifySLSAAttestation(response, { packageName, packageConfig, version, sourceCommit, tarballSHA512 }) {
  assertRecord(response, "npm attestation response");
  assertArray(response.attestations, "npm attestations");
  const matching = response.attestations.filter((entry) => entry?.predicateType === slsaPredicateType);
  if (matching.length !== 1) {
    fail(`npm attestations must contain exactly one ${slsaPredicateType} entry, found ${matching.length}`);
  }
  const attestation = matching[0];
  assertRecord(attestation.bundle, "npm SLSA bundle");
  if (typeof attestation.bundle.mediaType !== "string" || !attestation.bundle.mediaType.startsWith("application/vnd.dev.sigstore.bundle")) {
    fail("npm SLSA bundle mediaType is invalid");
  }
  assertRecord(attestation.bundle.verificationMaterial, "npm SLSA verification material");
  assertRecord(attestation.bundle.verificationMaterial.certificate, "npm SLSA certificate");
  assertNonEmptyString(attestation.bundle.verificationMaterial.certificate.rawBytes, "npm SLSA certificate bytes");
  assertArray(attestation.bundle.verificationMaterial.tlogEntries, "npm SLSA transparency log entries");
  if (attestation.bundle.verificationMaterial.tlogEntries.length < 1) {
    fail("npm SLSA transparency log evidence is missing");
  }
  const envelope = attestation.bundle.dsseEnvelope;
  assertRecord(envelope, "npm SLSA DSSE envelope");
  assertEqual(envelope.payloadType, "application/vnd.in-toto+json", "npm SLSA DSSE payload type");
  assertArray(envelope.signatures, "npm SLSA DSSE signatures");
  if (envelope.signatures.length < 1 || envelope.signatures.some((signature) => !signature || typeof signature.sig !== "string" || signature.sig.length === 0)) {
    fail("npm SLSA DSSE signatures are missing");
  }

  const statement = decodeBase64JSON(envelope.payload, "npm SLSA DSSE payload");
  assertRecord(statement, "npm SLSA statement");
  assertExactKeys(statement, ["_type", "subject", "predicateType", "predicate"], "npm SLSA statement");
  assertEqual(statement._type, "https://in-toto.io/Statement/v1", "npm SLSA statement type");
  assertEqual(statement.predicateType, slsaPredicateType, "npm SLSA statement predicate type");
  assertArray(statement.subject, "npm SLSA subjects");
  if (statement.subject.length !== 1) fail("npm SLSA statement must contain exactly one subject");
  const subject = statement.subject[0];
  assertRecord(subject, "npm SLSA subject");
  assertExactKeys(subject, ["name", "digest"], "npm SLSA subject");
  assertEqual(subject.name, `pkg:npm/${packageConfig.purlName}@${version}`, "npm SLSA subject name");
  assertRecord(subject.digest, "npm SLSA subject digest");
  assertExactKeys(subject.digest, ["sha512"], "npm SLSA subject digest");
  assertEqual(subject.digest.sha512, tarballSHA512, "npm SLSA subject sha512");

  const predicate = statement.predicate;
  assertRecord(predicate, "npm SLSA predicate");
  assertRecord(predicate.buildDefinition, "npm SLSA build definition");
  assertEqual(predicate.buildDefinition.buildType, workflowBuildType, "npm SLSA build type");
  assertRecord(predicate.buildDefinition.externalParameters, "npm SLSA external parameters");
  const workflow = predicate.buildDefinition.externalParameters.workflow;
  assertRecord(workflow, "npm SLSA workflow parameters");
  assertExactKeys(workflow, ["ref", "repository", "path"], "npm SLSA workflow parameters");
  assertEqual(workflow.repository, repositoryURL, "npm SLSA workflow repository");
  assertEqual(workflow.path, workflowPath, "npm SLSA workflow path");
  assertEqual(workflow.ref, `refs/tags/v${version}`, "npm SLSA workflow ref");

  assertArray(predicate.buildDefinition.resolvedDependencies, "npm SLSA resolved dependencies");
  if (predicate.buildDefinition.resolvedDependencies.length !== 1) {
    fail("npm SLSA build definition must contain exactly one resolved source dependency");
  }
  const source = predicate.buildDefinition.resolvedDependencies[0];
  assertRecord(source, "npm SLSA source dependency");
  assertExactKeys(source, ["uri", "digest"], "npm SLSA source dependency");
  assertEqual(source.uri, `git+${repositoryURL}@refs/tags/v${version}`, "npm SLSA source URI");
  assertRecord(source.digest, "npm SLSA source digest");
  assertExactKeys(source.digest, ["gitCommit"], "npm SLSA source digest");
  assertEqual(source.digest.gitCommit, sourceCommit, "npm SLSA source commit");

  assertRecord(predicate.runDetails, "npm SLSA run details");
  assertRecord(predicate.runDetails.builder, "npm SLSA builder");
  assertEqual(predicate.runDetails.builder.id, "https://github.com/actions/runner/github-hosted", "npm SLSA builder identity");
  assertRecord(predicate.runDetails.metadata, "npm SLSA run metadata");
  const invocationPrefix = `${repositoryURL}/actions/runs/`;
  if (typeof predicate.runDetails.metadata.invocationId !== "string" || !predicate.runDetails.metadata.invocationId.startsWith(invocationPrefix)) {
    fail("npm SLSA invocation ID does not belong to the release repository");
  }
}

async function fetchJSON(fetchImpl, url, label) {
  const response = await fetchImpl(url, { headers: { Accept: "application/json" }, redirect: "error" });
  if (!response.ok) fail(`${label} returned HTTP ${response.status}`);
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("json")) fail(`${label} returned a non-JSON content type`);
  try {
    return await response.json();
  } catch (error) {
    fail(`${label} returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function fetchBytes(fetchImpl, url, label) {
  const response = await fetchImpl(url, { headers: { Accept: "application/octet-stream" }, redirect: "error" });
  if (!response.ok) fail(`${label} returned HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

function assertRegistryURL(value, registryOrigin, expectedDecodedPath, label) {
  if (typeof value !== "string") fail(`${label} must be a URL`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} is invalid`);
  }
  if (parsed.origin !== registryOrigin || parsed.username || parsed.password || parsed.search || parsed.hash) {
    fail(`${label} must be an uncredentialed URL on ${registryOrigin}`);
  }
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(parsed.pathname);
  } catch {
    fail(`${label} has invalid path encoding`);
  }
  if (decodedPath !== expectedDecodedPath) fail(`${label} path is invalid`);
  return parsed;
}

function decodeBase64JSON(value, label) {
  assertNonEmptyString(value, label);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(`${label} is not canonical base64`);
  }
  try {
    return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
  } catch (error) {
    fail(`${label} is not valid UTF-8 JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function validateInputs(packageName, version, sourceCommit, expectedIntegrity, registryBaseURL, fetchImpl) {
  if (!Object.hasOwn(packages, packageName)) fail("npm package name is outside the platform package set");
  if (typeof version !== "string" || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    fail("version must be a semantic version without a leading v");
  }
  if (typeof sourceCommit !== "string" || !/^[0-9a-f]{40}$/.test(sourceCommit)) {
    fail("source commit must be a lowercase 40-character Git commit");
  }
  if (typeof expectedIntegrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(expectedIntegrity)) {
    fail("expected integrity must be SHA-512 SRI");
  }
  const registry = new URL(registryBaseURL);
  if (registry.pathname !== "/" || registry.search || registry.hash || registry.username || registry.password) {
    fail("registry base URL must be an uncredentialed origin");
  }
  if (typeof fetchImpl !== "function") fail("fetch implementation is unavailable");
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
}

function assertArray(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    fail(`${label} fields are invalid`);
  }
}

function assertNonEmptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a non-empty string`);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) fail(`${label} mismatch`);
}

function fail(message) {
  throw new Error(message);
}

async function main() {
  const [packageName, version, sourceCommit, expectedIntegrity, outputPath] = process.argv.slice(2);
  if (!packageName || !version || !sourceCommit || !expectedIntegrity || process.argv.length < 6 || process.argv.length > 7) {
    console.error("usage: verify_npm_registry_release.mjs <package-name> <version> <source-commit> <expected-integrity> [output-json]");
    process.exit(2);
  }
  const result = await verifyNpmRegistryRelease({ packageName, version, sourceCommit, expectedIntegrity });
  if (outputPath) {
    writeFileSync(outputPath, `${JSON.stringify({
      name: result.packageName,
      version: result.version,
      integrity: result.integrity,
      provenance_subject_sha512: result.tarballSHA512,
      source_commit: result.sourceCommit,
    }, null, 2)}\n`, { flag: "wx" });
  }
  console.log(`npm registry release verified: ${result.packageName}@${result.version} (${result.sourceCommit})`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
