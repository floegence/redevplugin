#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";

import {
  retryNpmRegistryReleaseReadback,
  verifyNpmRegistryRelease,
} from "./verify_npm_registry_release.mjs";

const version = "9.8.7";
const sourceCommit = "0123456789abcdef0123456789abcdef01234567";
const tarball = Buffer.from("deterministic redevplugin npm registry fixture\n");
const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
const tarballSHA512 = createHash("sha512").update(tarball).digest("hex");
let mutation = () => undefined;
let temporaryFailure = null;
let partialBodyFailure = null;
let malformedJSONRoute = "";
const requestCounts = { metadata: 0, tarball: 0, attestation: 0 };

const server = createServer((request, response) => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  if (request.url === `/@floegence%2fredevplugin-ui/${version}`) {
    requestCounts.metadata += 1;
    if (respondWithTemporaryFailure(request, response, "metadata")) return;
    if (respondWithPartialBodyFailure(response, "metadata", "application/json", "{")) return;
    if (malformedJSONRoute === "metadata") {
      response.writeHead(200, { "content-type": "application/json" });
      return response.end("{");
    }
    const metadata = npmMetadata(origin);
    mutation({ metadata });
    return sendJSON(response, metadata);
  }
  if (request.url === `/@floegence/redevplugin-ui/-/redevplugin-ui-${version}.tgz`) {
    requestCounts.tarball += 1;
    if (respondWithTemporaryFailure(request, response, "tarball")) return;
    if (respondWithPartialBodyFailure(response, "tarball", "application/octet-stream", "partial")) return;
    const state = { tarball: Buffer.from(tarball) };
    mutation(state);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    return response.end(state.tarball);
  }
  if (request.url === `/-/npm/v1/attestations/@floegence%2fredevplugin-ui@${version}`) {
    requestCounts.attestation += 1;
    if (respondWithTemporaryFailure(request, response, "attestation")) return;
    const statement = slsaStatement();
    const state = { statement, attestations: undefined };
    mutation(state);
    state.attestations ??= attestationResponse(state.statement);
    return sendJSON(response, state.attestations);
  }
  response.writeHead(404).end();
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const registryBaseURL = `http://127.0.0.1:${server.address().port}`;

try {
  await verify();
  await recoversFromTemporaryFailure("metadata", 404);
  await recoversFromTemporaryFailure("metadata", 408);
  await recoversFromTemporaryFailure("metadata", 425);
  await recoversFromTemporaryFailure("tarball", 429);
  await recoversFromTemporaryFailure("attestation", 503);
  await recoversFromTemporaryFailure("metadata", "transport");
  await recoversFromPartialBodyFailure("metadata");
  await recoversFromPartialBodyFailure("tarball");
  await temporaryFailureBudgetIsBounded();
  await retryConfigurationIsBounded();
  await terminalHTTPFailureIsNotRetried();
  await malformedJSONIsNotRetried();
  await rejected("npm package name", (state) => {
    if (state.metadata) state.metadata.name = "@floegence/other";
  });
  await rejected("npm package version", (state) => {
    if (state.metadata) state.metadata.version = "9.8.6";
  });
  await rejected("npm repository directory", (state) => {
    if (state.metadata) state.metadata.repository.directory = "packages/other";
  });
  await rejected("npm dist integrity", (state) => {
    if (state.metadata) state.metadata.dist.integrity = "sha512-invalid";
  });
  await rejected("downloaded npm tarball integrity", (state) => {
    if (state.tarball) state.tarball = Buffer.from("tampered tarball");
  });
  await rejected("npm SLSA subject sha512", (state) => {
    if (state.statement) state.statement.subject[0].digest.sha512 = "0".repeat(128);
  });
  await rejected("npm SLSA workflow repository", (state) => {
    if (state.statement) state.statement.predicate.buildDefinition.externalParameters.workflow.repository = "https://github.com/attacker/repo";
  });
  await rejected("npm SLSA workflow path", (state) => {
    if (state.statement) state.statement.predicate.buildDefinition.externalParameters.workflow.path = ".github/workflows/other.yml";
  });
  await rejected("npm SLSA workflow ref", (state) => {
    if (state.statement) state.statement.predicate.buildDefinition.externalParameters.workflow.ref = "refs/heads/main";
  });
  await rejected("npm SLSA source commit", (state) => {
    if (state.statement) state.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = "f".repeat(40);
  });
  await rejected("npm package gitHead", (state) => {
    if (state.metadata) state.metadata.gitHead = "f".repeat(40);
  });
  await rejected("npm tarball URL", (state) => {
    if (state.metadata) state.metadata.dist.tarball = "https://attacker.example/package.tgz";
  });
  await rejected("npm attestation URL", (state) => {
    if (state.metadata) state.metadata.dist.attestations.url = "https://attacker.example/attestations";
  });
  console.log("npm registry release verifier fixtures passed");
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function verify() {
  return verifyNpmRegistryRelease({ version, sourceCommit, expectedIntegrity: integrity, registryBaseURL });
}

async function retryVerify() {
  return retryNpmRegistryReleaseReadback({
    version,
    sourceCommit,
    expectedIntegrity: integrity,
    registryBaseURL,
    retryDelaysMs: [0, 0, 0],
    sleepImpl: async () => {},
    logger: () => {},
  });
}

async function rejected(expectedMessage, nextMutation) {
  mutation = nextMutation;
  resetRequestCounts();
  try {
    await assert.rejects(retryVerify(), (error) => error instanceof Error && error.message.includes(expectedMessage));
    assert.equal(requestCounts.metadata, 1, `${expectedMessage} must fail on its first immutable readback attempt`);
  } finally {
    mutation = () => undefined;
  }
}

async function recoversFromTemporaryFailure(route, status) {
  resetRequestCounts();
  temporaryFailure = { route, status, remaining: 2 };
  try {
    await retryVerify();
    assert.equal(requestCounts[route], 3, `${route} temporary failure retry count`);
  } finally {
    temporaryFailure = null;
  }
}

async function recoversFromPartialBodyFailure(route) {
  resetRequestCounts();
  partialBodyFailure = { route, remaining: 2 };
  try {
    await retryVerify();
    assert.equal(requestCounts[route], 3, `${route} partial body failure retry count`);
  } finally {
    partialBodyFailure = null;
  }
}

async function temporaryFailureBudgetIsBounded() {
  resetRequestCounts();
  temporaryFailure = { route: "metadata", status: 503, remaining: 4 };
  try {
    await assert.rejects(retryVerify(), /remained unavailable after 3 bounded attempts/);
    assert.equal(requestCounts.metadata, 3);
  } finally {
    temporaryFailure = null;
  }
}

async function terminalHTTPFailureIsNotRetried() {
  resetRequestCounts();
  temporaryFailure = { route: "metadata", status: 403, remaining: 3 };
  try {
    await assert.rejects(retryVerify(), /npm package metadata returned HTTP 403/);
    assert.equal(requestCounts.metadata, 1);
  } finally {
    temporaryFailure = null;
  }
}

async function retryConfigurationIsBounded() {
  const base = {
    version,
    sourceCommit,
    expectedIntegrity: integrity,
    registryBaseURL,
    sleepImpl: async () => {},
    logger: () => {},
  };
  await assert.rejects(
    retryNpmRegistryReleaseReadback({ ...base, retryDelaysMs: Array(21).fill(0) }),
    /retry delays are invalid/,
  );
  await assert.rejects(
    retryNpmRegistryReleaseReadback({ ...base, retryDelaysMs: [0, 6_001] }),
    /retry delays are invalid/,
  );
}

async function malformedJSONIsNotRetried() {
  resetRequestCounts();
  malformedJSONRoute = "metadata";
  try {
    await assert.rejects(retryVerify(), /npm package metadata returned invalid JSON/);
    assert.equal(requestCounts.metadata, 1);
  } finally {
    malformedJSONRoute = "";
  }
}

function respondWithTemporaryFailure(request, response, route) {
  if (temporaryFailure?.route !== route || temporaryFailure.remaining <= 0) return false;
  temporaryFailure.remaining -= 1;
  if (temporaryFailure.status === "transport") {
    request.socket.destroy();
    return true;
  }
  response.writeHead(temporaryFailure.status, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "temporary fixture failure" }));
  return true;
}

function respondWithPartialBodyFailure(response, route, contentType, partialBody) {
  if (partialBodyFailure?.route !== route || partialBodyFailure.remaining <= 0) return false;
  partialBodyFailure.remaining -= 1;
  response.writeHead(200, {
    "content-length": String(Buffer.byteLength(partialBody) + 1_024),
    "content-type": contentType,
  });
  response.flushHeaders();
  response.write(partialBody);
  setImmediate(() => response.destroy());
  return true;
}

function resetRequestCounts() {
  requestCounts.metadata = 0;
  requestCounts.tarball = 0;
  requestCounts.attestation = 0;
}

function npmMetadata(origin) {
  return {
    name: "@floegence/redevplugin-ui",
    version,
    repository: {
      type: "git",
      url: "git+https://github.com/floegence/redevplugin.git",
      directory: "packages/redevplugin-ui",
    },
    dist: {
      integrity,
      tarball: `${origin}/@floegence/redevplugin-ui/-/redevplugin-ui-${version}.tgz`,
      attestations: {
        url: `${origin}/-/npm/v1/attestations/@floegence%2fredevplugin-ui@${version}`,
        provenance: { predicateType: "https://slsa.dev/provenance/v1" },
      },
    },
  };
}

function slsaStatement() {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{
      name: `pkg:npm/%40floegence/redevplugin-ui@${version}`,
      digest: { sha512: tarballSHA512 },
    }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
        externalParameters: {
          workflow: {
            ref: `refs/tags/v${version}`,
            repository: "https://github.com/floegence/redevplugin",
            path: ".github/workflows/release.yml",
          },
        },
        resolvedDependencies: [{
          uri: `git+https://github.com/floegence/redevplugin@refs/tags/v${version}`,
          digest: { gitCommit: sourceCommit },
        }],
      },
      runDetails: {
        builder: { id: "https://github.com/actions/runner/github-hosted" },
        metadata: { invocationId: "https://github.com/floegence/redevplugin/actions/runs/123/attempts/1" },
      },
    },
  };
}

function attestationResponse(statement) {
  return {
    attestations: [{
      predicateType: "https://slsa.dev/provenance/v1",
      bundle: {
        mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
        verificationMaterial: {
          certificate: { rawBytes: "fixture-certificate" },
          tlogEntries: [{ logIndex: "1" }],
        },
        dsseEnvelope: {
          payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
          payloadType: "application/vnd.in-toto+json",
          signatures: [{ sig: "fixture-signature", keyid: "" }],
        },
      },
    }],
  };
}

function sendJSON(response, value) {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}
