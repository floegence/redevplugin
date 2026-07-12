#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { verifyNpmRegistryRelease } from "./verify_npm_registry_release.mjs";

const version = "9.8.7";
const sourceCommit = "0123456789abcdef0123456789abcdef01234567";
const tarball = Buffer.from("deterministic redevplugin npm registry fixture\n");
const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
const tarballSHA512 = createHash("sha512").update(tarball).digest("hex");
let mutation = () => undefined;

const server = createServer((request, response) => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  if (request.url === `/@floegence%2fredevplugin-ui/${version}`) {
    const metadata = npmMetadata(origin);
    mutation({ metadata });
    return sendJSON(response, metadata);
  }
  if (request.url === `/@floegence/redevplugin-ui/-/redevplugin-ui-${version}.tgz`) {
    const state = { tarball: Buffer.from(tarball) };
    mutation(state);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    return response.end(state.tarball);
  }
  if (request.url === `/-/npm/v1/attestations/@floegence%2fredevplugin-ui@${version}`) {
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

async function rejected(expectedMessage, nextMutation) {
  mutation = nextMutation;
  try {
    await assert.rejects(verify(), (error) => error instanceof Error && error.message.includes(expectedMessage));
  } finally {
    mutation = () => undefined;
  }
}

function npmMetadata(origin) {
  return {
    name: "@floegence/redevplugin-ui",
    version,
    gitHead: sourceCommit,
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
