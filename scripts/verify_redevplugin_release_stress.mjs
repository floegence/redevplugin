#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const [rawSummaryPath] = process.argv.slice(2);
if (!rawSummaryPath) {
  console.error("usage: verify_redevplugin_release_stress.mjs <summary-path>");
  process.exit(2);
}

const summaryPath = resolve(rawSummaryPath);

function fail(message) {
  console.error(`invalid release stress summary: ${message}`);
  process.exit(1);
}

function object(value, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  return value;
}

function integer(value, label) {
  if (!Number.isInteger(value)) {
    fail(`${label} must be an integer`);
  }
  return value;
}

function counter(evidenceByCategory, category, name) {
  const evidence = evidenceByCategory.get(category);
  if (!evidence) {
    fail(`missing stress evidence category ${category}`);
  }
  return integer(object(evidence.counters, `${category}.counters`)[name], `${category}.counters.${name}`);
}

function requireAtLeast(evidenceByCategory, category, name, minimum) {
  const value = counter(evidenceByCategory, category, name);
  if (value < minimum) {
    fail(`${category}.counters.${name} = ${value}, want >= ${minimum}`);
  }
  return value;
}

let summary;
try {
  summary = JSON.parse(readFileSync(summaryPath, "utf8"));
} catch (error) {
  fail(`cannot parse ${summaryPath}: ${error.message}`);
}

object(summary, "summary");
if (summary.ok !== true) {
  fail("ok must be true");
}
if (summary.mode !== "release") {
  fail(`mode = ${JSON.stringify(summary.mode)}, want "release"`);
}

const requiredCategories = [
  "go_race",
  "stream_backpressure",
  "operation_cancel_ownership",
  "connectivity_classifier",
  "runtime_revoke_ack",
  "storage_quota",
  "browser_harness",
  "runtime_contract",
  "release_bundle",
  "published_release_verifier",
];
const stressCategoryList = array(summary.stress_categories, "stress_categories");
const stressCategories = new Set(stressCategoryList);
if (stressCategories.size !== stressCategoryList.length) {
  fail("stress_categories must not contain duplicates");
}
for (const category of requiredCategories) {
  if (!stressCategories.has(category)) {
    fail(`stress_categories missing ${category}`);
  }
}
const unexpectedCategories = [...stressCategories].filter((category) => !requiredCategories.includes(category));
if (unexpectedCategories.length > 0) {
  fail(`stress_categories contain unexpected values: ${unexpectedCategories.join(", ")}`);
}

const evidenceByCategory = new Map();
for (const evidence of array(summary.stress_evidence, "stress_evidence")) {
  object(evidence, "stress_evidence entry");
  if (typeof evidence.category !== "string" || evidence.category.length === 0) {
    fail("stress_evidence entry category must be a non-empty string");
  }
  if (evidenceByCategory.has(evidence.category)) {
    fail(`duplicate stress evidence category ${evidence.category}`);
  }
  evidenceByCategory.set(evidence.category, evidence);
}

const requiredSteps = [
  "npm_ci",
  "go_race_core",
  "connectivity_stress_evidence",
  "stress_evidence",
  "go_all",
  "browser_harness",
  "runtime_contract",
  "release_bundle",
  "published_release_verifier",
];
const stepsByName = new Map();
const stepNames = [];
for (const candidate of array(summary.steps, "steps")) {
  const step = object(candidate, "step");
  if (typeof step.name !== "string" || step.name.length === 0) {
    fail("step name must be a non-empty string");
  }
  if (stepsByName.has(step.name)) {
    fail(`duplicate step ${step.name}`);
  }
  integer(step.duration_ms, `step ${step.name} duration_ms`);
  if (step.duration_ms < 0) {
    fail(`step ${step.name} duration_ms must be non-negative`);
  }
  stepNames.push(step.name);
  stepsByName.set(step.name, step);
}
for (const stepName of requiredSteps) {
  const step = stepsByName.get(stepName);
  if (!step) {
    fail(`steps missing ${stepName}`);
  }
  if (step.status !== 0) {
    fail(`step ${stepName} status = ${step.status}, want 0`);
  }
}
if (JSON.stringify(stepNames) !== JSON.stringify(requiredSteps)) {
  fail(`step order mismatch: got ${JSON.stringify(stepNames)}, want ${JSON.stringify(requiredSteps)}`);
}

const streamWorkers = requireAtLeast(evidenceByCategory, "stream_backpressure", "workers", 1);
const backpressureDenials = requireAtLeast(evidenceByCategory, "stream_backpressure", "backpressure_denials", 1);
if (backpressureDenials < streamWorkers) {
  fail(`stream_backpressure backpressure_denials ${backpressureDenials} must cover workers ${streamWorkers}`);
}
requireAtLeast(evidenceByCategory, "stream_backpressure", "core_operation_checks", 1);
const streamCloseRequests = requireAtLeast(evidenceByCategory, "stream_backpressure", "stream_close_requests", 1);
const closedStreams = requireAtLeast(evidenceByCategory, "stream_backpressure", "closed_streams", 1);
if (closedStreams !== streamCloseRequests) {
  fail(`stream_backpressure closed_streams ${closedStreams} must equal stream_close_requests ${streamCloseRequests}`);
}
const postCloseAppendDenials = requireAtLeast(evidenceByCategory, "stream_backpressure", "post_close_append_denials", 1);
if (postCloseAppendDenials !== closedStreams) {
  fail(`stream_backpressure post_close_append_denials ${postCloseAppendDenials} must equal closed_streams ${closedStreams}`);
}
requireAtLeast(evidenceByCategory, "stream_backpressure", "stream_close_status_checked", 1);

const operationCancelRegistered = requireAtLeast(evidenceByCategory, "operation_cancel_ownership", "operations_registered", 2);
const operationCancelRequested = requireAtLeast(evidenceByCategory, "operation_cancel_ownership", "cancel_requested_records", 2);
if (operationCancelRequested !== operationCancelRegistered) {
  fail(`operation_cancel_ownership cancel_requested_records ${operationCancelRequested} must equal operations_registered ${operationCancelRegistered}`);
}
requireAtLeast(evidenceByCategory, "operation_cancel_ownership", "durable_requests_without_active_lease", 2);
requireAtLeast(evidenceByCategory, "operation_cancel_ownership", "http_accepted_requests", 1);
const operationCancelAudits = requireAtLeast(evidenceByCategory, "operation_cancel_ownership", "audit_cancel_requested_events", 2);
if (operationCancelAudits !== operationCancelRequested) {
  fail(`operation_cancel_ownership audit_cancel_requested_events ${operationCancelAudits} must equal cancel_requested_records ${operationCancelRequested}`);
}
const registryRedispatches = counter(evidenceByCategory, "operation_cancel_ownership", "registry_redispatches");
if (registryRedispatches !== 0) {
  fail(`operation_cancel_ownership registry_redispatches ${registryRedispatches} must equal 0`);
}

requireAtLeast(evidenceByCategory, "connectivity_classifier", "minted_grants", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "stale_grant_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "blocked_resolved_ips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "connector_policy_count", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_redirects_not_followed", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "dns_rebinding_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_proxy_env_ignored", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_connect_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "alt_svc_headers_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "proxy_auth_headers_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_chunks", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_cancelled_reads", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_database_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_cancelled_reads", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_source_mismatch_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_rate_limit_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_cancelled_reads", 1);

requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "attempts", 1);
const p95Ms = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "p95_ms", 0);
const maxMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "max_ms", 0);
const thresholdMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "threshold_ms", 1);
const hardTimeoutMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "hard_timeout_ms", 1);
if (p95Ms > thresholdMs) {
  fail(`runtime_revoke_ack p95_ms ${p95Ms} exceeds threshold_ms ${thresholdMs}`);
}
if (maxMs >= hardTimeoutMs) {
  fail(`runtime_revoke_ack max_ms ${maxMs} must be below hard_timeout_ms ${hardTimeoutMs}`);
}
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_socket", 1);
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_stream", 1);
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_storage", 1);

const storageWrites = requireAtLeast(evidenceByCategory, "storage_quota", "writes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "quota_denials", 1);
const imported = requireAtLeast(evidenceByCategory, "storage_quota", "imported", 1);
if (imported !== storageWrites) {
  fail(`storage_quota imported ${imported} must equal writes ${storageWrites}`);
}
requireAtLeast(evidenceByCategory, "storage_quota", "usage_bytes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_quota_denials", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_usage_files", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_quota_files", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_quota_denials", 2);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_rollback_checks", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_page_count", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sidecar_files", 4);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sidecar_bytes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sparse_logical_bytes", 1);

console.log(`redevplugin release stress summary verified: ${summaryPath}`);
