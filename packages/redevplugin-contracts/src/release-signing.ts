export const rootDelegationSchemaVersion = "redevplugin.release_root_delegation.v1" as const;
export const packageSignatureSchemaVersion = "redevplugin.package_signature.v1" as const;
export const releaseMetadataSchemaVersion = "redevplugin.release_metadata.v5" as const;
export const sourcePolicySchemaVersion = "redevplugin.release_source_policy.v2" as const;
export const sourcePolicyPointerSchemaVersion = "redevplugin.release_source_policy_pointer.v1" as const;
export const revocationSchemaVersion = "redevplugin.release_revocation.v2" as const;
export const revocationPointerSchemaVersion = "redevplugin.release_revocation_pointer.v1" as const;
export const releaseSigningLedgerEvidenceSchemaVersion = "redevplugin.release_signing_ledger_evidence.v1" as const;
export const signingSubjectSchemaVersion = "redevplugin.release_signing_subject.v1" as const;
export const signatureEnvelopeSchemaVersion = "redevplugin.release_signature_envelope.v1" as const;
export const signingLedgerSchemaVersion = "redevplugin.release_signing_ledger.v1" as const;
export const signingLedgerEntrySchemaVersion = "redevplugin.release_signing_ledger_entry.v1" as const;
export const signingLedgerLogLeafSchemaVersion = "redevplugin.release_signing_ledger_log_leaf.v1" as const;
export const signingLedgerReceiptSchemaVersion = "redevplugin.release_signing_ledger_receipt.v1" as const;
export const signatureAlgorithmEd25519 = "ed25519" as const;
export const genesisPreviousEpoch = "0" as const;
export const genesisPreviousDocumentSHA256 = "0".repeat(64);

export const signingUsages = {
  rootDelegation: "redevplugin.release-signing.root-delegation.v1",
  package: "redevplugin.release-signing.package.v1",
  releaseMetadata: "redevplugin.release-signing.release-metadata.v1",
  sourcePolicy: "redevplugin.release-signing.source-policy-document.v1",
  sourcePolicyPointer: "redevplugin.release-signing.source-policy-pointer.v1",
  revocation: "redevplugin.release-signing.revocation-document.v1",
  revocationPointer: "redevplugin.release-signing.revocation-pointer.v1",
} as const;

export type SigningUsage = (typeof signingUsages)[keyof typeof signingUsages];
export type DelegatedKeyUsage =
  | "package"
  | "release_metadata"
  | "source_policy_document"
  | "source_policy_pointer"
  | "revocation_document"
  | "revocation_pointer"
  | "signing_ledger"
  | "trusted_time";

export type RootDelegatedKey = Readonly<{
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  public_key: string;
  usages: readonly DelegatedKeyUsage[];
  channels: readonly string[];
  valid_from: string;
  valid_until: string;
}>;

export type RootDelegationV1 = Readonly<{
  schema_version: typeof rootDelegationSchemaVersion;
  source_id: string;
  root_epoch: string;
  previous_root_epoch: string;
  previous_delegation_sha256: string;
  generated_at: string;
  expires_at: string;
  delegated_keys: readonly RootDelegatedKey[];
  key_id: string;
  signature: string;
}>;

export type RootDelegationInput = Omit<RootDelegationV1, "schema_version" | "signature">;

export type PackageSigningInput = Readonly<{
  source_id: string;
  channel: string;
  version: string;
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  publisher_id: string;
  plugin_id: string;
  package_hash: string;
  manifest_hash: string;
  entries_hash: string;
  signed_at: string;
}>;

export type PackageVerificationContext = Readonly<{
  source_id: string;
  channel: string;
  version: string;
}>;

export type PackageSignatureV1 = Readonly<{
  schema_version: typeof packageSignatureSchemaVersion;
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  publisher_id?: string;
  plugin_id?: string;
  package_hash: string;
  manifest_hash: string;
  entries_hash: string;
  signature: string;
  signed_at?: string;
}>;

export type ReleaseDistributionRef = Readonly<{
  distribution: "registry_ref" | "host_artifact_ref";
  artifact_ref: string;
}>;

export type ReleasePackageHashSet = Readonly<{
  package_sha256: string;
  manifest_sha256: string;
  entries_sha256: string;
}>;

export type ReleaseMetadataSignatureRef = Readonly<{
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  signature_ref: string;
  source_policy_epoch: string;
  revocation_epoch: string;
}>;

export type PackageReleaseSignatureRef = Readonly<{
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  signature_bundle_ref: string;
  source_policy_epoch: string;
  revocation_epoch: string;
}>;

export type ReleaseCompatibility = Readonly<{
  min_redevplugin_version: string;
  min_runtime_version: string;
  ui_protocol_version: "plugin-ui-v5";
  supported_targets?: readonly ("darwin/amd64" | "darwin/arm64" | "linux/amd64" | "linux/arm64")[];
}>;

export type HostCapabilityContractRef = Readonly<{
  publisher_id: string;
  contract_id: string;
  contract_version: string;
  artifact_ref: string;
  artifact_sha256: string;
  manifest_ref: string;
  manifest_sha256: string;
  signature_ref: string;
  signature_sha256: string;
  signature_key_id: string;
  signature_policy_epoch: string;
  signature_revocation_epoch: string;
  compatibility_ref: string;
  compatibility_sha256: string;
  generated_client_ref: string;
  generated_client_sha256: string;
  notices_ref: string;
  notices_sha256: string;
}>;

export type HostCapabilityRequirementRef = Readonly<{
  capability_id: string;
  capability_version: string;
  contract: HostCapabilityContractRef;
}>;

export type ReleaseHostRequirement = Readonly<{
  host_id: string;
  min_host_version?: string;
  required_capability_contracts?: readonly HostCapabilityRequirementRef[];
}>;

export type ReleaseEvidence = Readonly<{
  notices_sha256?: string;
  provenance_sha256?: string;
  generated_at?: string;
}>;

export type ReleaseMetadataV5 = Readonly<{
  schema_version: typeof releaseMetadataSchemaVersion;
  source_id: string;
  release_metadata_ref: string;
  publisher_id: string;
  plugin_id: string;
  version: string;
  distribution_ref: ReleaseDistributionRef;
  hashes: ReleasePackageHashSet;
  release_metadata_signature: ReleaseMetadataSignatureRef;
  package_signature: PackageReleaseSignatureRef;
  compatibility: ReleaseCompatibility;
  host_requirements?: readonly ReleaseHostRequirement[];
  release_evidence?: ReleaseEvidence;
  metadata?: Readonly<Record<string, string>>;
}>;

export type SourcePolicyLimits = Readonly<{
  document_max_lifetime_seconds: 86400;
  future_skew_seconds: 300;
  activation_lease_max_seconds: 300;
  refresh_interval_max_seconds: 60;
  failure_teardown_deadline_seconds: 30;
}>;

export const defaultSourcePolicyLimits: SourcePolicyLimits = Object.freeze({
  document_max_lifetime_seconds: 86400,
  future_skew_seconds: 300,
  activation_lease_max_seconds: 300,
  refresh_interval_max_seconds: 60,
  failure_teardown_deadline_seconds: 30,
});

export type SourcePolicyActiveKeys = Readonly<{
  package: readonly string[];
  release_metadata: readonly string[];
  source_policy_pointer: readonly string[];
  revocation_document: readonly string[];
  revocation_pointer: readonly string[];
}>;

export type SourcePolicyV2 = Readonly<{
  schema_version: typeof sourcePolicySchemaVersion;
  source_id: string;
  channel: string;
  epoch: string;
  previous_epoch: string;
  previous_document_sha256: string;
  root_epoch: string;
  source_type: "registry" | "host_artifact";
  source_class: "official" | "curated" | "community" | "private";
  allowed_publishers: readonly string[];
  allowed_artifact_hosts: readonly string[];
  active_keys: SourcePolicyActiveKeys;
  require_signature: boolean;
  install_policy: "allow" | "review_required" | "block";
  unsigned_policy: "dev_only" | "review_required" | "block";
  downgrade_policy: "review_required" | "block";
  minimum_revocation_epoch: string;
  limits: SourcePolicyLimits;
  generated_at: string;
  expires_at: string;
  key_id: string;
  signature: string;
}>;

export type SourcePolicyInput = Omit<SourcePolicyV2, "schema_version" | "signature">;

export type ReleasePointerInput = Readonly<{
  source_id: string;
  channel: string;
  epoch: string;
  previous_epoch: string;
  previous_document_sha256: string;
  ref: string;
  document_sha256: string;
  generated_at: string;
  expires_at: string;
  key_id: string;
}>;

export type SourcePolicyPointerV1 = Readonly<ReleasePointerInput & {
  schema_version: typeof sourcePolicyPointerSchemaVersion;
  signature: string;
}>;

export type RevokedRelease = Readonly<{
  publisher_id: string;
  plugin_id: string;
  version: string;
  release_metadata_sha256: string;
  revoked_at: string;
}>;

export type RevocationV2 = Readonly<{
  schema_version: typeof revocationSchemaVersion;
  source_id: string;
  channel: string;
  epoch: string;
  previous_epoch: string;
  previous_document_sha256: string;
  root_epoch: string;
  generated_at: string;
  expires_at: string;
  revoked_key_ids: readonly string[];
  revoked_releases: readonly RevokedRelease[];
  key_id: string;
  signature: string;
}>;

export type RevocationInput = Omit<RevocationV2, "schema_version" | "signature">;

export type RevocationPointerV1 = Readonly<ReleasePointerInput & {
  schema_version: typeof revocationPointerSchemaVersion;
  signature: string;
}>;

export type SigningLedgerEvidenceV1 = Readonly<{
  schema_version: typeof releaseSigningLedgerEvidenceSchemaVersion;
  source_id: string;
  channel?: string;
  subject_identity_sha256: string;
  signing_preimage_sha256: string;
  signature_envelope_sha256: string;
  receipt_ref: string;
  receipt_sha256: string;
  checkpoint_ref: string;
  checkpoint_sha256: string;
  inclusion_proof_ref: string;
  inclusion_proof_sha256: string;
  latest_proof_ref: string;
  latest_proof_sha256: string;
  consistency_proof_ref?: string;
  consistency_proof_sha256?: string;
}>;

export type SigningSubjectUsage =
  | "root_delegation"
  | "package"
  | "release_metadata"
  | "source_policy_document"
  | "source_policy_pointer"
  | "revocation_document"
  | "revocation_pointer";

export type SigningSubjectV1 = Readonly<{
  schema_version: typeof signingSubjectSchemaVersion;
  usage: SigningSubjectUsage;
  source_id: string;
  channel?: string;
  root_epoch?: string;
  publisher_id?: string;
  plugin_id?: string;
  version?: string;
  artifact_or_metadata_identity_sha256?: string;
  epoch?: string;
}>;

export type SignatureEnvelopeV1 = Readonly<{
  schema_version: typeof signatureEnvelopeSchemaVersion;
  subject_identity_sha256: string;
  signing_preimage_sha256: string;
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  signature: string;
}>;

export type SigningLedgerEntryState = "reserved" | "finalized" | "terminal_failed";
export type SigningLedgerFailureCode = "signer_rejected" | "subject_conflict" | "ledger_rejected";

export type SigningLedgerEntryV1 = Readonly<{
  schema_version: typeof signingLedgerEntrySchemaVersion;
  state: SigningLedgerEntryState;
  subject: SigningSubjectV1;
  subject_identity_sha256: string;
  signing_preimage_sha256: string;
  algorithm: typeof signatureAlgorithmEd25519;
  key_id: string;
  revision: number;
  reserved_at: string;
  signature_envelope?: SignatureEnvelopeV1;
  signature_envelope_sha256?: string;
  finalized_at?: string;
  failure_code?: SigningLedgerFailureCode;
  failed_at?: string;
}>;

export type SigningLedgerLogLeafV1 = Readonly<{
  schema_version: typeof signingLedgerLogLeafSchemaVersion;
  source_id: string;
  channel?: string;
  subject_identity_sha256: string;
  signing_preimage_sha256: string;
  signature_envelope_sha256: string;
  sequence: number;
}>;

export type SigningLedgerCheckpointV1 = Readonly<{
  schema_version: typeof signingLedgerSchemaVersion;
  kind: "checkpoint";
  log_id: string;
  tree_size: number;
  log_root_hash: string;
  latest_map_root_hash: string;
  checkpoint_time: string;
  key_id: string;
  signature: string;
}>;

export type SigningLedgerReceiptV1 = Readonly<{
  schema_version: typeof signingLedgerReceiptSchemaVersion;
  log_id: string;
  source_id: string;
  channel?: string;
  subject_identity_sha256: string;
  signing_preimage_sha256: string;
  signature_envelope_sha256: string;
  sequence: number;
  leaf_index: number;
  tree_size: number;
  log_root_hash: string;
  latest_map_root_hash: string;
  checkpoint_sha256: string;
  checkpoint_time: string;
  key_id: string;
  signature: string;
}>;

export type SigningLedgerInclusionProofV1 = Readonly<{
  schema_version: typeof signingLedgerSchemaVersion;
  kind: "inclusion_proof";
  log_id: string;
  leaf_index: number;
  tree_size: number;
  nodes: readonly string[];
}>;

export type SigningLedgerLatestProofV1 = Readonly<{
  schema_version: typeof signingLedgerSchemaVersion;
  kind: "latest_proof";
  log_id: string;
  subject_identity_sha256: string;
  present: boolean;
  sequence?: number;
  signing_preimage_sha256?: string;
  signature_envelope_sha256?: string;
  siblings: readonly string[];
}>;

export type SigningLedgerConsistencyProofV1 = Readonly<{
  schema_version: typeof signingLedgerSchemaVersion;
  kind: "consistency_proof";
  log_id: string;
  old_tree_size: number;
  new_tree_size: number;
  nodes: readonly string[];
}>;

export type SignatureVerificationRequest = Readonly<{
  usage: SigningUsage;
  keyID: string;
  signingPreimageSHA256: Uint8Array;
  signature: Uint8Array;
}>;

export type SignatureVerifier = (
  request: SignatureVerificationRequest,
) => boolean | Promise<boolean>;

export class InvalidReleaseDocumentError extends TypeError {
  constructor() {
    super("release contract document is invalid");
    this.name = "InvalidReleaseDocumentError";
  }
}

export class InvalidReleaseSignatureError extends Error {
  constructor() {
    super("release contract signature is invalid");
    this.name = "InvalidReleaseSignatureError";
  }
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const maximumDocumentBytes = 1024 * 1024;
const signingPrefix = textEncoder.encode("REDEVPLUGIN-SIGNING-V1\0");
const newIDPattern = /^[a-z][a-z0-9._-]{0,127}$/;
const legacyIDPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const epochPattern = /^(0|[1-9][0-9]*)$/;
const positiveEpochPattern = /^[1-9][0-9]*$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const prefixedSHA256Pattern = /^sha256:[0-9a-f]{64}$/;
const legacySHA256Pattern = /^(?:sha256:)?[0-9a-f]{64}$/;
const artifactRefPattern = /^[A-Za-z0-9._/@+-]+$/;
const hostnamePattern = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const semverPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const canonicalTimePattern = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const publicKeyPattern = /^[A-Za-z0-9+/]{43}=$/;
const signaturePattern = /^[A-Za-z0-9+/]{86}==$/;
const delegatedUsageOrder: readonly DelegatedKeyUsage[] = [
  "package",
  "release_metadata",
  "revocation_document",
  "revocation_pointer",
  "source_policy_document",
  "source_policy_pointer",
  "signing_ledger",
  "trusted_time",
];

function invalidDocument(): never {
  throw new InvalidReleaseDocumentError();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertRecord(value: unknown): asserts value is Record<string, unknown> {
  if (!isRecord(value)) invalidDocument();
}

function matchesPattern(pattern: RegExp, value: unknown): value is string {
  return typeof value === "string" && pattern.test(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(value).sort(compareUTF8);
  const expected = [...keys].sort(compareUTF8);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    invalidDocument();
  }
}

function exactOptionalKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in value)) || Object.keys(value).some((key) => !allowed.has(key))) {
    invalidDocument();
  }
}

function compareUTF8(left: string, right: string): number {
  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index]! - rightBytes[index]!;
  }
  return leftBytes.length - rightBytes.length;
}

function assertWellFormedString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) invalidDocument();
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      invalidDocument();
    }
  }
}

function canonicalJSONString(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    assertWellFormedString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) invalidDocument();
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJSONString(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort(compareUTF8);
    return `{${keys.map((key) => `${canonicalJSONString(key)}:${canonicalJSONString(value[key])}`).join(",")}}`;
  }
  invalidDocument();
}

function canonicalJSON(value: unknown): Uint8Array {
  return textEncoder.encode(canonicalJSONString(value));
}

function signingPreimage(usage: SigningUsage, value: unknown): Uint8Array {
  const domain = textEncoder.encode(usage);
  const payload = canonicalJSON(value);
  const result = new Uint8Array(signingPrefix.length + domain.length + 1 + payload.length);
  result.set(signingPrefix, 0);
  result.set(domain, signingPrefix.length);
  result[signingPrefix.length + domain.length] = 0;
  result.set(payload, signingPrefix.length + domain.length + 1);
  return result;
}

function preimageWithoutTopLevelSignature(usage: SigningUsage, value: Record<string, unknown>): Uint8Array {
  const payload = cloneJSON(value);
  delete payload.signature;
  return signingPreimage(usage, payload);
}

function cloneJSON<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: unknown, expectedLength: number): Uint8Array {
  const pattern = expectedLength === 32 ? publicKeyPattern : signaturePattern;
  if (!matchesPattern(pattern, value)) invalidDocument();
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    invalidDocument();
  }
  if (binary.length !== expectedLength) invalidDocument();
  const result = Uint8Array.from(binary, (item) => item.charCodeAt(0));
  if (encodeBase64(result) !== value) invalidDocument();
  return result;
}

function requireSignatureBytes(signature: Uint8Array): void {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) invalidDocument();
}

function parseCanonicalTime(value: unknown): number {
  if (!matchesPattern(canonicalTimePattern, value)) invalidDocument();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value.replace("Z", ".000Z")) {
    invalidDocument();
  }
  return parsed;
}

function validateTimeRange(generatedAt: string, expiresAt: string, maximumMilliseconds = 0): void {
  const generated = parseCanonicalTime(generatedAt);
  const expires = parseCanonicalTime(expiresAt);
  if (expires <= generated || (maximumMilliseconds > 0 && expires - generated > maximumMilliseconds)) {
    invalidDocument();
  }
}

function validateEpochChain(epoch: string, previousEpoch: string, previousDigest: string): void {
  if (!matchesPattern(positiveEpochPattern, epoch) || !matchesPattern(epochPattern, previousEpoch) || !matchesPattern(sha256Pattern, previousDigest)) {
    invalidDocument();
  }
  if (BigInt(previousEpoch) + 1n !== BigInt(epoch)) invalidDocument();
  if (previousEpoch === genesisPreviousEpoch) {
    if (previousDigest !== genesisPreviousDocumentSHA256) invalidDocument();
  } else if (previousDigest === genesisPreviousDocumentSHA256) {
    invalidDocument();
  }
}

function validateSortedIDs(values: unknown, minimum: number, maximum: number, lower = true): void {
  if (!Array.isArray(values) || values.length < minimum || values.length > maximum) invalidDocument();
  let previous = "";
  const pattern = lower ? newIDPattern : legacyIDPattern;
  for (const value of values) {
    if (!matchesPattern(pattern, value) || compareUTF8(value, previous) <= 0) invalidDocument();
    previous = value;
  }
}

function validArtifactRef(value: unknown): value is string {
  if (!matchesPattern(artifactRefPattern, value) || value.length < 1 || value.length > 1024 || value.startsWith("/") || value.includes("\\") || /[?#]/.test(value)) {
    return false;
  }
  return value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function validateRootDelegation(value: RootDelegationV1, requireSignature: boolean): void {
  assertRecord(value);
  closeRootDelegation(value);
  if (value.schema_version !== rootDelegationSchemaVersion || !matchesPattern(newIDPattern, value.source_id) || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  validateEpochChain(value.root_epoch, value.previous_root_epoch, value.previous_delegation_sha256);
  validateTimeRange(value.generated_at, value.expires_at);
  if (!Array.isArray(value.delegated_keys) || value.delegated_keys.length < 1 || value.delegated_keys.length > 32) invalidDocument();
  let previous = "";
  for (const key of value.delegated_keys) {
    if (key.algorithm !== signatureAlgorithmEd25519 || !matchesPattern(newIDPattern, key.key_id) || compareUTF8(key.key_id, previous) <= 0) invalidDocument();
    decodeBase64(key.public_key, 32);
    if (!Array.isArray(key.usages) || key.usages.length < 1 || key.usages.length > 8) invalidDocument();
    let previousUsage = -1;
    for (const usage of key.usages) {
      const rank = delegatedUsageOrder.indexOf(usage);
      if (rank < 0 || rank <= previousUsage) invalidDocument();
      previousUsage = rank;
    }
    const sourceWide = key.usages.every((usage: DelegatedKeyUsage) => usage === "signing_ledger" || usage === "trusted_time");
    const hasSourceWide = key.usages.some((usage: DelegatedKeyUsage) => usage === "signing_ledger" || usage === "trusted_time");
    if (hasSourceWide !== sourceWide) invalidDocument();
    validateSortedIDs(key.channels, sourceWide ? 0 : 1, sourceWide ? 0 : 16);
    validateTimeRange(key.valid_from, key.valid_until);
    if (parseCanonicalTime(key.valid_until) > parseCanonicalTime(value.expires_at)) invalidDocument();
    previous = key.key_id;
  }
  if (requireSignature) decodeBase64(value.signature, 64);
  else if (value.signature !== "") invalidDocument();
}

function validatePackageInput(value: PackageSigningInput): void {
  assertRecord(value);
  exactKeys(value, ["source_id", "channel", "version", "algorithm", "key_id", "publisher_id", "plugin_id", "package_hash", "manifest_hash", "entries_hash", "signed_at"]);
  if (!matchesPattern(newIDPattern, value.source_id) || !matchesPattern(newIDPattern, value.channel) || value.algorithm !== signatureAlgorithmEd25519 || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  if (!matchesPattern(legacyIDPattern, value.publisher_id) || !matchesPattern(legacyIDPattern, value.plugin_id) || !matchesPattern(semverPattern, value.version)) invalidDocument();
  if (!matchesPattern(prefixedSHA256Pattern, value.package_hash) || !matchesPattern(prefixedSHA256Pattern, value.manifest_hash) || !matchesPattern(prefixedSHA256Pattern, value.entries_hash)) invalidDocument();
  parseCanonicalTime(value.signed_at);
}

function packageInputFromDocument(context: PackageVerificationContext, value: PackageSignatureV1): PackageSigningInput {
  return {
    ...context,
    algorithm: value.algorithm,
    key_id: value.key_id,
    publisher_id: value.publisher_id ?? "",
    plugin_id: value.plugin_id ?? "",
    package_hash: value.package_hash,
    manifest_hash: value.manifest_hash,
    entries_hash: value.entries_hash,
    signed_at: value.signed_at ?? "",
  };
}

function validatePackageSignature(context: PackageVerificationContext, value: PackageSignatureV1, requireSignature: boolean): void {
  assertRecord(context);
  exactKeys(context, ["source_id", "channel", "version"]);
  assertRecord(value);
  closePackageSignature(value);
  if (value.schema_version !== packageSignatureSchemaVersion || value.publisher_id === undefined || value.plugin_id === undefined || value.signed_at === undefined) invalidDocument();
  validatePackageInput(packageInputFromDocument(context, value));
  if (requireSignature) decodeBase64(value.signature, 64);
  else if (value.signature !== "") invalidDocument();
}

function validateReleaseMetadata(value: ReleaseMetadataV5): void {
  assertRecord(value);
  closeReleaseMetadata(value);
  if (value.schema_version !== releaseMetadataSchemaVersion || !matchesPattern(newIDPattern, value.source_id)) invalidDocument();
  if (!matchesPattern(legacyIDPattern, value.publisher_id) || !matchesPattern(legacyIDPattern, value.plugin_id) || !matchesPattern(semverPattern, value.version) || !validArtifactRef(value.release_metadata_ref)) invalidDocument();
  if ((value.distribution_ref.distribution !== "registry_ref" && value.distribution_ref.distribution !== "host_artifact_ref") || !validArtifactRef(value.distribution_ref.artifact_ref)) invalidDocument();
  if (!legacySHA256Pattern.test(value.hashes.package_sha256) || !legacySHA256Pattern.test(value.hashes.manifest_sha256) || !legacySHA256Pattern.test(value.hashes.entries_sha256)) invalidDocument();
  const metadataSignature = value.release_metadata_signature;
  if (metadataSignature.algorithm !== signatureAlgorithmEd25519 || !matchesPattern(newIDPattern, metadataSignature.key_id) || !validArtifactRef(metadataSignature.signature_ref) || !matchesPattern(epochPattern, metadataSignature.source_policy_epoch) || !matchesPattern(epochPattern, metadataSignature.revocation_epoch)) invalidDocument();
  const packageSignature = value.package_signature;
  if (packageSignature.algorithm !== signatureAlgorithmEd25519 || !matchesPattern(newIDPattern, packageSignature.key_id) || !validArtifactRef(packageSignature.signature_bundle_ref) || !matchesPattern(epochPattern, packageSignature.source_policy_epoch) || !matchesPattern(epochPattern, packageSignature.revocation_epoch)) invalidDocument();
  if (!matchesPattern(semverPattern, value.compatibility.min_redevplugin_version) || !matchesPattern(semverPattern, value.compatibility.min_runtime_version) || value.compatibility.ui_protocol_version !== "plugin-ui-v5") invalidDocument();
  if (value.compatibility.supported_targets !== undefined) {
    if (!Array.isArray(value.compatibility.supported_targets)) invalidDocument();
    const allowed = new Set(["darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"]);
    let previous = "";
    for (const target of value.compatibility.supported_targets) {
      if (typeof target !== "string" || !allowed.has(target) || compareUTF8(target, previous) <= 0) invalidDocument();
      previous = target;
    }
  }
  let previousHost = "";
  for (const requirement of value.host_requirements ?? []) {
    if (!matchesPattern(legacyIDPattern, requirement.host_id) || compareUTF8(requirement.host_id, previousHost) <= 0) invalidDocument();
    if (requirement.min_host_version !== undefined && !matchesPattern(semverPattern, requirement.min_host_version)) invalidDocument();
    let previousCapability = "";
    for (const capability of requirement.required_capability_contracts ?? []) {
      if (!matchesPattern(legacyIDPattern, capability.capability_id) || !matchesPattern(semverPattern, capability.capability_version)) invalidDocument();
      const identity = `${capability.capability_id}\0${capability.capability_version}`;
      if (compareUTF8(identity, previousCapability) <= 0) invalidDocument();
      validateCapabilityContractRef(capability.contract);
      previousCapability = identity;
    }
    previousHost = requirement.host_id;
  }
  if (value.release_evidence !== undefined) {
    if (value.release_evidence.notices_sha256 !== undefined && !legacySHA256Pattern.test(value.release_evidence.notices_sha256)) invalidDocument();
    if (value.release_evidence.provenance_sha256 !== undefined && !legacySHA256Pattern.test(value.release_evidence.provenance_sha256)) invalidDocument();
    if (value.release_evidence.generated_at !== undefined) parseCanonicalTime(value.release_evidence.generated_at);
  }
  if (value.metadata !== undefined) {
    const entries = Object.entries(value.metadata);
    if (entries.length > 128 || entries.some(([key, item]) => {
      if (key.length < 1 || key.length > 128 || typeof item !== "string" || item.length > 4096) return true;
      assertWellFormedString(key);
      assertWellFormedString(item);
      return false;
    })) invalidDocument();
  }
}

function validateCapabilityContractRef(value: HostCapabilityContractRef): void {
  if (![value.publisher_id, value.contract_id, value.signature_key_id].every((item) => matchesPattern(legacyIDPattern, item)) || !matchesPattern(semverPattern, value.contract_version)) invalidDocument();
  if (!matchesPattern(epochPattern, value.signature_policy_epoch) || !matchesPattern(epochPattern, value.signature_revocation_epoch)) invalidDocument();
  if (![value.artifact_ref, value.manifest_ref, value.signature_ref, value.compatibility_ref, value.generated_client_ref, value.notices_ref].every(validArtifactRef)) invalidDocument();
  if (![value.artifact_sha256, value.manifest_sha256, value.signature_sha256, value.compatibility_sha256, value.generated_client_sha256, value.notices_sha256].every((item) => sha256Pattern.test(item))) invalidDocument();
}

function validateSourcePolicy(value: SourcePolicyV2, requireSignature: boolean): void {
  assertRecord(value);
  closeSourcePolicy(value);
  if (value.schema_version !== sourcePolicySchemaVersion || !matchesPattern(newIDPattern, value.source_id) || !matchesPattern(newIDPattern, value.channel) || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  validateEpochChain(value.epoch, value.previous_epoch, value.previous_document_sha256);
  if (!matchesPattern(positiveEpochPattern, value.root_epoch) || !matchesPattern(epochPattern, value.minimum_revocation_epoch)) invalidDocument();
  if (value.source_type !== "registry" && value.source_type !== "host_artifact") invalidDocument();
  if (!new Set(["official", "curated", "community", "private"]).has(value.source_class)) invalidDocument();
  validateSortedIDs(value.allowed_publishers, 1, 1024);
  if (!Array.isArray(value.allowed_artifact_hosts) || value.allowed_artifact_hosts.length > 1024) invalidDocument();
  let previousHost = "";
  for (const host of value.allowed_artifact_hosts) {
    if (!matchesPattern(hostnamePattern, host) || host.length > 253 || host.toLowerCase() !== host || compareUTF8(host, previousHost) <= 0) invalidDocument();
    previousHost = host;
  }
  for (const keys of [
    value.active_keys.package,
    value.active_keys.release_metadata,
    value.active_keys.source_policy_pointer,
    value.active_keys.revocation_document,
    value.active_keys.revocation_pointer,
  ]) validateSortedIDs(keys, 1, 16);
  if (!new Set(["allow", "review_required", "block"]).has(value.install_policy)) invalidDocument();
  if (!new Set(["dev_only", "review_required", "block"]).has(value.unsigned_policy)) invalidDocument();
  if (!new Set(["review_required", "block"]).has(value.downgrade_policy)) invalidDocument();
  if (canonicalJSONString(value.limits) !== canonicalJSONString(defaultSourcePolicyLimits)) invalidDocument();
  validateTimeRange(value.generated_at, value.expires_at, 24 * 60 * 60 * 1000);
  if (requireSignature) decodeBase64(value.signature, 64);
  else if (value.signature !== "") invalidDocument();
}

function validatePointer(
  value: ReleasePointerInput & { schema_version: string; signature: string },
  expectedSchemaVersion: string,
  requireSignature: boolean,
): void {
  assertRecord(value);
  closePointer(value);
  if (value.schema_version !== expectedSchemaVersion || !matchesPattern(newIDPattern, value.source_id) || !matchesPattern(newIDPattern, value.channel) || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  validateEpochChain(value.epoch, value.previous_epoch, value.previous_document_sha256);
  if (!validArtifactRef(value.ref) || !sha256Pattern.test(value.document_sha256) || value.document_sha256 === genesisPreviousDocumentSHA256) invalidDocument();
  validateTimeRange(value.generated_at, value.expires_at, 24 * 60 * 60 * 1000);
  if (requireSignature) decodeBase64(value.signature, 64);
  else if (value.signature !== "") invalidDocument();
}

function validateRevocation(value: RevocationV2, requireSignature: boolean): void {
  assertRecord(value);
  closeRevocation(value);
  if (value.schema_version !== revocationSchemaVersion || !matchesPattern(newIDPattern, value.source_id) || !matchesPattern(newIDPattern, value.channel) || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  validateEpochChain(value.epoch, value.previous_epoch, value.previous_document_sha256);
  if (!matchesPattern(positiveEpochPattern, value.root_epoch)) invalidDocument();
  validateTimeRange(value.generated_at, value.expires_at, 24 * 60 * 60 * 1000);
  validateSortedIDs(value.revoked_key_ids, 0, 4096);
  if (!Array.isArray(value.revoked_releases) || value.revoked_releases.length > 16384) invalidDocument();
  let previous = "";
  for (const revoked of value.revoked_releases) {
    if (!matchesPattern(legacyIDPattern, revoked.publisher_id) || !matchesPattern(legacyIDPattern, revoked.plugin_id) || !matchesPattern(semverPattern, revoked.version) || !matchesPattern(sha256Pattern, revoked.release_metadata_sha256)) invalidDocument();
    const identity = `${revoked.publisher_id}\0${revoked.plugin_id}\0${revoked.version}\0${revoked.release_metadata_sha256}`;
    if (compareUTF8(identity, previous) <= 0) invalidDocument();
    if (parseCanonicalTime(revoked.revoked_at) > parseCanonicalTime(value.expires_at)) invalidDocument();
    previous = identity;
  }
  if (requireSignature) decodeBase64(value.signature, 64);
  else if (value.signature !== "") invalidDocument();
}

function validateSigningLedgerEvidence(value: SigningLedgerEvidenceV1): void {
  assertRecord(value);
  closeSigningLedgerEvidence(value);
  if (value.schema_version !== releaseSigningLedgerEvidenceSchemaVersion || !matchesPattern(newIDPattern, value.source_id)) invalidDocument();
  if (value.channel !== undefined && !matchesPattern(newIDPattern, value.channel)) invalidDocument();
  for (const digest of [
    value.subject_identity_sha256,
    value.signing_preimage_sha256,
    value.signature_envelope_sha256,
    value.receipt_sha256,
    value.checkpoint_sha256,
    value.inclusion_proof_sha256,
    value.latest_proof_sha256,
  ]) {
    if (!sha256Pattern.test(digest)) invalidDocument();
  }
  for (const reference of [
    value.receipt_ref,
    value.checkpoint_ref,
    value.inclusion_proof_ref,
    value.latest_proof_ref,
  ]) {
    if (!validArtifactRef(reference)) invalidDocument();
  }
  if ((value.consistency_proof_ref === undefined) !== (value.consistency_proof_sha256 === undefined)) invalidDocument();
  if (value.consistency_proof_ref !== undefined && (!validArtifactRef(value.consistency_proof_ref) || !sha256Pattern.test(value.consistency_proof_sha256!))) invalidDocument();
}

function validateSigningSubject(value: SigningSubjectV1): void {
  assertRecord(value);
  closeSigningSubject(value);
  if (value.schema_version !== signingSubjectSchemaVersion || !matchesPattern(newIDPattern, value.source_id)) invalidDocument();
  if (value.usage === "root_delegation") {
    if (!matchesPattern(positiveEpochPattern, value.root_epoch)) invalidDocument();
    return;
  }
  if (value.usage === "package" || value.usage === "release_metadata") {
    if (!matchesPattern(newIDPattern, value.channel) || !matchesPattern(legacyIDPattern, value.publisher_id) ||
      !matchesPattern(legacyIDPattern, value.plugin_id) || !matchesPattern(semverPattern, value.version) ||
      !matchesPattern(sha256Pattern, value.artifact_or_metadata_identity_sha256)) invalidDocument();
    return;
  }
  if (["source_policy_document", "source_policy_pointer", "revocation_document", "revocation_pointer"].includes(value.usage)) {
    if (!matchesPattern(newIDPattern, value.channel) || !matchesPattern(positiveEpochPattern, value.epoch)) invalidDocument();
    return;
  }
  invalidDocument();
}

function validateSignatureEnvelope(value: SignatureEnvelopeV1): void {
  assertRecord(value);
  closeSignatureEnvelope(value);
  if (value.schema_version !== signatureEnvelopeSchemaVersion || !matchesPattern(sha256Pattern, value.subject_identity_sha256) ||
    !matchesPattern(sha256Pattern, value.signing_preimage_sha256) || value.algorithm !== signatureAlgorithmEd25519 ||
    !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  decodeBase64(value.signature, 64);
}

function validateSigningLedgerEntry(value: SigningLedgerEntryV1): void {
  assertRecord(value);
  closeSigningLedgerEntry(value);
  if (value.schema_version !== signingLedgerEntrySchemaVersion || !matchesPattern(sha256Pattern, value.subject_identity_sha256) ||
    !matchesPattern(sha256Pattern, value.signing_preimage_sha256) || value.algorithm !== signatureAlgorithmEd25519 ||
    !matchesPattern(newIDPattern, value.key_id) || !Number.isSafeInteger(value.revision) || value.revision < 1) invalidDocument();
  validateSigningSubject(value.subject);
  const reservedAt = parseCanonicalTime(value.reserved_at);
  if (value.state === "reserved") {
    if (value.signature_envelope !== undefined || value.signature_envelope_sha256 !== undefined || value.finalized_at !== undefined ||
      value.failure_code !== undefined || value.failed_at !== undefined) invalidDocument();
    return;
  }
  if (value.state === "finalized") {
    if (value.signature_envelope === undefined || !matchesPattern(sha256Pattern, value.signature_envelope_sha256) ||
      value.finalized_at === undefined || value.failure_code !== undefined || value.failed_at !== undefined) invalidDocument();
    validateSignatureEnvelope(value.signature_envelope);
    if (value.signature_envelope.subject_identity_sha256 !== value.subject_identity_sha256 ||
      value.signature_envelope.signing_preimage_sha256 !== value.signing_preimage_sha256 ||
      value.signature_envelope.algorithm !== value.algorithm || value.signature_envelope.key_id !== value.key_id ||
      parseCanonicalTime(value.finalized_at) < reservedAt) invalidDocument();
    return;
  }
  if (value.state === "terminal_failed") {
    if (value.signature_envelope !== undefined || value.signature_envelope_sha256 !== undefined || value.finalized_at !== undefined ||
      value.failure_code === undefined || !["signer_rejected", "subject_conflict", "ledger_rejected"].includes(value.failure_code) ||
      value.failed_at === undefined || parseCanonicalTime(value.failed_at) < reservedAt) invalidDocument();
    return;
  }
  invalidDocument();
}

function validateSigningLedgerLogLeaf(value: SigningLedgerLogLeafV1): void {
  assertRecord(value);
  closeSigningLedgerLogLeaf(value);
  if (value.schema_version !== signingLedgerLogLeafSchemaVersion || !matchesPattern(newIDPattern, value.source_id) ||
    (value.channel !== undefined && !matchesPattern(newIDPattern, value.channel)) ||
    !matchesPattern(sha256Pattern, value.subject_identity_sha256) || !matchesPattern(sha256Pattern, value.signing_preimage_sha256) ||
    !matchesPattern(sha256Pattern, value.signature_envelope_sha256) || !Number.isSafeInteger(value.sequence) || value.sequence < 1) invalidDocument();
}

function validateSigningLedgerCheckpoint(value: SigningLedgerCheckpointV1): void {
  assertRecord(value);
  closeSigningLedgerCheckpoint(value);
  if (value.schema_version !== signingLedgerSchemaVersion || value.kind !== "checkpoint" || !matchesPattern(newIDPattern, value.log_id) ||
    !Number.isSafeInteger(value.tree_size) || value.tree_size < 1 || !matchesPattern(sha256Pattern, value.log_root_hash) ||
    !matchesPattern(sha256Pattern, value.latest_map_root_hash) || !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  parseCanonicalTime(value.checkpoint_time);
  decodeBase64(value.signature, 64);
}

function validateSigningLedgerReceipt(value: SigningLedgerReceiptV1): void {
  assertRecord(value);
  closeSigningLedgerReceipt(value);
  if (value.schema_version !== signingLedgerReceiptSchemaVersion || !matchesPattern(newIDPattern, value.log_id) ||
    !matchesPattern(newIDPattern, value.source_id) || (value.channel !== undefined && !matchesPattern(newIDPattern, value.channel)) ||
    !matchesPattern(sha256Pattern, value.subject_identity_sha256) || !matchesPattern(sha256Pattern, value.signing_preimage_sha256) ||
    !matchesPattern(sha256Pattern, value.signature_envelope_sha256) || !Number.isSafeInteger(value.sequence) || value.sequence < 1 ||
    !Number.isSafeInteger(value.leaf_index) || value.leaf_index !== value.sequence - 1 || !Number.isSafeInteger(value.tree_size) ||
    value.tree_size < value.sequence || !matchesPattern(sha256Pattern, value.log_root_hash) ||
    !matchesPattern(sha256Pattern, value.latest_map_root_hash) || !matchesPattern(sha256Pattern, value.checkpoint_sha256) ||
    !matchesPattern(newIDPattern, value.key_id)) invalidDocument();
  parseCanonicalTime(value.checkpoint_time);
  decodeBase64(value.signature, 64);
}

function validateLedgerNodes(value: readonly string[], exact?: number): void {
  if (!Array.isArray(value) || (exact === undefined ? value.length > 64 : value.length !== exact) ||
    value.some((node) => !matchesPattern(sha256Pattern, node))) invalidDocument();
}

function validateSigningLedgerInclusionProof(value: SigningLedgerInclusionProofV1): void {
  assertRecord(value);
  closeSigningLedgerInclusionProof(value);
  if (value.schema_version !== signingLedgerSchemaVersion || value.kind !== "inclusion_proof" || !matchesPattern(newIDPattern, value.log_id) ||
    !Number.isSafeInteger(value.leaf_index) || value.leaf_index < 0 || !Number.isSafeInteger(value.tree_size) ||
    value.tree_size < 1 || value.leaf_index >= value.tree_size) invalidDocument();
  validateLedgerNodes(value.nodes);
}

function validateSigningLedgerLatestProof(value: SigningLedgerLatestProofV1): void {
  assertRecord(value);
  closeSigningLedgerLatestProof(value);
  if (value.schema_version !== signingLedgerSchemaVersion || value.kind !== "latest_proof" || !matchesPattern(newIDPattern, value.log_id) ||
    !matchesPattern(sha256Pattern, value.subject_identity_sha256) || typeof value.present !== "boolean") invalidDocument();
  validateLedgerNodes(value.siblings, 256);
  if (value.present) {
    if (!Number.isSafeInteger(value.sequence) || value.sequence! < 1 || !matchesPattern(sha256Pattern, value.signing_preimage_sha256) ||
      !matchesPattern(sha256Pattern, value.signature_envelope_sha256)) invalidDocument();
  } else if (value.sequence !== undefined || value.signing_preimage_sha256 !== undefined || value.signature_envelope_sha256 !== undefined) {
    invalidDocument();
  }
}

function validateSigningLedgerConsistencyProof(value: SigningLedgerConsistencyProofV1): void {
  assertRecord(value);
  closeSigningLedgerConsistencyProof(value);
  if (value.schema_version !== signingLedgerSchemaVersion || value.kind !== "consistency_proof" || !matchesPattern(newIDPattern, value.log_id) ||
    !Number.isSafeInteger(value.old_tree_size) || value.old_tree_size < 1 || !Number.isSafeInteger(value.new_tree_size) ||
    value.new_tree_size < value.old_tree_size) invalidDocument();
  validateLedgerNodes(value.nodes);
}

function decodeCanonicalDocument<T>(
  raw: Uint8Array | string,
  close: (value: Record<string, unknown>) => void,
  validate: (value: T) => void,
): T {
  const bytes = typeof raw === "string" ? textEncoder.encode(raw) : raw;
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > maximumDocumentBytes) invalidDocument();
  let source: string;
  try {
    source = textDecoder.decode(bytes);
  } catch {
    invalidDocument();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    invalidDocument();
  }
  assertRecord(parsed);
  close(parsed);
  validate(parsed as T);
  if (canonicalJSONString(parsed) !== source) invalidDocument();
  return deepFreeze(cloneJSON(parsed as T));
}

function closeRootDelegation(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "source_id", "root_epoch", "previous_root_epoch", "previous_delegation_sha256", "generated_at", "expires_at", "delegated_keys", "key_id", "signature"]);
  if (!Array.isArray(value.delegated_keys)) invalidDocument();
  for (const item of value.delegated_keys) {
    assertRecord(item);
    exactKeys(item, ["algorithm", "key_id", "public_key", "usages", "channels", "valid_from", "valid_until"]);
  }
}

function closePackageSignature(value: Record<string, unknown>): void {
  exactOptionalKeys(value, ["schema_version", "algorithm", "key_id", "package_hash", "manifest_hash", "entries_hash", "signature"], ["publisher_id", "plugin_id", "signed_at"]);
}

function closeReleaseMetadata(value: Record<string, unknown>): void {
  exactOptionalKeys(value, ["schema_version", "source_id", "release_metadata_ref", "publisher_id", "plugin_id", "version", "distribution_ref", "hashes", "release_metadata_signature", "package_signature", "compatibility"], ["host_requirements", "release_evidence", "metadata"]);
  for (const [key, keys] of [
    ["distribution_ref", ["distribution", "artifact_ref"]],
    ["hashes", ["package_sha256", "manifest_sha256", "entries_sha256"]],
    ["release_metadata_signature", ["algorithm", "key_id", "signature_ref", "source_policy_epoch", "revocation_epoch"]],
    ["package_signature", ["algorithm", "key_id", "signature_bundle_ref", "source_policy_epoch", "revocation_epoch"]],
  ] as const) {
    assertRecord(value[key]);
    exactKeys(value[key], keys);
  }
  assertRecord(value.compatibility);
  exactOptionalKeys(value.compatibility, ["min_redevplugin_version", "min_runtime_version", "ui_protocol_version"], ["supported_targets"]);
  if (value.host_requirements !== undefined) {
    if (!Array.isArray(value.host_requirements)) invalidDocument();
    for (const host of value.host_requirements) {
      assertRecord(host);
      exactOptionalKeys(host, ["host_id"], ["min_host_version", "required_capability_contracts"]);
      if (host.required_capability_contracts !== undefined) {
        if (!Array.isArray(host.required_capability_contracts)) invalidDocument();
        for (const requirement of host.required_capability_contracts) {
          assertRecord(requirement);
          exactKeys(requirement, ["capability_id", "capability_version", "contract"]);
          assertRecord(requirement.contract);
          exactKeys(requirement.contract, ["publisher_id", "contract_id", "contract_version", "artifact_ref", "artifact_sha256", "manifest_ref", "manifest_sha256", "signature_ref", "signature_sha256", "signature_key_id", "signature_policy_epoch", "signature_revocation_epoch", "compatibility_ref", "compatibility_sha256", "generated_client_ref", "generated_client_sha256", "notices_ref", "notices_sha256"]);
        }
      }
    }
  }
  if (value.release_evidence !== undefined) {
    assertRecord(value.release_evidence);
    exactOptionalKeys(value.release_evidence, [], ["notices_sha256", "provenance_sha256", "generated_at"]);
  }
  if (value.metadata !== undefined) assertRecord(value.metadata);
}

function closeSourcePolicy(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "source_id", "channel", "epoch", "previous_epoch", "previous_document_sha256", "root_epoch", "source_type", "source_class", "allowed_publishers", "allowed_artifact_hosts", "active_keys", "require_signature", "install_policy", "unsigned_policy", "downgrade_policy", "minimum_revocation_epoch", "limits", "generated_at", "expires_at", "key_id", "signature"]);
  assertRecord(value.active_keys);
  exactKeys(value.active_keys, ["package", "release_metadata", "source_policy_pointer", "revocation_document", "revocation_pointer"]);
  assertRecord(value.limits);
  exactKeys(value.limits, ["document_max_lifetime_seconds", "future_skew_seconds", "activation_lease_max_seconds", "refresh_interval_max_seconds", "failure_teardown_deadline_seconds"]);
}

function closePointer(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "source_id", "channel", "epoch", "previous_epoch", "previous_document_sha256", "ref", "document_sha256", "generated_at", "expires_at", "key_id", "signature"]);
}

function closeRevocation(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "source_id", "channel", "epoch", "previous_epoch", "previous_document_sha256", "root_epoch", "generated_at", "expires_at", "revoked_key_ids", "revoked_releases", "key_id", "signature"]);
  if (!Array.isArray(value.revoked_releases)) invalidDocument();
  for (const item of value.revoked_releases) {
    assertRecord(item);
    exactKeys(item, ["publisher_id", "plugin_id", "version", "release_metadata_sha256", "revoked_at"]);
  }
}

function closeSigningLedgerEvidence(value: Record<string, unknown>): void {
  exactOptionalKeys(
    value,
    [
      "schema_version",
      "source_id",
      "subject_identity_sha256",
      "signing_preimage_sha256",
      "signature_envelope_sha256",
      "receipt_ref",
      "receipt_sha256",
      "checkpoint_ref",
      "checkpoint_sha256",
      "inclusion_proof_ref",
      "inclusion_proof_sha256",
      "latest_proof_ref",
      "latest_proof_sha256",
    ],
    ["channel", "consistency_proof_ref", "consistency_proof_sha256"],
  );
}

function closeSigningSubject(value: Record<string, unknown>): void {
  if (value.usage === "root_delegation") {
    exactKeys(value, ["schema_version", "usage", "source_id", "root_epoch"]);
  } else if (value.usage === "package" || value.usage === "release_metadata") {
    exactKeys(value, ["schema_version", "usage", "source_id", "channel", "publisher_id", "plugin_id", "version", "artifact_or_metadata_identity_sha256"]);
  } else {
    exactKeys(value, ["schema_version", "usage", "source_id", "channel", "epoch"]);
  }
}

function closeSignatureEnvelope(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "subject_identity_sha256", "signing_preimage_sha256", "algorithm", "key_id", "signature"]);
}

function closeSigningLedgerEntry(value: Record<string, unknown>): void {
  exactOptionalKeys(value, [
    "schema_version", "state", "subject", "subject_identity_sha256", "signing_preimage_sha256",
    "algorithm", "key_id", "revision", "reserved_at",
  ], ["signature_envelope", "signature_envelope_sha256", "finalized_at", "failure_code", "failed_at"]);
  assertRecord(value.subject);
  closeSigningSubject(value.subject);
  if (value.signature_envelope !== undefined) {
    assertRecord(value.signature_envelope);
    closeSignatureEnvelope(value.signature_envelope);
  }
}

function closeSigningLedgerLogLeaf(value: Record<string, unknown>): void {
  exactOptionalKeys(value, [
    "schema_version", "source_id", "subject_identity_sha256", "signing_preimage_sha256", "signature_envelope_sha256", "sequence",
  ], ["channel"]);
}

function closeSigningLedgerCheckpoint(value: Record<string, unknown>): void {
  exactKeys(value, [
    "schema_version", "kind", "log_id", "tree_size", "log_root_hash", "latest_map_root_hash", "checkpoint_time", "key_id", "signature",
  ]);
}

function closeSigningLedgerReceipt(value: Record<string, unknown>): void {
  exactOptionalKeys(value, [
    "schema_version", "log_id", "source_id", "subject_identity_sha256", "signing_preimage_sha256",
    "signature_envelope_sha256", "sequence", "leaf_index", "tree_size", "log_root_hash", "latest_map_root_hash",
    "checkpoint_sha256", "checkpoint_time", "key_id", "signature",
  ], ["channel"]);
}

function closeSigningLedgerInclusionProof(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "kind", "log_id", "leaf_index", "tree_size", "nodes"]);
}

function closeSigningLedgerLatestProof(value: Record<string, unknown>): void {
  exactOptionalKeys(value, ["schema_version", "kind", "log_id", "subject_identity_sha256", "present", "siblings"], [
    "sequence", "signing_preimage_sha256", "signature_envelope_sha256",
  ]);
}

function closeSigningLedgerConsistencyProof(value: Record<string, unknown>): void {
  exactKeys(value, ["schema_version", "kind", "log_id", "old_tree_size", "new_tree_size", "nodes"]);
}

export function buildRootDelegation(input: RootDelegationInput, signature: Uint8Array): RootDelegationV1 {
  requireSignatureBytes(signature);
  const document: RootDelegationV1 = {
    schema_version: rootDelegationSchemaVersion,
    ...cloneJSON(input),
    signature: encodeBase64(signature),
  };
  validateRootDelegation(document, true);
  return deepFreeze(document);
}

export function rootDelegationSigningPreimage(input: RootDelegationInput): Uint8Array {
  const document = { schema_version: rootDelegationSchemaVersion, ...cloneJSON(input), signature: "" } satisfies RootDelegationV1;
  validateRootDelegation(document, false);
  return preimageWithoutTopLevelSignature(signingUsages.rootDelegation, document);
}

export function canonicalRootDelegation(document: RootDelegationV1): Uint8Array {
  validateRootDelegation(document, true);
  return canonicalJSON(document);
}

export async function verifyRootDelegation(document: RootDelegationV1, verifier: SignatureVerifier): Promise<void> {
  await verifyEncoded(signingUsages.rootDelegation, document.key_id, rootDelegationSigningPreimage(unsignedDocument<RootDelegationInput>(document)), document.signature, verifier);
}

export function buildPackageSignature(input: PackageSigningInput, signature: Uint8Array): PackageSignatureV1 {
  requireSignatureBytes(signature);
  validatePackageInput(input);
  const document: PackageSignatureV1 = {
    schema_version: packageSignatureSchemaVersion,
    algorithm: input.algorithm,
    key_id: input.key_id,
    publisher_id: input.publisher_id,
    plugin_id: input.plugin_id,
    package_hash: input.package_hash,
    manifest_hash: input.manifest_hash,
    entries_hash: input.entries_hash,
    signature: encodeBase64(signature),
    signed_at: input.signed_at,
  };
  validatePackageSignature({ source_id: input.source_id, channel: input.channel, version: input.version }, document, true);
  return deepFreeze(document);
}

export function packageSigningPreimage(input: PackageSigningInput): Uint8Array {
  validatePackageInput(input);
  return signingPreimage(signingUsages.package, {
    channel: input.channel,
    package_signature: {
      algorithm: input.algorithm,
      entries_hash: input.entries_hash,
      key_id: input.key_id,
      manifest_hash: input.manifest_hash,
      package_hash: input.package_hash,
      plugin_id: input.plugin_id,
      publisher_id: input.publisher_id,
      schema_version: packageSignatureSchemaVersion,
      signed_at: input.signed_at,
    },
    source_id: input.source_id,
    version: input.version,
  });
}

export function canonicalPackageSignature(context: PackageVerificationContext, document: PackageSignatureV1): Uint8Array {
  validatePackageSignature(context, document, true);
  return canonicalJSON(document);
}

export async function verifyPackageSignature(
  context: PackageVerificationContext,
  document: PackageSignatureV1,
  verifier: SignatureVerifier,
): Promise<void> {
  validatePackageSignature(context, document, true);
  const input = packageInputFromDocument(context, document);
  await verifyEncoded(signingUsages.package, document.key_id, packageSigningPreimage(input), document.signature, verifier);
}

export function buildReleaseMetadata(document: ReleaseMetadataV5): ReleaseMetadataV5 {
  const cloned = cloneJSON(document);
  validateReleaseMetadata(cloned);
  return deepFreeze(cloned);
}

export function releaseMetadataSigningPreimage(channel: string, document: ReleaseMetadataV5): Uint8Array {
  if (!matchesPattern(newIDPattern, channel)) invalidDocument();
  const built = buildReleaseMetadata(document);
  return signingPreimage(signingUsages.releaseMetadata, { channel, release_metadata: built });
}

export function canonicalReleaseMetadata(document: ReleaseMetadataV5): Uint8Array {
  return canonicalJSON(buildReleaseMetadata(document));
}

export async function verifyReleaseMetadata(
  channel: string,
  document: ReleaseMetadataV5,
  signature: Uint8Array,
  verifier: SignatureVerifier,
): Promise<void> {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new InvalidReleaseSignatureError();
  }
  await verifyRaw(signingUsages.releaseMetadata, document.release_metadata_signature.key_id, releaseMetadataSigningPreimage(channel, document), signature, verifier);
}

export function buildSourcePolicy(input: SourcePolicyInput, signature: Uint8Array): SourcePolicyV2 {
  requireSignatureBytes(signature);
  const document: SourcePolicyV2 = {
    schema_version: sourcePolicySchemaVersion,
    ...cloneJSON(input),
    signature: encodeBase64(signature),
  };
  validateSourcePolicy(document, true);
  return deepFreeze(document);
}

export function sourcePolicySigningPreimage(input: SourcePolicyInput): Uint8Array {
  const document = { schema_version: sourcePolicySchemaVersion, ...cloneJSON(input), signature: "" } satisfies SourcePolicyV2;
  validateSourcePolicy(document, false);
  return preimageWithoutTopLevelSignature(signingUsages.sourcePolicy, document);
}

export function canonicalSourcePolicy(document: SourcePolicyV2): Uint8Array {
  validateSourcePolicy(document, true);
  return canonicalJSON(document);
}

export async function verifySourcePolicy(document: SourcePolicyV2, verifier: SignatureVerifier): Promise<void> {
  await verifyEncoded(signingUsages.sourcePolicy, document.key_id, sourcePolicySigningPreimage(unsignedDocument<SourcePolicyInput>(document)), document.signature, verifier);
}

export function buildSourcePolicyPointer(input: ReleasePointerInput, signature: Uint8Array): SourcePolicyPointerV1 {
  requireSignatureBytes(signature);
  const document: SourcePolicyPointerV1 = {
    schema_version: sourcePolicyPointerSchemaVersion,
    ...cloneJSON(input),
    signature: encodeBase64(signature),
  };
  validatePointer(document, sourcePolicyPointerSchemaVersion, true);
  return deepFreeze(document);
}

export function sourcePolicyPointerSigningPreimage(input: ReleasePointerInput): Uint8Array {
  const document = { schema_version: sourcePolicyPointerSchemaVersion, ...cloneJSON(input), signature: "" } satisfies SourcePolicyPointerV1;
  validatePointer(document, sourcePolicyPointerSchemaVersion, false);
  return preimageWithoutTopLevelSignature(signingUsages.sourcePolicyPointer, document);
}

export function canonicalSourcePolicyPointer(document: SourcePolicyPointerV1): Uint8Array {
  validatePointer(document, sourcePolicyPointerSchemaVersion, true);
  return canonicalJSON(document);
}

export async function verifySourcePolicyPointer(document: SourcePolicyPointerV1, verifier: SignatureVerifier): Promise<void> {
  await verifyEncoded(signingUsages.sourcePolicyPointer, document.key_id, sourcePolicyPointerSigningPreimage(unsignedDocument<ReleasePointerInput>(document)), document.signature, verifier);
}

export function buildRevocation(input: RevocationInput, signature: Uint8Array): RevocationV2 {
  requireSignatureBytes(signature);
  const document: RevocationV2 = {
    schema_version: revocationSchemaVersion,
    ...cloneJSON(input),
    signature: encodeBase64(signature),
  };
  validateRevocation(document, true);
  return deepFreeze(document);
}

export function revocationSigningPreimage(input: RevocationInput): Uint8Array {
  const document = { schema_version: revocationSchemaVersion, ...cloneJSON(input), signature: "" } satisfies RevocationV2;
  validateRevocation(document, false);
  return preimageWithoutTopLevelSignature(signingUsages.revocation, document);
}

export function canonicalRevocation(document: RevocationV2): Uint8Array {
  validateRevocation(document, true);
  return canonicalJSON(document);
}

export async function verifyRevocation(document: RevocationV2, verifier: SignatureVerifier): Promise<void> {
  await verifyEncoded(signingUsages.revocation, document.key_id, revocationSigningPreimage(unsignedDocument<RevocationInput>(document)), document.signature, verifier);
}

export function buildRevocationPointer(input: ReleasePointerInput, signature: Uint8Array): RevocationPointerV1 {
  requireSignatureBytes(signature);
  const document: RevocationPointerV1 = {
    schema_version: revocationPointerSchemaVersion,
    ...cloneJSON(input),
    signature: encodeBase64(signature),
  };
  validatePointer(document, revocationPointerSchemaVersion, true);
  return deepFreeze(document);
}

export function revocationPointerSigningPreimage(input: ReleasePointerInput): Uint8Array {
  const document = { schema_version: revocationPointerSchemaVersion, ...cloneJSON(input), signature: "" } satisfies RevocationPointerV1;
  validatePointer(document, revocationPointerSchemaVersion, false);
  return preimageWithoutTopLevelSignature(signingUsages.revocationPointer, document);
}

export function canonicalRevocationPointer(document: RevocationPointerV1): Uint8Array {
  validatePointer(document, revocationPointerSchemaVersion, true);
  return canonicalJSON(document);
}

export async function verifyRevocationPointer(document: RevocationPointerV1, verifier: SignatureVerifier): Promise<void> {
  await verifyEncoded(signingUsages.revocationPointer, document.key_id, revocationPointerSigningPreimage(unsignedDocument<ReleasePointerInput>(document)), document.signature, verifier);
}

export function decodeRootDelegation(raw: Uint8Array | string): RootDelegationV1 {
  return decodeCanonicalDocument(raw, closeRootDelegation, (value) => validateRootDelegation(value, true));
}

export function decodePackageSignature(raw: Uint8Array | string, context: PackageVerificationContext): PackageSignatureV1 {
  return decodeCanonicalDocument(raw, closePackageSignature, (value) => validatePackageSignature(context, value, true));
}

export function decodeReleaseMetadata(raw: Uint8Array | string): ReleaseMetadataV5 {
  return decodeCanonicalDocument(raw, closeReleaseMetadata, validateReleaseMetadata);
}

export function decodeSourcePolicy(raw: Uint8Array | string): SourcePolicyV2 {
  return decodeCanonicalDocument(raw, closeSourcePolicy, (value) => validateSourcePolicy(value, true));
}

export function decodeSourcePolicyPointer(raw: Uint8Array | string): SourcePolicyPointerV1 {
  return decodeCanonicalDocument(raw, closePointer, (value) => validatePointer(value, sourcePolicyPointerSchemaVersion, true));
}

export function decodeRevocation(raw: Uint8Array | string): RevocationV2 {
  return decodeCanonicalDocument(raw, closeRevocation, (value) => validateRevocation(value, true));
}

export function decodeRevocationPointer(raw: Uint8Array | string): RevocationPointerV1 {
  return decodeCanonicalDocument(raw, closePointer, (value) => validatePointer(value, revocationPointerSchemaVersion, true));
}

export function decodeSigningLedgerEvidence(raw: Uint8Array | string): SigningLedgerEvidenceV1 {
  const bytes = typeof raw === "string" ? textEncoder.encode(raw) : raw;
  if (!(bytes instanceof Uint8Array) || bytes.length > 64 * 1024) invalidDocument();
  return decodeCanonicalDocument(bytes, closeSigningLedgerEvidence, validateSigningLedgerEvidence);
}

export function canonicalSigningSubject(value: SigningSubjectV1): Uint8Array {
  validateSigningSubject(value);
  return canonicalJSON(value);
}

export function decodeSigningSubject(raw: Uint8Array | string): SigningSubjectV1 {
  return decodeCanonicalDocument(raw, closeSigningSubject, validateSigningSubject);
}

export function canonicalSignatureEnvelope(value: SignatureEnvelopeV1): Uint8Array {
  validateSignatureEnvelope(value);
  return canonicalJSON(value);
}

export function decodeSignatureEnvelope(raw: Uint8Array | string): SignatureEnvelopeV1 {
  return decodeCanonicalDocument(raw, closeSignatureEnvelope, validateSignatureEnvelope);
}

export function canonicalSigningLedgerEntry(value: SigningLedgerEntryV1): Uint8Array {
  validateSigningLedgerEntry(value);
  return canonicalJSON(value);
}

export function decodeSigningLedgerEntry(raw: Uint8Array | string): SigningLedgerEntryV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerEntry, validateSigningLedgerEntry);
}

export async function verifySigningLedgerEntryBindings(value: SigningLedgerEntryV1): Promise<void> {
  validateSigningLedgerEntry(value);
  if (await sha256Hex(canonicalSigningSubject(value.subject)) !== value.subject_identity_sha256) invalidDocument();
  if (value.state === "finalized") {
    if (value.signature_envelope === undefined || value.signature_envelope_sha256 === undefined ||
      await sha256Hex(canonicalSignatureEnvelope(value.signature_envelope)) !== value.signature_envelope_sha256) invalidDocument();
  }
}

export function decodeSigningLedgerLogLeaf(raw: Uint8Array | string): SigningLedgerLogLeafV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerLogLeaf, validateSigningLedgerLogLeaf);
}

export function decodeSigningLedgerCheckpoint(raw: Uint8Array | string): SigningLedgerCheckpointV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerCheckpoint, validateSigningLedgerCheckpoint);
}

export function decodeSigningLedgerReceipt(raw: Uint8Array | string): SigningLedgerReceiptV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerReceipt, validateSigningLedgerReceipt);
}

export function decodeSigningLedgerInclusionProof(raw: Uint8Array | string): SigningLedgerInclusionProofV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerInclusionProof, validateSigningLedgerInclusionProof);
}

export function decodeSigningLedgerLatestProof(raw: Uint8Array | string): SigningLedgerLatestProofV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerLatestProof, validateSigningLedgerLatestProof);
}

export function decodeSigningLedgerConsistencyProof(raw: Uint8Array | string): SigningLedgerConsistencyProofV1 {
  return decodeCanonicalDocument(raw, closeSigningLedgerConsistencyProof, validateSigningLedgerConsistencyProof);
}

export function createEd25519Verifier(
  publicKeys: Readonly<Record<string, Uint8Array>>,
  subtle?: SubtleCrypto,
): SignatureVerifier {
  const selectedSubtle = subtle ?? globalThis.crypto?.subtle;
  return async (request) => {
    const publicKey = publicKeys[request.keyID];
    if (selectedSubtle === undefined || publicKey === undefined || publicKey.length !== 32) return false;
    try {
      const key = await selectedSubtle.importKey("raw", toArrayBuffer(publicKey), { name: "Ed25519" }, false, ["verify"]);
      return await selectedSubtle.verify({ name: "Ed25519" }, key, toArrayBuffer(request.signature), toArrayBuffer(request.signingPreimageSHA256));
    } catch {
      return false;
    }
  };
}

async function verifyEncoded(
  usage: SigningUsage,
  keyID: string,
  preimage: Uint8Array,
  encodedSignature: string,
  verifier: SignatureVerifier,
): Promise<void> {
  let signature: Uint8Array;
  try {
    signature = decodeBase64(encodedSignature, 64);
  } catch {
    throw new InvalidReleaseSignatureError();
  }
  await verifyRaw(usage, keyID, preimage, signature, verifier);
}

async function verifyRaw(
  usage: SigningUsage,
  keyID: string,
  preimage: Uint8Array,
  signature: Uint8Array,
  verifier: SignatureVerifier,
): Promise<void> {
  let valid = false;
  try {
	const subtle = globalThis.crypto?.subtle;
	if (subtle === undefined) throw new Error("Web Crypto SHA-256 is unavailable");
	const digest = new Uint8Array(await subtle.digest("SHA-256", toArrayBuffer(preimage)));
    valid = await verifier({
      usage,
      keyID,
	  signingPreimageSHA256: digest,
      signature: signature.slice(),
    });
  } catch {
    valid = false;
  }
  if (!valid) throw new InvalidReleaseSignatureError();
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) invalidDocument();
  const digest = new Uint8Array(await subtle.digest("SHA-256", toArrayBuffer(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function unsignedDocument<T>(value: Readonly<{ schema_version: string; signature: string }>): T {
  const input = cloneJSON(value) as Record<string, unknown>;
  delete input.schema_version;
  delete input.signature;
  return input as T;
}
