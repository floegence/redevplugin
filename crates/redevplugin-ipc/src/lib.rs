use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const RUST_IPC_VERSION: &str = "rust-ipc-v2";
pub const WASM_ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
pub const RUNTIME_LEASE_SIGNATURE_SCHEMA_VERSION: &str = "redevplugin.runtime_execution_lease.v1";
pub const RUNTIME_LEASE_TOKEN_KIND: &str = "runtime_execution_lease";
pub const RUNTIME_LEASE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const WORKER_INVOCATION_TARGET_SCHEMA_VERSION: &str = "redevplugin.worker_invocation_target.v1";
pub const MAX_RUNTIME_LEASE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const FRAME_TYPE_HELLO: &str = "hello";
pub const FRAME_TYPE_HELLO_ACK: &str = "hello_ack";
pub const FRAME_TYPE_HEARTBEAT: &str = "heartbeat";
pub const FRAME_TYPE_INVOKE_WORKER: &str = "invoke_worker";
pub const FRAME_TYPE_INVOKE_WORKER_RESULT: &str = "invoke_worker_result";
pub const FRAME_TYPE_OPEN_HANDLE: &str = "open_handle";
pub const FRAME_TYPE_VALIDATE_HANDLE_GRANT: &str = "validate_handle_grant";
pub const FRAME_TYPE_STORAGE_FILE: &str = "storage_file";
pub const FRAME_TYPE_STORAGE_KV: &str = "storage_kv";
pub const FRAME_TYPE_STORAGE_SQLITE: &str = "storage_sqlite";
pub const FRAME_TYPE_NETWORK_GRANT: &str = "network_grant";
pub const FRAME_TYPE_NETWORK_EXECUTE: &str = "network_execute";
pub const FRAME_TYPE_REVOKE_EPOCH: &str = "revoke_epoch";
pub const FRAME_TYPE_REVOKE_EPOCH_ACK: &str = "revoke_epoch_ack";
pub const ERR_ARTIFACT_HANDLE_FAILED: &str = "ARTIFACT_HANDLE_FAILED";
pub const ERR_HANDLE_GRANT_VALIDATION_FAILED: &str = "HANDLE_GRANT_VALIDATION_FAILED";
pub const ERR_STORAGE_FILE_FAILED: &str = "STORAGE_FILE_FAILED";
pub const ERR_STORAGE_KV_FAILED: &str = "STORAGE_KV_FAILED";
pub const ERR_STORAGE_SQLITE_FAILED: &str = "STORAGE_SQLITE_FAILED";
pub const ERR_NETWORK_GRANT_FAILED: &str = "NETWORK_GRANT_FAILED";
pub const ERR_NETWORK_EXECUTE_FAILED: &str = "NETWORK_EXECUTE_FAILED";
pub const ERR_NETWORK_STREAM_STORE_UNAVAILABLE: &str = "NETWORK_STREAM_STORE_UNAVAILABLE";
pub const ERR_NETWORK_STREAM_FAILED: &str = "NETWORK_STREAM_FAILED";
pub const ERR_NETWORK_STREAM_BACKPRESSURE: &str = "NETWORK_STREAM_BACKPRESSURE";
pub const ERR_NETWORK_STREAM_INVALID: &str = "NETWORK_STREAM_INVALID";
pub const ERR_NETWORK_STREAM_NOT_FOUND: &str = "NETWORK_STREAM_NOT_FOUND";
pub const ERR_NETWORK_STREAM_CLOSED: &str = "NETWORK_STREAM_CLOSED";
pub const ERR_WORKER_INVOCATION_INVALID: &str = "WORKER_INVOCATION_INVALID";
pub const ERR_RUNTIME_CAPABILITY_REVOKED: &str = "RUNTIME_CAPABILITY_REVOKED";
pub const ERR_RUNTIME_CONTROL_CHANNEL_STALE: &str = "RUNTIME_CONTROL_CHANNEL_STALE";
pub const ERR_RUNTIME_LEASE_INVALID: &str = "RUNTIME_LEASE_INVALID";
pub const ERR_RUNTIME_LEASE_SIGNATURE_INVALID: &str = "RUNTIME_LEASE_SIGNATURE_INVALID";
pub const ERR_LEASE_REPLAYED: &str = "PLUGIN_LEASE_REPLAYED";
pub const ERR_WASM_WORKER_INVALID: &str = "WASM_WORKER_INVALID";
pub const ERR_WASM_WORKER_FAILED: &str = "WASM_WORKER_FAILED";
pub const ERR_WASM_HOSTCALL_FAILED: &str = "WASM_HOSTCALL_FAILED";
pub const ERR_UNSUPPORTED_FRAME: &str = "UNSUPPORTED_FRAME";
pub const ERROR_ORIGIN_RUNTIME: &str = "runtime";
pub const ERROR_ORIGIN_HOSTCALL: &str = "hostcall";
pub const ERROR_ORIGIN_PLUGIN: &str = "plugin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Hello,
    HelloAck,
    Heartbeat,
    InvokeWorker,
    InvokeWorkerResult,
    OpenHandle,
    ValidateHandleGrant,
    StorageFile,
    StorageKV,
    StorageSQLite,
    NetworkGrant,
    NetworkExecute,
    RevokeEpoch,
    RevokeEpochAck,
    Diagnostic,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIPCFrame {
    ipc_version: String,
    frame_type: String,
    request_id: String,
    runtime_generation_id: Option<String>,
    payload: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloPayload {
    target: HelloTarget,
    host_process_id: u64,
    host_ipc_version: String,
    host_wasm_abi: String,
    started_unix_nano: u64,
    channel_nonce: String,
    runtime_lease_public_keys: Vec<RuntimeLeasePublicKeyPayload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloTarget {
    os: String,
    arch: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLeasePublicKeyPayload {
    algorithm: String,
    key_id: String,
    public_key_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerFramePayload {
    lease: Box<serde_json::value::RawValue>,
    method: String,
    invocation: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WorkerLeasePayload {
    lease_id: Option<String>,
    token_id: Option<String>,
    lease_token: Option<String>,
    lease_nonce: Option<String>,
    plugin_id: Option<String>,
    plugin_version: Option<String>,
    active_fingerprint: Option<String>,
    surface_instance_id: Option<String>,
    owner_session_hash: Option<String>,
    owner_user_hash: Option<String>,
    session_channel_id_hash: Option<String>,
    bridge_channel_id: Option<String>,
    runtime_generation_id: Option<String>,
    plugin_instance_id: Option<String>,
    method: Option<String>,
    effect: Option<String>,
    execution: Option<String>,
    operation_id: Option<String>,
    stream_id: Option<String>,
    audit_correlation_id: Option<String>,
    target_descriptor_hashes: Option<Vec<String>>,
    limits: Option<WorkerLeaseLimitsPayload>,
    policy_revision: Option<u64>,
    management_revision: Option<u64>,
    revoke_epoch: Option<u64>,
    runtime_shard_id: Option<String>,
    runtime_instance_id: Option<String>,
    ipc_channel_id: Option<String>,
    connection_nonce: Option<String>,
    key_id: Option<String>,
    signature: Option<String>,
    issued_at: Option<String>,
    issued_at_unix_ms: Option<i64>,
    expires_at: Option<String>,
    expires_at_unix_ms: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WorkerLeaseLimitsPayload {
    timeout_ms: Option<i64>,
    memory_bytes: Option<u64>,
    max_payload_bytes: Option<i64>,
    max_stream_bytes_per_sec: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WorkerInvocationPayload {
    plugin_id: Option<String>,
    plugin_instance_id: Option<String>,
    active_fingerprint: Option<String>,
    runtime_instance_id: Option<String>,
    runtime_generation_id: Option<String>,
    package_hash: Option<String>,
    worker_id: Option<String>,
    worker_mode: Option<String>,
    worker_scope: Option<String>,
    artifact: Option<String>,
    artifact_sha256: Option<String>,
    abi: Option<String>,
    method: Option<String>,
    export: Option<String>,
    effect: Option<String>,
    execution: Option<String>,
    surface_instance_id: Option<String>,
    owner_session_hash: Option<String>,
    owner_user_hash: Option<String>,
    session_channel_id_hash: Option<String>,
    bridge_channel_id: Option<String>,
    operation_id: Option<String>,
    stream_id: Option<String>,
    audit_correlation_id: Option<String>,
    policy_revision: Option<u64>,
    management_revision: Option<u64>,
    revoke_epoch: Option<u64>,
    params_sha256: Option<String>,
    params: Option<Box<serde_json::value::RawValue>>,
    storage_handle_grants: Option<HashMap<String, String>>,
    broker_access: Option<Box<serde_json::value::RawValue>>,
    broker_access_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerBrokerAccessPayload {
    #[serde(default)]
    storage: Vec<WorkerStorageBrokerAccessPayload>,
    #[serde(default)]
    network: Vec<WorkerNetworkBrokerAccessPayload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerStorageBrokerAccessPayload {
    store_id: String,
    operations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerNetworkBrokerAccessPayload {
    connector_id: String,
    transport: String,
    operations: Vec<String>,
    #[serde(default)]
    http_methods: Vec<String>,
}

struct ClosedWorkerFrame {
    lease: WorkerLeasePayload,
    invocation: WorkerInvocationPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInvocationContext {
    pub plugin_id: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub method: String,
    pub effect: String,
    pub execution: String,
    pub surface_instance_id: String,
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub session_channel_id_hash: String,
    pub bridge_channel_id: String,
    pub operation_id: String,
    pub stream_id: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub storage_handle_grants: HashMap<String, String>,
    pub broker_access_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub sent_unix_nano: u64,
    pub max_staleness_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeEpochRequest {
    pub plugin_instance_id: String,
    pub revoke_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatRequestPayload {
    sent_unix_nano: u64,
    max_staleness_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeEpochRequestPayload {
    plugin_instance_id: String,
    revoke_epoch: u64,
}

fn parse_raw_frame(input: &str) -> Result<RawIPCFrame, String> {
    serde_json::from_str(input).map_err(|err| format!("decode IPC frame: {err}"))
}

fn parse_hello_payload(frame: &RawIPCFrame) -> Result<HelloPayload, String> {
    serde_json::from_str(frame.payload.get()).map_err(|err| format!("decode hello payload: {err}"))
}

fn parse_closed_worker_frame(input: &str) -> Result<ClosedWorkerFrame, String> {
    let frame = parse_raw_frame(input)?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err("unsupported ipc_version".to_string());
    }
    if frame.frame_type != FRAME_TYPE_INVOKE_WORKER {
        return Err("expected invoke_worker frame".to_string());
    }
    if frame.request_id.trim().is_empty() {
        return Err("request_id is empty".to_string());
    }
    if frame
        .runtime_generation_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("runtime_generation_id is empty".to_string());
    }
    let payload: WorkerFramePayload = serde_json::from_str(frame.payload.get())
        .map_err(|err| format!("decode worker frame payload: {err}"))?;
    if payload.method.trim().is_empty() {
        return Err("worker frame method is empty".to_string());
    }
    let lease: WorkerLeasePayload = serde_json::from_str(payload.lease.get())
        .map_err(|err| format!("decode worker lease payload: {err}"))?;
    let invocation: WorkerInvocationPayload = serde_json::from_str(payload.invocation.get())
        .map_err(|err| format!("decode worker invocation payload: {err}"))?;
    if let Some(broker_access) = invocation.broker_access.as_ref() {
        serde_json::from_str::<WorkerBrokerAccessPayload>(broker_access.get())
            .map_err(|err| format!("decode worker broker access: {err}"))?;
    }
    if invocation
        .method
        .as_deref()
        .is_some_and(|method| method.trim() != payload.method.trim())
    {
        return Err("worker invocation method does not match the frame envelope".to_string());
    }
    Ok(ClosedWorkerFrame { lease, invocation })
}

fn required_string(value: &Option<String>, field: &str) -> Result<String, String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("missing {field}"))
}

pub fn parse_worker_invocation_context(input: &str) -> Result<WorkerInvocationContext, String> {
    let parsed = parse_closed_worker_frame(input)?;
    let invocation = &parsed.invocation;
    Ok(WorkerInvocationContext {
        plugin_id: required_string(&invocation.plugin_id, "plugin_id")?,
        plugin_instance_id: required_string(&invocation.plugin_instance_id, "plugin_instance_id")?,
        active_fingerprint: required_string(&invocation.active_fingerprint, "active_fingerprint")?,
        runtime_instance_id: required_string(
            &invocation.runtime_instance_id,
            "runtime_instance_id",
        )?,
        runtime_generation_id: required_string(
            &invocation.runtime_generation_id,
            "runtime_generation_id",
        )?,
        method: required_string(&invocation.method, "method")?,
        effect: invocation.effect.clone().unwrap_or_default(),
        execution: invocation.execution.clone().unwrap_or_default(),
        surface_instance_id: invocation.surface_instance_id.clone().unwrap_or_default(),
        owner_session_hash: invocation.owner_session_hash.clone().unwrap_or_default(),
        owner_user_hash: invocation.owner_user_hash.clone().unwrap_or_default(),
        session_channel_id_hash: invocation
            .session_channel_id_hash
            .clone()
            .unwrap_or_default(),
        bridge_channel_id: invocation.bridge_channel_id.clone().unwrap_or_default(),
        operation_id: invocation.operation_id.clone().unwrap_or_default(),
        stream_id: invocation.stream_id.clone().unwrap_or_default(),
        policy_revision: parsed.lease.policy_revision.unwrap_or_default(),
        management_revision: parsed.lease.management_revision.unwrap_or_default(),
        revoke_epoch: parsed.lease.revoke_epoch.unwrap_or_default(),
        storage_handle_grants: invocation.storage_handle_grants.clone().unwrap_or_default(),
        broker_access_json: invocation
            .broker_access
            .as_ref()
            .map(|value| value.get().to_string())
            .unwrap_or_else(|| "{}".to_string()),
    })
}

pub fn parse_heartbeat_request(input: &str) -> Result<HeartbeatRequest, String> {
    let frame = parse_raw_frame(input)?;
    if frame.frame_type != FRAME_TYPE_HEARTBEAT {
        return Err("expected heartbeat frame".to_string());
    }
    let payload: HeartbeatRequestPayload = serde_json::from_str(frame.payload.get())
        .map_err(|err| format!("decode heartbeat payload: {err}"))?;
    Ok(HeartbeatRequest {
        sent_unix_nano: payload.sent_unix_nano,
        max_staleness_ms: payload.max_staleness_ms,
    })
}

pub fn parse_revoke_epoch_request(input: &str) -> Result<RevokeEpochRequest, String> {
    let frame = parse_raw_frame(input)?;
    if frame.frame_type != FRAME_TYPE_REVOKE_EPOCH {
        return Err("expected revoke_epoch frame".to_string());
    }
    let payload: RevokeEpochRequestPayload = serde_json::from_str(frame.payload.get())
        .map_err(|err| format!("decode revoke_epoch payload: {err}"))?;
    if payload.plugin_instance_id.trim().is_empty() {
        return Err("plugin_instance_id is empty".to_string());
    }
    Ok(RevokeEpochRequest {
        plugin_instance_id: payload.plugin_instance_id,
        revoke_epoch: payload.revoke_epoch,
    })
}

pub fn extract_json_string(input: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let mut chars = after_colon.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            value.push(match ch {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{0008}',
                'f' => '\u{000c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(value),
            other => value.push(other),
        }
    }
    None
}

pub fn escape_json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            other => out.push(other),
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLeasePublicKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

pub fn parse_runtime_lease_public_keys(input: &str) -> Result<Vec<RuntimeLeasePublicKey>, String> {
    let frame = parse_raw_frame(input)?;
    let payload = parse_hello_payload(&frame)?;
    let keys = payload.runtime_lease_public_keys;
    let mut seen = HashSet::new();
    let mut parsed = Vec::with_capacity(keys.len());
    if keys.is_empty() {
        return Err("runtime_lease_public_keys must not be empty".to_string());
    }
    for key in keys {
        let key_id = key.key_id.trim().to_string();
        if key_id.trim().is_empty() {
            return Err("runtime lease public key key_id is empty".to_string());
        }
        if !seen.insert(key_id.clone()) {
            return Err("runtime lease public key key_id is duplicated".to_string());
        }
        if key.algorithm != RUNTIME_LEASE_SIGNATURE_ALGORITHM {
            return Err("runtime lease public key algorithm is unsupported".to_string());
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key.public_key_base64.as_bytes())
            .map_err(|_| "runtime lease public key is not valid base64".to_string())?;
        let public_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| "runtime lease public key length is invalid".to_string())?;
        parsed.push(RuntimeLeasePublicKey { key_id, public_key });
    }
    Ok(parsed)
}

pub fn verify_worker_runtime_lease_signature(
    input: &str,
    public_keys: &[RuntimeLeasePublicKey],
) -> Result<(), String> {
    if public_keys.is_empty() {
        return Err("runtime lease public keys are required".to_string());
    }
    parse_closed_worker_frame(input)?;
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|err| format!("decode worker invocation: {err}"))?;
    let payload = value
        .get("payload")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing worker invocation payload".to_string())?;
    let method = json_object_string(payload, "method")?;
    let lease = payload
        .get("lease")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing runtime execution lease".to_string())?;
    let key_id = json_object_string(lease, "key_id")?;
    let public_key = public_keys
        .iter()
        .find(|key| key.key_id == key_id)
        .ok_or_else(|| "runtime lease signing key not found".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key.public_key)
        .map_err(|_| "runtime lease public key is invalid".to_string())?;
    let payload = runtime_lease_signature_payload_json(lease, &method)?;
    let signature = decode_runtime_lease_signature(&json_object_string(lease, "signature")?)?;
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| "runtime lease signature is invalid".to_string())
}

pub fn validate_worker_runtime_lease(input: &str, now_unix_ms: i64) -> Result<(), String> {
    parse_closed_worker_frame(input)?;
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|err| format!("decode worker invocation: {err}"))?;
    let frame = value
        .as_object()
        .ok_or_else(|| "worker invocation frame must be an object".to_string())?;
    let frame_type = json_object_string(frame, "frame_type")?;
    if frame_type != FRAME_TYPE_INVOKE_WORKER {
        return Err("worker invocation frame_type is invalid".to_string());
    }
    let frame_generation_id = json_object_string(frame, "runtime_generation_id")?;
    let payload = frame
        .get("payload")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing worker invocation payload".to_string())?;
    let lease = payload
        .get("lease")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing runtime execution lease".to_string())?;
    let invocation = payload
        .get("invocation")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing worker invocation".to_string())?;

    let expires_at_unix_ms = runtime_lease_expires_at_unix_ms(lease)?;
    if expires_at_unix_ms <= now_unix_ms {
        return Err("runtime execution lease is expired".to_string());
    }
    let payload_method = json_object_string(payload, "method")?;
    validate_runtime_lease_string_binding(lease, invocation, "method", true)?;
    if json_object_string(lease, "method")? != payload_method {
        return Err("runtime lease method does not match the invocation envelope".to_string());
    }
    for field in [
        "plugin_id",
        "plugin_instance_id",
        "active_fingerprint",
        "runtime_instance_id",
        "runtime_generation_id",
        "effect",
        "execution",
        "audit_correlation_id",
    ] {
        validate_runtime_lease_string_binding(lease, invocation, field, true)?;
    }
    for field in [
        "surface_instance_id",
        "owner_session_hash",
        "owner_user_hash",
        "session_channel_id_hash",
        "bridge_channel_id",
        "operation_id",
        "stream_id",
    ] {
        validate_runtime_lease_string_binding(lease, invocation, field, false)?;
    }
    if json_object_string(lease, "runtime_generation_id")? != frame_generation_id {
        return Err(
            "runtime lease runtime_generation_id does not match the invocation frame".to_string(),
        );
    }
    validate_runtime_execution_handles(lease)?;
    validate_runtime_execution_handles(invocation)?;
    let invocation_target_hash = worker_invocation_target_hash(input)?;
    let target_hashes = lease
        .get("target_descriptor_hashes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "runtime lease target_descriptor_hashes are required".to_string())?;
    if target_hashes
        .iter()
        .filter(|value| value.as_str() == Some(invocation_target_hash.as_str()))
        .count()
        != 1
    {
        return Err("runtime lease does not bind the worker invocation target".to_string());
    }
    Ok(())
}

#[derive(Deserialize)]
struct RawWorkerInvocationFrame {
    payload: RawWorkerInvocationEnvelope,
}

#[derive(Deserialize)]
struct RawWorkerInvocationEnvelope {
    invocation: RawWorkerInvocation,
}

#[derive(Deserialize)]
struct RawWorkerInvocation {
    params: Box<serde_json::value::RawValue>,
    broker_access: Box<serde_json::value::RawValue>,
    broker_access_sha256: String,
}

pub fn worker_invocation_target_hash(input: &str) -> Result<String, String> {
    parse_closed_worker_frame(input)?;
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|err| format!("decode worker invocation: {err}"))?;
    let invocation = value
        .get("payload")
        .and_then(|value| value.get("invocation"))
        .and_then(|value| value.as_object())
        .ok_or_else(|| "missing worker invocation".to_string())?;
    let raw: RawWorkerInvocationFrame = serde_json::from_str(input)
        .map_err(|err| format!("decode raw worker invocation parameters: {err}"))?;
    let params_hash = format!(
        "sha256:{}",
        lowercase_hex(&Sha256::digest(
            raw.payload.invocation.params.get().as_bytes()
        ))
    );
    if json_object_string(invocation, "params_sha256")? != params_hash {
        return Err("worker invocation params_sha256 does not match params".to_string());
    }
    let broker_access_hash = format!(
        "sha256:{}",
        lowercase_hex(&Sha256::digest(
            raw.payload.invocation.broker_access.get().as_bytes()
        ))
    );
    if raw.payload.invocation.broker_access_sha256 != broker_access_hash {
        return Err(
            "worker invocation broker_access_sha256 does not match broker_access".to_string(),
        );
    }
    let required = |field: &str| json_object_string(invocation, field);
    let optional = |field: &str| {
        json_object_optional_string(invocation, field).map(|value| value.unwrap_or_default())
    };
    let fields = [
        WORKER_INVOCATION_TARGET_SCHEMA_VERSION.to_string(),
        required("plugin_id")?,
        required("plugin_instance_id")?,
        required("active_fingerprint")?,
        required("runtime_instance_id")?,
        required("runtime_generation_id")?,
        required("package_hash")?,
        required("worker_id")?,
        required("worker_mode")?,
        required("worker_scope")?,
        required("artifact")?,
        required("artifact_sha256")?,
        required("abi")?,
        required("method")?,
        required("export")?,
        required("effect")?,
        required("execution")?,
        optional("surface_instance_id")?,
        optional("owner_session_hash")?,
        optional("owner_user_hash")?,
        optional("session_channel_id_hash")?,
        optional("bridge_channel_id")?,
        optional("operation_id")?,
        optional("stream_id")?,
        required("audit_correlation_id")?,
        params_hash,
        broker_access_hash,
    ];
    let mut canonical = Vec::new();
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| "worker invocation target field exceeds uint32 length".to_string())?;
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(field.as_bytes());
    }
    Ok(format!(
        "invocation:sha256:{}",
        lowercase_hex(&Sha256::digest(canonical))
    ))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn validate_runtime_lease_string_binding(
    lease: &serde_json::Map<String, serde_json::Value>,
    invocation: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    required: bool,
) -> Result<(), String> {
    let lease_value = json_object_optional_string(lease, field)?;
    let invocation_value = json_object_optional_string(invocation, field)?;
    if required && (lease_value.is_none() || invocation_value.is_none()) {
        return Err(format!("runtime lease {field} binding is required"));
    }
    if lease_value != invocation_value {
        return Err(format!(
            "runtime lease {field} does not match the worker invocation"
        ));
    }
    Ok(())
}

fn validate_runtime_execution_handles(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let execution = json_object_string(object, "execution")?;
    let operation_id = json_object_optional_string(object, "operation_id")?.unwrap_or_default();
    let stream_id = json_object_optional_string(object, "stream_id")?.unwrap_or_default();
    match execution.as_str() {
        "sync" if operation_id.is_empty() && stream_id.is_empty() => Ok(()),
        "operation" if !operation_id.is_empty() && stream_id.is_empty() => Ok(()),
        "subscription" if !operation_id.is_empty() && !stream_id.is_empty() => Ok(()),
        _ => Err("runtime lease execution handles are invalid".to_string()),
    }
}

fn decode_runtime_lease_signature(input: &str) -> Result<Signature, String> {
    let raw = input.trim();
    let prefix = format!("{RUNTIME_LEASE_SIGNATURE_ALGORITHM}:");
    let encoded = raw
        .strip_prefix(prefix.as_str())
        .ok_or_else(|| "runtime lease signature algorithm is unsupported".to_string())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "runtime lease signature is not valid base64".to_string())?;
    Signature::from_slice(&decoded)
        .map_err(|_| "runtime lease signature length is invalid".to_string())
}

fn runtime_lease_signature_payload_json(
    lease: &serde_json::Map<String, serde_json::Value>,
    method: &str,
) -> Result<String, String> {
    let lease_method = lease.get("method").and_then(|value| value.as_str());
    if let Some(lease_method) = lease_method {
        if !lease_method.trim().is_empty() && lease_method.trim() != method.trim() {
            return Err("runtime lease method mismatch".to_string());
        }
    }
    let lease_id = json_object_string(lease, "lease_id")?;
    let token_id = lease
        .get("token_id")
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| lease_id.clone());
    let expires_at_unix_ms = runtime_lease_expires_at_unix_ms(lease)?;
    let issued_at_unix_ms =
        runtime_lease_optional_unix_ms(lease, "issued_at_unix_ms", "issued_at")?;
    let mut out = String::new();
    out.push('{');
    append_json_string_field(
        &mut out,
        "schema_version",
        RUNTIME_LEASE_SIGNATURE_SCHEMA_VERSION,
        false,
    );
    append_json_string_field(&mut out, "token_kind", RUNTIME_LEASE_TOKEN_KIND, true);
    append_json_string_field(&mut out, "lease_id", &lease_id, true);
    append_json_string_field(&mut out, "token_id", &token_id, true);
    append_json_string_field(
        &mut out,
        "lease_nonce",
        &json_object_string(lease, "lease_nonce")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "plugin_instance_id",
        &json_object_string(lease, "plugin_instance_id")?,
        true,
    );
    append_json_optional_string_field(
        &mut out,
        "plugin_id",
        lease.get("plugin_id").and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "plugin_version",
        lease.get("plugin_version").and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "active_fingerprint",
        lease
            .get("active_fingerprint")
            .and_then(|value| value.as_str()),
    );
    if let Some(value) = issued_at_unix_ms {
        append_json_i64_field(&mut out, "issued_at_unix_ms", value);
    }
    append_json_string_field(&mut out, "method", method.trim(), true);
    append_json_optional_string_field(
        &mut out,
        "effect",
        lease.get("effect").and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "execution",
        lease.get("execution").and_then(|value| value.as_str()),
    );
    validate_runtime_execution_handles(lease)?;
    let operation_id = json_object_optional_string(lease, "operation_id")?.unwrap_or_default();
    let stream_id = json_object_optional_string(lease, "stream_id")?.unwrap_or_default();
    append_json_optional_string_field(&mut out, "operation_id", Some(&operation_id));
    append_json_optional_string_field(&mut out, "stream_id", Some(&stream_id));
    append_json_string_field(
        &mut out,
        "audit_correlation_id",
        &json_object_string(lease, "audit_correlation_id")?,
        true,
    );
    append_json_optional_string_field(
        &mut out,
        "surface_instance_id",
        lease
            .get("surface_instance_id")
            .and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "owner_session_hash",
        lease
            .get("owner_session_hash")
            .and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "owner_user_hash",
        lease
            .get("owner_user_hash")
            .and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "session_channel_id_hash",
        lease
            .get("session_channel_id_hash")
            .and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "bridge_channel_id",
        lease
            .get("bridge_channel_id")
            .and_then(|value| value.as_str()),
    );
    if let Some(target_hashes) = lease.get("target_descriptor_hashes") {
        let hashes = target_hashes
            .as_array()
            .ok_or_else(|| "target_descriptor_hashes must be an array".to_string())?;
        if !hashes.is_empty() {
            out.push_str(",\"target_descriptor_hashes\":[");
            for (index, hash) in hashes.iter().enumerate() {
                let hash = hash
                    .as_str()
                    .ok_or_else(|| "target_descriptor_hashes item must be a string".to_string())?;
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(hash));
                out.push('"');
            }
            out.push(']');
        }
    }
    append_runtime_lease_limits_field(&mut out, lease.get("limits"))?;
    append_json_u64_field(
        &mut out,
        "policy_revision",
        json_object_u64(lease, "policy_revision").unwrap_or(0),
    );
    append_json_u64_field(
        &mut out,
        "management_revision",
        json_object_u64(lease, "management_revision").unwrap_or(0),
    );
    append_json_u64_field(
        &mut out,
        "revoke_epoch",
        json_object_u64(lease, "revoke_epoch").unwrap_or(0),
    );
    append_json_i64_field(&mut out, "expires_at_unix_ms", expires_at_unix_ms);
    append_json_optional_string_field(
        &mut out,
        "runtime_shard_id",
        lease
            .get("runtime_shard_id")
            .and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "runtime_instance_id",
        lease
            .get("runtime_instance_id")
            .and_then(|value| value.as_str()),
    );
    append_json_string_field(
        &mut out,
        "runtime_generation_id",
        &json_object_string(lease, "runtime_generation_id")?,
        true,
    );
    append_json_optional_string_field(
        &mut out,
        "ipc_channel_id",
        lease.get("ipc_channel_id").and_then(|value| value.as_str()),
    );
    append_json_optional_string_field(
        &mut out,
        "connection_nonce",
        lease
            .get("connection_nonce")
            .and_then(|value| value.as_str()),
    );
    append_json_string_field(
        &mut out,
        "key_id",
        &json_object_string(lease, "key_id")?,
        true,
    );
    out.push('}');
    Ok(out)
}

fn runtime_lease_optional_unix_ms(
    lease: &serde_json::Map<String, serde_json::Value>,
    unix_key: &str,
    rfc3339_key: &str,
) -> Result<Option<i64>, String> {
    if let Some(value) = lease.get(unix_key) {
        let value = json_value_i64(value, unix_key)?;
        if value == 0 {
            return Ok(None);
        }
        return Ok(Some(value));
    }
    let Some(value) = lease.get(rfc3339_key).and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.starts_with("0001-01-01T00:00:00") {
        return Ok(None);
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| format!("{rfc3339_key} is not valid RFC3339"))?;
    let unix_ms = (parsed.unix_timestamp_nanos() / 1_000_000) as i64;
    if unix_ms == 0 {
        Ok(None)
    } else {
        Ok(Some(unix_ms))
    }
}

fn runtime_lease_expires_at_unix_ms(
    lease: &serde_json::Map<String, serde_json::Value>,
) -> Result<i64, String> {
    if let Some(value) = lease.get("expires_at_unix_ms") {
        return json_value_i64(value, "expires_at_unix_ms");
    }
    let expires_at = json_object_string(lease, "expires_at")?;
    let parsed = OffsetDateTime::parse(&expires_at, &Rfc3339)
        .map_err(|_| "expires_at is not valid RFC3339".to_string())?;
    Ok((parsed.unix_timestamp_nanos() / 1_000_000) as i64)
}

fn json_object_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing {key}"))
}

fn json_object_optional_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| format!("{key} must be a string"))?
        .trim()
        .to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn json_object_u64(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(|value| value.as_u64())
}

fn json_value_i64(value: &serde_json::Value, key: &str) -> Result<i64, String> {
    if let Some(value) = value.as_i64() {
        return Ok(value);
    }
    if let Some(value) = value.as_u64() {
        return i64::try_from(value).map_err(|_| format!("{key} is too large"));
    }
    Err(format!("{key} must be an integer"))
}

fn append_json_string_field(out: &mut String, key: &str, value: &str, comma: bool) {
    if comma {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(&escape_json_string(value));
    out.push('"');
}

fn append_json_optional_string_field(out: &mut String, key: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    append_json_string_field(out, key, value, true);
}

fn append_json_u64_field(out: &mut String, key: &str, value: u64) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(value.to_string().as_str());
}

fn append_json_i64_field(out: &mut String, key: &str, value: i64) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(value.to_string().as_str());
}

fn append_runtime_lease_limits_field(
    out: &mut String,
    limits: Option<&serde_json::Value>,
) -> Result<(), String> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let limits = limits
        .as_object()
        .ok_or_else(|| "limits must be an object".to_string())?;
    let mut rendered = Vec::new();
    for key in [
        "timeout_ms",
        "memory_bytes",
        "max_payload_bytes",
        "max_stream_bytes_per_sec",
    ] {
        let Some(value) = limits.get(key) else {
            continue;
        };
        let value = json_value_i64(value, key)?;
        if value == 0 {
            continue;
        }
        rendered.push(format!("\"{key}\":{value}"));
    }
    if rendered.is_empty() {
        return Ok(());
    }
    out.push_str(",\"limits\":{");
    out.push_str(&rendered.join(","));
    out.push('}');
    Ok(())
}

pub fn hello_ack_frame(
    request_id: &str,
    runtime_generation_id: &str,
    channel_nonce: &str,
    runtime_version: &str,
    wasm_abi_version: &str,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"runtime_version\":\"{}\",\"rust_ipc_version\":\"{}\",\"wasm_abi_version\":\"{}\",\"channel_nonce\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_HELLO_ACK,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(runtime_version),
        RUST_IPC_VERSION,
        escape_json_string(wasm_abi_version),
        escape_json_string(channel_nonce)
    )
}

pub fn response_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    ok: bool,
    result_json: Option<&str>,
    code: Option<&str>,
    message: Option<&str>,
) -> String {
    let payload = if ok {
        match result_json {
            Some(result) => format!("{{\"ok\":true,\"result\":{result}}}"),
            None => "{\"ok\":true}".to_string(),
        }
    } else {
        render_error_payload(ResponseError {
            code: code.unwrap_or("RUNTIME_REQUEST_FAILED"),
            message: message.unwrap_or("runtime request failed"),
            origin: ERROR_ORIGIN_RUNTIME,
        })
    };
    render_response_frame(frame_type, request_id, runtime_generation_id, &payload)
}

pub struct ResponseError<'a> {
    pub code: &'a str,
    pub message: &'a str,
    pub origin: &'a str,
}

pub fn response_error_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    error: ResponseError<'_>,
) -> String {
    let payload = render_error_payload(error);
    render_response_frame(frame_type, request_id, runtime_generation_id, &payload)
}

fn render_error_payload(error: ResponseError<'_>) -> String {
    let error_origin = if matches!(
        error.origin,
        ERROR_ORIGIN_RUNTIME | ERROR_ORIGIN_HOSTCALL | ERROR_ORIGIN_PLUGIN
    ) {
        error.origin
    } else {
        ERROR_ORIGIN_RUNTIME
    };
    format!(
        "{{\"ok\":false,\"code\":\"{}\",\"message\":\"{}\",\"error_origin\":\"{}\"}}",
        escape_json_string(error.code),
        escape_json_string(error.message),
        error_origin,
    )
}

fn render_response_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    payload: &str,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{}}}",
        RUST_IPC_VERSION,
        escape_json_string(frame_type),
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        payload,
    )
}

pub fn revoke_epoch_ack_result_json(
    plugin_instance_id: &str,
    revoke_epoch: u64,
    closed_socket_count: u64,
    closed_stream_count: u64,
    closed_storage_handle_count: u64,
) -> String {
    format!(
        "{{\"plugin_instance_id\":\"{}\",\"revoke_epoch\":{},\"closed_socket_count\":{},\"closed_stream_count\":{},\"closed_storage_handle_count\":{}}}",
        escape_json_string(plugin_instance_id),
        revoke_epoch,
        closed_socket_count,
        closed_stream_count,
        closed_storage_handle_count
    )
}

pub fn heartbeat_ack_result_json(
    runtime_generation_id: &str,
    runtime_unix_nano: u64,
    max_staleness_ms: u64,
    host_sent_unix_nano: u64,
) -> String {
    format!(
        "{{\"runtime_generation_id\":\"{}\",\"runtime_unix_nano\":{},\"max_staleness_ms\":{},\"host_sent_unix_nano\":{}}}",
        escape_json_string(runtime_generation_id),
        runtime_unix_nano,
        max_staleness_ms,
        host_sent_unix_nano
    )
}

pub fn open_handle_frame(
    request_id: &str,
    runtime_generation_id: &str,
    identity: &WorkerInvocationIdentity,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"package_hash\":\"{}\",\"artifact\":\"{}\",\"artifact_sha256\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_OPEN_HANDLE,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&identity.package_hash),
        escape_json_string(&identity.artifact),
        escape_json_string(&identity.artifact_sha256)
    )
}

pub fn validate_open_handle_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_identity: &WorkerInvocationIdentity,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_OPEN_HANDLE {
        return Err("expected open_handle frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("open_handle request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("open_handle runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    let package_hash = extract_json_string(input, "package_hash").ok_or("missing package_hash")?;
    let artifact = extract_json_string(input, "artifact").ok_or("missing artifact")?;
    let sha256 = extract_json_string(input, "sha256").ok_or("missing sha256")?;
    if package_hash != expected_identity.package_hash
        || artifact != expected_identity.artifact
        || sha256 != expected_identity.artifact_sha256
    {
        return Err("open_handle artifact identity mismatch".to_string());
    }
    let content_base64 =
        extract_json_string(input, "content_base64").ok_or("missing content_base64")?;
    if content_base64.trim().is_empty() {
        return Err("empty content_base64".to_string());
    }
    Ok(())
}

pub fn open_handle_content_base64(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_identity: &WorkerInvocationIdentity,
) -> Result<String, String> {
    validate_open_handle_response(
        input,
        expected_request_id,
        expected_runtime_generation_id,
        expected_identity,
    )?;
    extract_json_string(input, "content_base64").ok_or("missing content_base64".to_string())
}

pub fn worker_success_result_json(
    identity: &WorkerInvocationIdentity,
    wasm_byte_len: usize,
    storage_file_result_json: Option<&str>,
    storage_kv_result_json: Option<&str>,
    storage_sqlite_result_json: Option<&str>,
    network_execute_result_json: Option<&str>,
) -> String {
    worker_success_result_json_with_network_results(
        identity,
        wasm_byte_len,
        storage_file_result_json,
        storage_kv_result_json,
        storage_sqlite_result_json,
        network_execute_result_json.into_iter().collect(),
    )
}

pub fn worker_success_result_json_with_network_results(
    identity: &WorkerInvocationIdentity,
    wasm_byte_len: usize,
    storage_file_result_json: Option<&str>,
    storage_kv_result_json: Option<&str>,
    storage_sqlite_result_json: Option<&str>,
    network_execute_result_jsons: Vec<&str>,
) -> String {
    let storage_file = storage_file_result_json
        .map(|result| format!(",\"storage_file\":{result}"))
        .unwrap_or_default();
    let storage_kv = storage_kv_result_json
        .map(|result| format!(",\"storage_kv\":{result}"))
        .unwrap_or_default();
    let storage_sqlite = storage_sqlite_result_json
        .map(|result| format!(",\"storage_sqlite\":{result}"))
        .unwrap_or_default();
    let stream_id = first_network_stream_id(&network_execute_result_jsons)
        .map(|value| format!(",\"stream_id\":\"{}\"", escape_json_string(&value)))
        .unwrap_or_default();
    let network_execute = network_success_fields(network_execute_result_jsons);
    format!(
        "{{\"data\":{{\"method\":\"{}\",\"worker_id\":\"{}\",\"backend\":\"executed wasm worker scaffold\",\"transport\":\"rust runtime ipc\",\"wasm_abi\":\"{}\",\"wasm_byte_len\":{}{}{}{}{}}}{}}}",
        escape_json_string(&identity.method),
        escape_json_string(&identity.worker_id),
        WASM_ABI_VERSION,
        wasm_byte_len,
        storage_file,
        storage_kv,
        storage_sqlite,
        network_execute,
        stream_id
    )
}

fn network_success_fields(results: Vec<&str>) -> String {
    let mut fields = String::new();
    for (index, result) in results.into_iter().enumerate() {
        let field = if index == 0 {
            "network_execute".to_string()
        } else {
            format!(
                "network_execute_{}",
                network_result_transport(result)
                    .filter(|transport| !transport.is_empty())
                    .unwrap_or_else(|| index.to_string())
            )
        };
        fields.push_str(&format!(",\"{}\":{}", escape_json_string(&field), result));
    }
    fields
}

fn network_result_transport(result: &str) -> Option<String> {
    extract_json_string(result, "transport").map(|value| {
        value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    ch.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string()
    })
}

fn first_network_stream_id(results: &[&str]) -> Option<String> {
    results
        .iter()
        .filter_map(|result| extract_json_string(result, "stream_id"))
        .find(|stream_id| !stream_id.trim().is_empty())
}

pub fn extract_json_number_u64(input: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let digits: String = after_colon
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

pub fn extract_json_object(input: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let value = after_key[colon + 1..].trim_start();
    json_object_prefix(value)
}

pub fn storage_file_payload_json(input: &str) -> Result<String, String> {
    let (frame_type, _, _) = parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_FILE {
        return Err("expected storage_file frame".to_string());
    }
    frame_payload_json(input)
}

pub fn storage_kv_payload_json(input: &str) -> Result<String, String> {
    let (frame_type, _, _) = parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_KV {
        return Err("expected storage_kv frame".to_string());
    }
    frame_payload_json(input)
}

pub fn storage_sqlite_payload_json(input: &str) -> Result<String, String> {
    let (frame_type, _, _) = parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_SQLITE {
        return Err("expected storage_sqlite frame".to_string());
    }
    frame_payload_json(input)
}

pub fn network_execute_payload_json(input: &str) -> Result<String, String> {
    let (frame_type, _, _) = parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_NETWORK_EXECUTE {
        return Err("expected network_execute frame".to_string());
    }
    frame_payload_json(input)
}

fn frame_payload_json(input: &str) -> Result<String, String> {
    let payload_key = "\"payload\"";
    let Some(payload_start) = input.find(payload_key) else {
        return Err("missing payload".to_string());
    };
    let after_payload = &input[payload_start + payload_key.len()..];
    let Some(colon) = after_payload.find(':') else {
        return Err("missing payload colon".to_string());
    };
    let payload = after_payload[colon + 1..].trim_start();
    if !payload.starts_with('{') {
        return Err("payload is not an object".to_string());
    }
    json_object_prefix(payload).ok_or_else(|| "unterminated payload object".to_string())
}

fn json_object_prefix(input: &str) -> Option<String> {
    if !input.starts_with('{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(input[..=idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub fn validate_handle_grant_frame(
    request_id: &str,
    runtime_generation_id: &str,
    handle_grant_token: &str,
    plugin_instance_id: &str,
    active_fingerprint: &str,
    handle_id: &str,
    method: &str,
    policy_revision: u64,
    management_revision: u64,
    revoke_epoch: u64,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_generation_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_VALIDATE_HANDLE_GRANT,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(handle_grant_token),
        escape_json_string(plugin_instance_id),
        escape_json_string(active_fingerprint),
        escape_json_string(runtime_generation_id),
        escape_json_string(handle_id),
        escape_json_string(method),
        policy_revision,
        management_revision,
        revoke_epoch
    )
}

pub fn validate_handle_grant_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_handle_id: &str,
    expected_method: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_VALIDATE_HANDLE_GRANT {
        return Err("expected validate_handle_grant frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("validate_handle_grant request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("validate_handle_grant runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    let handle_id = extract_json_string(input, "handle_id").ok_or("missing handle_id")?;
    let method = extract_json_string(input, "method").ok_or("missing method")?;
    if handle_id != expected_handle_id || method != expected_method {
        return Err("validate_handle_grant audience mismatch".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageFileRequest {
    pub handle_grant_token: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub handle_id: String,
    pub method: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub operation: String,
    pub store_id: String,
    pub path: String,
    pub data_base64: String,
    pub max_bytes: u64,
    pub max_entries: u64,
    pub recursive: bool,
}

pub fn storage_file_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &StorageFileRequest,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"path\":\"{}\",\"data_base64\":\"{}\",\"max_bytes\":{},\"max_entries\":{},\"recursive\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_STORAGE_FILE,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.handle_grant_token),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        escape_json_string(&req.handle_id),
        escape_json_string(&req.method),
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
        escape_json_string(&req.operation),
        escape_json_string(&req.store_id),
        escape_json_string(&req.path),
        escape_json_string(&req.data_base64),
        req.max_bytes,
        req.max_entries,
        if req.recursive { "true" } else { "false" }
    )
}

pub fn validate_storage_file_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_FILE {
        return Err("expected storage_file frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("storage_file request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("storage_file runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKVRequest {
    pub handle_grant_token: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub handle_id: String,
    pub method: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub operation: String,
    pub store_id: String,
    pub key: String,
    pub value_base64: String,
    pub prefix: String,
    pub max_bytes: u64,
    pub max_entries: u64,
}

pub fn storage_kv_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &StorageKVRequest,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"key\":\"{}\",\"value_base64\":\"{}\",\"prefix\":\"{}\",\"max_bytes\":{},\"max_entries\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_STORAGE_KV,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.handle_grant_token),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        escape_json_string(&req.handle_id),
        escape_json_string(&req.method),
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
        escape_json_string(&req.operation),
        escape_json_string(&req.store_id),
        escape_json_string(&req.key),
        escape_json_string(&req.value_base64),
        escape_json_string(&req.prefix),
        req.max_bytes,
        req.max_entries
    )
}

pub fn validate_storage_kv_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_KV {
        return Err("expected storage_kv frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("storage_kv request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("storage_kv runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSQLiteRequest {
    pub handle_grant_token: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub handle_id: String,
    pub method: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub operation: String,
    pub store_id: String,
    pub database: String,
    pub sql: String,
    pub args_json: String,
    pub max_rows: u64,
    pub max_response_bytes: u64,
    pub timeout_ms: u64,
}

pub fn storage_sqlite_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &StorageSQLiteRequest,
) -> String {
    let args_json = if req.args_json.trim().is_empty() {
        "[]"
    } else {
        req.args_json.trim()
    };
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"database\":\"{}\",\"sql\":\"{}\",\"args\":{},\"max_rows\":{},\"max_response_bytes\":{},\"timeout_ms\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_STORAGE_SQLITE,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.handle_grant_token),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        escape_json_string(&req.handle_id),
        escape_json_string(&req.method),
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
        escape_json_string(&req.operation),
        escape_json_string(&req.store_id),
        escape_json_string(&req.database),
        escape_json_string(&req.sql),
        args_json,
        req.max_rows,
        req.max_response_bytes,
        req.timeout_ms
    )
}

pub fn validate_storage_sqlite_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_STORAGE_SQLITE {
        return Err("expected storage_sqlite frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("storage_sqlite request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("storage_sqlite runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrantRequest {
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub connector_id: String,
    pub transport: String,
    pub destination: String,
    pub ttl_ms: u64,
}

pub fn network_grant_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &NetworkGrantRequest,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"connector_id\":\"{}\",\"transport\":\"{}\",\"destination\":\"{}\",\"ttl_ms\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_NETWORK_GRANT,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
        escape_json_string(&req.connector_id),
        escape_json_string(&req.transport),
        escape_json_string(&req.destination),
        req.ttl_ms
    )
}

pub fn validate_network_grant_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_connector_id: &str,
    expected_transport: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_NETWORK_GRANT {
        return Err("expected network_grant frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("network_grant request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("network_grant runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    let grant_id = extract_json_string(input, "grant_id").ok_or("missing grant_id")?;
    if !grant_id.starts_with("netgrant_") || grant_id.len() != "netgrant_".len() + 32 {
        return Err("invalid network grant id".to_string());
    }
    let connector_id = extract_json_string(input, "connector_id").ok_or("missing connector_id")?;
    let transport = extract_json_string(input, "transport").ok_or("missing transport")?;
    if connector_id != expected_connector_id || transport != expected_transport {
        return Err("network_grant audience mismatch".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkExecuteRequest {
    pub plugin_id: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
    pub connector_id: String,
    pub transport: String,
    pub destination: String,
    pub ttl_ms: u64,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub query_json: String,
    pub headers_json: String,
    pub message_type: String,
    pub body_base64: String,
    pub payload_base64: String,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_chunk_bytes: u64,
    pub max_buffered_bytes: u64,
    pub timeout_ms: u64,
    pub stream_id: String,
    pub stream_method: String,
    pub stream_effect: String,
    pub stream_execution: String,
    pub surface_instance_id: String,
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub session_channel_id_hash: String,
    pub bridge_channel_id: String,
    pub content_type: String,
}

pub fn network_execute_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &NetworkExecuteRequest,
) -> String {
    let query_json = if req.query_json.trim().is_empty() {
        "{}"
    } else {
        req.query_json.trim()
    };
    let headers_json = if req.headers_json.trim().is_empty() {
        "{}"
    } else {
        req.headers_json.trim()
    };
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"plugin_id\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"connector_id\":\"{}\",\"transport\":\"{}\",\"destination\":\"{}\",\"ttl_ms\":{},\"operation\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"query\":{},\"headers\":{},\"message_type\":\"{}\",\"body_base64\":\"{}\",\"payload_base64\":\"{}\",\"max_request_bytes\":{},\"max_response_bytes\":{},\"max_chunk_bytes\":{},\"max_buffered_bytes\":{},\"timeout_ms\":{},\"stream_id\":\"{}\",\"stream_method\":\"{}\",\"stream_effect\":\"{}\",\"stream_execution\":\"{}\",\"surface_instance_id\":\"{}\",\"owner_session_hash\":\"{}\",\"owner_user_hash\":\"{}\",\"session_channel_id_hash\":\"{}\",\"bridge_channel_id\":\"{}\",\"content_type\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_NETWORK_EXECUTE,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.plugin_id),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
        escape_json_string(&req.connector_id),
        escape_json_string(&req.transport),
        escape_json_string(&req.destination),
        req.ttl_ms,
        escape_json_string(&req.operation),
        escape_json_string(&req.method),
        escape_json_string(&req.path),
        query_json,
        headers_json,
        escape_json_string(&req.message_type),
        escape_json_string(&req.body_base64),
        escape_json_string(&req.payload_base64),
        req.max_request_bytes,
        req.max_response_bytes,
        req.max_chunk_bytes,
        req.max_buffered_bytes,
        req.timeout_ms,
        escape_json_string(&req.stream_id),
        escape_json_string(&req.stream_method),
        escape_json_string(&req.stream_effect),
        escape_json_string(&req.stream_execution),
        escape_json_string(&req.surface_instance_id),
        escape_json_string(&req.owner_session_hash),
        escape_json_string(&req.owner_user_hash),
        escape_json_string(&req.session_channel_id_hash),
        escape_json_string(&req.bridge_channel_id),
        escape_json_string(&req.content_type)
    )
}

pub fn validate_network_execute_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_connector_id: &str,
    expected_transport: &str,
) -> Result<(), String> {
    let (frame_type, request_id, runtime_generation_id) =
        parse_frame_identity(input).map_err(|err| err.to_string())?;
    if frame_type != FRAME_TYPE_NETWORK_EXECUTE {
        return Err("expected network_execute frame".to_string());
    }
    if request_id != expected_request_id {
        return Err("network_execute request_id mismatch".to_string());
    }
    if runtime_generation_id != expected_runtime_generation_id {
        return Err("network_execute runtime_generation_id mismatch".to_string());
    }
    if !extract_json_bool(input, "ok").unwrap_or(false) {
        return Err(validated_hostcall_failure(input)?);
    }
    let connector_id = extract_json_string(input, "connector_id").ok_or("missing connector_id")?;
    let transport = extract_json_string(input, "transport").ok_or("missing transport")?;
    if connector_id != expected_connector_id || transport != expected_transport {
        return Err("network_execute audience mismatch".to_string());
    }
    Ok(())
}

fn validated_hostcall_failure(input: &str) -> Result<String, String> {
    let origin = extract_json_string(input, "error_origin")
        .ok_or_else(|| "hostcall response error_origin is missing".to_string())?;
    if origin != ERROR_ORIGIN_HOSTCALL {
        return Err("hostcall response error_origin must be hostcall".to_string());
    }
    let code = extract_json_string(input, "code")
        .filter(|value| is_stable_worker_error_code(value))
        .ok_or_else(|| "hostcall response code is missing or invalid".to_string())?;
    let message = extract_json_string(input, "message")
        .filter(|value| !value.trim().is_empty() && value.len() <= 4096)
        .ok_or_else(|| "hostcall response message is missing or invalid".to_string())?;
    Ok(format!("{code}: {message}"))
}

pub fn validate_hello_frame(input: &str) -> Result<(String, String, String), &'static str> {
    let frame: RawIPCFrame = serde_json::from_str(input).map_err(|err| {
        if err.to_string().contains("missing field `request_id`") {
            "missing request_id"
        } else if err
            .to_string()
            .contains("missing field `runtime_generation_id`")
        {
            "missing runtime_generation_id"
        } else {
            "invalid hello frame"
        }
    })?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err("unsupported ipc_version");
    }
    if frame.frame_type != FRAME_TYPE_HELLO {
        return Err("expected hello frame");
    }
    if frame.request_id.trim().is_empty() {
        return Err("empty request_id");
    }
    let runtime_generation_id = frame
        .runtime_generation_id
        .as_deref()
        .ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    let payload: HelloPayload = serde_json::from_str(frame.payload.get()).map_err(|err| {
        if err.to_string().contains("missing field `channel_nonce`") {
            "missing channel_nonce"
        } else {
            "invalid hello payload"
        }
    })?;
    if payload.target.os.trim().is_empty() || payload.target.arch.trim().is_empty() {
        return Err("invalid hello target");
    }
    if payload.host_process_id == 0 || payload.started_unix_nano == 0 {
        return Err("invalid hello process metadata");
    }
    if payload.host_ipc_version != RUST_IPC_VERSION {
        return Err("unsupported host_ipc_version");
    }
    if payload.host_wasm_abi != WASM_ABI_VERSION {
        return Err("unsupported host_wasm_abi");
    }
    if payload.channel_nonce.trim().is_empty() {
        return Err("empty channel_nonce");
    }
    Ok((
        frame.request_id,
        runtime_generation_id.to_string(),
        payload.channel_nonce,
    ))
}

pub fn parse_frame_identity(input: &str) -> Result<(String, String, String), &'static str> {
    let frame: RawIPCFrame = serde_json::from_str(input).map_err(|err| {
        let message = err.to_string();
        if message.contains("missing field `ipc_version`") {
            "missing ipc_version"
        } else if message.contains("missing field `frame_type`") {
            "missing frame_type"
        } else if message.contains("missing field `request_id`") {
            "missing request_id"
        } else if message.contains("missing field `runtime_generation_id`") {
            "missing runtime_generation_id"
        } else if message.contains("missing field `payload`") {
            "missing payload"
        } else {
            "invalid IPC frame"
        }
    })?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err("unsupported ipc_version");
    }
    if frame.frame_type.trim().is_empty() {
        return Err("empty frame_type");
    }
    if frame.request_id.trim().is_empty() {
        return Err("empty request_id");
    }
    let runtime_generation_id = frame
        .runtime_generation_id
        .ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    Ok((frame.frame_type, frame.request_id, runtime_generation_id))
}

pub fn extract_json_bool(input: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if after_colon.starts_with("true") {
        return Some(true);
    }
    if after_colon.starts_with("false") {
        return Some(false);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInvocationIdentity {
    pub package_hash: String,
    pub artifact: String,
    pub artifact_sha256: String,
    pub worker_id: String,
    pub method: String,
    pub export: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerResponseV2 {
    Success(String),
    Failure { code: String, message: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkerSuccessV2 {
    ok: bool,
    data: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkerFailureV2 {
    ok: bool,
    error_code: String,
    message: String,
}

pub fn worker_request_json_v2(input: &str) -> Result<String, String> {
    let parsed = parse_closed_worker_frame(input)?;
    let method = required_string(&parsed.invocation.method, "worker invocation method")?;
    let params = parsed
        .invocation
        .params
        .as_ref()
        .ok_or_else(|| "worker invocation params are missing".to_string())?;
    if method.trim().is_empty() {
        return Err("worker invocation method is empty".to_string());
    }
    let params_value: serde_json::Value = serde_json::from_str(params.get())
        .map_err(|err| format!("decode worker invocation params: {err}"))?;
    if !params_value.is_object() {
        return Err("worker invocation params must be an object".to_string());
    }
    Ok(format!(
        "{{\"schema_version\":\"redevplugin.worker_request.v2\",\"method\":\"{}\",\"params\":{}}}",
        escape_json_string(&method),
        params.get()
    ))
}

pub fn runtime_lease_memory_limit_bytes(input: &str) -> Result<usize, String> {
    let parsed = parse_closed_worker_frame(input)?;
    let memory_bytes = parsed
        .lease
        .limits
        .as_ref()
        .and_then(|limits| limits.memory_bytes)
        .filter(|value| *value > 0)
        .ok_or_else(|| "runtime lease memory_bytes limit is missing or invalid".to_string())?;
    if memory_bytes > MAX_RUNTIME_LEASE_MEMORY_BYTES {
        return Err(format!(
            "runtime lease memory_bytes limit exceeds {MAX_RUNTIME_LEASE_MEMORY_BYTES} bytes"
        ));
    }
    usize::try_from(memory_bytes)
        .map_err(|_| "runtime lease memory_bytes limit exceeds this runtime".to_string())
}

pub fn worker_storage_handle_grant(input: &str, store_id: &str) -> Result<String, String> {
    let parsed = parse_closed_worker_frame(input)?;
    let grants = parsed
        .invocation
        .storage_handle_grants
        .as_ref()
        .ok_or_else(|| "worker invocation storage_handle_grants are missing".to_string())?;
    let grant = grants
        .get(store_id)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("worker invocation has no storage grant for {store_id:?}"))?;
    Ok(grant.to_string())
}

pub fn validate_worker_storage_broker_access(
    input: &str,
    store_id: &str,
    operation: &str,
) -> Result<(), String> {
    let parsed = parse_closed_worker_frame(input)?;
    let effect = required_string(&parsed.invocation.effect, "effect")?;
    if effect == "read" && !matches!(operation, "read" | "list" | "get" | "query") {
        return Err(format!(
            "worker method with read effect is not allowed to perform storage operation {operation:?}"
        ));
    }
    let broker_access = parsed
        .invocation
        .broker_access
        .as_ref()
        .ok_or_else(|| "worker method has no storage broker access".to_string())?;
    let broker_access: WorkerBrokerAccessPayload = serde_json::from_str(broker_access.get())
        .map_err(|err| format!("decode worker broker access: {err}"))?;
    let allowed = broker_access.storage.iter().any(|entry| {
        entry.store_id == store_id && entry.operations.iter().any(|value| value == operation)
    });
    if !allowed {
        return Err(format!(
            "worker method is not allowed to perform storage operation {operation:?} on {store_id:?}"
        ));
    }
    Ok(())
}

pub fn validate_worker_network_broker_access(
    input: &str,
    connector_id: &str,
    transport: &str,
    operation: &str,
    http_method: &str,
) -> Result<(), String> {
    let parsed = parse_closed_worker_frame(input)?;
    let broker_access = parsed
        .invocation
        .broker_access
        .as_ref()
        .ok_or_else(|| "worker method has no network broker access".to_string())?;
    let broker_access: WorkerBrokerAccessPayload = serde_json::from_str(broker_access.get())
        .map_err(|err| format!("decode worker broker access: {err}"))?;
    let allowed = broker_access.network.iter().any(|entry| {
        if entry.connector_id != connector_id
            || entry.transport != transport
            || !entry.operations.iter().any(|value| value == operation)
        {
            return false;
        }
        transport != "http" || entry.http_methods.iter().any(|value| value == http_method)
    });
    if !allowed {
        return Err(format!(
            "worker method is not allowed to perform network operation {operation:?} with {http_method:?} on {connector_id:?}/{transport:?}"
        ));
    }
    Ok(())
}

pub fn parse_worker_response_v2(input: &str) -> Result<WorkerResponseV2, String> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|err| format!("decode worker response: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "worker response must be a closed object".to_string())?;
    let ok = object
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "worker response ok must be a boolean".to_string())?;
    if ok {
        if object.len() != 2 || !object.contains_key("data") {
            return Err("worker success response must be a closed object".to_string());
        }
        let raw: RawWorkerSuccessV2 = serde_json::from_str(input)
            .map_err(|err| format!("decode worker success response: {err}"))?;
        if !raw.ok {
            return Err("worker success response ok must be true".to_string());
        }
        return Ok(WorkerResponseV2::Success(raw.data.get().to_string()));
    }
    if object.len() != 3 || !object.contains_key("error_code") || !object.contains_key("message") {
        return Err("worker failure response must be a closed object".to_string());
    }
    let raw: RawWorkerFailureV2 = serde_json::from_str(input)
        .map_err(|err| format!("decode worker failure response: {err}"))?;
    if raw.ok {
        return Err("worker failure response ok must be false".to_string());
    }
    if !is_stable_worker_error_code(&raw.error_code) {
        return Err("worker failure response error_code is invalid".to_string());
    }
    if raw.message.trim().is_empty() || raw.message.len() > 4096 {
        return Err("worker failure response message is invalid".to_string());
    }
    Ok(WorkerResponseV2::Failure {
        code: raw.error_code,
        message: raw.message,
    })
}

fn is_stable_worker_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().enumerate().all(|(index, ch)| {
            ch.is_ascii_uppercase() || ch.is_ascii_digit() || (index > 0 && ch == '_')
        })
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkerLeaseReplayKey {
    pub lease_id: String,
    pub lease_nonce: String,
    pub expires_at_unix_ms: i64,
}

pub fn parse_worker_lease_replay_key(input: &str) -> Result<WorkerLeaseReplayKey, &'static str> {
    let parsed = parse_closed_worker_frame(input).map_err(|_| "invalid invocation")?;
    let lease_id = parsed.lease.lease_id.ok_or("missing lease_id")?;
    if lease_id.trim().is_empty() {
        return Err("empty lease_id");
    }
    let lease_nonce = parsed.lease.lease_nonce.ok_or("missing lease_nonce")?;
    if lease_nonce.trim().is_empty() {
        return Err("empty lease_nonce");
    }
    let expires_at_unix_ms = match (parsed.lease.expires_at_unix_ms, parsed.lease.expires_at) {
        (Some(value), _) => value,
        (None, Some(value)) => OffsetDateTime::parse(value.trim(), &Rfc3339)
            .map(|parsed| (parsed.unix_timestamp_nanos() / 1_000_000) as i64)
            .map_err(|_| "missing or invalid expires_at_unix_ms")?,
        (None, None) => return Err("missing or invalid expires_at_unix_ms"),
    };
    Ok(WorkerLeaseReplayKey {
        lease_id,
        lease_nonce,
        expires_at_unix_ms,
    })
}

pub fn parse_worker_invocation_identity(
    input: &str,
) -> Result<WorkerInvocationIdentity, &'static str> {
    let parsed = parse_closed_worker_frame(input).map_err(|_| "invalid worker invocation")?;
    let invocation = parsed.invocation;
    let package_hash = invocation.package_hash.ok_or("missing package_hash")?;
    if !is_sha256_ref(&package_hash) {
        return Err("invalid package_hash");
    }
    let artifact = invocation.artifact.ok_or("missing artifact")?;
    if !is_worker_artifact_path(&artifact) {
        return Err("invalid artifact");
    }
    let artifact_sha256 = invocation
        .artifact_sha256
        .ok_or("missing artifact_sha256")?;
    if !is_sha256_ref(&artifact_sha256) {
        return Err("invalid artifact_sha256");
    }
    let worker_id = invocation.worker_id.ok_or("missing worker_id")?;
    if worker_id.trim().is_empty() {
        return Err("empty worker_id");
    }
    let method = invocation.method.ok_or("missing method")?;
    if method.trim().is_empty() {
        return Err("empty method");
    }
    let export = invocation.export.ok_or("missing export")?;
    if export != "redevplugin_worker_invoke" {
        return Err("invalid export");
    }
    Ok(WorkerInvocationIdentity {
        package_hash,
        artifact,
        artifact_sha256,
        worker_id,
        method,
        export,
    })
}

pub fn worker_invocation_not_implemented_message(identity: &WorkerInvocationIdentity) -> String {
    format!(
        "runtime worker execution is not implemented for {}:{}",
        identity.worker_id, identity.method
    )
}

fn is_sha256_ref(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

fn is_worker_artifact_path(value: &str) -> bool {
    if !value.starts_with("workers/") || !value.ends_with(".wasm") {
        return false;
    }
    if value.contains('\\') || value.contains("//") {
        return false;
    }
    value
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    fn closed_worker_frame(lease: &str, invocation: &str) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{lease},"method":"worker.echo","invocation":{invocation}}}}}"#
        )
    }

    fn hello_frame(channel_nonce: Option<&str>, public_keys: &str) -> String {
        let channel_nonce = channel_nonce
            .map(|value| format!(",\"channel_nonce\":\"{value}\""))
            .unwrap_or_default();
        format!(
            r#"{{"ipc_version":"rust-ipc-v2","frame_type":"hello","request_id":"r1","runtime_generation_id":"g1","payload":{{"target":{{"os":"test","arch":"test"}},"host_process_id":1,"host_ipc_version":"rust-ipc-v2","host_wasm_abi":"redevplugin-wasm-worker-v2","started_unix_nano":1{channel_nonce},"runtime_lease_public_keys":{public_keys}}}}}"#
        )
    }

    #[test]
    fn validates_hello_frame() {
        let input = hello_frame(Some("nonce_1234567890"), "[]");
        let (request_id, generation_id, channel_nonce) =
            validate_hello_frame(&input).expect("valid hello");
        assert_eq!(request_id, "r1");
        assert_eq!(generation_id, "g1");
        assert_eq!(channel_nonce, "nonce_1234567890");
    }

    #[test]
    fn closed_ipc_decoding_rejects_ambiguous_or_extended_frames() {
        let valid = r#"{"ipc_version":"rust-ipc-v2","frame_type":"heartbeat","request_id":"outer","runtime_generation_id":"g1","payload":{"request_id":"nested"}}"#;
        let (_, request_id, _) = parse_frame_identity(valid).expect("top-level frame identity");
        assert_eq!(request_id, "outer");

        for invalid in [
            format!("{valid}{{}}"),
            valid.replace(r#""payload""#, r#""unknown":true,"payload""#),
            valid.replace(
                r#""request_id":"outer""#,
                r#""request_id":"outer","request_id":"replayed""#,
            ),
        ] {
            assert!(parse_frame_identity(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn closed_worker_decoding_rejects_unknown_duplicate_and_trailing_fields() {
        let valid = closed_worker_frame(
            r#"{"plugin_instance_id":"plugini_1","revoke_epoch":1}"#,
            r#"{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","method":"worker.echo"}"#,
        );
        parse_worker_invocation_context(&valid).expect("closed worker invocation");

        for invalid in [
            format!("{valid}{{}}"),
            valid.replace(
                r#""method":"worker.echo"}}}"#,
                r#""method":"worker.echo","unknown":true}}}"#,
            ),
            valid.replace(
                r#""plugin_instance_id":"plugini_1","active_fingerprint""#,
                r#""plugin_instance_id":"plugini_1","plugin_instance_id":"plugini_2","active_fingerprint""#,
            ),
            valid.replace(
                r#""revoke_epoch":1}"#,
                r#""revoke_epoch":1,"unknown":true}"#,
            ),
        ] {
            assert!(parse_worker_invocation_context(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn rejects_hello_frame_without_channel_nonce() {
        let input = hello_frame(None, "[]");
        assert_eq!(validate_hello_frame(&input), Err("missing channel_nonce"));
    }

    #[test]
    fn parses_runtime_lease_public_keys_from_hello() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let input = hello_frame(
            Some("nonce_1234567890"),
            &format!(
                r#"[{{"algorithm":"ed25519","key_id":"host_ephemeral_key_1","public_key_base64":"{public_key}"}}]"#
            ),
        );
        let keys = parse_runtime_lease_public_keys(&input).expect("keys");
        assert_eq!(
            keys,
            vec![RuntimeLeasePublicKey {
                key_id: "host_ephemeral_key_1".to_string(),
                public_key: [7u8; 32],
            }]
        );
    }

    #[test]
    fn rejects_hello_without_runtime_lease_public_keys() {
        let missing = hello_frame(Some("nonce_1234567890"), "null");
        assert!(parse_runtime_lease_public_keys(&missing).is_err());
        let empty = hello_frame(Some("nonce_1234567890"), "[]");
        assert!(parse_runtime_lease_public_keys(&empty).is_err());
    }

    #[test]
    fn verifies_worker_runtime_lease_signature() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let frame = signed_runtime_lease_invocation_for_test(&signing_key, None);
        let key = RuntimeLeasePublicKey {
            key_id: "host_ephemeral_key_1".to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
        };
        verify_worker_runtime_lease_signature(&frame, &[key]).expect("signed lease");
    }

    #[test]
    fn rejects_tampered_worker_runtime_lease_signature() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let frame =
            signed_runtime_lease_invocation_for_test(&signing_key, Some(("revoke_epoch", "14")));
        let key = RuntimeLeasePublicKey {
            key_id: "host_ephemeral_key_1".to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
        };
        let err = verify_worker_runtime_lease_signature(&frame, &[key])
            .expect_err("tampered lease should fail");
        assert!(err.contains("signature"));
    }

    #[test]
    fn rejects_unsigned_worker_runtime_lease_when_keys_are_configured() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"rtgen_1","payload":{"lease":{"lease_id":"rel_1","lease_token":"token_1","lease_nonce":"nonce_1234567890","runtime_generation_id":"rtgen_1","plugin_instance_id":"plugini_1","method":"worker.echo","effect":"read","execution":"sync","audit_correlation_id":"audit_1","key_id":"host_ephemeral_key_1","expires_at":"2026-07-04T10:45:30Z"},"method":"worker.echo","invocation":{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}}}"#;
        let err = verify_worker_runtime_lease_signature(
            frame,
            &[RuntimeLeasePublicKey {
                key_id: "host_ephemeral_key_1".to_string(),
                public_key: signing_key.verifying_key().to_bytes(),
            }],
        )
        .expect_err("missing signature should fail");
        assert!(err.contains("signature"));
    }

    #[test]
    fn rejects_worker_runtime_lease_without_runtime_keys() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let frame = signed_runtime_lease_invocation_for_test(&signing_key, None);
        let err = verify_worker_runtime_lease_signature(&frame, &[])
            .expect_err("missing runtime keyring should fail closed");
        assert!(err.contains("public keys"));
    }

    #[test]
    fn validates_worker_runtime_lease_expiry_and_execution_binding() {
        let frame =
            include_str!("../../../testdata/contracts/runtime-lease-signature-v1-invocation.json");
        validate_worker_runtime_lease(frame, 1_783_161_901_000)
            .expect("current runtime lease binding");

        let expired = validate_worker_runtime_lease(frame, 1_783_161_930_000)
            .expect_err("expired runtime lease must fail closed");
        assert!(expired.contains("expired"), "{expired}");

        let mut mismatched: Value = serde_json::from_str(frame).expect("invocation fixture");
        mismatched["payload"]["invocation"]["stream_id"] =
            Value::String("stream_other".to_string());
        let mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&mismatched).expect("mismatched invocation"),
            1_783_161_901_000,
        )
        .expect_err("execution handle mismatch must fail closed");
        assert!(mismatch.contains("stream_id"), "{mismatch}");

        let mut tampered_params: Value = serde_json::from_str(frame).expect("invocation fixture");
        tampered_params["payload"]["invocation"]["params"]["message"] =
            Value::String("tampered".to_string());
        let params_mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&tampered_params).expect("tampered invocation"),
            1_783_161_901_000,
        )
        .expect_err("tampered params must fail closed");
        assert!(
            params_mismatch.contains("params_sha256"),
            "{params_mismatch}"
        );

        let mut unbound_target: Value = serde_json::from_str(frame).expect("invocation fixture");
        unbound_target["payload"]["lease"]["target_descriptor_hashes"] = serde_json::json!([
            "method:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "worker:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        ]);
        let target_mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&unbound_target).expect("unbound invocation"),
            1_783_161_901_000,
        )
        .expect_err("unbound invocation target must fail closed");
        assert!(
            target_mismatch.contains("does not bind"),
            "{target_mismatch}"
        );
    }

    #[test]
    fn runtime_lease_signature_payload_matches_go_canonical_order() {
        let lease = serde_json::json!({
            "lease_id": "rel_lease_signature",
            "token_id": "rel_token_signature",
            "lease_token": "runtime_execution_lease.rel_lease_signature.secret",
            "lease_nonce": "nonce_1234567890",
            "runtime_generation_id": "rtgen_1",
            "plugin_instance_id": "plugini_1",
            "plugin_id": "com.example.worker",
            "plugin_version": "1.2.3",
            "active_fingerprint": "sha256:active",
            "issued_at": "2026-07-04T10:45:00Z",
            "method": "worker.echo",
            "effect": "read",
            "execution": "sync",
            "audit_correlation_id": "audit_lease_signature",
            "surface_instance_id": "surface_runtime",
            "owner_session_hash": "session_hash",
            "owner_user_hash": "user_hash",
            "session_channel_id_hash": "channel_hash",
            "bridge_channel_id": "bridge_runtime",
            "target_descriptor_hashes": [
                "method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "limits": {
                "timeout_ms": 2000,
                "memory_bytes": 65536,
                "max_payload_bytes": 4096,
                "max_stream_bytes_per_sec": 1024
            },
            "policy_revision": 11,
            "management_revision": 12,
            "revoke_epoch": 13,
            "runtime_shard_id": "rtshard_1",
            "runtime_instance_id": "rtinst_1",
            "ipc_channel_id": "ipc_1",
            "connection_nonce": "connection_nonce_1234567890",
            "key_id": "host_ephemeral_key_1",
            "signature": "ed25519:not-part-of-the-payload",
            "expires_at": "2026-07-04T10:45:30Z"
        });
        let payload = runtime_lease_signature_payload_json(
            lease.as_object().expect("lease object"),
            "worker.echo",
        )
        .expect("payload");
        assert_eq!(
            payload,
            r#"{"schema_version":"redevplugin.runtime_execution_lease.v1","token_kind":"runtime_execution_lease","lease_id":"rel_lease_signature","token_id":"rel_token_signature","lease_nonce":"nonce_1234567890","plugin_instance_id":"plugini_1","plugin_id":"com.example.worker","plugin_version":"1.2.3","active_fingerprint":"sha256:active","issued_at_unix_ms":1783161900000,"method":"worker.echo","effect":"read","execution":"sync","audit_correlation_id":"audit_lease_signature","surface_instance_id":"surface_runtime","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_runtime","target_descriptor_hashes":["method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"limits":{"timeout_ms":2000,"memory_bytes":65536,"max_payload_bytes":4096,"max_stream_bytes_per_sec":1024},"policy_revision":11,"management_revision":12,"revoke_epoch":13,"expires_at_unix_ms":1783161930000,"runtime_shard_id":"rtshard_1","runtime_instance_id":"rtinst_1","runtime_generation_id":"rtgen_1","ipc_channel_id":"ipc_1","connection_nonce":"connection_nonce_1234567890","key_id":"host_ephemeral_key_1"}"#
        );
        assert!(!payload.contains("lease_token"));
        assert!(!payload.contains("not-part-of-the-payload"));
    }

    #[test]
    fn runtime_lease_signature_shared_fixture_matches_go() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/contracts/runtime-lease-signature-v1.json"
        ))
        .expect("shared runtime lease fixture");
        let lease = fixture
            .get("lease")
            .and_then(|value| value.as_object())
            .expect("fixture lease");
        let method = fixture
            .get("method")
            .and_then(|value| value.as_str())
            .expect("fixture method");
        let canonical = fixture
            .get("canonical_payload")
            .and_then(|value| value.as_str())
            .expect("fixture canonical payload");
        assert_eq!(
            runtime_lease_signature_payload_json(lease, method).expect("canonical payload"),
            canonical
        );
        let public_key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(
                fixture
                    .get("public_key_base64")
                    .and_then(|value| value.as_str())
                    .expect("fixture public key")
                    .as_bytes(),
            )
            .expect("fixture public key base64")
            .try_into()
            .expect("fixture public key length");
        verify_worker_runtime_lease_signature(
            include_str!("../../../testdata/contracts/runtime-lease-signature-v1-invocation.json"),
            &[RuntimeLeasePublicKey {
                key_id: "host_ephemeral_fixture_v1".to_string(),
                public_key,
            }],
        )
        .expect("shared runtime lease fixture signature");
    }

    #[test]
    fn renders_hello_ack_frame() {
        let frame = hello_ack_frame("r1", "g1", "nonce_1", "0.0.0-dev", WASM_ABI_VERSION);
        assert!(frame.contains(r#""frame_type":"hello_ack""#));
        assert!(frame.contains(r#""request_id":"r1""#));
        assert!(frame.contains(r#""runtime_generation_id":"g1""#));
        assert!(frame.contains(r#""rust_ipc_version":"rust-ipc-v2""#));
        assert!(frame.contains(r#""channel_nonce":"nonce_1""#));
    }

    #[test]
    fn renders_error_response_frame() {
        let frame = response_frame(
            FRAME_TYPE_INVOKE_WORKER_RESULT,
            "r1",
            "g1",
            false,
            None,
            Some(ERR_WASM_WORKER_FAILED),
            Some("runtime worker execution failed"),
        );
        assert!(frame.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(frame.contains(r#""ok":false"#));
        assert!(frame.contains(r#""code":"WASM_WORKER_FAILED""#));
        assert!(frame.contains(r#""error_origin":"runtime""#));

        let plugin_frame = response_error_frame(
            FRAME_TYPE_INVOKE_WORKER_RESULT,
            "r2",
            "g1",
            ResponseError {
                code: "NOTE_NOT_FOUND",
                message: "note was not found",
                origin: ERROR_ORIGIN_PLUGIN,
            },
        );
        assert!(plugin_frame.contains(r#""error_origin":"plugin""#));
    }

    #[test]
    fn ipc_golden_fixtures_match_rust_frame_contract() {
        let fixtures = [
            "current_hello_ack.json",
            "invoke_worker_result_ok.json",
            "host_new_rust_old.json",
            "host_old_rust_new.json",
            "wasm_abi_old.json",
            "wasm_abi_new.json",
            "missing_required.json",
            "replay_frame.json",
            "runtime_generation_mismatch.json",
            "unknown_enum.json",
        ];
        for fixture_name in fixtures {
            let fixture = load_ipc_fixture(fixture_name);
            assert_eq!(
                fixture["want_error"].as_bool(),
                Some(
                    fixture_name != "current_hello_ack.json"
                        && fixture_name != "invoke_worker_result_ok.json"
                ),
                "fixture {fixture_name} want_error mismatch"
            );
            let frame = fixture.get("frame").expect("fixture frame").clone();
            let frame_json = serde_json::to_string(&frame).expect("compact frame");
            match fixture_name {
                "current_hello_ack.json" => {
                    let encoded = hello_ack_frame(
                        fixture["request_id"].as_str().expect("request_id"),
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("runtime_generation_id"),
                        fixture["channel_nonce"].as_str().expect("channel_nonce"),
                        frame["payload"]["runtime_version"]
                            .as_str()
                            .expect("runtime_version"),
                        WASM_ABI_VERSION,
                    );
                    assert_json_eq(&frame_json, &encoded, fixture_name);
                }
                "invoke_worker_result_ok.json" => {
                    let result =
                        serde_json::to_string(&frame["payload"]["result"]).expect("compact result");
                    let encoded = response_frame(
                        FRAME_TYPE_INVOKE_WORKER_RESULT,
                        fixture["request_id"].as_str().expect("request_id"),
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("runtime_generation_id"),
                        true,
                        Some(&result),
                        None,
                        None,
                    );
                    assert_json_eq(&frame_json, &encoded, fixture_name);
                }
                "host_new_rust_old.json" | "host_old_rust_new.json" => {
                    assert_eq!(
                        parse_frame_identity(&frame_json),
                        Err("unsupported ipc_version"),
                        "fixture {fixture_name} should reject unsupported ipc version"
                    );
                }
                "wasm_abi_old.json" | "wasm_abi_new.json" => {
                    let (_, _, _) = parse_frame_identity(&frame_json)
                        .expect("wasm abi mismatch fixture should keep valid frame identity");
                    assert_ne!(
                        frame["payload"]["wasm_abi_version"].as_str(),
                        Some(WASM_ABI_VERSION),
                        "fixture {fixture_name} should carry mismatched wasm abi"
                    );
                }
                "missing_required.json" => {
                    assert_eq!(
                        parse_frame_identity(&frame_json),
                        Err("missing request_id"),
                        "fixture {fixture_name} should reject missing request_id"
                    );
                }
                "replay_frame.json" => {
                    let (_, request_id, _) =
                        parse_frame_identity(&frame_json).expect("parse replay fixture");
                    assert_ne!(
                        request_id,
                        fixture["request_id"].as_str().expect("expected request_id"),
                        "fixture {fixture_name} should replay a different request_id"
                    );
                }
                "runtime_generation_mismatch.json" => {
                    let (_, _, runtime_generation_id) = parse_frame_identity(&frame_json)
                        .expect("parse runtime generation mismatch fixture");
                    assert_ne!(
                        runtime_generation_id,
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("expected runtime_generation_id"),
                        "fixture {fixture_name} should carry mismatched runtime generation"
                    );
                }
                "unknown_enum.json" => {
                    let (frame_type, _, _) =
                        parse_frame_identity(&frame_json).expect("parse unknown enum fixture");
                    assert_ne!(
                        frame_type, FRAME_TYPE_INVOKE_WORKER_RESULT,
                        "fixture {fixture_name} should use an unknown frame type"
                    );
                }
                _ => panic!("unhandled fixture {fixture_name}"),
            }
        }
    }

    fn load_ipc_fixture(name: &str) -> Value {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("..");
        path.push("..");
        path.push("testdata");
        path.push("contracts");
        path.push("ipc");
        path.push(name);
        let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("read fixture {}: {err}", path.display());
        });
        serde_json::from_str(&raw).unwrap_or_else(|err| {
            panic!("decode fixture {}: {err}", path.display());
        })
    }

    fn assert_json_eq(actual: &str, expected: &str, label: &str) {
        let actual: Value = serde_json::from_str(actual).expect("actual json");
        let expected: Value = serde_json::from_str(expected).expect("expected json");
        assert_eq!(actual, expected, "{label} json mismatch");
    }

    #[test]
    fn renders_revoke_epoch_ack_result_json() {
        let result = revoke_epoch_ack_result_json("plugini_1", 7, 2, 3, 4);
        assert!(result.contains(r#""plugin_instance_id":"plugini_1""#));
        assert!(result.contains(r#""revoke_epoch":7"#));
        assert!(result.contains(r#""closed_socket_count":2"#));
        assert!(result.contains(r#""closed_stream_count":3"#));
        assert!(result.contains(r#""closed_storage_handle_count":4"#));
    }

    #[test]
    fn renders_heartbeat_ack_result_json() {
        let result = heartbeat_ack_result_json("runtime_gen_1", 101, 5000, 100);
        assert!(result.contains(r#""runtime_generation_id":"runtime_gen_1""#));
        assert!(result.contains(r#""runtime_unix_nano":101"#));
        assert!(result.contains(r#""max_staleness_ms":5000"#));
        assert!(result.contains(r#""host_sent_unix_nano":100"#));
    }

    #[test]
    fn renders_open_handle_frame() {
        let identity = WorkerInvocationIdentity {
            package_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            artifact: "workers/backend.wasm".to_string(),
            artifact_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            worker_id: "backend".to_string(),
            method: "worker.echo".to_string(),
            export: "redevplugin_worker_invoke".to_string(),
        };
        let frame = open_handle_frame("r1", "g1", &identity);
        assert!(frame.contains(r#""frame_type":"open_handle""#));
        assert!(frame.contains(r#""artifact":"workers/backend.wasm""#));
    }

    #[test]
    fn validates_open_handle_response() {
        let identity = WorkerInvocationIdentity {
            package_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            artifact: "workers/backend.wasm".to_string(),
            artifact_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            worker_id: "backend".to_string(),
            method: "worker.echo".to_string(),
            export: "redevplugin_worker_invoke".to_string(),
        };
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{"ok":true,"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"AAE="}}"#;
        validate_open_handle_response(frame, "r1:artifact", "g1", &identity)
            .expect("valid open_handle");
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{"ok":false,"code":"ARTIFACT_HANDLE_FAILED","message":"unavailable","error_origin":"hostcall"}}"#;
        let err = validate_open_handle_response(failed, "r1:artifact", "g1", &identity)
            .expect_err("failed open_handle response");
        assert!(err.contains("ARTIFACT_HANDLE_FAILED"));
    }

    #[test]
    fn renders_validate_handle_grant_frame() {
        let frame = validate_handle_grant_frame(
            "r1:handle",
            "g1",
            "handle_grant.secret",
            "plugini_1",
            "sha256:active",
            "storage:db",
            "storage.sqlite",
            1,
            2,
            3,
        );
        assert!(frame.contains(r#""frame_type":"validate_handle_grant""#));
        assert!(frame.contains(r#""handle_id":"storage:db""#));
        assert!(frame.contains(r#""policy_revision":1"#));
    }

    #[test]
    fn validates_handle_grant_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"validate_handle_grant","request_id":"r1:handle","runtime_generation_id":"g1","payload":{"ok":true,"handle_grant_id":"h1","handle_id":"storage:db","method":"storage.sqlite","runtime_generation_id":"g1","max_total_bytes":4096}}"#;
        validate_handle_grant_response(frame, "r1:handle", "g1", "storage:db", "storage.sqlite")
            .expect("valid handle grant");
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"validate_handle_grant","request_id":"r1:handle","runtime_generation_id":"g1","payload":{"ok":false,"code":"HANDLE_GRANT_VALIDATION_FAILED","message":"denied","error_origin":"hostcall"}}"#;
        let err = validate_handle_grant_response(
            failed,
            "r1:handle",
            "g1",
            "storage:db",
            "storage.sqlite",
        )
        .expect_err("failed handle grant response");
        assert!(err.contains("HANDLE_GRANT_VALIDATION_FAILED"));
    }

    #[test]
    fn renders_storage_file_frame() {
        let req = StorageFileRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:workspace".to_string(),
            method: "storage.files".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
            operation: "read".to_string(),
            store_id: "workspace".to_string(),
            path: "notes/today.txt".to_string(),
            data_base64: "".to_string(),
            max_bytes: 1024,
            max_entries: 10,
            recursive: false,
        };
        let frame = storage_file_frame("r1:storage_file", "g1", &req);
        assert!(frame.contains(r#""frame_type":"storage_file""#));
        assert!(frame.contains(r#""handle_id":"storage:workspace""#));
        assert!(frame.contains(r#""method":"storage.files""#));
        assert!(frame.contains(r#""operation":"read""#));
    }

    #[test]
    fn validates_storage_file_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/today.txt","data_base64":"aGVsbG8=","size_bytes":5}}"#;
        validate_storage_file_response(frame, "r1:storage_file", "g1")
            .expect("valid storage file response");
        let payload = storage_file_payload_json(frame).expect("storage file payload");
        assert!(payload.contains(r#""path":"notes/today.txt""#));
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing","error_origin":"hostcall"}}"#;
        let err = validate_storage_file_response(failed, "r1:storage_file", "g1")
            .expect_err("failed storage file response");
        assert!(err.contains("STORAGE_FILE_NOT_FOUND"));
        let missing_origin = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing"}}"#;
        let err = validate_storage_file_response(missing_origin, "r1:storage_file", "g1")
            .expect_err("hostcall origin is required");
        assert!(err.contains("error_origin"));
        let spoofed_origin = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing","error_origin":"plugin"}}"#;
        let err = validate_storage_file_response(spoofed_origin, "r1:storage_file", "g1")
            .expect_err("hostcall origin cannot be spoofed");
        assert!(err.contains("must be hostcall"));
    }

    #[test]
    fn renders_storage_kv_frame() {
        let req = StorageKVRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:settings".to_string(),
            method: "storage.kv".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
            operation: "put".to_string(),
            store_id: "settings".to_string(),
            key: "demo/last_broker_run".to_string(),
            value_base64: "aGVsbG8=".to_string(),
            prefix: String::new(),
            max_bytes: 0,
            max_entries: 10,
        };
        let frame = storage_kv_frame("r1:storage_kv", "g1", &req);
        assert!(frame.contains(r#""frame_type":"storage_kv""#));
        assert!(frame.contains(r#""handle_id":"storage:settings""#));
        assert!(frame.contains(r#""method":"storage.kv""#));
        assert!(frame.contains(r#""operation":"put""#));
        assert!(frame.contains(r#""key":"demo/last_broker_run""#));
    }

    #[test]
    fn validates_storage_kv_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":true,"key":"demo/last_broker_run","size_bytes":5}}"#;
        validate_storage_kv_response(frame, "r1:storage_kv", "g1")
            .expect("valid storage kv response");
        let payload = storage_kv_payload_json(frame).expect("storage kv payload");
        assert!(payload.contains(r#""key":"demo/last_broker_run""#));
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_KV_NOT_FOUND","message":"missing","error_origin":"hostcall"}}"#;
        let err = validate_storage_kv_response(failed, "r1:storage_kv", "g1")
            .expect_err("failed storage kv response");
        assert!(err.contains("STORAGE_KV_NOT_FOUND"));
    }

    #[test]
    fn renders_worker_success_with_storage_result() {
        let identity = WorkerInvocationIdentity {
            package_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            artifact: "workers/backend.wasm".to_string(),
            artifact_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            worker_id: "backend".to_string(),
            method: "worker.echo".to_string(),
            export: "redevplugin_worker_invoke".to_string(),
        };
        let result = worker_success_result_json(
            &identity,
            42,
            Some(r#"{"ok":true,"path":"notes/from-wasm.txt","size_bytes":5}"#),
            Some(r#"{"ok":true,"key":"demo/last_broker_run","size_bytes":12}"#),
            Some(r#"{"ok":true,"database":"plugin.sqlite","rows_affected":1}"#),
            Some(r#"{"ok":true,"transport":"http","status_code":201,"stream_id":"stream_http_1"}"#),
        );
        assert!(result.contains(r#""storage_file":{"ok":true"#));
        assert!(result.contains(r#""storage_kv":{"ok":true"#));
        assert!(result.contains(r#""storage_sqlite":{"ok":true"#));
        assert!(result.contains(r#""network_execute":{"ok":true"#));
        assert!(result.contains(r#""stream_id":"stream_http_1""#));
        assert!(result.contains(r#""wasm_byte_len":42"#));
    }

    #[test]
    fn renders_storage_sqlite_frame() {
        let req = StorageSQLiteRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:db".to_string(),
            method: "storage.sqlite".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
            operation: "query".to_string(),
            store_id: "db".to_string(),
            database: "plugin.sqlite".to_string(),
            sql: "SELECT title FROM events WHERE score = ?".to_string(),
            args_json: r#"[{"int":7}]"#.to_string(),
            max_rows: 10,
            max_response_bytes: 4096,
            timeout_ms: 1000,
        };
        let frame = storage_sqlite_frame("r1:storage_sqlite", "g1", &req);
        assert!(frame.contains(r#""frame_type":"storage_sqlite""#));
        assert!(frame.contains(r#""handle_id":"storage:db""#));
        assert!(frame.contains(r#""method":"storage.sqlite""#));
        assert!(frame.contains(r#""operation":"query""#));
        assert!(frame.contains(r#""args":[{"int":7}]"#));
    }

    #[test]
    fn validates_storage_sqlite_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":true,"database":"plugin.sqlite","columns":["title"],"rows":[[{"text":"stored from wasm"}]]}}"#;
        validate_storage_sqlite_response(frame, "r1:storage_sqlite", "g1")
            .expect("valid storage sqlite response");
        let payload = storage_sqlite_payload_json(frame).expect("storage sqlite payload");
        assert!(payload.contains(r#""database":"plugin.sqlite""#));
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_SQLITE_RESULT_TOO_LARGE","message":"too large","error_origin":"hostcall"}}"#;
        let err = validate_storage_sqlite_response(failed, "r1:storage_sqlite", "g1")
            .expect_err("failed storage sqlite response");
        assert!(err.contains("STORAGE_SQLITE_RESULT_TOO_LARGE"));
    }

    #[test]
    fn extracts_nested_json_object_values() {
        let input = r#"{"headers":{"Content-Type":["text/plain"],"X-Test":["value with } brace"]},"after":true}"#;
        let headers = extract_json_object(input, "headers").expect("headers object");
        assert_eq!(
            headers,
            r#"{"Content-Type":["text/plain"],"X-Test":["value with } brace"]}"#
        );
        assert_eq!(extract_json_object(input, "missing"), None);
    }

    #[test]
    fn renders_network_grant_frame() {
        let req = NetworkGrantRequest {
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
            connector_id: "api".to_string(),
            transport: "http".to_string(),
            destination: "https://api.example.com".to_string(),
            ttl_ms: 30000,
        };
        let frame = network_grant_frame("r1:network_grant", "g1", &req);
        assert!(frame.contains(r#""frame_type":"network_grant""#));
        assert!(frame.contains(r#""connector_id":"api""#));
        assert!(frame.contains(r#""transport":"http""#));
        assert!(frame.contains(r#""ttl_ms":30000"#));
    }

    #[test]
    fn validates_network_grant_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":true,"grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"runtime_generation_id":"g1","target_classifier_version":"target-classifier-v1","expires_at":"2026-06-30T10:00:30Z"}}"#;
        validate_network_grant_response(frame, "r1:network_grant", "g1", "api", "http")
            .expect("valid network grant response");
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_TARGET_DENIED","message":"blocked","error_origin":"hostcall"}}"#;
        let err = validate_network_grant_response(failed, "r1:network_grant", "g1", "api", "http")
            .expect_err("failed network grant response");
        assert!(err.contains("NETWORK_TARGET_DENIED"));
    }

    #[test]
    fn renders_network_execute_frame() {
        let req = NetworkExecuteRequest {
            plugin_id: "com.example.worker".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
            connector_id: "api".to_string(),
            transport: "http".to_string(),
            destination: "https://api.example.com".to_string(),
            ttl_ms: 30000,
            operation: "http".to_string(),
            method: "POST".to_string(),
            path: "/v1/worker".to_string(),
            query_json: r#"{"lang":["en"],"units":["metric"]}"#.to_string(),
            headers_json: r#"{"X-Test":["ok"]}"#.to_string(),
            message_type: "".to_string(),
            body_base64: "e30=".to_string(),
            payload_base64: "".to_string(),
            max_request_bytes: 1024,
            max_response_bytes: 2048,
            max_chunk_bytes: 256,
            max_buffered_bytes: 65536,
            timeout_ms: 2000,
            stream_id: "stream_1".to_string(),
            stream_method: "worker.echo".to_string(),
            stream_effect: "read".to_string(),
            stream_execution: "subscription".to_string(),
            surface_instance_id: "surface_1".to_string(),
            owner_session_hash: "session_hash".to_string(),
            owner_user_hash: "user_hash".to_string(),
            session_channel_id_hash: "channel_hash".to_string(),
            bridge_channel_id: "bridge_1".to_string(),
            content_type: "text/plain".to_string(),
        };
        let frame = network_execute_frame("r1:network_execute", "g1", &req);
        assert!(frame.contains(r#""frame_type":"network_execute""#));
        assert!(frame.contains(r#""operation":"http""#));
        assert!(frame.contains(r#""headers":{"X-Test":["ok"]}"#));
        assert!(frame.contains(r#""query":{"lang":["en"],"units":["metric"]}"#));
        assert!(frame.contains(r#""body_base64":"e30=""#));
        assert!(frame.contains(r#""stream_id":"stream_1""#));
        assert!(frame.contains(r#""owner_session_hash":"session_hash""#));
        assert!(frame.contains(r#""max_chunk_bytes":256"#));
        assert!(frame.contains(r#""timeout_ms":2000"#));
    }

    #[test]
    fn validates_network_execute_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":true,"transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"status_code":201,"headers":{"X-Worker":["ok"]},"body_base64":"e30=","grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","runtime_generation_id":"g1"}}"#;
        validate_network_execute_response(frame, "r1:network_execute", "g1", "api", "http")
            .expect("valid network execute response");
        let failed = r#"{"ipc_version":"rust-ipc-v2","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_RESPONSE_TOO_LARGE","message":"too large","error_origin":"hostcall"}}"#;
        let err =
            validate_network_execute_response(failed, "r1:network_execute", "g1", "api", "http")
                .expect_err("failed network execute response");
        assert!(err.contains("NETWORK_RESPONSE_TOO_LARGE"));
    }

    #[test]
    fn parses_worker_invocation_identity() {
        let frame = closed_worker_frame(
            "{}",
            r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}"#,
        );
        let identity = parse_worker_invocation_identity(&frame).expect("valid invocation");
        assert_eq!(
            identity.package_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(identity.artifact, "workers/backend.wasm");
        assert_eq!(identity.worker_id, "backend");
    }

    #[test]
    fn projects_secret_free_worker_request_v2() {
        let frame = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"lease_token":"secret"},"method":"notes.save","invocation":{"plugin_id":"com.example.notes","plugin_instance_id":"plugini_1","storage_handle_grants":{"notes":"handle-secret"},"method":"notes.save","params":{"title":"Launch notes","body":"Ship the examples"}}}}"#;

        let request = worker_request_json_v2(frame).expect("worker request projection");

        assert_eq!(
            request,
            r#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.save","params":{"title":"Launch notes","body":"Ship the examples"}}"#
        );
        assert!(!request.contains("lease_token"));
        assert!(!request.contains("handle-secret"));
        assert!(!request.contains("plugin_instance_id"));
    }

    #[test]
    fn reads_positive_worker_memory_limit_from_signed_lease() {
        let frame = closed_worker_frame(
            r#"{"limits":{"memory_bytes":33554432}}"#,
            r#"{"method":"worker.echo"}"#,
        );
        assert_eq!(
            runtime_lease_memory_limit_bytes(&frame).expect("memory limit"),
            33_554_432
        );
        for lease in [
            r#"{"limits":{}}"#,
            r#"{"limits":{"memory_bytes":0}}"#,
            r#"{"limits":{"memory_bytes":268435457}}"#,
        ] {
            assert!(
                runtime_lease_memory_limit_bytes(&closed_worker_frame(
                    lease,
                    r#"{"method":"worker.echo"}"#,
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn read_effect_rejects_mutating_storage_broker_operations() {
        for operation in ["write", "delete", "put", "exec"] {
            let frame = format!(
                r#"{{"effect":"read","broker_access":{{"storage":[{{"store_id":"store","operations":["{operation}"]}}]}}}}"#
            );
            let frame = closed_worker_frame("{}", &frame);
            let err = validate_worker_storage_broker_access(&frame, "store", operation)
                .expect_err("read methods must not mutate storage");
            assert!(err.contains("read effect"), "{err}");
        }
    }

    #[test]
    fn read_effect_allows_declared_http_post_network_request() {
        let frame = closed_worker_frame(
            "{}",
            r#"{"effect":"read","broker_access":{"network":[{"connector_id":"search","transport":"http","operations":["http"],"http_methods":["POST"]}]}}"#,
        );
        validate_worker_network_broker_access(&frame, "search", "http", "http", "POST")
            .expect("HTTP verbs do not define method effect");
    }

    #[test]
    fn parses_worker_response_v2_success_and_rejects_extra_authority() {
        let success =
            parse_worker_response_v2(r#"{"ok":true,"data":{"saved":true,"id":"note_1"}}"#)
                .expect("worker success response");
        assert_eq!(
            success,
            WorkerResponseV2::Success(r#"{"saved":true,"id":"note_1"}"#.to_string())
        );

        let error = parse_worker_response_v2(
            r#"{"ok":true,"data":{"saved":true},"gateway_token":"secret"}"#,
        )
        .expect_err("extra response authority must fail closed");
        assert!(error.contains("closed object"), "{error}");
    }

    #[test]
    fn rejects_worker_invocation_without_artifact_identity() {
        let frame = closed_worker_frame("{}", r#"{"artifact":"../backend.wasm"}"#);
        let err = parse_worker_invocation_identity(&frame).expect_err("invalid invocation");
        assert_eq!(err, "missing package_hash");
        let frame = closed_worker_frame(
            "{}",
            r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/../backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}"#,
        );
        let err = parse_worker_invocation_identity(&frame).expect_err("invalid artifact");
        assert_eq!(err, "invalid artifact");
    }

    #[test]
    fn parses_worker_lease_replay_key() {
        let input = closed_worker_frame(
            r#"{"lease_id":"lease_1","lease_nonce":"nonce_1","expires_at_unix_ms":2000}"#,
            r#"{"method":"worker.echo"}"#,
        );
        let key = parse_worker_lease_replay_key(&input).expect("valid replay key");
        assert_eq!(key.lease_id, "lease_1");
        assert_eq!(key.lease_nonce, "nonce_1");
        assert_eq!(key.expires_at_unix_ms, 2_000);
    }

    #[test]
    fn rejects_worker_lease_replay_key_without_nonce() {
        let input = closed_worker_frame(r#"{"lease_id":"lease_1"}"#, r#"{"method":"worker.echo"}"#);
        let err = parse_worker_lease_replay_key(&input).expect_err("missing nonce should fail");
        assert_eq!(err, "missing lease_nonce");
    }

    fn runtime_lease_signing_key_for_test(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn signed_runtime_lease_invocation_for_test(
        signing_key: &SigningKey,
        replace: Option<(&str, &str)>,
    ) -> String {
        let mut lease = serde_json::json!({
            "lease_id": "rel_lease_signature",
            "token_id": "rel_token_signature",
            "lease_token": "runtime_execution_lease.rel_lease_signature.secret",
            "lease_nonce": "nonce_1234567890",
            "runtime_generation_id": "rtgen_1",
            "plugin_instance_id": "plugini_1",
            "plugin_id": "com.example.worker",
            "plugin_version": "1.2.3",
            "active_fingerprint": "sha256:active",
            "issued_at": "2026-07-04T10:45:00Z",
            "method": "worker.echo",
            "effect": "read",
            "execution": "sync",
            "audit_correlation_id": "audit_lease_signature",
            "surface_instance_id": "surface_runtime",
            "owner_session_hash": "session_hash",
            "owner_user_hash": "user_hash",
            "session_channel_id_hash": "channel_hash",
            "bridge_channel_id": "bridge_runtime",
            "target_descriptor_hashes": [
                "method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "limits": {
                "timeout_ms": 2000,
                "memory_bytes": 65536,
                "max_payload_bytes": 4096,
                "max_stream_bytes_per_sec": 1024
            },
            "policy_revision": 11,
            "management_revision": 12,
            "revoke_epoch": 13,
            "runtime_shard_id": "rtshard_1",
            "runtime_instance_id": "rtinst_1",
            "ipc_channel_id": "ipc_1",
            "connection_nonce": "connection_nonce_1234567890",
            "key_id": "host_ephemeral_key_1",
            "expires_at": "2026-07-04T10:45:30Z"
        });
        let payload = runtime_lease_signature_payload_json(
            lease.as_object().expect("lease object"),
            "worker.echo",
        )
        .expect("payload");
        let signature = signing_key.sign(payload.as_bytes());
        lease["signature"] = serde_json::Value::String(format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ));
        if let Some((key, value)) = replace {
            let parsed = value.parse::<u64>().expect("numeric replacement");
            lease[key] = serde_json::Value::Number(parsed.into());
        }
        format!(
            r#"{{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"rtgen_1","payload":{{"lease":{},"method":"worker.echo","invocation":{{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}}}}}}"#,
            serde_json::to_string(&lease).expect("lease json")
        )
    }
}
