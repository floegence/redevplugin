use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

mod contract_set_gen;

pub use contract_set_gen::CONTRACT_SET_SHA256;

pub const RUST_IPC_VERSION: &str = "rust-ipc-v6";
pub const WASM_ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
pub const RUNTIME_LEASE_SIGNATURE_SCHEMA_VERSION: &str = "redevplugin.runtime_execution_lease.v1";

#[cfg(test)]
fn contract_fixture(id: redevplugin_contracts::ContractId) -> &'static str {
    std::str::from_utf8(redevplugin_contracts::get(id).bytes())
        .expect("generated contracts are valid UTF-8")
}
pub const RUNTIME_LEASE_TOKEN_KIND: &str = "runtime_execution_lease";
pub const RUNTIME_LEASE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const WORKER_INVOCATION_TARGET_SCHEMA_VERSION: &str = "redevplugin.worker_invocation_target.v1";
pub const MAX_RUNTIME_LEASE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_JSON_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
pub const MIN_RUNTIME_WORKER_COUNT: usize = 1;
pub const MAX_RUNTIME_WORKER_COUNT: usize = 64;
pub const MIN_RUNTIME_QUEUE_CAPACITY: usize = 1;
pub const MAX_RUNTIME_QUEUE_CAPACITY: usize = 64;
pub const MIN_RUNTIME_PER_PLUGIN_CONCURRENCY: usize = 1;
pub const MAX_RUNTIME_PER_PLUGIN_CONCURRENCY: usize = 64;
pub const MIN_RUNTIME_MODULE_CACHE_ENTRIES: usize = 1;
pub const MAX_RUNTIME_MODULE_CACHE_ENTRIES: usize = 1024;
pub const MIN_RUNTIME_MODULE_CACHE_SOURCE_BYTES: usize = 1;
pub const MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES: usize = 128 * 1024 * 1024;
pub const FRAME_TYPE_HELLO: &str = "hello";
pub const FRAME_TYPE_HELLO_ACK: &str = "hello_ack";
pub const FRAME_TYPE_HEARTBEAT: &str = "heartbeat";
pub const FRAME_TYPE_INVOKE_WORKER: &str = "invoke_worker";
pub const FRAME_TYPE_INVOKE_WORKER_RESULT: &str = "invoke_worker_result";
pub const FRAME_TYPE_CANCEL_INVOKE: &str = "cancel_invoke";
pub const FRAME_TYPE_CANCEL_INVOKE_ACK: &str = "cancel_invoke_ack";
pub const FRAME_TYPE_COMPILE_FLIGHT_REGISTER: &str = "compile_flight_register";
pub const FRAME_TYPE_COMPILE_FLIGHT_COMPLETE: &str = "compile_flight_complete";
pub const FRAME_TYPE_OPEN_HANDLE: &str = "open_handle";
pub const FRAME_TYPE_VALIDATE_HANDLE_GRANT: &str = "validate_handle_grant";
pub const FRAME_TYPE_STORAGE_FILE: &str = "storage_file";
pub const FRAME_TYPE_STORAGE_KV: &str = "storage_kv";
pub const FRAME_TYPE_STORAGE_SQLITE: &str = "storage_sqlite";
pub const FRAME_TYPE_NETWORK_GRANT: &str = "network_grant";
pub const FRAME_TYPE_NETWORK_EXECUTE: &str = "network_execute";
pub const FRAME_TYPE_REVOKE_EPOCH: &str = "revoke_epoch";
pub const FRAME_TYPE_REVOKE_EPOCH_ACK: &str = "revoke_epoch_ack";
pub const FRAME_TYPE_SESSION_REVOKE: &str = "session_revoke";
pub const FRAME_TYPE_SESSION_REVOKE_ACK: &str = "session_revoke_ack";
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
pub const ERR_RUNTIME_CAPACITY_EXCEEDED: &str = "RUNTIME_CAPACITY_EXCEEDED";
pub const ERR_RUNTIME_INVOCATION_CANCELED: &str = "RUNTIME_INVOCATION_CANCELED";
pub const ERR_SESSION_REVOKED: &str = "PLUGIN_SESSION_REVOKED";
pub const ERR_SESSION_REVOKE_SEQUENCE_STALE: &str = "SESSION_REVOKE_SEQUENCE_STALE";
pub const ERR_SESSION_REVOKE_DRAIN_TIMEOUT: &str = "SESSION_REVOKE_DRAIN_TIMEOUT";
pub const ERR_UNSUPPORTED_FRAME: &str = "UNSUPPORTED_FRAME";
pub const ERROR_ORIGIN_RUNTIME: &str = "runtime";
pub const ERROR_ORIGIN_HOSTCALL: &str = "hostcall";
pub const ERROR_ORIGIN_PLUGIN: &str = "plugin";

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpcError {
    DecodeFailed { context: &'static str },
    EncodeFailed { context: &'static str },
    MissingField { field: &'static str },
    InvalidField { field: &'static str },
    ProtocolViolation { message: &'static str },
    CapacityOverflow { capacity: &'static str },
    RemoteFailure { code: String },
    InvalidResponseResultJson,
    EmptyResponseErrorCode,
    EmptyResponseErrorMessage,
}

pub type IpcResult<T> = Result<T, IpcError>;

impl std::fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeFailed { context } => write!(formatter, "failed to decode {context}"),
            Self::EncodeFailed { context } => write!(formatter, "failed to encode {context}"),
            Self::MissingField { field } => write!(formatter, "missing {field}"),
            Self::InvalidField { field } => write!(formatter, "invalid {field}"),
            Self::ProtocolViolation { message } => formatter.write_str(message),
            Self::CapacityOverflow { capacity } => write!(formatter, "{capacity} overflows usize"),
            Self::RemoteFailure { code } => {
                write!(formatter, "hostcall response failed with code {code}")
            }
            Self::InvalidResponseResultJson => {
                formatter.write_str("runtime response result must be valid JSON")
            }
            Self::EmptyResponseErrorCode => {
                formatter.write_str("runtime response code is required")
            }
            Self::EmptyResponseErrorMessage => {
                formatter.write_str("runtime response message is required")
            }
        }
    }
}

impl std::error::Error for IpcError {}

fn decode_failed(context: &'static str) -> IpcError {
    IpcError::DecodeFailed { context }
}

fn encode_failed(context: &'static str) -> IpcError {
    IpcError::EncodeFailed { context }
}

fn missing_field(field: &'static str) -> IpcError {
    IpcError::MissingField { field }
}

fn invalid_field(field: &'static str) -> IpcError {
    IpcError::InvalidField { field }
}

fn protocol_violation(message: &'static str) -> IpcError {
    IpcError::ProtocolViolation { message }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Hello,
    HelloAck,
    Heartbeat,
    InvokeWorker,
    InvokeWorkerResult,
    CompileFlightRegister,
    CompileFlightComplete,
    OpenHandle,
    ValidateHandleGrant,
    StorageFile,
    StorageKV,
    StorageSQLite,
    NetworkGrant,
    NetworkExecute,
    RevokeEpoch,
    RevokeEpochAck,
    SessionRevoke,
    SessionRevokeAck,
    Diagnostic,
}

#[cfg(test)]
mod property_gates {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ipc_frame_parser_is_total(input in any::<String>()) {
            let parsed = std::panic::catch_unwind(|| {
                let _ = decode_runtime_input_frame(&input);
                let _ = parse_frame_identity(&input);
                let _ = parse_hello_frame(&input);
                let _ = validate_hello_frame(&input);
                let _ = parse_worker_invocation(&input);
                let _ = parse_worker_invocation_context(&input);
                let _ = parse_worker_invocation_identity(&input);
                let _ = parse_worker_lease_replay_key(&input);
                let _ = parse_worker_response_v2(&input);
                let _ = parse_heartbeat_request(&input);
                let _ = parse_revoke_epoch_request(&input);
                let _ = parse_session_revoke_request(&input);
                let _ = parse_cancel_invoke(&input);
                let _ = parse_runtime_lease_public_keys(&input);
                let _ = bind_parent_request_id(&input, "parent_request");
            });
            prop_assert!(parsed.is_ok());
        }

        #[test]
        fn response_frame_builders_are_total(
            frame_type in any::<String>(),
            request_id in any::<String>(),
            runtime_generation_id in any::<String>(),
            result_json in any::<String>(),
            code in any::<String>(),
            message in any::<String>(),
        ) {
            let success = std::panic::catch_unwind(|| {
                success_response_frame(
                    &frame_type,
                    &request_id,
                    &runtime_generation_id,
                    &result_json,
                )
            });
            prop_assert!(success.is_ok());
            let error = std::panic::catch_unwind(|| ResponseError::runtime(&code, &message));
            prop_assert!(error.is_ok());
            if let Ok(Ok(error)) = error {
                let frame = std::panic::catch_unwind(|| {
                    error_response_frame(
                        &frame_type,
                        &request_id,
                        &runtime_generation_id,
                        error,
                    )
                });
                prop_assert!(frame.is_ok());
            }
        }

        #[test]
        fn session_revoke_ack_builder_is_total(
            request_id in any::<String>(),
            runtime_generation_id in any::<String>(),
            sequence in any::<u64>(),
            queued_invocations in any::<u64>(),
            running_invocations in any::<u64>(),
            storage_hostcalls in any::<u64>(),
            active_network_requests in any::<u64>(),
            sockets in any::<u64>(),
            network_streams in any::<u64>(),
        ) {
            let built = std::panic::catch_unwind(|| {
                session_revoke_ack_frame(
                    &request_id,
                    &runtime_generation_id,
                    sequence,
                    SessionRevokeState::Complete,
                    SessionRevokeAckCounts {
                        queued_invocations,
                        running_invocations,
                        storage_hostcalls,
                        active_network_requests,
                        sockets,
                        network_streams,
                    },
                )
            });
            prop_assert!(built.is_ok());
        }

        #[test]
        fn network_frame_builders_are_total(
            request_id in any::<String>(),
            runtime_generation_id in any::<String>(),
            scope_kind in any::<String>(),
            owner_env_hash in any::<String>(),
            owner_user_hash in any::<String>(),
            query_json in any::<String>(),
            headers_json in any::<String>(),
        ) {
            let resource_scope = NetworkResourceScope {
                kind: scope_kind,
                owner_env_hash,
                owner_user_hash,
            };
            let grant = NetworkGrantRequest {
                plugin_instance_id: "plugini_1".to_string(),
                active_fingerprint: "sha256:active".to_string(),
                resource_scope: resource_scope.clone(),
                runtime_instance_id: "runtime_1".to_string(),
                runtime_generation_id: runtime_generation_id.clone(),
                runtime_shard_id: "runtime_shard_1".to_string(),
                policy_revision: 1,
                management_revision: 1,
                revoke_epoch: 1,
                connector_id: "api".to_string(),
                transport: "http".to_string(),
                destination: "https://api.example.com".to_string(),
                ttl_ms: 1,
            };
            let grant_result = std::panic::catch_unwind(|| {
                network_grant_frame(&request_id, &runtime_generation_id, &grant)
            });
            prop_assert!(grant_result.is_ok());

            let execute = NetworkExecuteRequest {
                plugin_id: "com.example.worker".to_string(),
                plugin_instance_id: "plugini_1".to_string(),
                active_fingerprint: "sha256:active".to_string(),
                resource_scope,
                runtime_instance_id: "runtime_1".to_string(),
                runtime_generation_id: runtime_generation_id.clone(),
                runtime_shard_id: "runtime_shard_1".to_string(),
                policy_revision: 1,
                management_revision: 1,
                revoke_epoch: 1,
                connector_id: "api".to_string(),
                transport: "http".to_string(),
                destination: "https://api.example.com".to_string(),
                ttl_ms: 1,
                operation: "http".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                query_json,
                headers_json,
                message_type: String::new(),
                body_base64: String::new(),
                payload_base64: String::new(),
                max_request_bytes: 1,
                max_response_bytes: 1,
                max_chunk_bytes: 1,
                max_buffered_bytes: 1,
                timeout_ms: 1,
                stream_id: String::new(),
                stream_method: String::new(),
                stream_effect: String::new(),
                stream_execution: String::new(),
                surface_instance_id: String::new(),
                owner_session_hash: String::new(),
                owner_user_hash: String::new(),
                owner_env_hash: String::new(),
                session_channel_id_hash: String::new(),
                bridge_channel_id: String::new(),
                content_type: String::new(),
            };
            let execute_result = std::panic::catch_unwind(|| {
                network_execute_frame(&request_id, &runtime_generation_id, &execute)
            });
            prop_assert!(execute_result.is_ok());
        }

        #[test]
        fn runtime_limits_keep_derived_capacities_bounded(
            worker_count in MIN_RUNTIME_WORKER_COUNT..=MAX_RUNTIME_WORKER_COUNT,
            queue_capacity in MIN_RUNTIME_QUEUE_CAPACITY..=MAX_RUNTIME_QUEUE_CAPACITY,
            per_plugin_concurrency in MIN_RUNTIME_PER_PLUGIN_CONCURRENCY..=MAX_RUNTIME_PER_PLUGIN_CONCURRENCY,
            module_cache_entries in MIN_RUNTIME_MODULE_CACHE_ENTRIES..=MAX_RUNTIME_MODULE_CACHE_ENTRIES,
            module_cache_source_bytes in MIN_RUNTIME_MODULE_CACHE_SOURCE_BYTES..=MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES,
        ) {
            let limits = RuntimeLimits {
                worker_count,
                queue_capacity,
                per_plugin_concurrency,
                module_cache_entries,
                module_cache_source_bytes,
            };
            match limits.validate() {
                Ok(validated) => {
                    prop_assert!(per_plugin_concurrency <= worker_count);
                    prop_assert_eq!(validated.hostcall_active_route_capacity(), worker_count);
                    prop_assert_eq!(
                        validated.hostcall_canceled_route_capacity().unwrap(),
                        worker_count + queue_capacity,
                    );
                    prop_assert_eq!(validated.compile_flight_route_capacity(), worker_count);
                }
                Err(_) => prop_assert!(per_plugin_concurrency > worker_count),
            }
        }

        #[test]
        fn lease_signature_payload_is_stable_for_valid_fields(
            lease_id in "[a-z][a-z0-9_]{0,24}",
            token_id in "[a-z][a-z0-9_]{0,24}",
            nonce in prop::collection::vec(any::<u8>(), 16..=32),
            method in "worker\\.[a-z][a-z0-9_]{0,16}",
        ) {
            let nonce = nonce.into_iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let fixture: serde_json::Value = serde_json::from_str(include_str!(
                "../testdata/runtime-lease-signature-v1.json"
            ))
            .unwrap();
            let mut lease = fixture.get("lease").cloned().unwrap();
            lease["lease_id"] = serde_json::Value::String(lease_id);
            lease["token_id"] = serde_json::Value::String(token_id);
            lease["lease_nonce"] = serde_json::Value::String(nonce);
            lease["method"] = serde_json::Value::String(method.clone());
            let typed: WorkerLeasePayload = serde_json::from_value(lease).unwrap();
            let first = runtime_lease_signature_payload_json(&typed, method.as_str()).unwrap();
            let second = runtime_lease_signature_payload_json(&typed, method.as_str()).unwrap();
            prop_assert_eq!(&first, &second);
            let parsed: serde_json::Value = serde_json::from_str(&first).unwrap();
            prop_assert!(parsed.is_object());
            prop_assert!(parsed.get("signature").is_none());
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIPCFrame {
    ipc_version: String,
    frame_type: String,
    request_id: String,
    parent_request_id: Option<String>,
    runtime_generation_id: Option<String>,
    payload: Box<serde_json::value::RawValue>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLimits {
    pub worker_count: usize,
    pub queue_capacity: usize,
    pub per_plugin_concurrency: usize,
    pub module_cache_entries: usize,
    pub module_cache_source_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessContainmentEvidence {
    pub schema_version: String,
    pub profile: String,
    pub seccomp_policy_sha256: String,
    pub no_new_privs: bool,
    pub seccomp_tsync: bool,
    pub process_creation_denied: bool,
    pub reexec_denied: bool,
    pub active: bool,
}

impl ProcessContainmentEvidence {
    pub fn validate(&self) -> IpcResult<()> {
        if self.schema_version != "redevplugin.process_containment.v1"
            || self.profile != "linux-runtime-v1"
            || self.seccomp_policy_sha256.len() != 64
            || !self
                .seccomp_policy_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !self.no_new_privs
            || !self.seccomp_tsync
            || !self.process_creation_denied
            || !self.reexec_denied
            || !self.active
        {
            return Err(invalid_field("process_containment"));
        }
        Ok(())
    }
}

impl RuntimeLimits {
    pub fn validate(self) -> IpcResult<Self> {
        if self.worker_count < MIN_RUNTIME_WORKER_COUNT
            || self.queue_capacity < MIN_RUNTIME_QUEUE_CAPACITY
            || self.per_plugin_concurrency < MIN_RUNTIME_PER_PLUGIN_CONCURRENCY
            || self.module_cache_entries < MIN_RUNTIME_MODULE_CACHE_ENTRIES
            || self.module_cache_source_bytes < MIN_RUNTIME_MODULE_CACHE_SOURCE_BYTES
        {
            return Err(protocol_violation(
                "runtime limits are below platform minimums",
            ));
        }
        if self.worker_count > MAX_RUNTIME_WORKER_COUNT
            || self.queue_capacity > MAX_RUNTIME_QUEUE_CAPACITY
            || self.per_plugin_concurrency > MAX_RUNTIME_PER_PLUGIN_CONCURRENCY
            || self.module_cache_entries > MAX_RUNTIME_MODULE_CACHE_ENTRIES
            || self.module_cache_source_bytes > MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES
        {
            return Err(protocol_violation(
                "runtime limits exceed platform maximums",
            ));
        }
        if self.per_plugin_concurrency > self.worker_count {
            return Err(protocol_violation(
                "runtime per_plugin_concurrency exceeds worker_count",
            ));
        }
        self.hostcall_canceled_route_capacity()?;
        Ok(self)
    }

    pub fn hostcall_active_route_capacity(self) -> usize {
        self.worker_count
    }

    pub fn hostcall_canceled_route_capacity(self) -> IpcResult<usize> {
        self.worker_count
            .checked_add(self.queue_capacity)
            .ok_or(IpcError::CapacityOverflow {
                capacity: "runtime hostcall canceled route capacity",
            })
    }

    pub fn compile_flight_route_capacity(self) -> usize {
        self.worker_count
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloPayload {
    target: String,
    host_process_id: u64,
    host_ipc_version: String,
    host_wasm_abi: String,
    contract_set_sha256: String,
    started_unix_nano: u64,
    channel_nonce: String,
    runtime_lease_public_keys: Vec<RuntimeLeasePublicKeyPayload>,
    limits: RuntimeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTarget {
    LinuxAmd64,
    LinuxArm64,
}

impl RuntimeTarget {
    pub fn parse(value: &str) -> IpcResult<Self> {
        match value {
            "linux/amd64" => Ok(Self::LinuxAmd64),
            "linux/arm64" => Ok(Self::LinuxArm64),
            _ => Err(protocol_violation("unsupported runtime target")),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::LinuxAmd64 => "linux/amd64",
            Self::LinuxArm64 => "linux/arm64",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLeasePublicKeyPayload {
    algorithm: String,
    key_id: String,
    public_key_base64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerFramePayload {
    lease: WorkerLeasePayload,
    method: String,
    invocation: WorkerInvocationPayload,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WorkerLeasePayload {
    lease_id: Option<String>,
    token_id: Option<String>,
    lease_nonce: Option<String>,
    plugin_id: Option<String>,
    plugin_version: Option<String>,
    active_fingerprint: Option<String>,
    surface_instance_id: Option<String>,
    owner_session_hash: Option<String>,
    owner_user_hash: Option<String>,
    owner_env_hash: Option<String>,
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
    issued_at_unix_ms: Option<i64>,
    expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WorkerLeaseLimitsPayload {
    timeout_ms: Option<i64>,
    memory_bytes: Option<u64>,
    max_payload_bytes: Option<i64>,
    max_stream_bytes_per_sec: Option<i64>,
}

#[derive(Clone, Deserialize, Serialize)]
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
    effect: Option<String>,
    execution: Option<String>,
    surface_instance_id: Option<String>,
    owner_session_hash: Option<String>,
    owner_user_hash: Option<String>,
    owner_env_hash: Option<String>,
    session_channel_id_hash: Option<String>,
    bridge_channel_id: Option<String>,
    operation_id: Option<String>,
    stream_id: Option<String>,
    audit_correlation_id: Option<String>,
    policy_revision: Option<u64>,
    management_revision: Option<u64>,
    revoke_epoch: Option<u64>,
    params_sha256: Option<String>,
    params: Option<serde_json::Map<String, serde_json::Value>>,
    storage_handle_grants: Option<HashMap<String, String>>,
    broker_access: Option<WorkerBrokerAccessPayload>,
    broker_access_sha256: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerBrokerAccessPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    storage: Vec<WorkerStorageBrokerAccessPayload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    network: Vec<WorkerNetworkBrokerAccessPayload>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerStorageBrokerAccessPayload {
    store_id: String,
    scope: String,
    operations: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerNetworkBrokerAccessPayload {
    connector_id: String,
    transport: String,
    scope: String,
    operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    http_methods: Vec<String>,
}

struct ClosedWorkerFrame {
    request_id: String,
    runtime_generation_id: String,
    method: String,
    lease: WorkerLeasePayload,
    invocation: WorkerInvocationPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameIdentity {
    pub frame_type: String,
    pub request_id: String,
    pub parent_request_id: Option<String>,
    pub runtime_generation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloFrame {
    pub request_id: String,
    pub runtime_generation_id: String,
    pub target: RuntimeTarget,
    pub contract_set_sha256: String,
    pub channel_nonce: String,
    pub runtime_lease_public_keys: Vec<RuntimeLeasePublicKey>,
    pub limits: RuntimeLimits,
}

pub struct ParsedWorkerInvocation {
    request_id: String,
    runtime_generation_id: String,
    method: String,
    lease: WorkerLeasePayload,
    invocation: WorkerInvocationPayload,
    params_json: Option<String>,
    broker_access_json: Option<String>,
    context: OnceLock<IpcResult<WorkerInvocationContext>>,
    identity: OnceLock<IpcResult<WorkerInvocationIdentity>>,
    target_hash: OnceLock<IpcResult<String>>,
}

pub struct WorkerInvocationInput {
    pub identity: FrameIdentity,
    pub invocation: IpcResult<ParsedWorkerInvocation>,
}

pub struct CancelInvocationInput {
    pub identity: FrameIdentity,
    pub invocation_request_id: String,
}

pub struct RuntimeHostcallResponseInput {
    pub identity: FrameIdentity,
    pub raw_frame: String,
}

pub enum RuntimeInputFrame {
    InvokeWorker(Box<WorkerInvocationInput>),
    CancelInvoke(CancelInvocationInput),
    HostcallResponse(RuntimeHostcallResponseInput),
    Unsupported(FrameIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInvocationContext {
    pub plugin_id: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub method: String,
    pub effect: String,
    pub execution: String,
    pub surface_instance_id: String,
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub owner_env_hash: String,
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
    pub resource_scope: NetworkResourceScope,
    pub plugin_instance_id: String,
    pub revoke_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionScope {
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub owner_env_hash: String,
    pub session_channel_id_hash: String,
}

impl SessionScope {
    pub fn new(
        owner_session_hash: impl Into<String>,
        owner_user_hash: impl Into<String>,
        owner_env_hash: impl Into<String>,
        session_channel_id_hash: impl Into<String>,
    ) -> IpcResult<Self> {
        let scope = Self {
            owner_session_hash: owner_session_hash.into(),
            owner_user_hash: owner_user_hash.into(),
            owner_env_hash: owner_env_hash.into(),
            session_channel_id_hash: session_channel_id_hash.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> IpcResult<()> {
        for (value, field) in [
            (&self.owner_session_hash, "owner_session_hash"),
            (&self.owner_user_hash, "owner_user_hash"),
            (&self.owner_env_hash, "owner_env_hash"),
            (&self.session_channel_id_hash, "session_channel_id_hash"),
        ] {
            if value.is_empty() || value.trim() != value {
                return Err(invalid_field(field));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevokeRequest {
    pub request_id: String,
    pub runtime_generation_id: String,
    pub session_revoke_sequence: u64,
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub owner_env_hash: String,
    pub session_channel_id_hash: String,
}

impl SessionRevokeRequest {
    pub fn session_scope(&self) -> SessionScope {
        SessionScope {
            owner_session_hash: self.owner_session_hash.clone(),
            owner_user_hash: self.owner_user_hash.clone(),
            owner_env_hash: self.owner_env_hash.clone(),
            session_channel_id_hash: self.session_channel_id_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRevokeState {
    Complete,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeAckCounts {
    pub queued_invocations: u64,
    pub running_invocations: u64,
    pub storage_hostcalls: u64,
    pub active_network_requests: u64,
    pub sockets: u64,
    pub network_streams: u64,
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
    resource_scope: NetworkResourceScope,
    plugin_instance_id: String,
    revoke_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRevokeRequestPayload {
    session_revoke_sequence: u64,
    owner_session_hash: String,
    owner_user_hash: String,
    owner_env_hash: String,
    session_channel_id_hash: String,
}

fn parse_raw_frame(input: &str) -> IpcResult<RawIPCFrame> {
    serde_json::from_str(input).map_err(|_| decode_failed("IPC frame"))
}

fn parse_hello_payload(frame: &RawIPCFrame) -> IpcResult<HelloPayload> {
    serde_json::from_str(frame.payload.get()).map_err(|_| decode_failed("hello payload"))
}

fn parse_closed_worker_frame(
    identity: &FrameIdentity,
    payload: &serde_json::value::RawValue,
) -> IpcResult<ClosedWorkerFrame> {
    if identity.parent_request_id.is_some() {
        return Err(protocol_violation(
            "invoke_worker must not have parent_request_id",
        ));
    }
    let payload: WorkerFramePayload =
        serde_json::from_str(payload.get()).map_err(|_| decode_failed("worker frame payload"))?;
    if payload.method.trim().is_empty() {
        return Err(invalid_field("worker frame method"));
    }
    if payload
        .invocation
        .method
        .as_deref()
        .is_some_and(|method| method.trim() != payload.method.trim())
    {
        return Err(protocol_violation(
            "worker invocation method does not match the frame envelope",
        ));
    }
    Ok(ClosedWorkerFrame {
        request_id: identity.request_id.clone(),
        runtime_generation_id: identity.runtime_generation_id.clone(),
        method: payload.method,
        lease: payload.lease,
        invocation: payload.invocation,
    })
}

fn parsed_worker_invocation(
    identity: &FrameIdentity,
    payload: &serde_json::value::RawValue,
) -> IpcResult<ParsedWorkerInvocation> {
    let parsed = parse_closed_worker_frame(identity, payload)?;
    let params_json = parsed
        .invocation
        .params
        .as_ref()
        .map(encode_worker_canonical_json)
        .transpose()
        .map_err(|_| encode_failed("parsed worker params"))?;
    let broker_access_json = parsed
        .invocation
        .broker_access
        .as_ref()
        .map(encode_worker_canonical_json)
        .transpose()
        .map_err(|_| encode_failed("parsed worker broker access"))?;
    Ok(ParsedWorkerInvocation {
        request_id: parsed.request_id,
        runtime_generation_id: parsed.runtime_generation_id,
        method: parsed.method,
        lease: parsed.lease,
        invocation: parsed.invocation,
        params_json,
        broker_access_json,
        context: OnceLock::new(),
        identity: OnceLock::new(),
        target_hash: OnceLock::new(),
    })
}

pub fn parse_worker_invocation(input: &str) -> IpcResult<ParsedWorkerInvocation> {
    match decode_runtime_input_frame(input)? {
        RuntimeInputFrame::InvokeWorker(worker) => worker.invocation,
        _ => Err(protocol_violation("expected invoke_worker frame")),
    }
}

fn encode_worker_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_string(value)?;
    if !encoded.contains(['\u{2028}', '\u{2029}']) {
        return Ok(encoded);
    }
    let mut canonical = String::with_capacity(encoded.len());
    for character in encoded.chars() {
        match character {
            '\u{2028}' => canonical.push_str("\\u2028"),
            '\u{2029}' => canonical.push_str("\\u2029"),
            _ => canonical.push(character),
        }
    }
    Ok(canonical)
}

fn required_string(value: &Option<String>, field: &'static str) -> IpcResult<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| missing_field(field))
}

impl ParsedWorkerInvocation {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn runtime_generation_id(&self) -> &str {
        &self.runtime_generation_id
    }

    pub fn plugin_instance_id(&self) -> IpcResult<&str> {
        self.invocation
            .plugin_instance_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| missing_field("plugin_instance_id"))
    }

    /// Returns the exact session scope when the invocation is session-bound.
    /// Background invocations may omit both session-specific hashes. A partial
    /// session identity is rejected instead of being treated as unscoped.
    pub fn session_scope(&self) -> IpcResult<Option<SessionScope>> {
        let invocation = &self.invocation;
        let session_present = invocation
            .owner_session_hash
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || invocation
                .session_channel_id_hash
                .as_deref()
                .is_some_and(|value| !value.is_empty());
        if !session_present {
            return Ok(None);
        }
        SessionScope::new(
            required_string(&invocation.owner_session_hash, "owner_session_hash")?,
            required_string(&invocation.owner_user_hash, "owner_user_hash")?,
            required_string(&invocation.owner_env_hash, "owner_env_hash")?,
            required_string(
                &invocation.session_channel_id_hash,
                "session_channel_id_hash",
            )?,
        )
        .map(Some)
    }

    pub fn context(&self) -> IpcResult<WorkerInvocationContext> {
        self.context.get_or_init(|| self.build_context()).clone()
    }

    fn build_context(&self) -> IpcResult<WorkerInvocationContext> {
        let invocation = &self.invocation;
        Ok(WorkerInvocationContext {
            plugin_id: required_string(&invocation.plugin_id, "plugin_id")?,
            plugin_instance_id: required_string(
                &invocation.plugin_instance_id,
                "plugin_instance_id",
            )?,
            active_fingerprint: required_string(
                &invocation.active_fingerprint,
                "active_fingerprint",
            )?,
            runtime_instance_id: required_string(
                &invocation.runtime_instance_id,
                "runtime_instance_id",
            )?,
            runtime_generation_id: required_string(
                &invocation.runtime_generation_id,
                "runtime_generation_id",
            )?,
            runtime_shard_id: required_string(&self.lease.runtime_shard_id, "runtime_shard_id")?,
            method: required_string(&invocation.method, "method")?,
            effect: invocation.effect.clone().unwrap_or_default(),
            execution: invocation.execution.clone().unwrap_or_default(),
            surface_instance_id: invocation.surface_instance_id.clone().unwrap_or_default(),
            owner_session_hash: invocation.owner_session_hash.clone().unwrap_or_default(),
            owner_user_hash: invocation.owner_user_hash.clone().unwrap_or_default(),
            owner_env_hash: invocation.owner_env_hash.clone().unwrap_or_default(),
            session_channel_id_hash: invocation
                .session_channel_id_hash
                .clone()
                .unwrap_or_default(),
            bridge_channel_id: invocation.bridge_channel_id.clone().unwrap_or_default(),
            operation_id: invocation.operation_id.clone().unwrap_or_default(),
            stream_id: invocation.stream_id.clone().unwrap_or_default(),
            policy_revision: required_safe_u64(self.lease.policy_revision, "policy_revision")?,
            management_revision: required_safe_u64(
                self.lease.management_revision,
                "management_revision",
            )?,
            revoke_epoch: required_positive_u64(self.lease.revoke_epoch, "revoke_epoch")?,
            storage_handle_grants: invocation.storage_handle_grants.clone().unwrap_or_default(),
            broker_access_json: self
                .broker_access_json
                .clone()
                .unwrap_or_else(|| "{}".to_string()),
        })
    }

    pub fn identity(&self) -> IpcResult<WorkerInvocationIdentity> {
        self.identity.get_or_init(|| self.build_identity()).clone()
    }

    pub fn validate_worker_contract(&self) -> IpcResult<()> {
        if self.invocation.abi.as_deref() != Some(WASM_ABI_VERSION) {
            return Err(protocol_violation("worker invocation ABI is unsupported"));
        }
        if self.invocation.worker_mode.as_deref() != Some("job") {
            return Err(protocol_violation("worker invocation mode is unsupported"));
        }
        required_string(&self.invocation.worker_scope, "worker_scope")?;
        Ok(())
    }

    fn build_identity(&self) -> IpcResult<WorkerInvocationIdentity> {
        let invocation = &self.invocation;
        let package_hash = invocation
            .package_hash
            .clone()
            .ok_or_else(|| missing_field("package_hash"))?;
        if !is_sha256_ref(&package_hash) {
            return Err(invalid_field("package_hash"));
        }
        let artifact = invocation
            .artifact
            .clone()
            .ok_or_else(|| missing_field("artifact"))?;
        if !is_worker_artifact_path(&artifact) {
            return Err(invalid_field("artifact"));
        }
        let artifact_sha256 = invocation
            .artifact_sha256
            .clone()
            .ok_or_else(|| missing_field("artifact_sha256"))?;
        if !is_sha256_ref(&artifact_sha256) {
            return Err(invalid_field("artifact_sha256"));
        }
        let worker_id = invocation
            .worker_id
            .clone()
            .ok_or_else(|| missing_field("worker_id"))?;
        if worker_id.trim().is_empty() {
            return Err(invalid_field("worker_id"));
        }
        let method = invocation
            .method
            .clone()
            .ok_or_else(|| missing_field("method"))?;
        if method.trim().is_empty() {
            return Err(invalid_field("method"));
        }
        Ok(WorkerInvocationIdentity {
            package_hash,
            artifact,
            artifact_sha256,
            worker_id,
            method,
        })
    }

    pub fn worker_request_json_v2(&self) -> IpcResult<String> {
        let method = required_string(&self.invocation.method, "worker invocation method")?;
        let params = self
            .params_json
            .as_ref()
            .ok_or_else(|| missing_field("worker invocation params"))?;
        Ok(format!(
            "{{\"schema_version\":\"redevplugin.worker_request.v2\",\"method\":\"{}\",\"params\":{}}}",
            escape_json_string(&method),
            params
        ))
    }

    pub fn memory_limit_bytes(&self) -> IpcResult<usize> {
        let memory_bytes = self
            .lease
            .limits
            .as_ref()
            .and_then(|limits| limits.memory_bytes)
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid_field("runtime lease memory_bytes limit"))?;
        if memory_bytes > MAX_RUNTIME_LEASE_MEMORY_BYTES {
            return Err(protocol_violation(
                "runtime lease memory_bytes limit exceeds platform maximum",
            ));
        }
        usize::try_from(memory_bytes)
            .map_err(|_| protocol_violation("runtime lease memory_bytes limit exceeds runtime"))
    }

    pub fn replay_key(&self) -> IpcResult<WorkerLeaseReplayKey> {
        let lease_id = self
            .lease
            .lease_id
            .clone()
            .ok_or_else(|| missing_field("lease_id"))?;
        if lease_id.trim().is_empty() {
            return Err(invalid_field("lease_id"));
        }
        let lease_nonce = self
            .lease
            .lease_nonce
            .clone()
            .ok_or_else(|| missing_field("lease_nonce"))?;
        if lease_nonce.trim().is_empty() {
            return Err(invalid_field("lease_nonce"));
        }
        let expires_at_unix_ms = self
            .lease
            .expires_at_unix_ms
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid_field("expires_at_unix_ms"))?;
        Ok(WorkerLeaseReplayKey {
            lease_id,
            lease_nonce,
            expires_at_unix_ms,
        })
    }

    pub fn storage_handle_grant(&self, store_id: &str) -> IpcResult<String> {
        let grants = self
            .invocation
            .storage_handle_grants
            .as_ref()
            .ok_or_else(|| missing_field("worker invocation storage_handle_grants"))?;
        grants
            .get(store_id)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| invalid_field("worker invocation storage grant"))
    }

    pub fn validate_storage_broker_access(&self, store_id: &str, operation: &str) -> IpcResult<()> {
        let effect = required_string(&self.invocation.effect, "effect")?;
        if effect == "read" && !matches!(operation, "read" | "list" | "get" | "query") {
            return Err(protocol_violation(
                "worker method with read effect cannot perform the storage mutation",
            ));
        }
        if !self
            .invocation
            .broker_access
            .as_ref()
            .is_some_and(|access| {
                access.storage.iter().any(|entry| {
                    entry.store_id == store_id
                        && entry.operations.iter().any(|value| value == operation)
                })
            })
        {
            return Err(protocol_violation(
                "worker method is not allowed to perform the storage operation",
            ));
        }
        Ok(())
    }

    pub fn storage_broker_scope(&self, store_id: &str) -> IpcResult<String> {
        let scope = self
            .invocation
            .broker_access
            .as_ref()
            .and_then(|access| {
                access
                    .storage
                    .iter()
                    .find(|entry| entry.store_id == store_id)
            })
            .map(|entry| entry.scope.as_str())
            .filter(|scope| matches!(*scope, "user" | "environment"))
            .ok_or_else(|| invalid_field("worker invocation storage scope"))?;
        Ok(scope.to_string())
    }

    pub fn validate_network_broker_access(
        &self,
        connector_id: &str,
        transport: &str,
        operation: &str,
        http_method: &str,
    ) -> IpcResult<()> {
        let allowed = self
            .invocation
            .broker_access
            .as_ref()
            .is_some_and(|access| {
                access.network.iter().any(|entry| {
                    entry.connector_id == connector_id
                        && entry.transport == transport
                        && entry.operations.iter().any(|value| value == operation)
                        && (transport != "http"
                            || entry.http_methods.iter().any(|value| value == http_method))
                })
            });
        if !allowed {
            return Err(protocol_violation(
                "worker method is not allowed to perform the network operation",
            ));
        }
        Ok(())
    }

    pub fn network_broker_scope(&self, connector_id: &str, transport: &str) -> IpcResult<String> {
        let scope = self
            .invocation
            .broker_access
            .as_ref()
            .and_then(|access| {
                access.network.iter().find(|entry| {
                    entry.connector_id == connector_id && entry.transport == transport
                })
            })
            .map(|entry| entry.scope.trim())
            .filter(|scope| matches!(*scope, "user" | "environment"))
            .ok_or_else(|| invalid_field("worker invocation network scope"))?;
        Ok(scope.to_string())
    }
}

pub fn parse_worker_invocation_context(input: &str) -> IpcResult<WorkerInvocationContext> {
    parse_worker_invocation(input)?.context()
}

pub fn parse_heartbeat_request(input: &str) -> IpcResult<HeartbeatRequest> {
    let frame = parse_raw_frame(input)?;
    if frame.frame_type != FRAME_TYPE_HEARTBEAT {
        return Err(protocol_violation("expected heartbeat frame"));
    }
    let payload: HeartbeatRequestPayload = serde_json::from_str(frame.payload.get())
        .map_err(|_| decode_failed("heartbeat payload"))?;
    Ok(HeartbeatRequest {
        sent_unix_nano: payload.sent_unix_nano,
        max_staleness_ms: payload.max_staleness_ms,
    })
}

pub fn parse_revoke_epoch_request(input: &str) -> IpcResult<RevokeEpochRequest> {
    let frame = parse_raw_frame(input)?;
    if frame.frame_type != FRAME_TYPE_REVOKE_EPOCH {
        return Err(protocol_violation("expected revoke_epoch frame"));
    }
    let payload: RevokeEpochRequestPayload = serde_json::from_str(frame.payload.get())
        .map_err(|_| decode_failed("revoke_epoch payload"))?;
    if payload.plugin_instance_id.trim().is_empty() {
        return Err(invalid_field("plugin_instance_id"));
    }
    if !payload.resource_scope.valid() || payload.resource_scope.kind != "environment" {
        return Err(invalid_field("revoke resource_scope"));
    }
    validate_revoke_epoch(payload.revoke_epoch)?;
    Ok(RevokeEpochRequest {
        resource_scope: payload.resource_scope,
        plugin_instance_id: payload.plugin_instance_id,
        revoke_epoch: payload.revoke_epoch,
    })
}

pub fn parse_session_revoke_request(input: &str) -> IpcResult<SessionRevokeRequest> {
    let frame = parse_raw_frame(input)?;
    let identity = validated_frame_identity(&frame)?;
    if identity.frame_type != FRAME_TYPE_SESSION_REVOKE {
        return Err(protocol_violation("expected session_revoke frame"));
    }
    if identity.parent_request_id.is_some() {
        return Err(protocol_violation(
            "session_revoke must not have parent_request_id",
        ));
    }
    let payload: SessionRevokeRequestPayload = serde_json::from_str(frame.payload.get())
        .map_err(|_| decode_failed("session_revoke payload"))?;
    if payload.session_revoke_sequence == 0
        || payload.session_revoke_sequence > MAX_JSON_SAFE_INTEGER
    {
        return Err(invalid_field("session_revoke_sequence"));
    }
    let scope = SessionScope::new(
        payload.owner_session_hash,
        payload.owner_user_hash,
        payload.owner_env_hash,
        payload.session_channel_id_hash,
    )?;
    Ok(SessionRevokeRequest {
        request_id: identity.request_id,
        runtime_generation_id: identity.runtime_generation_id,
        session_revoke_sequence: payload.session_revoke_sequence,
        owner_session_hash: scope.owner_session_hash,
        owner_user_hash: scope.owner_user_hash,
        owner_env_hash: scope.owner_env_hash,
        session_channel_id_hash: scope.session_channel_id_hash,
    })
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

pub fn bind_parent_request_id(frame: &str, parent_request_id: &str) -> IpcResult<String> {
    if parent_request_id.trim().is_empty() {
        return Err(invalid_field("parent_request_id"));
    }
    let mut value: serde_json::Value =
        serde_json::from_str(frame).map_err(|_| decode_failed("outbound IPC frame"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| protocol_violation("outbound IPC frame must be an object"))?;
    object.insert(
        "parent_request_id".to_string(),
        serde_json::Value::String(parent_request_id.to_string()),
    );
    serde_json::to_string(&value).map_err(|_| encode_failed("outbound IPC frame"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLeasePublicKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

fn parse_runtime_lease_public_key_payloads(
    keys: Vec<RuntimeLeasePublicKeyPayload>,
) -> IpcResult<Vec<RuntimeLeasePublicKey>> {
    let mut seen = HashSet::new();
    let mut parsed = Vec::with_capacity(keys.len());
    if keys.is_empty() {
        return Err(invalid_field("runtime_lease_public_keys"));
    }
    for key in keys {
        let key_id = key.key_id.trim().to_string();
        if key_id.is_empty() {
            return Err(invalid_field("runtime lease public key key_id"));
        }
        if !seen.insert(key_id.clone()) {
            return Err(protocol_violation(
                "runtime lease public key key_id is duplicated",
            ));
        }
        if key.algorithm != RUNTIME_LEASE_SIGNATURE_ALGORITHM {
            return Err(protocol_violation(
                "runtime lease public key algorithm is unsupported",
            ));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key.public_key_base64.as_bytes())
            .map_err(|_| invalid_field("runtime lease public key base64"))?;
        let public_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| invalid_field("runtime lease public key length"))?;
        parsed.push(RuntimeLeasePublicKey { key_id, public_key });
    }
    Ok(parsed)
}

pub fn parse_runtime_lease_public_keys(input: &str) -> IpcResult<Vec<RuntimeLeasePublicKey>> {
    let frame = parse_raw_frame(input)?;
    let payload = parse_hello_payload(&frame)?;
    parse_runtime_lease_public_key_payloads(payload.runtime_lease_public_keys)
}

pub fn verify_worker_runtime_lease_signature(
    input: &str,
    public_keys: &[RuntimeLeasePublicKey],
) -> IpcResult<()> {
    parse_worker_invocation(input)?.verify_runtime_lease_signature(public_keys)
}

impl ParsedWorkerInvocation {
    pub fn verify_runtime_lease_signature(
        &self,
        public_keys: &[RuntimeLeasePublicKey],
    ) -> IpcResult<()> {
        if public_keys.is_empty() {
            return Err(missing_field("runtime lease public keys"));
        }
        let key_id = required_string(&self.lease.key_id, "key_id")?;
        let public_key = public_keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| invalid_field("runtime lease signing key"))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key.public_key)
            .map_err(|_| invalid_field("runtime lease public key"))?;
        let payload = runtime_lease_signature_payload_json(&self.lease, &self.method)?;
        let signature =
            decode_runtime_lease_signature(&required_string(&self.lease.signature, "signature")?)?;
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| invalid_field("runtime lease signature"))
    }
}

pub fn validate_worker_runtime_lease(input: &str, now_unix_ms: i64) -> IpcResult<()> {
    parse_worker_invocation(input)?.validate_runtime_lease(now_unix_ms)
}

impl ParsedWorkerInvocation {
    pub fn validate_runtime_lease(&self, now_unix_ms: i64) -> IpcResult<()> {
        let lease = &self.lease;
        let invocation = &self.invocation;
        let expires_at_unix_ms = positive_i64(lease.expires_at_unix_ms, "expires_at_unix_ms")?;
        if expires_at_unix_ms <= now_unix_ms {
            return Err(protocol_violation("runtime execution lease is expired"));
        }
        validate_runtime_lease_string_binding(&lease.method, &invocation.method, "method", true)?;
        if required_string(&lease.method, "method")? != self.method {
            return Err(protocol_violation(
                "runtime lease method does not match the invocation envelope",
            ));
        }
        for (lease_value, invocation_value, field) in [
            (&lease.plugin_id, &invocation.plugin_id, "plugin_id"),
            (
                &lease.plugin_instance_id,
                &invocation.plugin_instance_id,
                "plugin_instance_id",
            ),
            (
                &lease.active_fingerprint,
                &invocation.active_fingerprint,
                "active_fingerprint",
            ),
            (
                &lease.runtime_instance_id,
                &invocation.runtime_instance_id,
                "runtime_instance_id",
            ),
            (
                &lease.runtime_generation_id,
                &invocation.runtime_generation_id,
                "runtime_generation_id",
            ),
            (&lease.effect, &invocation.effect, "effect"),
            (&lease.execution, &invocation.execution, "execution"),
            (
                &lease.audit_correlation_id,
                &invocation.audit_correlation_id,
                "audit_correlation_id",
            ),
        ] {
            validate_runtime_lease_string_binding(lease_value, invocation_value, field, true)?;
        }
        for (lease_value, invocation_value, field) in [
            (
                &lease.surface_instance_id,
                &invocation.surface_instance_id,
                "surface_instance_id",
            ),
            (
                &lease.owner_session_hash,
                &invocation.owner_session_hash,
                "owner_session_hash",
            ),
            (
                &lease.owner_user_hash,
                &invocation.owner_user_hash,
                "owner_user_hash",
            ),
            (
                &lease.owner_env_hash,
                &invocation.owner_env_hash,
                "owner_env_hash",
            ),
            (
                &lease.session_channel_id_hash,
                &invocation.session_channel_id_hash,
                "session_channel_id_hash",
            ),
            (
                &lease.bridge_channel_id,
                &invocation.bridge_channel_id,
                "bridge_channel_id",
            ),
            (
                &lease.operation_id,
                &invocation.operation_id,
                "operation_id",
            ),
            (&lease.stream_id, &invocation.stream_id, "stream_id"),
        ] {
            validate_runtime_lease_string_binding(lease_value, invocation_value, field, false)?;
        }
        if required_string(&lease.runtime_generation_id, "runtime_generation_id")?
            != self.runtime_generation_id
        {
            return Err(protocol_violation(
                "runtime lease runtime_generation_id does not match the invocation frame",
            ));
        }
        validate_runtime_execution_handles(
            &lease.execution,
            &lease.operation_id,
            &lease.stream_id,
        )?;
        validate_runtime_execution_handles(
            &invocation.execution,
            &invocation.operation_id,
            &invocation.stream_id,
        )?;
        let invocation_target_hash = self.target_hash()?;
        let target_hashes = lease
            .target_descriptor_hashes
            .as_ref()
            .ok_or_else(|| missing_field("runtime lease target_descriptor_hashes"))?;
        if target_hashes
            .iter()
            .filter(|value| value.as_str() == invocation_target_hash.as_str())
            .count()
            != 1
        {
            return Err(protocol_violation(
                "runtime lease does not bind the worker invocation target",
            ));
        }
        Ok(())
    }
}

pub fn worker_invocation_target_hash(input: &str) -> IpcResult<String> {
    parse_worker_invocation(input)?.target_hash()
}

impl ParsedWorkerInvocation {
    pub fn target_hash(&self) -> IpcResult<String> {
        self.target_hash
            .get_or_init(|| self.build_target_hash())
            .clone()
    }

    fn build_target_hash(&self) -> IpcResult<String> {
        let invocation = &self.invocation;
        let params = self
            .params_json
            .as_ref()
            .ok_or_else(|| missing_field("worker invocation params"))?;
        let broker_access = self
            .broker_access_json
            .as_ref()
            .ok_or_else(|| missing_field("worker invocation broker_access"))?;
        let params_hash = format!(
            "sha256:{}",
            lowercase_hex(&Sha256::digest(params.as_bytes()))
        );
        if required_string(&invocation.params_sha256, "params_sha256")? != params_hash {
            return Err(protocol_violation(
                "worker invocation params_sha256 does not match params",
            ));
        }
        let broker_access_hash = format!(
            "sha256:{}",
            lowercase_hex(&Sha256::digest(broker_access.as_bytes()))
        );
        if self.invocation.broker_access_sha256.as_deref() != Some(broker_access_hash.as_str()) {
            return Err(protocol_violation(
                "worker invocation broker_access_sha256 does not match broker_access",
            ));
        }
        let fields = [
            WORKER_INVOCATION_TARGET_SCHEMA_VERSION.to_string(),
            required_string(&invocation.plugin_id, "plugin_id")?,
            required_string(&invocation.plugin_instance_id, "plugin_instance_id")?,
            required_string(&invocation.active_fingerprint, "active_fingerprint")?,
            required_string(&invocation.runtime_instance_id, "runtime_instance_id")?,
            required_string(&invocation.runtime_generation_id, "runtime_generation_id")?,
            required_string(&invocation.package_hash, "package_hash")?,
            required_string(&invocation.worker_id, "worker_id")?,
            required_string(&invocation.worker_mode, "worker_mode")?,
            required_string(&invocation.worker_scope, "worker_scope")?,
            required_string(&invocation.artifact, "artifact")?,
            required_string(&invocation.artifact_sha256, "artifact_sha256")?,
            required_string(&invocation.abi, "abi")?,
            required_string(&invocation.method, "method")?,
            required_string(&invocation.effect, "effect")?,
            required_string(&invocation.execution, "execution")?,
            optional_string(&invocation.surface_instance_id),
            optional_string(&invocation.owner_session_hash),
            optional_string(&invocation.owner_user_hash),
            optional_string(&invocation.owner_env_hash),
            optional_string(&invocation.session_channel_id_hash),
            optional_string(&invocation.bridge_channel_id),
            optional_string(&invocation.operation_id),
            optional_string(&invocation.stream_id),
            required_string(&invocation.audit_correlation_id, "audit_correlation_id")?,
            params_hash,
            broker_access_hash,
        ];
        let mut canonical = Vec::new();
        for field in fields {
            let length = u32::try_from(field.len()).map_err(|_| {
                protocol_violation("worker invocation target field exceeds uint32 length")
            })?;
            canonical.extend_from_slice(&length.to_be_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        Ok(format!(
            "invocation:sha256:{}",
            lowercase_hex(&Sha256::digest(canonical))
        ))
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_runtime_lease_string_binding(
    lease: &Option<String>,
    invocation: &Option<String>,
    field: &'static str,
    required: bool,
) -> IpcResult<()> {
    let lease_value = optional_string_ref(lease);
    let invocation_value = optional_string_ref(invocation);
    if required && (lease_value.is_none() || invocation_value.is_none()) {
        return Err(IpcError::MissingField { field });
    }
    if lease_value != invocation_value {
        return Err(IpcError::InvalidField { field });
    }
    Ok(())
}

fn validate_runtime_execution_handles(
    execution: &Option<String>,
    operation_id: &Option<String>,
    stream_id: &Option<String>,
) -> IpcResult<()> {
    let execution = required_string(execution, "execution")?;
    let operation_id = optional_string_ref(operation_id).unwrap_or_default();
    let stream_id = optional_string_ref(stream_id).unwrap_or_default();
    match execution.as_str() {
        "sync" if operation_id.is_empty() && stream_id.is_empty() => Ok(()),
        "operation" if !operation_id.is_empty() && stream_id.is_empty() => Ok(()),
        "subscription" if !operation_id.is_empty() && !stream_id.is_empty() => Ok(()),
        _ => Err(invalid_field("runtime lease execution handles")),
    }
}

fn decode_runtime_lease_signature(input: &str) -> IpcResult<Signature> {
    let raw = input.trim();
    let prefix = format!("{RUNTIME_LEASE_SIGNATURE_ALGORITHM}:");
    let encoded = raw
        .strip_prefix(prefix.as_str())
        .ok_or_else(|| protocol_violation("runtime lease signature algorithm is unsupported"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| invalid_field("runtime lease signature base64"))?;
    Signature::from_slice(&decoded).map_err(|_| invalid_field("runtime lease signature length"))
}

fn runtime_lease_signature_payload_json(
    lease: &WorkerLeasePayload,
    method: &str,
) -> IpcResult<String> {
    if let Some(lease_method) = optional_string_ref(&lease.method) {
        if lease_method != method.trim() {
            return Err(protocol_violation("runtime lease method mismatch"));
        }
    }
    let lease_id = required_string(&lease.lease_id, "lease_id")?;
    let token_id = required_string(&lease.token_id, "token_id")?;
    let expires_at_unix_ms = positive_i64(lease.expires_at_unix_ms, "expires_at_unix_ms")?;
    let issued_at_unix_ms = positive_i64(lease.issued_at_unix_ms, "issued_at_unix_ms")?;
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
    let lease_nonce = required_string(&lease.lease_nonce, "lease_nonce")?;
    if lease_nonce.len() < 16 {
        return Err(invalid_field("runtime lease lease_nonce"));
    }
    append_json_string_field(&mut out, "lease_nonce", &lease_nonce, true);
    append_json_string_field(
        &mut out,
        "plugin_instance_id",
        &required_string(&lease.plugin_instance_id, "plugin_instance_id")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "plugin_id",
        &required_string(&lease.plugin_id, "plugin_id")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "plugin_version",
        &required_string(&lease.plugin_version, "plugin_version")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "active_fingerprint",
        &required_string(&lease.active_fingerprint, "active_fingerprint")?,
        true,
    );
    append_json_i64_field(&mut out, "issued_at_unix_ms", issued_at_unix_ms);
    append_json_string_field(&mut out, "method", method.trim(), true);
    let effect = required_string(&lease.effect, "effect")?;
    if !matches!(
        effect.as_str(),
        "read" | "write" | "execute" | "delete" | "admin"
    ) {
        return Err(invalid_field("runtime lease effect"));
    }
    append_json_string_field(&mut out, "effect", &effect, true);
    append_json_string_field(
        &mut out,
        "execution",
        &required_string(&lease.execution, "execution")?,
        true,
    );
    validate_runtime_execution_handles(&lease.execution, &lease.operation_id, &lease.stream_id)?;
    let operation_id = optional_string(&lease.operation_id);
    let stream_id = optional_string(&lease.stream_id);
    append_json_optional_string_field(&mut out, "operation_id", Some(&operation_id));
    append_json_optional_string_field(&mut out, "stream_id", Some(&stream_id));
    append_json_string_field(
        &mut out,
        "audit_correlation_id",
        &required_string(&lease.audit_correlation_id, "audit_correlation_id")?,
        true,
    );
    append_json_optional_string_field(
        &mut out,
        "surface_instance_id",
        optional_string_ref(&lease.surface_instance_id),
    );
    append_json_optional_string_field(
        &mut out,
        "owner_session_hash",
        optional_string_ref(&lease.owner_session_hash),
    );
    append_json_optional_string_field(
        &mut out,
        "owner_user_hash",
        optional_string_ref(&lease.owner_user_hash),
    );
    append_json_string_field(
        &mut out,
        "owner_env_hash",
        &required_string(&lease.owner_env_hash, "owner_env_hash")?,
        true,
    );
    append_json_optional_string_field(
        &mut out,
        "session_channel_id_hash",
        optional_string_ref(&lease.session_channel_id_hash),
    );
    append_json_optional_string_field(
        &mut out,
        "bridge_channel_id",
        optional_string_ref(&lease.bridge_channel_id),
    );
    let target_hashes = lease
        .target_descriptor_hashes
        .as_ref()
        .filter(|hashes| !hashes.is_empty())
        .ok_or_else(|| missing_field("runtime lease target_descriptor_hashes"))?;
    let mut seen_target_hashes = HashSet::new();
    out.push_str(",\"target_descriptor_hashes\":[");
    for (index, hash) in target_hashes.iter().enumerate() {
        let hash = hash.trim();
        if hash.is_empty() {
            return Err(invalid_field("target_descriptor_hashes item"));
        }
        if !seen_target_hashes.insert(hash) {
            return Err(protocol_violation(
                "target_descriptor_hashes item is duplicated",
            ));
        }
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json_string(hash));
        out.push('"');
    }
    out.push(']');
    append_runtime_lease_limits_field(
        &mut out,
        lease
            .limits
            .as_ref()
            .ok_or_else(|| missing_field("runtime lease limits"))?,
    )?;
    append_json_u64_field(
        &mut out,
        "policy_revision",
        required_safe_u64(lease.policy_revision, "policy_revision")?,
    );
    append_json_u64_field(
        &mut out,
        "management_revision",
        required_safe_u64(lease.management_revision, "management_revision")?,
    );
    append_json_u64_field(
        &mut out,
        "revoke_epoch",
        required_positive_u64(lease.revoke_epoch, "revoke_epoch")?,
    );
    append_json_i64_field(&mut out, "expires_at_unix_ms", expires_at_unix_ms);
    append_json_string_field(
        &mut out,
        "runtime_shard_id",
        &required_string(&lease.runtime_shard_id, "runtime_shard_id")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "runtime_instance_id",
        &required_string(&lease.runtime_instance_id, "runtime_instance_id")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "runtime_generation_id",
        &required_string(&lease.runtime_generation_id, "runtime_generation_id")?,
        true,
    );
    append_json_string_field(
        &mut out,
        "ipc_channel_id",
        &required_string(&lease.ipc_channel_id, "ipc_channel_id")?,
        true,
    );
    let connection_nonce = required_string(&lease.connection_nonce, "connection_nonce")?;
    if connection_nonce.len() < 16 {
        return Err(invalid_field("runtime lease connection_nonce"));
    }
    append_json_string_field(&mut out, "connection_nonce", &connection_nonce, true);
    append_json_string_field(
        &mut out,
        "key_id",
        &required_string(&lease.key_id, "key_id")?,
        true,
    );
    out.push('}');
    Ok(out)
}

fn optional_string_ref(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_string(value: &Option<String>) -> String {
    optional_string_ref(value).unwrap_or_default().to_string()
}

fn positive_i64(value: Option<i64>, field: &'static str) -> IpcResult<i64> {
    value.ok_or_else(|| missing_field(field)).and_then(|value| {
        if value > 0 && value as u64 <= MAX_JSON_SAFE_INTEGER {
            Ok(value)
        } else {
            Err(invalid_field(field))
        }
    })
}

fn nonnegative_i64(value: Option<i64>, field: &'static str) -> IpcResult<i64> {
    value.ok_or_else(|| missing_field(field)).and_then(|value| {
        if value >= 0 && value as u64 <= MAX_JSON_SAFE_INTEGER {
            Ok(value)
        } else {
            Err(invalid_field(field))
        }
    })
}

fn required_u64(value: Option<u64>, field: &'static str) -> IpcResult<u64> {
    value.ok_or_else(|| missing_field(field))
}

fn required_safe_u64(value: Option<u64>, field: &'static str) -> IpcResult<u64> {
    validate_safe_u64(required_u64(value, field)?, field)
}

fn required_positive_u64(value: Option<u64>, field: &'static str) -> IpcResult<u64> {
    validate_positive_u64(required_u64(value, field)?, field)
}

fn validate_positive_u64(value: u64, field: &'static str) -> IpcResult<u64> {
    if value == 0 {
        return Err(invalid_field(field));
    }
    validate_safe_u64(value, field)
}

fn validate_safe_u64(value: u64, field: &'static str) -> IpcResult<u64> {
    if value > MAX_JSON_SAFE_INTEGER {
        return Err(invalid_field(field));
    }
    Ok(value)
}

fn validate_revoke_epoch(revoke_epoch: u64) -> IpcResult<()> {
    validate_positive_u64(revoke_epoch, "revoke_epoch").map(|_| ())
}

fn validate_revision_binding(
    policy_revision: u64,
    management_revision: u64,
    revoke_epoch: u64,
) -> IpcResult<()> {
    validate_safe_u64(policy_revision, "policy_revision")?;
    validate_safe_u64(management_revision, "management_revision")?;
    validate_revoke_epoch(revoke_epoch)
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
    limits: &WorkerLeaseLimitsPayload,
) -> IpcResult<()> {
    let timeout_ms = nonnegative_i64(limits.timeout_ms, "timeout_ms")?;
    let memory_bytes = limits
        .memory_bytes
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_field("memory_bytes"))?;
    if memory_bytes > MAX_RUNTIME_LEASE_MEMORY_BYTES {
        return Err(protocol_violation(
            "memory_bytes exceeds runtime lease limit",
        ));
    }
    let max_payload_bytes = nonnegative_i64(limits.max_payload_bytes, "max_payload_bytes")?;
    let max_stream_bytes_per_sec =
        nonnegative_i64(limits.max_stream_bytes_per_sec, "max_stream_bytes_per_sec")?;
    out.push_str(&format!(
        ",\"limits\":{{\"timeout_ms\":{timeout_ms},\"memory_bytes\":{memory_bytes},\"max_payload_bytes\":{max_payload_bytes},\"max_stream_bytes_per_sec\":{max_stream_bytes_per_sec}}}"
    ));
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct HelloAckFrameRequest<'a> {
    pub request_id: &'a str,
    pub runtime_generation_id: &'a str,
    pub channel_nonce: &'a str,
    pub runtime_version: &'a str,
    pub actual_target: &'a RuntimeTarget,
    pub wasm_abi_version: &'a str,
    pub limits: RuntimeLimits,
    pub process_containment: &'a ProcessContainmentEvidence,
}

pub fn hello_ack_frame(request: HelloAckFrameRequest<'_>) -> IpcResult<String> {
    let limits = request.limits.validate()?;
    let limits = serde_json::to_string(&limits).map_err(|_| encode_failed("runtime limits"))?;
    request.process_containment.validate()?;
    let process_containment = serde_json::to_string(request.process_containment)
        .map_err(|_| encode_failed("process containment evidence"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"runtime_version\":\"{}\",\"actual_target\":\"{}\",\"rust_ipc_version\":\"{}\",\"wasm_abi_version\":\"{}\",\"contract_set_sha256\":\"{}\",\"channel_nonce\":\"{}\",\"limits\":{},\"process_containment\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_HELLO_ACK,
        escape_json_string(request.request_id),
        escape_json_string(request.runtime_generation_id),
        escape_json_string(request.runtime_version),
        escape_json_string(request.actual_target.as_str()),
        RUST_IPC_VERSION,
        escape_json_string(request.wasm_abi_version),
        CONTRACT_SET_SHA256,
        escape_json_string(request.channel_nonce),
        limits,
        process_containment
    ))
}

pub fn success_response_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    result_json: &str,
) -> IpcResult<String> {
    serde_json::from_str::<serde_json::Value>(result_json)
        .map_err(|_| IpcError::InvalidResponseResultJson)?;
    let payload = format!("{{\"ok\":true,\"result\":{result_json}}}");
    Ok(render_response_frame(
        frame_type,
        request_id,
        runtime_generation_id,
        &payload,
    ))
}

pub fn session_revoke_ack_frame(
    request_id: &str,
    runtime_generation_id: &str,
    session_revoke_sequence: u64,
    state: SessionRevokeState,
    counts: SessionRevokeAckCounts,
) -> IpcResult<String> {
    if request_id.is_empty() || request_id.trim() != request_id {
        return Err(invalid_field("request_id"));
    }
    if runtime_generation_id.is_empty() || runtime_generation_id.trim() != runtime_generation_id {
        return Err(invalid_field("runtime_generation_id"));
    }
    if session_revoke_sequence == 0 || session_revoke_sequence > MAX_JSON_SAFE_INTEGER {
        return Err(invalid_field("session_revoke_sequence"));
    }
    for (count, field) in [
        (counts.queued_invocations, "queued_invocations"),
        (counts.running_invocations, "running_invocations"),
        (counts.storage_hostcalls, "storage_hostcalls"),
        (counts.active_network_requests, "active_network_requests"),
        (counts.sockets, "sockets"),
        (counts.network_streams, "network_streams"),
    ] {
        if count > MAX_JSON_SAFE_INTEGER {
            return Err(invalid_field(field));
        }
    }
    let result = serde_json::json!({
        "session_revoke_sequence": session_revoke_sequence,
        "state": state,
        "counts": counts,
    });
    success_response_frame(
        FRAME_TYPE_SESSION_REVOKE_ACK,
        request_id,
        runtime_generation_id,
        &result.to_string(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseError<'a> {
    code: &'a str,
    message: &'a str,
    origin: &'static str,
}

impl<'a> ResponseError<'a> {
    pub fn runtime(code: &'a str, message: &'a str) -> IpcResult<Self> {
        Self::new(code, message, ERROR_ORIGIN_RUNTIME)
    }

    pub fn hostcall(code: &'a str, message: &'a str) -> IpcResult<Self> {
        Self::new(code, message, ERROR_ORIGIN_HOSTCALL)
    }

    pub fn plugin(code: &'a str, message: &'a str) -> IpcResult<Self> {
        Self::new(code, message, ERROR_ORIGIN_PLUGIN)
    }

    fn new(code: &'a str, message: &'a str, origin: &'static str) -> IpcResult<Self> {
        if code.trim().is_empty() {
            return Err(IpcError::EmptyResponseErrorCode);
        }
        if message.trim().is_empty() {
            return Err(IpcError::EmptyResponseErrorMessage);
        }
        Ok(Self {
            code,
            message,
            origin,
        })
    }
}

pub fn error_response_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    error: ResponseError<'_>,
) -> IpcResult<String> {
    let payload = render_error_payload(error);
    Ok(render_response_frame(
        frame_type,
        request_id,
        runtime_generation_id,
        &payload,
    ))
}

fn render_error_payload(error: ResponseError<'_>) -> String {
    format!(
        "{{\"ok\":false,\"code\":\"{}\",\"message\":\"{}\",\"error_origin\":\"{}\"}}",
        escape_json_string(error.code),
        escape_json_string(error.message),
        error.origin,
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
    resource_scope: &NetworkResourceScope,
    plugin_instance_id: &str,
    revoke_epoch: u64,
    closed_socket_count: u64,
    closed_stream_count: u64,
    closed_storage_handle_count: u64,
) -> IpcResult<String> {
    if !resource_scope.valid() || resource_scope.kind != "environment" {
        return Err(invalid_field("revoke resource scope"));
    }
    validate_revoke_epoch(revoke_epoch)?;
    let resource_scope = serde_json::to_string(resource_scope)
        .map_err(|_| encode_failed("revoke resource scope"))?;
    Ok(format!(
        "{{\"resource_scope\":{},\"plugin_instance_id\":\"{}\",\"revoke_epoch\":{},\"closed_socket_count\":{},\"closed_stream_count\":{},\"closed_storage_handle_count\":{}}}",
        resource_scope,
        escape_json_string(plugin_instance_id),
        revoke_epoch,
        closed_socket_count,
        closed_stream_count,
        closed_storage_handle_count
    ))
}

pub fn heartbeat_ack_result_json(
    runtime_generation_id: &str,
    runtime_unix_nano: u64,
    max_staleness_ms: u64,
    host_sent_unix_nano: u64,
    status: RuntimeHeartbeatStatus,
) -> IpcResult<String> {
    let limits = status.limits.validate()?;
    Ok(serde_json::json!({
        "runtime_generation_id": runtime_generation_id,
        "runtime_unix_nano": runtime_unix_nano,
        "max_staleness_ms": max_staleness_ms,
        "host_sent_unix_nano": host_sent_unix_nano,
        "active_invocations": status.active_invocations,
        "queued_invocations": status.queued_invocations,
        "limits": limits,
        "module_cache": status.module_cache,
    })
    .to_string())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct ModuleCacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub compiles: u64,
    pub entries: usize,
    pub source_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHeartbeatStatus {
    pub active_invocations: usize,
    pub queued_invocations: usize,
    pub limits: RuntimeLimits,
    pub module_cache: ModuleCacheMetrics,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelInvokePayload {
    invocation_request_id: String,
}

pub fn parse_cancel_invoke(input: &str) -> IpcResult<String> {
    let frame = parse_raw_frame(input)?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err(protocol_violation("unsupported ipc_version"));
    }
    if frame.frame_type != FRAME_TYPE_CANCEL_INVOKE {
        return Err(protocol_violation("expected cancel_invoke frame"));
    }
    let payload: CancelInvokePayload = serde_json::from_str(frame.payload.get())
        .map_err(|_| decode_failed("cancel_invoke payload"))?;
    let request_id = payload.invocation_request_id.trim();
    if request_id.is_empty() {
        return Err(invalid_field("invocation_request_id"));
    }
    Ok(request_id.to_string())
}

pub fn cancel_invoke_ack_frame(
    request_id: &str,
    runtime_generation_id: &str,
    invocation_request_id: &str,
    disposition: &str,
) -> IpcResult<String> {
    let result = serde_json::json!({
        "invocation_request_id": invocation_request_id,
        "disposition": disposition,
    });
    success_response_frame(
        FRAME_TYPE_CANCEL_INVOKE_ACK,
        request_id,
        runtime_generation_id,
        &result.to_string(),
    )
}

enum HostcallResponsePayload<T> {
    Success(T),
    Failure(HostcallFailureResponsePayload),
}

#[derive(Deserialize)]
struct BooleanResponseDiscriminator {
    ok: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostcallFailureResponsePayload {
    ok: bool,
    code: String,
    message: String,
    error_origin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenHandleSuccessResponsePayload {
    ok: bool,
    package_hash: String,
    artifact: String,
    sha256: String,
    content_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct HandleGrantSuccessResponsePayload {
    ok: bool,
    handle_grant_id: String,
    handle_id: String,
    method: String,
    runtime_generation_id: String,
    resource_scope: NetworkResourceScope,
    max_bytes_per_second: Option<u64>,
    max_total_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageUsageResponsePayload {
    plugin_instance_id: String,
    store_id: String,
    usage_bytes: u64,
    quota_bytes: u64,
    usage_files: u64,
    quota_files: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageFileEntryResponsePayload {
    path: String,
    dir: bool,
    size_bytes: Option<u64>,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageFileReadSuccessResponsePayload {
    ok: bool,
    path: String,
    data_base64: String,
    size_bytes: u64,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageFileWriteSuccessResponsePayload {
    ok: bool,
    path: String,
    size_bytes: u64,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageFileDeleteSuccessResponsePayload {
    ok: bool,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageFileListSuccessResponsePayload {
    ok: bool,
    path: String,
    entries: Vec<StorageFileEntryResponsePayload>,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageKVEntryResponsePayload {
    key: String,
    size_bytes: u64,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageKVGetSuccessResponsePayload {
    ok: bool,
    key: String,
    value_base64: String,
    size_bytes: u64,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageKVPutSuccessResponsePayload {
    ok: bool,
    key: String,
    size_bytes: u64,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageKVDeleteSuccessResponsePayload {
    ok: bool,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageKVListSuccessResponsePayload {
    ok: bool,
    prefix: Option<String>,
    entries: Vec<StorageKVEntryResponsePayload>,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageSQLiteValueResponsePayload {
    #[serde(rename = "null")]
    null_value: Option<bool>,
    int: Option<i64>,
    float: Option<f64>,
    text: Option<String>,
    blob_base64: Option<String>,
}

impl StorageSQLiteValueResponsePayload {
    fn is_exactly_typed(&self) -> bool {
        let variants = usize::from(self.null_value.is_some())
            + usize::from(self.int.is_some())
            + usize::from(self.float.is_some())
            + usize::from(self.text.is_some())
            + usize::from(self.blob_base64.is_some());
        variants == 1 && self.null_value.unwrap_or(true)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageSQLiteExecSuccessResponsePayload {
    ok: bool,
    database: String,
    rows_affected: u64,
    last_insert_id: Option<u64>,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StorageSQLiteQuerySuccessResponsePayload {
    ok: bool,
    database: String,
    columns: Vec<String>,
    rows: Vec<Vec<StorageSQLiteValueResponsePayload>>,
    usage: StorageUsageResponsePayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct NetworkDestinationResponsePayload {
    transport: String,
    scheme: Option<String>,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct NetworkGrantSuccessResponsePayload {
    ok: bool,
    grant_id: String,
    plugin_instance_id: String,
    active_fingerprint: String,
    resource_scope: NetworkResourceScope,
    policy_revision: u64,
    management_revision: u64,
    revoke_epoch: u64,
    connector_id: String,
    transport: String,
    destination: NetworkDestinationResponsePayload,
    runtime_generation_id: String,
    target_classifier_version: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct NetworkExecuteSuccessResponsePayload {
    ok: bool,
    transport: String,
    destination: NetworkDestinationResponsePayload,
    status_code: Option<u16>,
    headers: Option<HashMap<String, Vec<String>>>,
    message_type: Option<String>,
    body_base64: Option<String>,
    payload_base64: Option<String>,
    stream_id: Option<String>,
    bytes_read: Option<u64>,
    chunk_count: Option<u64>,
    grant_id: String,
    connector_id: String,
    runtime_generation_id: String,
}

fn parse_hostcall_response_frame<T: DeserializeOwned>(
    input: &str,
    expected_frame_type: &'static str,
) -> IpcResult<(RawIPCFrame, HostcallResponsePayload<T>)> {
    let frame = parse_raw_frame(input)?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err(protocol_violation("unsupported ipc_version"));
    }
    if frame.frame_type != expected_frame_type {
        return Err(protocol_violation(
            "unexpected hostcall response frame type",
        ));
    }
    if frame.request_id.trim().is_empty() {
        return Err(invalid_field("hostcall response request_id"));
    }
    let runtime_generation_id = frame
        .runtime_generation_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| missing_field("hostcall response runtime_generation_id"))?;
    if runtime_generation_id.trim().is_empty() {
        return Err(invalid_field("hostcall response runtime_generation_id"));
    }
    let discriminator: BooleanResponseDiscriminator = serde_json::from_str(frame.payload.get())
        .map_err(|_| decode_failed("hostcall response discriminator"))?;
    let payload = if discriminator.ok {
        HostcallResponsePayload::Success(
            serde_json::from_str(frame.payload.get())
                .map_err(|_| decode_failed("hostcall success response payload"))?,
        )
    } else {
        HostcallResponsePayload::Failure(
            serde_json::from_str(frame.payload.get())
                .map_err(|_| decode_failed("hostcall failure response payload"))?,
        )
    };
    Ok((frame, payload))
}

fn validate_hostcall_response_identity(
    frame: &RawIPCFrame,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    _label: &'static str,
) -> IpcResult<()> {
    if frame.request_id != expected_request_id {
        return Err(protocol_violation("hostcall response request_id mismatch"));
    }
    if frame.runtime_generation_id.as_deref() != Some(expected_runtime_generation_id) {
        return Err(protocol_violation(
            "hostcall response runtime_generation_id mismatch",
        ));
    }
    Ok(())
}

fn validated_hostcall_failure(failure: HostcallFailureResponsePayload) -> IpcResult<IpcError> {
    if failure.ok {
        return Err(protocol_violation(
            "hostcall failure response ok must be false",
        ));
    }
    if failure.error_origin != ERROR_ORIGIN_HOSTCALL {
        return Err(protocol_violation(
            "hostcall response error_origin must be hostcall",
        ));
    }
    let code = failure.code.trim();
    if !is_stable_worker_error_code(code) {
        return Err(invalid_field("hostcall response code"));
    }
    let message = failure.message.trim();
    if message.is_empty() || message.len() > 4096 {
        return Err(invalid_field("hostcall response message"));
    }
    Ok(IpcError::RemoteFailure {
        code: code.to_string(),
    })
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

pub fn compile_flight_register_frame(
    parent_request_id: &str,
    runtime_generation_id: &str,
    identity: &WorkerInvocationIdentity,
) -> String {
    compile_flight_lifecycle_frame(
        FRAME_TYPE_COMPILE_FLIGHT_REGISTER,
        parent_request_id,
        runtime_generation_id,
        identity,
    )
}

pub fn compile_flight_complete_frame(
    parent_request_id: &str,
    runtime_generation_id: &str,
    identity: &WorkerInvocationIdentity,
) -> String {
    compile_flight_lifecycle_frame(
        FRAME_TYPE_COMPILE_FLIGHT_COMPLETE,
        parent_request_id,
        runtime_generation_id,
        identity,
    )
}

fn compile_flight_lifecycle_frame(
    frame_type: &str,
    parent_request_id: &str,
    runtime_generation_id: &str,
    identity: &WorkerInvocationIdentity,
) -> String {
    let artifact_request_id = format!("{parent_request_id}:artifact");
    let request_id = if frame_type == FRAME_TYPE_COMPILE_FLIGHT_REGISTER {
        format!("{artifact_request_id}:register")
    } else {
        format!("{artifact_request_id}:complete")
    };
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"parent_request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"artifact_request_id\":\"{}\",\"package_hash\":\"{}\",\"artifact\":\"{}\",\"artifact_sha256\":\"{}\",\"wasm_abi_version\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        frame_type,
        escape_json_string(&request_id),
        escape_json_string(parent_request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&artifact_request_id),
        escape_json_string(&identity.package_hash),
        escape_json_string(&identity.artifact),
        escape_json_string(&identity.artifact_sha256),
        WASM_ABI_VERSION,
    )
}

pub fn validate_open_handle_response(
    input: &str,
    expected_request_id: &str,
    expected_parent_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_identity: &WorkerInvocationIdentity,
) -> IpcResult<()> {
    parse_open_handle_success_response(
        input,
        expected_request_id,
        expected_parent_request_id,
        expected_runtime_generation_id,
        expected_identity,
    )?;
    Ok(())
}

fn parse_open_handle_success_response(
    input: &str,
    expected_request_id: &str,
    expected_parent_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_identity: &WorkerInvocationIdentity,
) -> IpcResult<OpenHandleSuccessResponsePayload> {
    let (frame, response) = parse_hostcall_response_frame::<OpenHandleSuccessResponsePayload>(
        input,
        FRAME_TYPE_OPEN_HANDLE,
    )?;
    validate_hostcall_response_identity(
        &frame,
        expected_request_id,
        expected_runtime_generation_id,
        "open_handle",
    )?;
    if frame.parent_request_id.as_deref() != Some(expected_parent_request_id) {
        return Err(protocol_violation("open_handle parent_request_id mismatch"));
    }
    let success = match response {
        HostcallResponsePayload::Success(success) if success.ok => success,
        HostcallResponsePayload::Success(_) => {
            return Err(protocol_violation(
                "open_handle success response ok must be true",
            ));
        }
        HostcallResponsePayload::Failure(failure) => {
            return Err(validated_hostcall_failure(failure)?);
        }
    };
    if success.package_hash != expected_identity.package_hash
        || success.artifact != expected_identity.artifact
        || success.sha256 != expected_identity.artifact_sha256
    {
        return Err(protocol_violation("open_handle artifact identity mismatch"));
    }
    if success.content_base64.trim().is_empty() {
        return Err(invalid_field("content_base64"));
    }
    Ok(success)
}

pub fn open_handle_content_base64(
    input: &str,
    expected_request_id: &str,
    expected_parent_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_identity: &WorkerInvocationIdentity,
) -> IpcResult<String> {
    let success = parse_open_handle_success_response(
        input,
        expected_request_id,
        expected_parent_request_id,
        expected_runtime_generation_id,
        expected_identity,
    )?;
    Ok(success.content_base64)
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

#[derive(Deserialize)]
struct NetworkResultProjection {
    transport: Option<String>,
    stream_id: Option<String>,
}

fn parse_network_result_projection(result: &str) -> Option<NetworkResultProjection> {
    serde_json::from_str(result).ok()
}

fn network_result_transport(result: &str) -> Option<String> {
    parse_network_result_projection(result)
        .and_then(|result| result.transport)
        .map(|value| {
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
        .filter_map(|result| parse_network_result_projection(result)?.stream_id)
        .find(|stream_id| !stream_id.trim().is_empty())
}

pub fn storage_file_payload_json(input: &str, expected_operation: &str) -> IpcResult<String> {
    match expected_operation {
        "read" => successful_hostcall_payload_json::<StorageFileReadSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            |payload| payload.ok,
        ),
        "write" => successful_hostcall_payload_json::<StorageFileWriteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            |payload| payload.ok,
        ),
        "delete" => successful_hostcall_payload_json::<StorageFileDeleteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            |payload| payload.ok,
        ),
        "list" => successful_hostcall_payload_json::<StorageFileListSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            |payload| payload.ok,
        ),
        _ => Err(invalid_field("storage_file response operation")),
    }
}

pub fn storage_kv_payload_json(input: &str, expected_operation: &str) -> IpcResult<String> {
    match expected_operation {
        "get" => successful_hostcall_payload_json::<StorageKVGetSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            |payload| payload.ok,
        ),
        "put" => successful_hostcall_payload_json::<StorageKVPutSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            |payload| payload.ok,
        ),
        "delete" => successful_hostcall_payload_json::<StorageKVDeleteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            |payload| payload.ok,
        ),
        "list" => successful_hostcall_payload_json::<StorageKVListSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            |payload| payload.ok,
        ),
        _ => Err(invalid_field("storage_kv response operation")),
    }
}

pub fn storage_sqlite_payload_json(input: &str, expected_operation: &str) -> IpcResult<String> {
    match expected_operation {
        "exec" => successful_hostcall_payload_json::<StorageSQLiteExecSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_SQLITE,
            |payload| payload.ok,
        ),
        "query" => successful_hostcall_payload_json::<StorageSQLiteQuerySuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_SQLITE,
            |payload| {
                payload.ok
                    && payload
                        .rows
                        .iter()
                        .flatten()
                        .all(StorageSQLiteValueResponsePayload::is_exactly_typed)
            },
        ),
        _ => Err(invalid_field("storage_sqlite response operation")),
    }
}

pub fn network_execute_payload_json(input: &str) -> IpcResult<String> {
    successful_hostcall_payload_json::<NetworkExecuteSuccessResponsePayload, _>(
        input,
        FRAME_TYPE_NETWORK_EXECUTE,
        |payload| payload.ok,
    )
}

fn successful_hostcall_payload_json<T, F>(
    input: &str,
    frame_type: &'static str,
    is_success: F,
) -> IpcResult<String>
where
    T: DeserializeOwned,
    F: FnOnce(&T) -> bool,
{
    let (frame, response) = parse_hostcall_response_frame::<T>(input, frame_type)?;
    match response {
        HostcallResponsePayload::Success(payload) if is_success(&payload) => {
            Ok(frame.payload.get().to_string())
        }
        HostcallResponsePayload::Success(_) => Err(protocol_violation(
            "hostcall success response ok must be true",
        )),
        HostcallResponsePayload::Failure(failure) => Err(validated_hostcall_failure(failure)?),
    }
}

fn parse_validated_hostcall_success<T, F>(
    input: &str,
    frame_type: &'static str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    is_success: F,
) -> IpcResult<T>
where
    T: DeserializeOwned,
    F: FnOnce(&T) -> bool,
{
    let (frame, response) = parse_hostcall_response_frame::<T>(input, frame_type)?;
    validate_hostcall_response_identity(
        &frame,
        expected_request_id,
        expected_runtime_generation_id,
        frame_type,
    )?;
    match response {
        HostcallResponsePayload::Success(payload) if is_success(&payload) => Ok(payload),
        HostcallResponsePayload::Success(_) => Err(protocol_violation(
            "hostcall success response ok must be true",
        )),
        HostcallResponsePayload::Failure(failure) => Err(validated_hostcall_failure(failure)?),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleGrantValidationRequest {
    pub handle_grant_token: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub runtime_instance_id: String,
    pub runtime_generation_id: String,
    pub runtime_shard_id: String,
    pub owner_session_hash: String,
    pub owner_user_hash: String,
    pub owner_env_hash: String,
    pub session_channel_id_hash: String,
    pub handle_id: String,
    pub method: String,
    pub resource_scope: NetworkResourceScope,
    pub policy_revision: u64,
    pub management_revision: u64,
    pub revoke_epoch: u64,
}

pub fn validate_handle_grant_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &HandleGrantValidationRequest,
) -> IpcResult<String> {
    for (value, field) in [
        (request_id, "request_id"),
        (runtime_generation_id, "runtime_generation_id"),
        (&req.handle_grant_token, "handle_grant_token"),
        (&req.plugin_instance_id, "plugin_instance_id"),
        (&req.active_fingerprint, "active_fingerprint"),
        (&req.runtime_instance_id, "runtime_instance_id"),
        (&req.runtime_generation_id, "runtime_generation_id"),
        (&req.runtime_shard_id, "runtime_shard_id"),
        (&req.handle_id, "handle_id"),
        (&req.method, "method"),
    ] {
        if value.trim().is_empty() {
            return Err(invalid_field(field));
        }
    }
    if runtime_generation_id != req.runtime_generation_id {
        return Err(protocol_violation(
            "validate_handle_grant runtime_generation_id mismatch",
        ));
    }
    if !req.resource_scope.valid() {
        return Err(invalid_field("handle grant resource scope"));
    }
    if req.owner_session_hash.trim().is_empty()
        || req.owner_user_hash.trim().is_empty()
        || req.owner_env_hash.trim().is_empty()
        || req.session_channel_id_hash.trim().is_empty()
    {
        return Err(invalid_field("handle grant session audience"));
    }
    if req.resource_scope.owner_env_hash != req.owner_env_hash
        || (req.resource_scope.kind == "user"
            && req.resource_scope.owner_user_hash != req.owner_user_hash)
    {
        return Err(invalid_field("handle grant resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("handle grant resource scope"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"owner_session_hash\":\"{}\",\"owner_user_hash\":\"{}\",\"owner_env_hash\":\"{}\",\"session_channel_id_hash\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"resource_scope\":{},\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_VALIDATE_HANDLE_GRANT,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.handle_grant_token),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        escape_json_string(&req.runtime_instance_id),
        escape_json_string(&req.runtime_generation_id),
        escape_json_string(&req.runtime_shard_id),
        escape_json_string(&req.owner_session_hash),
        escape_json_string(&req.owner_user_hash),
        escape_json_string(&req.owner_env_hash),
        escape_json_string(&req.session_channel_id_hash),
        escape_json_string(&req.handle_id),
        escape_json_string(&req.method),
        resource_scope,
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch
    ))
}

pub fn validate_handle_grant_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_handle_id: &str,
    expected_method: &str,
    expected_resource_scope: &NetworkResourceScope,
) -> IpcResult<()> {
    let (frame, response) = parse_hostcall_response_frame::<HandleGrantSuccessResponsePayload>(
        input,
        FRAME_TYPE_VALIDATE_HANDLE_GRANT,
    )?;
    validate_hostcall_response_identity(
        &frame,
        expected_request_id,
        expected_runtime_generation_id,
        "validate_handle_grant",
    )?;
    let success = match response {
        HostcallResponsePayload::Success(success) if success.ok => success,
        HostcallResponsePayload::Success(_) => {
            return Err(protocol_violation(
                "validate_handle_grant success response ok must be true",
            ));
        }
        HostcallResponsePayload::Failure(failure) => {
            return Err(validated_hostcall_failure(failure)?);
        }
    };
    if success.handle_id != expected_handle_id || success.method != expected_method {
        return Err(protocol_violation(
            "validate_handle_grant audience mismatch",
        ));
    }
    if success.runtime_generation_id != expected_runtime_generation_id {
        return Err(protocol_violation(
            "validate_handle_grant payload runtime_generation_id mismatch",
        ));
    }
    if !success.resource_scope.valid() || success.resource_scope != *expected_resource_scope {
        return Err(protocol_violation(
            "validate_handle_grant payload resource_scope mismatch",
        ));
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
    pub resource_scope: NetworkResourceScope,
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
) -> IpcResult<String> {
    if !req.resource_scope.valid() {
        return Err(invalid_field("storage file resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("storage file resource scope"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"resource_scope\":{},\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"path\":\"{}\",\"data_base64\":\"{}\",\"max_bytes\":{},\"max_entries\":{},\"recursive\":{}}}}}",
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
        resource_scope,
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
    ))
}

pub fn validate_storage_file_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_operation: &str,
) -> IpcResult<()> {
    match expected_operation {
        "read" => parse_validated_hostcall_success::<StorageFileReadSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "write" => parse_validated_hostcall_success::<StorageFileWriteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "delete" => parse_validated_hostcall_success::<StorageFileDeleteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "list" => parse_validated_hostcall_success::<StorageFileListSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_FILE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        _ => Err(invalid_field("storage_file response operation")),
    }?;
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
    pub resource_scope: NetworkResourceScope,
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
) -> IpcResult<String> {
    if !req.resource_scope.valid() {
        return Err(invalid_field("storage kv resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("storage kv resource scope"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"resource_scope\":{},\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"key\":\"{}\",\"value_base64\":\"{}\",\"prefix\":\"{}\",\"max_bytes\":{},\"max_entries\":{}}}}}",
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
        resource_scope,
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
    ))
}

pub fn validate_storage_kv_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_operation: &str,
) -> IpcResult<()> {
    match expected_operation {
        "get" => parse_validated_hostcall_success::<StorageKVGetSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "put" => parse_validated_hostcall_success::<StorageKVPutSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "delete" => parse_validated_hostcall_success::<StorageKVDeleteSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "list" => parse_validated_hostcall_success::<StorageKVListSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_KV,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        _ => Err(invalid_field("storage_kv response operation")),
    }?;
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
    pub resource_scope: NetworkResourceScope,
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
) -> IpcResult<String> {
    if !req.resource_scope.valid() {
        return Err(invalid_field("storage sqlite resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("storage sqlite resource scope"))?;
    let args_json = if req.args_json.trim().is_empty() {
        "[]"
    } else {
        req.args_json.trim()
    };
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"handle_grant_token\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"handle_id\":\"{}\",\"method\":\"{}\",\"resource_scope\":{},\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"operation\":\"{}\",\"store_id\":\"{}\",\"database\":\"{}\",\"sql\":\"{}\",\"args\":{},\"max_rows\":{},\"max_response_bytes\":{},\"timeout_ms\":{}}}}}",
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
        resource_scope,
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
    ))
}

pub fn validate_storage_sqlite_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_operation: &str,
) -> IpcResult<()> {
    match expected_operation {
        "exec" => parse_validated_hostcall_success::<StorageSQLiteExecSuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_SQLITE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| payload.ok,
        )
        .map(|_| ()),
        "query" => parse_validated_hostcall_success::<StorageSQLiteQuerySuccessResponsePayload, _>(
            input,
            FRAME_TYPE_STORAGE_SQLITE,
            expected_request_id,
            expected_runtime_generation_id,
            |payload| {
                payload.ok
                    && payload
                        .rows
                        .iter()
                        .flatten()
                        .all(StorageSQLiteValueResponsePayload::is_exactly_typed)
            },
        )
        .map(|_| ()),
        _ => Err(invalid_field("storage_sqlite response operation")),
    }?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResourceScope {
    pub kind: String,
    pub owner_env_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_user_hash: String,
}

impl NetworkResourceScope {
    fn valid(&self) -> bool {
        valid_owner_hash(&self.owner_env_hash)
            && match self.kind.as_str() {
                "user" => valid_owner_hash(&self.owner_user_hash),
                "environment" => self.owner_user_hash.is_empty(),
                _ => false,
            }
    }
}

fn valid_owner_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=256).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrantRequest {
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub resource_scope: NetworkResourceScope,
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
) -> IpcResult<String> {
    if !req.resource_scope.valid() {
        return Err(invalid_field("network resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("network resource scope"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"resource_scope\":{},\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"connector_id\":\"{}\",\"transport\":\"{}\",\"destination\":\"{}\",\"ttl_ms\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_NETWORK_GRANT,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        resource_scope,
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
    ))
}

pub fn validate_network_grant_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_connector_id: &str,
    expected_transport: &str,
    expected_resource_scope: &NetworkResourceScope,
) -> IpcResult<()> {
    let success = parse_validated_hostcall_success::<NetworkGrantSuccessResponsePayload, _>(
        input,
        FRAME_TYPE_NETWORK_GRANT,
        expected_request_id,
        expected_runtime_generation_id,
        |payload| payload.ok,
    )?;
    let grant_suffix = success.grant_id.strip_prefix("netgrant_");
    if grant_suffix.is_none_or(|suffix| {
        suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(invalid_field("network grant id"));
    }
    if success.connector_id != expected_connector_id || success.transport != expected_transport {
        return Err(protocol_violation("network_grant audience mismatch"));
    }
    if !success.resource_scope.valid() || success.resource_scope != *expected_resource_scope {
        return Err(protocol_violation("network_grant resource scope mismatch"));
    }
    validate_revision_binding(
        success.policy_revision,
        success.management_revision,
        success.revoke_epoch,
    )?;
    if success.runtime_generation_id != expected_runtime_generation_id {
        return Err(protocol_violation(
            "network_grant payload runtime_generation_id mismatch",
        ));
    }
    if success.target_classifier_version != "target-classifier-v2" {
        return Err(protocol_violation(
            "network_grant target classifier version mismatch",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkExecuteRequest {
    pub plugin_id: String,
    pub plugin_instance_id: String,
    pub active_fingerprint: String,
    pub resource_scope: NetworkResourceScope,
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
    pub owner_env_hash: String,
    pub session_channel_id_hash: String,
    pub bridge_channel_id: String,
    pub content_type: String,
}

pub fn network_execute_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &NetworkExecuteRequest,
) -> IpcResult<String> {
    if !req.resource_scope.valid() {
        return Err(invalid_field("network resource scope"));
    }
    validate_revision_binding(
        req.policy_revision,
        req.management_revision,
        req.revoke_epoch,
    )?;
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
    let query: serde_json::Value =
        serde_json::from_str(query_json).map_err(|_| invalid_field("network execute query"))?;
    if !query.is_object() {
        return Err(invalid_field("network execute query"));
    }
    let headers: serde_json::Value =
        serde_json::from_str(headers_json).map_err(|_| invalid_field("network execute headers"))?;
    if !headers.is_object() {
        return Err(invalid_field("network execute headers"));
    }
    let resource_scope = serde_json::to_string(&req.resource_scope)
        .map_err(|_| encode_failed("network resource scope"))?;
    Ok(format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"plugin_id\":\"{}\",\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"resource_scope\":{},\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"connector_id\":\"{}\",\"transport\":\"{}\",\"destination\":\"{}\",\"ttl_ms\":{},\"operation\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"query\":{},\"headers\":{},\"message_type\":\"{}\",\"body_base64\":\"{}\",\"payload_base64\":\"{}\",\"max_request_bytes\":{},\"max_response_bytes\":{},\"max_chunk_bytes\":{},\"max_buffered_bytes\":{},\"timeout_ms\":{},\"stream_id\":\"{}\",\"stream_method\":\"{}\",\"stream_effect\":\"{}\",\"stream_execution\":\"{}\",\"surface_instance_id\":\"{}\",\"owner_session_hash\":\"{}\",\"owner_user_hash\":\"{}\",\"owner_env_hash\":\"{}\",\"session_channel_id_hash\":\"{}\",\"bridge_channel_id\":\"{}\",\"content_type\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_NETWORK_EXECUTE,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(&req.plugin_id),
        escape_json_string(&req.plugin_instance_id),
        escape_json_string(&req.active_fingerprint),
        resource_scope,
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
        escape_json_string(&req.owner_env_hash),
        escape_json_string(&req.session_channel_id_hash),
        escape_json_string(&req.bridge_channel_id),
        escape_json_string(&req.content_type)
    ))
}

pub fn validate_network_execute_response(
    input: &str,
    expected_request_id: &str,
    expected_runtime_generation_id: &str,
    expected_connector_id: &str,
    expected_transport: &str,
) -> IpcResult<()> {
    let success = parse_validated_hostcall_success::<NetworkExecuteSuccessResponsePayload, _>(
        input,
        FRAME_TYPE_NETWORK_EXECUTE,
        expected_request_id,
        expected_runtime_generation_id,
        |payload| payload.ok,
    )?;
    if success.connector_id != expected_connector_id || success.transport != expected_transport {
        return Err(protocol_violation("network_execute audience mismatch"));
    }
    if success.runtime_generation_id != expected_runtime_generation_id {
        return Err(protocol_violation(
            "network_execute payload runtime_generation_id mismatch",
        ));
    }
    Ok(())
}

pub fn validate_hello_frame(input: &str) -> IpcResult<(String, String, String)> {
    let parsed = parse_hello_frame(input)?;
    Ok((
        parsed.request_id,
        parsed.runtime_generation_id,
        parsed.channel_nonce,
    ))
}

pub fn parse_hello_frame(input: &str) -> IpcResult<HelloFrame> {
    let frame: RawIPCFrame = serde_json::from_str(input).map_err(|err| {
        if err.to_string().contains("missing field `request_id`") {
            missing_field("request_id")
        } else if err
            .to_string()
            .contains("missing field `runtime_generation_id`")
        {
            missing_field("runtime_generation_id")
        } else {
            decode_failed("hello frame")
        }
    })?;
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err(protocol_violation("unsupported ipc_version"));
    }
    if frame.frame_type != FRAME_TYPE_HELLO {
        return Err(protocol_violation("expected hello frame"));
    }
    if frame.request_id.trim().is_empty() {
        return Err(invalid_field("request_id"));
    }
    let runtime_generation_id = frame
        .runtime_generation_id
        .as_deref()
        .ok_or_else(|| missing_field("runtime_generation_id"))?;
    if runtime_generation_id.trim().is_empty() {
        return Err(invalid_field("runtime_generation_id"));
    }
    let payload: HelloPayload = serde_json::from_str(frame.payload.get()).map_err(|err| {
        if err.to_string().contains("missing field `channel_nonce`") {
            missing_field("channel_nonce")
        } else {
            decode_failed("hello payload")
        }
    })?;
    let target =
        RuntimeTarget::parse(&payload.target).map_err(|_| invalid_field("hello target"))?;
    if payload.host_process_id == 0 || payload.started_unix_nano == 0 {
        return Err(invalid_field("hello process metadata"));
    }
    if payload.host_ipc_version != RUST_IPC_VERSION {
        return Err(protocol_violation("unsupported host_ipc_version"));
    }
    if payload.host_wasm_abi != WASM_ABI_VERSION {
        return Err(protocol_violation("unsupported host_wasm_abi"));
    }
    if payload.contract_set_sha256 != CONTRACT_SET_SHA256 {
        return Err(protocol_violation("contract_set_sha256 mismatch"));
    }
    if payload.channel_nonce.trim().is_empty() {
        return Err(invalid_field("channel_nonce"));
    }
    let limits = payload.limits.validate()?;
    let runtime_lease_public_keys =
        parse_runtime_lease_public_key_payloads(payload.runtime_lease_public_keys)?;
    Ok(HelloFrame {
        request_id: frame.request_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        target,
        contract_set_sha256: payload.contract_set_sha256,
        channel_nonce: payload.channel_nonce,
        runtime_lease_public_keys,
        limits,
    })
}

pub fn parse_frame_identity(input: &str) -> IpcResult<FrameIdentity> {
    let frame: RawIPCFrame = serde_json::from_str(input).map_err(|err| {
        let message = err.to_string();
        if message.contains("missing field `ipc_version`") {
            missing_field("ipc_version")
        } else if message.contains("missing field `frame_type`") {
            missing_field("frame_type")
        } else if message.contains("missing field `request_id`") {
            missing_field("request_id")
        } else if message.contains("missing field `runtime_generation_id`") {
            missing_field("runtime_generation_id")
        } else if message.contains("missing field `payload`") {
            missing_field("payload")
        } else {
            decode_failed("IPC frame")
        }
    })?;
    validated_frame_identity(&frame)
}

fn validated_frame_identity(frame: &RawIPCFrame) -> IpcResult<FrameIdentity> {
    if frame.ipc_version != RUST_IPC_VERSION {
        return Err(protocol_violation("unsupported ipc_version"));
    }
    if frame.frame_type.trim().is_empty() {
        return Err(invalid_field("frame_type"));
    }
    if frame.request_id.trim().is_empty() {
        return Err(invalid_field("request_id"));
    }
    let runtime_generation_id = frame
        .runtime_generation_id
        .as_deref()
        .ok_or_else(|| missing_field("runtime_generation_id"))?;
    if runtime_generation_id.trim().is_empty() {
        return Err(invalid_field("runtime_generation_id"));
    }
    if frame
        .parent_request_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(invalid_field("parent_request_id"));
    }
    Ok(FrameIdentity {
        frame_type: frame.frame_type.clone(),
        request_id: frame.request_id.clone(),
        parent_request_id: frame.parent_request_id.clone(),
        runtime_generation_id: runtime_generation_id.to_string(),
    })
}

pub fn decode_runtime_input_frame(input: &str) -> IpcResult<RuntimeInputFrame> {
    let frame = parse_raw_frame(input)?;
    let identity = validated_frame_identity(&frame)?;
    match identity.frame_type.as_str() {
        FRAME_TYPE_INVOKE_WORKER => {
            let invocation = parsed_worker_invocation(&identity, frame.payload.as_ref());
            Ok(RuntimeInputFrame::InvokeWorker(Box::new(
                WorkerInvocationInput {
                    identity,
                    invocation,
                },
            )))
        }
        FRAME_TYPE_CANCEL_INVOKE => {
            if identity.parent_request_id.is_some() {
                return Err(protocol_violation(
                    "cancel_invoke must not have parent_request_id",
                ));
            }
            let payload: CancelInvokePayload = serde_json::from_str(frame.payload.get())
                .map_err(|_| decode_failed("cancel_invoke payload"))?;
            if payload.invocation_request_id.trim().is_empty() {
                return Err(invalid_field("cancel invocation_request_id"));
            }
            Ok(RuntimeInputFrame::CancelInvoke(CancelInvocationInput {
                identity,
                invocation_request_id: payload.invocation_request_id,
            }))
        }
        FRAME_TYPE_OPEN_HANDLE
        | FRAME_TYPE_VALIDATE_HANDLE_GRANT
        | FRAME_TYPE_STORAGE_FILE
        | FRAME_TYPE_STORAGE_KV
        | FRAME_TYPE_STORAGE_SQLITE
        | FRAME_TYPE_NETWORK_GRANT
        | FRAME_TYPE_NETWORK_EXECUTE => {
            if identity.parent_request_id.is_none() {
                return Err(missing_field("runtime hostcall response parent_request_id"));
            }
            Ok(RuntimeInputFrame::HostcallResponse(
                RuntimeHostcallResponseInput {
                    identity,
                    raw_frame: input.to_string(),
                },
            ))
        }
        _ => Ok(RuntimeInputFrame::Unsupported(identity)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInvocationIdentity {
    pub package_hash: String,
    pub artifact: String,
    pub artifact_sha256: String,
    pub worker_id: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerResponseV2 {
    Success(String),
    Failure { code: String, message: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkerResponseV2<'a> {
    ok: bool,
    #[serde(borrow)]
    data: Option<&'a serde_json::value::RawValue>,
    error_code: Option<String>,
    message: Option<String>,
}

pub fn worker_request_json_v2(input: &str) -> IpcResult<String> {
    parse_worker_invocation(input)?.worker_request_json_v2()
}

pub fn runtime_lease_memory_limit_bytes(input: &str) -> IpcResult<usize> {
    parse_worker_invocation(input)?.memory_limit_bytes()
}

pub fn worker_storage_handle_grant(input: &str, store_id: &str) -> IpcResult<String> {
    parse_worker_invocation(input)?.storage_handle_grant(store_id)
}

pub fn validate_worker_storage_broker_access(
    input: &str,
    store_id: &str,
    operation: &str,
) -> IpcResult<()> {
    parse_worker_invocation(input)?.validate_storage_broker_access(store_id, operation)
}

pub fn validate_worker_network_broker_access(
    input: &str,
    connector_id: &str,
    transport: &str,
    operation: &str,
    http_method: &str,
) -> IpcResult<()> {
    parse_worker_invocation(input)?.validate_network_broker_access(
        connector_id,
        transport,
        operation,
        http_method,
    )
}

pub fn parse_worker_response_v2(input: &str) -> IpcResult<WorkerResponseV2> {
    let response: RawWorkerResponseV2<'_> =
        serde_json::from_str(input).map_err(|_| decode_failed("worker response"))?;
    if response.ok {
        if response.error_code.is_some() || response.message.is_some() {
            return Err(protocol_violation(
                "worker success response contains failure fields",
            ));
        }
        let data = response
            .data
            .ok_or_else(|| missing_field("worker success response data"))?;
        return Ok(WorkerResponseV2::Success(data.get().to_string()));
    }
    if response.data.is_some() {
        return Err(protocol_violation(
            "worker failure response contains success data",
        ));
    }
    let error_code = response
        .error_code
        .ok_or_else(|| missing_field("worker failure response error_code"))?;
    let message = response
        .message
        .ok_or_else(|| missing_field("worker failure response message"))?;
    if !is_stable_worker_error_code(&error_code) {
        return Err(invalid_field("worker failure response error_code"));
    }
    if message.trim().is_empty() || message.len() > 4096 {
        return Err(invalid_field("worker failure response message"));
    }
    Ok(WorkerResponseV2::Failure {
        code: error_code,
        message,
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

pub fn parse_worker_lease_replay_key(input: &str) -> IpcResult<WorkerLeaseReplayKey> {
    parse_worker_invocation(input)?.replay_key()
}

pub fn parse_worker_invocation_identity(input: &str) -> IpcResult<WorkerInvocationIdentity> {
    parse_worker_invocation(input)?.identity()
}

pub fn worker_invocation_not_implemented_message(identity: &WorkerInvocationIdentity) -> String {
    format!(
        "runtime worker execution is not implemented for {}:{}",
        identity.worker_id, identity.method
    )
}

pub fn validate_worker_artifact_bytes(
    identity: &WorkerInvocationIdentity,
    content: &[u8],
) -> IpcResult<()> {
    let actual = format!("sha256:{}", lowercase_hex(&Sha256::digest(content)));
    if actual != identity.artifact_sha256 {
        return Err(protocol_violation(
            "worker artifact content does not match artifact_sha256",
        ));
    }
    Ok(())
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

    fn runtime_limits() -> RuntimeLimits {
        RuntimeLimits {
            worker_count: 8,
            queue_capacity: 32,
            per_plugin_concurrency: 4,
            module_cache_entries: 64,
            module_cache_source_bytes: 128 * 1024 * 1024,
        }
    }

    fn invalid_runtime_limits() -> RuntimeLimits {
        RuntimeLimits {
            worker_count: 1,
            per_plugin_concurrency: 2,
            ..runtime_limits()
        }
    }

    fn process_containment() -> ProcessContainmentEvidence {
        ProcessContainmentEvidence {
            schema_version: "redevplugin.process_containment.v1".to_string(),
            profile: "linux-runtime-v1".to_string(),
            seccomp_policy_sha256:
                "6305735925c1fbacaf4950df2e535d3a11cebec8ab7aa16ce37fca3c31745543".to_string(),
            no_new_privs: true,
            seccomp_tsync: true,
            process_creation_denied: true,
            reexec_denied: true,
            active: true,
        }
    }

    #[test]
    fn runtime_limit_constants_match_the_ipc_schema() {
        let schema: Value = serde_json::from_str(contract_fixture(
            redevplugin_contracts::ContractId::RUST_IPC_SCHEMA,
        ))
        .expect("IPC schema");
        let properties = schema["$defs"]["runtime_limits"]["properties"]
            .as_object()
            .expect("runtime limit properties");
        for (field, minimum, maximum) in [
            (
                "worker_count",
                MIN_RUNTIME_WORKER_COUNT,
                MAX_RUNTIME_WORKER_COUNT,
            ),
            (
                "queue_capacity",
                MIN_RUNTIME_QUEUE_CAPACITY,
                MAX_RUNTIME_QUEUE_CAPACITY,
            ),
            (
                "per_plugin_concurrency",
                MIN_RUNTIME_PER_PLUGIN_CONCURRENCY,
                MAX_RUNTIME_PER_PLUGIN_CONCURRENCY,
            ),
            (
                "module_cache_entries",
                MIN_RUNTIME_MODULE_CACHE_ENTRIES,
                MAX_RUNTIME_MODULE_CACHE_ENTRIES,
            ),
            (
                "module_cache_source_bytes",
                MIN_RUNTIME_MODULE_CACHE_SOURCE_BYTES,
                MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES,
            ),
        ] {
            let property = properties.get(field).expect("runtime limit property");
            assert_eq!(property["minimum"].as_u64(), Some(minimum as u64));
            assert_eq!(property["maximum"].as_u64(), Some(maximum as u64));
        }
    }

    #[test]
    fn runtime_limits_enforce_all_platform_bounds() {
        RuntimeLimits {
            worker_count: MAX_RUNTIME_WORKER_COUNT,
            queue_capacity: MAX_RUNTIME_QUEUE_CAPACITY,
            per_plugin_concurrency: MAX_RUNTIME_PER_PLUGIN_CONCURRENCY,
            module_cache_entries: MAX_RUNTIME_MODULE_CACHE_ENTRIES,
            module_cache_source_bytes: MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES,
        }
        .validate()
        .expect("maximum runtime limits");

        for invalid in [
            RuntimeLimits {
                worker_count: 0,
                queue_capacity: 0,
                per_plugin_concurrency: 0,
                module_cache_entries: 0,
                module_cache_source_bytes: 0,
            },
            RuntimeLimits {
                worker_count: MAX_RUNTIME_WORKER_COUNT + 1,
                ..runtime_limits()
            },
            RuntimeLimits {
                queue_capacity: MAX_RUNTIME_QUEUE_CAPACITY + 1,
                ..runtime_limits()
            },
            RuntimeLimits {
                per_plugin_concurrency: MAX_RUNTIME_PER_PLUGIN_CONCURRENCY + 1,
                ..runtime_limits()
            },
            invalid_runtime_limits(),
            RuntimeLimits {
                module_cache_entries: MAX_RUNTIME_MODULE_CACHE_ENTRIES + 1,
                ..runtime_limits()
            },
            RuntimeLimits {
                module_cache_source_bytes: MAX_RUNTIME_MODULE_CACHE_SOURCE_BYTES + 1,
                ..runtime_limits()
            },
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(IpcError::ProtocolViolation { .. })
            ));
        }
    }

    fn user_resource_scope() -> NetworkResourceScope {
        NetworkResourceScope {
            kind: "user".to_string(),
            owner_env_hash: "env_hash".to_string(),
            owner_user_hash: "user_hash".to_string(),
        }
    }

    fn environment_resource_scope() -> NetworkResourceScope {
        NetworkResourceScope {
            kind: "environment".to_string(),
            owner_env_hash: "env_hash".to_string(),
            owner_user_hash: String::new(),
        }
    }

    fn handle_grant_validation_request() -> HandleGrantValidationRequest {
        HandleGrantValidationRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            owner_session_hash: "session_hash".to_string(),
            owner_user_hash: "user_hash".to_string(),
            owner_env_hash: "env_hash".to_string(),
            session_channel_id_hash: "channel_hash".to_string(),
            handle_id: "storage:db".to_string(),
            method: "storage.sqlite".to_string(),
            resource_scope: user_resource_scope(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 3,
        }
    }

    #[test]
    fn resource_scopes_match_the_closed_owner_hash_contract() {
        let maximum_hash = format!("a{}", "b".repeat(255));
        for valid in [
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: maximum_hash.clone(),
                owner_user_hash: "user.hash:_-1".to_string(),
            },
            NetworkResourceScope {
                kind: "environment".to_string(),
                owner_env_hash: maximum_hash,
                owner_user_hash: String::new(),
            },
        ] {
            assert!(valid.valid(), "valid resource scope rejected: {valid:?}");
        }

        for invalid in [
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: String::new(),
                owner_user_hash: "user_hash".to_string(),
            },
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: " env_hash".to_string(),
                owner_user_hash: "user_hash".to_string(),
            },
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: "env/hash".to_string(),
                owner_user_hash: "user_hash".to_string(),
            },
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: "env_hash".to_string(),
                owner_user_hash: "user_hash ".to_string(),
            },
            NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: "env_hash".to_string(),
                owner_user_hash: String::new(),
            },
            NetworkResourceScope {
                kind: "environment".to_string(),
                owner_env_hash: "env_hash".to_string(),
                owner_user_hash: " ".to_string(),
            },
            NetworkResourceScope {
                kind: "environment".to_string(),
                owner_env_hash: "a".repeat(257),
                owner_user_hash: String::new(),
            },
            NetworkResourceScope {
                kind: "environment".to_string(),
                owner_env_hash: "\u{73af}\u{5883}".to_string(),
                owner_user_hash: String::new(),
            },
        ] {
            assert!(
                !invalid.valid(),
                "invalid resource scope accepted: {invalid:?}"
            );
        }
    }

    fn closed_worker_frame(lease: &str, invocation: &str) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{lease},"method":"worker.echo","invocation":{invocation}}}}}"#
        )
    }

    fn worker_lease_from_value(value: &serde_json::Value) -> WorkerLeasePayload {
        serde_json::from_value(value.clone()).expect("typed worker lease")
    }

    fn worker_lease_from_object(
        value: &serde_json::Map<String, serde_json::Value>,
    ) -> WorkerLeasePayload {
        worker_lease_from_value(&serde_json::Value::Object(value.clone()))
    }

    fn hello_frame(channel_nonce: Option<&str>, public_keys: &str) -> String {
        let channel_nonce = channel_nonce
            .map(|value| format!(",\"channel_nonce\":\"{value}\""))
            .unwrap_or_default();
        format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"hello","request_id":"r1","runtime_generation_id":"g1","payload":{{"target":"linux/amd64","host_process_id":1,"host_ipc_version":"rust-ipc-v6","host_wasm_abi":"redevplugin-wasm-worker-v2","contract_set_sha256":"{CONTRACT_SET_SHA256}","started_unix_nano":1{channel_nonce},"runtime_lease_public_keys":{public_keys},"limits":{{"worker_count":8,"queue_capacity":32,"per_plugin_concurrency":4,"module_cache_entries":64,"module_cache_source_bytes":134217728}}}}}}"#
        )
    }

    fn hostcall_response_frame(frame_type: &str, payload: &str) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"{frame_type}","request_id":"r1","runtime_generation_id":"g1","payload":{payload}}}"#
        )
    }

    fn without_payload_field(frame: &str, field: &str) -> String {
        let mut value: Value = serde_json::from_str(frame).expect("hostcall response frame");
        value["payload"]
            .as_object_mut()
            .expect("hostcall response payload")
            .remove(field)
            .unwrap_or_else(|| panic!("hostcall response payload missing {field}"));
        serde_json::to_string(&value).expect("hostcall response json")
    }

    fn validate_test_hostcall_response<T: DeserializeOwned>(
        frame_type: &'static str,
        payload: &str,
    ) -> IpcResult<()> {
        let frame = hostcall_response_frame(frame_type, payload);
        let (_, response) = parse_hostcall_response_frame::<T>(&frame, frame_type)?;
        match response {
            HostcallResponsePayload::Success(_) => Ok(()),
            HostcallResponsePayload::Failure(failure) => {
                validated_hostcall_failure(failure).map(|_| ())
            }
        }
    }

    fn assert_closed_hostcall_response_union<T: DeserializeOwned>(
        frame_type: &'static str,
        success_payload: &str,
        success_field: &str,
    ) {
        validate_test_hostcall_response::<T>(frame_type, success_payload)
            .unwrap_or_else(|err| panic!("valid {frame_type} success response: {err}"));

        let success_prefix = success_payload
            .strip_suffix('}')
            .expect("success response object");
        let duplicate_success_field = success_payload.replacen(
            success_field,
            &format!("{success_field},{success_field}"),
            1,
        );
        let failure =
            r#"{"ok":false,"code":"HOSTCALL_FAILED","message":"failed","error_origin":"hostcall"}"#;
        let failure_prefix = failure.strip_suffix('}').expect("failure response object");
        let invalid = [
            format!(r#"{success_prefix},"future":true}}"#),
            success_payload.replacen(r#""ok":true"#, r#""ok":true,"ok":false"#, 1),
            success_payload.replacen(r#""ok":true"#, r#""ok":true,"OK":false"#, 1),
            duplicate_success_field,
            format!(r#"{success_prefix},"code":"HOSTCALL_FAILED"}}"#),
            format!(r#"{failure_prefix},{success_field}}}"#),
            format!(r#"{failure_prefix},"future":true}}"#),
            r#"{"ok":false,"code":"HOSTCALL_FAILED","message":"failed"}"#.to_string(),
            r#"{"ok":false,"code":"HOSTCALL_FAILED","message":"failed","error_origin":"runtime"}"#
                .to_string(),
        ];
        for payload in invalid {
            assert!(
                validate_test_hostcall_response::<T>(frame_type, &payload).is_err(),
                "{frame_type} accepted non-closed response payload {payload}"
            );
        }
    }

    #[test]
    fn hostcall_response_unions_reject_ambiguous_or_extended_payloads() {
        assert_closed_hostcall_response_union::<OpenHandleSuccessResponsePayload>(
            FRAME_TYPE_OPEN_HANDLE,
            r#"{"ok":true,"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"AGFzbQ=="}"#,
            r#""content_base64":"AGFzbQ==""#,
        );
        assert_closed_hostcall_response_union::<HandleGrantSuccessResponsePayload>(
            FRAME_TYPE_VALIDATE_HANDLE_GRANT,
            r#"{"ok":true,"handle_grant_id":"grant_1","handle_id":"storage:settings","method":"storage.kv","runtime_generation_id":"g1","resource_scope":{"kind":"user","owner_env_hash":"env_hash","owner_user_hash":"user_hash"}}"#,
            r#""handle_id":"storage:settings""#,
        );
        assert_closed_hostcall_response_union::<StorageFileDeleteSuccessResponsePayload>(
            FRAME_TYPE_STORAGE_FILE,
            r#"{"ok":true,"path":"notes/a.txt"}"#,
            r#""path":"notes/a.txt""#,
        );
        assert_closed_hostcall_response_union::<StorageKVDeleteSuccessResponsePayload>(
            FRAME_TYPE_STORAGE_KV,
            r#"{"ok":true,"key":"settings/theme"}"#,
            r#""key":"settings/theme""#,
        );
        assert_closed_hostcall_response_union::<StorageSQLiteExecSuccessResponsePayload>(
            FRAME_TYPE_STORAGE_SQLITE,
            r#"{"ok":true,"database":"plugin.sqlite","rows_affected":1,"usage":{"plugin_instance_id":"plugini_1","store_id":"db","usage_bytes":1,"quota_bytes":100,"usage_files":1,"quota_files":10}}"#,
            r#""database":"plugin.sqlite""#,
        );
        assert_closed_hostcall_response_union::<NetworkGrantSuccessResponsePayload>(
            FRAME_TYPE_NETWORK_GRANT,
            r#"{"ok":true,"grant_id":"netgrant_00112233445566778899aabbccddeeff","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","resource_scope":{"kind":"user","owner_env_hash":"env_hash","owner_user_hash":"user_hash"},"policy_revision":1,"management_revision":2,"revoke_epoch":3,"connector_id":"api","transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"runtime_generation_id":"g1","target_classifier_version":"target-classifier-v2","expires_at":"2026-06-30T10:00:30Z"}"#,
            r#""grant_id":"netgrant_00112233445566778899aabbccddeeff""#,
        );
        assert_closed_hostcall_response_union::<NetworkExecuteSuccessResponsePayload>(
            FRAME_TYPE_NETWORK_EXECUTE,
            r#"{"ok":true,"transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"status_code":200,"grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","runtime_generation_id":"g1"}"#,
            r#""status_code":200"#,
        );
    }

    #[test]
    fn validates_hello_frame() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let input = hello_frame(
            Some("nonce_1234567890"),
            &format!(
                r#"[{{"algorithm":"ed25519","key_id":"host_ephemeral_key_1","public_key_base64":"{public_key}"}}]"#
            ),
        );
        let (request_id, generation_id, channel_nonce) =
            validate_hello_frame(&input).expect("valid hello");
        assert_eq!(request_id, "r1");
        assert_eq!(generation_id, "g1");
        assert_eq!(channel_nonce, "nonce_1234567890");
        let parsed = parse_hello_frame(&input).expect("typed hello");
        assert_eq!(parsed.target, RuntimeTarget::LinuxAmd64);
        assert_eq!(parsed.limits, runtime_limits());
    }

    #[test]
    fn runtime_target_enum_covers_only_canonical_linux_targets() {
        for (value, expected) in [
            ("linux/amd64", RuntimeTarget::LinuxAmd64),
            ("linux/arm64", RuntimeTarget::LinuxArm64),
        ] {
            let parsed = RuntimeTarget::parse(value).expect("canonical runtime target");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), value);
        }
        for value in [
            "linux/x86_64",
            "darwin/amd64",
            "darwin/arm64",
            "windows/amd64",
            "Linux/amd64",
            "linux-amd64",
        ] {
            assert_eq!(
                RuntimeTarget::parse(value).unwrap_err(),
                IpcError::ProtocolViolation {
                    message: "unsupported runtime target"
                }
            );
        }
    }

    #[test]
    fn rejects_noncanonical_hello_targets() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let valid = hello_frame(
            Some("nonce_1234567890"),
            &format!(
                r#"[{{"algorithm":"ed25519","key_id":"host_ephemeral_key_1","public_key_base64":"{public_key}"}}]"#
            ),
        );
        for invalid in [
            valid.replace("linux/amd64", "darwin/amd64"),
            valid.replace("linux/amd64", "linux/x86_64"),
        ] {
            assert_eq!(
                parse_hello_frame(&invalid).unwrap_err(),
                IpcError::InvalidField {
                    field: "hello target"
                }
            );
        }
    }

    #[test]
    fn rejects_v2_and_invalid_runtime_limits() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let valid = hello_frame(
            Some("nonce_1234567890"),
            &format!(
                r#"[{{"algorithm":"ed25519","key_id":"host_ephemeral_key_1","public_key_base64":"{public_key}"}}]"#
            ),
        );
        assert!(parse_hello_frame(&valid.replace("rust-ipc-v6", "rust-ipc-v2")).is_err());
        assert!(
            parse_hello_frame(&valid.replacen("\"worker_count\":8", "\"worker_count\":0", 1))
                .is_err()
        );
        assert!(
            parse_hello_frame(&valid.replacen(
                "\"module_cache_source_bytes\":134217728",
                "\"module_cache_source_bytes\":134217729",
                1,
            ))
            .is_err()
        );
        assert!(
            parse_hello_frame(&valid.replacen(
                "\"per_plugin_concurrency\":4",
                "\"per_plugin_concurrency\":9",
                1,
            ))
            .is_err()
        );
    }

    #[test]
    fn runtime_route_capacities_are_closed_derivations_of_hello_limits() {
        let limits = runtime_limits().validate().unwrap();
        assert_eq!(limits.hostcall_active_route_capacity(), limits.worker_count);
        assert_eq!(
            limits.hostcall_canceled_route_capacity().unwrap(),
            limits.worker_count + limits.queue_capacity
        );
        assert_eq!(limits.compile_flight_route_capacity(), limits.worker_count);
    }

    #[test]
    fn decodes_invalid_worker_input_once_into_a_typed_runtime_variant() {
        let input = r#"{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"invoke-invalid","runtime_generation_id":"g1","payload":{"method":"worker.echo","invocation":{}}}"#;
        let decoded = decode_runtime_input_frame(input).expect("outer IPC frame decodes");
        let RuntimeInputFrame::InvokeWorker(worker) = decoded else {
            panic!("invoke_worker must use the typed worker variant");
        };
        assert_eq!(worker.identity.request_id, "invoke-invalid");
        assert_eq!(worker.identity.runtime_generation_id, "g1");
        assert!(worker.invocation.is_err());
    }

    #[test]
    fn parses_cancel_and_binds_parent_request_id() {
        let cancel = r#"{"ipc_version":"rust-ipc-v6","frame_type":"cancel_invoke","request_id":"cancel-1","runtime_generation_id":"g1","payload":{"invocation_request_id":"invoke-1"}}"#;
        assert_eq!(parse_cancel_invoke(cancel).unwrap(), "invoke-1");
        let ack = cancel_invoke_ack_frame("cancel-1", "g1", "invoke-1", "running")
            .expect("cancel acknowledgement frame");
        assert!(ack.contains(r#""frame_type":"cancel_invoke_ack""#));
        let hostcall = bind_parent_request_id(
            r#"{"ipc_version":"rust-ipc-v6","frame_type":"open_handle","request_id":"invoke-1:artifact","runtime_generation_id":"g1","payload":{}}"#,
            "invoke-1",
        )
        .unwrap();
        assert_eq!(
            parse_frame_identity(&hostcall).unwrap().parent_request_id,
            Some("invoke-1".to_string())
        );
    }

    #[test]
    fn closed_ipc_decoding_rejects_ambiguous_or_extended_frames() {
        let valid = r#"{"ipc_version":"rust-ipc-v6","frame_type":"heartbeat","request_id":"outer","runtime_generation_id":"g1","payload":{"request_id":"nested"}}"#;
        let identity = parse_frame_identity(valid).expect("top-level frame identity");
        assert_eq!(identity.request_id, "outer");

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
    fn runtime_hostcall_response_requires_nonempty_parent_request_id() {
        let without_parent = r#"{"ipc_version":"rust-ipc-v6","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{"ok":false,"code":"ARTIFACT_HANDLE_FAILED","message":"unavailable","error_origin":"hostcall"}}"#;
        assert!(decode_runtime_input_frame(without_parent).is_err());
        let empty_parent = without_parent.replace(
            r#""request_id":"r1:artifact""#,
            r#""request_id":"r1:artifact","parent_request_id":"""#,
        );
        assert!(decode_runtime_input_frame(&empty_parent).is_err());
    }

    #[test]
    fn closed_worker_decoding_rejects_unknown_duplicate_and_trailing_fields() {
        let valid = closed_worker_frame(
            r#"{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed","policy_revision":1,"management_revision":2,"revoke_epoch":1}"#,
            r#"{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","method":"worker.echo"}"#,
        );
        let context = parse_worker_invocation_context(&valid).expect("closed worker invocation");
        assert_eq!(context.runtime_shard_id, "runtime_shard_signed");

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
                r#""runtime_instance_id":"runtime_1""#,
                r#""runtime_instance_id":"runtime_1","runtime_shard_id":"runtime_shard_spoofed""#,
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
    fn worker_frame_initial_decode_types_params_and_broker_access() {
        for invocation in [
            r#"{"method":"worker.echo","params":[]}"#,
            r#"{"method":"worker.echo","broker_access":{"unknown":true}}"#,
            r#"{"method":"worker.echo","broker_access":{"storage":[{"store_id":"notes","scope":"user","operations":["read"],"unknown":true}]}}"#,
        ] {
            let error = match parse_worker_invocation(&closed_worker_frame("{}", invocation)) {
                Ok(_) => panic!("typed invocation fields must fail during initial frame decode"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                IpcError::DecodeFailed {
                    context: "worker frame payload"
                }
            );
        }

        let invocation = r#"{"method":"worker.echo","params":{"title":"Launch notes","body":"<script>&\u2028"},"broker_access":{"storage":[{"store_id":"notes","scope":"user","operations":["read"]}]}}"#;
        serde_json::from_str::<WorkerInvocationPayload>(invocation)
            .expect("direct typed worker invocation payload");
        let parsed = parse_worker_invocation(&closed_worker_frame("{}", invocation))
            .expect("typed worker invocation");
        assert_eq!(
            parsed.params_json.as_deref(),
            Some(r#"{"body":"<script>&\u2028","title":"Launch notes"}"#)
        );
        assert_eq!(
            parsed.broker_access_json.as_deref(),
            Some(r#"{"storage":[{"store_id":"notes","scope":"user","operations":["read"]}]}"#)
        );
    }

    #[test]
    fn rejects_hello_frame_without_channel_nonce() {
        let input = hello_frame(None, "[]");
        assert_eq!(
            validate_hello_frame(&input),
            Err(IpcError::MissingField {
                field: "channel_nonce"
            })
        );
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
        assert_eq!(
            err,
            IpcError::InvalidField {
                field: "runtime lease signature"
            }
        );
    }

    #[test]
    fn rejects_unsigned_worker_runtime_lease_when_keys_are_configured() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let signed = signed_runtime_lease_invocation_for_test(&signing_key, None);
        let mut frame: serde_json::Value = serde_json::from_str(&signed).expect("signed frame");
        frame["payload"]["lease"]
            .as_object_mut()
            .expect("lease object")
            .remove("signature");
        let frame = serde_json::to_string(&frame).expect("unsigned frame");
        let err = verify_worker_runtime_lease_signature(
            &frame,
            &[RuntimeLeasePublicKey {
                key_id: "host_ephemeral_key_1".to_string(),
                public_key: signing_key.verifying_key().to_bytes(),
            }],
        )
        .expect_err("missing signature should fail");
        assert_eq!(err, IpcError::MissingField { field: "signature" });
    }

    #[test]
    fn runtime_lease_signature_requires_closed_contract_fields() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let signed = signed_runtime_lease_invocation_for_test(&signing_key, None);
        let frame: serde_json::Value = serde_json::from_str(&signed).expect("signed frame");
        let lease = frame["payload"]["lease"]
            .as_object()
            .expect("lease object")
            .clone();
        let method = frame["payload"]["method"].as_str().expect("method");

        for field in [
            "plugin_id",
            "plugin_version",
            "active_fingerprint",
            "owner_env_hash",
            "target_descriptor_hashes",
            "limits",
            "policy_revision",
            "management_revision",
            "revoke_epoch",
            "runtime_shard_id",
            "runtime_instance_id",
            "ipc_channel_id",
            "connection_nonce",
        ] {
            let mut missing = lease.clone();
            missing.remove(field);
            assert!(
                runtime_lease_signature_payload_json(&worker_lease_from_object(&missing), method)
                    .is_err(),
                "accepted lease without {field}"
            );
        }

        let mut zero_revoke_epoch = lease.clone();
        zero_revoke_epoch.insert("revoke_epoch".to_string(), serde_json::Value::from(0));
        assert_eq!(
            runtime_lease_signature_payload_json(
                &worker_lease_from_object(&zero_revoke_epoch),
                method
            )
            .unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );

        for field in [
            "timeout_ms",
            "memory_bytes",
            "max_payload_bytes",
            "max_stream_bytes_per_sec",
        ] {
            let mut missing = lease.clone();
            missing["limits"]
                .as_object_mut()
                .expect("limits object")
                .remove(field);
            assert!(
                runtime_lease_signature_payload_json(&worker_lease_from_object(&missing), method)
                    .is_err(),
                "accepted limits without {field}"
            );
        }

        let mut zero_limits = lease;
        for field in [
            "timeout_ms",
            "max_payload_bytes",
            "max_stream_bytes_per_sec",
        ] {
            zero_limits["limits"][field] = serde_json::Value::from(0);
        }
        let canonical =
            runtime_lease_signature_payload_json(&worker_lease_from_object(&zero_limits), method)
                .expect("zero-valued optional quota dimensions remain explicit");
        for field in [
            "\"timeout_ms\":0",
            "\"max_payload_bytes\":0",
            "\"max_stream_bytes_per_sec\":0",
        ] {
            assert!(
                canonical.contains(field),
                "canonical payload omitted {field}"
            );
        }
    }

    #[test]
    fn rejects_worker_runtime_lease_without_runtime_keys() {
        let signing_key = runtime_lease_signing_key_for_test(7);
        let frame = signed_runtime_lease_invocation_for_test(&signing_key, None);
        let err = verify_worker_runtime_lease_signature(&frame, &[])
            .expect_err("missing runtime keyring should fail closed");
        assert_eq!(
            err,
            IpcError::MissingField {
                field: "runtime lease public keys"
            }
        );
    }

    #[test]
    fn validates_worker_runtime_lease_expiry_and_execution_binding() {
        let frame = runtime_lease_invocation_fixture();
        validate_worker_runtime_lease(frame, 1_783_161_901_000)
            .expect("current runtime lease binding");

        let expired = validate_worker_runtime_lease(frame, 1_783_161_930_000)
            .expect_err("expired runtime lease must fail closed");
        assert_eq!(
            expired,
            IpcError::ProtocolViolation {
                message: "runtime execution lease is expired"
            }
        );

        let mut mismatched: Value = serde_json::from_str(frame).expect("invocation fixture");
        mismatched["payload"]["invocation"]["stream_id"] =
            Value::String("stream_other".to_string());
        let mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&mismatched).expect("mismatched invocation"),
            1_783_161_901_000,
        )
        .expect_err("execution handle mismatch must fail closed");
        assert_eq!(mismatch, IpcError::InvalidField { field: "stream_id" });

        let mut wrong_environment: Value = serde_json::from_str(frame).expect("invocation fixture");
        wrong_environment["payload"]["invocation"]["owner_env_hash"] =
            Value::String("environment_other".to_string());
        let environment_mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&wrong_environment).expect("mismatched environment"),
            1_783_161_901_000,
        )
        .expect_err("environment mismatch must fail closed");
        assert_eq!(
            environment_mismatch,
            IpcError::InvalidField {
                field: "owner_env_hash"
            }
        );

        let mut tampered_params: Value = serde_json::from_str(frame).expect("invocation fixture");
        tampered_params["payload"]["invocation"]["params"]["message"] =
            Value::String("tampered".to_string());
        let params_mismatch = validate_worker_runtime_lease(
            &serde_json::to_string(&tampered_params).expect("tampered invocation"),
            1_783_161_901_000,
        )
        .expect_err("tampered params must fail closed");
        assert_eq!(
            params_mismatch,
            IpcError::ProtocolViolation {
                message: "worker invocation params_sha256 does not match params"
            }
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
        assert_eq!(
            target_mismatch,
            IpcError::ProtocolViolation {
                message: "runtime lease does not bind the worker invocation target"
            }
        );
    }

    #[test]
    fn runtime_lease_signature_payload_matches_go_canonical_order() {
        let lease = serde_json::json!({
            "lease_id": "rel_lease_signature",
            "token_id": "rel_token_signature",
            "lease_nonce": "nonce_1234567890",
            "runtime_generation_id": "rtgen_1",
            "plugin_instance_id": "plugini_1",
            "plugin_id": "com.example.worker",
            "plugin_version": "1.2.3",
            "active_fingerprint": "sha256:active",
            "issued_at_unix_ms": 1783161900000_i64,
            "method": "worker.echo",
            "effect": "read",
            "execution": "sync",
            "audit_correlation_id": "audit_lease_signature",
            "surface_instance_id": "surface_runtime",
            "owner_session_hash": "session_hash",
            "owner_user_hash": "user_hash",
            "owner_env_hash": "env_hash",
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
            "expires_at_unix_ms": 1783161930000_i64
        });
        let payload =
            runtime_lease_signature_payload_json(&worker_lease_from_value(&lease), "worker.echo")
                .expect("payload");
        assert_eq!(
            payload,
            r#"{"schema_version":"redevplugin.runtime_execution_lease.v1","token_kind":"runtime_execution_lease","lease_id":"rel_lease_signature","token_id":"rel_token_signature","lease_nonce":"nonce_1234567890","plugin_instance_id":"plugini_1","plugin_id":"com.example.worker","plugin_version":"1.2.3","active_fingerprint":"sha256:active","issued_at_unix_ms":1783161900000,"method":"worker.echo","effect":"read","execution":"sync","audit_correlation_id":"audit_lease_signature","surface_instance_id":"surface_runtime","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_runtime","target_descriptor_hashes":["method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"limits":{"timeout_ms":2000,"memory_bytes":65536,"max_payload_bytes":4096,"max_stream_bytes_per_sec":1024},"policy_revision":11,"management_revision":12,"revoke_epoch":13,"expires_at_unix_ms":1783161930000,"runtime_shard_id":"rtshard_1","runtime_instance_id":"rtinst_1","runtime_generation_id":"rtgen_1","ipc_channel_id":"ipc_1","connection_nonce":"connection_nonce_1234567890","key_id":"host_ephemeral_key_1"}"#
        );
        assert!(!payload.contains("not-part-of-the-payload"));
    }

    #[test]
    fn runtime_lease_signature_shared_fixture_matches_go() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/runtime-lease-signature-v1.json"))
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
            runtime_lease_signature_payload_json(&worker_lease_from_object(lease), method,)
                .expect("canonical payload"),
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
            runtime_lease_invocation_fixture(),
            &[RuntimeLeasePublicKey {
                key_id: "host_ephemeral_fixture_v1".to_string(),
                public_key,
            }],
        )
        .expect("shared runtime lease fixture signature");
    }

    #[test]
    fn renders_hello_ack_frame() {
        let actual_target = RuntimeTarget::LinuxAmd64;
        let frame = hello_ack_frame(HelloAckFrameRequest {
            request_id: "r1",
            runtime_generation_id: "g1",
            channel_nonce: "nonce_1",
            runtime_version: "0.0.0-dev",
            actual_target: &actual_target,
            wasm_abi_version: WASM_ABI_VERSION,
            limits: runtime_limits(),
            process_containment: &process_containment(),
        })
        .expect("hello acknowledgement frame");
        assert!(frame.contains(r#""frame_type":"hello_ack""#));
        assert!(frame.contains(r#""request_id":"r1""#));
        assert!(frame.contains(r#""runtime_generation_id":"g1""#));
        assert!(frame.contains(r#""actual_target":"linux/amd64""#));
        assert!(frame.contains(r#""rust_ipc_version":"rust-ipc-v6""#));
        assert!(frame.contains(&format!(r#""contract_set_sha256":"{CONTRACT_SET_SHA256}""#)));
        assert!(frame.contains(r#""channel_nonce":"nonce_1""#));
        assert!(frame.contains(r#""worker_count":8"#));
        assert!(frame.contains(r#""module_cache_source_bytes":134217728"#));
    }

    #[test]
    fn hello_ack_frame_rejects_invalid_runtime_limits() {
        let actual_target = RuntimeTarget::LinuxAmd64;
        assert!(matches!(
            hello_ack_frame(HelloAckFrameRequest {
                request_id: "r1",
                runtime_generation_id: "g1",
                channel_nonce: "nonce_1",
                runtime_version: "0.0.0-dev",
                actual_target: &actual_target,
                wasm_abi_version: WASM_ABI_VERSION,
                limits: invalid_runtime_limits(),
                process_containment: &process_containment(),
            }),
            Err(IpcError::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn renders_error_response_frame() {
        let frame = error_response_frame(
            FRAME_TYPE_INVOKE_WORKER_RESULT,
            "r1",
            "g1",
            ResponseError::runtime(ERR_WASM_WORKER_FAILED, "runtime worker execution failed")
                .expect("runtime response error"),
        )
        .expect("runtime error response frame");
        assert!(frame.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(frame.contains(r#""ok":false"#));
        assert!(frame.contains(r#""code":"WASM_WORKER_FAILED""#));
        assert!(frame.contains(r#""error_origin":"runtime""#));

        let plugin_frame = error_response_frame(
            FRAME_TYPE_INVOKE_WORKER_RESULT,
            "r2",
            "g1",
            ResponseError::plugin("NOTE_NOT_FOUND", "note was not found")
                .expect("plugin response error"),
        )
        .expect("plugin error response frame");
        assert!(plugin_frame.contains(r#""error_origin":"plugin""#));
    }

    #[test]
    fn error_response_rejects_empty_code() {
        assert_eq!(
            ResponseError::runtime(" ", "failed"),
            Err(IpcError::EmptyResponseErrorCode),
        );
    }

    #[test]
    fn error_response_rejects_empty_message() {
        assert_eq!(
            ResponseError::runtime("FAILED", " "),
            Err(IpcError::EmptyResponseErrorMessage),
        );
    }

    #[test]
    fn success_response_rejects_invalid_result_json_without_panicking() {
        assert_eq!(
            success_response_frame(FRAME_TYPE_INVOKE_WORKER_RESULT, "r1", "g1", "{"),
            Err(IpcError::InvalidResponseResultJson),
        );
    }

    #[test]
    fn ipc_errors_are_cloneable_comparable_and_have_stable_redacted_display() {
        let error = IpcError::RemoteFailure {
            code: "NETWORK_TARGET_DENIED".to_string(),
        };
        assert_eq!(error.clone(), error);
        assert_eq!(
            error.to_string(),
            "hostcall response failed with code NETWORK_TARGET_DENIED"
        );

        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_TARGET_DENIED","message":"bearer secret-token https://api.example.com/path?token=secret /Users/private/key","error_origin":"hostcall"}}"#;
        let error =
            validate_network_execute_response(failed, "r1:network_execute", "g1", "api", "http")
                .expect_err("hostcall failure");
        let display = error.to_string();
        assert_eq!(
            display,
            "hostcall response failed with code NETWORK_TARGET_DENIED"
        );
        for sensitive in [
            "secret-token",
            "api.example.com",
            "token=secret",
            "/Users/private",
        ] {
            assert!(!display.contains(sensitive), "display leaked {sensitive}");
        }
    }

    #[test]
    fn ipc_golden_fixtures_match_rust_frame_contract() {
        let fixtures = [
            "valid_hello_ack.json",
            "valid_invoke_worker_result.json",
            "valid_validate_handle_grant.json",
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
                    fixture_name != "valid_hello_ack.json"
                        && fixture_name != "valid_invoke_worker_result.json"
                        && fixture_name != "valid_validate_handle_grant.json"
                ),
                "fixture {fixture_name} want_error mismatch"
            );
            let frame = fixture.get("frame").expect("fixture frame").clone();
            let frame_json = serde_json::to_string(&frame).expect("compact frame");
            match fixture_name {
                "valid_hello_ack.json" => {
                    let actual_target = RuntimeTarget::parse(
                        frame["payload"]["actual_target"]
                            .as_str()
                            .expect("actual_target"),
                    )
                    .expect("actual_target");
                    let encoded = hello_ack_frame(HelloAckFrameRequest {
                        request_id: fixture["request_id"].as_str().expect("request_id"),
                        runtime_generation_id: fixture["runtime_generation_id"]
                            .as_str()
                            .expect("runtime_generation_id"),
                        channel_nonce: fixture["channel_nonce"].as_str().expect("channel_nonce"),
                        runtime_version: frame["payload"]["runtime_version"]
                            .as_str()
                            .expect("runtime_version"),
                        actual_target: &actual_target,
                        wasm_abi_version: WASM_ABI_VERSION,
                        limits: runtime_limits(),
                        process_containment: &process_containment(),
                    })
                    .expect("hello acknowledgement frame");
                    assert_json_eq(&frame_json, &encoded, fixture_name);
                }
                "valid_invoke_worker_result.json" => {
                    let result =
                        serde_json::to_string(&frame["payload"]["result"]).expect("compact result");
                    let encoded = success_response_frame(
                        FRAME_TYPE_INVOKE_WORKER_RESULT,
                        fixture["request_id"].as_str().expect("request_id"),
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("runtime_generation_id"),
                        &result,
                    )
                    .expect("success response frame");
                    assert_json_eq(&frame_json, &encoded, fixture_name);
                }
                "valid_validate_handle_grant.json" => {
                    let encoded = validate_handle_grant_frame(
                        fixture["request_id"].as_str().expect("request_id"),
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("runtime_generation_id"),
                        &handle_grant_validation_request(),
                    )
                    .expect("validate handle grant frame");
                    let encoded = bind_parent_request_id(
                        &encoded,
                        fixture["parent_request_id"]
                            .as_str()
                            .expect("parent_request_id"),
                    )
                    .expect("bind validate handle grant parent");
                    assert_json_eq(&frame_json, &encoded, fixture_name);
                }
                "missing_required.json" => {
                    assert_eq!(
                        parse_frame_identity(&frame_json),
                        Err(IpcError::MissingField {
                            field: "request_id"
                        }),
                        "fixture {fixture_name} should reject missing request_id"
                    );
                }
                "replay_frame.json" => {
                    let identity = parse_frame_identity(&frame_json).expect("parse replay fixture");
                    assert_ne!(
                        identity.request_id,
                        fixture["request_id"].as_str().expect("expected request_id"),
                        "fixture {fixture_name} should replay a different request_id"
                    );
                }
                "runtime_generation_mismatch.json" => {
                    let identity = parse_frame_identity(&frame_json)
                        .expect("parse runtime generation mismatch fixture");
                    assert_ne!(
                        identity.runtime_generation_id,
                        fixture["runtime_generation_id"]
                            .as_str()
                            .expect("expected runtime_generation_id"),
                        "fixture {fixture_name} should carry mismatched runtime generation"
                    );
                }
                "unknown_enum.json" => {
                    let identity =
                        parse_frame_identity(&frame_json).expect("parse unknown enum fixture");
                    assert_ne!(
                        identity.frame_type, FRAME_TYPE_INVOKE_WORKER_RESULT,
                        "fixture {fixture_name} should use an unknown frame type"
                    );
                }
                _ => panic!("unhandled fixture {fixture_name}"),
            }
        }
    }

    fn load_ipc_fixture(name: &str) -> Value {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("testdata");
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
        let result =
            revoke_epoch_ack_result_json(&environment_resource_scope(), "plugini_1", 7, 2, 3, 4)
                .expect("valid revoke result");
        assert!(
            result
                .contains(r#""resource_scope":{"kind":"environment","owner_env_hash":"env_hash"}"#)
        );
        assert!(result.contains(r#""plugin_instance_id":"plugini_1""#));
        assert!(result.contains(r#""revoke_epoch":7"#));
        assert!(result.contains(r#""closed_socket_count":2"#));
        assert!(result.contains(r#""closed_stream_count":3"#));
        assert!(result.contains(r#""closed_storage_handle_count":4"#));
    }

    #[test]
    fn renders_heartbeat_ack_result_json() {
        let result = heartbeat_ack_result_json(
            "runtime_gen_1",
            101,
            5000,
            100,
            RuntimeHeartbeatStatus {
                active_invocations: 2,
                queued_invocations: 3,
                limits: runtime_limits(),
                module_cache: ModuleCacheMetrics {
                    hits: 4,
                    misses: 5,
                    compiles: 1,
                    entries: 1,
                    source_bytes: 1024,
                },
            },
        )
        .expect("heartbeat acknowledgement result");
        assert!(result.contains(r#""runtime_generation_id":"runtime_gen_1""#));
        assert!(result.contains(r#""runtime_unix_nano":101"#));
        assert!(result.contains(r#""max_staleness_ms":5000"#));
        assert!(result.contains(r#""host_sent_unix_nano":100"#));
    }

    #[test]
    fn heartbeat_ack_result_rejects_invalid_runtime_limits() {
        assert!(matches!(
            heartbeat_ack_result_json(
                "runtime_gen_1",
                101,
                5000,
                100,
                RuntimeHeartbeatStatus {
                    active_invocations: 0,
                    queued_invocations: 0,
                    limits: invalid_runtime_limits(),
                    module_cache: ModuleCacheMetrics {
                        hits: 0,
                        misses: 0,
                        compiles: 0,
                        entries: 0,
                        source_bytes: 0,
                    },
                },
            ),
            Err(IpcError::ProtocolViolation { .. })
        ));
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
        };
        let frame = open_handle_frame("r1", "g1", &identity);
        assert!(frame.contains(r#""frame_type":"open_handle""#));
        assert!(frame.contains(r#""artifact":"workers/backend.wasm""#));
    }

    #[test]
    fn renders_compile_flight_lifecycle_frames() {
        let identity = WorkerInvocationIdentity {
            package_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            artifact: "workers/backend.wasm".to_string(),
            artifact_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            worker_id: "backend".to_string(),
            method: "worker.echo".to_string(),
        };
        for (frame_type, actual) in [
            (
                FRAME_TYPE_COMPILE_FLIGHT_REGISTER,
                compile_flight_register_frame("invoke-1", "generation-1", &identity),
            ),
            (
                FRAME_TYPE_COMPILE_FLIGHT_COMPLETE,
                compile_flight_complete_frame("invoke-1", "generation-1", &identity),
            ),
        ] {
            let suffix = if frame_type == FRAME_TYPE_COMPILE_FLIGHT_REGISTER {
                "register"
            } else {
                "complete"
            };
            let expected = format!(
                r#"{{"ipc_version":"rust-ipc-v6","frame_type":"{frame_type}","request_id":"invoke-1:artifact:{suffix}","parent_request_id":"invoke-1","runtime_generation_id":"generation-1","payload":{{"artifact_request_id":"invoke-1:artifact","package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wasm_abi_version":"redevplugin-wasm-worker-v2"}}}}"#
            );
            assert_json_eq(&actual, &expected, frame_type);
        }
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
        };
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"open_handle","request_id":"r1:artifact","parent_request_id":"r1","runtime_generation_id":"g1","payload":{"ok":true,"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"AAE="}}"#;
        validate_open_handle_response(frame, "r1:artifact", "r1", "g1", &identity)
            .expect("valid open_handle");
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"open_handle","request_id":"r1:artifact","parent_request_id":"r1","runtime_generation_id":"g1","payload":{"ok":false,"code":"ARTIFACT_HANDLE_FAILED","message":"unavailable","error_origin":"hostcall"}}"#;
        let err = validate_open_handle_response(failed, "r1:artifact", "r1", "g1", &identity)
            .expect_err("failed open_handle response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "ARTIFACT_HANDLE_FAILED".to_string()
            }
        );
    }

    #[test]
    fn renders_validate_handle_grant_frame() {
        let request = handle_grant_validation_request();
        let frame = validate_handle_grant_frame("r1:handle", "g1", &request)
            .expect("valid handle grant frame");
        assert!(frame.contains(r#""frame_type":"validate_handle_grant""#));
        assert!(frame.contains(r#""handle_id":"storage:db""#));
        assert!(frame.contains(r#""runtime_instance_id":"runtime_1""#));
        assert!(frame.contains(r#""runtime_shard_id":"runtime_shard_1""#));
        assert!(frame.contains(r#""owner_session_hash":"session_hash""#));
        assert!(frame.contains(r#""owner_user_hash":"user_hash""#));
        assert!(frame.contains(r#""owner_env_hash":"env_hash""#));
        assert!(frame.contains(r#""session_channel_id_hash":"channel_hash""#));
        assert!(frame.contains(r#""policy_revision":1"#));

        let mut missing_session = request.clone();
        missing_session.owner_session_hash.clear();
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g1", &missing_session).unwrap_err(),
            IpcError::InvalidField {
                field: "handle grant session audience"
            }
        );

        let mut mismatched_scope = request.clone();
        mismatched_scope.owner_env_hash = "env_other".to_string();
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g1", &mismatched_scope).unwrap_err(),
            IpcError::InvalidField {
                field: "handle grant resource scope"
            }
        );

        let mut missing_token = request.clone();
        missing_token.handle_grant_token.clear();
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g1", &missing_token).unwrap_err(),
            IpcError::InvalidField {
                field: "handle_grant_token"
            }
        );
        assert_eq!(
            validate_handle_grant_frame("", "g1", &request).unwrap_err(),
            IpcError::InvalidField {
                field: "request_id"
            }
        );
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g2", &request).unwrap_err(),
            IpcError::ProtocolViolation {
                message: "validate_handle_grant runtime_generation_id mismatch"
            }
        );
        let mut unsafe_revision = request;
        unsafe_revision.policy_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g1", &unsafe_revision).unwrap_err(),
            IpcError::InvalidField {
                field: "policy_revision"
            }
        );
    }

    #[test]
    fn zero_revoke_epoch_returns_typed_errors() {
        let revoke = r#"{"ipc_version":"rust-ipc-v6","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"resource_scope":{"kind":"environment","owner_env_hash":"env_hash"},"plugin_instance_id":"plugini_1","revoke_epoch":0}}"#;
        assert_eq!(
            parse_revoke_epoch_request(revoke).unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );
        let worker = closed_worker_frame(
            r#"{"runtime_shard_id":"runtime_shard_signed","policy_revision":1,"management_revision":2,"revoke_epoch":0}"#,
            r#"{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","method":"worker.echo"}"#,
        );
        assert_eq!(
            parse_worker_invocation_context(&worker).unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );
        assert_eq!(
            revoke_epoch_ack_result_json(&environment_resource_scope(), "plugini_1", 0, 0, 0, 0)
                .unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );

        let mut handle_grant = handle_grant_validation_request();
        handle_grant.revoke_epoch = 0;
        assert_eq!(
            validate_handle_grant_frame("r1:handle", "g1", &handle_grant).unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );

        let mut network_grant = NetworkGrantRequest {
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            resource_scope: user_resource_scope(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            policy_revision: 1,
            management_revision: 2,
            revoke_epoch: 0,
            connector_id: "api".to_string(),
            transport: "http".to_string(),
            destination: "https://api.example.com".to_string(),
            ttl_ms: 30000,
        };
        assert_eq!(
            network_grant_frame("r1:network_grant", "g1", &network_grant).unwrap_err(),
            IpcError::InvalidField {
                field: "revoke_epoch"
            }
        );
        network_grant.revoke_epoch = 1;
        network_grant.resource_scope.owner_env_hash = " env_hash".to_string();
        assert_eq!(
            network_grant_frame("r1:network_grant", "g1", &network_grant).unwrap_err(),
            IpcError::InvalidField {
                field: "network resource scope"
            }
        );
    }

    #[test]
    fn validates_handle_grant_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"validate_handle_grant","request_id":"r1:handle","runtime_generation_id":"g1","payload":{"ok":true,"handle_grant_id":"h1","handle_id":"storage:db","method":"storage.sqlite","runtime_generation_id":"g1","resource_scope":{"kind":"user","owner_env_hash":"env_hash","owner_user_hash":"user_hash"},"max_total_bytes":4096}}"#;
        validate_handle_grant_response(
            frame,
            "r1:handle",
            "g1",
            "storage:db",
            "storage.sqlite",
            &user_resource_scope(),
        )
        .expect("valid handle grant");
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"validate_handle_grant","request_id":"r1:handle","runtime_generation_id":"g1","payload":{"ok":false,"code":"HANDLE_GRANT_VALIDATION_FAILED","message":"denied","error_origin":"hostcall"}}"#;
        let err = validate_handle_grant_response(
            failed,
            "r1:handle",
            "g1",
            "storage:db",
            "storage.sqlite",
            &user_resource_scope(),
        )
        .expect_err("failed handle grant response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "HANDLE_GRANT_VALIDATION_FAILED".to_string()
            }
        );
    }

    #[test]
    fn renders_storage_file_frame() {
        let mut req = StorageFileRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:workspace".to_string(),
            method: "storage.files".to_string(),
            resource_scope: user_resource_scope(),
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
        let frame =
            storage_file_frame("r1:storage_file", "g1", &req).expect("valid storage file frame");
        assert!(frame.contains(r#""frame_type":"storage_file""#));
        assert!(frame.contains(r#""handle_id":"storage:workspace""#));
        assert!(frame.contains(r#""method":"storage.files""#));
        assert!(frame.contains(r#""operation":"read""#));
        req.policy_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            storage_file_frame("r1:storage_file", "g1", &req).unwrap_err(),
            IpcError::InvalidField {
                field: "policy_revision"
            }
        );
    }

    #[test]
    fn validates_storage_file_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/today.txt","data_base64":"aGVsbG8=","size_bytes":5,"usage":{"plugin_instance_id":"plugini_1","store_id":"workspace","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}}}"#;
        validate_storage_file_response(frame, "r1:storage_file", "g1", "read")
            .expect("valid storage file response");
        let payload = storage_file_payload_json(frame, "read").expect("storage file payload");
        assert!(payload.contains(r#""path":"notes/today.txt""#));
        for wrong_operation in ["write", "delete", "list"] {
            assert!(
                validate_storage_file_response(frame, "r1:storage_file", "g1", wrong_operation)
                    .is_err(),
                "read response accepted as {wrong_operation}"
            );
        }
        let mixed = frame.replace(r#""usage":{"#, r#""entries":[],"usage":{"#);
        assert!(validate_storage_file_response(&mixed, "r1:storage_file", "g1", "read").is_err());
        let missing = without_payload_field(frame, "data_base64");
        assert!(validate_storage_file_response(&missing, "r1:storage_file", "g1", "read").is_err());
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing","error_origin":"hostcall"}}"#;
        let err = validate_storage_file_response(failed, "r1:storage_file", "g1", "read")
            .expect_err("failed storage file response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "STORAGE_FILE_NOT_FOUND".to_string()
            }
        );
        let missing_origin = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing"}}"#;
        let err = validate_storage_file_response(missing_origin, "r1:storage_file", "g1", "read")
            .expect_err("hostcall origin is required");
        assert_eq!(
            err,
            IpcError::DecodeFailed {
                context: "hostcall failure response payload"
            }
        );
        let spoofed_origin = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing","error_origin":"plugin"}}"#;
        let err = validate_storage_file_response(spoofed_origin, "r1:storage_file", "g1", "read")
            .expect_err("hostcall origin cannot be spoofed");
        assert_eq!(
            err,
            IpcError::ProtocolViolation {
                message: "hostcall response error_origin must be hostcall"
            }
        );
    }

    #[test]
    fn validates_all_storage_file_success_operations() {
        let usage = r#"{"plugin_instance_id":"plugini_1","store_id":"workspace","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}"#;
        let cases = [
            (
                "read",
                format!(
                    r#"{{"ok":true,"path":"a.txt","data_base64":"YQ==","size_bytes":1,"usage":{usage}}}"#
                ),
            ),
            (
                "write",
                format!(r#"{{"ok":true,"path":"a.txt","size_bytes":1,"usage":{usage}}}"#),
            ),
            ("delete", r#"{"ok":true,"path":"a.txt"}"#.to_string()),
            (
                "list",
                format!(r#"{{"ok":true,"path":"","entries":[],"usage":{usage}}}"#),
            ),
        ];
        for (operation, payload) in &cases {
            let frame = hostcall_response_frame(FRAME_TYPE_STORAGE_FILE, payload);
            validate_storage_file_response(&frame, "r1", "g1", operation)
                .unwrap_or_else(|err| panic!("{operation} response: {err}"));
            for (other, _) in &cases {
                if other != operation {
                    assert!(validate_storage_file_response(&frame, "r1", "g1", other).is_err());
                }
            }
        }
    }

    #[test]
    fn renders_storage_kv_frame() {
        let mut req = StorageKVRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:settings".to_string(),
            method: "storage.kv".to_string(),
            resource_scope: user_resource_scope(),
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
        let frame = storage_kv_frame("r1:storage_kv", "g1", &req).expect("valid storage kv frame");
        assert!(frame.contains(r#""frame_type":"storage_kv""#));
        assert!(frame.contains(r#""handle_id":"storage:settings""#));
        assert!(frame.contains(r#""method":"storage.kv""#));
        assert!(frame.contains(r#""operation":"put""#));
        req.management_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            storage_kv_frame("r1:storage_kv", "g1", &req).unwrap_err(),
            IpcError::InvalidField {
                field: "management_revision"
            }
        );
        assert!(frame.contains(r#""key":"demo/last_broker_run""#));
    }

    #[test]
    fn validates_storage_kv_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":true,"key":"demo/last_broker_run","value_base64":"aGVsbG8=","size_bytes":5,"usage":{"plugin_instance_id":"plugini_1","store_id":"settings","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}}}"#;
        validate_storage_kv_response(frame, "r1:storage_kv", "g1", "get")
            .expect("valid storage kv response");
        let payload = storage_kv_payload_json(frame, "get").expect("storage kv payload");
        assert!(payload.contains(r#""key":"demo/last_broker_run""#));
        for wrong_operation in ["put", "delete", "list"] {
            assert!(
                validate_storage_kv_response(frame, "r1:storage_kv", "g1", wrong_operation)
                    .is_err()
            );
        }
        let mixed = frame.replace(r#""usage":{"#, r#""entries":[],"usage":{"#);
        assert!(validate_storage_kv_response(&mixed, "r1:storage_kv", "g1", "get").is_err());
        let missing = without_payload_field(frame, "value_base64");
        assert!(validate_storage_kv_response(&missing, "r1:storage_kv", "g1", "get").is_err());
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_KV_NOT_FOUND","message":"missing","error_origin":"hostcall"}}"#;
        let err = validate_storage_kv_response(failed, "r1:storage_kv", "g1", "get")
            .expect_err("failed storage kv response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "STORAGE_KV_NOT_FOUND".to_string()
            }
        );
    }

    #[test]
    fn validates_all_storage_kv_success_operations() {
        let usage = r#"{"plugin_instance_id":"plugini_1","store_id":"settings","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}"#;
        let cases = [
            (
                "get",
                format!(
                    r#"{{"ok":true,"key":"theme","value_base64":"ZGFyaw==","size_bytes":4,"usage":{usage}}}"#
                ),
            ),
            (
                "put",
                format!(r#"{{"ok":true,"key":"theme","size_bytes":4,"usage":{usage}}}"#),
            ),
            ("delete", r#"{"ok":true,"key":"theme"}"#.to_string()),
            (
                "list",
                format!(r#"{{"ok":true,"prefix":"","entries":[],"usage":{usage}}}"#),
            ),
        ];
        for (operation, payload) in &cases {
            let frame = hostcall_response_frame(FRAME_TYPE_STORAGE_KV, payload);
            validate_storage_kv_response(&frame, "r1", "g1", operation)
                .unwrap_or_else(|err| panic!("{operation} response: {err}"));
            for (other, _) in &cases {
                if other != operation {
                    assert!(validate_storage_kv_response(&frame, "r1", "g1", other).is_err());
                }
            }
        }
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
        let mut req = StorageSQLiteRequest {
            handle_grant_token: "handle_grant.secret".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: "runtime_shard_1".to_string(),
            handle_id: "storage:db".to_string(),
            method: "storage.sqlite".to_string(),
            resource_scope: user_resource_scope(),
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
        let frame = storage_sqlite_frame("r1:storage_sqlite", "g1", &req)
            .expect("valid storage sqlite frame");
        assert!(frame.contains(r#""frame_type":"storage_sqlite""#));
        assert!(frame.contains(r#""handle_id":"storage:db""#));
        assert!(frame.contains(r#""method":"storage.sqlite""#));
        assert!(frame.contains(r#""operation":"query""#));
        assert!(frame.contains(r#""args":[{"int":7}]"#));
        req.policy_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            storage_sqlite_frame("r1:storage_sqlite", "g1", &req).unwrap_err(),
            IpcError::InvalidField {
                field: "policy_revision"
            }
        );
    }

    #[test]
    fn validates_storage_sqlite_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":true,"database":"plugin.sqlite","columns":["title"],"rows":[[{"text":"stored from wasm"}]],"usage":{"plugin_instance_id":"plugini_1","store_id":"db","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}}}"#;
        validate_storage_sqlite_response(frame, "r1:storage_sqlite", "g1", "query")
            .expect("valid storage sqlite response");
        let payload = storage_sqlite_payload_json(frame, "query").expect("storage sqlite payload");
        assert!(payload.contains(r#""database":"plugin.sqlite""#));
        assert!(
            validate_storage_sqlite_response(frame, "r1:storage_sqlite", "g1", "exec").is_err()
        );
        let mixed = frame.replace(
            r#""columns":["title"]"#,
            r#""rows_affected":1,"columns":["title"]"#,
        );
        assert!(
            validate_storage_sqlite_response(&mixed, "r1:storage_sqlite", "g1", "query").is_err()
        );
        let missing = without_payload_field(frame, "rows");
        assert!(
            validate_storage_sqlite_response(&missing, "r1:storage_sqlite", "g1", "query").is_err()
        );
        let empty_blob = frame.replace(r#"{"text":"stored from wasm"}"#, r#"{"blob_base64":""}"#);
        validate_storage_sqlite_response(&empty_blob, "r1:storage_sqlite", "g1", "query")
            .expect("empty SQLite blob is a valid typed value");
        for invalid_value in [
            r#"{}"#,
            r#"{"null":false}"#,
            r#"{"int":1,"text":"ambiguous"}"#,
        ] {
            let invalid = frame.replace(r#"{"text":"stored from wasm"}"#, invalid_value);
            assert!(
                validate_storage_sqlite_response(&invalid, "r1:storage_sqlite", "g1", "query")
                    .is_err(),
                "accepted invalid SQLite value {invalid_value}"
            );
        }
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_SQLITE_RESULT_TOO_LARGE","message":"too large","error_origin":"hostcall"}}"#;
        let err = validate_storage_sqlite_response(failed, "r1:storage_sqlite", "g1", "query")
            .expect_err("failed storage sqlite response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "STORAGE_SQLITE_RESULT_TOO_LARGE".to_string()
            }
        );
    }

    #[test]
    fn validates_all_storage_sqlite_success_operations() {
        let usage = r#"{"plugin_instance_id":"plugini_1","store_id":"db","usage_bytes":5,"quota_bytes":100,"usage_files":1,"quota_files":10}"#;
        let cases = [
            (
                "exec",
                format!(
                    r#"{{"ok":true,"database":"plugin.sqlite","rows_affected":0,"usage":{usage}}}"#
                ),
            ),
            (
                "query",
                format!(
                    r#"{{"ok":true,"database":"plugin.sqlite","columns":[],"rows":[],"usage":{usage}}}"#
                ),
            ),
        ];
        for (operation, payload) in &cases {
            let frame = hostcall_response_frame(FRAME_TYPE_STORAGE_SQLITE, payload);
            validate_storage_sqlite_response(&frame, "r1", "g1", operation)
                .unwrap_or_else(|err| panic!("{operation} response: {err}"));
            for (other, _) in &cases {
                if other != operation {
                    assert!(validate_storage_sqlite_response(&frame, "r1", "g1", other).is_err());
                }
            }
        }
    }

    #[test]
    fn renders_network_grant_frame() {
        let mut req = NetworkGrantRequest {
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            resource_scope: NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: "env_hash".to_string(),
                owner_user_hash: "user_hash".to_string(),
            },
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
        let frame =
            network_grant_frame("r1:network_grant", "g1", &req).expect("network grant frame");
        assert!(frame.contains(r#""frame_type":"network_grant""#));
        assert!(frame.contains(r#""connector_id":"api""#));
        assert!(frame.contains(r#""transport":"http""#));
        assert!(frame.contains(r#""resource_scope":{"kind":"user","owner_env_hash":"env_hash","owner_user_hash":"user_hash"}"#));
        assert!(frame.contains(r#""ttl_ms":30000"#));
        req.management_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            network_grant_frame("r1:network_grant", "g1", &req).unwrap_err(),
            IpcError::InvalidField {
                field: "management_revision"
            }
        );
    }

    #[test]
    fn validates_network_grant_response() {
        let scope = NetworkResourceScope {
            kind: "user".to_string(),
            owner_env_hash: "env_hash".to_string(),
            owner_user_hash: "user_hash".to_string(),
        };
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":true,"grant_id":"netgrant_00112233445566778899aabbccddeeff","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","resource_scope":{"kind":"user","owner_env_hash":"env_hash","owner_user_hash":"user_hash"},"policy_revision":1,"management_revision":2,"revoke_epoch":3,"connector_id":"api","transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"runtime_generation_id":"g1","target_classifier_version":"target-classifier-v2","expires_at":"2026-06-30T10:00:30Z"}}"#;
        validate_network_grant_response(frame, "r1:network_grant", "g1", "api", "http", &scope)
            .expect("valid network grant response");
        let unsafe_revision = frame.replace(
            r#""policy_revision":1"#,
            r#""policy_revision":9007199254740992"#,
        );
        assert_eq!(
            validate_network_grant_response(
                &unsafe_revision,
                "r1:network_grant",
                "g1",
                "api",
                "http",
                &scope,
            )
            .unwrap_err(),
            IpcError::InvalidField {
                field: "policy_revision"
            }
        );
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_TARGET_DENIED","message":"blocked","error_origin":"hostcall"}}"#;
        let err = validate_network_grant_response(
            failed,
            "r1:network_grant",
            "g1",
            "api",
            "http",
            &scope,
        )
        .expect_err("failed network grant response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "NETWORK_TARGET_DENIED".to_string()
            }
        );
    }

    #[test]
    fn renders_network_execute_frame() {
        let mut req = NetworkExecuteRequest {
            plugin_id: "com.example.worker".to_string(),
            plugin_instance_id: "plugini_1".to_string(),
            active_fingerprint: "sha256:active".to_string(),
            resource_scope: NetworkResourceScope {
                kind: "user".to_string(),
                owner_env_hash: "env_hash".to_string(),
                owner_user_hash: "user_hash".to_string(),
            },
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
            owner_env_hash: "env_hash".to_string(),
            session_channel_id_hash: "channel_hash".to_string(),
            bridge_channel_id: "bridge_1".to_string(),
            content_type: "text/plain".to_string(),
        };
        let frame =
            network_execute_frame("r1:network_execute", "g1", &req).expect("network execute frame");
        assert!(frame.contains(r#""frame_type":"network_execute""#));
        assert!(frame.contains(r#""operation":"http""#));
        assert!(frame.contains(r#""headers":{"X-Test":["ok"]}"#));
        assert!(frame.contains(r#""query":{"lang":["en"],"units":["metric"]}"#));
        req.policy_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            network_execute_frame("r1:network_execute", "g1", &req).unwrap_err(),
            IpcError::InvalidField {
                field: "policy_revision"
            }
        );
        req.policy_revision = 1;
        assert!(frame.contains(r#""body_base64":"e30=""#));
        assert!(frame.contains(r#""stream_id":"stream_1""#));
        assert!(frame.contains(r#""owner_session_hash":"session_hash""#));
        assert!(frame.contains(r#""max_chunk_bytes":256"#));
        assert!(frame.contains(r#""timeout_ms":2000"#));

        req.query_json = "[]".to_string();
        assert_eq!(
            network_execute_frame("r1:network_execute", "g1", &req),
            Err(IpcError::InvalidField {
                field: "network execute query"
            })
        );
        req.query_json = "{}".to_string();
        req.headers_json = "[".to_string();
        assert_eq!(
            network_execute_frame("r1:network_execute", "g1", &req),
            Err(IpcError::InvalidField {
                field: "network execute headers"
            })
        );
        req.headers_json = "{}".to_string();
        req.resource_scope.owner_user_hash.clear();
        assert_eq!(
            network_execute_frame("r1:network_execute", "g1", &req),
            Err(IpcError::InvalidField {
                field: "network resource scope"
            })
        );
    }

    #[test]
    fn validates_network_execute_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":true,"transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"status_code":201,"headers":{"X-Worker":["ok"]},"body_base64":"e30=","grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","runtime_generation_id":"g1"}}"#;
        validate_network_execute_response(frame, "r1:network_execute", "g1", "api", "http")
            .expect("valid network execute response");
        let failed = r#"{"ipc_version":"rust-ipc-v6","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_RESPONSE_TOO_LARGE","message":"too large","error_origin":"hostcall"}}"#;
        let err =
            validate_network_execute_response(failed, "r1:network_execute", "g1", "api", "http")
                .expect_err("failed network execute response");
        assert_eq!(
            err,
            IpcError::RemoteFailure {
                code: "NETWORK_RESPONSE_TOO_LARGE".to_string()
            }
        );
    }

    #[test]
    fn parses_worker_invocation_identity() {
        let frame = closed_worker_frame(
            "{}",
            r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo"}"#,
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
    fn validates_worker_artifact_content_hash() {
        let identity = WorkerInvocationIdentity {
            package_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            artifact: "workers/backend.wasm".to_string(),
            artifact_sha256:
                "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                    .to_string(),
            worker_id: "backend".to_string(),
            method: "worker.echo".to_string(),
        };
        validate_worker_artifact_bytes(&identity, b"hello").unwrap();
        assert!(validate_worker_artifact_bytes(&identity, b"tampered").is_err());
    }

    #[test]
    fn rejects_unsupported_worker_runtime_contract() {
        let valid = runtime_lease_invocation_fixture();
        parse_worker_invocation(valid)
            .unwrap()
            .validate_worker_contract()
            .unwrap();
        let invalid = valid.replacen(
            "redevplugin-wasm-worker-v2",
            "redevplugin-wasm-worker-v99",
            1,
        );
        assert!(
            parse_worker_invocation(&invalid)
                .unwrap()
                .validate_worker_contract()
                .is_err()
        );
    }

    #[test]
    fn projects_closed_worker_request_v2() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{},"method":"notes.save","invocation":{"plugin_id":"com.example.notes","plugin_instance_id":"plugini_1","storage_handle_grants":{"notes":"handle-secret"},"method":"notes.save","params":{"title":"Launch notes","body":"Ship the examples"}}}}"#;

        let request = worker_request_json_v2(frame).expect("worker request projection");

        assert_eq!(
            request,
            r#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.save","params":{"body":"Ship the examples","title":"Launch notes"}}"#
        );
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
                r#"{{"effect":"read","broker_access":{{"storage":[{{"store_id":"store","scope":"user","operations":["{operation}"]}}]}}}}"#
            );
            let frame = closed_worker_frame("{}", &frame);
            let err = validate_worker_storage_broker_access(&frame, "store", operation)
                .expect_err("read methods must not mutate storage");
            assert_eq!(
                err,
                IpcError::ProtocolViolation {
                    message: "worker method with read effect cannot perform the storage mutation"
                }
            );
        }
    }

    #[test]
    fn read_effect_allows_declared_http_post_network_request() {
        let frame = closed_worker_frame(
            "{}",
            r#"{"effect":"read","broker_access":{"network":[{"connector_id":"search","transport":"http","scope":"user","operations":["http"],"http_methods":["POST"]}]}}"#,
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
        assert_eq!(
            error,
            IpcError::DecodeFailed {
                context: "worker response"
            }
        );
        assert!(!error.to_string().contains("gateway_token"));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn worker_response_v2_enforces_closed_success_and_failure_branches() {
        let failure = parse_worker_response_v2(
            r#"{"ok":false,"error_code":"WORKER_FAILED","message":"failed"}"#,
        )
        .expect("worker failure response");
        assert_eq!(
            failure,
            WorkerResponseV2::Failure {
                code: "WORKER_FAILED".to_string(),
                message: "failed".to_string(),
            }
        );

        for invalid in [
            r#"{"ok":true}"#,
            r#"{"ok":true,"data":{},"error_code":"WORKER_FAILED"}"#,
            r#"{"ok":false,"data":{},"error_code":"WORKER_FAILED","message":"failed"}"#,
            r#"{"ok":false,"message":"failed"}"#,
            r#"{"ok":false,"error_code":"WORKER_FAILED"}"#,
        ] {
            assert!(
                parse_worker_response_v2(invalid).is_err(),
                "accepted ambiguous worker response {invalid}"
            );
        }
    }

    #[test]
    fn worker_response_v2_preserves_large_raw_success_payload() {
        let payload = "x".repeat(512 * 1024 - 64);
        let input = format!(r#"{{"ok":true,"data":{{"payload":"{payload}"}}}}"#);
        let response = parse_worker_response_v2(&input).expect("large worker response");
        match response {
            WorkerResponseV2::Success(data) => {
                assert_eq!(data.len(), payload.len() + r#"{"payload":""}"#.len());
                assert!(data.ends_with("\"}"));
            }
            WorkerResponseV2::Failure { .. } => panic!("expected success response"),
        }
    }

    #[test]
    fn rejects_worker_invocation_without_artifact_identity() {
        let frame = closed_worker_frame("{}", r#"{"artifact":"../backend.wasm"}"#);
        let err = parse_worker_invocation_identity(&frame).expect_err("invalid invocation");
        assert_eq!(
            err,
            IpcError::MissingField {
                field: "package_hash"
            }
        );
        let frame = closed_worker_frame(
            "{}",
            r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/../backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo"}"#,
        );
        let err = parse_worker_invocation_identity(&frame).expect_err("invalid artifact");
        assert_eq!(err, IpcError::InvalidField { field: "artifact" });
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
        assert_eq!(
            err,
            IpcError::MissingField {
                field: "lease_nonce"
            }
        );
    }

    fn runtime_lease_signing_key_for_test(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn runtime_lease_invocation_fixture() -> &'static str {
        include_str!("../testdata/runtime-lease-signature-v1-invocation.json")
    }

    fn signed_runtime_lease_invocation_for_test(
        signing_key: &SigningKey,
        replace: Option<(&str, &str)>,
    ) -> String {
        let mut lease = serde_json::json!({
            "lease_id": "rel_lease_signature",
            "token_id": "rel_token_signature",
            "lease_nonce": "nonce_1234567890",
            "runtime_generation_id": "rtgen_1",
            "plugin_instance_id": "plugini_1",
            "plugin_id": "com.example.worker",
            "plugin_version": "1.2.3",
            "active_fingerprint": "sha256:active",
            "issued_at_unix_ms": 1783161900000_i64,
            "method": "worker.echo",
            "effect": "read",
            "execution": "sync",
            "audit_correlation_id": "audit_lease_signature",
            "surface_instance_id": "surface_runtime",
            "owner_session_hash": "session_hash",
            "owner_user_hash": "user_hash",
            "owner_env_hash": "env_hash",
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
            "expires_at_unix_ms": 1783161930000_i64
        });
        let payload =
            runtime_lease_signature_payload_json(&worker_lease_from_value(&lease), "worker.echo")
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
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"rtgen_1","payload":{{"lease":{},"method":"worker.echo","invocation":{{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo"}}}}}}"#,
            serde_json::to_string(&lease).expect("lease json")
        )
    }
}
