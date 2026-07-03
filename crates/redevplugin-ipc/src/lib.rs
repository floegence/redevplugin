pub const RUST_IPC_VERSION: &str = "rust-ipc-v1";
pub const WASM_ABI_VERSION: &str = "redevplugin-wasm-worker-v1";
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
pub const ERR_WORKER_INVOCATION_INVALID: &str = "WORKER_INVOCATION_INVALID";
pub const ERR_RUNTIME_CAPABILITY_REVOKED: &str = "RUNTIME_CAPABILITY_REVOKED";
pub const ERR_RUNTIME_CONTROL_CHANNEL_STALE: &str = "RUNTIME_CONTROL_CHANNEL_STALE";
pub const ERR_LEASE_REPLAYED: &str = "PLUGIN_LEASE_REPLAYED";
pub const ERR_WASM_NOT_IMPLEMENTED: &str = "WASM_NOT_IMPLEMENTED";
pub const ERR_WASM_WORKER_INVALID: &str = "WASM_WORKER_INVALID";
pub const ERR_WASM_HOSTCALL_FAILED: &str = "WASM_HOSTCALL_FAILED";
pub const ERR_UNSUPPORTED_FRAME: &str = "UNSUPPORTED_FRAME";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Hello,
    HelloAck,
    Heartbeat,
    LeaseGrant,
    InvokeWorker,
    InvokeWorkerResult,
    OpenHandle,
    ValidateHandleGrant,
    StorageFile,
    StorageKV,
    StorageSQLite,
    NetworkGrant,
    NetworkExecute,
    CloseHandle,
    RevokeEpoch,
    RevokeEpochAck,
    Diagnostic,
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
        format!(
            "{{\"ok\":false,\"code\":\"{}\",\"message\":\"{}\"}}",
            escape_json_string(code.unwrap_or("RUNTIME_REQUEST_FAILED")),
            escape_json_string(message.unwrap_or("runtime request failed"))
        )
    };
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{}}}",
        RUST_IPC_VERSION,
        escape_json_string(frame_type),
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        payload
    )
}

pub fn revoke_epoch_ack_result_json(
    plugin_instance_id: &str,
    revoke_epoch: u64,
    closed_actor_count: u64,
    closed_socket_count: u64,
    closed_stream_count: u64,
    closed_storage_handle_count: u64,
) -> String {
    format!(
        "{{\"plugin_instance_id\":\"{}\",\"revoke_epoch\":{},\"closed_actor_count\":{},\"closed_socket_count\":{},\"closed_stream_count\":{},\"closed_storage_handle_count\":{}}}",
        escape_json_string(plugin_instance_id),
        revoke_epoch,
        closed_actor_count,
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_ARTIFACT_HANDLE_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "artifact handle request failed".to_string());
        return Err(format!("{code}: {message}"));
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
    let network_execute = network_success_fields(network_execute_result_jsons);
    format!(
        "{{\"data\":{{\"method\":\"{}\",\"worker_id\":\"{}\",\"backend\":\"executed wasm worker scaffold\",\"transport\":\"rust runtime ipc\",\"wasm_abi\":\"{}\",\"wasm_byte_len\":{}{}{}{}{}}}}}",
        escape_json_string(&identity.method),
        escape_json_string(&identity.worker_id),
        WASM_ABI_VERSION,
        wasm_byte_len,
        storage_file,
        storage_kv,
        storage_sqlite,
        network_execute
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_HANDLE_GRANT_VALIDATION_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "handle grant validation failed".to_string());
        return Err(format!("{code}: {message}"));
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_STORAGE_FILE_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "storage file request failed".to_string());
        return Err(format!("{code}: {message}"));
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
        let code =
            extract_json_string(input, "code").unwrap_or_else(|| ERR_STORAGE_KV_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "storage kv request failed".to_string());
        return Err(format!("{code}: {message}"));
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_STORAGE_SQLITE_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "storage sqlite request failed".to_string());
        return Err(format!("{code}: {message}"));
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_NETWORK_GRANT_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "network grant request failed".to_string());
        return Err(format!("{code}: {message}"));
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
    pub headers_json: String,
    pub message_type: String,
    pub body_base64: String,
    pub payload_base64: String,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub timeout_ms: u64,
}

pub fn network_execute_frame(
    request_id: &str,
    runtime_generation_id: &str,
    req: &NetworkExecuteRequest,
) -> String {
    let headers_json = if req.headers_json.trim().is_empty() {
        "{}"
    } else {
        req.headers_json.trim()
    };
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"plugin_instance_id\":\"{}\",\"active_fingerprint\":\"{}\",\"runtime_instance_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"runtime_shard_id\":\"{}\",\"policy_revision\":{},\"management_revision\":{},\"revoke_epoch\":{},\"connector_id\":\"{}\",\"transport\":\"{}\",\"destination\":\"{}\",\"ttl_ms\":{},\"operation\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"headers\":{},\"message_type\":\"{}\",\"body_base64\":\"{}\",\"payload_base64\":\"{}\",\"max_request_bytes\":{},\"max_response_bytes\":{},\"timeout_ms\":{}}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_NETWORK_EXECUTE,
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
        req.ttl_ms,
        escape_json_string(&req.operation),
        escape_json_string(&req.method),
        escape_json_string(&req.path),
        headers_json,
        escape_json_string(&req.message_type),
        escape_json_string(&req.body_base64),
        escape_json_string(&req.payload_base64),
        req.max_request_bytes,
        req.max_response_bytes,
        req.timeout_ms
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
        let code = extract_json_string(input, "code")
            .unwrap_or_else(|| ERR_NETWORK_EXECUTE_FAILED.to_string());
        let message = extract_json_string(input, "message")
            .unwrap_or_else(|| "network execute request failed".to_string());
        return Err(format!("{code}: {message}"));
    }
    let connector_id = extract_json_string(input, "connector_id").ok_or("missing connector_id")?;
    let transport = extract_json_string(input, "transport").ok_or("missing transport")?;
    if connector_id != expected_connector_id || transport != expected_transport {
        return Err("network_execute audience mismatch".to_string());
    }
    Ok(())
}

pub fn validate_hello_frame(input: &str) -> Result<(String, String, String), &'static str> {
    let ipc_version = extract_json_string(input, "ipc_version").ok_or("missing ipc_version")?;
    if ipc_version != RUST_IPC_VERSION {
        return Err("unsupported ipc_version");
    }
    let frame_type = extract_json_string(input, "frame_type").ok_or("missing frame_type")?;
    if frame_type != FRAME_TYPE_HELLO {
        return Err("expected hello frame");
    }
    let request_id = extract_json_string(input, "request_id").ok_or("missing request_id")?;
    if request_id.trim().is_empty() {
        return Err("empty request_id");
    }
    let runtime_generation_id = extract_json_string(input, "runtime_generation_id")
        .ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    let channel_nonce =
        extract_json_string(input, "channel_nonce").ok_or("missing channel_nonce")?;
    if channel_nonce.trim().is_empty() {
        return Err("empty channel_nonce");
    }
    Ok((request_id, runtime_generation_id, channel_nonce))
}

pub fn parse_frame_identity(input: &str) -> Result<(String, String, String), &'static str> {
    let ipc_version = extract_json_string(input, "ipc_version").ok_or("missing ipc_version")?;
    if ipc_version != RUST_IPC_VERSION {
        return Err("unsupported ipc_version");
    }
    let frame_type = extract_json_string(input, "frame_type").ok_or("missing frame_type")?;
    let request_id = extract_json_string(input, "request_id").ok_or("missing request_id")?;
    if request_id.trim().is_empty() {
        return Err("empty request_id");
    }
    let runtime_generation_id = extract_json_string(input, "runtime_generation_id")
        .ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    Ok((frame_type, request_id, runtime_generation_id))
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkerLeaseReplayKey {
    pub lease_id: String,
    pub lease_nonce: String,
}

pub fn parse_worker_lease_replay_key(input: &str) -> Result<WorkerLeaseReplayKey, &'static str> {
    let lease_id = extract_json_string(input, "lease_id").ok_or("missing lease_id")?;
    if lease_id.trim().is_empty() {
        return Err("empty lease_id");
    }
    let lease_nonce = extract_json_string(input, "lease_nonce").ok_or("missing lease_nonce")?;
    if lease_nonce.trim().is_empty() {
        return Err("empty lease_nonce");
    }
    Ok(WorkerLeaseReplayKey {
        lease_id,
        lease_nonce,
    })
}

pub fn parse_worker_invocation_identity(
    input: &str,
) -> Result<WorkerInvocationIdentity, &'static str> {
    let package_hash = extract_json_string(input, "package_hash").ok_or("missing package_hash")?;
    if !is_sha256_ref(&package_hash) {
        return Err("invalid package_hash");
    }
    let artifact = extract_json_string(input, "artifact").ok_or("missing artifact")?;
    if !is_worker_artifact_path(&artifact) {
        return Err("invalid artifact");
    }
    let artifact_sha256 =
        extract_json_string(input, "artifact_sha256").ok_or("missing artifact_sha256")?;
    if !is_sha256_ref(&artifact_sha256) {
        return Err("invalid artifact_sha256");
    }
    let worker_id = extract_json_string(input, "worker_id").ok_or("missing worker_id")?;
    if worker_id.trim().is_empty() {
        return Err("empty worker_id");
    }
    let method = extract_json_string(input, "method").ok_or("missing method")?;
    if method.trim().is_empty() {
        return Err("empty method");
    }
    let export = extract_json_string(input, "export").ok_or("missing export")?;
    if !matches!(
        export.as_str(),
        "redevplugin_worker_invoke" | "redevplugin_actor_start" | "redevplugin_actor_stop"
    ) {
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
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn validates_hello_frame() {
        let input = r#"{"ipc_version":"rust-ipc-v1","frame_type":"hello","request_id":"r1","runtime_generation_id":"g1","payload":{"channel_nonce":"nonce_1"}}"#;
        let (request_id, generation_id, channel_nonce) =
            validate_hello_frame(input).expect("valid hello");
        assert_eq!(request_id, "r1");
        assert_eq!(generation_id, "g1");
        assert_eq!(channel_nonce, "nonce_1");
    }

    #[test]
    fn rejects_hello_frame_without_channel_nonce() {
        let input = r#"{"ipc_version":"rust-ipc-v1","frame_type":"hello","request_id":"r1","runtime_generation_id":"g1","payload":{}}"#;
        assert_eq!(validate_hello_frame(input), Err("missing channel_nonce"));
    }

    #[test]
    fn renders_hello_ack_frame() {
        let frame = hello_ack_frame("r1", "g1", "nonce_1", "0.0.0-dev", WASM_ABI_VERSION);
        assert!(frame.contains(r#""frame_type":"hello_ack""#));
        assert!(frame.contains(r#""request_id":"r1""#));
        assert!(frame.contains(r#""runtime_generation_id":"g1""#));
        assert!(frame.contains(r#""rust_ipc_version":"rust-ipc-v1""#));
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
            Some(ERR_WASM_NOT_IMPLEMENTED),
            Some("runtime worker execution is not implemented"),
        );
        assert!(frame.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(frame.contains(r#""ok":false"#));
        assert!(frame.contains(r#""code":"WASM_NOT_IMPLEMENTED""#));
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
        let result = revoke_epoch_ack_result_json("plugini_1", 7, 1, 2, 3, 4);
        assert!(result.contains(r#""plugin_instance_id":"plugini_1""#));
        assert!(result.contains(r#""revoke_epoch":7"#));
        assert!(result.contains(r#""closed_actor_count":1"#));
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{"ok":true,"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"AAE="}}"#;
        validate_open_handle_response(frame, "r1:artifact", "g1", &identity)
            .expect("valid open_handle");
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"validate_handle_grant","request_id":"r1:handle","runtime_generation_id":"g1","payload":{"ok":true,"handle_grant_id":"h1","handle_id":"storage:db","method":"storage.sqlite","runtime_generation_id":"g1","max_total_bytes":4096}}"#;
        validate_handle_grant_response(frame, "r1:handle", "g1", "storage:db", "storage.sqlite")
            .expect("valid handle grant");
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/today.txt","data_base64":"aGVsbG8=","size_bytes":5}}"#;
        validate_storage_file_response(frame, "r1:storage_file", "g1")
            .expect("valid storage file response");
        let payload = storage_file_payload_json(frame).expect("storage file payload");
        assert!(payload.contains(r#""path":"notes/today.txt""#));
        let failed = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_FILE_NOT_FOUND","message":"missing"}}"#;
        let err = validate_storage_file_response(failed, "r1:storage_file", "g1")
            .expect_err("failed storage file response");
        assert!(err.contains("STORAGE_FILE_NOT_FOUND"));
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":true,"key":"demo/last_broker_run","size_bytes":5}}"#;
        validate_storage_kv_response(frame, "r1:storage_kv", "g1")
            .expect("valid storage kv response");
        let payload = storage_kv_payload_json(frame).expect("storage kv payload");
        assert!(payload.contains(r#""key":"demo/last_broker_run""#));
        let failed = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_kv","request_id":"r1:storage_kv","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_KV_NOT_FOUND","message":"missing"}}"#;
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
            Some(r#"{"ok":true,"transport":"http","status_code":201}"#),
        );
        assert!(result.contains(r#""storage_file":{"ok":true"#));
        assert!(result.contains(r#""storage_kv":{"ok":true"#));
        assert!(result.contains(r#""storage_sqlite":{"ok":true"#));
        assert!(result.contains(r#""network_execute":{"ok":true"#));
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":true,"database":"plugin.sqlite","columns":["title"],"rows":[[{"text":"stored from wasm"}]]}}"#;
        validate_storage_sqlite_response(frame, "r1:storage_sqlite", "g1")
            .expect("valid storage sqlite response");
        let payload = storage_sqlite_payload_json(frame).expect("storage sqlite payload");
        assert!(payload.contains(r#""database":"plugin.sqlite""#));
        let failed = r#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_sqlite","request_id":"r1:storage_sqlite","runtime_generation_id":"g1","payload":{"ok":false,"code":"STORAGE_SQLITE_RESULT_TOO_LARGE","message":"too large"}}"#;
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
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":true,"grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"runtime_generation_id":"g1","target_classifier_version":"target-classifier-v1","expires_at":"2026-06-30T10:00:30Z"}}"#;
        validate_network_grant_response(frame, "r1:network_grant", "g1", "api", "http")
            .expect("valid network grant response");
        let failed = r#"{"ipc_version":"rust-ipc-v1","frame_type":"network_grant","request_id":"r1:network_grant","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_TARGET_DENIED","message":"blocked"}}"#;
        let err = validate_network_grant_response(failed, "r1:network_grant", "g1", "api", "http")
            .expect_err("failed network grant response");
        assert!(err.contains("NETWORK_TARGET_DENIED"));
    }

    #[test]
    fn renders_network_execute_frame() {
        let req = NetworkExecuteRequest {
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
            headers_json: r#"{"X-Test":["ok"]}"#.to_string(),
            message_type: "".to_string(),
            body_base64: "e30=".to_string(),
            payload_base64: "".to_string(),
            max_request_bytes: 1024,
            max_response_bytes: 2048,
            timeout_ms: 2000,
        };
        let frame = network_execute_frame("r1:network_execute", "g1", &req);
        assert!(frame.contains(r#""frame_type":"network_execute""#));
        assert!(frame.contains(r#""operation":"http""#));
        assert!(frame.contains(r#""headers":{"X-Test":["ok"]}"#));
        assert!(frame.contains(r#""body_base64":"e30=""#));
        assert!(frame.contains(r#""timeout_ms":2000"#));
    }

    #[test]
    fn validates_network_execute_response() {
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":true,"transport":"http","destination":{"transport":"http","scheme":"https","host":"api.example.com","port":443},"status_code":201,"headers":{"X-Worker":["ok"]},"body_base64":"e30=","grant_id":"netgrant_00112233445566778899aabbccddeeff","connector_id":"api","runtime_generation_id":"g1"}}"#;
        validate_network_execute_response(frame, "r1:network_execute", "g1", "api", "http")
            .expect("valid network execute response");
        let failed = r#"{"ipc_version":"rust-ipc-v1","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":false,"code":"NETWORK_RESPONSE_TOO_LARGE","message":"too large"}}"#;
        let err =
            validate_network_execute_response(failed, "r1:network_execute", "g1", "api", "http")
                .expect_err("failed network execute response");
        assert!(err.contains("NETWORK_RESPONSE_TOO_LARGE"));
    }

    #[test]
    fn parses_worker_invocation_identity() {
        let frame = r#"{"payload":{"invocation":{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}}}"#;
        let identity = parse_worker_invocation_identity(frame).expect("valid invocation");
        assert_eq!(
            identity.package_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(identity.artifact, "workers/backend.wasm");
        assert_eq!(identity.worker_id, "backend");
    }

    #[test]
    fn rejects_worker_invocation_without_artifact_identity() {
        let err = parse_worker_invocation_identity(
            r#"{"payload":{"invocation":{"artifact":"../backend.wasm"}}}"#,
        )
        .expect_err("invalid invocation");
        assert_eq!(err, "missing package_hash");
        let err = parse_worker_invocation_identity(r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/../backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}"#)
            .expect_err("invalid artifact");
        assert_eq!(err, "invalid artifact");
    }

    #[test]
    fn parses_worker_lease_replay_key() {
        let input = r#"{"payload":{"lease":{"lease_id":"lease_1","lease_nonce":"nonce_1"}}}"#;
        let key = parse_worker_lease_replay_key(input).expect("valid replay key");
        assert_eq!(key.lease_id, "lease_1");
        assert_eq!(key.lease_nonce, "nonce_1");
    }

    #[test]
    fn rejects_worker_lease_replay_key_without_nonce() {
        let err = parse_worker_lease_replay_key(r#"{"payload":{"lease":{"lease_id":"lease_1"}}}"#)
            .expect_err("missing nonce should fail");
        assert_eq!(err, "missing lease_nonce");
    }
}
