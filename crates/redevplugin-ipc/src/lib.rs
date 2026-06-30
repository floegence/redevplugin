pub const RUST_IPC_VERSION: &str = "rust-ipc-v1";
pub const WASM_ABI_VERSION: &str = "redeven-wasm-worker-v1";
pub const FRAME_TYPE_HELLO: &str = "hello";
pub const FRAME_TYPE_HELLO_ACK: &str = "hello_ack";
pub const FRAME_TYPE_INVOKE_WORKER: &str = "invoke_worker";
pub const FRAME_TYPE_INVOKE_WORKER_RESULT: &str = "invoke_worker_result";
pub const FRAME_TYPE_OPEN_HANDLE: &str = "open_handle";
pub const FRAME_TYPE_VALIDATE_HANDLE_GRANT: &str = "validate_handle_grant";
pub const FRAME_TYPE_REVOKE_EPOCH: &str = "revoke_epoch";
pub const FRAME_TYPE_REVOKE_EPOCH_ACK: &str = "revoke_epoch_ack";
pub const ERR_ARTIFACT_HANDLE_FAILED: &str = "ARTIFACT_HANDLE_FAILED";
pub const ERR_HANDLE_GRANT_VALIDATION_FAILED: &str = "HANDLE_GRANT_VALIDATION_FAILED";
pub const ERR_WORKER_INVOCATION_INVALID: &str = "WORKER_INVOCATION_INVALID";
pub const ERR_WASM_NOT_IMPLEMENTED: &str = "WASM_NOT_IMPLEMENTED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Hello,
    HelloAck,
    Heartbeat,
    LeaseGrant,
    InvokeWorker,
    InvokeWorkerResult,
    OpenHandle,
    CloseHandle,
    RevokeEpoch,
    RevokeEpochAck,
    Diagnostic,
}

pub fn extract_json_string(input: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
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
    runtime_version: &str,
    wasm_abi_version: &str,
) -> String {
    format!(
        "{{\"ipc_version\":\"{}\",\"frame_type\":\"{}\",\"request_id\":\"{}\",\"runtime_generation_id\":\"{}\",\"payload\":{{\"runtime_version\":\"{}\",\"rust_ipc_version\":\"{}\",\"wasm_abi_version\":\"{}\"}}}}",
        RUST_IPC_VERSION,
        FRAME_TYPE_HELLO_ACK,
        escape_json_string(request_id),
        escape_json_string(runtime_generation_id),
        escape_json_string(runtime_version),
        RUST_IPC_VERSION,
        escape_json_string(wasm_abi_version)
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
    let package_hash =
        extract_json_string(input, "package_hash").ok_or("missing package_hash")?;
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

pub fn validate_hello_frame(input: &str) -> Result<(String, String), &'static str> {
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
    let runtime_generation_id =
        extract_json_string(input, "runtime_generation_id").ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    Ok((request_id, runtime_generation_id))
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
    let runtime_generation_id =
        extract_json_string(input, "runtime_generation_id").ok_or("missing runtime_generation_id")?;
    if runtime_generation_id.trim().is_empty() {
        return Err("empty runtime_generation_id");
    }
    Ok((frame_type, request_id, runtime_generation_id))
}

pub fn extract_json_bool(input: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
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
        "redeven_worker_invoke" | "redeven_actor_start" | "redeven_actor_stop"
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
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
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

    #[test]
    fn validates_hello_frame() {
        let input = r#"{"ipc_version":"rust-ipc-v1","frame_type":"hello","request_id":"r1","runtime_generation_id":"g1","payload":{}}"#;
        let (request_id, generation_id) = validate_hello_frame(input).expect("valid hello");
        assert_eq!(request_id, "r1");
        assert_eq!(generation_id, "g1");
    }

    #[test]
    fn renders_hello_ack_frame() {
        let frame = hello_ack_frame("r1", "g1", "0.0.0-dev", WASM_ABI_VERSION);
        assert!(frame.contains(r#""frame_type":"hello_ack""#));
        assert!(frame.contains(r#""request_id":"r1""#));
        assert!(frame.contains(r#""runtime_generation_id":"g1""#));
        assert!(frame.contains(r#""rust_ipc_version":"rust-ipc-v1""#));
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
            export: "redeven_worker_invoke".to_string(),
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
            export: "redeven_worker_invoke".to_string(),
        };
        let frame = r#"{"ipc_version":"rust-ipc-v1","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{"ok":true,"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"AAE="}}"#;
        validate_open_handle_response(frame, "r1:artifact", "g1", &identity).expect("valid open_handle");
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
    fn parses_worker_invocation_identity() {
        let frame = r#"{"payload":{"invocation":{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redeven_worker_invoke"}}}"#;
        let identity = parse_worker_invocation_identity(frame).expect("valid invocation");
        assert_eq!(identity.package_hash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(identity.artifact, "workers/backend.wasm");
        assert_eq!(identity.worker_id, "backend");
    }

    #[test]
    fn rejects_worker_invocation_without_artifact_identity() {
        let err = parse_worker_invocation_identity(r#"{"payload":{"invocation":{"artifact":"../backend.wasm"}}}"#)
            .expect_err("invalid invocation");
        assert_eq!(err, "missing package_hash");
        let err = parse_worker_invocation_identity(r#"{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/../backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redeven_worker_invoke"}"#)
            .expect_err("invalid artifact");
        assert_eq!(err, "invalid artifact");
    }
}
