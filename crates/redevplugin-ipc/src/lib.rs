pub const RUST_IPC_VERSION: &str = "rust-ipc-v1";
pub const WASM_ABI_VERSION: &str = "redeven-wasm-worker-v1";
pub const FRAME_TYPE_HELLO: &str = "hello";
pub const FRAME_TYPE_HELLO_ACK: &str = "hello_ack";
pub const FRAME_TYPE_INVOKE_WORKER: &str = "invoke_worker";
pub const FRAME_TYPE_INVOKE_WORKER_RESULT: &str = "invoke_worker_result";
pub const FRAME_TYPE_REVOKE_EPOCH: &str = "revoke_epoch";
pub const FRAME_TYPE_REVOKE_EPOCH_ACK: &str = "revoke_epoch_ack";

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
            Some("WASM_NOT_IMPLEMENTED"),
            Some("runtime worker execution is not implemented"),
        );
        assert!(frame.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(frame.contains(r#""ok":false"#));
        assert!(frame.contains(r#""code":"WASM_NOT_IMPLEMENTED""#));
    }
}
