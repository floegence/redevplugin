use crate::WorkerError;
use crate::api;
use crate::decode_base64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_buffer_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runtime_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub program: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub environment: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_removals: Vec<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secret_references: std::collections::BTreeMap<String, String>,
    pub client_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub handle: String,
    pub client_key: String,
    pub state: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub termination_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteResponse {
    pub written: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub handle: String,
    #[serde(default)]
    pub cursor: u64,
    pub max_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadResponse {
    pub data_base64: String,
    pub cursor: u64,
    pub eof: bool,
    pub process_exit: bool,
    pub stream_gap: bool,
    #[serde(default)]
    pub dropped_bytes: u64,
}

impl ReadResponse {
    pub fn data(&self) -> Result<Vec<u8>, WorkerError> {
        decode_base64(&self.data_base64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitResponse {
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub termination_reason: String,
}

#[derive(Serialize)]
struct WriteRequest<'a> {
    handle: &'a str,
    data_base64: String,
}

#[derive(Serialize)]
struct HandleRequest<'a> {
    handle: &'a str,
}

#[derive(Serialize)]
struct ClientKeyRequest<'a> {
    client_key: &'a str,
}

pub fn start(request: &StartRequest) -> Result<Status, WorkerError> {
    call("process.start", request)
}

pub fn attach(client_key: &str) -> Result<Status, WorkerError> {
    call("process.attach", &ClientKeyRequest { client_key })
}

pub fn status(handle: &str) -> Result<Status, WorkerError> {
    call("process.status", &HandleRequest { handle })
}

pub fn write_stdin(handle: &str, data: &[u8]) -> Result<WriteResponse, WorkerError> {
    call(
        "process.write_stdin",
        &WriteRequest {
            handle,
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
        },
    )
}

pub fn close_stdin(handle: &str) -> Result<(), WorkerError> {
    call::<_, serde_json::Value>("process.close_stdin", &HandleRequest { handle }).map(|_| ())
}

pub fn read_stdout(request: &ReadRequest) -> Result<ReadResponse, WorkerError> {
    call("process.read_stdout", request)
}

pub fn read_stderr(request: &ReadRequest) -> Result<ReadResponse, WorkerError> {
    call("process.read_stderr", request)
}

pub fn wait(handle: &str) -> Result<ExitResponse, WorkerError> {
    call("process.wait", &HandleRequest { handle })
}

pub fn terminate(handle: &str) -> Result<(), WorkerError> {
    call::<_, serde_json::Value>("process.terminate", &HandleRequest { handle }).map(|_| ())
}

pub fn kill(handle: &str) -> Result<(), WorkerError> {
    call::<_, serde_json::Value>("process.kill", &HandleRequest { handle }).map(|_| ())
}

pub fn close(handle: &str) -> Result<(), WorkerError> {
    call::<_, serde_json::Value>("process.close", &HandleRequest { handle }).map(|_| ())
}

fn call<RequestValue, ResponseValue>(
    operation: &str,
    request: &RequestValue,
) -> Result<ResponseValue, WorkerError>
where
    RequestValue: Serialize,
    ResponseValue: for<'de> Deserialize<'de>,
{
    api::call(operation, request).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_read_result_decodes_binary_data_without_text_assumptions() {
        let result: ReadResponse = serde_json::from_value(serde_json::json!({
            "data_base64": "AP8B",
            "cursor": 3,
            "eof": false,
            "process_exit": false,
            "stream_gap": false
        }))
        .unwrap();
        assert_eq!(result.data().unwrap(), vec![0, 255, 1]);
    }

    #[test]
    fn process_start_request_contains_secret_references_not_secret_values() {
        let request = StartRequest {
            program: "tool".into(),
            argv: vec!["--json".into()],
            cwd: None,
            environment: std::collections::BTreeMap::new(),
            environment_removals: Vec::new(),
            secret_references: std::collections::BTreeMap::from([(
                "TOKEN".into(),
                "secret.token".into(),
            )]),
            client_key: "client".into(),
            resource_limits: None,
        };
        let encoded = serde_json::to_value(request).unwrap();
        assert_eq!(encoded["secret_references"]["TOKEN"], "secret.token");
        assert!(encoded.get("TOKEN").is_none());
    }
}
