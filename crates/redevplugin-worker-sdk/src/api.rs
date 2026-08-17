use crate::PLUGIN_API;
use crate::error::{Error, Result};
use crate::resource::call_control_raw;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
struct ControlRequest<'a, Arguments> {
    plugin_api: u16,
    operation: &'a str,
    arguments: &'a Arguments,
}

#[derive(serde::Deserialize)]
struct ControlResponse {
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Error>,
}

pub(crate) fn call<Arguments, ResultValue>(
    operation: &str,
    arguments: &Arguments,
) -> Result<ResultValue>
where
    Arguments: Serialize,
    ResultValue: DeserializeOwned,
{
    let request = serde_json::to_vec(&ControlRequest {
        plugin_api: PLUGIN_API,
        operation,
        arguments,
    })
    .map_err(|error| Error::internal(format!("encode Worker API request: {error}")))?;
    let response = call_control_raw(&request)?;
    decode_response(&response)
}

fn decode_response<ResultValue>(raw: &[u8]) -> Result<ResultValue>
where
    ResultValue: DeserializeOwned,
{
    let response: ControlResponse = serde_json::from_slice(raw)
        .map_err(|error| Error::internal(format!("decode Worker API response: {error}")))?;
    match (response.ok, response.result, response.error) {
        (true, Some(result), _) => serde_json::from_value(result)
            .map_err(|error| Error::internal(format!("decode typed Worker API result: {error}"))),
        (false, _, Some(error)) if !error.message.trim().is_empty() => Err(error),
        _ => Err(Error::internal("Worker API response branch is incomplete")),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Context {
    pub plugin_id: String,
    pub plugin_version: String,
    pub scope_kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    pub control_response_bytes: u64,
    pub io_chunk_bytes: u64,
    pub open_files_min: u32,
    pub open_connections_min: u32,
    pub open_watches_min: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub plugin_api: u16,
    #[serde(default)]
    pub features: Vec<String>,
    pub limits: Limits,
}

pub fn context() -> Result<Context> {
    call("platform.context", &serde_json::json!({}))
}

pub fn capabilities() -> Result<Capabilities> {
    call("platform.capabilities", &serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn control_request_uses_the_single_plugin_api_identity() {
        let request = serde_json::to_value(ControlRequest {
            plugin_api: PLUGIN_API,
            operation: "storage.sqlite",
            arguments: &json!({"operation": "query"}),
        })
        .unwrap();
        assert_eq!(
            request,
            json!({
                "plugin_api": PLUGIN_API,
                "operation": "storage.sqlite",
                "arguments": {"operation": "query"}
            })
        );
    }

    #[test]
    fn new_control_reader_tolerates_unknown_optional_fields() {
        let value: Value = decode_response(
            br#"{"ok":true,"result":{"plugin_api":1,"future":true},"future_envelope":7}"#,
        )
        .unwrap();
        assert_eq!(value["plugin_api"], 1);
        let error = decode_response::<Value>(
            br#"{"ok":false,"error":{"code":"TIMEOUT","message":"late","retryable":true,"details":{},"future":1},"future_envelope":7}"#,
        )
        .unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::Timeout);
        assert!(error.retryable);
    }
}
