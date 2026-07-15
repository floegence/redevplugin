use crate::{MAX_HOSTCALL_RESPONSE_BYTES, WorkerError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;

type Hostcall = unsafe extern "C" fn(i32, i32, i32, i32) -> i32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostcallFailure {
    ok: bool,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error_origin: String,
}

fn call_host<Request, Response>(
    request: &Request,
    hostcall: Hostcall,
) -> Result<Response, WorkerError>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let request_bytes = serde_json::to_vec(request)
        .map_err(|err| WorkerError::hostcall(format!("encode hostcall request: {err}")))?;
    let mut response = vec![0_u8; MAX_HOSTCALL_RESPONSE_BYTES];
    let written = unsafe {
        hostcall(
            request_bytes.as_ptr() as i32,
            request_bytes.len() as i32,
            response.as_mut_ptr() as i32,
            response.len() as i32,
        )
    };
    if written < 0 {
        return Err(WorkerError::hostcall(format!(
            "hostcall failed with ABI code {written}"
        )));
    }
    let written = usize::try_from(written)
        .map_err(|_| WorkerError::hostcall("hostcall response length is invalid"))?;
    if written > response.len() {
        return Err(WorkerError::hostcall(
            "hostcall response exceeded the provided buffer",
        ));
    }
    response.truncate(written);
    decode_hostcall_response(&response)
}

fn decode_hostcall_response<Response>(response: &[u8]) -> Result<Response, WorkerError>
where
    Response: DeserializeOwned,
{
    let value: Value = serde_json::from_slice(response)
        .map_err(|err| WorkerError::hostcall(format!("decode hostcall response: {err}")))?;
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => serde_json::from_value(value)
            .map_err(|err| WorkerError::hostcall(format!("decode typed hostcall response: {err}"))),
        Some(false) => {
            let failure: HostcallFailure = serde_json::from_value(value)
                .map_err(|err| WorkerError::hostcall(format!("decode hostcall failure: {err}")))?;
            let _ = failure.ok;
            let _ = failure.error_origin;
            let code = if failure.error_code.trim().is_empty() {
                failure.code.trim()
            } else {
                failure.error_code.trim()
            };
            let message = failure.message.trim();
            Err(WorkerError::new(
                if code.is_empty() {
                    "HOSTCALL_FAILED"
                } else {
                    code
                },
                if message.is_empty() {
                    "hostcall failed"
                } else {
                    message
                },
            ))
        }
        None => Err(WorkerError::hostcall(
            "hostcall response omitted the ok discriminator",
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub plugin_instance_id: String,
    pub store_id: String,
    pub usage_bytes: i64,
    pub quota_bytes: i64,
    pub usage_files: i64,
    pub quota_files: i64,
}

#[derive(Serialize)]
struct OperationRequest<'a, Request> {
    operation: &'static str,
    #[serde(flatten)]
    request: &'a Request,
}

#[link(wasm_import_module = "redevplugin.storage")]
unsafe extern "C" {
    #[link_name = "files"]
    fn storage_files_hostcall(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_len: i32,
    ) -> i32;
    #[link_name = "kv"]
    fn storage_kv_hostcall(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_len: i32,
    ) -> i32;
    #[link_name = "sqlite"]
    fn storage_sqlite_hostcall(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_len: i32,
    ) -> i32;
}

#[link(wasm_import_module = "redevplugin.network")]
unsafe extern "C" {
    #[link_name = "execute"]
    fn network_execute_hostcall(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_len: i32,
    ) -> i32;
}

pub mod storage {
    use super::*;

    pub mod files {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ReadRequest {
            pub store_id: String,
            pub path: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_bytes: Option<u64>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ReadResponse {
            pub ok: bool,
            pub path: String,
            pub data_base64: String,
            pub size_bytes: i64,
            pub usage: Usage,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct WriteRequest {
            pub store_id: String,
            pub path: String,
            pub data_base64: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct WriteResponse {
            pub ok: bool,
            pub path: String,
            pub size_bytes: i64,
            pub usage: Usage,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct DeleteRequest {
            pub store_id: String,
            pub path: String,
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub recursive: bool,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct DeleteResponse {
            pub ok: bool,
            pub path: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ListRequest {
            pub store_id: String,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub path: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_entries: Option<u32>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct Entry {
            pub path: String,
            pub dir: bool,
            #[serde(default)]
            pub size_bytes: i64,
            pub updated_at: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ListResponse {
            pub ok: bool,
            pub path: String,
            pub entries: Vec<Entry>,
            pub usage: Usage,
        }

        pub fn read(request: ReadRequest) -> Result<ReadResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "read",
                    request: &request,
                },
                storage_files_hostcall,
            )
        }

        pub fn write(request: WriteRequest) -> Result<WriteResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "write",
                    request: &request,
                },
                storage_files_hostcall,
            )
        }

        pub fn delete(request: DeleteRequest) -> Result<DeleteResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "delete",
                    request: &request,
                },
                storage_files_hostcall,
            )
        }

        pub fn list(request: ListRequest) -> Result<ListResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "list",
                    request: &request,
                },
                storage_files_hostcall,
            )
        }
    }

    pub mod kv {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct GetRequest {
            pub store_id: String,
            pub key: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_bytes: Option<u64>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct GetResponse {
            pub ok: bool,
            pub key: String,
            pub value_base64: String,
            pub size_bytes: i64,
            pub usage: Usage,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PutRequest {
            pub store_id: String,
            pub key: String,
            pub value_base64: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PutResponse {
            pub ok: bool,
            pub key: String,
            pub size_bytes: i64,
            pub usage: Usage,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct DeleteRequest {
            pub store_id: String,
            pub key: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct DeleteResponse {
            pub ok: bool,
            pub key: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ListRequest {
            pub store_id: String,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub prefix: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_entries: Option<u32>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct Entry {
            pub key: String,
            pub size_bytes: i64,
            pub updated_at: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ListResponse {
            pub ok: bool,
            #[serde(default)]
            pub prefix: String,
            pub entries: Vec<Entry>,
            pub usage: Usage,
        }

        pub fn get(request: GetRequest) -> Result<GetResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "get",
                    request: &request,
                },
                storage_kv_hostcall,
            )
        }

        pub fn put(request: PutRequest) -> Result<PutResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "put",
                    request: &request,
                },
                storage_kv_hostcall,
            )
        }

        pub fn delete(request: DeleteRequest) -> Result<DeleteResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "delete",
                    request: &request,
                },
                storage_kv_hostcall,
            )
        }

        pub fn list(request: ListRequest) -> Result<ListResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "list",
                    request: &request,
                },
                storage_kv_hostcall,
            )
        }
    }

    pub mod sqlite {
        use super::*;

        #[derive(Debug, Clone, PartialEq)]
        pub enum Value {
            Null,
            Integer(i64),
            Float(f64),
            Text(String),
            BlobBase64(String),
        }

        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ValueWire {
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            null: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            int: Option<i64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            float: Option<f64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            text: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            blob_base64: Option<String>,
        }

        impl Serialize for Value {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let wire = match self {
                    Self::Null => ValueWire {
                        null: true,
                        int: None,
                        float: None,
                        text: None,
                        blob_base64: None,
                    },
                    Self::Integer(value) => ValueWire {
                        null: false,
                        int: Some(*value),
                        float: None,
                        text: None,
                        blob_base64: None,
                    },
                    Self::Float(value) => ValueWire {
                        null: false,
                        int: None,
                        float: Some(*value),
                        text: None,
                        blob_base64: None,
                    },
                    Self::Text(value) => ValueWire {
                        null: false,
                        int: None,
                        float: None,
                        text: Some(value.clone()),
                        blob_base64: None,
                    },
                    Self::BlobBase64(value) => ValueWire {
                        null: false,
                        int: None,
                        float: None,
                        text: None,
                        blob_base64: Some(value.clone()),
                    },
                };
                wire.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for Value {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let wire = ValueWire::deserialize(deserializer)?;
                let variants = usize::from(wire.null)
                    + usize::from(wire.int.is_some())
                    + usize::from(wire.float.is_some())
                    + usize::from(wire.text.is_some())
                    + usize::from(wire.blob_base64.is_some());
                if variants != 1 {
                    return Err(serde::de::Error::custom(
                        "SQLite value must contain exactly one typed field",
                    ));
                }
                if wire.null {
                    return Ok(Self::Null);
                }
                if let Some(value) = wire.int {
                    return Ok(Self::Integer(value));
                }
                if let Some(value) = wire.float {
                    return Ok(Self::Float(value));
                }
                if let Some(value) = wire.text {
                    return Ok(Self::Text(value));
                }
                Ok(Self::BlobBase64(wire.blob_base64.unwrap_or_default()))
            }
        }

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ExecRequest {
            pub store_id: String,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub database: String,
            pub sql: String,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub args: Vec<Value>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub timeout_ms: Option<u64>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ExecResponse {
            pub ok: bool,
            pub database: String,
            pub rows_affected: i64,
            #[serde(default)]
            pub last_insert_id: i64,
            pub usage: Usage,
        }

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct QueryRequest {
            pub store_id: String,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub database: String,
            pub sql: String,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub args: Vec<Value>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_rows: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub max_response_bytes: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub timeout_ms: Option<u64>,
        }

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct QueryResponse {
            pub ok: bool,
            pub database: String,
            pub columns: Vec<String>,
            pub rows: Vec<Vec<Value>>,
            pub usage: Usage,
        }

        pub fn exec(request: ExecRequest) -> Result<ExecResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "exec",
                    request: &request,
                },
                storage_sqlite_hostcall,
            )
        }

        pub fn query(request: QueryRequest) -> Result<QueryResponse, WorkerError> {
            call_host(
                &OperationRequest {
                    operation: "query",
                    request: &request,
                },
                storage_sqlite_hostcall,
            )
        }
    }
}

pub mod network {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Transport {
        Http,
        Websocket,
        Tcp,
        Udp,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Operation {
        Http,
        HttpStream,
        WebsocketRoundTrip,
        TcpRoundTrip,
        UdpRoundTrip,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExecuteRequest {
        pub connector_id: String,
        pub transport: Transport,
        pub destination: String,
        pub operation: Operation,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub method: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub path: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub query: BTreeMap<String, Vec<String>>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub headers: BTreeMap<String, Vec<String>>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub message_type: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub body_base64: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub payload_base64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ttl_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_request_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_response_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_chunk_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_buffered_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub content_type: String,
    }

    impl ExecuteRequest {
        pub fn http_get(
            connector_id: impl Into<String>,
            destination: impl Into<String>,
            path: impl Into<String>,
        ) -> Self {
            Self {
                connector_id: connector_id.into(),
                transport: Transport::Http,
                destination: destination.into(),
                operation: Operation::Http,
                method: "GET".to_string(),
                path: path.into(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                message_type: String::new(),
                body_base64: String::new(),
                payload_base64: String::new(),
                ttl_ms: None,
                max_request_bytes: None,
                max_response_bytes: None,
                max_chunk_bytes: None,
                max_buffered_bytes: None,
                timeout_ms: None,
                content_type: String::new(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Destination {
        pub transport: Transport,
        #[serde(default)]
        pub scheme: String,
        pub host: String,
        pub port: u16,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExecuteResponse {
        pub ok: bool,
        #[serde(default)]
        pub transport: Option<Transport>,
        #[serde(default)]
        pub destination: Option<Destination>,
        #[serde(default)]
        pub status_code: Option<u16>,
        #[serde(default)]
        pub headers: BTreeMap<String, Vec<String>>,
        #[serde(default)]
        pub message_type: String,
        #[serde(default)]
        pub body_base64: String,
        #[serde(default)]
        pub payload_base64: String,
        #[serde(default)]
        pub stream_id: String,
        #[serde(default)]
        pub bytes_read: i64,
        #[serde(default)]
        pub chunk_count: u32,
        #[serde(default)]
        pub grant_id: String,
        #[serde(default)]
        pub connector_id: String,
        #[serde(default)]
        pub runtime_generation_id: String,
    }

    pub fn execute(request: ExecuteRequest) -> Result<ExecuteResponse, WorkerError> {
        call_host(&request, network_execute_hostcall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sqlite_values_are_exactly_typed() {
        let values = vec![
            storage::sqlite::Value::Null,
            storage::sqlite::Value::Integer(7),
            storage::sqlite::Value::Float(1.5),
            storage::sqlite::Value::Text("memo".to_string()),
            storage::sqlite::Value::BlobBase64("AAE=".to_string()),
        ];
        let encoded = serde_json::to_value(&values).unwrap();
        let decoded: Vec<storage::sqlite::Value> = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, values);
        assert!(
            serde_json::from_value::<storage::sqlite::Value>(json!({"int": 1, "text": "x"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<storage::sqlite::Value>(
                json!({"text": "x", "token": "secret"})
            )
            .is_err()
        );
    }

    #[test]
    fn network_request_cannot_encode_host_owned_invocation_fields() {
        let mut request = network::ExecuteRequest::http_get(
            "forecast",
            "https://api.example.com",
            "/v1/forecast",
        );
        request
            .query
            .insert("latitude".to_string(), vec!["52.52".to_string()]);
        let encoded = serde_json::to_value(request).unwrap();
        assert_eq!(encoded["operation"], "http");
        for forbidden in [
            "stream_id",
            "surface_instance_id",
            "owner_session_hash",
            "owner_user_hash",
            "session_channel_id_hash",
            "bridge_channel_id",
        ] {
            assert!(encoded.get(forbidden).is_none(), "unexpected {forbidden}");
        }
    }

    #[test]
    fn typed_success_responses_reject_unknown_fields() {
        let response = json!({
            "ok": true,
            "database": "notes.sqlite",
            "columns": ["title"],
            "rows": [[{"text": "Launch"}]],
            "usage": {
                "plugin_instance_id": "plugini_1",
                "store_id": "notes",
                "usage_bytes": 10,
                "quota_bytes": 100,
                "usage_files": 1,
                "quota_files": 4
            },
            "handle_grant_token": "secret"
        });
        assert!(serde_json::from_value::<storage::sqlite::QueryResponse>(response).is_err());
    }
}
