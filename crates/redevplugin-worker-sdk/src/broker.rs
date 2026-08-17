use crate::WorkerError;
use crate::api;
use crate::error::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn call_broker<Request, Response>(
    operation: &str,
    request: &Request,
) -> Result<Response, WorkerError>
where
    Request: Serialize,
    Response: for<'de> Deserialize<'de>,
{
    api::call(operation, request).map_err(worker_error)
}

fn worker_error(error: Error) -> WorkerError {
    error.into()
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
            call_broker(
                "storage.files",
                &OperationRequest {
                    operation: "read",
                    request: &request,
                },
            )
        }

        pub fn write(request: WriteRequest) -> Result<WriteResponse, WorkerError> {
            call_broker(
                "storage.files",
                &OperationRequest {
                    operation: "write",
                    request: &request,
                },
            )
        }

        pub fn delete(request: DeleteRequest) -> Result<DeleteResponse, WorkerError> {
            call_broker(
                "storage.files",
                &OperationRequest {
                    operation: "delete",
                    request: &request,
                },
            )
        }

        pub fn list(request: ListRequest) -> Result<ListResponse, WorkerError> {
            call_broker(
                "storage.files",
                &OperationRequest {
                    operation: "list",
                    request: &request,
                },
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
            call_broker(
                "storage.kv",
                &OperationRequest {
                    operation: "get",
                    request: &request,
                },
            )
        }

        pub fn put(request: PutRequest) -> Result<PutResponse, WorkerError> {
            call_broker(
                "storage.kv",
                &OperationRequest {
                    operation: "put",
                    request: &request,
                },
            )
        }

        pub fn delete(request: DeleteRequest) -> Result<DeleteResponse, WorkerError> {
            call_broker(
                "storage.kv",
                &OperationRequest {
                    operation: "delete",
                    request: &request,
                },
            )
        }

        pub fn list(request: ListRequest) -> Result<ListResponse, WorkerError> {
            call_broker(
                "storage.kv",
                &OperationRequest {
                    operation: "list",
                    request: &request,
                },
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
            call_broker(
                "storage.sqlite",
                &OperationRequest {
                    operation: "exec",
                    request: &request,
                },
            )
        }

        pub fn query(request: QueryRequest) -> Result<QueryResponse, WorkerError> {
            call_broker(
                "storage.sqlite",
                &OperationRequest {
                    operation: "query",
                    request: &request,
                },
            )
        }
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
    fn storage_operation_is_an_argument_of_the_single_control_call() {
        let encoded = serde_json::to_value(OperationRequest {
            operation: "query",
            request: &storage::sqlite::QueryRequest {
                store_id: "memos".to_string(),
                database: "memos.sqlite".to_string(),
                sql: "SELECT 1".to_string(),
                args: vec![],
                max_rows: Some(1),
                max_response_bytes: Some(4096),
                timeout_ms: Some(1000),
            },
        })
        .unwrap();
        assert_eq!(encoded["operation"], "query");
        assert_eq!(encoded["store_id"], "memos");
        assert!(encoded.get("plugin_api").is_none());
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

    #[test]
    fn operation_specific_storage_responses_reject_cross_operation_fields() {
        let usage = json!({
            "plugin_instance_id": "plugini_1",
            "store_id": "workspace",
            "usage_bytes": 10,
            "quota_bytes": 100,
            "usage_files": 1,
            "quota_files": 4
        });
        let cases = [
            serde_json::to_vec(&json!({
                "ok": true,
                "path": "notes/a.txt",
                "data_base64": "YQ==",
                "size_bytes": 1,
                "entries": [],
                "usage": usage.clone()
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "ok": true,
                "path": "notes/a.txt",
                "size_bytes": 1,
                "data_base64": "YQ==",
                "usage": usage.clone()
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "ok": true,
                "path": "notes/a.txt",
                "usage": usage.clone()
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "ok": true,
                "path": "notes",
                "entries": [],
                "data_base64": "YQ==",
                "usage": usage.clone()
            }))
            .unwrap(),
        ];
        assert!(serde_json::from_slice::<storage::files::ReadResponse>(&cases[0]).is_err());
        assert!(serde_json::from_slice::<storage::files::WriteResponse>(&cases[1]).is_err());
        assert!(serde_json::from_slice::<storage::files::DeleteResponse>(&cases[2]).is_err());
        assert!(serde_json::from_slice::<storage::files::ListResponse>(&cases[3]).is_err());

        let kv_get = serde_json::to_vec(&json!({
            "ok": true,
            "key": "theme",
            "value_base64": "ZGFyaw==",
            "size_bytes": 4,
            "entries": [],
            "usage": usage.clone()
        }))
        .unwrap();
        let kv_put = serde_json::to_vec(&json!({
            "ok": true,
            "key": "theme",
            "size_bytes": 4,
            "value_base64": "ZGFyaw==",
            "usage": usage.clone()
        }))
        .unwrap();
        let kv_delete = serde_json::to_vec(&json!({
            "ok": true,
            "key": "theme",
            "usage": usage.clone()
        }))
        .unwrap();
        let kv_list = serde_json::to_vec(&json!({
            "ok": true,
            "prefix": "settings/",
            "entries": [],
            "value_base64": "ZGFyaw==",
            "usage": usage.clone()
        }))
        .unwrap();
        assert!(serde_json::from_slice::<storage::kv::GetResponse>(&kv_get).is_err());
        assert!(serde_json::from_slice::<storage::kv::PutResponse>(&kv_put).is_err());
        assert!(serde_json::from_slice::<storage::kv::DeleteResponse>(&kv_delete).is_err());
        assert!(serde_json::from_slice::<storage::kv::ListResponse>(&kv_list).is_err());

        let sqlite_exec = serde_json::to_vec(&json!({
            "ok": true,
            "database": "notes.sqlite",
            "rows_affected": 1,
            "columns": [],
            "rows": [],
            "usage": usage.clone()
        }))
        .unwrap();
        let sqlite_query = serde_json::to_vec(&json!({
            "ok": true,
            "database": "notes.sqlite",
            "columns": [],
            "rows": [],
            "rows_affected": 1,
            "usage": usage
        }))
        .unwrap();
        assert!(serde_json::from_slice::<storage::sqlite::ExecResponse>(&sqlite_exec).is_err());
        assert!(serde_json::from_slice::<storage::sqlite::QueryResponse>(&sqlite_query).is_err());
    }

    #[test]
    fn broker_errors_preserve_the_plugin_api_code_and_message() {
        let error = worker_error(Error {
            code: crate::ErrorCode::PermissionDenied,
            message: "blocked".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
        });
        assert_eq!(error.code, "PERMISSION_DENIED");
        assert_eq!(error.message, "blocked");
    }
}
