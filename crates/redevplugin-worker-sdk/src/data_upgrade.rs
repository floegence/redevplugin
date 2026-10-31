//! Data conversion is available only inside the declared upgrade Worker.
//! Input is read-only; output belongs to an unpublished generation. Ordinary
//! resources, credentials and network APIs are unavailable in this invocation.

use crate::{api, error::Result, storage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dataset {
    Input,
    Output,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub from_version: String,
    pub to_version: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub scope: String,
    pub revision: u64,
    pub values: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct Operation<'a, T> {
    operation: &'a str,
    #[serde(flatten)]
    request: &'a T,
}

#[derive(Serialize)]
struct Arguments<'a, T> {
    dataset: Dataset,
    kind: &'a str,
    request: Operation<'a, T>,
}

fn call<T: Serialize, R: for<'de> Deserialize<'de>>(
    dataset: Dataset,
    kind: &str,
    operation: &str,
    request: &T,
) -> Result<R> {
    api::call(
        "data.upgrade",
        &Arguments {
            dataset,
            kind,
            request: Operation { operation, request },
        },
    )
}

pub fn read_settings(dataset: Dataset) -> Result<Settings> {
    call(dataset, "settings", "read", &serde_json::json!({}))
}

pub fn write_settings(values: BTreeMap<String, Value>) -> Result<()> {
    let _: Value = call(
        Dataset::Output,
        "settings",
        "write",
        &serde_json::json!({"values": values}),
    )?;
    Ok(())
}

pub mod files {
    use super::*;
    pub fn read(
        dataset: Dataset,
        request: storage::files::ReadRequest,
    ) -> Result<storage::files::ReadResponse> {
        call(dataset, "files", "read", &request)
    }
    pub fn write(request: storage::files::WriteRequest) -> Result<storage::files::WriteResponse> {
        call(Dataset::Output, "files", "write", &request)
    }
    pub fn delete(
        request: storage::files::DeleteRequest,
    ) -> Result<storage::files::DeleteResponse> {
        call(Dataset::Output, "files", "delete", &request)
    }
    pub fn list(
        dataset: Dataset,
        request: storage::files::ListRequest,
    ) -> Result<storage::files::ListResponse> {
        call(dataset, "files", "list", &request)
    }
}

pub mod kv {
    use super::*;
    pub fn get(
        dataset: Dataset,
        request: storage::kv::GetRequest,
    ) -> Result<storage::kv::GetResponse> {
        call(dataset, "kv", "get", &request)
    }
    pub fn put(request: storage::kv::PutRequest) -> Result<storage::kv::PutResponse> {
        call(Dataset::Output, "kv", "put", &request)
    }
    pub fn delete(request: storage::kv::DeleteRequest) -> Result<storage::kv::DeleteResponse> {
        call(Dataset::Output, "kv", "delete", &request)
    }
    pub fn list(
        dataset: Dataset,
        request: storage::kv::ListRequest,
    ) -> Result<storage::kv::ListResponse> {
        call(dataset, "kv", "list", &request)
    }
}

pub mod sqlite {
    use super::*;
    pub fn query(
        dataset: Dataset,
        request: storage::sqlite::QueryRequest,
    ) -> Result<storage::sqlite::QueryResponse> {
        call(dataset, "sqlite", "query", &request)
    }
    pub fn exec(request: storage::sqlite::ExecRequest) -> Result<storage::sqlite::ExecResponse> {
        call(Dataset::Output, "sqlite", "exec", &request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + for<'de> Deserialize<'de>>(value: Value) -> Value {
        serde_json::to_value(serde_json::from_value::<T>(value).unwrap()).unwrap()
    }

    #[test]
    fn shared_fixtures_match_author_storage_types() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../testdata/data-upgrade-fixtures.json")).unwrap();
        for fixture in fixtures["valid"].as_array().unwrap() {
            let envelope = &fixture["request"];
            let args = &envelope["arguments"];
            let kind = args["kind"].as_str().unwrap();
            let mut request = args["request"].clone();
            let operation = request
                .as_object_mut()
                .unwrap()
                .remove("operation")
                .unwrap();
            let operation = operation.as_str().unwrap();
            let encoded = match (kind, operation) {
                ("files", "read") => round_trip::<storage::files::ReadRequest>(request),
                ("files", "write") => round_trip::<storage::files::WriteRequest>(request),
                ("files", "delete") => round_trip::<storage::files::DeleteRequest>(request),
                ("files", "list") => round_trip::<storage::files::ListRequest>(request),
                ("kv", "get") => round_trip::<storage::kv::GetRequest>(request),
                ("kv", "put") => round_trip::<storage::kv::PutRequest>(request),
                ("kv", "delete") => round_trip::<storage::kv::DeleteRequest>(request),
                ("kv", "list") => round_trip::<storage::kv::ListRequest>(request),
                ("sqlite", "query") => round_trip::<storage::sqlite::QueryRequest>(request),
                ("sqlite", "exec") => round_trip::<storage::sqlite::ExecRequest>(request),
                ("settings", "read" | "write") => request,
                _ => panic!("uncovered canonical operation"),
            };
            let dataset = match args["dataset"].as_str().unwrap() {
                "input" => Dataset::Input,
                "output" => Dataset::Output,
                _ => panic!("invalid dataset"),
            };
            let actual = serde_json::to_value(Arguments {
                dataset,
                kind,
                request: Operation {
                    operation,
                    request: &encoded,
                },
            })
            .unwrap();
            assert_eq!(&actual, args, "{}", fixture["name"]);
        }
    }

    #[test]
    fn upgrade_reuses_storage_requests_with_explicit_dataset() {
        let request = storage::files::ReadRequest {
            store_id: "notes".into(),
            path: "note.txt".into(),
            max_bytes: Some(4096),
        };
        let value = serde_json::to_value(Arguments {
            dataset: Dataset::Input,
            kind: "files",
            request: Operation {
                operation: "read",
                request: &request,
            },
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"dataset":"input","kind":"files","request":{"operation":"read","store_id":"notes","path":"note.txt","max_bytes":4096}})
        );
    }
}
