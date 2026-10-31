use base64::{Engine, engine::general_purpose::STANDARD};
use redevplugin_worker_sdk::{
    WorkerError, WorkerRequest, WorkerResult, data_upgrade as upgrade, export_worker, storage,
};
use serde_json::json;

// Exercise the public author SDK against real Host storage and WASM transport.
fn handle(request: WorkerRequest) -> WorkerResult {
    let params: upgrade::Parameters = serde_json::from_value(request.params)
        .map_err(|_| WorkerError::invalid_request("invalid upgrade parameters"))?;
    if params.scope == "environment" {
        return Ok(json!({}));
    }
    let old = upgrade::read_settings(upgrade::Dataset::Input)?;
    let count = old
        .values
        .get("count")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| WorkerError::invalid_request("invalid old count"))?;
    upgrade::write_settings([("count".into(), json!(count + 1))].into())?;
    let file = upgrade::files::read(
        upgrade::Dataset::Input,
        storage::files::ReadRequest {
            store_id: "workspace".into(),
            path: "note.txt".into(),
            max_bytes: Some(4096),
        },
    )?;
    let mut bytes = STANDARD
        .decode(file.data_base64)
        .map_err(|_| WorkerError::invalid_request("invalid file encoding"))?;
    bytes.extend_from_slice(b" upgraded");
    upgrade::files::write(storage::files::WriteRequest {
        store_id: "workspace".into(),
        path: "note.txt".into(),
        data_base64: STANDARD.encode(bytes),
    })?;
    let value = upgrade::kv::get(
        upgrade::Dataset::Input,
        storage::kv::GetRequest {
            store_id: "cache".into(),
            key: "message".into(),
            max_bytes: Some(4096),
        },
    )?;
    upgrade::kv::put(storage::kv::PutRequest {
        store_id: "cache".into(),
        key: "converted".into(),
        value_base64: value.value_base64,
    })?;
    let rows = upgrade::sqlite::query(
        upgrade::Dataset::Input,
        storage::sqlite::QueryRequest {
            store_id: "records".into(),
            database: String::new(),
            sql: "SELECT value FROM notes".into(),
            args: vec![],
            max_rows: Some(1),
            max_response_bytes: Some(4096),
            timeout_ms: Some(1000),
        },
    )?;
    let value = rows
        .rows
        .first()
        .and_then(|row| row.first())
        .cloned()
        .ok_or_else(|| WorkerError::invalid_request("missing old SQLite value"))?;
    upgrade::sqlite::exec(storage::sqlite::ExecRequest {
        store_id: "records".into(),
        database: String::new(),
        sql: "CREATE TABLE converted(value TEXT)".into(),
        args: vec![],
        timeout_ms: Some(1000),
    })?;
    upgrade::sqlite::exec(storage::sqlite::ExecRequest {
        store_id: "records".into(),
        database: String::new(),
        sql: "INSERT INTO converted(value) VALUES (?)".into(),
        args: vec![value],
        timeout_ms: Some(1000),
    })?;
    Ok(json!({}))
}

export_worker!(handle);
