use redevplugin_worker_sdk::{WorkerRequest, WorkerResult, export_worker, storage};
use serde_json::json;

// A normal author method; scheduling does not add a Worker protocol or SDK.
fn handle(_request: WorkerRequest) -> WorkerResult {
    storage::sqlite::exec(storage::sqlite::ExecRequest {
        store_id: "counter".into(),
        database: String::new(),
        sql: "CREATE TABLE IF NOT EXISTS ticks(id INTEGER PRIMARY KEY, count INTEGER NOT NULL)"
            .into(),
        args: vec![],
        timeout_ms: Some(1000),
    })?;
    storage::sqlite::exec(storage::sqlite::ExecRequest {
        store_id: "counter".into(),
        database: String::new(),
        sql: "INSERT INTO ticks(id,count) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET count=count+1"
            .into(),
        args: vec![],
        timeout_ms: Some(1000),
    })?;
    Ok(json!({}))
}

export_worker!(handle);
