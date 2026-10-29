use redevplugin_worker_sdk::{WorkerError, WorkerRequest, WorkerResult, export_worker, fs};
use serde_json::json;

// This integration fixture executes the public SDK against the real Host broker.
fn handle(request: WorkerRequest) -> WorkerResult {
    let uri = request
        .params
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WorkerError::invalid_request("uri is required"))?;
    let text = request
        .params
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WorkerError::invalid_request("text is required"))?;
    let mut file = match fs::File::open(
        uri,
        fs::OpenOptions {
            read: true,
            write: true,
            ..Default::default()
        },
    ) {
        Ok(file) => file,
        Err(error) => return Ok(json!({"code": error.code.as_str()})),
    };
    let (before, _) = file.read(65536)?;
    file.seek(0, 0)?;
    file.write_all(text.as_bytes())?;
    file.sync()?;
    file.seek(0, 0)?;
    let (after, _) = file.read(65536)?;
    file.close()?;
    Ok(
        json!({"before": String::from_utf8_lossy(&before), "after": String::from_utf8_lossy(&after)}),
    )
}

export_worker!(handle);
