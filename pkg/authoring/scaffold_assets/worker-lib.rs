#[cfg(target_arch = "wasm32")]
use redevplugin_worker_sdk::{PLUGIN_API, api};
use redevplugin_worker_sdk::{WorkerError, WorkerRequest, WorkerResult, export_worker};
use serde_json::{Value, json};

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "worker.echo" => echo(request.params),
        _ => Err(WorkerError::invalid_request(
            "unsupported scaffold worker method",
        )),
    }
}

fn echo(params: Value) -> WorkerResult {
    require_current_plugin_api()?;
    let message = params
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if message.is_empty() || message.len() > 4_096 {
        return Err(WorkerError::invalid_request(
            "message must contain 1 to 4096 characters",
        ));
    }
    Ok(json!({
        "backend": "executed wasm worker scaffold",
        "transport": "rust runtime ipc",
        "method": "worker.echo",
        "worker_id": "backend",
        "message": message
    }))
}

#[cfg(target_arch = "wasm32")]
fn require_current_plugin_api() -> Result<(), WorkerError> {
    let capabilities = api::capabilities()
        .map_err(|error| WorkerError::hostcall(format!("discover Plugin API: {error}")))?;
    if capabilities.plugin_api != PLUGIN_API {
        return Err(WorkerError::hostcall("Current Plugin API is unavailable"));
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn require_current_plugin_api() -> Result<(), WorkerError> {
    Ok(())
}

export_worker!(handle);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_rejects_empty_messages() {
        let error = echo(json!({"message": "  "})).expect_err("empty message must fail");
        assert_eq!(error.code, "INVALID_REQUEST");
    }

    #[test]
    fn echo_returns_the_worker_result() {
        let response = echo(json!({"message": "hello"})).expect("echo response");
        assert_eq!(response["message"], "hello");
    }
}
