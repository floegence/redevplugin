use redevplugin_worker_sdk::{WorkerRequest, WorkerResult, export_worker};
use serde_json::json;
mod guest;
fn handle(request: WorkerRequest) -> WorkerResult {
    let which = request.params["message"].as_str().unwrap_or("noop");
    let result = match which {
        "mix" => guest::bench_mix(500000),
        "sort" => guest::bench_sort(20000),
        "json" => guest::bench_json(1),
        "json_1m" => json_matrix(1 << 20, 0),
        "json_10m" => json_matrix(10 << 20, 0),
        "json_deep" => json_matrix(1 << 20, 16),
        _ => guest::bench_noop(1),
    };
    Ok(json!({"from_worker":true,"backend":result.to_string()}))
}
fn json_matrix(minimum: usize, depth: usize) -> i64 {
    let row = format!(
        "{}{{\"id\":1,\"label\":\"bounded workload fixture\",\"values\":[1,2,3,4]}}{}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let count = (minimum / (row.len() + 1)).max(1);
    let mut text = String::with_capacity(minimum + 2);
    text.push('[');
    for i in 0..count {
        if i > 0 {
            text.push(',');
        }
        text.push_str(&row);
    }
    text.push(']');
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value.as_array().unwrap().len() as i64
}
export_worker!(handle);
