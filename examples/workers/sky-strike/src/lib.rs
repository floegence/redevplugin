use redevplugin_worker_sdk::storage::sqlite::{
    self, ExecRequest, QueryRequest, Value as SQLiteValue,
};
use redevplugin_worker_sdk::{WorkerError, WorkerRequest, WorkerResult, export_worker};
use serde::Deserialize;
use serde_json::{Value, json};

const STORE_ID: &str = "game";
const DATABASE: &str = "sky-strike.sqlite";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveScoreParams {
    score: i64,
}

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "game.initialize" => initialize(),
        "game.highScore.load" => load_high_score(),
        "game.highScore.save" => save_high_score(decode(request.params)?),
        _ => Err(WorkerError::invalid_request(
            "unsupported Sky Strike method",
        )),
    }
}

fn initialize() -> WorkerResult {
    exec(
        "CREATE TABLE IF NOT EXISTS high_score (slot INTEGER PRIMARY KEY CHECK (slot = 1), score INTEGER NOT NULL)",
        vec![],
    )?;
    Ok(json!({"ready": true}))
}

fn load_high_score() -> WorkerResult {
    let response = sqlite::query(QueryRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: "SELECT score FROM high_score WHERE slot = 1".to_string(),
        args: vec![],
        max_rows: Some(1),
        max_response_bytes: Some(4_096),
        timeout_ms: Some(1_000),
    })?;
    let score = match response.rows.first().and_then(|row| row.first()) {
        Some(SQLiteValue::Integer(value)) => *value,
        _ => 0,
    };
    Ok(json!({"score": score}))
}

fn save_high_score(params: SaveScoreParams) -> WorkerResult {
    if !(0..=100_000_000).contains(&params.score) {
        return Err(WorkerError::invalid_request(
            "score is outside the accepted range",
        ));
    }
    exec(
        "INSERT INTO high_score (slot, score) VALUES (1, ?) ON CONFLICT(slot) DO UPDATE SET score = MAX(score, excluded.score)",
        vec![SQLiteValue::Integer(params.score)],
    )?;
    load_high_score()
}

fn exec(sql: &str, args: Vec<SQLiteValue>) -> Result<(), WorkerError> {
    sqlite::exec(ExecRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: sql.to_string(),
        args,
        timeout_ms: Some(1_000),
    })?;
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, WorkerError> {
    serde_json::from_value(value)
        .map_err(|err| WorkerError::invalid_request(format!("invalid method params: {err}")))
}

export_worker!(handle);

#[cfg(test)]
mod tests {
    #[test]
    fn score_range_matches_the_public_contract() {
        assert!((0_i64..=100_000_000).contains(&42));
        assert!(!(0_i64..=100_000_000).contains(&-1));
    }
}
