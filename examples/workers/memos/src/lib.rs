use redevplugin_worker_sdk::storage::sqlite::{
    self, ExecRequest, QueryRequest, QueryResponse, Value as SQLiteValue,
};
use redevplugin_worker_sdk::{WorkerError, WorkerRequest, WorkerResult, export_worker};
use serde::Deserialize;
use serde_json::{Value, json};

const STORE_ID: &str = "memos";
const DATABASE: &str = "memos.sqlite";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_size")]
    limit: usize,
    #[serde(default)]
    pinned_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveParams {
    #[serde(default)]
    id: String,
    title: String,
    body: String,
    #[serde(default)]
    pinned: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IDParams {
    id: String,
}

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "memos.bootstrap" => bootstrap(),
        "memos.list" => list_notes(decode(request.params)?),
        "memos.get" => get_note(decode(request.params)?),
        "memos.save" => save_note(decode(request.params)?),
        "memos.delete" => delete_note(decode(request.params)?),
        "memos.togglePin" => toggle_pin(decode(request.params)?),
        _ => Err(WorkerError::invalid_request("unsupported memos method")),
    }
}

fn bootstrap() -> WorkerResult {
    initialize()?;
    let page = list_notes(ListParams {
        query: String::new(),
        offset: 0,
        limit: default_page_size(),
        pinned_only: false,
    })?;
    let selected_note = page
        .get("notes")
        .and_then(Value::as_array)
        .and_then(|notes| notes.first())
        .and_then(|note| note.get("id"))
        .and_then(Value::as_str)
        .map(note_by_id)
        .transpose()?
        .and_then(|value| value.get("note").cloned());
    Ok(json!({
        "notes": page.get("notes").cloned().unwrap_or_else(|| json!([])),
        "total": page.get("total").cloned().unwrap_or_else(|| json!(0)),
        "offset": 0,
        "has_more": page.get("has_more").cloned().unwrap_or(json!(false)),
        "selected_note": selected_note
    }))
}

fn initialize() -> WorkerResult {
    exec(
        "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, pinned INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
        vec![],
    )?;
    Ok(json!({"ready": true}))
}

fn list_notes(params: ListParams) -> WorkerResult {
    let search_query = params.query.trim();
    let limit = params.limit.clamp(1, 30);
    let offset = params.offset.min(100_000);
    let (sql, args, count_sql, count_args) = if params.pinned_only && search_query.is_empty() {
        (
            "SELECT id, title, substr(body, 1, 180), pinned, created_at, updated_at FROM notes WHERE pinned = 1 ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            vec![
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
            "SELECT count(*) FROM notes WHERE pinned = 1",
            vec![],
        )
    } else if params.pinned_only {
        (
            "SELECT id, title, substr(body, 1, 180), pinned, created_at, updated_at FROM notes WHERE pinned = 1 AND (lower(title) LIKE lower(?) OR lower(body) LIKE lower(?)) ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            vec![
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
            "SELECT count(*) FROM notes WHERE pinned = 1 AND (lower(title) LIKE lower(?) OR lower(body) LIKE lower(?))",
            vec![
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Text(format!("%{search_query}%")),
            ],
        )
    } else if search_query.is_empty() {
        (
            "SELECT id, title, substr(body, 1, 180), pinned, created_at, updated_at FROM notes ORDER BY pinned DESC, updated_at DESC LIMIT ? OFFSET ?",
            vec![
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
            "SELECT count(*) FROM notes",
            vec![],
        )
    } else {
        (
            "SELECT id, title, substr(body, 1, 180), pinned, created_at, updated_at FROM notes WHERE lower(title) LIKE lower(?) OR lower(body) LIKE lower(?) ORDER BY pinned DESC, updated_at DESC LIMIT ? OFFSET ?",
            vec![
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
            "SELECT count(*) FROM notes WHERE lower(title) LIKE lower(?) OR lower(body) LIKE lower(?)",
            vec![
                SQLiteValue::Text(format!("%{search_query}%")),
                SQLiteValue::Text(format!("%{search_query}%")),
            ],
        )
    };
    let response = query(sql, args, limit, 131_072)?;
    let notes = rows(&response)
        .iter()
        .map(|row| note_summary_from_row(row))
        .collect::<Result<Vec<_>, _>>()?;
    let count_response = query(count_sql, count_args, 1, 4_096)?;
    let total = rows(&count_response)
        .first()
        .and_then(|row| row.first())
        .map(cell_int)
        .transpose()?
        .unwrap_or(0)
        .max(0) as usize;
    let loaded = notes.len();
    Ok(json!({
        "notes": notes,
        "total": total,
        "offset": offset,
        "has_more": page_has_more(offset, loaded, total)
    }))
}

fn page_has_more(offset: usize, loaded: usize, total: usize) -> bool {
    offset.saturating_add(loaded) < total
}

fn get_note(params: IDParams) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    note_by_id(id)
}

fn save_note(params: SaveParams) -> WorkerResult {
    let title = params.title.trim();
    if title.is_empty() || title.len() > 160 || params.body.len() > 20_000 {
        return Err(WorkerError::invalid_request(
            "note title or body is invalid",
        ));
    }
    let id = params.id.trim();
    if id.is_empty() {
        exec(
            "INSERT INTO notes (id, title, body, pinned, created_at, updated_at) VALUES ('note_' || lower(hex(randomblob(12))), ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            vec![
                SQLiteValue::Text(title.to_string()),
                SQLiteValue::Text(params.body),
                SQLiteValue::Integer(bool_int(params.pinned)),
            ],
        )?;
        return latest_note();
    }
    validate_id(id)?;
    exec(
        "UPDATE notes SET title = ?, body = ?, pinned = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
        vec![
            SQLiteValue::Text(title.to_string()),
            SQLiteValue::Text(params.body),
            SQLiteValue::Integer(bool_int(params.pinned)),
            SQLiteValue::Text(id.to_string()),
        ],
    )?;
    note_by_id(id)
}

fn delete_note(params: IDParams) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    exec(
        "DELETE FROM notes WHERE id = ?",
        vec![SQLiteValue::Text(id.to_string())],
    )?;
    Ok(json!({"deleted_id": id}))
}

fn toggle_pin(params: IDParams) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    exec(
        "UPDATE notes SET pinned = CASE pinned WHEN 0 THEN 1 ELSE 0 END, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
        vec![SQLiteValue::Text(id.to_string())],
    )?;
    note_by_id(id)
}

fn latest_note() -> WorkerResult {
    query_one(
        "SELECT id, title, body, pinned, created_at, updated_at FROM notes ORDER BY rowid DESC LIMIT 1",
        vec![],
    )
}

fn note_by_id(id: &str) -> WorkerResult {
    query_one(
        "SELECT id, title, body, pinned, created_at, updated_at FROM notes WHERE id = ? LIMIT 1",
        vec![SQLiteValue::Text(id.to_string())],
    )
}

fn query_one(sql: &str, args: Vec<SQLiteValue>) -> WorkerResult {
    let response = query(sql, args, 1, 32_768)?;
    let row = rows(&response)
        .first()
        .ok_or_else(|| WorkerError::new("NOTE_NOT_FOUND", "note was not found"))?;
    Ok(json!({"note": note_from_row(row)?}))
}

fn note_from_row(values: &[SQLiteValue]) -> Result<Value, WorkerError> {
    if values.len() != 6 {
        return Err(WorkerError::hostcall(
            "memos query row has an unexpected column count",
        ));
    }
    Ok(json!({
        "id": cell_text(&values[0])?,
        "title": cell_text(&values[1])?,
        "body": cell_text(&values[2])?,
        "pinned": cell_int(&values[3])? != 0,
        "created_at": cell_text(&values[4])?,
        "updated_at": cell_text(&values[5])?
    }))
}

fn note_summary_from_row(values: &[SQLiteValue]) -> Result<Value, WorkerError> {
    if values.len() != 6 {
        return Err(WorkerError::hostcall(
            "memos summary row has an unexpected column count",
        ));
    }
    Ok(json!({
        "id": cell_text(&values[0])?,
        "title": cell_text(&values[1])?,
        "preview": cell_text(&values[2])?,
        "pinned": cell_int(&values[3])? != 0,
        "created_at": cell_text(&values[4])?,
        "updated_at": cell_text(&values[5])?
    }))
}

fn exec(sql: &str, args: Vec<SQLiteValue>) -> Result<(), WorkerError> {
    sqlite::exec(ExecRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: sql.to_string(),
        args,
        timeout_ms: Some(1_500),
    })?;
    Ok(())
}

fn query(
    sql: &str,
    args: Vec<SQLiteValue>,
    max_rows: usize,
    max_response_bytes: u64,
) -> Result<QueryResponse, WorkerError> {
    sqlite::query(QueryRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: sql.to_string(),
        args,
        max_rows: Some(max_rows as u32),
        max_response_bytes: Some(max_response_bytes),
        timeout_ms: Some(1_500),
    })
}

fn rows(response: &QueryResponse) -> &[Vec<SQLiteValue>] {
    &response.rows
}

fn cell_text(cell: &SQLiteValue) -> Result<&str, WorkerError> {
    match cell {
        SQLiteValue::Text(value) => Ok(value),
        _ => Err(WorkerError::hostcall("SQLite text cell is invalid")),
    }
}

fn cell_int(cell: &SQLiteValue) -> Result<i64, WorkerError> {
    match cell {
        SQLiteValue::Integer(value) => Ok(*value),
        _ => Err(WorkerError::hostcall("SQLite integer cell is invalid")),
    }
}

fn validate_id(id: &str) -> Result<(), WorkerError> {
    if id.len() < 6
        || id.len() > 80
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(WorkerError::invalid_request("note id is invalid"));
    }
    Ok(())
}

fn bool_int(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn default_page_size() -> usize {
    24
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, WorkerError> {
    serde_json::from_value(value)
        .map_err(|err| WorkerError::invalid_request(format!("invalid method params: {err}")))
}

export_worker!(handle);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_ids_are_closed_and_stable() {
        assert!(validate_id("note_0123456789abcdef").is_ok());
        assert!(validate_id("../notes").is_err());
    }

    #[test]
    fn sqlite_rows_project_to_public_note_shape() {
        let row = vec![
            SQLiteValue::Text("note_1".into()),
            SQLiteValue::Text("Launch".into()),
            SQLiteValue::Text("Ship it".into()),
            SQLiteValue::Integer(1),
            SQLiteValue::Text("2026-07-14T00:00:00Z".into()),
            SQLiteValue::Text("2026-07-14T01:00:00Z".into()),
        ];
        let note = note_from_row(&row).unwrap();
        assert_eq!(note["pinned"], true);
        assert_eq!(note["title"], "Launch");
    }

    #[test]
    fn sixty_one_pinned_notes_require_three_bounded_pages() {
        assert!(page_has_more(0, 24, 61));
        assert!(page_has_more(24, 24, 61));
        assert!(!page_has_more(48, 13, 61));
    }
}
