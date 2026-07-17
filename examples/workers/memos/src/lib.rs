use redevplugin_worker_sdk::storage::sqlite::{
    self, ExecRequest, ExecResponse, QueryRequest, QueryResponse, Value as SQLiteValue,
};
use redevplugin_worker_sdk::{WorkerError, WorkerRequest, WorkerResult, export_worker};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const STORE_ID: &str = "memos";
const DATABASE: &str = "memos.sqlite";
const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_CONTENT_CHARS: usize = 20_000;
const MAX_QUERY_CHARS: usize = 200;
const MAX_TAGS: usize = 32;
const MAX_TAG_LENGTH: usize = 40;
const CURSOR_PREFIX: &str = "memos_cursor_v1_";
const MAX_CURSOR_CHARS: usize = 1024;
const MEMO_CURSOR_CLAUSE: &str =
    "(pinned < ? OR (pinned = ? AND created_at < ?) OR (pinned = ? AND created_at = ? AND id < ?))";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapParams {
    month: String,
    utc_offset_minutes: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    #[serde(default)]
    query: String,
    #[serde(default)]
    view: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    utc_offset_minutes: i32,
    cursor: Option<String>,
    #[serde(default = "default_page_size")]
    limit: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoCursorPayload {
    version: u8,
    filter_sha256: String,
    pinned: bool,
    created_at: String,
    id: String,
}

#[derive(Serialize)]
struct MemoFilterFingerprint<'a> {
    query: &'a str,
    view: &'a str,
    tag: &'a str,
    date: &'a str,
    utc_offset_minutes: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FacetsParams {
    month: String,
    utc_offset_minutes: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftParams {
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishParams {
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateParams {
    id: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateParams {
    id: String,
    value: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IDParams {
    id: String,
}

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "memos.bootstrap" => bootstrap(decode(request.params)?),
        "memos.list" => list_memos(decode(request.params)?),
        "memos.facets" => facets(decode(request.params)?),
        "memos.draft.save" => save_draft(decode(request.params)?),
        "memos.publish" => publish(decode(request.params)?),
        "memos.update" => update_memo(decode(request.params)?),
        "memos.setPinned" => set_pinned(decode(request.params)?),
        "memos.setArchived" => set_archived(decode(request.params)?),
        "memos.delete" => delete_memo(decode(request.params)?),
        _ => Err(WorkerError::invalid_request("unsupported memos method")),
    }
}

fn bootstrap(params: BootstrapParams) -> WorkerResult {
    initialize()?;
    validate_month(&params.month)?;
    validate_utc_offset(params.utc_offset_minutes)?;
    let page = list_memos(ListParams {
        query: String::new(),
        view: "all".to_string(),
        tag: String::new(),
        date: String::new(),
        utc_offset_minutes: params.utc_offset_minutes,
        cursor: None,
        limit: default_page_size(),
    })?;
    let facet_data = facets(FacetsParams {
        month: params.month,
        utc_offset_minutes: params.utc_offset_minutes,
    })?;
    Ok(json!({
        "memos": page.get("memos").cloned().unwrap_or_else(|| json!([])),
        "next_cursor": page.get("next_cursor").cloned().unwrap_or(Value::Null),
        "draft": draft_value()?,
        "facets": facet_data
    }))
}

fn initialize() -> WorkerResult {
    exec(
        "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, pinned INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, content TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0, tags TEXT NOT NULL DEFAULT '')",
        vec![],
    )?;
    exec(
        "CREATE TABLE IF NOT EXISTS drafts (id TEXT PRIMARY KEY, content TEXT NOT NULL, updated_at TEXT NOT NULL)",
        vec![],
    )?;
    exec(
        "CREATE TABLE IF NOT EXISTS memo_sequence (sequence INTEGER PRIMARY KEY AUTOINCREMENT)",
        vec![],
    )?;
    exec(
        "CREATE INDEX IF NOT EXISTS idx_notes_feed ON notes (archived, pinned DESC, created_at DESC, id DESC)",
        vec![],
    )?;
    exec(
        "CREATE INDEX IF NOT EXISTS idx_notes_updated ON notes (updated_at DESC, id DESC)",
        vec![],
    )?;
    exec(
        "CREATE TRIGGER IF NOT EXISTS clear_memos_draft_after_publish AFTER INSERT ON notes BEGIN DELETE FROM drafts WHERE id = 'composer'; END",
        vec![],
    )?;
    Ok(json!({"ready": true, "schema_version": 1}))
}

fn list_memos(params: ListParams) -> WorkerResult {
    validate_query(&params.query)?;
    validate_utc_offset(params.utc_offset_minutes)?;
    let query_limit = params.limit.clamp(1, 10).saturating_add(1);
    let limit = query_limit - 1;
    let mut clauses = Vec::new();
    let mut args = Vec::new();
    let view = match params.view.as_str() {
        "" | "all" => {
            clauses.push("archived = ?".to_string());
            args.push(SQLiteValue::Integer(0));
            "all"
        }
        "pinned" => {
            clauses.push("archived = ?".to_string());
            clauses.push("pinned = ?".to_string());
            args.push(SQLiteValue::Integer(0));
            args.push(SQLiteValue::Integer(1));
            "pinned"
        }
        "archived" => {
            clauses.push("archived = ?".to_string());
            args.push(SQLiteValue::Integer(1));
            "archived"
        }
        _ => return Err(WorkerError::invalid_request("memo view is invalid")),
    };
    let search_query = params.query.trim().to_ascii_lowercase();
    if !search_query.is_empty() {
        clauses.push("instr(lower(content), lower(?)) > 0".to_string());
        args.push(SQLiteValue::Text(search_query.clone()));
    }
    let tag = params.tag.trim().to_ascii_lowercase();
    if !tag.is_empty() {
        validate_tag(&tag)?;
        clauses
            .push("instr(char(10) || tags || char(10), char(10) || ? || char(10)) > 0".to_string());
        args.push(SQLiteValue::Text(tag.clone()));
    }
    let date = params.date.trim().to_string();
    if !date.is_empty() {
        validate_date(&date)?;
        clauses.push("date(created_at, ?) = ?".to_string());
        args.push(SQLiteValue::Text(timezone_modifier(
            params.utc_offset_minutes,
        )?));
        args.push(SQLiteValue::Text(date.clone()));
    }
    let filter_sha256 =
        filter_fingerprint(&search_query, view, &tag, &date, params.utc_offset_minutes)?;
    if let Some(encoded) = params.cursor.as_deref() {
        let cursor = decode_cursor(encoded, &filter_sha256)?;
        clauses.push(MEMO_CURSOR_CLAUSE.to_string());
        let pinned = bool_int(cursor.pinned);
        args.extend([
            SQLiteValue::Integer(pinned),
            SQLiteValue::Integer(pinned),
            SQLiteValue::Text(cursor.created_at.clone()),
            SQLiteValue::Integer(pinned),
            SQLiteValue::Text(cursor.created_at),
            SQLiteValue::Text(cursor.id),
        ]);
    }
    let where_sql = clauses.join(" AND ");
    args.push(SQLiteValue::Integer(query_limit as i64));
    let response = query(
        &format!(
            "SELECT id, content, pinned, archived, tags, created_at, updated_at FROM notes WHERE {where_sql} ORDER BY pinned DESC, created_at DESC, id DESC LIMIT ?"
        ),
        args,
        query_limit,
        280_000,
    )?;
    let page_rows = rows(&response);
    let has_more = page_rows.len() > limit;
    let visible_rows = &page_rows[..page_rows.len().min(limit)];
    let memos = visible_rows
        .iter()
        .map(|row| memo_from_row(row))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if has_more {
        visible_rows
            .last()
            .map(|row| encode_cursor(row, &filter_sha256))
            .transpose()?
    } else {
        None
    };
    Ok(json!({
        "memos": memos,
        "next_cursor": next_cursor
    }))
}

fn facets(params: FacetsParams) -> WorkerResult {
    validate_month(&params.month)?;
    let modifier = timezone_modifier(params.utc_offset_minutes)?;
    let tag_response = query(
        "WITH RECURSIVE split(rest, tag) AS (SELECT tags || char(10), '' FROM notes WHERE archived = 0 AND tags <> '' UNION ALL SELECT substr(rest, instr(rest, char(10)) + 1), substr(rest, 1, instr(rest, char(10)) - 1) FROM split WHERE rest <> '') SELECT tag, count(*) FROM split WHERE tag <> '' GROUP BY tag ORDER BY count(*) DESC, tag ASC LIMIT 64",
        vec![],
        64,
        32_768,
    )?;
    let tags = rows(&tag_response)
        .iter()
        .map(|row| {
            if row.len() != 2 {
                return Err(WorkerError::hostcall(
                    "memos tag facet row has an unexpected column count",
                ));
            }
            Ok(json!({"tag": cell_text(&row[0])?, "count": cell_int(&row[1])?}))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let day_response = query(
        "SELECT date(created_at, ?), count(*) FROM notes WHERE archived = 0 AND substr(date(created_at, ?), 1, 7) = ? GROUP BY 1 ORDER BY 1",
        vec![
            SQLiteValue::Text(modifier.clone()),
            SQLiteValue::Text(modifier),
            SQLiteValue::Text(params.month.clone()),
        ],
        31,
        16_384,
    )?;
    let days = rows(&day_response)
        .iter()
        .map(|row| {
            if row.len() != 2 {
                return Err(WorkerError::hostcall(
                    "memos day facet row has an unexpected column count",
                ));
            }
            Ok(json!({"date": cell_text(&row[0])?, "count": cell_int(&row[1])?}))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let summary_response = query(
        "SELECT COALESCE(SUM(CASE WHEN archived = 0 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN archived = 0 AND pinned = 1 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN archived = 1 THEN 1 ELSE 0 END), 0) FROM notes",
        vec![],
        1,
        4_096,
    )?;
    let (all_total, pinned_total, archived_total) = summary_counts(&summary_response)?;
    Ok(json!({
        "month": params.month,
        "tags": tags,
        "days": days,
        "all_total": all_total,
        "pinned_total": pinned_total,
        "archived_total": archived_total
    }))
}

fn save_draft(params: DraftParams) -> WorkerResult {
    validate_content(&params.content, true)?;
    if params.content.trim().is_empty() {
        exec("DELETE FROM drafts WHERE id = 'composer'", vec![])?;
        return Ok(json!({"draft": Value::Null}));
    }
    exec(
        "INSERT INTO drafts (id, content, updated_at) VALUES ('composer', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(id) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at",
        vec![SQLiteValue::Text(params.content)],
    )?;
    Ok(json!({"draft": draft_value()?}))
}

fn publish(params: PublishParams) -> WorkerResult {
    let content = normalized_content(params.content)?;
    let tags = encode_tags(&extract_tags(&content));
    let (title, body) = content_parts(&content);
    let sequence = exec_result("INSERT INTO memo_sequence DEFAULT VALUES", vec![])?.last_insert_id;
    let id = memo_id_from_sequence(sequence)?;
    exec(
        "INSERT INTO notes (id, title, body, pinned, created_at, updated_at, content, archived, tags) VALUES (?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, 0, ?)",
        vec![
            SQLiteValue::Text(id.clone()),
            SQLiteValue::Text(title),
            SQLiteValue::Text(body),
            SQLiteValue::Text(content),
            SQLiteValue::Text(tags),
        ],
    )?;
    memo_by_id(&id)
}

fn update_memo(params: UpdateParams) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    let content = normalized_content(params.content)?;
    let tags = encode_tags(&extract_tags(&content));
    let (title, body) = content_parts(&content);
    let result = exec_result(
        "UPDATE notes SET title = ?, body = ?, content = ?, tags = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
        vec![
            SQLiteValue::Text(title),
            SQLiteValue::Text(body),
            SQLiteValue::Text(content),
            SQLiteValue::Text(tags),
            SQLiteValue::Text(id.to_string()),
        ],
    )?;
    ensure_changed(&result)?;
    memo_by_id(id)
}

fn set_pinned(params: StateParams) -> WorkerResult {
    set_boolean_state(params, "pinned")
}

fn set_archived(params: StateParams) -> WorkerResult {
    set_boolean_state(params, "archived")
}

fn set_boolean_state(params: StateParams, column: &str) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    let result = exec_result(
        &format!(
            "UPDATE notes SET {column} = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?"
        ),
        vec![
            SQLiteValue::Integer(bool_int(params.value)),
            SQLiteValue::Text(id.to_string()),
        ],
    )?;
    ensure_changed(&result)?;
    memo_by_id(id)
}

fn delete_memo(params: IDParams) -> WorkerResult {
    let id = params.id.trim();
    validate_id(id)?;
    let result = exec_result(
        "DELETE FROM notes WHERE id = ?",
        vec![SQLiteValue::Text(id.to_string())],
    )?;
    ensure_changed(&result)?;
    Ok(json!({"deleted_id": id}))
}

fn memo_by_id(id: &str) -> WorkerResult {
    query_one(
        "SELECT id, content, pinned, archived, tags, created_at, updated_at FROM notes WHERE id = ? LIMIT 1",
        vec![SQLiteValue::Text(id.to_string())],
    )
}

fn query_one(sql: &str, args: Vec<SQLiteValue>) -> WorkerResult {
    let response = query(sql, args, 1, 32_768)?;
    let row = rows(&response)
        .first()
        .ok_or_else(|| WorkerError::new("MEMO_NOT_FOUND", "memo was not found"))?;
    Ok(json!({"memo": memo_from_row(row)?}))
}

fn draft_value() -> Result<Value, WorkerError> {
    let response = query(
        "SELECT content, updated_at FROM drafts WHERE id = 'composer' LIMIT 1",
        vec![],
        1,
        24_576,
    )?;
    let Some(row) = rows(&response).first() else {
        return Ok(Value::Null);
    };
    if row.len() != 2 {
        return Err(WorkerError::hostcall(
            "memos draft row has an unexpected column count",
        ));
    }
    Ok(json!({
        "content": cell_text(&row[0])?,
        "updated_at": cell_text(&row[1])?
    }))
}

fn memo_from_row(values: &[SQLiteValue]) -> Result<Value, WorkerError> {
    if values.len() != 7 {
        return Err(WorkerError::hostcall(
            "memos query row has an unexpected column count",
        ));
    }
    Ok(json!({
        "id": cell_text(&values[0])?,
        "content": cell_text(&values[1])?,
        "pinned": cell_int(&values[2])? != 0,
        "archived": cell_int(&values[3])? != 0,
        "tags": decode_tags(cell_text(&values[4])?),
        "created_at": cell_text(&values[5])?,
        "updated_at": cell_text(&values[6])?
    }))
}

fn summary_counts(response: &QueryResponse) -> Result<(usize, usize, usize), WorkerError> {
    let Some(row) = rows(response).first() else {
        return Ok((0, 0, 0));
    };
    summary_counts_from_row(row)
}

fn summary_counts_from_row(row: &[SQLiteValue]) -> Result<(usize, usize, usize), WorkerError> {
    if row.len() != 3 {
        return Err(WorkerError::hostcall(
            "memos summary row has an unexpected column count",
        ));
    }
    Ok((
        cell_int(&row[0])?.max(0) as usize,
        cell_int(&row[1])?.max(0) as usize,
        cell_int(&row[2])?.max(0) as usize,
    ))
}

fn filter_fingerprint(
    query: &str,
    view: &str,
    tag: &str,
    date: &str,
    utc_offset_minutes: i32,
) -> Result<String, WorkerError> {
    let canonical = serde_json::to_vec(&MemoFilterFingerprint {
        query,
        view,
        tag,
        date,
        utc_offset_minutes,
    })
    .map_err(|err| WorkerError::hostcall(format!("encode memo filter fingerprint: {err}")))?;
    Ok(hex_encode(&Sha256::digest(canonical)))
}

fn encode_cursor(row: &[SQLiteValue], filter_sha256: &str) -> Result<String, WorkerError> {
    if row.len() != 7 {
        return Err(WorkerError::hostcall(
            "memos cursor row has an unexpected column count",
        ));
    }
    let payload = MemoCursorPayload {
        version: 1,
        filter_sha256: filter_sha256.to_string(),
        pinned: cell_int(&row[2])? != 0,
        created_at: cell_text(&row[5])?.to_string(),
        id: cell_text(&row[0])?.to_string(),
    };
    validate_cursor_payload(&payload, filter_sha256)?;
    let encoded = serde_json::to_vec(&payload)
        .map_err(|err| WorkerError::hostcall(format!("encode memo cursor: {err}")))?;
    Ok(format!("{CURSOR_PREFIX}{}", hex_encode(&encoded)))
}

fn decode_cursor(value: &str, filter_sha256: &str) -> Result<MemoCursorPayload, WorkerError> {
    if value.len() > MAX_CURSOR_CHARS {
        return Err(WorkerError::invalid_request("memo cursor is invalid"));
    }
    let encoded = value
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| WorkerError::invalid_request("memo cursor is invalid"))?;
    let decoded = hex_decode(encoded)?;
    let payload: MemoCursorPayload = serde_json::from_slice(&decoded)
        .map_err(|_| WorkerError::invalid_request("memo cursor is invalid"))?;
    validate_cursor_payload(&payload, filter_sha256)?;
    Ok(payload)
}

fn validate_cursor_payload(
    cursor: &MemoCursorPayload,
    filter_sha256: &str,
) -> Result<(), WorkerError> {
    if cursor.version != 1
        || cursor.filter_sha256 != filter_sha256
        || cursor.filter_sha256.len() != 64
        || !cursor
            .filter_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WorkerError::invalid_request(
            "memo cursor does not match the active filters",
        ));
    }
    validate_id(&cursor.id)?;
    validate_cursor_timestamp(&cursor.created_at)
}

fn validate_cursor_timestamp(value: &str) -> Result<(), WorkerError> {
    let bytes = value.as_bytes();
    let valid_shape = match bytes.len() {
        20 => bytes[19] == b'Z',
        24 => bytes[19] == b'.' && bytes[23] == b'Z',
        _ => false,
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if !valid_shape
        || separators
            .iter()
            .any(|(index, expected)| bytes.get(*index) != Some(expected))
        || bytes.iter().enumerate().any(|(index, byte)| {
            !separators.iter().any(|(position, _)| *position == index)
                && index != 19
                && index != 23
                && !byte.is_ascii_digit()
        })
    {
        return Err(WorkerError::invalid_request("memo cursor is invalid"));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, WorkerError> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(WorkerError::invalid_request("memo cursor is invalid"));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> Result<u8, WorkerError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(WorkerError::invalid_request("memo cursor is invalid")),
    }
}

fn content_parts(content: &str) -> (String, String) {
    let mut title = "Untitled memo".to_string();
    let mut body_start = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        let next_start = body_start + line.len() + 1;
        if !trimmed.is_empty() {
            title = trimmed.chars().take(160).collect();
            body_start = next_start.min(content.len());
            break;
        }
        body_start = next_start.min(content.len());
    }
    (
        title,
        content
            .get(body_start..)
            .unwrap_or("")
            .trim_start()
            .to_string(),
    )
}

fn extract_tags(content: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut seen = HashSet::new();
    let mut fence: Option<char> = None;
    for line in content.lines() {
        let trimmed = line.trim_start();
        let fence_char = if trimmed.starts_with("```") {
            Some('`')
        } else if trimmed.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        if let Some(marker) = fence_char {
            if fence == Some(marker) {
                fence = None;
            } else if fence.is_none() {
                fence = Some(marker);
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }
        let chars = line.char_indices().collect::<Vec<_>>();
        let mut cursor = 0;
        while cursor < chars.len() && tags.len() < MAX_TAGS {
            let (byte_index, ch) = chars[cursor];
            let boundary = cursor == 0 || chars[cursor - 1].1.is_whitespace();
            if ch != '#' || !boundary {
                cursor += 1;
                continue;
            }
            let mut end = byte_index + 1;
            let mut length = 0;
            let mut next = cursor + 1;
            while next < chars.len() && is_tag_char(chars[next].1) {
                length += 1;
                end = chars[next].0 + chars[next].1.len_utf8();
                next += 1;
            }
            if length > 0 && length <= MAX_TAG_LENGTH {
                let tag = line[byte_index + 1..end].to_ascii_lowercase();
                if seen.insert(tag.clone()) {
                    tags.push(tag);
                }
            }
            cursor = next.max(cursor + 1);
        }
    }
    tags
}

fn is_tag_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/')
}

fn encode_tags(tags: &[String]) -> String {
    tags.join("\n")
}

fn decode_tags(value: &str) -> Vec<&str> {
    value.lines().filter(|tag| !tag.is_empty()).collect()
}

fn normalized_content(content: String) -> Result<String, WorkerError> {
    validate_content(&content, false)?;
    Ok(content.trim().to_string())
}

fn validate_content(content: &str, empty_allowed: bool) -> Result<(), WorkerError> {
    if (!empty_allowed && content.trim().is_empty()) || content.chars().count() > MAX_CONTENT_CHARS
    {
        return Err(WorkerError::invalid_request("memo content is invalid"));
    }
    Ok(())
}

fn validate_query(query: &str) -> Result<(), WorkerError> {
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(WorkerError::invalid_request("memo query is invalid"));
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), WorkerError> {
    if tag.is_empty()
        || tag.len() > MAX_TAG_LENGTH
        || !tag.chars().all(is_tag_char)
        || tag != tag.to_ascii_lowercase()
    {
        return Err(WorkerError::invalid_request("memo tag is invalid"));
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), WorkerError> {
    if id.len() < 6
        || id.len() > 80
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(WorkerError::invalid_request("memo id is invalid"));
    }
    Ok(())
}

fn memo_id_from_sequence(sequence: i64) -> Result<String, WorkerError> {
    if sequence <= 0 {
        return Err(WorkerError::hostcall("memo sequence is invalid"));
    }
    Ok(format!("memo_{sequence:024x}"))
}

fn validate_month(month: &str) -> Result<(), WorkerError> {
    let bytes = month.as_bytes();
    if bytes.len() != 7
        || bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return Err(WorkerError::invalid_request("memo month is invalid"));
    }
    let parsed = month[5..]
        .parse::<u8>()
        .map_err(|_| WorkerError::invalid_request("memo month is invalid"))?;
    if !(1..=12).contains(&parsed) {
        return Err(WorkerError::invalid_request("memo month is invalid"));
    }
    Ok(())
}

fn validate_date(date: &str) -> Result<(), WorkerError> {
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
    {
        return Err(WorkerError::invalid_request("memo date is invalid"));
    }
    validate_month(&date[..7])?;
    let day = date[8..]
        .parse::<u8>()
        .map_err(|_| WorkerError::invalid_request("memo date is invalid"))?;
    if !(1..=31).contains(&day) {
        return Err(WorkerError::invalid_request("memo date is invalid"));
    }
    Ok(())
}

fn validate_utc_offset(offset: i32) -> Result<(), WorkerError> {
    if !(-840..=840).contains(&offset) {
        return Err(WorkerError::invalid_request("memo UTC offset is invalid"));
    }
    Ok(())
}

fn timezone_modifier(offset: i32) -> Result<String, WorkerError> {
    validate_utc_offset(offset)?;
    Ok(format!("{offset:+} minutes"))
}

fn ensure_changed(response: &ExecResponse) -> Result<(), WorkerError> {
    if response.rows_affected == 0 {
        return Err(WorkerError::new("MEMO_NOT_FOUND", "memo was not found"));
    }
    Ok(())
}

fn bool_int(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn default_page_size() -> usize {
    DEFAULT_PAGE_SIZE
}

fn exec(sql: &str, args: Vec<SQLiteValue>) -> Result<(), WorkerError> {
    exec_result(sql, args).map(|_| ())
}

fn exec_result(sql: &str, args: Vec<SQLiteValue>) -> Result<ExecResponse, WorkerError> {
    sqlite::exec(ExecRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: sql.to_string(),
        args,
        timeout_ms: Some(2_000),
    })
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
        timeout_ms: Some(2_000),
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

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, WorkerError> {
    serde_json::from_value(value)
        .map_err(|err| WorkerError::invalid_request(format!("invalid method params: {err}")))
}

export_worker!(handle);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_ids_are_closed_and_stable() {
        assert!(validate_id("memo_0123456789abcdef").is_ok());
        assert!(validate_id("../memos").is_err());
        assert_eq!(
            memo_id_from_sequence(1).unwrap(),
            "memo_000000000000000000000001"
        );
        assert!(memo_id_from_sequence(0).is_err());
    }

    #[test]
    fn content_projects_to_title_and_body() {
        let (title, body) = content_parts("# A quick thought\n\nMore detail here.");
        assert_eq!(title, "# A quick thought");
        assert_eq!(body, "More detail here.");
    }

    #[test]
    fn tags_are_normalized_deduplicated_and_ignore_code_fences() {
        let tags = extract_tags(
            "Planning #Work #work #road/map\n```sh\necho #ignored\n```\nDone #next-step",
        );
        assert_eq!(tags, vec!["work", "road/map", "next-step"]);
    }

    #[test]
    fn invalid_tags_and_dates_fail_closed() {
        assert!(validate_tag("valid/tag").is_ok());
        assert!(validate_tag("UPPER").is_err());
        assert!(validate_month("2026-07").is_ok());
        assert!(validate_month("2026-13").is_err());
        assert!(validate_date("2026-07-16").is_ok());
        assert!(validate_date("2026-07-00").is_err());
        assert_eq!(timezone_modifier(480).unwrap(), "+480 minutes");
    }

    #[test]
    fn cursors_are_opaque_and_bound_to_normalized_filters() {
        let row = vec![
            SQLiteValue::Text("memo_0123456789abcdef".to_string()),
            SQLiteValue::Text("content".to_string()),
            SQLiteValue::Integer(1),
            SQLiteValue::Integer(0),
            SQLiteValue::Text(String::new()),
            SQLiteValue::Text("2026-07-14T00:00:00.000Z".to_string()),
            SQLiteValue::Text("2026-07-14T00:00:00.000Z".to_string()),
        ];
        let filter = filter_fingerprint("query", "all", "tag", "2026-07-14", 480)
            .expect("filter fingerprint");
        let cursor = encode_cursor(&row, &filter).expect("cursor");
        assert!(cursor.starts_with(CURSOR_PREFIX));
        assert!(!cursor.contains("memo_0123456789abcdef"));
        let decoded = decode_cursor(&cursor, &filter).expect("decode cursor");
        assert!(decoded.pinned);
        assert_eq!(decoded.id, "memo_0123456789abcdef");
        let other_filter = filter_fingerprint("other", "all", "tag", "2026-07-14", 480)
            .expect("other filter fingerprint");
        assert!(decode_cursor(&cursor, &other_filter).is_err());
    }

    #[test]
    fn sqlite_rows_project_to_public_memo_shape() {
        let row = vec![
            SQLiteValue::Text("memo_0123456789abcdef".to_string()),
            SQLiteValue::Text("Hello #Work".to_string()),
            SQLiteValue::Integer(1),
            SQLiteValue::Integer(0),
            SQLiteValue::Text("work\nnotes".to_string()),
            SQLiteValue::Text("2026-07-14T00:00:00Z".to_string()),
            SQLiteValue::Text("2026-07-16T00:00:00Z".to_string()),
        ];
        let memo = memo_from_row(&row).expect("memo row");
        assert_eq!(memo["content"], "Hello #Work");
        assert_eq!(memo["pinned"], true);
        assert_eq!(memo["archived"], false);
        assert_eq!(memo["tags"], json!(["work", "notes"]));
    }

    #[test]
    fn content_limit_counts_unicode_characters() {
        assert!(validate_content(&"界".repeat(MAX_CONTENT_CHARS), false).is_ok());
        assert!(validate_content(&"界".repeat(MAX_CONTENT_CHARS + 1), false).is_err());
    }

    #[test]
    fn summary_counts_keep_active_pinned_and_archived_totals_distinct() {
        let counts = summary_counts_from_row(&[
            SQLiteValue::Integer(7),
            SQLiteValue::Integer(2),
            SQLiteValue::Integer(3),
        ])
        .expect("summary row");
        assert_eq!(counts, (7, 2, 3));
        assert!(summary_counts_from_row(&[SQLiteValue::Integer(1)]).is_err());
    }
}
