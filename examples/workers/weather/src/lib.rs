use redevplugin_worker_sdk::storage::sqlite::{
    self, ExecRequest, QueryRequest, QueryResponse, Value as SQLiteValue,
};
use redevplugin_worker_sdk::{
    WorkerError, WorkerRequest, WorkerResult, decode_base64_text, export_worker, network,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const STORE_ID: &str = "weather";
const DATABASE: &str = "weather.sqlite";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchParams {
    query: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocationParams {
    id: String,
    name: String,
    admin1: String,
    country: String,
    latitude: f64,
    longitude: f64,
    timezone: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IDParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForecastParams {
    latitude: f64,
    longitude: f64,
    timezone: String,
}

fn handle(request: WorkerRequest) -> WorkerResult {
    match request.method.as_str() {
        "weather.initialize" => initialize(),
        "weather.locations.search" => search_locations(decode(request.params)?),
        "weather.locations.list" => list_locations(),
        "weather.locations.save" => save_location(decode(request.params)?),
        "weather.locations.remove" => remove_location(decode(request.params)?),
        "weather.forecast" => forecast(decode(request.params)?),
        _ => Err(WorkerError::invalid_request("unsupported weather method")),
    }
}

fn initialize() -> WorkerResult {
    exec(
        "CREATE TABLE IF NOT EXISTS locations (id TEXT PRIMARY KEY, name TEXT NOT NULL, admin1 TEXT NOT NULL, country TEXT NOT NULL, latitude REAL NOT NULL, longitude REAL NOT NULL, timezone TEXT NOT NULL, saved_at TEXT NOT NULL)",
        vec![],
    )?;
    Ok(json!({"ready": true}))
}

fn search_locations(params: SearchParams) -> WorkerResult {
    let query = params.query.trim();
    if query.len() < 2 || query.len() > 120 {
        return Err(WorkerError::invalid_request(
            "location query must contain 2 to 120 characters",
        ));
    }
    let payload = http_get(
        "geocoding",
        "https://geocoding-api.open-meteo.com",
        "/v1/search",
        BTreeMap::from([
            ("name".to_string(), vec![query.to_string()]),
            ("count".to_string(), vec!["8".to_string()]),
            ("language".to_string(), vec!["en".to_string()]),
            ("format".to_string(), vec!["json".to_string()]),
        ]),
    )?;
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let locations = results
        .iter()
        .filter_map(project_search_location)
        .collect::<Vec<_>>();
    Ok(json!({"locations": locations}))
}

fn list_locations() -> WorkerResult {
    let response = query(
        "SELECT id, name, admin1, country, latitude, longitude, timezone FROM locations ORDER BY saved_at DESC",
        vec![],
        50,
        131_072,
    )?;
    let locations = response
        .rows
        .iter()
        .map(|row| project_saved_location(row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"locations": locations}))
}

fn save_location(params: LocationParams) -> WorkerResult {
    validate_location(&params)?;
    exec(
        "INSERT INTO locations (id, name, admin1, country, latitude, longitude, timezone, saved_at) VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(id) DO UPDATE SET name=excluded.name, admin1=excluded.admin1, country=excluded.country, latitude=excluded.latitude, longitude=excluded.longitude, timezone=excluded.timezone, saved_at=excluded.saved_at",
        vec![
            SQLiteValue::Text(params.id.clone()),
            SQLiteValue::Text(params.name.clone()),
            SQLiteValue::Text(params.admin1.clone()),
            SQLiteValue::Text(params.country.clone()),
            SQLiteValue::Float(params.latitude),
            SQLiteValue::Float(params.longitude),
            SQLiteValue::Text(params.timezone.clone()),
        ],
    )?;
    Ok(json!({"location": location_json(&params)}))
}

fn remove_location(params: IDParams) -> WorkerResult {
    validate_id(&params.id)?;
    exec(
        "DELETE FROM locations WHERE id = ?",
        vec![SQLiteValue::Text(params.id.clone())],
    )?;
    Ok(json!({"removed_id": params.id}))
}

fn forecast(params: ForecastParams) -> WorkerResult {
    if !params.latitude.is_finite()
        || !params.longitude.is_finite()
        || params.latitude.abs() > 90.0
        || params.longitude.abs() > 180.0
    {
        return Err(WorkerError::invalid_request(
            "forecast coordinates are invalid",
        ));
    }
    let timezone = if params.timezone.trim().is_empty() {
        "auto"
    } else {
        params.timezone.trim()
    };
    let payload = http_get(
        "forecast",
        "https://api.open-meteo.com",
        "/v1/forecast",
        BTreeMap::from([
            ("latitude".to_string(), vec![params.latitude.to_string()]),
            ("longitude".to_string(), vec![params.longitude.to_string()]),
            ("timezone".to_string(), vec![timezone.to_string()]),
            ("forecast_days".to_string(), vec!["7".to_string()]),
            ("current".to_string(), vec!["temperature_2m,relative_humidity_2m,apparent_temperature,is_day,weather_code,wind_speed_10m".to_string()]),
            ("daily".to_string(), vec!["weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunrise,sunset".to_string()]),
        ]),
    )?;
    project_forecast(&payload)
}

fn http_get(
    connector_id: &str,
    destination: &str,
    path: &str,
    query: BTreeMap<String, Vec<String>>,
) -> Result<Value, WorkerError> {
    let mut request = network::ExecuteRequest::http_get(connector_id, destination, path);
    request.query = query;
    request.max_request_bytes = Some(32_768);
    request.max_response_bytes = Some(393_216);
    request.timeout_ms = Some(8_000);
    let response = network::execute(request)?;
    let status = response.status_code.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(WorkerError::new(
            "WEATHER_SERVICE_FAILED",
            format!("weather service returned HTTP {status}"),
        ));
    }
    if response.body_base64.is_empty() {
        return Err(WorkerError::hostcall("network response omitted body"));
    }
    let text = decode_base64_text(&response.body_base64)?;
    serde_json::from_str(&text).map_err(|err| {
        WorkerError::new(
            "WEATHER_SERVICE_FAILED",
            format!("decode weather response: {err}"),
        )
    })
}

fn project_search_location(value: &Value) -> Option<Value> {
    let id = value.get("id")?.as_i64()?;
    let name = value.get("name")?.as_str()?;
    let latitude = value.get("latitude")?.as_f64()?;
    let longitude = value.get("longitude")?.as_f64()?;
    let timezone = value
        .get("timezone")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    Some(json!({
        "id": format!("location_{id}"),
        "name": name,
        "admin1": value.get("admin1").and_then(Value::as_str).unwrap_or(""),
        "country": value.get("country").and_then(Value::as_str).unwrap_or(""),
        "latitude": latitude,
        "longitude": longitude,
        "timezone": timezone
    }))
}

fn project_saved_location(cells: &[SQLiteValue]) -> Result<Value, WorkerError> {
    if cells.len() != 7 {
        return Err(WorkerError::hostcall(
            "saved location row has an unexpected column count",
        ));
    }
    Ok(json!({
        "id": cell_text(&cells[0])?, "name": cell_text(&cells[1])?, "admin1": cell_text(&cells[2])?,
        "country": cell_text(&cells[3])?, "latitude": cell_float(&cells[4])?, "longitude": cell_float(&cells[5])?,
        "timezone": cell_text(&cells[6])?
    }))
}

fn project_forecast(payload: &Value) -> WorkerResult {
    let current = payload
        .get("current")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WorkerError::new(
                "WEATHER_SERVICE_FAILED",
                "forecast omitted current conditions",
            )
        })?;
    let daily = payload
        .get("daily")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WorkerError::new(
                "WEATHER_SERVICE_FAILED",
                "forecast omitted daily conditions",
            )
        })?;
    let dates = daily_array(daily, "time")?;
    let mut days = Vec::with_capacity(dates.len());
    for index in 0..dates.len().min(7) {
        days.push(json!({
            "date": array_string(daily, "time", index)?,
            "weather_code": array_i64(daily, "weather_code", index)?,
            "temperature_max": array_f64(daily, "temperature_2m_max", index)?,
            "temperature_min": array_f64(daily, "temperature_2m_min", index)?,
            "precipitation_probability": array_f64(daily, "precipitation_probability_max", index)?,
            "sunrise": array_string(daily, "sunrise", index)?,
            "sunset": array_string(daily, "sunset", index)?
        }));
    }
    Ok(json!({
        "timezone": payload.get("timezone").and_then(Value::as_str).unwrap_or(""),
        "timezone_abbreviation": payload.get("timezone_abbreviation").and_then(Value::as_str).unwrap_or(""),
        "current": {
            "time": object_string(current, "time")?,
            "temperature": object_f64(current, "temperature_2m")?,
            "apparent_temperature": object_f64(current, "apparent_temperature")?,
            "humidity": object_f64(current, "relative_humidity_2m")?,
            "weather_code": object_i64(current, "weather_code")?,
            "wind_speed": object_f64(current, "wind_speed_10m")?,
            "is_day": object_i64(current, "is_day")? == 1
        },
        "days": days
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
    max_rows: u32,
    max_response_bytes: u64,
) -> Result<QueryResponse, WorkerError> {
    sqlite::query(QueryRequest {
        store_id: STORE_ID.to_string(),
        database: DATABASE.to_string(),
        sql: sql.to_string(),
        args,
        max_rows: Some(max_rows),
        max_response_bytes: Some(max_response_bytes),
        timeout_ms: Some(1_500),
    })
}

fn validate_location(value: &LocationParams) -> Result<(), WorkerError> {
    validate_id(&value.id)?;
    if value.name.trim().is_empty()
        || value.name.len() > 160
        || !value.latitude.is_finite()
        || !value.longitude.is_finite()
        || value.latitude.abs() > 90.0
        || value.longitude.abs() > 180.0
    {
        return Err(WorkerError::invalid_request("saved location is invalid"));
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), WorkerError> {
    if value.len() < 3
        || value.len() > 80
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(WorkerError::invalid_request("location id is invalid"));
    }
    Ok(())
}

fn location_json(value: &LocationParams) -> Value {
    json!({"id":value.id,"name":value.name,"admin1":value.admin1,"country":value.country,"latitude":value.latitude,"longitude":value.longitude,"timezone":value.timezone})
}

fn cell_text(cell: &SQLiteValue) -> Result<&str, WorkerError> {
    match cell {
        SQLiteValue::Text(value) => Ok(value),
        _ => Err(WorkerError::hostcall("SQLite text cell is invalid")),
    }
}
fn cell_float(cell: &SQLiteValue) -> Result<f64, WorkerError> {
    match cell {
        SQLiteValue::Float(value) => Ok(*value),
        SQLiteValue::Integer(value) => Ok(*value as f64),
        _ => Err(WorkerError::hostcall("SQLite number cell is invalid")),
    }
}
fn object_string<'a>(
    value: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, WorkerError> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        WorkerError::new("WEATHER_SERVICE_FAILED", format!("forecast omitted {key}"))
    })
}
fn object_f64(value: &serde_json::Map<String, Value>, key: &str) -> Result<f64, WorkerError> {
    value.get(key).and_then(Value::as_f64).ok_or_else(|| {
        WorkerError::new("WEATHER_SERVICE_FAILED", format!("forecast omitted {key}"))
    })
}
fn object_i64(value: &serde_json::Map<String, Value>, key: &str) -> Result<i64, WorkerError> {
    value.get(key).and_then(Value::as_i64).ok_or_else(|| {
        WorkerError::new("WEATHER_SERVICE_FAILED", format!("forecast omitted {key}"))
    })
}
fn daily_array<'a>(
    value: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Vec<Value>, WorkerError> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        WorkerError::new(
            "WEATHER_SERVICE_FAILED",
            format!("daily forecast omitted {key}"),
        )
    })
}
fn array_string<'a>(
    value: &'a serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<&'a str, WorkerError> {
    daily_array(value, key)?
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WorkerError::new(
                "WEATHER_SERVICE_FAILED",
                format!("daily forecast {key} is incomplete"),
            )
        })
}
fn array_f64(
    value: &serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<f64, WorkerError> {
    daily_array(value, key)?
        .get(index)
        .and_then(Value::as_f64)
        .ok_or_else(|| {
            WorkerError::new(
                "WEATHER_SERVICE_FAILED",
                format!("daily forecast {key} is incomplete"),
            )
        })
}
fn array_i64(
    value: &serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<i64, WorkerError> {
    daily_array(value, key)?
        .get(index)
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            WorkerError::new(
                "WEATHER_SERVICE_FAILED",
                format!("daily forecast {key} is incomplete"),
            )
        })
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
    fn projects_open_meteo_location_without_exposing_raw_response() {
        let location = project_search_location(&json!({"id":2950159,"name":"Berlin","admin1":"Berlin","country":"Germany","latitude":52.52,"longitude":13.41,"timezone":"Europe/Berlin"})).unwrap();
        assert_eq!(location["id"], "location_2950159");
        assert_eq!(location["country"], "Germany");
    }

    #[test]
    fn rejects_invalid_saved_coordinates() {
        let value = LocationParams {
            id: "location_1".into(),
            name: "Nowhere".into(),
            admin1: "".into(),
            country: "".into(),
            latitude: 100.0,
            longitude: 0.0,
            timezone: "auto".into(),
        };
        assert!(validate_location(&value).is_err());
    }
}
