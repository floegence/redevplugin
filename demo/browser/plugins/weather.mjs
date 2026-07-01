import { PluginBridgeClient, PluginBridgeError } from "../../../packages/redevplugin-ui/dist/index.js";
import { createDemoBootstrap, formatJSON } from "../demo-platform.mjs";

const params = new URLSearchParams(window.location.search);
const parentOrigin = params.get("parent_origin");
if (!parentOrigin || parentOrigin === "*") {
  throw new Error("parent_origin query parameter must be an exact origin");
}

const bootstrap = createDemoBootstrap({
  pluginId: params.get("plugin_id"),
  surfaceId: params.get("surface_id"),
  surfaceInstanceId: params.get("surface_instance_id"),
  activeFingerprint: params.get("active_fingerprint"),
  bridgeNonce: params.get("bridge_nonce"),
});
const client = new PluginBridgeClient({ ...bootstrap, parentOrigin });

const status = document.querySelector("#plugin-status");
const fetchButton = document.querySelector("#weather-fetch");
const compareButton = document.querySelector("#weather-compare");
const detectButton = document.querySelector("#weather-detect");
const explainButton = document.querySelector("#weather-explain");
const locationInput = document.querySelector("#weather-location");
const savedLocations = document.querySelector("#saved-locations");
const detectedLocation = document.querySelector("#detected-location");
const detectedConfidence = document.querySelector("#detected-confidence");
const detectedCoordinates = document.querySelector("#detected-coordinates");
const place = document.querySelector("#weather-place");
const temp = document.querySelector("#weather-temp");
const condition = document.querySelector("#weather-condition");
const wind = document.querySelector("#weather-wind");
const humidity = document.querySelector("#weather-humidity");
const pressure = document.querySelector("#weather-pressure");
const uv = document.querySelector("#weather-uv");
const aqi = document.querySelector("#weather-aqi");
const pollutant = document.querySelector("#weather-pollutant");
const aqiCategory = document.querySelector("#weather-aqi-category");
const alertCount = document.querySelector("#weather-alert-count");
const weatherAlerts = document.querySelector("#weather-alerts");
const networkOperation = document.querySelector("#network-operation");
const networkLatency = document.querySelector("#network-latency");
const networkBytes = document.querySelector("#network-bytes");
const networkConnector = document.querySelector("#network-connector");
const networkBroker = document.querySelector("#network-broker");
const networkResponse = document.querySelector("#network-response");
const networkParser = document.querySelector("#network-parser");
const networkHistoryCount = document.querySelector("#network-history-count");
const networkHistory = document.querySelector("#network-history");
const compareCount = document.querySelector("#weather-compare-count");
const compareGrid = document.querySelector("#weather-compare-grid");
const forecast = document.querySelector("#forecast");
const hourly = document.querySelector("#hourly");
const rawWeatherResponse = document.querySelector("#raw-weather-response");
const parserRun = document.querySelector("#parser-run");
const parserFields = document.querySelector("#parser-fields");
const parserQuality = document.querySelector("#parser-quality");
const parserSteps = document.querySelector("#parser-steps");
const result = document.querySelector("#plugin-result");

client.onLifecycle((event) => {
  status.textContent = event.type;
  writeResult({ lifecycle: event.type });
  if (event.type === "ready") {
    void loadSavedLocation();
  }
});
client.handshake();

fetchButton.addEventListener("click", async () => {
  const location = locationInput.value.trim() || "San Francisco";
  await callPlugin("weather.location.save", { location });
  await callPlugin("weather.fetch", { location });
});

compareButton.addEventListener("click", async () => {
  await callPlugin("weather.saved.compare", {});
});

explainButton.addEventListener("click", async () => {
  const location = locationInput.value.trim() || "San Francisco";
  await callPlugin("weather.parser.explain", { location });
});

detectButton.addEventListener("click", async () => {
  const detected = await callPlugin("weather.location.detect", {});
  const location = detected?.data?.location ?? detected?.location;
  if (location) {
    locationInput.value = location;
    await callPlugin("weather.fetch", { location });
  }
});

locationInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    fetchButton.click();
  }
});

async function loadSavedLocation() {
  const response = await callPlugin("weather.location.get", {});
  const location = response?.data?.location ?? response?.location ?? "San Francisco";
  const locations = response?.data?.saved_locations ?? response?.saved_locations ?? [location];
  const detected = response?.data?.detected_locations ?? response?.detected_locations ?? [];
  renderSavedLocations(locations);
  renderDetectedLocations(detected);
  locationInput.value = location;
  await callPlugin("weather.fetch", { location });
}

async function callPlugin(method, payload) {
  status.textContent = "network";
  try {
    const response = await client.call(method, payload);
    const data = response?.data ?? response;
    if (data?.current) {
      renderWeather(data);
    }
    if (Array.isArray(data?.saved_locations)) {
      renderSavedLocations(data.saved_locations);
    }
    if (Array.isArray(data?.detected_locations)) {
      renderDetectedLocations(data.detected_locations);
    }
    if (Array.isArray(data?.comparisons)) {
      renderComparisons(data.comparisons);
    }
    if (data?.parser_explanation) {
      renderParserExplanation(data.parser_explanation);
    }
    if (data?.location && method !== "weather.fetch") {
      place.textContent = data.location;
    }
    if (method === "weather.location.detect") {
      renderDetectedLocation(data);
    }
    status.textContent = "ready";
    writeResult({ method, response });
    return response;
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      writeResult({ method, error_code: error.errorCode, error: error.message });
      return null;
    }
    writeResult({ method, error: String(error) });
    return null;
  }
}

function renderWeather(data) {
  const parsed = parseWeatherResponse(data);
  place.textContent = data.location;
  temp.textContent = String(parsed.current.temperature_c);
  condition.textContent = data.parsed_summary ?? `${parsed.current.condition} · ${parsed.current.wind_kph} kph wind · ${parsed.current.humidity_percent}% humidity`;
  wind.textContent = `${parsed.current.wind_kph} kph`;
  humidity.textContent = `${parsed.current.humidity_percent}%`;
  pressure.textContent = `${parsed.current.pressure_hpa ?? "--"} hPa`;
  uv.textContent = String(parsed.current.uv_index ?? "--");
  aqi.textContent = String(parsed.air_quality?.aqi ?? "--");
  pollutant.textContent = parsed.air_quality?.dominant_pollutant ?? "--";
  aqiCategory.textContent = parsed.air_quality?.category ?? "--";
  alertCount.textContent = String(parsed.alerts.length);
  networkOperation.textContent = `${data.network?.transport ?? "http"} ${data.network?.operation ?? "GET /v1/forecast"}`;
  networkLatency.textContent = `${data.network?.latency_ms ?? "--"} ms`;
  networkBytes.textContent = `${data.network?.bytes_received ?? "--"} bytes`;
  networkConnector.textContent = data.network?.connector_id ?? "weather_api";
  networkBroker.textContent = data.network?.upstream_mode ?? "host http fetch";
  networkResponse.textContent = `${data.network?.response_status ?? 200} · ${data.network?.response_headers?.["content-type"] ?? "application/json"}`;
  networkParser.textContent = `${data.parser?.format ?? "json"} · ${data.parser?.fields?.length ?? 0} fields`;
  rawWeatherResponse.textContent = formatJSON({
    request: data.network?.operation,
    broker_endpoint: data.network?.broker_endpoint,
    upstream_mode: data.network?.upstream_mode,
    response_headers: data.network?.response_headers,
    parsed_from_raw: true,
    sample: parsed,
  });
  weatherAlerts.replaceChildren(...parsed.alerts.map((alert) => {
    const item = document.createElement("div");
    item.innerHTML = `<strong>${escapeHTML(alert.title)}</strong><span>${escapeHTML(alert.severity)}</span><p>${escapeHTML(alert.detail)}</p>`;
    return item;
  }));
  renderNetworkHistory(data.network_history ?? []);
  if (Array.isArray(data.detected_locations)) {
    renderDetectedLocations(data.detected_locations);
  }
  forecast.replaceChildren(...parsed.forecast.map((day) => {
    const item = document.createElement("div");
    item.innerHTML = `<strong>${escapeHTML(day.day)}</strong><span>${Number(day.high_c)}°/${Number(day.low_c)}°</span><small>${escapeHTML(day.condition)} · ${Number(day.precipitation_percent ?? 0)}% rain</small>`;
    return item;
  }));
  hourly.replaceChildren(...parsed.hourly.map((point) => {
    const item = document.createElement("div");
    item.innerHTML = `<strong>${escapeHTML(point.hour)}</strong><span>${Number(point.temperature_c)}°</span><small>${escapeHTML(point.condition)} · ${Number(point.wind_kph)} kph</small>`;
    return item;
  }));
}

function renderDetectedLocation(data) {
  detectedLocation.textContent = `${data.location ?? "Unknown"} · ${data.source ?? "network geolocation broker"}`;
  detectedConfidence.textContent = `${Math.round(Number(data.confidence ?? 0) * 100)}%`;
  detectedCoordinates.textContent = `${Number(data.latitude ?? 0).toFixed(3)}, ${Number(data.longitude ?? 0).toFixed(3)}`;
}

function renderDetectedLocations(locations) {
  if (!locations.length) {
    return;
  }
  renderDetectedLocation(locations[0]);
}

function renderSavedLocations(locations) {
  savedLocations.replaceChildren(...locations.map((location) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost-button";
    button.textContent = location;
    button.addEventListener("click", async () => {
      locationInput.value = location;
      await callPlugin("weather.fetch", { location });
    });
    return button;
  }));
}

function renderComparisons(entries) {
  compareCount.textContent = `${entries.length} locations`;
  compareGrid.replaceChildren(...entries.map((entry) => {
    const parsed = parseWeatherResponse(entry);
    const card = document.createElement("button");
    card.type = "button";
    card.className = "weather-compare-card";
    card.innerHTML = `<strong>${escapeHTML(entry.location)}</strong><span>${Number(parsed.current.temperature_c)}°C · ${escapeHTML(parsed.current.condition)}</span><small>${Number(parsed.current.wind_kph)} kph wind · AQI ${Number(parsed.air_quality?.aqi ?? 0)} · ${Number(entry.network?.latency_ms ?? 0)} ms</small>`;
    card.addEventListener("click", () => {
      locationInput.value = entry.location;
      renderWeather(entry);
    });
    return card;
  }));
}

function renderParserExplanation(explanation) {
  parserRun.textContent = String(explanation.run ?? 0);
  parserFields.textContent = String(explanation.field_count ?? 0);
  parserQuality.textContent = explanation.quality ?? "valid";
  parserSteps.replaceChildren(...(explanation.steps ?? []).map((step) => {
    const item = document.createElement("li");
    item.innerHTML = `<strong>${escapeHTML(step.field)}</strong><span>${escapeHTML(step.source)}</span><small>${escapeHTML(step.value)}</small>`;
    return item;
  }));
}

function writeResult(value) {
  result.textContent = formatJSON(value);
}

function parseWeatherResponse(data) {
  if (typeof data.raw_response_body !== "string") {
    return data;
  }
  try {
    const parsed = JSON.parse(data.raw_response_body);
    return {
      current: parsed.current ?? data.current,
      forecast: Array.isArray(parsed.forecast) ? parsed.forecast : data.forecast,
      hourly: Array.isArray(parsed.hourly) ? parsed.hourly : [],
      air_quality: parsed.air_quality ?? data.air_quality ?? null,
      alerts: Array.isArray(parsed.alerts) ? parsed.alerts : [],
    };
  } catch {
    return {
      current: data.current,
      forecast: data.forecast ?? [],
      hourly: [],
      air_quality: data.air_quality ?? null,
      alerts: data.alerts ?? [],
    };
  }
}

function renderNetworkHistory(entries) {
  networkHistoryCount.textContent = String(entries.length);
  networkHistory.replaceChildren(...entries.slice(0, 6).map((entry) => {
    const item = document.createElement("li");
    item.innerHTML = `<strong>${escapeHTML(entry.operation)}</strong><span>${Number(entry.response_status)} · ${Number(entry.latency_ms)} ms · ${Number(entry.bytes_received)} bytes</span><small>${escapeHTML(entry.upstream_mode)} · ${formatTime(entry.at)}</small>`;
    return item;
  }));
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value || "--");
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char]);
}
