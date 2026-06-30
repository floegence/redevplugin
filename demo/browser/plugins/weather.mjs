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
const locationInput = document.querySelector("#weather-location");
const savedLocations = document.querySelector("#saved-locations");
const place = document.querySelector("#weather-place");
const temp = document.querySelector("#weather-temp");
const condition = document.querySelector("#weather-condition");
const wind = document.querySelector("#weather-wind");
const humidity = document.querySelector("#weather-humidity");
const pressure = document.querySelector("#weather-pressure");
const uv = document.querySelector("#weather-uv");
const networkOperation = document.querySelector("#network-operation");
const networkLatency = document.querySelector("#network-latency");
const networkBytes = document.querySelector("#network-bytes");
const networkConnector = document.querySelector("#network-connector");
const networkBroker = document.querySelector("#network-broker");
const networkResponse = document.querySelector("#network-response");
const networkParser = document.querySelector("#network-parser");
const forecast = document.querySelector("#forecast");
const hourly = document.querySelector("#hourly");
const rawWeatherResponse = document.querySelector("#raw-weather-response");
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

async function loadSavedLocation() {
  const response = await callPlugin("weather.location.get", {});
  const location = response?.data?.location ?? response?.location ?? "San Francisco";
  const locations = response?.data?.saved_locations ?? response?.saved_locations ?? [location];
  renderSavedLocations(locations);
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
    if (data?.location && method !== "weather.fetch") {
      place.textContent = data.location;
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
    };
  } catch {
    return {
      current: data.current,
      forecast: data.forecast ?? [],
      hourly: [],
    };
  }
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
