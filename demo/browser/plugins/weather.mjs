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
const place = document.querySelector("#weather-place");
const temp = document.querySelector("#weather-temp");
const condition = document.querySelector("#weather-condition");
const forecast = document.querySelector("#forecast");
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
  place.textContent = data.location;
  temp.textContent = String(data.current.temperature_c);
  condition.textContent = `${data.current.condition} · ${data.current.wind_kph} kph wind · ${data.current.humidity_percent}% humidity`;
  forecast.replaceChildren(...data.forecast.map((day) => {
    const item = document.createElement("div");
    item.innerHTML = `<strong>${day.day}</strong><span>${day.high_c}°/${day.low_c}°</span><small>${day.condition}</small>`;
    return item;
  }));
}

function writeResult(value) {
  result.textContent = formatJSON(value);
}
