import { PluginBridgeClient, type PluginMethodResult, type PluginUIActionEvent, type PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

type Location = { id: string; name: string; admin1: string; country: string; latitude: number; longitude: number; timezone: string };
type CurrentWeather = { time: string; temperature: number; apparent_temperature: number; humidity: number; weather_code: number; wind_speed: number; is_day: boolean };
type ForecastDay = { date: string; weather_code: number; temperature_max: number; temperature_min: number; precipitation_probability: number; sunrise: string; sunset: string };
type Forecast = { timezone: string; timezone_abbreviation: string; current: CurrentWeather; days: ForecastDay[] };

const DEFAULT_LOCATION: Location = {
  id: "location_2950159",
  name: "Berlin",
  admin1: "Berlin",
  country: "Germany",
  latitude: 52.52,
  longitude: 13.41,
  timezone: "Europe/Berlin",
};

const bridge = new PluginBridgeClient({ timeoutMs: 25_000 });
const state: {
  saved: Location[];
  results: Location[];
  selected: Location;
  forecast?: Forecast;
  query: string;
  busy: boolean;
  status: string;
  error: boolean;
  errorMessage: string;
  searchMessage: string;
} = {
  saved: [],
  results: [],
  selected: DEFAULT_LOCATION,
  query: "",
  busy: false,
  status: "Preparing live conditions...",
  error: false,
  errorMessage: "",
  searchMessage: "",
};

bridge.onAction("search-weather", (event) => void search(event));
bridge.onAction("save-location", (event) => void saveLocation(event.value));
bridge.onAction("open-location", (event) => void openLocation(event.value));
bridge.onAction("preview-location", (event) => void openLocation(event.value));
bridge.onAction("remove-location", (event) => void removeLocation(event.value));
bridge.onAction("retry-weather", () => void retryWeather());
bridge.onAction("dismiss-results", () => dismissResults());

void initialize();

async function initialize(): Promise<void> {
  await bridge.ready();
  await run(async () => {
    await bridge.call("weather.initialize", {});
    const response = await bridge.call<PluginMethodResult<{ locations: Location[] }>>("weather.locations.list", {});
    state.saved = response.data.locations;
    state.selected = state.saved[0] ?? DEFAULT_LOCATION;
    await loadForecast(state.selected);
  }, "Live weather could not be loaded");
}

async function search(event: PluginUIActionEvent): Promise<void> {
  const query = String(event.form_data?.query ?? "").trim();
  if (query.length < 2) {
    state.searchMessage = "Enter at least two characters to search.";
    await render();
    return;
  }
  await run(async () => {
    state.query = query;
    const response = await bridge.call<PluginMethodResult<{ locations: Location[] }>>("weather.locations.search", { query });
    state.results = response.data.locations.slice(0, 6);
    state.searchMessage = state.results.length === 0 ? `No places found for ${query}.` : "";
    state.status = state.results.length === 0 ? state.status : `${state.results.length} places found`;
    state.error = false;
  }, "Place search is temporarily unavailable");
}

async function saveLocation(id?: string): Promise<void> {
  const location = state.results.find((candidate) => candidate.id === id) ?? (state.selected.id === id ? state.selected : undefined);
  if (!location) return;
  await run(async () => {
    const forecastLocationID = state.selected.id;
    await bridge.call("weather.locations.save", location);
    await reloadSaved();
    if (!state.forecast || forecastLocationID !== location.id) await loadForecast(location);
    else state.selected = location;
    state.results = [];
    state.searchMessage = "";
    state.status = `${location.name} saved`;
  }, "This place could not be saved");
}

async function openLocation(id?: string): Promise<void> {
  const location = state.saved.find((candidate) => candidate.id === id) ?? state.results.find((candidate) => candidate.id === id);
  if (!location) return;
  await run(async () => {
    state.results = [];
    state.searchMessage = "";
    await loadForecast(location);
  }, `Live weather for ${location.name} is unavailable`);
}

async function removeLocation(id?: string): Promise<void> {
  if (!id) return;
  await run(async () => {
    const removed = state.saved.find((location) => location.id === id);
    await bridge.call("weather.locations.remove", { id });
    await reloadSaved();
    if (state.selected.id === id) {
      await loadForecast(state.saved[0] ?? DEFAULT_LOCATION);
    }
    state.status = removed ? `${removed.name} removed` : "Saved place removed";
  }, "This saved place could not be removed");
}

async function retryWeather(): Promise<void> {
  await run(() => loadForecast(state.selected), `Live weather for ${state.selected.name} is unavailable`);
}

function dismissResults(): void {
  state.results = [];
  state.searchMessage = "";
  state.status = state.forecast ? `Updated ${formatTime(state.forecast.current.time)}` : "Search closed";
  void render();
}

async function reloadSaved(): Promise<void> {
  const response = await bridge.call<PluginMethodResult<{ locations: Location[] }>>("weather.locations.list", {});
  state.saved = response.data.locations;
}

async function loadForecast(location: Location): Promise<void> {
  state.status = `Refreshing ${location.name}...`;
  const response = await bridge.call<PluginMethodResult<Forecast>>("weather.forecast", {
    latitude: location.latitude,
    longitude: location.longitude,
    timezone: location.timezone || "auto",
  });
  state.selected = location;
  state.forecast = response.data;
  state.status = `Updated ${formatTime(response.data.current.time)}`;
  state.error = false;
  state.errorMessage = "";
}

async function run(action: () => Promise<void>, fallback: string): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.error = false;
  state.errorMessage = "";
  await render();
  try {
    await action();
  } catch (error) {
    state.status = fallback;
    state.error = true;
    state.errorMessage = friendlyWeatherError(error);
  } finally {
    state.busy = false;
    await render();
  }
}

function friendlyWeatherError(error: unknown): string {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (message.includes("network") || message.includes("runtime") || message.includes("permission") || message.includes("timeout")) {
    return "Check your connection, then try the refresh again.";
  }
  return "The forecast service did not return fresh conditions. Your saved places are still here.";
}

function render(): Promise<void> {
  const current = state.forecast?.current;
  const atmosphere = current ? `${current.is_day ? "day" : "night"} ${conditionKind(current.weather_code)}` : "day partly";
  return bridge.render({
    type: "element",
    tag: "main",
    attributes: { class: `weather-app ${atmosphere}` },
    children: [topbar(), layout()],
  });
}

function topbar(): PluginUIVNode {
  return { type: "element", tag: "header", attributes: { class: "weather-topbar" }, children: [
    { type: "element", tag: "div", attributes: { class: "weather-brand" }, children: [
      { type: "element", tag: "span", attributes: { class: "weather-brand-mark", "aria-hidden": true }, children: [] },
      { type: "element", tag: "div", children: [
        { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["Live local outlook"] },
        { type: "element", tag: "h1", children: ["Weather"] },
      ] },
    ] },
    { type: "element", tag: "form", attributes: { class: "location-search", "data-redevplugin-action": "search-weather" }, children: [
      { type: "element", tag: "input", attributes: { type: "search", name: "query", value: state.query, placeholder: "Search city or place", autocomplete: "off", disabled: state.busy, "aria-label": "Search city or place" } },
      { type: "element", tag: "button", attributes: { class: "search-button", type: "submit", title: "Search weather", "aria-label": "Search weather", disabled: state.busy }, children: [
        { type: "element", tag: "span", attributes: { class: "search-button-icon", "aria-hidden": true }, children: [] },
      ] },
    ] },
    state.results.length > 0 ? searchResults() : state.searchMessage ? searchNotice() : "",
  ] };
}

function layout(): PluginUIVNode {
  return { type: "element", tag: "section", attributes: { class: "weather-main" }, children: [
    forecastToolbar(),
    state.forecast ? forecastView(state.selected, state.forecast) : state.busy ? weatherLoading() : weatherError(),
  ] };
}

function forecastToolbar(): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "forecast-toolbar" }, children: [
    { type: "element", tag: "div", attributes: { class: state.error ? "weather-status error" : "weather-status", role: "status" }, children: [
      { type: "element", tag: "span", attributes: { class: "status-dot", "aria-hidden": true }, children: [] },
      { type: "element", tag: "span", children: [state.busy ? "Contacting weather services..." : state.status] },
    ] },
    state.saved.length > 0 ? savedStrip() : "",
  ] };
}

function savedStrip(): PluginUIVNode {
  return { type: "element", tag: "nav", attributes: { class: "saved-strip", "aria-label": "Saved places" }, children: [
    { type: "element", tag: "span", attributes: { class: "saved-strip-label" }, children: [state.saved.length === 0 ? "Discover" : "My places"] },
    { type: "element", tag: "ul", attributes: { class: "saved-list" }, children: [
      ...(state.saved.length === 0 ? [savedLocation(DEFAULT_LOCATION, true)] : state.saved.map((location) => savedLocation(location, false))),
    ] },
  ] };
}

function savedLocation(location: Location, exploring: boolean): PluginUIVNode {
  return { type: "element", tag: "li", children: [
    { type: "element", tag: "button", attributes: { class: "saved-location", type: "button", value: location.id, disabled: state.busy, "aria-pressed": state.selected.id === location.id, "data-redevplugin-action": "open-location" }, children: [
      { type: "element", tag: "strong", children: [exploring ? "Explore Berlin" : location.name] },
    ] },
  ] };
}

function searchResults(): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "search-popover" }, children: [
    { type: "element", tag: "div", attributes: { class: "search-popover-heading" }, children: [
      { type: "element", tag: "div", children: [
        { type: "element", tag: "strong", children: ["Places"] },
        { type: "element", tag: "span", children: [`Results for ${state.query}`] },
      ] },
      { type: "element", tag: "button", attributes: { class: "close-results", type: "button", title: "Close search results", "aria-label": "Close search results", "data-redevplugin-action": "dismiss-results" }, children: [
        { type: "element", tag: "span", attributes: { class: "icon-close", "aria-hidden": true }, children: [] },
      ] },
    ] },
    { type: "element", tag: "ul", attributes: { class: "search-results" }, children: state.results.map(searchResult) },
  ] };
}

function searchNotice(): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "search-popover search-notice", role: "status" }, children: [
    { type: "element", tag: "span", attributes: { class: "result-pin", "aria-hidden": true }, children: [] },
    { type: "element", tag: "p", children: [state.searchMessage] },
    { type: "element", tag: "button", attributes: { class: "close-results", type: "button", title: "Close search message", "aria-label": "Close search message", "data-redevplugin-action": "dismiss-results" }, children: [
      { type: "element", tag: "span", attributes: { class: "icon-close", "aria-hidden": true }, children: [] },
    ] },
  ] };
}

function searchResult(location: Location): PluginUIVNode {
  return { type: "element", tag: "li", attributes: { class: "search-result" }, children: [
    { type: "element", tag: "span", attributes: { class: "result-pin", "aria-hidden": true }, children: [] },
    { type: "element", tag: "div", attributes: { class: "result-copy" }, children: [
      { type: "element", tag: "strong", children: [location.name] },
      { type: "element", tag: "p", children: [placeSubtitle(location)] },
    ] },
    { type: "element", tag: "div", attributes: { class: "result-actions" }, children: [
      { type: "element", tag: "button", attributes: { class: "button secondary", type: "button", value: location.id, disabled: state.busy, "aria-label": `View weather for ${location.name}`, "data-redevplugin-action": "preview-location" }, children: ["View"] },
      { type: "element", tag: "button", attributes: { class: "button secondary", type: "button", value: location.id, disabled: state.busy || isSaved(location.id), "aria-label": isSaved(location.id) ? `${location.name} is saved` : `Save ${location.name}`, "data-redevplugin-action": "save-location" }, children: [isSaved(location.id) ? "Saved" : "Save"] },
    ] },
  ] };
}

function forecastView(location: Location, forecast: Forecast): PluginUIVNode {
  const current = forecast.current;
  const today = forecast.days[0];
  return { type: "element", tag: "article", attributes: { class: "forecast-view" }, children: [
    { type: "element", tag: "section", attributes: { class: "weather-hero" }, children: [
      { type: "element", tag: "div", attributes: { class: "weather-scene", "aria-hidden": true }, children: [] },
      { type: "element", tag: "div", attributes: { class: "hero-atmosphere", "aria-hidden": true }, children: [
        { type: "element", tag: "span", attributes: { class: "atmosphere-sun" }, children: [] },
        { type: "element", tag: "span", attributes: { class: "atmosphere-line line-one" }, children: [] },
        { type: "element", tag: "span", attributes: { class: "atmosphere-line line-two" }, children: [] },
      ] },
      { type: "element", tag: "div", attributes: { class: "current-summary" }, children: [
        { type: "element", tag: "div", attributes: { class: "hero-copy" }, children: [
          { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: [condition(current.weather_code)] },
          { type: "element", tag: "h2", children: [location.name] },
          { type: "element", tag: "p", attributes: { class: "hero-meta" }, children: [`${placeSubtitle(location)} / ${forecast.timezone_abbreviation || forecast.timezone} / Local ${formatTime(current.time)}`] },
          { type: "element", tag: "p", attributes: { class: "weather-story" }, children: [weatherStory(current, today)] },
        ] },
        { type: "element", tag: "div", attributes: { class: "temperature" }, children: [
          { type: "element", tag: "strong", attributes: { class: "temperature-value" }, children: [`${round(current.temperature)}°`] },
          { type: "element", tag: "span", attributes: { class: "temperature-feels" }, children: [`Feels like ${round(current.apparent_temperature)}°`] },
        ] },
        { type: "element", tag: "span", attributes: { class: `weather-icon hero-icon weather-icon--${conditionKind(current.weather_code)}`, role: "img", "aria-label": condition(current.weather_code) }, children: [] },
      ] },
      { type: "element", tag: "div", attributes: { class: "hero-footer" }, children: [
        { type: "element", tag: "div", attributes: { class: "hero-actions" }, children: [
          isSaved(location.id)
            ? { type: "element", tag: "span", attributes: { class: "saved-badge" }, children: ["Saved place"] }
            : { type: "element", tag: "button", attributes: { class: "button hero-save", type: "button", value: location.id, disabled: state.busy, "data-redevplugin-action": "save-location" }, children: ["Save place"] },
          isSaved(location.id) ? { type: "element", tag: "button", attributes: { class: "remove-location", type: "button", value: location.id, disabled: state.busy, "data-redevplugin-action": "remove-location" }, children: ["Remove"] } : "",
        ] },
        { type: "element", tag: "div", attributes: { class: "weather-glance", "aria-label": "Today at a glance" }, children: [
          glanceItem("High", today ? `${round(today.temperature_max)}°` : "-"),
          glanceItem("Low", today ? `${round(today.temperature_min)}°` : "-"),
          glanceItem("Rain", today ? `${round(today.precipitation_probability)}%` : "-"),
        ] },
      ] },
      { type: "element", tag: "div", attributes: { class: "weather-metrics" }, children: [
        weatherMetric("Humidity", `${round(current.humidity)}%`, "Moisture"),
        weatherMetric("Wind", `${round(current.wind_speed)} km/h`, "At ground level"),
        weatherMetric("Sunrise", today ? formatTime(today.sunrise) : "-", "First light"),
        weatherMetric("Sunset", today ? formatTime(today.sunset) : "-", "Last light"),
      ] },
    ] },
    { type: "element", tag: "section", attributes: { class: "forecast-section" }, children: [
      { type: "element", tag: "div", attributes: { class: "forecast-heading" }, children: [
        { type: "element", tag: "div", children: [
          { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["The week ahead"] },
          { type: "element", tag: "h3", children: ["Seven day forecast"] },
        ] },
        { type: "element", tag: "span", children: [formatFullDate(forecast.days[0]?.date)] },
      ] },
      { type: "element", tag: "div", attributes: { class: "forecast-scroll" }, children: [
        { type: "element", tag: "ol", attributes: { class: "forecast-grid", "aria-label": "Seven day forecast" }, children: forecast.days.map(forecastDay) },
      ] },
    ] },
  ] };
}

function glanceItem(label: string, value: string): PluginUIVNode {
  return { type: "element", tag: "span", attributes: { class: "glance-item" }, children: [
    { type: "element", tag: "small", children: [label] },
    { type: "element", tag: "strong", children: [value] },
  ] };
}

function weatherStory(current: Forecast["current"], today?: ForecastDay): string {
  if (!today) return `${condition(current.weather_code)} around ${round(current.temperature)}°.`;
  return `${condition(current.weather_code)}. A high of ${round(today.temperature_max)}° with a ${round(today.precipitation_probability)}% chance of rain.`;
}

function weatherLoading(): PluginUIVNode {
  return { type: "element", tag: "section", attributes: { class: "weather-loading", "aria-label": "Loading live weather" }, children: [
    { type: "element", tag: "div", attributes: { class: "weather-loading-scene", "aria-hidden": true }, children: [
      { type: "element", tag: "span", attributes: { class: "loading-city" }, children: [] },
      { type: "element", tag: "span", attributes: { class: "loading-temperature" }, children: [] },
      { type: "element", tag: "span", attributes: { class: "loading-condition" }, children: [] },
    ] },
    { type: "element", tag: "p", children: ["Bringing in live conditions for your place..."] },
  ] };
}

function weatherMetric(label: string, value: string, detail: string): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "weather-metric" }, children: [
    { type: "element", tag: "span", children: [label] },
    { type: "element", tag: "strong", children: [value] },
    { type: "element", tag: "small", children: [detail] },
  ] };
}

function forecastDay(day: ForecastDay, index: number): PluginUIVNode {
  return { type: "element", tag: "li", attributes: { class: `forecast-day forecast-day--${conditionKind(day.weather_code)}` }, children: [
    { type: "element", tag: "div", attributes: { class: "forecast-day-heading" }, children: [
      { type: "element", tag: "strong", children: [index === 0 ? "Today" : formatDay(day.date)] },
      { type: "element", tag: "span", children: [formatDateNumber(day.date)] },
    ] },
    { type: "element", tag: "span", attributes: { class: `weather-icon forecast-icon weather-icon--${conditionKind(day.weather_code)}`, role: "img", "aria-label": condition(day.weather_code) }, children: [] },
    { type: "element", tag: "span", attributes: { class: "condition-label" }, children: [condition(day.weather_code)] },
    { type: "element", tag: "div", attributes: { class: "temperature-range" }, children: [
      { type: "element", tag: "strong", children: [`${round(day.temperature_max)}°`] },
      { type: "element", tag: "span", children: [`${round(day.temperature_min)}°`] },
    ] },
    { type: "element", tag: "span", attributes: { class: "rain-chance" }, children: [`${round(day.precipitation_probability)}% rain`] },
  ] };
}

function weatherError(): PluginUIVNode {
  return { type: "element", tag: "section", attributes: { class: "weather-error" }, children: [
    { type: "element", tag: "div", attributes: { class: "weather-error-visual", "aria-hidden": true }, children: [
      { type: "element", tag: "span", attributes: { class: "weather-icon weather-icon--partly" }, children: [] },
      { type: "element", tag: "span", attributes: { class: "offline-mark" }, children: [] },
    ] },
    { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: [state.selected.name] },
    { type: "element", tag: "h2", children: ["Live weather is unavailable"] },
    { type: "element", tag: "p", children: [state.errorMessage || "Fresh conditions could not be reached just now."] },
    { type: "element", tag: "button", attributes: { class: "button", type: "button", disabled: state.busy, "data-redevplugin-action": "retry-weather" }, children: [state.busy ? "Refreshing" : "Try again"] },
  ] };
}

function isSaved(id: string): boolean { return state.saved.some((location) => location.id === id); }
function placeSubtitle(location: Location): string { return [location.admin1, location.country].filter(Boolean).join(", ") || "Local forecast"; }
function round(value: number): string { return Number.isFinite(value) ? String(Math.round(value)) : "-"; }
function formatTime(value: string): string { return value.includes("T") ? value.slice(11, 16) : value; }
function formatDay(value: string): string { return new Date(`${value}T12:00:00Z`).toLocaleDateString("en", { weekday: "short" }); }
function formatDateNumber(value: string): string { return new Date(`${value}T12:00:00Z`).toLocaleDateString("en", { month: "short", day: "numeric" }); }
function formatFullDate(value?: string): string { return value ? new Date(`${value}T12:00:00Z`).toLocaleDateString("en", { month: "long", day: "numeric", year: "numeric" }) : ""; }
function condition(code: number): string {
  if (code === 0) return "Clear sky";
  if (code <= 3) return "Partly cloudy";
  if (code <= 48) return "Misty";
  if (code <= 67) return "Rain";
  if (code <= 77) return "Snow";
  if (code <= 82) return "Rain showers";
  if (code <= 86) return "Snow showers";
  return "Thunderstorms";
}
function conditionKind(code: number): string {
  if (code === 0) return "clear";
  if (code <= 3) return "partly";
  if (code <= 48) return "fog";
  if (code <= 67) return "rain";
  if (code <= 77) return "snow";
  if (code <= 82) return "rain";
  if (code <= 86) return "snow";
  return "storm";
}
