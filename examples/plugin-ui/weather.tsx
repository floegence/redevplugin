import { For, Show } from "solid-js";
import { createMutable } from "solid-js/store";
import { render as mount } from "solid-js/web";
import { connectTheme } from "./theme.js";
import { PluginBridgeClient, PluginBridgeError, type PluginMethodResult } from "../../packages/redevplugin-ui/src/plugin.js";

type Location = { id: string; name: string; admin1: string; country: string; latitude: number; longitude: number; timezone: string };
type CurrentWeather = { time: string; temperature: number; apparent_temperature: number; humidity: number; weather_code: number; wind_speed: number; is_day: boolean };
type ForecastDay = { date: string; weather_code: number; temperature_max: number; temperature_min: number; precipitation_probability: number; sunrise: string; sunset: string };
type Forecast = { timezone: string; timezone_abbreviation: string; current: CurrentWeather; days: ForecastDay[] };
type ForecastResult = Forecast & { cache_state: "fresh" | "stale" | "network"; age_seconds: number };

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
const state = createMutable<{
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
}>({
  saved: [],
  results: [],
  selected: DEFAULT_LOCATION,
  query: "",
  busy: false,
  status: "Preparing live conditions...",
  error: false,
  errorMessage: "",
  searchMessage: "",
});
let disposed = false;

connectTheme(bridge);
document.body.replaceChildren();
const unmount = mount(() => <WeatherApp />, document.body);
const initialization = initialize();
bridge.onLifecycle(async (event) => {
  if (event.type === "dispose") {
    disposed = true;
    unmount();
    await initialization.catch(() => undefined);
  }
});

void initialization.catch(reportUnhandledFailure);

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

async function search(): Promise<void> {
  const query = state.query.trim();
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
    await bridge.call("weather.locations.save", {
      id: location.id, name: location.name, admin1: location.admin1,
      country: location.country, latitude: location.latitude,
      longitude: location.longitude, timezone: location.timezone,
    });
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
  await run(() => loadForecast(state.selected, true), `Live weather for ${state.selected.name} is unavailable`);
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

async function loadForecast(location: Location, forceRefresh = false): Promise<void> {
  state.status = `Refreshing ${location.name}...`;
  const response = await bridge.call<PluginMethodResult<ForecastResult>>(
    "weather.forecast",
    {
    latitude: location.latitude,
    longitude: location.longitude,
    timezone: location.timezone || "auto",
    force_refresh: forceRefresh,
    },
  );
  state.selected = location;
  state.forecast = response.data;
  state.status = response.data.cache_state === "stale"
    ? `Saved forecast from ${formatCacheAge(response.data.age_seconds)} ago; refreshing...`
    : `Updated ${formatTime(response.data.current.time)}`;
  state.error = false;
  state.errorMessage = "";
  if (response.data.cache_state === "stale") {
    await render();
    setTimeout(() => void refreshStaleForecast(location), 0);
  }
}

async function refreshStaleForecast(location: Location): Promise<void> {
  try {
    const response = await bridge.call<PluginMethodResult<ForecastResult>>("weather.forecast", {
      latitude: location.latitude,
      longitude: location.longitude,
      timezone: location.timezone || "auto",
      force_refresh: true,
    });
    if (state.selected.id !== location.id) return;
    state.forecast = response.data;
    state.status = `Updated ${formatTime(response.data.current.time)}`;
    state.error = false;
    state.errorMessage = "";
  } catch (error) {
    if (state.selected.id !== location.id) return;
    state.status = `Showing saved forecast for ${location.name}`;
    state.error = true;
    state.errorMessage = friendlyWeatherError(error);
  }
  await render();
}

async function run(action: () => Promise<void>, defaultStatus: string): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.error = false;
  state.errorMessage = "";
  await render();
  try {
    await action();
  } catch (error) {
    state.status = defaultStatus;
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

function render(): Promise<void> { return Promise.resolve(); }

function reportUnhandledFailure(error: unknown): void {
  if (disposed && error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED") return;
  state.error = true;
  state.errorMessage = friendlyWeatherError(error);
}

function WeatherApp() {
  return <main class="weather-app">
    <header class="weather-topbar"><div><p class="eyebrow">Live local outlook</p><h1>Weather</h1></div>
      <form class="location-search" onSubmit={(event) => { event.preventDefault(); void search(); }}>
        <input type="search" name="query" value={state.query} onInput={(event) => { state.query = event.currentTarget.value; }} placeholder="Search city or place" autocomplete="off" aria-label="Search city or place" />
        <button type="submit" aria-label="Search weather" disabled={state.busy}>Search</button>
      </form>
    </header>
    <Show when={state.results.length || state.searchMessage}>
      <section class="search-results" data-floe-surface="floating" aria-label="Search results">
        <header><strong>Places</strong><button onClick={dismissResults}>Close search</button></header>
        <Show when={state.searchMessage}><p role="status">{state.searchMessage}</p></Show>
        <For each={state.results}>{(location) => <div class="search-result">
          <button aria-label={"View weather for " + location.name} onClick={() => void openLocation(location.id)} disabled={state.busy}><strong>{location.name}</strong><span>{placeSubtitle(location)}</span></button>
          <button disabled={state.busy || isSaved(location.id)} onClick={() => void saveLocation(location.id)}>{isSaved(location.id) ? "Saved" : "Save place"}</button>
        </div>}</For>
      </section>
    </Show>
    <section class="weather-main">
      <div class="forecast-toolbar"><nav class="saved-strip" aria-label="Saved places"><For each={state.saved}>{(location) => <button aria-pressed={state.selected.id === location.id} onClick={() => void openLocation(location.id)} disabled={state.busy}>{location.name}</button>}</For></nav>
        <button onClick={() => void retryWeather()} disabled={state.busy}>Refresh</button></div>
      <p class="weather-status" role="status"><span>{state.status}</span><Show when={state.error}> · {state.errorMessage}</Show></p>
      <Show when={state.forecast} fallback={<section class="weather-empty" data-floe-surface="raised"><h2>{state.busy ? "Loading live weather" : "Live weather is unavailable"}</h2><p>{state.errorMessage || "Bringing in live conditions for your place..."}</p><button disabled={state.busy} onClick={() => void retryWeather()}>Try again</button></section>}>{(forecast) => <article class="forecast-view">
        <section class="weather-hero" data-floe-surface="raised">
          <div class="current-summary"><div><p class="eyebrow">{condition(forecast().current.weather_code)}</p><h2>{state.selected.name}</h2><p class="hero-meta">{placeSubtitle(state.selected)} · {forecast().timezone_abbreviation || forecast().timezone} · {formatTime(forecast().current.time)}</p><p class="weather-story">{weatherStory(forecast().current, forecast().days[0])}</p></div>
            <div class="temperature"><strong class="temperature-value">{round(forecast().current.temperature)}°</strong><span>Feels like {round(forecast().current.apparent_temperature)}°</span></div></div>
          <div class="hero-actions"><Show when={isSaved(state.selected.id)} fallback={<button disabled={state.busy} onClick={() => void saveLocation(state.selected.id)}>Save place</button>}><span>Saved place</span><button disabled={state.busy} onClick={() => void removeLocation(state.selected.id)}>Remove</button></Show></div>
          <div class="weather-metrics"><Metric label="Humidity" value={`${round(forecast().current.humidity)}%`} /><Metric label="Wind" value={`${round(forecast().current.wind_speed)} km/h`} /><Metric label="Sunrise" value={formatTime(forecast().days[0]?.sunrise || "—")} /><Metric label="Sunset" value={formatTime(forecast().days[0]?.sunset || "—")} /></div>
        </section>
        <section class="forecast-section"><header><div><p class="eyebrow">The week ahead</p><h3>Seven day forecast</h3></div><span>{formatFullDate(forecast().days[0]?.date)}</span></header>
          <ol class="forecast-grid" aria-label="Seven day forecast"><For each={forecast().days}>{(day, index) => <li class="forecast-day" data-floe-surface="raised"><strong>{index() === 0 ? "Today" : formatDay(day.date)}</strong><span>{formatDateNumber(day.date)}</span><span class={`condition-mark ${conditionKind(day.weather_code)}`} aria-hidden="true">{day.weather_code === 0 ? "☀" : day.weather_code <= 3 ? "☁" : "☂"}</span><span>{condition(day.weather_code)}</span><strong>{round(day.temperature_max)}° <small>{round(day.temperature_min)}°</small></strong><span>{round(day.precipitation_probability)}% rain</span></li>}</For></ol>
        </section>
      </article>}</Show>
    </section>
  </main>;
}
function Metric(props: { label: string; value: string }) { return <div class="weather-metric"><span>{props.label}</span><strong>{props.value}</strong></div>; }

function weatherStory(current: Forecast["current"], today?: ForecastDay): string {
  if (!today) return `${condition(current.weather_code)} around ${round(current.temperature)}°.`;
  return `${condition(current.weather_code)}. A high of ${round(today.temperature_max)}° with a ${round(today.precipitation_probability)}% chance of rain.`;
}

function isSaved(id: string): boolean { return state.saved.some((location) => location.id === id); }
function placeSubtitle(location: Location): string { return [location.admin1, location.country].filter(Boolean).join(", ") || "Local forecast"; }
function round(value: number): string { return Number.isFinite(value) ? String(Math.round(value)) : "-"; }
function formatTime(value: string): string { return value.includes("T") ? value.slice(11, 16) : value; }
function formatCacheAge(seconds: number): string {
  const minutes = Math.max(1, Math.round(seconds / 60));
  return minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} hr`;
}
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
