// Business-service responses for the examples UI acceptance suite. SDK surface
// initialization, Worker UI, WASM storage mutations and network conformance are
// exercised separately; this suite must not depend on public weather uptime.
export async function installWeatherReadFixtures(page) {
  const locations = [
    { id: "location_2988507", name: "Paris", admin1: "Ile-de-France", country: "France", latitude: 48.8566, longitude: 2.3522, timezone: "Europe/Paris" },
    { id: "location_2950159", name: "Berlin", admin1: "Berlin", country: "Germany", latitude: 52.52, longitude: 13.41, timezone: "Europe/Berlin" },
  ];
  // A context route survives removal of page-scoped failure injections.
  await page.context().route("**/_redevplugin/api/plugins/rpc", async (route) => {
    const request = route.request().postDataJSON();
    let data;
    if (request.method === "weather.locations.search") {
      const query = String(request.params?.query ?? "").toLowerCase();
      data = { locations: locations.filter((location) => location.name.toLowerCase().includes(query)) };
    } else if (request.method === "weather.forecast") {
      const paris = String(request.params?.timezone ?? "").includes("Paris");
      data = {
        timezone: paris ? "Europe/Paris" : "Europe/Berlin", timezone_abbreviation: "CEST", cache_state: "network", age_seconds: 0,
        current: { time: "2026-07-14T14:00", temperature: paris ? 25.6 : 21.4, apparent_temperature: 26.1, humidity: 47, weather_code: 1, wind_speed: 8.4, is_day: true },
        days: Array.from({ length: 7 }, (_, index) => ({ date: `2026-07-${14 + index}`, weather_code: index % 3, temperature_max: 28 - index, temperature_min: 18 - index, precipitation_probability: 5 + index * 5, sunrise: `2026-07-${14 + index}T06:00`, sunset: `2026-07-${14 + index}T21:00` })),
      };
    } else {
      await route.fallback();
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, data: { data } }) });
  });
}
