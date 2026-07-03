const connectors = [
  { id: "forecast_api", transport: "http", destination: "https://api.example.com" },
  { id: "live_updates", transport: "websocket", destination: "wss://stream.example.com" },
  { id: "database", transport: "tcp", destination: "db.example.com:5432" },
  { id: "metrics", transport: "udp", destination: "metrics.example.com:8125" },
];

document.getElementById("preview")?.addEventListener("click", () => {
  document.getElementById("result").textContent = JSON.stringify({ connectors }, null, 2);
  document.getElementById("status").textContent = "Connector preview rendered";
});
