const stores = [
  { id: "workspace", kind: "files", scope: "user", quotaBytes: 1048576, quotaFiles: 64 },
  { id: "preferences", kind: "kv", scope: "user", quotaBytes: 262144, quotaFiles: 32 },
  { id: "local_db", kind: "sqlite", scope: "environment", quotaBytes: 1048576, quotaFiles: 32 },
];

document.getElementById("preview")?.addEventListener("click", () => {
  document.getElementById("result").textContent = JSON.stringify({ stores }, null, 2);
  document.getElementById("status").textContent = "Store preview rendered";
});
