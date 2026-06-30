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

const canvas = document.querySelector("#game-canvas");
const context = canvas.getContext("2d");
const status = document.querySelector("#plugin-status");
const result = document.querySelector("#plugin-result");
const scoreEl = document.querySelector("#score");
const bestEl = document.querySelector("#best-score");
const speedEl = document.querySelector("#speed");
const toggleButton = document.querySelector("#game-toggle");
const boostButton = document.querySelector("#game-boost");
const saveButton = document.querySelector("#game-save");

let running = true;
let lastFrame = performance.now();
let score = 0;
let bestScore = 0;
let speed = 1;
let paddleX = 360;
const ball = { x: 180, y: 80, vx: 230, vy: 190, radius: 13 };
const bricks = createBricks();

client.onLifecycle((event) => {
  status.textContent = event.type;
  writeResult({ lifecycle: event.type, score });
});
client.handshake();

toggleButton.addEventListener("click", () => {
  running = !running;
  toggleButton.textContent = running ? "Pause" : "Resume";
  status.textContent = running ? "ready" : "paused";
  if (running) {
    lastFrame = performance.now();
    requestAnimationFrame(tick);
  }
});

boostButton.addEventListener("click", () => {
  speed = Math.min(2.2, speed + 0.2);
  updateHUD();
});

saveButton.addEventListener("click", async () => {
  await callPlugin("game.score.save", { score });
});

canvas.addEventListener("pointermove", (event) => {
  const rect = canvas.getBoundingClientRect();
  paddleX = Math.max(60, Math.min(canvas.width - 60, ((event.clientX - rect.left) / rect.width) * canvas.width));
});

requestAnimationFrame(tick);

function tick(now) {
  const dt = Math.min(0.032, (now - lastFrame) / 1000) * speed;
  lastFrame = now;
  update(dt);
  draw();
  if (running) {
    requestAnimationFrame(tick);
  }
}

function update(dt) {
  ball.x += ball.vx * dt;
  ball.y += ball.vy * dt;
  if (ball.x < ball.radius || ball.x > canvas.width - ball.radius) {
    ball.vx *= -1;
  }
  if (ball.y < ball.radius) {
    ball.vy *= -1;
  }
  const paddleY = canvas.height - 44;
  if (ball.y + ball.radius > paddleY && ball.y < paddleY + 18 && Math.abs(ball.x - paddleX) < 72 && ball.vy > 0) {
    ball.vy = -Math.abs(ball.vy) - 10;
    ball.vx += (ball.x - paddleX) * 3;
    score += 3;
  }
  if (ball.y > canvas.height + 40) {
    ball.x = 180;
    ball.y = 80;
    ball.vx = 230;
    ball.vy = 190;
    score = Math.max(0, score - 12);
  }
  for (const brick of bricks) {
    if (brick.hit) {
      continue;
    }
    if (ball.x > brick.x && ball.x < brick.x + brick.w && ball.y > brick.y && ball.y < brick.y + brick.h) {
      brick.hit = true;
      ball.vy *= -1;
      score += 11;
    }
  }
  if (bricks.every((brick) => brick.hit)) {
    for (const brick of bricks) {
      brick.hit = false;
    }
    speed = Math.min(2.2, speed + 0.1);
  }
  bestScore = Math.max(bestScore, score);
  updateHUD();
}

function draw() {
  const gradient = context.createLinearGradient(0, 0, canvas.width, canvas.height);
  gradient.addColorStop(0, "#06121f");
  gradient.addColorStop(0.52, "#0b2a3d");
  gradient.addColorStop(1, "#172554");
  context.fillStyle = gradient;
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "rgba(255,255,255,0.07)";
  for (let x = 0; x < canvas.width; x += 42) {
    context.fillRect(x, 0, 1, canvas.height);
  }
  for (const brick of bricks) {
    if (brick.hit) {
      continue;
    }
    context.fillStyle = brick.color;
    roundRect(context, brick.x, brick.y, brick.w, brick.h, 7);
    context.fill();
  }
  context.fillStyle = "#f8fafc";
  roundRect(context, paddleX - 76, canvas.height - 34, 152, 15, 10);
  context.fill();
  const glow = context.createRadialGradient(ball.x, ball.y, 4, ball.x, ball.y, 34);
  glow.addColorStop(0, "#fef08a");
  glow.addColorStop(0.45, "#22d3ee");
  glow.addColorStop(1, "rgba(34,211,238,0)");
  context.fillStyle = glow;
  context.beginPath();
  context.arc(ball.x, ball.y, 34, 0, Math.PI * 2);
  context.fill();
  context.fillStyle = "#fef08a";
  context.beginPath();
  context.arc(ball.x, ball.y, ball.radius, 0, Math.PI * 2);
  context.fill();
}

function createBricks() {
  const colors = ["#f97316", "#14b8a6", "#38bdf8", "#eab308", "#f43f5e"];
  return Array.from({ length: 30 }, (_, index) => ({
    x: 46 + (index % 10) * 78,
    y: 44 + Math.floor(index / 10) * 34,
    w: 62,
    h: 18,
    color: colors[index % colors.length],
    hit: false,
  }));
}

async function callPlugin(method, payload) {
  status.textContent = "saving";
  try {
    const response = await client.call(method, payload);
    bestScore = Math.max(bestScore, Number(response?.data?.best_score ?? response?.best_score ?? bestScore));
    status.textContent = "ready";
    writeResult({ method, response });
    updateHUD();
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      writeResult({ method, error_code: error.errorCode, error: error.message });
      return;
    }
    writeResult({ method, error: String(error) });
  }
}

function updateHUD() {
  scoreEl.textContent = String(score);
  bestEl.textContent = String(bestScore);
  speedEl.textContent = `${speed.toFixed(1)}x`;
}

function writeResult(value) {
  result.textContent = formatJSON(value);
}

function roundRect(ctx, x, y, w, h, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + w, y, x + w, y + h, radius);
  ctx.arcTo(x + w, y + h, x, y + h, radius);
  ctx.arcTo(x, y + h, x, y, radius);
  ctx.arcTo(x, y, x + w, y, radius);
  ctx.closePath();
}
