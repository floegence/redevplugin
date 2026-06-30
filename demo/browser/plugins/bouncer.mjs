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
const levelEl = document.querySelector("#level");
const comboEl = document.querySelector("#combo");
const bricksClearedEl = document.querySelector("#bricks-cleared");
const speedEl = document.querySelector("#speed");
const toggleButton = document.querySelector("#game-toggle");
const resetButton = document.querySelector("#game-reset");
const boostButton = document.querySelector("#game-boost");
const saveButton = document.querySelector("#game-save");

let running = true;
let lastFrame = performance.now();
let score = 0;
let bestScore = 0;
let level = 1;
let combo = 0;
let bricksCleared = 0;
let speed = 1;
let paddleX = 360;
let startedAt = performance.now();
const ball = { x: 180, y: 80, vx: 230, vy: 190, radius: 13 };
let bricks = createBricks(level);
const particles = [];

client.onLifecycle((event) => {
  status.textContent = event.type;
  writeResult({ lifecycle: event.type, score });
  if (event.type === "ready") {
    void loadSavedState();
  }
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

resetButton.addEventListener("click", () => {
  resetRound();
  writeResult({ reset: true, level, score });
});

boostButton.addEventListener("click", () => {
  speed = Math.min(2.2, speed + 0.2);
  updateHUD();
});

saveButton.addEventListener("click", async () => {
  await callPlugin("game.score.save", {
    score,
    level,
    combo,
    bricks_cleared: bricksCleared,
    duration_ms: Math.round(performance.now() - startedAt),
  });
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
  ball.vx *= 0.9996;
  if (ball.x < ball.radius || ball.x > canvas.width - ball.radius) {
    ball.vx *= -1;
    spawnParticles(ball.x, ball.y, "#38bdf8", 7);
  }
  if (ball.y < ball.radius) {
    ball.vy *= -1;
    spawnParticles(ball.x, ball.y, "#fef08a", 6);
  }
  const paddleY = canvas.height - 44;
  if (ball.y + ball.radius > paddleY && ball.y < paddleY + 18 && Math.abs(ball.x - paddleX) < 72 && ball.vy > 0) {
    ball.vy = -Math.abs(ball.vy) - 10;
    ball.vx += (ball.x - paddleX) * 3;
    combo += 1;
    score += 3 + combo;
    spawnParticles(ball.x, paddleY, "#fef08a", 12);
  }
  if (ball.y > canvas.height + 40) {
    resetBall();
    score = Math.max(0, score - 12);
    combo = 0;
  }
  for (const brick of bricks) {
    if (brick.hit) {
      continue;
    }
    if (ball.x > brick.x && ball.x < brick.x + brick.w && ball.y > brick.y && ball.y < brick.y + brick.h) {
      brick.hit = true;
      ball.vy *= -1;
      combo += 1;
      bricksCleared += 1;
      score += 11 + combo * 2 + level;
      spawnParticles(ball.x, ball.y, brick.color, 18);
    }
  }
  if (bricks.every((brick) => brick.hit)) {
    level += 1;
    bricks = createBricks(level);
    resetBall();
    speed = Math.min(2.2, speed + 0.1);
    spawnParticles(canvas.width / 2, canvas.height / 2, "#a7f3d0", 28);
  }
  updateParticles(dt);
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
  context.fillStyle = "rgba(125,211,252,0.08)";
  for (let x = -40; x < canvas.width; x += 42) {
    context.fillRect(x + Math.sin(performance.now() / 600 + x) * 3, 0, 1, canvas.height);
  }
  for (const brick of bricks) {
    if (brick.hit) {
      continue;
    }
    context.fillStyle = brick.color;
    roundRect(context, brick.x, brick.y, brick.w, brick.h, 7);
    context.fill();
  }
  for (const particle of particles) {
    context.globalAlpha = Math.max(0, particle.life);
    context.fillStyle = particle.color;
    context.beginPath();
    context.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
    context.fill();
  }
  context.globalAlpha = 1;
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

function createBricks(nextLevel) {
  const colors = ["#f97316", "#14b8a6", "#38bdf8", "#eab308", "#f43f5e"];
  const columns = 10;
  const rows = Math.min(5, 3 + Math.floor(nextLevel / 2));
  return Array.from({ length: columns * rows }, (_, index) => ({
    x: 46 + (index % columns) * 78,
    y: 44 + Math.floor(index / columns) * 34,
    w: 62,
    h: 18,
    color: colors[(index + nextLevel) % colors.length],
    hit: false,
  }));
}

function resetRound() {
  score = 0;
  combo = 0;
  bricksCleared = 0;
  level = 1;
  speed = 1;
  startedAt = performance.now();
  particles.length = 0;
  bricks = createBricks(level);
  resetBall();
  updateHUD();
}

function resetBall() {
  ball.x = 180 + level * 12;
  ball.y = 80;
  ball.vx = 220 + level * 12;
  ball.vy = 185 + level * 8;
}

function spawnParticles(x, y, color, count) {
  for (let index = 0; index < count; index += 1) {
    const angle = Math.random() * Math.PI * 2;
    const velocity = 70 + Math.random() * 140;
    particles.push({
      x,
      y,
      vx: Math.cos(angle) * velocity,
      vy: Math.sin(angle) * velocity,
      size: 2 + Math.random() * 4,
      color,
      life: 0.75 + Math.random() * 0.35,
    });
  }
}

function updateParticles(dt) {
  for (const particle of particles) {
    particle.x += particle.vx * dt;
    particle.y += particle.vy * dt;
    particle.vy += 90 * dt;
    particle.life -= dt * 1.4;
  }
  for (let index = particles.length - 1; index >= 0; index -= 1) {
    if (particles[index].life <= 0) {
      particles.splice(index, 1);
    }
  }
}

async function loadSavedState() {
  await callPlugin("game.state.get", {});
}

async function callPlugin(method, payload) {
  status.textContent = "saving";
  try {
    const response = await client.call(method, payload);
    const data = response?.data ?? response;
    bestScore = Math.max(bestScore, Number(data?.best_score ?? bestScore));
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
  levelEl.textContent = String(level);
  comboEl.textContent = String(combo);
  bricksClearedEl.textContent = String(bricksCleared);
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
