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
const stormLevelEl = document.querySelector("#storm-level");
const stormWaveEl = document.querySelector("#storm-wave");
const energyEl = document.querySelector("#energy");
const livesEl = document.querySelector("#lives");
const powerupsEl = document.querySelector("#powerups");
const elapsedEl = document.querySelector("#elapsed");
const challengeModeEl = document.querySelector("#challenge-mode");
const leaderboard = document.querySelector("#leaderboard");
const toggleButton = document.querySelector("#game-toggle");
const resetButton = document.querySelector("#game-reset");
const boostButton = document.querySelector("#game-boost");
const powerupButton = document.querySelector("#game-powerup");
const challengeButton = document.querySelector("#game-challenge");
const runSyncButton = document.querySelector("#game-run-sync");
const saveButton = document.querySelector("#game-save");
const snapshotSaveButton = document.querySelector("#game-snapshot-save");
const snapshotLoadButton = document.querySelector("#game-snapshot-load");
const snapshotList = document.querySelector("#snapshot-list");
const challengeList = document.querySelector("#challenge-list");
const missionTitle = document.querySelector("#mission-title");
const missionDetail = document.querySelector("#mission-detail");
const heatFill = document.querySelector("#heat-fill");
const heatLabel = document.querySelector("#heat-label");
const eventFeed = document.querySelector("#game-event-feed");

let running = true;
let lastFrame = performance.now();
let score = 0;
let bestScore = 0;
let level = 1;
let combo = 0;
let bricksCleared = 0;
let powerupsCollected = 0;
let lives = 3;
let energy = 100;
let speed = 1;
let peakSpeed = 1;
let shake = 0;
let paddleX = 360;
let startedAt = performance.now();
let nextMission = "clear";
let challengeActive = false;
let stormLevel = 1;
let stormWave = 0;
let stormTimer = 0;
const ball = { x: 180, y: 80, vx: 230, vy: 190, radius: 13 };
let bricks = createBricks(level);
let powerups = createPowerups(level);
let hazards = createHazards(stormLevel);
const particles = [];
const trails = [];
const events = [];
const stars = createStars(90);

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
  peakSpeed = Math.max(peakSpeed, speed);
  energy = Math.max(0, energy - 8);
  updateHUD();
});

powerupButton.addEventListener("click", () => {
  collectPowerup({
    kind: powerupsCollected % 2 === 0 ? "wide" : "spark",
    x: paddleX,
    y: canvas.height - 70,
  });
});

challengeButton.addEventListener("click", async () => {
  if (!challengeActive) {
    challengeActive = true;
    stormWave = Math.max(1, stormWave);
    stormTimer = 0;
    hazards = createHazards(stormLevel + stormWave);
    speed = Math.min(2.2, speed + 0.18);
    peakSpeed = Math.max(peakSpeed, speed);
    rememberEvent("storm challenge opened", "violet");
    challengeButton.textContent = "Bank storm";
    updateHUD();
    return;
  }
  await callPlugin("game.challenge.report", {
    id: `challenge-${Date.now().toString(36)}`,
    score,
    storm_level: stormLevel,
    waves_survived: stormWave,
    max_combo: combo,
    bricks_cleared: bricksCleared,
    powerups_collected: powerupsCollected,
    peak_speed: peakSpeed,
    duration_ms: Math.round(performance.now() - startedAt),
    completed: stormWave >= 3,
  });
  challengeActive = false;
  challengeButton.textContent = "Storm challenge";
  updateHUD();
});

runSyncButton.addEventListener("click", async () => {
  await callPlugin("game.run.sync", {
    run: captureSnapshot(),
    telemetry: {
      events,
      peak_speed: peakSpeed,
      duration_ms: Math.round(performance.now() - startedAt),
      canvas_size: `${canvas.width}x${canvas.height}`,
    },
  });
});

saveButton.addEventListener("click", async () => {
  await callPlugin("game.score.save", {
    score,
    level,
    combo,
    bricks_cleared: bricksCleared,
    powerups_collected: powerupsCollected,
    peak_speed: peakSpeed,
    duration_ms: Math.round(performance.now() - startedAt),
  });
});

snapshotSaveButton.addEventListener("click", async () => {
  await callPlugin("game.snapshot.save", captureSnapshot());
});

snapshotLoadButton.addEventListener("click", async () => {
  await callPlugin("game.snapshot.load", {});
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
  energy = Math.min(100, energy + dt * 4);
  updateStorm(dt);
  updateStars(dt);
  trails.push({ x: ball.x, y: ball.y, radius: ball.radius, life: 0.9 });
  if (trails.length > 28) {
    trails.shift();
  }
  ball.x += ball.vx * dt;
  ball.y += ball.vy * dt;
  ball.vx *= 0.9996;
  if (ball.x < ball.radius || ball.x > canvas.width - ball.radius) {
    ball.vx *= -1;
    spawnParticles(ball.x, ball.y, "#38bdf8", 7);
    rememberEvent("wall rebound", "blue");
  }
  if (ball.y < ball.radius) {
    ball.vy *= -1;
    spawnParticles(ball.x, ball.y, "#fef08a", 6);
    rememberEvent("ceiling spark", "gold");
  }
  const paddleY = canvas.height - 44;
  if (ball.y + ball.radius > paddleY && ball.y < paddleY + 18 && Math.abs(ball.x - paddleX) < 72 && ball.vy > 0) {
    ball.vy = -Math.abs(ball.vy) - 10;
    ball.vx += (ball.x - paddleX) * 3;
    combo += 1;
    score += 3 + combo;
    spawnParticles(ball.x, paddleY, "#fef08a", 12);
    rememberEvent(`paddle combo x${combo}`, "gold");
  }
  if (ball.y > canvas.height + 40) {
    resetBall();
    score = Math.max(0, score - 12);
    combo = 0;
    lives = Math.max(0, lives - 1);
    shake = 8;
    if (lives === 0) {
      running = false;
      toggleButton.textContent = "Resume";
      status.textContent = "game over";
    }
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
      shake = Math.min(10, shake + 1.4);
      spawnParticles(ball.x, ball.y, brick.color, 18);
      rememberEvent(`brick cleared +${11 + combo * 2 + level}`, "brick");
    }
  }
  for (const powerup of powerups) {
    if (powerup.collected) {
      continue;
    }
    powerup.y += powerup.vy * dt;
    powerup.spin += dt * 5;
    if (Math.abs(powerup.x - paddleX) < 78 && Math.abs(powerup.y - (canvas.height - 44)) < 26) {
      collectPowerup(powerup);
    }
  }
  for (const hazard of hazards) {
    hazard.x += hazard.vx * dt;
    hazard.y += Math.sin(performance.now() / 300 + hazard.phase) * dt * 18;
    if (hazard.x < -hazard.radius) {
      hazard.x = canvas.width + hazard.radius;
      hazard.y = 72 + Math.random() * 260;
    }
    if (challengeActive && Math.hypot(ball.x - hazard.x, ball.y - hazard.y) < ball.radius + hazard.radius) {
      ball.vx *= -1.05;
      ball.vy *= -1.05;
      energy = Math.max(0, energy - 12);
      combo = Math.max(0, combo - 1);
      shake = 12;
      spawnParticles(ball.x, ball.y, "#fb7185", 18);
      rememberEvent("storm hazard deflected", "red");
    }
  }
  if (bricks.every((brick) => brick.hit)) {
    level += 1;
    bricks = createBricks(level);
    powerups = createPowerups(level);
    hazards = createHazards(stormLevel + stormWave);
    resetBall();
    speed = Math.min(2.2, speed + 0.1);
    peakSpeed = Math.max(peakSpeed, speed);
    spawnParticles(canvas.width / 2, canvas.height / 2, "#a7f3d0", 28);
    rememberEvent(`level ${level} opened`, "green");
  }
  updateTrails(dt);
  updateParticles(dt);
  bestScore = Math.max(bestScore, score);
  shake = Math.max(0, shake - dt * 18);
  updateHUD();
}

function draw() {
  context.save();
  if (shake > 0) {
    context.translate((Math.random() - 0.5) * shake, (Math.random() - 0.5) * shake);
  }
  const gradient = context.createLinearGradient(0, 0, canvas.width, canvas.height);
  gradient.addColorStop(0, "#06121f");
  gradient.addColorStop(0.52, "#0b2a3d");
  gradient.addColorStop(1, "#172554");
  context.fillStyle = gradient;
  context.fillRect(0, 0, canvas.width, canvas.height);
  for (const star of stars) {
    context.globalAlpha = star.alpha;
    context.fillStyle = challengeActive ? "#fef08a" : "#67e8f9";
    context.fillRect(star.x, star.y, star.size, star.size);
  }
  context.globalAlpha = 1;
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
  for (const trail of trails) {
    context.globalAlpha = Math.max(0, trail.life * 0.22);
    context.fillStyle = "#67e8f9";
    context.beginPath();
    context.arc(trail.x, trail.y, trail.radius + (1 - trail.life) * 18, 0, Math.PI * 2);
    context.fill();
  }
  context.globalAlpha = 1;
  for (const powerup of powerups) {
    if (powerup.collected) {
      continue;
    }
    context.save();
    context.translate(powerup.x, powerup.y);
    context.rotate(powerup.spin);
    context.fillStyle = powerup.kind === "wide" ? "#a7f3d0" : "#f0abfc";
    roundRect(context, -14, -14, 28, 28, 8);
    context.fill();
    context.restore();
  }
  for (const hazard of hazards) {
    if (!challengeActive) {
      continue;
    }
    const hazardGlow = context.createRadialGradient(hazard.x, hazard.y, 2, hazard.x, hazard.y, hazard.radius + 18);
    hazardGlow.addColorStop(0, "rgba(251,113,133,0.95)");
    hazardGlow.addColorStop(0.5, "rgba(251,113,133,0.28)");
    hazardGlow.addColorStop(1, "rgba(251,113,133,0)");
    context.fillStyle = hazardGlow;
    context.beginPath();
    context.arc(hazard.x, hazard.y, hazard.radius + 18, 0, Math.PI * 2);
    context.fill();
    context.fillStyle = "#fb7185";
    roundRect(context, hazard.x - hazard.radius, hazard.y - hazard.radius / 2, hazard.radius * 2, hazard.radius, 8);
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
  context.restore();
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

function createHazards(nextLevel) {
  return Array.from({ length: Math.min(6, 2 + Math.floor(nextLevel / 2)) }, (_, index) => ({
    x: canvas.width + 90 + index * 126,
    y: 86 + (index % 4) * 74,
    vx: -(82 + nextLevel * 13 + index * 4),
    radius: 12 + (index % 3) * 3,
    phase: index * 0.8,
  }));
}

function createStars(count) {
  return Array.from({ length: count }, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    size: 1 + Math.random() * 2,
    vx: 12 + Math.random() * 48,
    alpha: 0.16 + Math.random() * 0.58,
  }));
}

function resetRound() {
  score = 0;
  combo = 0;
  bricksCleared = 0;
  powerupsCollected = 0;
  lives = 3;
  energy = 100;
  level = 1;
  speed = 1;
  peakSpeed = 1;
  challengeActive = false;
  stormLevel = 1;
  stormWave = 0;
  stormTimer = 0;
  startedAt = performance.now();
  particles.length = 0;
  trails.length = 0;
  events.length = 0;
  bricks = createBricks(level);
  powerups = createPowerups(level);
  hazards = createHazards(stormLevel);
  resetBall();
  running = true;
  status.textContent = "ready";
  toggleButton.textContent = "Pause";
  challengeButton.textContent = "Storm challenge";
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

function createPowerups(nextLevel) {
  return Array.from({ length: Math.min(4, 1 + Math.floor(nextLevel / 2)) }, (_, index) => ({
    kind: index % 2 === 0 ? "wide" : "spark",
    x: 120 + index * 180,
    y: 138 + index * 18,
    vy: 18 + nextLevel * 4,
    spin: index,
    collected: false,
  }));
}

function collectPowerup(powerup) {
  if (powerup.collected) {
    return;
  }
  powerup.collected = true;
  powerupsCollected += 1;
  combo += 2;
  score += 25 + level * 4;
  speed = Math.min(2.2, speed + 0.08);
  peakSpeed = Math.max(peakSpeed, speed);
  energy = Math.min(100, energy + 18);
  spawnParticles(powerup.x, powerup.y, powerup.kind === "wide" ? "#a7f3d0" : "#f0abfc", 24);
  rememberEvent(`${powerup.kind} power-up`, powerup.kind === "wide" ? "green" : "violet");
}

function updateStorm(dt) {
  if (!challengeActive) {
    return;
  }
  stormTimer += dt;
  if (stormTimer > 5.5) {
    stormTimer = 0;
    stormWave += 1;
    stormLevel = Math.max(stormLevel, Math.ceil(stormWave / 2));
    hazards = createHazards(stormLevel + stormWave);
    speed = Math.min(2.2, speed + 0.08);
    peakSpeed = Math.max(peakSpeed, speed);
    score += 18 + stormWave * 4;
    energy = Math.min(100, energy + 10);
    spawnParticles(canvas.width / 2, canvas.height / 2, "#f0abfc", 24);
    rememberEvent(`storm wave ${stormWave}`, "violet");
  }
}

function updateStars(dt) {
  for (const star of stars) {
    star.x -= star.vx * dt * (challengeActive ? 3.2 : 1);
    if (star.x < 0) {
      star.x = canvas.width;
      star.y = Math.random() * canvas.height;
    }
  }
}

function updateTrails(dt) {
  for (const trail of trails) {
    trail.life -= dt * 1.7;
  }
  for (let index = trails.length - 1; index >= 0; index -= 1) {
    if (trails[index].life <= 0) {
      trails.splice(index, 1);
    }
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
    if (Array.isArray(data?.leaderboard)) {
      renderLeaderboard(data.leaderboard);
    }
    if (Array.isArray(data?.snapshots)) {
      renderSnapshots(data.snapshots);
    }
    if (Array.isArray(data?.challenge_history)) {
      renderChallenges(data.challenge_history);
    }
    if (Array.isArray(data?.events)) {
      renderEventFeed(data.events);
    }
    if (data?.mission) {
      renderMission(data.mission);
    }
    if (data?.snapshot && method === "game.snapshot.load") {
      applySnapshot(data.snapshot);
    }
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

function captureSnapshot() {
  return {
    score,
    level,
    combo,
    bricks_cleared: bricksCleared,
    powerups_collected: powerupsCollected,
    lives,
    energy,
    speed,
    storm_level: stormLevel,
    waves_survived: stormWave,
    challenge_active: challengeActive,
    next_mission: nextMission,
  };
}

function applySnapshot(snapshot) {
  if (!snapshot) {
    return;
  }
  score = Number(snapshot.score ?? score);
  level = Number(snapshot.level ?? level);
  combo = Number(snapshot.combo ?? combo);
  bricksCleared = Number(snapshot.bricks_cleared ?? bricksCleared);
  powerupsCollected = Number(snapshot.powerups_collected ?? powerupsCollected);
  lives = Number(snapshot.lives ?? lives);
  energy = Number(snapshot.energy ?? energy);
  speed = Number(snapshot.speed ?? speed);
  stormLevel = Number(snapshot.storm_level ?? stormLevel);
  stormWave = Number(snapshot.waves_survived ?? stormWave);
  challengeActive = Boolean(snapshot.challenge_active ?? challengeActive);
  nextMission = String(snapshot.next_mission ?? nextMission);
  peakSpeed = Math.max(peakSpeed, speed);
  bricks = createBricks(level);
  powerups = createPowerups(level);
  hazards = createHazards(stormLevel + stormWave);
  resetBall();
  startedAt = performance.now();
}

function updateHUD() {
  scoreEl.textContent = String(score);
  bestEl.textContent = String(bestScore);
  levelEl.textContent = String(level);
  comboEl.textContent = String(combo);
  bricksClearedEl.textContent = String(bricksCleared);
  speedEl.textContent = `${speed.toFixed(1)}x`;
  stormLevelEl.textContent = String(stormLevel);
  stormWaveEl.textContent = String(stormWave);
  energyEl.textContent = `${Math.round(energy)}%`;
  livesEl.textContent = String(lives);
  powerupsEl.textContent = String(powerupsCollected);
  elapsedEl.textContent = `${Math.round((performance.now() - startedAt) / 1000)}s`;
  challengeModeEl.textContent = challengeActive ? "storm" : "off";
  const heat = Math.min(100, Math.round((combo / Math.max(1, bricks.length)) * 120 + speed * 8));
  heatFill.style.width = `${heat}%`;
  heatLabel.textContent = `${heat}%`;
  if (bricksCleared < 8) {
    renderMission({ title: "Break the front line", detail: "Clear eight bricks before syncing the run.", key: "clear" });
  } else if (combo < 6) {
    renderMission({ title: "Build combo heat", detail: "Keep rebounds alive until combo reaches six.", key: "combo" });
  } else {
    renderMission({ title: "Bank the run", detail: "Sync the current run to host-backed plugin storage.", key: "sync" });
  }
}

function renderLeaderboard(rows) {
  leaderboard.replaceChildren(...rows.map((row) => {
    const item = document.createElement("li");
    item.innerHTML = `<strong>#${Number(row.rank)} ${escapeHTML(row.name)}</strong><span>${Number(row.score)} pts</span>`;
    return item;
  }));
}

function renderSnapshots(rows) {
  snapshotList.replaceChildren(...rows.map((row, index) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "snapshot-chip";
    item.textContent = `#${index + 1} L${Number(row.level)} · ${Number(row.score)} pts · ${Number(row.energy)}%`;
    item.addEventListener("click", () => {
      applySnapshot(row);
      writeResult({ method: "game.snapshot.apply_local", snapshot: row });
      updateHUD();
    });
    return item;
  }));
}

function renderChallenges(rows) {
  challengeList.replaceChildren(...rows.map((row, index) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "snapshot-chip challenge-chip";
    item.textContent = `#${index + 1} wave ${Number(row.waves_survived)} · ${Number(row.score)} pts`;
    item.addEventListener("click", () => {
      stormLevel = Number(row.storm_level ?? stormLevel);
      stormWave = Number(row.waves_survived ?? stormWave);
      score = Number(row.score ?? score);
      combo = Number(row.max_combo ?? combo);
      challengeActive = false;
      challengeButton.textContent = "Storm challenge";
      writeResult({ method: "game.challenge.apply_local", challenge: row });
      updateHUD();
    });
    return item;
  }));
}

function renderMission(mission) {
  nextMission = String(mission.key ?? nextMission);
  missionTitle.textContent = mission.title ?? "Bank the run";
  missionDetail.textContent = mission.detail ?? "Sync the current run to host storage.";
}

function rememberEvent(label, tone) {
  const entry = {
    label,
    tone,
    score,
    level,
    combo,
    at: new Date().toISOString(),
  };
  events.unshift(entry);
  events.splice(8);
  renderEventFeed(events);
}

function renderEventFeed(rows) {
  eventFeed.replaceChildren(...rows.slice(0, 8).map((row) => {
    const item = document.createElement("li");
    item.className = `tone-${escapeClass(row.tone)}`;
    item.innerHTML = `<strong>${escapeHTML(row.label)}</strong><span>L${Number(row.level ?? level)} · ${Number(row.score ?? score)} pts · combo ${Number(row.combo ?? 0)}</span>`;
    return item;
  }));
}

function writeResult(value) {
  result.textContent = formatJSON(value);
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

function escapeClass(value) {
  return String(value || "default").replace(/[^a-z0-9_-]/gi, "").toLowerCase() || "default";
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
