import { PluginBridgeClient, type PluginCanvasInputEvent, type PluginMethodResult, type PluginUIElementVNode } from "../../packages/redevplugin-ui/src/plugin.js";

type Vec = { x: number; y: number };
type Bullet = Vec & { vy: number; enemy: boolean };
type Enemy = Vec & { vx: number; vy: number; hp: number; kind: "ship" | "meteor"; phase: number };
type Particle = Vec & { vx: number; vy: number; life: number; color: string };
type GamePhase = "ready" | "running" | "paused" | "game-over";
type InputMode = "keyboard" | "pointer";

const LANDSCAPE_WIDTH = 960;
const LANDSCAPE_HEIGHT = 540;
const PORTRAIT_WIDTH = 540;
const PORTRAIT_HEIGHT = 1080;
let WIDTH = LANDSCAPE_WIDTH;
let HEIGHT = LANDSCAPE_HEIGHT;
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const keys = new Set<string>();
const images = new Map<string, ImageBitmap>();
const player = { x: WIDTH / 2, y: HEIGHT - 72, speed: 330, cooldown: 0 };
let canvas: OffscreenCanvas;
let context: OffscreenCanvasRenderingContext2D;
let bullets: Bullet[] = [];
let enemies: Enemy[] = [];
let particles: Particle[] = [];
let score = 0;
let highScore = 0;
let lives = 3;
let level = 1;
let spawnTimer = 0;
let lastFrame = 0;
let fps = 60;
let phase: GamePhase = "ready";
let inputMode: InputMode = "pointer";
let pointerDown = false;
let pointerTarget: Vec | undefined;
let savedScore = 0;
let invulnerability = 0;
let cssWidth = WIDTH;
let cssHeight = HEIGHT;
let devicePixelRatio = 1;
let renderScale = 1;
let renderOffsetX = 0;
let renderOffsetY = 0;
let spawnedEnemies = 0;
let scorePersistTimer: ReturnType<typeof setTimeout> | undefined;
let scorePersistInFlight: Promise<void> | undefined;
let frameTimer: ReturnType<typeof setTimeout> | undefined;
let surfaceVisible = true;
let disposed = false;
let gameReady = false;
let accessibilityUpdateInFlight: Promise<void> | undefined;
let lastAccessibilityUpdateAt = 0;
let lastAccessibilitySignature = "";

bridge.onAction("pause-game", () => {
  if (phase === "ready" || phase === "game-over") startMission();
  else phase = phase === "running" ? "paused" : "running";
  syncCanvasAccessibility(true);
});
bridge.onAction("restart-game", () => {
  void persistHighScore();
  restart(false);
  syncCanvasAccessibility(true);
});
bridge.onCanvasInput("playfield", handleInput);
bridge.onLifecycle(async (event) => {
  if (event.type === "visible") {
    surfaceVisible = true;
    lastFrame = performance.now();
    scheduleFrame();
    syncCanvasAccessibility(true);
  }
  if (event.type === "hidden") {
    surfaceVisible = false;
    stopFrameLoop();
    if (phase === "running") phase = "paused";
    syncCanvasAccessibility(true);
    await persistHighScore();
  }
  if (event.type === "dispose") {
    disposed = true;
    surfaceVisible = false;
    gameReady = false;
    stopFrameLoop();
    clearScorePersistTimer();
    await persistHighScore();
    for (const image of images.values()) image.close();
  }
});

void initialize().catch((error) => void showFatalError(error));

async function initialize(): Promise<void> {
  await bridge.ready();
  await bridge.render(gameSurface(false));
  await bridge.call("game.initialize", {});
  const [surface, backgroundImage, playerImage, enemyImage, laserImage, meteorImage, saved] = await Promise.all([
    bridge.openCanvas("playfield"),
    bridge.loadImageAsset("starfield-background"),
    bridge.loadImageAsset("player-ship"),
    bridge.loadImageAsset("enemy-ship"),
    bridge.loadImageAsset("player-laser"),
    bridge.loadImageAsset("meteor"),
    bridge.call<PluginMethodResult<{ score: number }>>("game.highScore.load", {}),
  ]);
  canvas = surface.canvas;
  cssWidth = surface.cssWidth;
  cssHeight = surface.cssHeight;
  devicePixelRatio = surface.devicePixelRatio;
  configureWorld(cssWidth, cssHeight, devicePixelRatio);
  const ctx = canvas.getContext("2d", { alpha: false });
  if (!ctx) throw new Error("2D canvas is unavailable");
  context = ctx;
  images.set("background", backgroundImage);
  images.set("player", playerImage);
  images.set("enemy", enemyImage);
  images.set("laser", laserImage);
  images.set("meteor", meteorImage);
  highScore = saved.data.score;
  savedScore = highScore;
  restart(false);
  gameReady = true;
  lastFrame = performance.now();
  syncCanvasAccessibility(true);
  scheduleFrame();
}

async function showFatalError(_error: unknown): Promise<void> {
  try {
    await bridge.ready();
    await bridge.render(gameSurface(true));
  } catch {
    // The host owns the final fallback when the plugin bridge itself is unavailable.
  }
}

function gameSurface(fatal: boolean): PluginUIElementVNode {
  return {
    type: "element" as const,
    key: "game-root",
    tag: "main" as const,
    attributes: { class: fatal ? "game-shell arcade-shell game-failed" : "game-shell arcade-shell" },
    children: [
      { type: "element" as const, key: "canvas-stage", tag: "section" as const, attributes: { class: "canvas-stage", "aria-label": "Sky Strike game" }, children: [
        { type: "element" as const, key: "playfield", tag: "canvas" as const, attributes: { "data-redevplugin-canvas": "playfield", width: 960, height: 540, tabindex: 0, "aria-label": "Sky Strike mission playfield", "aria-describedby": "control-hint" }, children: [] },
        { type: "element" as const, key: "game-actions", tag: "div" as const, attributes: { class: "game-actions" }, children: [
          { type: "element" as const, key: "pause-game", tag: "button" as const, attributes: { type: "button", "data-redevplugin-action": "pause-game", title: "Play, pause, or resume", "aria-label": "Play, pause, or resume" }, children: [
            { type: "element" as const, key: "pause-game-icon", tag: "span" as const, attributes: { class: "icon-play-pause", "aria-hidden": true }, children: [] },
          ] },
          { type: "element" as const, key: "restart-game", tag: "button" as const, attributes: { type: "button", "data-redevplugin-action": "restart-game", title: "Restart mission", "aria-label": "Restart mission" }, children: [
            { type: "element" as const, key: "restart-game-icon", tag: "span" as const, attributes: { class: "icon-restart", "aria-hidden": true }, children: [] },
          ] },
        ] },
        { type: "element" as const, key: "control-hint", tag: "div" as const, attributes: { id: "control-hint", class: "control-hint" }, children: [
          { type: "element" as const, key: "keyboard-hint", tag: "span" as const, attributes: { class: "keyboard-copy" }, children: ["WASD or arrows to fly / Space to fire"] },
          { type: "element" as const, key: "touch-hint", tag: "span" as const, attributes: { class: "touch-copy" }, children: ["Drag to fly / Hold to fire"] },
        ] },
      ] },
      { type: "element" as const, key: "game-error", tag: "section" as const, attributes: { class: "game-error", hidden: !fatal, role: "alert" }, children: [
        { type: "element" as const, key: "game-error-mark", tag: "span" as const, attributes: { class: "game-error-mark", "aria-hidden": true }, children: ["07"] },
        { type: "element" as const, key: "game-error-eyebrow", tag: "p" as const, attributes: { class: "game-error-eyebrow" }, children: ["Mission unavailable"] },
        { type: "element" as const, key: "game-error-title", tag: "h1" as const, children: ["Sky Strike could not start"] },
        { type: "element" as const, key: "game-error-message", tag: "p" as const, children: ["The flight system did not finish loading. Reopen the app to try again."] },
      ] },
    ],
  };
}

function scheduleFrame(): void {
  if (disposed || !surfaceVisible || !gameReady || frameTimer !== undefined) return;
  frameTimer = setTimeout(() => {
    frameTimer = undefined;
    frame();
  }, 1000 / 60);
}

function stopFrameLoop(): void {
  if (frameTimer !== undefined) clearTimeout(frameTimer);
  frameTimer = undefined;
}

function frame(): void {
  if (disposed || !surfaceVisible || !gameReady) return;
  const now = performance.now();
  const dt = Math.min(0.05, Math.max(0.001, (now - lastFrame) / 1000));
  lastFrame = now;
  fps += ((1 / dt) - fps) * 0.08;
  if (phase === "running") update(dt);
  draw(now / 1000);
  syncCanvasAccessibility(false, now);
  scheduleFrame();
}

function update(dt: number): void {
  level = 1 + Math.floor(score / 1200);
  invulnerability = Math.max(0, invulnerability - dt);
  movePlayer(dt);
  player.cooldown = Math.max(0, player.cooldown - dt);
  if ((keys.has("Space") || pointerDown) && player.cooldown <= 0) fire();

  spawnTimer -= dt;
  if (spawnTimer <= 0) {
    spawnEnemy();
    spawnTimer = Math.max(0.28, 0.92 - level * 0.055) * (0.75 + Math.random() * 0.5);
  }
  for (const bullet of bullets) bullet.y += bullet.vy * dt;
  for (const enemy of enemies) {
    enemy.phase += dt;
    enemy.x += (enemy.vx + Math.sin(enemy.phase * 2.4) * 34) * dt;
    enemy.y += enemy.vy * dt;
    if (enemy.kind === "ship" && Math.random() < dt * (0.22 + level * 0.025)) {
      bullets.push({ x: enemy.x, y: enemy.y + 18, vy: 260 + level * 12, enemy: true });
    }
  }
  for (const particle of particles) {
    particle.x += particle.vx * dt;
    particle.y += particle.vy * dt;
    particle.life -= dt;
  }
  resolveCollisions();
  bullets = bullets.filter((bullet) => bullet.y > -30 && bullet.y < HEIGHT + 30);
  enemies = enemies.filter((enemy) => {
    if (enemy.y < HEIGHT + 40) return true;
    damagePlayer(enemy.x, HEIGHT - 10);
    return false;
  });
  particles = particles.filter((particle) => particle.life > 0);
}

function movePlayer(dt: number): void {
  let dx = 0;
  let dy = 0;
  if (keys.has("ArrowLeft") || keys.has("KeyA")) dx -= 1;
  if (keys.has("ArrowRight") || keys.has("KeyD")) dx += 1;
  if (keys.has("ArrowUp") || keys.has("KeyW")) dy -= 1;
  if (keys.has("ArrowDown") || keys.has("KeyS")) dy += 1;
  if (pointerTarget) {
    const deltaX = pointerTarget.x - player.x;
    const deltaY = pointerTarget.y - player.y;
    const distance = Math.hypot(deltaX, deltaY);
    if (distance > 3) {
      dx = deltaX / distance;
      dy = deltaY / distance;
    }
  }
  const length = Math.hypot(dx, dy) || 1;
  player.x = clamp(player.x + (dx / length) * player.speed * dt, 28, WIDTH - 28);
  player.y = clamp(player.y + (dy / length) * player.speed * dt, HEIGHT * 0.45, HEIGHT - 30);
}

function fire(): void {
  player.cooldown = Math.max(0.08, 0.18 - level * 0.006);
  bullets.push({ x: player.x - 10, y: player.y - 26, vy: -520, enemy: false });
  bullets.push({ x: player.x + 10, y: player.y - 26, vy: -520, enemy: false });
}

function spawnEnemy(): void {
  if (spawnedEnemies === 0) {
    spawnedEnemies += 1;
    enemies.push({
      x: WIDTH / 2, y: -34, vx: 0, vy: 120, hp: 1, kind: "ship", phase: 0,
    });
    return;
  }
  spawnedEnemies += 1;
  const meteor = Math.random() < 0.32;
  enemies.push({
    x: 40 + Math.random() * (WIDTH - 80), y: -34,
    vx: (Math.random() - 0.5) * (50 + level * 4),
    vy: (meteor ? 105 : 82) + level * 9 + Math.random() * 45,
    hp: meteor ? 2 + Math.floor(level / 4) : 1 + Math.floor(level / 6),
    kind: meteor ? "meteor" : "ship", phase: Math.random() * Math.PI * 2,
  });
}

function resolveCollisions(): void {
  const deadBullets = new Set<Bullet>();
  const deadEnemies = new Set<Enemy>();
  for (const bullet of bullets) {
    if (bullet.enemy) {
      if (distance(bullet, player) < 22) {
        deadBullets.add(bullet);
        damagePlayer(bullet.x, bullet.y);
      }
      continue;
    }
    for (const enemy of enemies) {
      if (distance(bullet, enemy) > (enemy.kind === "meteor" ? 27 : 24)) continue;
      deadBullets.add(bullet);
      enemy.hp -= 1;
      burst(bullet.x, bullet.y, 4, "#8ff2d5");
      if (enemy.hp <= 0) {
        deadEnemies.add(enemy);
        score += enemy.kind === "meteor" ? 180 : 120;
        if (score > highScore) {
          highScore = score;
          scheduleHighScorePersist();
        }
        burst(enemy.x, enemy.y, 18, enemy.kind === "meteor" ? "#e5b671" : "#ef6f63");
      }
      break;
    }
  }
  for (const enemy of enemies) {
    if (!deadEnemies.has(enemy) && distance(enemy, player) < (enemy.kind === "meteor" ? 42 : 38)) {
      deadEnemies.add(enemy);
      damagePlayer(enemy.x, enemy.y);
    }
  }
  bullets = bullets.filter((bullet) => !deadBullets.has(bullet));
  enemies = enemies.filter((enemy) => !deadEnemies.has(enemy));
}

function damagePlayer(x: number, y: number): void {
  if (phase === "game-over" || invulnerability > 0) return;
  lives -= 1;
  invulnerability = 1.1;
  burst(x, y, 22, "#f2d06b");
  player.x = WIDTH / 2;
  player.y = HEIGHT - 72;
  bullets = bullets.filter((bullet) => !bullet.enemy);
  if (lives <= 0) {
    phase = "game-over";
    syncCanvasAccessibility(true);
    void persistHighScore();
  }
}

async function persistHighScore(): Promise<void> {
  clearScorePersistTimer();
  if (scorePersistInFlight) {
    await scorePersistInFlight;
    if (highScore > savedScore) await persistHighScore();
    return;
  }
  if (highScore <= savedScore) return;
  const scoreToSave = highScore;
  scorePersistInFlight = (async () => {
    try {
      const response = await bridge.call<PluginMethodResult<{ score: number }>>("game.highScore.save", { score: scoreToSave });
      savedScore = Math.max(savedScore, response.data.score, scoreToSave);
      highScore = Math.max(highScore, response.data.score);
    } finally {
      scorePersistInFlight = undefined;
    }
  })();
  try {
    await scorePersistInFlight;
  } catch {
    savedScore = Math.min(savedScore, scoreToSave - 1);
  }
}

function scheduleHighScorePersist(): void {
  clearScorePersistTimer();
  scorePersistTimer = setTimeout(() => {
    scorePersistTimer = undefined;
    void persistHighScore();
  }, 900);
}

function clearScorePersistTimer(): void {
  if (scorePersistTimer !== undefined) clearTimeout(scorePersistTimer);
  scorePersistTimer = undefined;
}

function restart(autoStart: boolean): void {
  bullets = [];
  enemies = [];
  particles = [];
  score = 0;
  lives = 3;
  level = 1;
  spawnTimer = 0.5;
  spawnedEnemies = 0;
  phase = autoStart ? "running" : "ready";
  player.x = WIDTH / 2;
  player.y = HEIGHT - 72;
  player.cooldown = 0;
  invulnerability = 0;
}

function startMission(): void {
  if (phase === "game-over") restart(true);
  else phase = "running";
  syncCanvasAccessibility(true);
}

function handleInput(event: PluginCanvasInputEvent): void {
  if (event.type === "key") {
    inputMode = "keyboard";
    pointerTarget = undefined;
    pointerDown = false;
    if (event.event === "keydown") keys.add(event.code);
    else keys.delete(event.code);
    if (event.event === "keydown" && (event.code === "Enter" || event.code === "Space") && (phase === "ready" || phase === "game-over")) {
      startMission();
      return;
    }
    if (event.event === "keydown" && event.code === "KeyP") {
      if (phase === "running") phase = "paused";
      else if (phase === "paused") phase = "running";
      syncCanvasAccessibility(true);
    }
    return;
  }
  if (event.type === "blur") {
    keys.clear();
    pointerDown = false;
    if (phase === "running") phase = "paused";
    syncCanvasAccessibility(true);
    return;
  }
  if (event.type === "resize") {
    configureWorld(event.cssWidth, event.cssHeight, event.devicePixelRatio);
    return;
  }
  if (event.type !== "pointer") return;
  if (event.event === "pointermove" && event.buttons === 0) return;
  inputMode = "pointer";
  pointerTarget = {
    x: clamp((event.x - renderOffsetX) / Math.max(renderScale, 0.001), 0, WIDTH),
    y: clamp((event.y - renderOffsetY) / Math.max(renderScale, 0.001), 0, HEIGHT),
  };
  if (event.event === "pointerdown" && (phase === "ready" || phase === "game-over")) {
    startMission();
    pointerDown = false;
    return;
  }
  pointerDown = event.event === "pointerdown" || (event.event === "pointermove" && event.buttons > 0);
  if (event.event === "pointerup" || event.event === "pointercancel") pointerDown = false;
}

function draw(time: number): void {
  context.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  context.fillStyle = "#02060b";
  context.fillRect(0, 0, cssWidth, cssHeight);
  drawViewportBackground();
  context.save();
  context.translate(renderOffsetX, renderOffsetY);
  context.scale(renderScale, renderScale);
  const gradient = context.createLinearGradient(0, 0, 0, HEIGHT);
  gradient.addColorStop(0, "#07192b");
  gradient.addColorStop(0.58, "#07101e");
  gradient.addColorStop(1, "#02050a");
  context.fillStyle = gradient;
  context.fillRect(0, 0, WIDTH, HEIGHT);
  drawBackground();
  drawStars(time);
  drawFlightGrid(time);
  drawEngineTrail(time);
  drawImage("player", player.x, player.y, 56, 56, 0);
  if (invulnerability > 0) drawShield(time);
  for (const enemy of enemies) drawImage(enemy.kind === "ship" ? "enemy" : "meteor", enemy.x, enemy.y, enemy.kind === "ship" ? 48 : 54, enemy.kind === "ship" ? 48 : 54, enemy.phase * 0.3);
  for (const bullet of bullets) {
    if (bullet.enemy) {
      context.fillStyle = "#ff6d62";
      context.fillRect(bullet.x - 2, bullet.y - 7, 4, 14);
    } else drawImage("laser", bullet.x, bullet.y, 11, 28, 0);
  }
  for (const particle of particles) {
    context.globalAlpha = clamp(particle.life * 2, 0, 1);
    context.fillStyle = particle.color;
    context.fillRect(particle.x - 2, particle.y - 2, 4, 4);
  }
  context.globalAlpha = 1;
  if (phase !== "running") drawOverlay();
  drawHUD();
  context.restore();
}

function drawViewportBackground(): void {
  const image = images.get("background");
  if (!image) return;
  const imageRatio = image.width / image.height;
  const viewportRatio = cssWidth / cssHeight;
  const sourceWidth = imageRatio > viewportRatio ? image.height * viewportRatio : image.width;
  const sourceHeight = imageRatio > viewportRatio ? image.height : image.width / viewportRatio;
  const sourceX = (image.width - sourceWidth) / 2;
  const sourceY = (image.height - sourceHeight) / 2;
  context.save();
  context.globalAlpha = 0.5;
  context.drawImage(image, sourceX, sourceY, sourceWidth, sourceHeight, 0, 0, cssWidth, cssHeight);
  context.fillStyle = "rgba(1, 5, 12, .46)";
  context.fillRect(0, 0, cssWidth, cssHeight);
  context.restore();
}

function drawBackground(): void {
  const image = images.get("background");
  if (!image) return;
  const imageRatio = image.width / image.height;
  const worldRatio = WIDTH / HEIGHT;
  const sourceWidth = imageRatio > worldRatio ? image.height * worldRatio : image.width;
  const sourceHeight = imageRatio > worldRatio ? image.height : image.width / worldRatio;
  const sourceX = (image.width - sourceWidth) / 2;
  const sourceY = (image.height - sourceHeight) / 2;
  context.save();
  context.globalAlpha = 0.72;
  context.drawImage(image, sourceX, sourceY, sourceWidth, sourceHeight, 0, 0, WIDTH, HEIGHT);
  const veil = context.createLinearGradient(0, 0, 0, HEIGHT);
  veil.addColorStop(0, "rgba(2, 10, 20, .08)");
  veil.addColorStop(0.55, "rgba(2, 8, 17, .28)");
  veil.addColorStop(1, "rgba(1, 4, 10, .78)");
  context.fillStyle = veil;
  context.fillRect(0, 0, WIDTH, HEIGHT);
  context.restore();
}

function configureWorld(width: number, height: number, nextDevicePixelRatio: number): void {
  cssWidth = Math.max(1, width);
  cssHeight = Math.max(1, height);
  devicePixelRatio = clamp(nextDevicePixelRatio || 1, 0.5, 4);
  const portrait = height > width * 1.12;
  if (phase === "ready") inputMode = portrait ? "pointer" : "keyboard";
  const nextWidth = portrait ? PORTRAIT_WIDTH : LANDSCAPE_WIDTH;
  const nextHeight = portrait ? PORTRAIT_HEIGHT : LANDSCAPE_HEIGHT;
  if (WIDTH !== nextWidth || HEIGHT !== nextHeight) {
    const previousWidth = WIDTH;
    const previousHeight = HEIGHT;
    WIDTH = nextWidth;
    HEIGHT = nextHeight;
    const scaleX = WIDTH / previousWidth;
    const scaleY = HEIGHT / previousHeight;
    player.x = clamp(player.x * scaleX, 28, WIDTH - 28);
    player.y = clamp(player.y * scaleY, HEIGHT * 0.45, HEIGHT - 30);
    for (const bullet of bullets) {
      bullet.x *= scaleX;
      bullet.y *= scaleY;
    }
    for (const enemy of enemies) {
      enemy.x *= scaleX;
      enemy.y *= scaleY;
    }
    for (const particle of particles) {
      particle.x *= scaleX;
      particle.y *= scaleY;
    }
  }
  if (canvas) {
    canvas.width = Math.max(1, Math.ceil(cssWidth * devicePixelRatio));
    canvas.height = Math.max(1, Math.ceil(cssHeight * devicePixelRatio));
  }
  renderScale = Math.min(cssWidth / WIDTH, cssHeight / HEIGHT);
  renderOffsetX = (cssWidth - WIDTH * renderScale) / 2;
  renderOffsetY = (cssHeight - HEIGHT * renderScale) / 2;
}

function drawStars(time: number): void {
  context.fillStyle = "#bdeeff";
  for (let index = 0; index < 110; index += 1) {
    const x = (index * 109 + 17) % WIDTH;
    const y = (index * 61 + time * (22 + index % 4 * 11)) % HEIGHT;
    const size = index % 13 === 0 ? 2 : 1;
    context.globalAlpha = 0.24 + (index % 5) * 0.13;
    context.fillRect(x, y, size, size);
  }
  context.globalAlpha = 1;
}

function drawFlightGrid(time: number): void {
  const horizon = HEIGHT * 0.7;
  context.save();
  context.globalAlpha = 0.16;
  context.strokeStyle = "#55e8ff";
  context.lineWidth = 1;
  for (let index = 0; index < 8; index += 1) {
    const ratio = index / 8;
    const y = horizon + ratio * ratio * (HEIGHT - horizon) + ((time * 22) % 18);
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(WIDTH, y);
    context.stroke();
  }
  for (let x = -WIDTH; x <= WIDTH * 2; x += 96) {
    context.beginPath();
    context.moveTo(WIDTH / 2, horizon);
    context.lineTo(x, HEIGHT);
    context.stroke();
  }
  context.restore();
}

function drawEngineTrail(time: number): void {
  context.save();
  for (let index = 0; index < 6; index += 1) {
    const pulse = 5 + ((time * 46 + index * 7) % 18);
    context.globalAlpha = Math.max(0.08, 0.58 - index * 0.08);
    context.fillStyle = index % 2 === 0 ? "#55e8ff" : "#f2d06b";
    context.fillRect(player.x - 2, player.y + 24 + index * 7, 4, pulse);
  }
  context.restore();
}

function drawShield(time: number): void {
  context.save();
  context.globalAlpha = 0.42 + Math.sin(time * 18) * 0.16;
  context.strokeStyle = "#55e8ff";
  context.lineWidth = 3;
  context.beginPath();
  context.arc(player.x, player.y, 38, 0, Math.PI * 2);
  context.stroke();
  context.restore();
}

function drawHUD(): void {
  if (WIDTH === PORTRAIT_WIDTH) {
    drawPortraitHUD();
    return;
  }
  const missionProgress = (score % 1200) / 1200;
  context.fillStyle = "rgba(4, 11, 20, .88)";
  context.fillRect(18, 16, 360, 88);
  context.fillStyle = "#55e8ff";
  context.fillRect(18, 16, 5, 88);
  context.strokeStyle = "#355269";
  context.strokeRect(18.5, 16.5, 359, 87);
  context.fillStyle = "#88a9bc";
  context.font = "700 9px system-ui";
  context.fillText("MISSION PROGRESS", 36, 34);
  context.fillStyle = "#20384a";
  context.fillRect(36, 42, 142, 4);
  context.fillStyle = "#55e8ff";
  context.fillRect(36, 42, Math.max(5, 142 * missionProgress), 4);
  context.fillStyle = "#eff9ff";
  context.font = "850 20px system-ui";
  context.fillText(`SCORE ${String(score).padStart(6, "0")}`, 36, 82);
  context.strokeStyle = "#243d50";
  context.beginPath();
  context.moveTo(210.5, 30);
  context.lineTo(210.5, 91);
  context.stroke();
  context.fillStyle = "#91aabd";
  context.font = "700 10px system-ui";
  context.fillText(`HIGH ${String(highScore).padStart(6, "0")}`, 230, 48);
  context.fillText(`WAVE ${String(level).padStart(2, "0")}`, 230, 76);
  context.textAlign = "right";
  context.fillStyle = "rgba(4, 11, 20, .88)";
  context.fillRect(WIDTH - 230, 16, 212, 82);
  context.strokeStyle = "#355269";
  context.strokeRect(WIDTH - 229.5, 16.5, 211, 81);
  context.fillStyle = "#8ea6b8";
  context.font = "700 9px system-ui";
  context.fillText("HULL INTEGRITY", WIDTH - 34, 34);
  for (let index = 0; index < 3; index += 1) {
    context.fillStyle = index < lives ? "#ff5a67" : "#263545";
    context.fillRect(WIDTH - 122 + index * 30, 43, 22, 9);
  }
  context.fillStyle = "#55e8ff";
  context.font = "750 12px ui-monospace, monospace";
  context.fillText(`FPS ${Math.round(fps)}`, WIDTH - 34, 77);
  context.textAlign = "left";
}

function drawPortraitHUD(): void {
  const missionProgress = (score % 1200) / 1200;
  context.fillStyle = "rgba(5, 10, 18, .9)";
  context.fillRect(14, 14, WIDTH - 28, 104);
  context.strokeStyle = "#30475d";
  context.lineWidth = 1;
  context.strokeRect(14.5, 14.5, WIDTH - 29, 103);
  context.fillStyle = "#55e8ff";
  context.fillRect(14, 14, 5, 104);

  context.fillStyle = "#8ca8b9";
  context.font = "700 11px system-ui";
  context.fillText("MISSION PROGRESS", 34, 36);
  context.fillStyle = "#20384a";
  context.fillRect(34, 44, 136, 5);
  context.fillStyle = "#55e8ff";
  context.fillRect(34, 44, Math.max(6, 136 * missionProgress), 5);
  context.fillStyle = "#eff9ff";
  context.font = "800 24px system-ui";
  context.fillText(`SCORE ${String(score).padStart(6, "0")}`, 34, 79);
  context.fillStyle = "#91a8b8";
  context.font = "650 14px system-ui";
  context.fillText(`HIGH ${String(highScore).padStart(6, "0")}  WAVE ${String(level).padStart(2, "0")}`, 34, 104);

  context.textAlign = "right";
  context.fillStyle = "#55e8ff";
  context.font = "700 15px ui-monospace, monospace";
  context.fillText(`FPS ${Math.round(fps)}`, WIDTH - 28, 104);
  for (let index = 0; index < 3; index += 1) {
    context.fillStyle = index < lives ? "#ff5a67" : "#263545";
    context.fillRect(WIDTH - 106 + index * 25, 42, 18, 10);
  }
  context.textAlign = "left";
}

function drawOverlay(): void {
  context.fillStyle = phase === "paused" ? "rgba(2, 5, 11, .66)" : "rgba(2, 5, 11, .54)";
  context.fillRect(0, 0, WIDTH, HEIGHT);
  const launch = phase === "ready";
  const ended = phase === "game-over";
  const portrait = WIDTH === PORTRAIT_WIDTH;
  const primaryAction = inputMode === "keyboard"
    ? launch ? "PRESS ENTER OR CLICK TO LAUNCH" : ended ? "PRESS ENTER OR CLICK TO FLY AGAIN" : "PRESS P OR CLICK TO RESUME"
    : launch ? "TAP TO LAUNCH" : ended ? "TAP TO FLY AGAIN" : "TAP TO RESUME";
  context.textAlign = "center";
  context.fillStyle = "#8aaabd";
  context.font = `750 ${portrait ? 12 : 11}px system-ui`;
  context.fillText("FLOE ARCADE / SECTOR 07", WIDTH / 2, HEIGHT / 2 - 122);
  context.fillStyle = ended ? "#ff5a67" : "#55e8ff";
  context.fillRect(WIDTH / 2 - (portrait ? 86 : 98), HEIGHT / 2 - 96, portrait ? 172 : 196, 4);
  context.fillStyle = "#f4fbff";
  context.font = `900 ${portrait ? 44 : 48}px system-ui`;
  context.fillText(launch ? "SKY STRIKE" : ended ? "FLIGHT ENDED" : "FLIGHT PAUSED", WIDTH / 2, HEIGHT / 2 - 42);
  context.fillStyle = ended ? "#ff5a67" : "#55e8ff";
  context.font = `800 ${portrait ? 15 : 14}px system-ui`;
  context.fillText(launch ? "MISSION 07 / CLEAR THE SKY" : ended ? `FINAL SCORE ${String(score).padStart(6, "0")}` : "FLIGHT SYSTEMS HOLDING", WIDTH / 2, HEIGHT / 2 - 5);
  context.fillStyle = "#f4fbff";
  context.font = `800 ${portrait ? 17 : 15}px system-ui`;
  context.fillText(primaryAction, WIDTH / 2, HEIGHT / 2 + 48);
  context.fillStyle = "#91a8b8";
  context.font = `${portrait ? 14 : 12}px system-ui`;
  context.fillText(controlHint(), WIDTH / 2, HEIGHT / 2 + 82);
  context.textAlign = "left";
}

function controlHint(): string {
  if (inputMode === "keyboard") return phase === "paused" ? "PRESS P OR SPACE TO RESUME" : "WASD / ARROWS TO FLY / SPACE TO FIRE";
  return phase === "paused" ? "TAP TO RESUME" : "DRAG TO FLY / HOLD TO FIRE";
}

function syncCanvasAccessibility(force: boolean, now = performance.now()): void {
  if (!canvas || disposed || (!force && now - lastAccessibilityUpdateAt < 500)) return;
  const finalScore = phase === "game-over" ? score : 0;
  const signature = `${phase}:${lives}:${inputMode}:${finalScore}`;
  if (!force && signature === lastAccessibilitySignature) return;
  if (accessibilityUpdateInFlight) return;
  lastAccessibilityUpdateAt = now;
  lastAccessibilitySignature = signature;
  const label = "Sky Strike game canvas";
  const scoreSummary = phase === "game-over" ? ` Final score ${score}.` : "";
  const controls = inputMode === "keyboard"
    ? "Use WASD or arrow keys to fly, Space to fire, and P to pause or resume."
    : "Drag to fly, hold to fire, and use the play button to pause or resume.";
  const description = `${phaseLabel()}. ${lives} ${lives === 1 ? "life" : "lives"} remaining.${scoreSummary} ${controls}`;
  const update = bridge.updateCanvasAccessibility("playfield", { label, description }).catch(() => undefined).finally(() => {
    if (accessibilityUpdateInFlight === update) accessibilityUpdateInFlight = undefined;
  });
  accessibilityUpdateInFlight = update;
}

function phaseLabel(): string {
  if (phase === "ready") return "Ready to launch";
  if (phase === "running") return "Mission running";
  if (phase === "paused") return "Mission paused";
  return "Mission over";
}

function drawImage(name: string, x: number, y: number, width: number, height: number, rotation: number): void {
  const image = images.get(name);
  if (!image) return;
  context.save();
  context.translate(x, y);
  context.rotate(rotation);
  context.drawImage(image, -width / 2, -height / 2, width, height);
  context.restore();
}

function burst(x: number, y: number, count: number, color: string): void {
  for (let index = 0; index < count; index += 1) {
    const angle = Math.random() * Math.PI * 2;
    const speed = 35 + Math.random() * 150;
    particles.push({ x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, life: 0.25 + Math.random() * 0.45, color });
  }
}

function distance(a: Vec, b: Vec): number { return Math.hypot(a.x - b.x, a.y - b.y); }
function clamp(value: number, min: number, max: number): number { return Math.min(max, Math.max(min, value)); }
