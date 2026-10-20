import { PluginBridgeClient, type PluginUIVNode } from "../../../packages/redevplugin-ui/src/plugin.js";

const bridge = new PluginBridgeClient();
type Sample = { pixel: number[]; width: number; height: number; error: number; restored: number };
const samples: Record<string, Sample> = {};
const checks: Record<string, boolean> = {};
let failure = "";
let lifecycle = "ready";
const contexts = new Map<string, WebGLRenderingContext | WebGL2RenderingContext>();
const recovery = new Map<string, WEBGL_lose_context>();
const canvases = new Map<string, OffscreenCanvas>();

function tree(): PluginUIVNode {
  return { type: "element", key: "root", tag: "main", children: [
    ...["webgl", "webgl2"].map((id): PluginUIVNode => ({
      type: "element", key: id, tag: "canvas",
      attributes: { id, width: 64, height: 64, "data-redevplugin-canvas": id }, children: [],
    })),
    ...["lose", "restore"].map((action): PluginUIVNode => ({
      type: "element", key: action, tag: "button",
      attributes: { id: action, type: "button", "data-redevplugin-action": action },
      children: [{ type: "text", key: action + "-label", text: action }],
    })),
    { type: "element", key: "state", tag: "pre", attributes: { id: "webgl-state" },
      children: [{ type: "text", key: "state-text", text: JSON.stringify({ samples, checks, failure, lifecycle }) }] },
  ] };
}

function paint(id: string): void {
  const gl = contexts.get(id)!;
  const modern = id === "webgl2";
  const shader = (type: number, source: string) => {
    const value = gl.createShader(type);
    if (!value) throw new Error("shader allocation failed");
    gl.shaderSource(value, source);
    gl.compileShader(value);
    if (!gl.getShaderParameter(value, gl.COMPILE_STATUS)) throw new Error(String(gl.getShaderInfoLog(value)));
    return value;
  };
  const vertex = shader(gl.VERTEX_SHADER, modern
    ? "#version 300 es\n in vec2 position; void main(){gl_Position=vec4(position,0.,1.);}"
    : "attribute vec2 position; void main(){gl_Position=vec4(position,0.,1.);}");
  const color = id === "webgl" ? "vec4(1.,0.,0.,1.)" : "vec4(0.,1.,0.,1.)";
  const fragment = shader(gl.FRAGMENT_SHADER, modern
    ? "#version 300 es\n precision mediump float; out vec4 color; void main(){color=" + color + ";}"
    : "precision mediump float; void main(){gl_FragColor=" + color + ";}");
  const program = gl.createProgram();
  const buffer = gl.createBuffer();
  if (!program || !buffer) throw new Error("graphics resource allocation failed");
  gl.attachShader(program, vertex); gl.attachShader(program, fragment);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(String(gl.getProgramInfoLog(program)));
  gl.useProgram(program);
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const position = gl.getAttribLocation(program, "position");
  gl.enableVertexAttribArray(position);
  gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
  gl.viewport(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight);
  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLES, 0, 3);
  const pixel = new Uint8Array(4);
  gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
  gl.disableVertexAttribArray(position);
  gl.bindBuffer(gl.ARRAY_BUFFER, null); gl.useProgram(null);
  gl.deleteBuffer(buffer); gl.deleteProgram(program);
  gl.deleteShader(vertex); gl.deleteShader(fragment);
  samples[id] = { pixel: [...pixel], width: gl.drawingBufferWidth, height: gl.drawingBufferHeight, error: gl.getError(), restored: samples[id]?.restored ?? 0 };
}

function rejects(action: () => unknown): boolean {
  try { action(); return false; } catch { return true; }
}

for (const action of ["lose", "restore"]) bridge.onAction(action, () => {
  for (const extension of recovery.values()) {
    if (action === "lose") extension.loseContext();
    else extension.restoreContext();
  }
});

bridge.onLifecycle(async (event) => {
  lifecycle = event.type;
  if (event.type === "dispose") {
    for (const extension of recovery.values()) extension.loseContext();
    recovery.clear();
    contexts.clear();
    canvases.clear();
  } else await bridge.render(tree());
});

void (async () => {
  try {
    await bridge.ready();
    await bridge.render(tree());
    for (const id of ["webgl", "webgl2"] as const) {
      const surface = await bridge.openCanvas(id);
      const canvas = surface.canvas;
      canvases.set(id, canvas);
      canvas.width = 64;
      canvas.height = 64;
      checks[id + "UnsupportedContext"] = rejects(() => canvas.getContext("webgpu" as "2d"));
      checks[id + "SealedContext"] = rejects(() => Object.defineProperty(Object.getPrototypeOf(canvas), "getContext", { value() { return null; } }));
      checks[id + "DimensionBudget"] = rejects(() => { canvas.width = 4097; }) && canvas.width === 64;
      const gl = canvas.getContext(id, { preserveDrawingBuffer: true }) as WebGLRenderingContext | WebGL2RenderingContext | null;
      if (!gl) throw new Error(id + " context unavailable");
      contexts.set(id, gl);
      const extension = gl.getExtension("WEBGL_lose_context");
      if (!extension) throw new Error("context recovery extension unavailable");
      recovery.set(id, extension);
      canvas.addEventListener("webglcontextlost", (event) => {
        event.preventDefault();
        checks[id + "Lost"] = true;
        void bridge.render(tree());
      });
      canvas.addEventListener("webglcontextrestored", () => {
        samples[id].restored += 1;
        paint(id);
        void bridge.render(tree());
      });
      bridge.onCanvasInput(id, (event) => {
        if (event.type !== "resize") return;
        canvas.width = 1;
        canvas.height = Math.max(1, Math.round(event.cssHeight * event.devicePixelRatio));
        canvas.width = Math.max(1, Math.round(event.cssWidth * event.devicePixelRatio));
        paint(id);
        void bridge.render(tree());
      });
      paint(id);
    }
    checks.constructorHidden = typeof OffscreenCanvas === "undefined";
    checks.networkBlocked = rejects(() => fetch("https://example.invalid/"));
    const first = canvases.get("webgl")!;
    first.width = 4096;
    first.height = 4095;
    checks.aggregateBudget = rejects(() => { first.height = 4096; }) && first.height === 4095;
    first.width = 64; first.height = 64;
    paint("webgl"); paint("webgl2");
  } catch (error) { failure = error instanceof Error ? error.message : String(error); }
  await bridge.render(tree());
})();
