import { PluginBridgeClient, type PluginCanvasSurface, type PluginUIVNode } from "../../../packages/redevplugin-ui/src/plugin.js";

const bridge = new PluginBridgeClient({ timeoutMs: 1000 });
const canvases = new Map<string, PluginCanvasSurface>();
const samples = new Map<string, { width: number; height: number; dpr: number; pixelsWidth: number; pixelsHeight: number; updates: number }>();
let lifecycle = "ready";
let failure = "";

function tree(): PluginUIVNode {
  return {
    type: "element", key: "root", tag: "main", children: [
      ...["first", "second"].map((id): PluginUIVNode => ({
        type: "element", key: id, tag: "canvas",
        attributes: { id, width: 300, height: 150, "data-redevplugin-canvas": id }, children: [],
      })),
      { type: "element", key: "state", tag: "pre", attributes: { id: "canvas-state" }, children: [
        { type: "text", key: "state-text", text: JSON.stringify({ lifecycle, failure, canvases: Object.fromEntries(samples) }) },
      ] },
    ],
  };
}

function paint(surface: PluginCanvasSurface): void {
  const { canvas, canvasId, cssWidth, cssHeight, devicePixelRatio } = surface;
  // Release old backing dimensions before applying the new pair within the aggregate budget.
  canvas.width = 1;
  canvas.height = Math.max(1, Math.round(cssHeight * devicePixelRatio));
  canvas.width = Math.max(1, Math.round(cssWidth * devicePixelRatio));
  const context = canvas.getContext("2d");
  if (!context) throw new Error("canvas context unavailable");
  context.fillStyle = canvasId === "first" ? "#008866" : "#cc3355";
  context.fillRect(0, 0, canvas.width, canvas.height);
  samples.set(canvasId, {
    width: cssWidth, height: cssHeight, dpr: devicePixelRatio,
    pixelsWidth: canvas.width, pixelsHeight: canvas.height,
    updates: (samples.get(canvasId)?.updates ?? 0) + 1,
  });
  void bridge.render(tree());
}

for (const id of ["first", "second"]) bridge.onCanvasInput(id, (event) => {
  if (event.type !== "resize") return;
  const previous = canvases.get(id);
  if (!previous) return;
  const next = { ...previous, cssWidth: event.cssWidth, cssHeight: event.cssHeight, devicePixelRatio: event.devicePixelRatio };
  canvases.set(id, next);
  paint(next);
});

bridge.onLifecycle(async (event) => {
  lifecycle = event.type;
  if (event.type !== "dispose") await bridge.render(tree());
});

void (async () => {
  await bridge.ready();
  await bridge.render(tree());
  await Promise.all(["first", "second"].map(async (id) => {
    try {
      const surface = await bridge.openCanvas(id);
      canvases.set(id, surface);
      paint(surface);
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
      await bridge.render(tree());
    }
  }));
})();
