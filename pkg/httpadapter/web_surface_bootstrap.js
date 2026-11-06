(() => {
  "use strict";
  const documentID = "document_" + crypto.randomUUID().replaceAll("-", "");
  const prefix = "/_redevplugin_web/";
  const nativeFetch = globalThis.fetch.bind(globalThis);
  const controller = new AbortController();
  let parentOrigin, port, frameGeneration, surfaceHandle, context;
  let initialized = false, stopped = false, ready = false, claimed = false;
  let appPeer, appPort, sequence = 0, contextMenu = false;
  const send = (message, transfer) => { if (!stopped) port?.postMessage(message, transfer); };
  const fetchResource = (path, init = {}) => nativeFetch(path, { ...init, credentials: "include", cache: "no-store", signal: controller.signal });
  const fail = (error) => {
    if (stopped) return;
    const message = String(error.message || error).slice(0, 2048);
    send({ type: "redevplugin.surface.error", error: message });
    if (parentOrigin) parent.postMessage({ type: "redevplugin.surface.entry_error", error: message }, parentOrigin);
    stopped = true;
    controller.abort();
    port?.close();
    appPeer?.close();
    clearTimeout(deadline);
    document.body.textContent = message;
  };
  const deadline = setTimeout(() => fail(new Error("Application opening timed out")), 10000);
  const interaction = (kind, extra = {}) => {
    if (!ready) return;
    send({ type: "redevplugin.surface.interaction", frame_generation_id: frameGeneration, surface_handle: surfaceHandle,
      sequence: ++sequence, kind, target_key: null, action: kind === "action" ? "application.action" : null,
      local_scroll: false, selection_active: false, ...extra });
  };
  const visualTarget = element => {
    const width = Math.max(1, innerWidth), height = Math.max(1, innerHeight);
    const unit = n => Math.max(0, Math.min(1, n));
    const rect = element.getBoundingClientRect();
    const path = [];
    for (let node = element; node instanceof Element && path.length < 12; node = node.parentElement) {
      let position = 1;
      for (let sibling = node.previousElementSibling; sibling; sibling = sibling.previousElementSibling) if (sibling.localName === node.localName) position++;
      path.unshift(node.localName + ":nth-of-type(" + position + ")");
    }
    // Never copy form values, editable text, HTML, attributes, URLs, or document-wide state.
    let text = "", visited = 0;
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node && text.length < 240 && visited++ < 128; node = walker.nextNode()) {
      if (!node.parentElement?.closest("input,textarea,select,[contenteditable],script,style,[hidden]")) text += " " + node.textContent.slice(0, 240);
    }
    const x = unit(rect.left / width), y = unit(rect.top / height);
    return { tag: element.localName.slice(0, 64), role: (element.getAttribute("role") || "").slice(0, 64),
      text: text.replace(/\s+/g, " ").trim().slice(0, 240), selector: path.join(" > ").slice(0, 1024),
      bounds: { x, y, width: Math.max(0, unit(rect.right / width) - x), height: Math.max(0, unit(rect.bottom / height) - y) } };
  };
  const observe = () => {
    document.addEventListener("contextmenu", e => {
      if (!contextMenu || !ready || !e.isTrusted || !(e.target instanceof Element)) return;
      e.preventDefault(); e.stopImmediatePropagation();
      const target = visualTarget(e.target);
      send({ type: "redevplugin.surface.context_menu", frame_generation_id: frameGeneration, surface_handle: surfaceHandle,
        sequence: ++sequence, point: { x: Math.max(0, Math.min(1, e.clientX / Math.max(1, innerWidth))), y: Math.max(0, Math.min(1, e.clientY / Math.max(1, innerHeight))) },
        viewport: { width: innerWidth, height: innerHeight }, target });
    }, true);
    document.addEventListener("pointerdown", e => { if (e.isTrusted) interaction("activation"); }, true);
    document.addEventListener("focusin", e => { if (e.isTrusted) interaction("focus"); }, true);
    document.addEventListener("click", e => { if (e.isTrusted) interaction("action"); }, true);
    document.addEventListener("selectionchange", () => interaction("text-selection", { selection_active: !getSelection()?.isCollapsed }));
    document.addEventListener("wheel", e => {
      if (!e.isTrusted) return;
      let local = false;
      for (let n = e.target; n instanceof Element; n = n.parentElement) {
        if (n.scrollHeight > n.clientHeight && /auto|scroll/.test(getComputedStyle(n).overflowY)) { local = true; break; }
      }
      interaction("wheel", { local_scroll: local });
    }, { capture: true, passive: true });
    addEventListener("pagehide", () => {
      send({ type: "redevplugin.surface.navigation", frame_generation_id: frameGeneration });
      stopped = true;
      controller.abort();
      port?.close();
      appPeer?.close();
    }, { once: true });
  };
  const applicationMessages = new Set([
    "redevplugin.bridge.methods", "redevplugin.bridge.method_result",
    "redevplugin.bridge.call", "redevplugin.bridge.cancel", "redevplugin.bridge.execution.cancel",
    "redevplugin.bridge.execution.query", "redevplugin.bridge.execution.events", "redevplugin.bridge.close_response",
  ]);
  const start = async message => {
    if (stopped || initialized || message.frame_generation_id !== frameGeneration) return;
    initialized = true; surfaceHandle = message.surface_handle; context = message.context; contextMenu = message.context_menu === true;
    const channel = new MessageChannel(); appPeer = channel.port1; appPort = channel.port2;
    let contextDelivered;
    const initialContext = new Promise(resolve => { contextDelivered = resolve; });
    appPeer.onmessage = e => {
      const value = e.data;
      if (value?.type === "redevplugin.bridge.client_ready") {
        if (context) {
          // The SDK has registered its listener before client_ready. Observe the
          // same delivery after it, so synchronous context-driven mounting runs
          // before the parent reveals this document. No paint or RAF is needed.
          const revision = context.revision;
          const delivered = event => {
            if (event.data?.type !== "redevplugin.bridge.context" || !(event.data.context?.revision >= revision)) return;
            appPort.removeEventListener("message", delivered);
            contextDelivered();
          };
          appPort.addEventListener("message", delivered, { signal: controller.signal });
          appPeer.postMessage({ type: "redevplugin.bridge.context", context });
        }
        if (ready) appPeer.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
      } else if (value?.type === "redevplugin.ui.file.export") {
        send({ ...value, type: "redevplugin.surface.file.export", frame_generation_id: frameGeneration, surface_handle: surfaceHandle }, [value.content]);
      } else if (value?.type === "redevplugin.bridge.file_io") {
        send({ ...value, type: "redevplugin.surface.file_io", frame_generation_id: frameGeneration, surface_handle: surfaceHandle });
      } else if (value?.type === "redevplugin.bridge.lifecycle_ack") {
        send({ type: "redevplugin.surface.quiesce_ack", quiesce_id: value.quiesce_id });
      } else if (applicationMessages.has(value?.type)) send(value);
    };
    Object.defineProperty(globalThis, "__redevpluginWebBridge", {
      value: Object.freeze({ claim() { if (claimed) return; claimed = true; return { surfaceHandle, port: appPort }; } }),
      writable: false, configurable: false,
    });
    const response = await fetchResource(prefix + "document?path=" + encodeURIComponent(new URL(message.entry_path, location.origin).pathname));
    if (!response.ok) throw new Error("Application document unavailable");
    const html = await response.text();
    if (stopped) return;
    history.replaceState(null, "", message.entry_path);
    document.open();
    // document.write may leave readyState at the old document's complete value
    // while external modules are pending. Subscribe to this parser's event
    // before writing; inspecting readyState can expose an uninitialized page.
    const loaded = new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, { once: true, signal: controller.signal }));
    document.write(html); document.close();
    observe();
    await loaded;
    if (claimed && context) await initialContext;
    if (stopped) return;
    clearTimeout(deadline);
    send({ type: "redevplugin.surface.app_ready", frame_generation_id: frameGeneration });
  };
  const connect = event => {
    if (stopped || port || event.source !== parent || event.origin !== parentOrigin || event.data?.type !== "redevplugin.surface.port" || event.data.document_id !== documentID || event.ports.length !== 1) return;
    frameGeneration = event.data.frame_generation_id; port = event.ports[0];
    removeEventListener("message", connect);
    port.onmessage = e => {
      const m = e.data;
      if (m?.type === "redevplugin.surface.initialize") { void start(m).catch(fail); return; }
      if (m?.type === "redevplugin.surface.context") { context = m.context; appPeer?.postMessage({ type: "redevplugin.bridge.context", context }); return; }
      if (m?.type === "redevplugin.bridge.lifecycle" && m.event?.type === "ready") ready = true;
      if (m?.type === "redevplugin.bridge.lifecycle" && m.quiesce_id && !claimed) {
        send({ type: "redevplugin.surface.quiesce_ack", quiesce_id: m.quiesce_id }); return;
      }
      if (m?.type === "redevplugin.bridge.close_request" && !claimed) {
        send({ type: "redevplugin.bridge.close_response", close_id: m.close_id, allow: true }); return;
      }
      appPeer?.postMessage(m);
      if (m?.type === "redevplugin.bridge.lifecycle" && m.event?.type === "dispose" && !m.quiesce_id) {
        stopped = true; controller.abort(); clearTimeout(deadline); port.close(); appPeer?.close();
      }
    };
    port.start();
    send({ type: "redevplugin.surface.port_ack", frame_generation_id: frameGeneration });
  };
  addEventListener("message", connect);
  void (async () => {
    const initial = location.pathname === prefix + "bootstrap";
    const token = location.hash.slice(1);
    const applicationPath = location.pathname + location.search + location.hash;
    if (initial) history.replaceState(null, "", location.pathname);
    if (initial && !/^[a-f0-9]{64}$/.test(token)) throw new Error("Reopen this application from its host");
    const entry = initial
      ? await fetchResource(prefix + "enter", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) })
      : await fetchResource(prefix + "resume");
    if (!entry.ok) throw new Error("Application entry expired");
    const session = await entry.json(); parentOrigin = session.parent_origin;
    const entryPath = initial ? session.entry_path : applicationPath;
    const probe = async () => {
      const response = await fetchResource(prefix + "probe");
      if (!response.ok || await response.text() !== "redevplugin-web-boundary") throw new Error("Application connection unavailable");
    };
    await probe();
    let blocked = false;
    try { await fetchResource(prefix + "probe-redirect"); } catch { blocked = true; }
    await probe();
    if (!blocked) throw new Error("This browser cannot isolate application network access. Update your browser or Redeven Desktop.");
    if (!stopped) parent.postMessage({ type: "redevplugin.surface.entry_ready", entry_path: entryPath, document_id: documentID }, parentOrigin);
  })().catch(fail);
})();
