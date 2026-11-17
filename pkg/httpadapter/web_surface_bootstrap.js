(() => {
  "use strict";
  const documentID = "document_" + crypto.randomUUID().replaceAll("-", "");
  const prefix = "/_redevplugin_web/";
  const nativeFetch = globalThis.fetch.bind(globalThis);
  const controller = new AbortController();
  let parentOrigin, port, frameGeneration, surfaceHandle, context;
  let initialized = false, stopped = false, ready = false, claimed = false;
  let appPeer, appPort, sequence = 0, contextMenu = false;
  let clientReady = false, explicitPresentation = false, presented = false, parsed = false, deliveredRevision = 0, reportedRevision = -1;
  let presentationAccepted = false;
  const settleInitialMotion = () => {
    // A context subscriber can commit dark tokens while CSS still interpolates
    // from white. Resolve the browser's pending styles once at this boundary;
    // finish only finite, running CSS motion, including delayed pseudo-elements.
    // Script-controlled, paused and infinite animations retain their lifecycle.
    for (const animation of document.getAnimations()) {
      if (!(animation instanceof CSSAnimation || animation instanceof CSSTransition)
        || animation.playState !== "running" || animation.playbackRate === 0
        || !Number.isFinite(animation.effect?.getComputedTiming().endTime)) continue;
      animation.finish();
    }
  };
  const present = () => {
    const revision = context?.revision ?? 0;
    if (stopped || !parsed || (explicitPresentation && !presented) || (claimed && deliveredRevision < revision) || reportedRevision === revision) return;
    if (!presentationAccepted) settleInitialMotion();
    reportedRevision = revision;
    clearTimeout(deadline);
    send({ type: "redevplugin.surface.app_ready", frame_generation_id: frameGeneration, context_revision: revision });
  };
  const deliverContext = () => {
    if (!context || !clientReady) return;
    appPeer.postMessage({ type: "redevplugin.bridge.context", context });
  };
  const lockGetter = Object.getOwnPropertyDescriptor(Document.prototype, "pointerLockElement")?.get;
  const locked = lockGetter ? Function.call.bind(lockGetter, document) : () => null;
  const exitLock = document.exitPointerLock?.bind(document);
  const hasFocus = document.hasFocus.bind(document);
  let pointerLockAllowed = false, pointerGesture = false;
  const releaseLock = () => { pointerGesture = false; if (locked()) exitLock(); };
  const send = (message, transfer) => { if (!stopped) port?.postMessage(message, transfer); };
  const fetchResource = (path, init = {}) => nativeFetch(path, { ...init, credentials: "include", cache: "no-store", signal: controller.signal });
  const fail = (error) => {
    if (stopped) return;
    const message = String(error.message || error).slice(0, 2048);
    send({ type: "redevplugin.surface.error", error: message });
    if (parentOrigin) parent.postMessage({ type: "redevplugin.surface.entry_error", error: message }, parentOrigin);
    releaseLock();
    setSelecting(false);
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
  let selecting = false, selectionRevision = 0, selectionGesture, hoverFrame = 0, hoverEvent, lastHover = 0;
  let selectionCursor;
  const setSelecting = enabled => {
    selecting = enabled;
    // Inspection owns the pointer while application input is intercepted.
    // Keep application styles intact so leaving inspection restores them.
    if (enabled && !selectionCursor) {
      selectionCursor = new CSSStyleSheet();
      selectionCursor.replaceSync(":root, :root *, :root *::before, :root *::after { cursor: default !important; }");
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, selectionCursor];
    } else if (!enabled && selectionCursor) {
      document.adoptedStyleSheets = document.adoptedStyleSheets.filter(sheet => sheet !== selectionCursor);
      selectionCursor = undefined;
    }
  };
  const unit = n => Math.max(0, Math.min(1, n));
  const selectionPoint = e => ({ x: unit(e.clientX / Math.max(1, innerWidth)), y: unit(e.clientY / Math.max(1, innerHeight)) });
  const selectionEvent = (phase, point, target, bounds) => {
    if (!ready || !selecting) return;
    send({ type: "redevplugin.surface.selection", frame_generation_id: frameGeneration, surface_handle: surfaceHandle,
      sequence: ++sequence, revision: selectionRevision, phase, point, viewport: { width: innerWidth, height: innerHeight }, target, bounds });
  };
  const resetSelection = () => {
    cancelAnimationFrame(hoverFrame); hoverFrame = 0; hoverEvent = undefined;
    const gesture = selectionGesture; selectionGesture = undefined;
    if (gesture && document.documentElement.hasPointerCapture(gesture.id)) document.documentElement.releasePointerCapture(gesture.id);
  };
  const selectionAt = e => {
    const point = selectionPoint(e), gesture = selectionGesture;
    if (gesture && Math.hypot(e.clientX - gesture.x, e.clientY - gesture.y) >= 5) gesture.dragged = true;
    if (gesture?.dragged) return { point, target: null, bounds: { x: Math.min(point.x, gesture.point.x), y: Math.min(point.y, gesture.point.y),
      width: Math.abs(point.x - gesture.point.x), height: Math.abs(point.y - gesture.point.y) } };
    const element = gesture?.element ?? document.elementFromPoint(e.clientX, e.clientY);
    const target = element instanceof Element ? visualTarget(element) : null;
    return { point, target, bounds: target?.bounds ?? null };
  };
  const observeSelection = () => {
    const stop = e => { e.preventDefault(); e.stopImmediatePropagation(); };
    const flushHover = now => {
      hoverFrame = 0;
      if (!selecting || !hoverEvent) return;
      // Keep the final pointer position when limiting high-refresh displays.
      if (now - lastHover < 32) { hoverFrame = requestAnimationFrame(flushHover); return; }
      lastHover = now;
      const value = selectionAt(hoverEvent); hoverEvent = undefined;
      selectionEvent("hover", value.point, value.target, value.bounds);
    };
    addEventListener("pointermove", e => {
      if (!selecting || !ready || !e.isTrusted) return;
      stop(e); hoverEvent = e;
      if (!hoverFrame) hoverFrame = requestAnimationFrame(flushHover);
    }, true);
    addEventListener("pointerdown", e => {
      if (!selecting || !ready || !e.isTrusted) return;
      stop(e);
      if (e.button !== 0 || selectionGesture) return;
      const element = document.elementFromPoint(e.clientX, e.clientY);
      selectionGesture = { id: e.pointerId, x: e.clientX, y: e.clientY, point: selectionPoint(e), element, dragged: false };
      document.documentElement.setPointerCapture(e.pointerId);
    }, true);
    addEventListener("pointerup", e => {
      if (!selecting || !ready || !e.isTrusted) return;
      stop(e);
      if (selectionGesture?.id !== e.pointerId) return;
      const value = selectionAt(e); resetSelection();
      if (value.bounds?.width > 0 && value.bounds.height > 0) selectionEvent("select", value.point, value.target, value.bounds);
    }, true);
    const clear = () => { resetSelection(); selectionEvent("hover", { x: 0, y: 0 }, null, null); };
    addEventListener("pointercancel", clear, true);
    addEventListener("blur", clear);
    addEventListener("pointerout", e => { if (!e.relatedTarget) clear(); }, true);
    addEventListener("scroll", clear, true);
    addEventListener("resize", clear);
    for (const name of ["mousedown", "mouseup", "click", "dblclick", "contextmenu", "dragstart"]) {
      addEventListener(name, e => { if (selecting && ready) stop(e); }, true);
    }
    addEventListener("keydown", e => {
      if (!selecting || !ready) return;
      if (e.key === "Tab") return;
      stop(e);
      if (e.key === "Escape") { resetSelection(); selectionEvent("cancel", { x: 0, y: 0 }, null, null); setSelecting(false); }
    }, true);
  };
  const observe = () => {
    observeSelection();
    addEventListener("blur", releaseLock);
    document.addEventListener("visibilitychange", () => { if (document.hidden) releaseLock(); });
    const gesture = e => { if (e.isTrusted && pointerLockAllowed) pointerGesture = true; };
    document.addEventListener("pointerdown", gesture, true);
    document.addEventListener("keydown", e => {
      if (e.isTrusted && e.key === "Escape" && locked()) { e.preventDefault(); e.stopImmediatePropagation(); releaseLock(); return; }
      if (e.key === "Enter" || e.key === " ") gesture(e);
    }, true);
    document.addEventListener("pointerlockchange", () => {
      const value = !!locked();
      if (value && (!pointerLockAllowed || !pointerGesture || !hasFocus() || document.hidden)) { releaseLock(); return; }
      pointerGesture = false;
      send({ type: "redevplugin.surface.pointer_lock_state", frame_generation_id: frameGeneration, surface_handle: surfaceHandle, locked: value });
    });
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
    // Registered after the SDK listener: synchronous context subscribers commit
    // theme changes before the platform acknowledges this exact revision.
    let observingContext = false;
    appPeer.onmessage = e => {
      const value = e.data;
      if (value?.type === "redevplugin.bridge.client_ready") {
        if (!observingContext) {
          observingContext = true;
          appPort.addEventListener("message", event => {
            if (event.data?.type !== "redevplugin.bridge.context") return;
            deliveredRevision = Math.max(deliveredRevision, event.data.context.revision);
            present();
          }, { signal: controller.signal });
        }
        clientReady = true;
        deliverContext();
        if (ready) appPeer.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
      } else if (value?.type === "redevplugin.bridge.present" && Object.keys(value).length === 1 && explicitPresentation) {
        presented = true;
        present();
      } else if (value?.type === "redevplugin.ui.file.export") {
        send({ ...value, type: "redevplugin.surface.file.export", frame_generation_id: frameGeneration, surface_handle: surfaceHandle }, [value.content]);
      } else if (value?.type === "redevplugin.bridge.file_io") {
        send({ ...value, type: "redevplugin.surface.file_io", frame_generation_id: frameGeneration, surface_handle: surfaceHandle });
      } else if (value?.type === "redevplugin.bridge.lifecycle_ack") {
        send({ type: "redevplugin.surface.quiesce_ack", quiesce_id: value.quiesce_id });
      } else if (applicationMessages.has(value?.type)) send(value);
    };
    Object.defineProperty(globalThis, "__redevpluginWebBridge", {
      value: Object.freeze({ claim(options) {
        if (claimed) return;
        if (options !== undefined && (options?.presentation !== "explicit" || Object.keys(options).length !== 1)) throw new Error("Invalid presentation options");
        if (options && reportedRevision >= 0) throw new Error("Explicit presentation must be claimed before document readiness");
        claimed = true; explicitPresentation = options?.presentation === "explicit";
        return { surfaceHandle, port: appPort, presentation: true };
      } }),
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
    parsed = true;
    present();
  };
  const connect = event => {
    if (stopped || port || event.source !== parent || event.origin !== parentOrigin || event.data?.type !== "redevplugin.surface.port" || event.data.document_id !== documentID || event.ports.length !== 1) return;
    frameGeneration = event.data.frame_generation_id; port = event.ports[0];
    removeEventListener("message", connect);
    port.onmessage = e => {
      const m = e.data;
      if (m?.type === "redevplugin.surface.presented" && Object.keys(m).length === 3
        && m.frame_generation_id === frameGeneration && Number.isSafeInteger(m.context_revision)
        && m.context_revision >= 0 && m.context_revision <= reportedRevision) {
        presentationAccepted = true;
        return;
      }
      if (m?.type === "redevplugin.surface.selection_mode" && m.frame_generation_id === frameGeneration && m.surface_handle === surfaceHandle &&
        Number.isSafeInteger(m.revision) && m.revision > selectionRevision && typeof m.enabled === "boolean") {
        resetSelection(); selectionRevision = m.revision; setSelecting(m.enabled);
        if (selecting) releaseLock();
        return;
      }
      if (m?.type === "redevplugin.surface.pointer_lock" && m.frame_generation_id === frameGeneration && m.surface_handle === surfaceHandle) {
        pointerLockAllowed = m.enabled === true;
        if (!pointerLockAllowed) releaseLock();
        return;
      }
      if (m?.type === "redevplugin.bridge.lifecycle" && (m.event?.type === "hidden" || m.event?.type === "dispose")) {
        pointerLockAllowed = false; releaseLock(); setSelecting(false); resetSelection();
      }
      if (m?.type === "redevplugin.surface.initialize") { void start(m).catch(fail); return; }
      if (m?.type === "redevplugin.surface.context") { if (!context || m.context.revision > context.revision) { context = m.context; deliverContext(); present(); } return; }
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
