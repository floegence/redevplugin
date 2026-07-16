import { PluginBridgeClient, type PluginMethodResult, type PluginUIActionEvent, type PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

type Memo = { id: string; title: string; body: string; pinned: boolean; created_at: string; updated_at: string };
type MemoSummary = { id: string; title: string; preview: string; pinned: boolean; created_at: string; updated_at: string };
type MemoDraft = { id: string; title: string; body: string; pinned: boolean; created_at: string; updated_at: string };
type MemoListResult = { notes: MemoSummary[]; total: number; offset: number; has_more: boolean };
type MemosBootstrapResult = MemoListResult & { selected_note: Memo | null };
type SaveState = "idle" | "unsaved" | "saving" | "saved" | "error";
type SearchState = "idle" | "searching" | "error";
type Overlay = "none" | "memo-actions" | "delete-confirmation";
type FocusTarget = "none" | "title" | "menu-item" | "menu-button";

type MemosState = {
  library: {
    notes: MemoSummary[];
    total: number;
    hasMore: boolean;
    query: string;
    filter: "all" | "pinned";
    searchState: SearchState;
    errorMessage: string;
  };
  editor: {
    mode: "none" | "draft" | "saved";
    selectedId: string;
    returnId: string;
    draft: MemoDraft;
    dirty: boolean;
    revision: number;
    saveState: SaveState;
    errorMessage: string;
  };
  ui: {
    screen: "library" | "editor";
    overlay: Overlay;
    busy: boolean;
    focusTarget: FocusTarget;
    toast: string;
  };
};

const PAGE_SIZE = 24;
const AUTOSAVE_DELAY_MS = 700;
const SEARCH_DELAY_MS = 250;
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const state: MemosState = {
  library: {
    notes: [],
    total: 0,
    hasMore: false,
    query: "",
    filter: "all",
    searchState: "idle",
    errorMessage: "",
  },
  editor: {
    mode: "none",
    selectedId: "",
    returnId: "",
    draft: emptyDraft(),
    dirty: false,
    revision: 0,
    saveState: "idle",
    errorMessage: "",
  },
  ui: {
    screen: "library",
    overlay: "none",
    busy: false,
    focusTarget: "none",
    toast: "",
  },
};

let autosaveTimer: ReturnType<typeof setTimeout> | undefined;
let searchTimer: ReturnType<typeof setTimeout> | undefined;
let saveInFlight: Promise<boolean> | undefined;
let searchSequence = 0;

bridge.onAction("new-memo", () => void createMemo());
bridge.onAction("select-memo", (event) => void selectMemo(event.value));
bridge.onAction("back-to-list", () => void returnToList());
bridge.onAction("search-query", (event) => updateSearch(event.value ?? ""));
bridge.onAction("search-memos", (event) => submitSearch(event));
bridge.onAction("clear-search", () => clearSearch());
bridge.onAction("filter-memos", (event) => void setFilter(event.value));
bridge.onAction("load-more-memos", () => void loadMore());
bridge.onAction("edit-title", (event) => updateDraft("title", event.value ?? ""));
bridge.onAction("edit-body", (event) => updateDraft("body", event.value ?? ""));
bridge.onAction("retry-save", () => void flushDraft());
bridge.onAction("set-pinned", () => void setPinned());
bridge.onAction("toggle-memo-menu", () => void toggleMemoMenu());
bridge.onAction("close-memo-menu", () => void closeMemoMenu());
bridge.onAction("delete-memo", () => void requestDelete());
bridge.onAction("cancel-delete", () => void cancelDelete());
bridge.onAction("confirm-delete", () => void confirmDelete());
bridge.onLifecycle(async (event) => {
  if (event.type === "hidden") await flushDraft();
  if (event.type === "dispose") {
    clearAutosave();
    clearSearchTimer();
    await flushDraft();
  }
});

void initialize();

async function initialize(): Promise<void> {
  await bridge.ready();
  state.ui.busy = true;
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<MemosBootstrapResult>>("memos.bootstrap", {});
    state.library.notes = response.data.notes;
    state.library.total = response.data.total;
    state.library.hasMore = response.data.has_more;
    if (response.data.selected_note) {
      const note = response.data.selected_note;
      state.editor.mode = "saved";
      state.editor.selectedId = note.id;
      state.editor.returnId = note.id;
      state.editor.draft = draftFrom(note);
      state.editor.saveState = "saved";
    }
  } catch (error) {
    state.library.searchState = "error";
    state.library.errorMessage = readableError(error, "Memos is temporarily unavailable");
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function refreshNotes(append: boolean, sequence = ++searchSequence): Promise<boolean> {
  const offset = append ? state.library.notes.length : 0;
  let response: PluginMethodResult<MemoListResult>;
  try {
    response = await bridge.call<PluginMethodResult<MemoListResult>>("memos.list", {
      query: state.library.query,
      offset,
      limit: PAGE_SIZE,
      pinned_only: state.library.filter === "pinned",
    });
  } catch (error) {
    if (sequence !== searchSequence) return false;
    throw error;
  }
  if (sequence !== searchSequence) return false;
  state.library.notes = append ? dedupeSummaries([...state.library.notes, ...response.data.notes]) : response.data.notes;
  state.library.total = response.data.total;
  state.library.hasMore = response.data.has_more;
  state.library.searchState = "idle";
  state.library.errorMessage = "";
  return true;
}

async function loadMemo(id: string, openEditor = true): Promise<void> {
  const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.get", { id });
  state.editor.mode = "saved";
  state.editor.selectedId = response.data.note.id;
  state.editor.returnId = response.data.note.id;
  state.editor.draft = draftFrom(response.data.note);
  state.editor.dirty = false;
  state.editor.saveState = "saved";
  state.editor.errorMessage = "";
  state.ui.overlay = "none";
  if (openEditor) state.ui.screen = "editor";
}

async function createMemo(): Promise<void> {
  if ((saveInFlight || state.editor.dirty) && !(await flushDraft())) return;
  state.editor.returnId = state.editor.selectedId;
  state.editor.mode = "draft";
  state.editor.selectedId = "";
  state.editor.draft = emptyDraft();
  state.editor.dirty = false;
  state.editor.saveState = "idle";
  state.editor.errorMessage = "";
  state.ui.screen = "editor";
  state.ui.overlay = "none";
  state.ui.toast = "";
  await renderWithFocus("title");
}

async function selectMemo(id?: string): Promise<void> {
  if (!id) return;
  if (id === state.editor.selectedId) {
    state.ui.screen = "editor";
    await render();
    return;
  }
  if (!(await flushDraft())) return;
  await runBusy(async () => loadMemo(id));
}

async function returnToList(): Promise<void> {
  if (!(await flushDraft())) return;
  state.ui.overlay = "none";
  state.ui.screen = "library";
  await render();
}

function updateSearch(value: string): void {
  state.library.query = value.slice(0, 200);
  state.library.searchState = "searching";
  state.library.errorMessage = "";
  const sequence = ++searchSequence;
  clearSearchTimer();
  searchTimer = setTimeout(() => {
    searchTimer = undefined;
    void performSearch(sequence);
  }, SEARCH_DELAY_MS);
}

function submitSearch(event: PluginUIActionEvent): void {
  const value = String(event.form_data?.query ?? state.library.query);
  state.library.query = value.slice(0, 200);
  const sequence = ++searchSequence;
  clearSearchTimer();
  void performSearch(sequence);
}

function clearSearch(): void {
  state.library.query = "";
  const sequence = ++searchSequence;
  clearSearchTimer();
  void performSearch(sequence);
}

async function performSearch(sequence: number): Promise<void> {
  state.library.searchState = "searching";
  await render();
  try {
    await refreshNotes(false, sequence);
  } catch (error) {
    state.library.searchState = "error";
    state.library.errorMessage = readableError(error, "Search is temporarily unavailable");
  }
  await render();
}

function clearSearchTimer(): void {
  if (searchTimer !== undefined) clearTimeout(searchTimer);
  searchTimer = undefined;
}

async function setFilter(value?: string): Promise<void> {
  const next = value === "pinned" ? "pinned" : "all";
  if (next === state.library.filter) return;
  state.library.filter = next;
  state.library.searchState = "searching";
  clearSearchTimer();
  const sequence = ++searchSequence;
  await render();
  try {
    await refreshNotes(false, sequence);
  } catch (error) {
    state.library.searchState = "error";
    state.library.errorMessage = readableError(error, "Memos could not update this view");
  }
  await render();
}

async function loadMore(): Promise<void> {
  if (!state.library.hasMore || state.library.searchState === "searching") return;
  state.library.searchState = "searching";
  const sequence = ++searchSequence;
  await render();
  try {
    await refreshNotes(true, sequence);
  } catch (error) {
    state.library.searchState = "error";
    state.library.errorMessage = readableError(error, "More memos could not be loaded");
  }
  await render();
}

function updateDraft(field: "title" | "body", value: string): void {
  state.editor.draft[field] = field === "title" ? value.slice(0, 160) : value.slice(0, 20_000);
  state.editor.dirty = true;
  state.editor.revision += 1;
  state.editor.saveState = "unsaved";
  state.editor.errorMessage = "";
  state.ui.overlay = "none";
  state.ui.toast = "";
  scheduleAutosave();
  void render();
}

function scheduleAutosave(): void {
  clearAutosave();
  autosaveTimer = setTimeout(() => {
    autosaveTimer = undefined;
    void flushDraft();
  }, AUTOSAVE_DELAY_MS);
}

function clearAutosave(): void {
  if (autosaveTimer !== undefined) clearTimeout(autosaveTimer);
  autosaveTimer = undefined;
}

async function flushDraft(): Promise<boolean> {
  clearAutosave();
  if (saveInFlight) {
    const saved = await saveInFlight;
    if (!saved) return false;
    return state.editor.dirty ? flushDraft() : true;
  }
  if (!state.editor.dirty) return true;
  if (!state.editor.draft.title.trim() && !state.editor.draft.body.trim()) {
    state.editor.dirty = false;
    state.editor.saveState = "idle";
    return true;
  }

  const revision = state.editor.revision;
  const snapshot = { ...state.editor.draft, title: state.editor.draft.title.trim() || "Untitled memo" };
  state.editor.dirty = false;
  state.editor.saveState = "saving";
  state.editor.errorMessage = "";
  await render();
  const currentSave = (async (): Promise<boolean> => {
    try {
      const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.save", {
        id: snapshot.id,
        title: snapshot.title,
        body: snapshot.body,
        pinned: snapshot.pinned,
      });
      const note = response.data.note;
      state.editor.mode = "saved";
      state.editor.selectedId = note.id;
      state.editor.returnId = note.id;
      state.editor.draft.id = note.id;
      state.editor.draft.created_at = note.created_at;
      state.editor.draft.updated_at = note.updated_at;
      updateSummaryForCurrentView(note);
      if (state.editor.revision === revision) {
        state.editor.draft = draftFrom(note);
        state.editor.saveState = "saved";
      } else {
        state.editor.dirty = true;
        scheduleAutosave();
      }
      state.editor.errorMessage = "";
      return true;
    } catch (error) {
      state.editor.dirty = true;
      state.editor.saveState = "error";
      state.editor.errorMessage = readableError(error, "Memos could not save your changes");
      return false;
    }
  })();
  saveInFlight = currentSave;
  const saved = await currentSave;
  if (saveInFlight === currentSave) saveInFlight = undefined;
  await render();
  return saved;
}

async function setPinned(): Promise<void> {
  if (!state.editor.draft.id) {
    state.editor.draft.pinned = !state.editor.draft.pinned;
    state.editor.dirty = true;
    state.editor.revision += 1;
    state.editor.saveState = "unsaved";
    scheduleAutosave();
    await render();
    return;
  }
  if (!(await flushDraft())) return;
  await runBusy(async () => {
    const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.togglePin", { id: state.editor.draft.id });
    state.editor.draft = draftFrom(response.data.note);
    state.editor.selectedId = response.data.note.id;
    state.editor.returnId = response.data.note.id;
    state.editor.saveState = "saved";
    updateSummaryForCurrentView(response.data.note);
  });
}

async function toggleMemoMenu(): Promise<void> {
  if (state.ui.overlay === "memo-actions") {
    await closeMemoMenu();
    return;
  }
  state.ui.overlay = "memo-actions";
  await renderWithFocus("menu-item");
}

async function closeMemoMenu(): Promise<void> {
  state.ui.overlay = "none";
  await renderWithFocus("menu-button");
}

async function requestDelete(): Promise<void> {
  clearAutosave();
  if (saveInFlight) {
    state.ui.busy = true;
    await render();
    await saveInFlight;
    state.ui.busy = false;
  }
  state.ui.overlay = "delete-confirmation";
  await render();
}

async function cancelDelete(): Promise<void> {
  state.ui.overlay = "none";
  await renderWithFocus("menu-button");
}

async function confirmDelete(): Promise<void> {
  const id = state.editor.draft.id;
  clearAutosave();
  state.ui.overlay = "none";
  if (!id) {
    await discardDraft();
    state.ui.toast = "Draft discarded";
    await render();
    return;
  }
  const deleted = await runBusy(async () => {
    await bridge.call("memos.delete", { id });
    state.editor.dirty = false;
    const deletedIndex = state.library.notes.findIndex((note) => note.id === id);
    if (deletedIndex >= 0) {
      state.library.notes.splice(deletedIndex, 1);
      state.library.total = Math.max(0, state.library.total - 1);
    }
    state.library.hasMore = state.library.notes.length < state.library.total;
    state.editor = {
      mode: "none",
      selectedId: "",
      returnId: "",
      draft: emptyDraft(),
      dirty: false,
      revision: state.editor.revision,
      saveState: "idle",
      errorMessage: "",
    };
    state.ui.screen = "library";
    if (state.library.notes[0]) await loadMemo(state.library.notes[0].id, false);
    state.ui.toast = "Memo deleted";
  }, "Memos could not delete this note");
  if (!deleted && state.editor.dirty) scheduleAutosave();
}

async function discardDraft(): Promise<void> {
  clearAutosave();
  const returnId = state.editor.returnId;
  state.editor = {
    mode: "none",
    selectedId: "",
    returnId: "",
    draft: emptyDraft(),
    dirty: false,
    revision: state.editor.revision,
    saveState: "idle",
    errorMessage: "",
  };
  state.ui.overlay = "none";
  state.ui.screen = "library";
  if (returnId) await runBusy(async () => loadMemo(returnId, false));
  else await render();
}

async function runBusy(action: () => Promise<void>, fallback = "Memos is temporarily unavailable"): Promise<boolean> {
  if (state.ui.busy) return false;
  state.ui.busy = true;
  state.ui.toast = "";
  await render();
  try {
    await action();
    return true;
  } catch (error) {
    state.ui.toast = readableError(error, fallback);
    return false;
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function renderWithFocus(target: FocusTarget): Promise<void> {
  state.ui.focusTarget = target;
  await render();
  state.ui.focusTarget = "none";
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    key: "memos-root",
    tag: "main",
    attributes: { class: `memos-app view-${state.ui.screen}` },
    children: [libraryPane(), editorPane(), toast()],
  });
}

function libraryPane(): PluginUIVNode {
  const groups = groupedNotes();
  const hasNotes = state.library.notes.length > 0;
  return {
    type: "element", key: "library-pane", tag: "aside", attributes: { class: "memos-library", "aria-label": "Memo library" }, children: [
      { type: "element", key: "library-toolbar", tag: "header", attributes: { class: "library-toolbar" }, children: [
        { type: "element", key: "library-brand", tag: "div", attributes: { class: "brand-lockup" }, children: [
          { type: "element", key: "library-brand-mark", tag: "span", attributes: { class: "brand-mark", "aria-hidden": true }, children: [] },
          { type: "element", key: "library-brand-copy", tag: "div", children: [
            { type: "element", key: "library-title", tag: "h1", children: ["Memos"] },
            { type: "element", key: "library-count", tag: "p", children: [libraryCountLabel()] },
          ] },
        ] },
        { type: "element", key: "new-memo", tag: "button", attributes: { class: "new-memo-button", type: "button", title: "New memo", "aria-label": "New memo", disabled: backgroundDisabled(), "data-redevplugin-action": "new-memo" }, children: [
          { type: "element", key: "new-memo-icon", tag: "span", attributes: { class: "icon-plus", "aria-hidden": true }, children: [] },
        ] },
      ] },
      { type: "element", key: "search-form", tag: "form", attributes: { class: "search-form", "data-redevplugin-action": "search-memos" }, children: [
        { type: "element", key: "search-icon", tag: "span", attributes: { class: "search-icon", "aria-hidden": true }, children: [] },
        { type: "element", key: "search-query", tag: "input", attributes: { type: "search", name: "query", value: state.library.query, placeholder: "Search memos", autocomplete: "off", "aria-label": "Search memos", disabled: backgroundDisabled(), "data-redevplugin-action": "search-query" } },
        state.library.query ? { type: "element", key: "clear-search", tag: "button", attributes: { class: "clear-search", type: "button", title: "Clear search", "aria-label": "Clear search", disabled: backgroundDisabled(), "data-redevplugin-action": "clear-search" }, children: [
          { type: "element", key: "clear-search-icon", tag: "span", attributes: { class: "icon-close", "aria-hidden": true }, children: [] },
        ] } : "",
      ] },
      { type: "element", key: "library-filters", tag: "div", attributes: { class: "library-filters", role: "group", "aria-label": "Memo filter" }, children: [
        filterButton("all", "All"),
        filterButton("pinned", "Pinned"),
      ] },
      { type: "element", key: "library-content", tag: "div", attributes: { class: "library-content" }, children: [
        state.library.searchState === "searching" && !hasNotes ? libraryLoading() : "",
        state.library.searchState === "error" ? libraryError() : "",
        state.library.searchState !== "error" && !hasNotes ? libraryEmpty() : "",
        groups.pinned.length > 0 ? memoGroup("Pinned", "pinned-group", groups.pinned) : "",
        groups.recent.length > 0 ? memoGroup(state.library.filter === "pinned" ? "Pinned" : "Recent", "recent-group", groups.recent) : "",
        state.library.hasMore ? { type: "element", key: "load-more", tag: "button", attributes: { class: "load-more", type: "button", disabled: backgroundDisabled() || state.library.searchState === "searching", "data-redevplugin-action": "load-more-memos" }, children: [state.library.searchState === "searching" ? "Loading..." : "Load more"] } : "",
      ] },
    ],
  };
}

function groupedNotes(): { pinned: MemoSummary[]; recent: MemoSummary[] } {
  if (state.library.filter === "pinned") return { pinned: [], recent: state.library.notes };
  return {
    pinned: state.library.notes.filter((note) => note.pinned),
    recent: state.library.notes.filter((note) => !note.pinned),
  };
}

function memoGroup(label: string, className: string, notes: MemoSummary[]): PluginUIVNode {
  return { type: "element", key: `memo-group-${className}`, tag: "section", attributes: { class: `memo-group ${className}`, "aria-label": label }, children: [
    { type: "element", key: `memo-group-${className}-title`, tag: "h2", children: [label] },
    { type: "element", key: `memo-group-${className}-list`, tag: "ul", attributes: { class: "memo-list" }, children: notes.map(noteItem) },
  ] };
}

function noteItem(note: MemoSummary): PluginUIVNode {
  return { type: "element", key: `memo-${note.id}`, tag: "li", children: [
    { type: "element", key: `memo-${note.id}-select`, tag: "button", attributes: {
      class: "memo-row", type: "button", value: note.id, disabled: backgroundDisabled(), "aria-pressed": note.id === state.editor.selectedId,
      "data-redevplugin-action": "select-memo",
    }, children: [
      { type: "element", key: `memo-${note.id}-copy`, tag: "span", attributes: { class: "memo-copy" }, children: [
        { type: "element", key: `memo-${note.id}-title`, tag: "strong", children: [note.title] },
        { type: "element", key: `memo-${note.id}-preview`, tag: "span", children: [preview(note.preview) || "A blank page"] },
        { type: "element", key: `memo-${note.id}-date`, tag: "small", children: [formatMemoDate(note.updated_at)] },
      ] },
      note.pinned ? { type: "element", key: `memo-${note.id}-pinned`, tag: "span", attributes: { class: "pinned-mark", title: "Pinned", "aria-label": "Pinned" }, children: [
        { type: "element", key: `memo-${note.id}-pinned-icon`, tag: "span", attributes: { class: "icon-pin", "aria-hidden": true }, children: [] },
      ] } : "",
    ] },
  ] };
}

function editorPane(): PluginUIVNode {
  if (state.editor.mode === "none") return emptyWelcome();
  const words = wordCount(state.editor.draft.body);
  return { type: "element", key: "editor-pane", tag: "section", attributes: { class: "editor-pane", "aria-label": "Memo editor" }, children: [
    { type: "element", key: "editor-toolbar", tag: "header", attributes: { class: "editor-toolbar mobile-editor-bar" }, children: [
      { type: "element", key: "editor-back", tag: "button", attributes: { class: "back-button", type: "button", title: "Back to memos", "aria-label": "Back to memos", disabled: backgroundDisabled(), "data-redevplugin-action": "back-to-list" }, children: [
        { type: "element", key: "editor-back-icon", tag: "span", attributes: { class: "icon-back", "aria-hidden": true }, children: [] },
      ] },
      saveIndicator(),
      { type: "element", key: "editor-actions", tag: "div", attributes: { class: "editor-actions" }, children: [
        { type: "element", key: "editor-pin", tag: "button", attributes: { class: "editor-pin", type: "button", title: state.editor.draft.pinned ? "Unpin memo" : "Pin memo", "aria-label": state.editor.draft.pinned ? "Unpin memo" : "Pin memo", "aria-pressed": state.editor.draft.pinned, disabled: backgroundDisabled(), "data-redevplugin-action": "set-pinned" }, children: [
          { type: "element", key: "editor-pin-icon", tag: "span", attributes: { class: "icon-pin", "aria-hidden": true }, children: [] },
        ] },
        { type: "element", key: "editor-more", tag: "button", attributes: { class: "memo-more", type: "button", title: "More memo actions", "aria-label": "More memo actions", "aria-expanded": state.ui.overlay === "memo-actions", autofocus: state.ui.focusTarget === "menu-button", disabled: backgroundDisabled(), "data-redevplugin-action": "toggle-memo-menu" }, children: [
          { type: "element", key: "editor-more-icon", tag: "span", attributes: { class: "icon-more", "aria-hidden": true }, children: [] },
        ] },
      ] },
      state.ui.overlay === "memo-actions" ? memoMenu() : "",
    ] },
    { type: "element", key: "editor-scroll", tag: "div", attributes: { class: "editor-scroll" }, children: [
      { type: "element", key: "editor-document", tag: "article", attributes: { class: "editor-canvas" }, children: [
        { type: "element", key: "editor-date", tag: "p", attributes: { class: "memo-date" }, children: [formatDocumentDate(state.editor.draft.created_at)] },
        { type: "element", key: "editor-title", tag: "textarea", attributes: {
          class: "memo-title", name: "title", placeholder: "Untitled", rows: 1, maxlength: 160,
          value: state.editor.draft.title, autofocus: state.ui.focusTarget === "title", disabled: backgroundDisabled(), "aria-label": "Memo title", "data-redevplugin-action": "edit-title",
        } },
        { type: "element", key: "editor-body", tag: "textarea", attributes: {
          class: "memo-body", name: "body", value: state.editor.draft.body, placeholder: "Start writing...", maxlength: 20000, disabled: backgroundDisabled(),
          "aria-label": "Memo body", "data-redevplugin-action": "edit-body",
        } },
        { type: "element", key: "editor-footer", tag: "footer", attributes: { class: "editor-footer" }, children: [
          { type: "element", key: "editor-word-count", tag: "span", attributes: { class: "word-count" }, children: [`${words} ${words === 1 ? "word" : "words"}`] },
          { type: "element", key: "editor-updated", tag: "span", children: [state.editor.draft.updated_at ? `Updated ${formatMemoDate(state.editor.draft.updated_at).toLowerCase()}` : "Not saved yet"] },
        ] },
      ] },
    ] },
    state.ui.overlay === "delete-confirmation" ? deleteDialog() : "",
  ] };
}

function emptyWelcome(): PluginUIVNode {
  return { type: "element", key: "editor-pane", tag: "section", attributes: { class: "editor-pane empty-welcome", "aria-label": "Start a memo" }, children: [
    { type: "element", key: "welcome-artwork", tag: "div", attributes: { class: "empty-artwork", "aria-hidden": true }, children: [] },
    { type: "element", key: "welcome-kicker", tag: "p", attributes: { class: "empty-kicker" }, children: [formatNotebookDate()] },
    { type: "element", key: "welcome-title", tag: "h2", children: ["Keep a thought close"] },
    { type: "element", key: "welcome-copy", tag: "p", children: ["A private place for notes, plans, and passing ideas."] },
    { type: "element", key: "welcome-new", tag: "button", attributes: { class: "write-memo-button", type: "button", disabled: state.ui.busy, "data-redevplugin-action": "new-memo" }, children: [
      { type: "element", key: "welcome-new-icon", tag: "span", attributes: { class: "icon-plus", "aria-hidden": true }, children: [] },
      { type: "element", key: "welcome-new-label", tag: "span", children: ["Write a memo"] },
    ] },
  ] };
}

function saveIndicator(): PluginUIVNode {
  const label = saveLabel();
  return { type: "element", key: "save-indicator", tag: "div", attributes: { class: `save-indicator ${state.editor.saveState}`, role: "status" }, children: [
    { type: "element", key: "save-indicator-mark", tag: "span", attributes: { class: "save-mark", "aria-hidden": true }, children: [] },
    { type: "element", key: "save-indicator-label", tag: "span", children: [label] },
    state.editor.dirty && state.editor.saveState === "error" ? { type: "element", key: "retry-save", tag: "button", attributes: { class: "retry-save", type: "button", disabled: backgroundDisabled(), "data-redevplugin-action": "retry-save" }, children: ["Retry"] } : "",
  ] };
}

function saveLabel(): string {
  if (state.editor.saveState === "saving") return "Saving...";
  if (state.editor.saveState === "saved") return "Saved";
  if (state.editor.saveState === "unsaved") return "Unsaved";
  if (state.editor.saveState === "error") return state.editor.errorMessage || "Save failed";
  return state.editor.mode === "draft" ? "New memo" : "Saved";
}

function memoMenu(): PluginUIVNode {
  return { type: "element", key: "memo-menu", tag: "div", attributes: { class: "memo-menu", role: "menu", "aria-label": "Memo actions", "data-redevplugin-escape-action": "close-memo-menu" }, children: [
    state.editor.draft.id
      ? { type: "element", key: "memo-menu-delete", tag: "button", attributes: { type: "button", role: "menuitem", autofocus: state.ui.focusTarget === "menu-item", disabled: state.ui.busy, "data-redevplugin-action": "delete-memo" }, children: [
        { type: "element", key: "memo-menu-delete-icon", tag: "span", attributes: { class: "icon-trash", "aria-hidden": true }, children: [] },
        { type: "element", key: "memo-menu-delete-label", tag: "span", children: ["Delete memo"] },
      ] }
      : { type: "element", key: "memo-menu-delete", tag: "button", attributes: { type: "button", role: "menuitem", autofocus: state.ui.focusTarget === "menu-item", "data-redevplugin-action": "delete-memo" }, children: [
        { type: "element", key: "memo-menu-delete-icon", tag: "span", attributes: { class: "icon-trash", "aria-hidden": true }, children: [] },
        { type: "element", key: "memo-menu-delete-label", tag: "span", children: ["Discard draft"] },
      ] },
  ] };
}

function deleteDialog(): PluginUIVNode {
  const draft = !state.editor.draft.id;
  return { type: "element", key: "delete-layer", tag: "div", attributes: { class: "dialog-layer" }, children: [
    { type: "element", key: "delete-scrim", tag: "button", attributes: { class: "dialog-scrim", type: "button", tabindex: -1, "aria-label": draft ? "Cancel discard" : "Cancel delete", "data-redevplugin-action": "cancel-delete" }, children: [] },
    { type: "element", key: "delete-dialog", tag: "section", attributes: { class: "delete-dialog", role: "dialog", "aria-modal": true, "aria-label": draft ? "Discard draft" : "Delete memo", "data-redevplugin-escape-action": "cancel-delete" }, children: [
      { type: "element", key: "delete-mark", tag: "span", attributes: { class: "delete-mark", "aria-hidden": true }, children: ["!"] },
      { type: "element", key: "delete-copy", tag: "div", attributes: { class: "delete-copy" }, children: [
        { type: "element", key: "delete-title", tag: "h2", children: [draft ? "Discard this draft?" : "Delete this memo?"] },
        { type: "element", key: "delete-message", tag: "p", children: [draft ? "Your unsaved writing will be removed." : "This cannot be undone."] },
      ] },
      { type: "element", key: "delete-actions", tag: "div", attributes: { class: "delete-actions" }, children: [
        { type: "element", key: "delete-cancel", tag: "button", attributes: { class: "button quiet", type: "button", autofocus: true, "data-redevplugin-action": "cancel-delete" }, children: [draft ? "Keep writing" : "Keep memo"] },
        { type: "element", key: "delete-confirm", tag: "button", attributes: { class: "button danger", type: "button", "data-redevplugin-action": "confirm-delete" }, children: [draft ? "Discard draft" : "Delete memo"] },
      ] },
    ] },
  ] };
}

function filterButton(value: "all" | "pinned", label: string): PluginUIVNode {
  return { type: "element", key: `filter-${value}`, tag: "button", attributes: {
    type: "button", value, "aria-pressed": state.library.filter === value, disabled: backgroundDisabled() || state.library.searchState === "searching", "data-redevplugin-action": "filter-memos",
  }, children: [label] };
}

function backgroundDisabled(): boolean {
  return state.ui.busy || state.ui.overlay === "delete-confirmation";
}

function libraryLoading(): PluginUIVNode {
  return { type: "element", key: "library-loading", tag: "div", attributes: { class: "library-message", role: "status" }, children: [
    { type: "element", key: "library-loading-mark", tag: "span", attributes: { class: "loading-mark", "aria-hidden": true }, children: [] },
    { type: "element", key: "library-loading-label", tag: "strong", children: ["Finding your memos"] },
  ] };
}

function libraryError(): PluginUIVNode {
  return { type: "element", key: "library-error", tag: "div", attributes: { class: "library-message error", role: "status" }, children: [
    { type: "element", key: "library-error-title", tag: "strong", children: ["Memos need a moment"] },
    { type: "element", key: "library-error-message", tag: "span", children: [state.library.errorMessage] },
  ] };
}

function libraryEmpty(): PluginUIVNode {
  const searching = Boolean(state.library.query);
  const pinned = state.library.filter === "pinned";
  const variant = searching ? "search-empty" : pinned ? "pinned-empty" : "default-empty";
  return { type: "element", key: "library-empty", tag: "div", attributes: { class: `library-message library-empty ${variant}` }, children: [
    { type: "element", key: "library-empty-title", tag: "strong", children: [searching ? "No matches" : pinned ? "Nothing pinned" : "No memos yet"] },
    { type: "element", key: "library-empty-message", tag: "span", children: [searching ? "Try another phrase." : pinned ? "Pinned notes will stay within easy reach." : "Use the plus button to begin."] },
  ] };
}

function toast(): PluginUIVNode | string {
  return state.ui.toast ? { type: "element", key: "memos-toast", tag: "div", attributes: { class: "memos-toast", role: "status" }, children: [state.ui.toast] } : "";
}

function libraryCountLabel(): string {
  if (state.ui.busy) return "Opening your notes...";
  if (state.library.total === 0) return "Private notes";
  return `${state.library.total} ${state.library.total === 1 ? "memo" : "memos"}`;
}

function updateSummaryForCurrentView(note: Memo): void {
  const summary = summaryFrom(note);
  const index = state.library.notes.findIndex((candidate) => candidate.id === summary.id);
  if (!summaryMatchesCurrentView(note)) {
    if (index >= 0) {
      state.library.notes.splice(index, 1);
      state.library.total = Math.max(0, state.library.total - 1);
    }
    state.library.hasMore = state.library.notes.length < state.library.total;
    return;
  }
  if (index >= 0) state.library.notes[index] = summary;
  else {
    state.library.notes.unshift(summary);
    state.library.total += 1;
  }
  state.library.notes.sort((left, right) => Number(right.pinned) - Number(left.pinned) || right.updated_at.localeCompare(left.updated_at));
  state.library.hasMore = state.library.notes.length < state.library.total;
}

function summaryMatchesCurrentView(note: Memo): boolean {
  if (state.library.filter === "pinned" && !note.pinned) return false;
  const query = state.library.query.trim().toLowerCase();
  if (!query) return true;
  return `${note.title}\n${note.body}`.toLowerCase().includes(query);
}

function dedupeSummaries(notes: MemoSummary[]): MemoSummary[] {
  const seen = new Set<string>();
  return notes.filter((note) => {
    if (seen.has(note.id)) return false;
    seen.add(note.id);
    return true;
  });
}

function emptyDraft(): MemoDraft {
  return { id: "", title: "", body: "", pinned: false, created_at: "", updated_at: "" };
}

function draftFrom(note: Memo): MemoDraft {
  return { ...note };
}

function summaryFrom(note: Memo): MemoSummary {
  return { id: note.id, title: note.title, preview: note.body.slice(0, 180), pinned: note.pinned, created_at: note.created_at, updated_at: note.updated_at };
}

function preview(value: string): string {
  return normalizedWords(value).join(" ");
}

function wordCount(value: string): number {
  return normalizedWords(value).length;
}

function normalizedWords(value: string): string[] {
  return value
    .replaceAll("\n", " ")
    .replaceAll("\r", " ")
    .replaceAll("\t", " ")
    .split(" ")
    .filter(Boolean);
}

function formatNotebookDate(): string {
  return new Intl.DateTimeFormat("en", { weekday: "long", month: "long", day: "numeric" }).format(new Date());
}

function formatDocumentDate(value: string): string {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return formatNotebookDate();
  return new Intl.DateTimeFormat("en", { month: "long", day: "numeric", year: "numeric" }).format(date);
}

function formatMemoDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Just now";
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  if (sameDay) return new Intl.DateTimeFormat("en", { hour: "numeric", minute: "2-digit" }).format(date);
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(date);
}

function readableError(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message.trim() : "";
  if (!message || /PLUGIN_|runtime|broker|permission|rpc|worker|wasm/i.test(message)) return fallback;
  return message;
}
