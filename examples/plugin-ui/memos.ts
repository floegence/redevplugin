import { PluginBridgeClient, type PluginMethodResult, type PluginUIActionEvent, type PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

type Memo = { id: string; title: string; body: string; pinned: boolean; created_at: string; updated_at: string };
type MemoSummary = { id: string; title: string; preview: string; pinned: boolean; created_at: string; updated_at: string };
type MemoDraft = { id: string; title: string; body: string; pinned: boolean; created_at: string; updated_at: string };
type MemoListResult = { notes: MemoSummary[]; total: number; offset: number; has_more: boolean };

const PAGE_SIZE = 24;
const AUTOSAVE_DELAY_MS = 850;
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const state: {
  notes: MemoSummary[];
  total: number;
  hasMore: boolean;
  selectedId: string;
  draft: MemoDraft;
  query: string;
  filter: "all" | "pinned";
  view: "list" | "editor";
  busy: boolean;
  dirty: boolean;
  saveState: "idle" | "unsaved" | "saving" | "saved" | "error";
  status: string;
  error: boolean;
  confirmDelete: boolean;
  menuOpen: boolean;
  restoreMenuFocus: boolean;
} = {
  notes: [],
  total: 0,
  hasMore: false,
  selectedId: "",
  draft: emptyDraft(),
  query: "",
  filter: "all",
  view: "list",
  busy: false,
  dirty: false,
  saveState: "idle",
  status: "Opening your library...",
  error: false,
  confirmDelete: false,
  menuOpen: false,
  restoreMenuFocus: false,
};

let autosaveTimer: ReturnType<typeof setTimeout> | undefined;
let saveInFlight: Promise<boolean> | undefined;
let draftRevision = 0;

bridge.onAction("new-memo", () => void createMemo());
bridge.onAction("select-memo", (event) => void selectMemo(event.value));
bridge.onAction("back-to-list", () => void returnToList());
bridge.onAction("search-memos", (event) => void search(event));
bridge.onAction("filter-memos", (event) => void setFilter(event.value));
bridge.onAction("load-more-memos", () => void loadMore());
bridge.onAction("edit-title", (event) => updateDraft("title", event.value ?? ""));
bridge.onAction("edit-body", (event) => updateDraft("body", event.value ?? ""));
bridge.onAction("retry-save", () => void flushDraft());
bridge.onAction("set-pinned", () => void setPinned());
bridge.onAction("toggle-memo-menu", () => toggleMemoMenu());
bridge.onAction("close-memo-menu", () => closeMemoMenu());
bridge.onAction("delete-memo", () => requestDelete());
bridge.onAction("cancel-delete", () => cancelDelete());
bridge.onAction("confirm-delete", () => void confirmDelete());
bridge.onLifecycle(async (event) => {
  if (event.type === "hidden") await flushDraft();
  if (event.type === "dispose") {
    clearAutosave();
    await flushDraft();
  }
});

void initialize();

async function initialize(): Promise<void> {
  await bridge.ready();
  await run(async () => {
    await bridge.call("memos.initialize", {});
    await refreshNotes(false);
    if (state.notes[0]) await loadMemo(state.notes[0].id, false);
    state.status = state.total === 0 ? "Your first memo is ready when you are" : `${state.total} ${state.total === 1 ? "memo" : "memos"}`;
  });
}

async function refreshNotes(append: boolean): Promise<void> {
  const offset = append ? state.notes.length : 0;
  const response = await bridge.call<PluginMethodResult<MemoListResult>>("memos.list", {
    query: state.query,
    offset,
    limit: PAGE_SIZE,
    pinned_only: state.filter === "pinned",
  });
  state.notes = append ? dedupeSummaries([...state.notes, ...response.data.notes]) : response.data.notes;
  state.total = response.data.total;
  state.hasMore = response.data.has_more;
}

async function loadMemo(id: string, openEditor = true): Promise<void> {
  const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.get", { id });
  state.selectedId = response.data.note.id;
  state.draft = draftFrom(response.data.note);
  state.dirty = false;
  state.saveState = "saved";
  state.status = response.data.note.pinned ? "Pinned memo" : "All changes saved";
  state.error = false;
  state.confirmDelete = false;
  state.menuOpen = false;
  if (openEditor) state.view = "editor";
}

async function createMemo(): Promise<void> {
  if ((saveInFlight || state.dirty) && !(await flushDraft())) return;
  state.selectedId = "";
  state.draft = emptyDraft();
  state.dirty = false;
  state.saveState = "idle";
  state.status = "New private memo";
  state.error = false;
  state.confirmDelete = false;
  state.menuOpen = false;
  state.restoreMenuFocus = false;
  state.view = "editor";
  await render();
}

async function selectMemo(id?: string): Promise<void> {
  if (!id || id === state.selectedId) {
    state.view = "editor";
    await render();
    return;
  }
  if (!(await flushDraft())) return;
  await run(async () => loadMemo(id));
}

async function returnToList(): Promise<void> {
  if (!(await flushDraft())) return;
  state.menuOpen = false;
  state.view = "list";
  await render();
}

async function search(event: PluginUIActionEvent): Promise<void> {
  state.query = String(event.form_data?.query ?? "").trim();
  await run(async () => {
    await refreshNotes(false);
    state.status = state.notes.length === 0 ? (state.query ? "No matching memos" : "Your first memo is ready when you are") : `${state.total} ${state.total === 1 ? "memo" : "memos"}`;
  });
}

async function setFilter(value?: string): Promise<void> {
  state.filter = value === "pinned" ? "pinned" : "all";
  await run(async () => {
    await refreshNotes(false);
    state.status = state.filter === "pinned" ? `${state.total} pinned` : `${state.total} ${state.total === 1 ? "memo" : "memos"}`;
  });
}

async function loadMore(): Promise<void> {
  if (!state.hasMore || state.busy) return;
  await run(async () => {
    await refreshNotes(true);
    state.status = `${state.notes.length} of ${state.total} memos loaded`;
  });
}

function updateDraft(field: "title" | "body" | "pinned", value: string | boolean): void {
  if (field === "pinned") state.draft.pinned = value === true;
  else state.draft[field] = String(value);
  state.dirty = true;
  state.saveState = "unsaved";
  state.status = "Unsaved changes";
  state.error = false;
  state.confirmDelete = false;
  state.menuOpen = false;
  draftRevision += 1;
  scheduleAutosave();
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
    return state.dirty ? flushDraft() : true;
  }
  if (!state.dirty) return true;
  if (!state.draft.title.trim() && !state.draft.body.trim()) {
    state.dirty = false;
    state.saveState = "idle";
    state.status = "New private memo";
    return true;
  }

  const revision = draftRevision;
  const snapshot = { ...state.draft, title: state.draft.title.trim() || "Untitled memo" };
  state.dirty = false;
  state.saveState = "saving";
  state.status = "Saving...";
  let renderAfterSave = false;
  const currentSave = (async (): Promise<boolean> => {
    try {
      const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.save", {
        id: snapshot.id,
        title: snapshot.title,
        body: snapshot.body,
        pinned: snapshot.pinned,
      });
      const note = response.data.note;
      state.selectedId = note.id;
      state.draft.id = note.id;
      state.draft.created_at = note.created_at;
      state.draft.updated_at = note.updated_at;
      upsertSummary(summaryFrom(note));
      state.error = false;
      if (draftRevision === revision) {
        state.draft = draftFrom(note);
        state.saveState = "saved";
        state.status = "Saved just now";
        renderAfterSave = true;
      } else {
        state.dirty = true;
        scheduleAutosave();
      }
      return true;
    } catch (error) {
      state.dirty = true;
      state.saveState = "error";
      state.status = readableError(error, "Memos could not save your changes");
      state.error = true;
      renderAfterSave = true;
      return false;
    }
  })();
  saveInFlight = currentSave;
  const saved = await currentSave;
  if (saveInFlight === currentSave) saveInFlight = undefined;
  if (renderAfterSave) await render();
  return saved;
}

async function setPinned(): Promise<void> {
  if (!state.draft.id) {
    updateDraft("pinned", !state.draft.pinned);
    await render();
    return;
  }
  if (!(await flushDraft())) return;
  await run(async () => {
    const response = await bridge.call<PluginMethodResult<{ note: Memo }>>("memos.togglePin", { id: state.draft.id });
    state.draft = draftFrom(response.data.note);
    state.selectedId = response.data.note.id;
    upsertSummary(summaryFrom(response.data.note));
    state.status = response.data.note.pinned ? "Memo pinned" : "Memo unpinned";
    state.saveState = "saved";
    state.menuOpen = false;
  });
}

function toggleMemoMenu(): void {
  state.menuOpen = !state.menuOpen;
  state.restoreMenuFocus = !state.menuOpen;
  void render();
}

function closeMemoMenu(): void {
  state.menuOpen = false;
  state.restoreMenuFocus = true;
  void render();
}

function requestDelete(): void {
  if (!state.draft.id) {
    state.draft = emptyDraft();
    state.view = "list";
    state.status = "Draft discarded";
    void render();
    return;
  }
  state.menuOpen = false;
  state.restoreMenuFocus = false;
  state.confirmDelete = true;
  void render();
}

function cancelDelete(): void {
  state.confirmDelete = false;
  state.menuOpen = false;
  state.restoreMenuFocus = true;
  state.status = "Memo kept";
  void render();
}

async function confirmDelete(): Promise<void> {
  const id = state.draft.id;
  if (!id) return;
  clearAutosave();
  state.dirty = false;
  state.confirmDelete = false;
  await run(async () => {
    await bridge.call("memos.delete", { id });
    state.notes = state.notes.filter((note) => note.id !== id);
    state.total = Math.max(0, state.total - 1);
    state.selectedId = "";
    state.draft = emptyDraft();
    state.view = "list";
    state.status = "Memo deleted";
    state.saveState = "idle";
    if (state.notes[0]) await loadMemo(state.notes[0].id, false);
    state.status = "Memo deleted";
  });
}

async function run(action: () => Promise<void>): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.error = false;
  await render();
  try {
    await action();
  } catch (error) {
    state.status = readableError(error, "Memos is temporarily unavailable");
    state.error = true;
    state.saveState = "error";
  } finally {
    state.busy = false;
    await render();
  }
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    tag: "main",
    attributes: { class: `memos-app view-${state.view}` },
    children: [sidebar(), editor()],
  });
}

function sidebar(): PluginUIVNode {
  const notes = visibleNotes();
  return {
    type: "element", tag: "aside", attributes: { class: "memos-sidebar memo-library", "aria-label": "Memo library" }, children: [
      { type: "element", tag: "header", attributes: { class: "library-header" }, children: [
        { type: "element", tag: "div", attributes: { class: "brand-row" }, children: [
          { type: "element", tag: "div", attributes: { class: "brand-lockup" }, children: [
            { type: "element", tag: "span", attributes: { class: "brand-mark", "aria-hidden": true }, children: [] },
            { type: "element", tag: "div", children: [
              { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: [formatNotebookDate()] },
              { type: "element", tag: "h1", children: ["Memos"] },
            ] },
          ] },
          { type: "element", tag: "button", attributes: { class: "new-memo-button", type: "button", title: "New memo", "aria-label": "New memo", disabled: state.busy, "data-redevplugin-action": "new-memo" }, children: [
            { type: "element", tag: "span", attributes: { class: "icon-plus", "aria-hidden": true }, children: [] },
          ] },
        ] },
        { type: "element", tag: "p", attributes: { class: state.error ? "library-summary error" : "library-summary" }, children: [
          state.error ? "Your memos need attention" : state.busy ? "Refreshing your memos..." : `${state.total} ${state.total === 1 ? "memo" : "memos"} in your private notebook`,
        ] },
      ] },
      { type: "element", tag: "form", attributes: { class: "search-form", "data-redevplugin-action": "search-memos" }, children: [
        { type: "element", tag: "input", attributes: { type: "search", name: "query", value: state.query, placeholder: "Search your memos", autocomplete: "off", disabled: state.busy, "aria-label": "Search memos" } },
        { type: "element", tag: "button", attributes: { type: "submit", title: "Search", "aria-label": "Search" }, children: ["Search"] },
      ] },
      { type: "element", tag: "div", attributes: { class: "memo-filters", role: "group", "aria-label": "Memo filter" }, children: [
        filterButton("all", "All memos"),
        filterButton("pinned", "Pinned"),
      ] },
      libraryOverview(),
      notes.length === 0 ? emptyList() : { type: "element", tag: "ul", attributes: { class: "note-list" }, children: notes.map(noteItem) },
      state.hasMore ? { type: "element", tag: "button", attributes: { class: "load-more", type: "button", disabled: state.busy, "data-redevplugin-action": "load-more-memos" }, children: [state.filter === "pinned" ? "Load more pinned memos" : "Load more memos"] } : "",
    ],
  };
}

function libraryOverview(): PluginUIVNode {
  const pinned = state.notes.filter((note) => note.pinned).length;
  return { type: "element", tag: "section", attributes: { class: "library-overview", "aria-label": "Notebook overview" }, children: [
    { type: "element", tag: "div", attributes: { class: "overview-heading" }, children: [
      { type: "element", tag: "span", children: [state.filter === "pinned" ? "Pinned collection" : "Private library"] },
      { type: "element", tag: "strong", children: [state.total === 0 ? "A clear page is ready" : `${state.total} ${state.total === 1 ? "thought" : "thoughts"}, kept close`] },
    ] },
    { type: "element", tag: "dl", attributes: { class: "overview-stats" }, children: [
      { type: "element", tag: "div", children: [
        { type: "element", tag: "dt", children: ["Memos"] },
        { type: "element", tag: "dd", children: [String(state.total)] },
      ] },
      { type: "element", tag: "div", children: [
        { type: "element", tag: "dt", children: ["Pinned"] },
        { type: "element", tag: "dd", children: [String(pinned)] },
      ] },
    ] },
  ] };
}

function filterButton(value: "all" | "pinned", label: string): PluginUIVNode {
  return { type: "element", tag: "button", attributes: {
    type: "button", value, "aria-pressed": state.filter === value, disabled: state.busy, "data-redevplugin-action": "filter-memos",
  }, children: [label] };
}

function emptyList(): PluginUIVNode {
  return { type: "element", tag: "button", attributes: { class: "empty-list", type: "button", disabled: state.busy, "data-redevplugin-action": "new-memo" }, children: [
    { type: "element", tag: "span", attributes: { class: "empty-list-mark icon-plus", "aria-hidden": true }, children: [] },
    { type: "element", tag: "strong", children: [state.query ? "No memo matches that search" : state.filter === "pinned" ? "Nothing pinned yet" : "Start with a thought"] },
    { type: "element", tag: "span", children: [state.query ? "Try another phrase or create something new." : state.filter === "pinned" ? "Important memos will gather here." : "A clear page is waiting in your private notebook."] },
  ] };
}

function noteItem(note: MemoSummary): PluginUIVNode {
  return { type: "element", tag: "li", attributes: { class: "note-item" }, children: [
    { type: "element", tag: "button", attributes: {
      class: "note-row", type: "button", value: note.id, disabled: state.busy, "aria-pressed": note.id === state.selectedId,
      "data-redevplugin-action": "select-memo",
    }, children: [
      { type: "element", tag: "span", attributes: { class: note.pinned ? "note-accent pinned" : "note-accent", "aria-hidden": true }, children: [] },
      { type: "element", tag: "span", attributes: { class: "note-copy" }, children: [
        { type: "element", tag: "strong", children: [note.title] },
        { type: "element", tag: "span", children: [preview(note.preview) || "A beautifully blank page"] },
        { type: "element", tag: "small", children: [formatMemoDate(note.updated_at)] },
      ] },
      { type: "element", tag: "span", attributes: { class: "note-chevron", "aria-hidden": true }, children: [] },
    ] },
  ] };
}

function editor(): PluginUIVNode {
  const editing = Boolean(state.draft.id);
  const words = wordCount(state.draft.body);
  return { type: "element", tag: "section", attributes: { class: "editor", "aria-label": "Memo editor" }, children: [
    { type: "element", tag: "header", attributes: { class: "editor-toolbar mobile-editor-bar" }, children: [
      { type: "element", tag: "button", attributes: { class: "back-button", type: "button", "aria-label": "Back to memos", "data-redevplugin-action": "back-to-list" }, children: [
        { type: "element", tag: "span", attributes: { class: "icon-back", "aria-hidden": true }, children: [] },
      ] },
      { type: "element", tag: "div", attributes: { class: "save-state" }, children: [
        { type: "element", tag: "span", attributes: { class: `save-dot ${state.saveState}`, "aria-hidden": true }, children: [] },
        { type: "element", tag: "span", attributes: { role: "status" }, children: [state.busy ? "Opening..." : state.status] },
        state.dirty && state.saveState === "error" ? { type: "element", tag: "button", attributes: { class: "retry-save", type: "button", disabled: state.busy, "data-redevplugin-action": "retry-save" }, children: ["Retry"] } : "",
      ] },
      { type: "element", tag: "div", attributes: { class: "editor-controls" }, children: [
        { type: "element", tag: "button", attributes: { class: "editor-pin", type: "button", title: state.draft.pinned ? "Unpin memo" : "Pin memo", "aria-label": state.draft.pinned ? "Unpin memo" : "Pin memo", "aria-pressed": state.draft.pinned, disabled: state.busy, "data-redevplugin-action": "set-pinned" }, children: [
          { type: "element", tag: "span", attributes: { class: "icon-pin", "aria-hidden": true }, children: [] },
          { type: "element", tag: "span", attributes: { class: "control-label" }, children: [state.draft.pinned ? "Pinned" : "Pin"] },
        ] },
        { type: "element", tag: "button", attributes: { class: "memo-more", type: "button", title: "More memo actions", "aria-label": "More memo actions", "aria-expanded": state.menuOpen, autofocus: state.restoreMenuFocus, disabled: state.busy, "data-redevplugin-action": "toggle-memo-menu" }, children: [
          { type: "element", tag: "span", attributes: { class: "icon-more", "aria-hidden": true }, children: [] },
        ] },
      ] },
      state.menuOpen ? memoMenu(editing) : "",
    ] },
    { type: "element", tag: "div", attributes: { class: "editor-workspace" }, children: [
      { type: "element", tag: "div", attributes: { class: "editor-paper" }, children: [
        { type: "element", tag: "div", attributes: { class: "document-kicker" }, children: [
          { type: "element", tag: "span", attributes: { class: "document-date" }, children: [formatDocumentDate(state.draft.created_at)] },
          { type: "element", tag: "span", attributes: { class: "document-privacy" }, children: ["Private memo"] },
        ] },
        { type: "element", tag: "input", attributes: {
          class: "memo-title", type: "text", name: "title", value: state.draft.title, placeholder: "Memo title", autocomplete: "off", disabled: state.busy,
          "aria-label": "Memo title", "data-redevplugin-action": "edit-title",
        } },
        { type: "element", tag: "textarea", attributes: {
          class: "memo-body", name: "body", placeholder: "Write something worth remembering...", maxlength: 20000, disabled: state.busy,
          "aria-label": "Memo body", "data-redevplugin-action": "edit-body",
        }, children: [state.draft.body] },
        { type: "element", tag: "footer", attributes: { class: "editor-meta" }, children: [
          { type: "element", tag: "span", attributes: { class: "word-count" }, children: [`${words} ${words === 1 ? "word" : "words"}`] },
          { type: "element", tag: "span", children: [state.draft.updated_at ? `Edited ${formatMemoDate(state.draft.updated_at)}` : "Private to this profile"] },
        ] },
      ] },
      memoContextRail(words),
    ] },
    state.confirmDelete ? deleteConfirmation() : "",
  ] };
}

function memoContextRail(words: number): PluginUIVNode {
  const saveLabel = state.saveState === "saving" ? "Saving" : state.dirty ? "Draft" : state.draft.id ? "Saved" : "New";
  return { type: "element", tag: "aside", attributes: { class: "memo-context-rail", "aria-label": "Memo details" }, children: [
    { type: "element", tag: "div", attributes: { class: "context-heading" }, children: [
      { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["At a glance"] },
      { type: "element", tag: "strong", children: [state.draft.title.trim() || "New memo"] },
    ] },
    { type: "element", tag: "dl", attributes: { class: "context-stats" }, children: [
      contextStat("Words", String(words)),
      contextStat("Status", saveLabel),
      contextStat("Collection", state.draft.pinned ? "Pinned" : "All memos"),
      contextStat("Updated", state.draft.updated_at ? formatMemoDate(state.draft.updated_at) : "Just now"),
    ] },
    { type: "element", tag: "div", attributes: { class: "context-ribbon", "aria-hidden": true }, children: [
      { type: "element", tag: "span", children: [] },
      { type: "element", tag: "span", children: [] },
      { type: "element", tag: "span", children: [] },
    ] },
  ] };
}

function contextStat(label: string, value: string): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "context-stat" }, children: [
    { type: "element", tag: "dt", children: [label] },
    { type: "element", tag: "dd", children: [value] },
  ] };
}

function memoMenu(editing: boolean): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "memo-menu", role: "menu", "aria-label": "Memo actions", "data-redevplugin-escape-action": "close-memo-menu" }, children: [
    editing
      ? { type: "element", tag: "button", attributes: { type: "button", role: "menuitem", autofocus: true, disabled: state.busy, "data-redevplugin-action": "delete-memo" }, children: [
        { type: "element", tag: "span", attributes: { class: "icon-trash", "aria-hidden": true }, children: [] },
        { type: "element", tag: "span", children: ["Delete memo"] },
      ] }
      : { type: "element", tag: "span", attributes: { class: "menu-hint" }, children: ["This memo will be saved as you write."] },
  ] };
}

function deleteConfirmation(): PluginUIVNode {
  return { type: "element", tag: "div", attributes: { class: "delete-confirmation", role: "group", "aria-label": "Delete memo confirmation", "data-redevplugin-escape-action": "cancel-delete" }, children: [
    { type: "element", tag: "div", attributes: { class: "delete-confirmation-copy" }, children: [
      { type: "element", tag: "span", attributes: { class: "delete-mark", "aria-hidden": true }, children: ["!"] },
      { type: "element", tag: "div", children: [
        { type: "element", tag: "strong", children: ["Delete this memo?"] },
        { type: "element", tag: "p", children: ["This removes it from your private library and cannot be undone."] },
      ] },
    ] },
    { type: "element", tag: "div", attributes: { class: "delete-confirmation-actions" }, children: [
      { type: "element", tag: "button", attributes: { class: "button quiet", type: "button", autofocus: true, "data-redevplugin-action": "cancel-delete" }, children: ["Keep memo"] },
      { type: "element", tag: "button", attributes: { class: "button danger-solid", type: "button", "data-redevplugin-action": "confirm-delete" }, children: ["Delete permanently"] },
    ] },
  ] };
}

function visibleNotes(): MemoSummary[] {
  return state.notes;
}

function upsertSummary(summary: MemoSummary): void {
  const existed = state.notes.some((note) => note.id === summary.id);
  const matchesQuery = !state.query || `${summary.title} ${summary.preview}`.toLowerCase().includes(state.query.toLowerCase());
  const belongsInFilter = state.filter === "all" || summary.pinned;
  state.notes = state.notes.filter((note) => note.id !== summary.id);
  if (matchesQuery && belongsInFilter) state.notes.unshift(summary);
  state.notes.sort((left, right) => Number(right.pinned) - Number(left.pinned) || right.updated_at.localeCompare(left.updated_at));
  if (!existed && matchesQuery && belongsInFilter) state.total += 1;
  if (existed && (!matchesQuery || !belongsInFilter)) state.total = Math.max(0, state.total - 1);
}

function dedupeSummaries(notes: MemoSummary[]): MemoSummary[] {
  const seen = new Set<string>();
  return notes.filter((note) => {
    if (seen.has(note.id)) return false;
    seen.add(note.id);
    return true;
  });
}

function summaryFrom(note: Memo): MemoSummary {
  return { id: note.id, title: note.title, preview: preview(note.body), pinned: note.pinned, created_at: note.created_at, updated_at: note.updated_at };
}

function draftFrom(note: Memo): MemoDraft {
  return { ...note };
}

function emptyDraft(): MemoDraft {
  return { id: "", title: "", body: "", pinned: false, created_at: "", updated_at: "" };
}

function preview(value: string): string {
  return value.replace(new RegExp("\\s+", "g"), " ").trim().slice(0, 180);
}

function wordCount(value: string): number {
  const normalized = value.trim();
  return normalized ? normalized.split(new RegExp("\\s+")).length : 0;
}

function formatMemoDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Recently";
  const today = new Date();
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString("en", { hour: "numeric", minute: "2-digit" });
  return date.toLocaleDateString("en", { month: "short", day: "numeric" });
}

function formatNotebookDate(): string {
  return new Date().toLocaleDateString("en", { weekday: "long", month: "long", day: "numeric" });
}

function formatDocumentDate(value: string): string {
  const date = value ? new Date(value) : new Date();
  return date.toLocaleDateString("en", { month: "long", day: "numeric", year: "numeric" });
}

function readableError(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message : "";
  if (!message || message.includes("PLUGIN_") || message.toLowerCase().includes("permission")) return fallback;
  return message.length > 140 ? fallback : message;
}
