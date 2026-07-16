import { PluginBridgeClient, type PluginMethodResult, type PluginUIActionEvent, type PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";
import { renderMarkdown, toggleTaskMarker } from "./memos-markdown.js";

type Memo = {
  id: string;
  content: string;
  pinned: boolean;
  archived: boolean;
  tags: string[];
  created_at: string;
  updated_at: string;
};
type Draft = { content: string; updated_at: string };
type TagFacet = { tag: string; count: number };
type DayFacet = { date: string; count: number };
type FacetResult = {
  month: string;
  tags: TagFacet[];
  days: DayFacet[];
  all_total: number;
  pinned_total: number;
  archived_total: number;
};
type ListResult = { memos: Memo[]; total: number; offset: number; has_more: boolean };
type BootstrapResult = ListResult & { draft: Draft | null; facets: FacetResult };
type SaveState = "idle" | "unsaved" | "saving" | "saved" | "error";
type FeedView = "all" | "pinned" | "archived";
type FocusTarget = "none" | "composer" | "menu-item" | "menu-button";

type MemosState = {
  feed: {
    memos: Memo[];
    total: number;
    hasMore: boolean;
    query: string;
    view: FeedView;
    tag: string;
    date: string;
    loading: boolean;
    errorMessage: string;
  };
  composer: {
    content: string;
    dirty: boolean;
    revision: number;
    saveState: SaveState;
    errorMessage: string;
    updatedAt: string;
    expanded: boolean;
  };
  facets: {
    month: string;
    tags: TagFacet[];
    days: DayFacet[];
    allTotal: number;
    pinnedTotal: number;
    archivedTotal: number;
    loading: boolean;
    errorMessage: string;
  };
  editing: {
    id: string;
    content: string;
    originalContent: string;
    dirty: boolean;
    revision: number;
    saveState: SaveState;
    errorMessage: string;
  };
  ui: {
    ready: boolean;
    busy: boolean;
    drawerOpen: boolean;
    menuId: string;
    deleteId: string;
    focusTarget: FocusTarget;
    focusId: string;
    toast: string;
    expandedIds: Set<string>;
    pendingIds: Set<string>;
  };
};

const PAGE_SIZE = 10;
const DRAFT_DELAY_MS = 500;
const EDIT_DELAY_MS = 700;
const SEARCH_DELAY_MS = 250;
const MAX_CONTENT_CHARS = 20_000;
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const utcOffsetMinutes = -new Date().getTimezoneOffset();
const state: MemosState = {
  feed: { memos: [], total: 0, hasMore: false, query: "", view: "all", tag: "", date: "", loading: false, errorMessage: "" },
  composer: { content: "", dirty: false, revision: 0, saveState: "idle", errorMessage: "", updatedAt: "", expanded: false },
  facets: { month: currentMonth(), tags: [], days: [], allTotal: 0, pinnedTotal: 0, archivedTotal: 0, loading: false, errorMessage: "" },
  editing: { id: "", content: "", originalContent: "", dirty: false, revision: 0, saveState: "idle", errorMessage: "" },
  ui: { ready: false, busy: false, drawerOpen: false, menuId: "", deleteId: "", focusTarget: "none", focusId: "", toast: "", expandedIds: new Set(), pendingIds: new Set() },
};

let draftTimer: ReturnType<typeof setTimeout> | undefined;
let editTimer: ReturnType<typeof setTimeout> | undefined;
let searchTimer: ReturnType<typeof setTimeout> | undefined;
let toastTimer: ReturnType<typeof setTimeout> | undefined;
let draftSaveInFlight: Promise<boolean> | undefined;
let editSaveInFlight: Promise<boolean> | undefined;
let feedSequence = 0;
let facetsSequence = 0;

bridge.onAction("toggle-explorer", () => void toggleExplorer());
bridge.onAction("close-explorer", () => void closeExplorer());
bridge.onAction("search-query", (event) => updateSearch(event));
bridge.onAction("search-memos", (event) => submitSearch(event));
bridge.onAction("clear-search", () => clearSearch());
bridge.onAction("filter-view", (event) => void setView(event.value));
bridge.onAction("filter-tag", (event) => void setTag(event.value));
bridge.onAction("filter-date", (event) => void setDate(event.value));
bridge.onAction("clear-filters", () => void clearFilters());
bridge.onAction("previous-month", () => void moveMonth(-1));
bridge.onAction("next-month", () => void moveMonth(1));
bridge.onAction("load-more-memos", () => void loadMore());
bridge.onAction("composer-content", (event) => updateComposer(event));
bridge.onAction("expand-composer", () => void expandComposer());
bridge.onAction("retry-draft", () => void flushComposer());
bridge.onAction("publish-memo", () => void publishMemo());
bridge.onAction("edit-memo", (event) => void beginEdit(event.value));
bridge.onAction("edit-content", (event) => updateEdit(event));
bridge.onAction("finish-edit", () => void finishEdit());
bridge.onAction("retry-edit", () => void flushEdit());
bridge.onAction("set-pinned", (event) => void setPinned(event.value));
bridge.onAction("toggle-memo-menu", (event) => void toggleMemoMenu(event.value));
bridge.onAction("close-memo-menu", () => void closeMemoMenu());
bridge.onAction("set-archived", (event) => void setArchived(event.value));
bridge.onAction("request-delete", (event) => void requestDelete(event.value));
bridge.onAction("cancel-delete", () => void cancelDelete());
bridge.onAction("confirm-delete", () => void confirmDelete());
bridge.onAction("toggle-task", (event) => void toggleTask(event));
bridge.onAction("toggle-expanded", (event) => void toggleExpanded(event.value));
bridge.onLifecycle(async (event) => {
  if (event.type === "dispose") {
    clearTimers();
    await Promise.all([flushComposer(), flushEdit()]);
  } else if (event.type === "hidden") {
    await Promise.all([flushComposer(), flushEdit()]);
  }
});

void initialize();

async function initialize(): Promise<void> {
  await bridge.ready();
  state.ui.busy = true;
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<BootstrapResult>>("memos.bootstrap", {
      month: state.facets.month,
      utc_offset_minutes: utcOffsetMinutes,
    });
    applyList(response.data);
    applyFacets(response.data.facets);
    if (response.data.draft) {
      state.composer.content = response.data.draft.content;
      state.composer.updatedAt = response.data.draft.updated_at;
      state.composer.saveState = "saved";
      state.composer.expanded = true;
    }
    state.ui.ready = true;
  } catch (error) {
    state.feed.errorMessage = readableError(error, "Memos is temporarily unavailable");
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function refreshFeed(append: boolean, sequence = ++feedSequence): Promise<boolean> {
  const offset = append ? state.feed.memos.length : 0;
  let response: PluginMethodResult<ListResult>;
  try {
    response = await bridge.call<PluginMethodResult<ListResult>>("memos.list", {
      query: state.feed.query,
      view: state.feed.view,
      tag: state.feed.tag,
      date: state.feed.date,
      utc_offset_minutes: utcOffsetMinutes,
      offset,
      limit: PAGE_SIZE,
    });
  } catch (error) {
    if (sequence !== feedSequence) return false;
    throw error;
  }
  if (sequence !== feedSequence) return false;
  state.feed.memos = append ? dedupeMemos([...state.feed.memos, ...response.data.memos]) : response.data.memos;
  state.feed.total = response.data.total;
  state.feed.hasMore = response.data.has_more;
  state.feed.loading = false;
  state.feed.errorMessage = "";
  return true;
}

async function refreshFacets(sequence = ++facetsSequence): Promise<boolean> {
  let response: PluginMethodResult<FacetResult>;
  try {
    response = await bridge.call<PluginMethodResult<FacetResult>>("memos.facets", {
      month: state.facets.month,
      utc_offset_minutes: utcOffsetMinutes,
    });
  } catch (error) {
    if (sequence !== facetsSequence) return false;
    throw error;
  }
  if (sequence !== facetsSequence) return false;
  applyFacets(response.data);
  return true;
}

async function reloadFeed(fallback: string): Promise<void> {
  const sequence = ++feedSequence;
  state.feed.loading = true;
  state.feed.errorMessage = "";
  await render();
  try {
    await refreshFeed(false, sequence);
  } catch (error) {
    state.feed.loading = false;
    state.feed.errorMessage = readableError(error, fallback);
  }
  await render();
}

function updateSearch(event: PluginUIActionEvent): void {
  if (event.event !== "input" && event.event !== "change") return;
  state.feed.query = (event.value ?? "").slice(0, 200);
  state.feed.loading = true;
  state.feed.errorMessage = "";
  const sequence = ++feedSequence;
  clearSearchTimer();
  searchTimer = setTimeout(() => {
    searchTimer = undefined;
    void performSearch(sequence);
  }, SEARCH_DELAY_MS);
  void render();
}

function submitSearch(event: PluginUIActionEvent): void {
  state.feed.query = String(event.form_data?.query ?? state.feed.query).slice(0, 200);
  const sequence = ++feedSequence;
  clearSearchTimer();
  void performSearch(sequence);
}

function clearSearch(): void {
  state.feed.query = "";
  const sequence = ++feedSequence;
  clearSearchTimer();
  void performSearch(sequence);
}

async function performSearch(sequence: number): Promise<void> {
  state.feed.loading = true;
  state.feed.errorMessage = "";
  await render();
  try {
    await refreshFeed(false, sequence);
  } catch (error) {
    if (sequence === feedSequence) {
      state.feed.loading = false;
      state.feed.errorMessage = readableError(error, "Search is temporarily unavailable");
    }
  }
  await render();
}

async function setView(value?: string): Promise<void> {
  const next: FeedView = value === "pinned" ? "pinned" : value === "archived" ? "archived" : "all";
  if (next === state.feed.view) return;
  if (!(await canLeaveEdit())) return;
  state.feed.view = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not update this view");
}

async function setTag(value?: string): Promise<void> {
  const next = (value ?? "").toLowerCase().slice(0, 40);
  if (next === state.feed.tag) return;
  if (!(await canLeaveEdit())) return;
  state.feed.tag = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not filter this tag");
}

async function setDate(value?: string): Promise<void> {
  const next = value ?? "";
  if (next === state.feed.date) return;
  if (!(await canLeaveEdit())) return;
  state.feed.date = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not filter this date");
}

async function clearFilters(): Promise<void> {
  if (!(await canLeaveEdit())) return;
  state.feed.query = "";
  state.feed.tag = "";
  state.feed.date = "";
  state.feed.view = "all";
  clearSearchTimer();
  await reloadFeed("Memos could not clear these filters");
}

async function moveMonth(direction: -1 | 1): Promise<void> {
  const [year, month] = state.facets.month.split("-").map(Number);
  const next = new Date(Date.UTC(year, month - 1 + direction, 1));
  state.facets.month = `${next.getUTCFullYear()}-${pad(next.getUTCMonth() + 1)}`;
  state.facets.loading = true;
  await render();
  try {
    await refreshFacets();
  } catch (error) {
    state.facets.loading = false;
    state.facets.errorMessage = readableError(error, "Calendar is temporarily unavailable");
  }
  await render();
}

async function loadMore(): Promise<void> {
  if (state.feed.loading || !state.feed.hasMore) return;
  const sequence = ++feedSequence;
  state.feed.loading = true;
  await render();
  try {
    await refreshFeed(true, sequence);
  } catch (error) {
    state.feed.loading = false;
    state.feed.errorMessage = readableError(error, "More memos could not be loaded");
  }
  await render();
}

function updateComposer(event: PluginUIActionEvent): void {
  if (event.event === "click") {
    state.composer.expanded = true;
    void render();
    return;
  }
  if (event.event !== "input" && event.event !== "change") return;
  const content = limitCharacters(event.value ?? "", MAX_CONTENT_CHARS);
  if (content === state.composer.content) return;
  state.composer.content = content;
  state.composer.expanded = true;
  state.composer.dirty = true;
  state.composer.revision += 1;
  state.composer.saveState = "unsaved";
  state.composer.errorMessage = "";
  state.ui.toast = "";
  scheduleDraftSave();
  void render();
}

async function expandComposer(): Promise<void> {
  state.composer.expanded = true;
  await renderWithFocus("composer");
}

function scheduleDraftSave(): void {
  clearDraftTimer();
  draftTimer = setTimeout(() => {
    draftTimer = undefined;
    void flushComposer();
  }, DRAFT_DELAY_MS);
}

async function flushComposer(): Promise<boolean> {
  clearDraftTimer();
  if (draftSaveInFlight) {
    const saved = await draftSaveInFlight;
    if (!saved) return false;
    return state.composer.dirty ? flushComposer() : true;
  }
  if (!state.composer.dirty) return true;
  const revision = state.composer.revision;
  const snapshot = state.composer.content;
  state.composer.dirty = false;
  state.composer.saveState = "saving";
  state.composer.errorMessage = "";
  await render();
  const currentSave = (async (): Promise<boolean> => {
    try {
      const response = await bridge.call<PluginMethodResult<{ draft: Draft | null }>>("memos.draft.save", { content: snapshot });
      if (state.composer.revision === revision) {
        state.composer.updatedAt = response.data.draft?.updated_at ?? "";
        state.composer.saveState = snapshot.trim() ? "saved" : "idle";
      } else {
        state.composer.dirty = true;
        scheduleDraftSave();
      }
      return true;
    } catch (error) {
      state.composer.dirty = true;
      state.composer.saveState = "error";
      state.composer.errorMessage = readableError(error, "Memos could not protect this draft");
      return false;
    }
  })();
  draftSaveInFlight = currentSave;
  const saved = await currentSave;
  if (draftSaveInFlight === currentSave) draftSaveInFlight = undefined;
  await render();
  return saved;
}

async function publishMemo(): Promise<void> {
  if (state.ui.busy || !state.composer.content.trim()) return;
  if (!(await flushComposer())) return;
  state.ui.busy = true;
  state.ui.toast = "";
  await render();
  try {
    const hadUnloadedRows = state.feed.hasMore;
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>("memos.publish", { content: state.composer.content });
    const reconcileFacets = applyMemoTransition(undefined, response.data.memo);
    state.composer = { content: "", dirty: false, revision: state.composer.revision + 1, saveState: "idle", errorMessage: "", updatedAt: "", expanded: false };
    showToast("Memo published");
    scheduleReconciliation(hadUnloadedRows, reconcileFacets);
  } catch (error) {
    state.composer.saveState = "error";
    state.composer.errorMessage = readableError(error, "Memos could not publish this memo");
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function beginEdit(id?: string): Promise<void> {
  if (!id || state.ui.pendingIds.has(id)) return;
  if (state.editing.id === id) {
    await renderWithFocus("none");
    return;
  }
  if (!(await canLeaveEdit())) return;
  const memo = memoById(id);
  if (!memo) return;
  state.editing = { id, content: memo.content, originalContent: memo.content, dirty: false, revision: state.editing.revision + 1, saveState: "saved", errorMessage: "" };
  state.ui.menuId = "";
  await render();
}

function updateEdit(event: PluginUIActionEvent): void {
  if (event.event !== "input" && event.event !== "change" || !state.editing.id) return;
  const content = limitCharacters(event.value ?? "", MAX_CONTENT_CHARS);
  if (content === state.editing.content) return;
  state.editing.content = content;
  state.editing.dirty = true;
  state.editing.revision += 1;
  state.editing.saveState = "unsaved";
  state.editing.errorMessage = "";
  scheduleEditSave();
  void render();
}

function scheduleEditSave(): void {
  clearEditTimer();
  editTimer = setTimeout(() => {
    editTimer = undefined;
    void flushEdit();
  }, EDIT_DELAY_MS);
}

async function flushEdit(): Promise<boolean> {
  clearEditTimer();
  if (editSaveInFlight) {
    const saved = await editSaveInFlight;
    if (!saved) return false;
    return state.editing.dirty ? flushEdit() : true;
  }
  if (!state.editing.id || !state.editing.dirty) return true;
  if (!state.editing.content.trim()) {
    state.editing.saveState = "error";
    state.editing.errorMessage = "A memo cannot be empty";
    await render();
    return false;
  }
  const id = state.editing.id;
  const content = state.editing.content;
  const revision = state.editing.revision;
  const previousMemo = memoById(id);
  const hadUnloadedRows = state.feed.hasMore;
  state.editing.dirty = false;
  state.editing.saveState = "saving";
  state.editing.errorMessage = "";
  await render();
  const currentSave = (async (): Promise<boolean> => {
    try {
      const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>("memos.update", { id, content });
      const reconcileFacets = applyMemoTransition(previousMemo, response.data.memo);
      if (state.editing.id === id && state.editing.revision === revision) {
        state.editing.content = response.data.memo.content;
        state.editing.originalContent = response.data.memo.content;
        state.editing.saveState = "saved";
      } else if (state.editing.id === id) {
        state.editing.dirty = true;
        scheduleEditSave();
      }
      scheduleReconciliation(hadUnloadedRows, reconcileFacets);
      return true;
    } catch (error) {
      if (state.editing.id === id) {
        state.editing.dirty = true;
        state.editing.saveState = "error";
        state.editing.errorMessage = readableError(error, "Memos could not save your changes");
      }
      return false;
    }
  })();
  editSaveInFlight = currentSave;
  const saved = await currentSave;
  if (editSaveInFlight === currentSave) editSaveInFlight = undefined;
  await render();
  return saved;
}

async function finishEdit(): Promise<void> {
  if (!(await flushEdit())) return;
  resetEditing();
  await render();
}

async function canLeaveEdit(): Promise<boolean> {
  if (!(await flushEdit())) return false;
  resetEditing();
  return true;
}

async function setPinned(id?: string): Promise<void> {
  const memo = id ? memoById(id) : undefined;
  if (!memo || state.ui.pendingIds.has(memo.id)) return;
  if (state.editing.id === memo.id && !(await flushEdit())) return;
  await mutateMemo(memo.id, "memos.setPinned", { id: memo.id, value: !memo.pinned }, "Memos could not change this pin");
}

async function setArchived(id?: string): Promise<void> {
  const memo = id ? memoById(id) : undefined;
  if (!memo || state.ui.pendingIds.has(memo.id)) return;
  if (state.editing.id === memo.id && !(await flushEdit())) return;
  state.ui.menuId = "";
  await mutateMemo(memo.id, "memos.setArchived", { id: memo.id, value: !memo.archived }, "Memos could not change this archive");
}

async function mutateMemo(id: string, method: string, params: Record<string, string | boolean>, fallback: string): Promise<void> {
  const previousMemo = memoById(id);
  if (!previousMemo) return;
  const hadUnloadedRows = state.feed.hasMore;
  state.ui.pendingIds.add(id);
  state.ui.toast = "";
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>(method, params);
    const reconcileFacets = applyMemoTransition(previousMemo, response.data.memo);
    scheduleReconciliation(hadUnloadedRows, reconcileFacets);
  } catch (error) {
    showToast(readableError(error, fallback));
  } finally {
    state.ui.pendingIds.delete(id);
    await render();
  }
}

async function toggleMemoMenu(id?: string): Promise<void> {
  if (!id) return;
  if (state.ui.menuId === id) {
    await closeMemoMenu();
    return;
  }
  state.ui.menuId = id;
  state.ui.focusId = id;
  state.ui.focusTarget = "menu-item";
  await render();
  state.ui.focusTarget = "none";
}

async function closeMemoMenu(): Promise<void> {
  if (!state.ui.menuId) return;
  state.ui.menuId = "";
  await renderWithFocus("menu-button");
}

async function requestDelete(id?: string): Promise<void> {
  if (!id) return;
  if (state.editing.id === id && !(await flushEdit())) return;
  state.ui.menuId = "";
  state.ui.deleteId = id;
  state.ui.focusId = id;
  await render();
}

async function cancelDelete(): Promise<void> {
  state.ui.deleteId = "";
  await renderWithFocus("menu-button");
}

async function confirmDelete(): Promise<void> {
  const id = state.ui.deleteId;
  if (!id || state.ui.busy) return;
  const previousMemo = memoById(id);
  if (!previousMemo) return;
  const hadUnloadedRows = state.feed.hasMore;
  state.ui.deleteId = "";
  state.ui.busy = true;
  await render();
  try {
    await bridge.call("memos.delete", { id });
    if (state.editing.id === id) resetEditing();
    state.ui.expandedIds.delete(id);
    const reconcileFacets = applyMemoTransition(previousMemo, undefined);
    showToast("Memo deleted");
    scheduleReconciliation(hadUnloadedRows, reconcileFacets);
  } catch (error) {
    showToast(readableError(error, "Memos could not delete this memo"));
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function toggleTask(event: PluginUIActionEvent): Promise<void> {
  if (event.event !== "change" && event.event !== "click") return;
  const [id, rawIndex] = (event.value ?? "").split(":");
  const memo = memoById(id);
  const index = Number(rawIndex);
  if (!memo || !Number.isInteger(index) || index < 0 || state.ui.pendingIds.has(id)) return;
  const content = toggleTaskMarker(memo.content, index, event.checked === true);
  if (content === memo.content) return;
  const hadUnloadedRows = state.feed.hasMore;
  state.ui.pendingIds.add(id);
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>("memos.update", { id, content });
    const reconcileFacets = applyMemoTransition(memo, response.data.memo);
    scheduleReconciliation(hadUnloadedRows, reconcileFacets);
  } catch (error) {
    showToast(readableError(error, "Memos could not update this task"));
  } finally {
    state.ui.pendingIds.delete(id);
    await render();
  }
}

async function toggleExpanded(id?: string): Promise<void> {
  if (!id) return;
  if (state.ui.expandedIds.has(id)) state.ui.expandedIds.delete(id);
  else state.ui.expandedIds.add(id);
  await render();
}

async function toggleExplorer(): Promise<void> {
  state.ui.drawerOpen = !state.ui.drawerOpen;
  await render();
}

async function closeExplorer(): Promise<void> {
  state.ui.drawerOpen = false;
  await render();
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    key: "memos-root",
    tag: "main",
    attributes: { class: `memos-app${state.ui.drawerOpen ? " explorer-open" : ""}` },
    children: [explorerScrim(), explorer(), workspace(), deleteDialog(), toast()],
  });
}

function explorerScrim(): PluginUIVNode | string {
  return state.ui.drawerOpen ? { type: "element", key: "explorer-scrim", tag: "button", attributes: { class: "explorer-scrim", type: "button", tabindex: -1, "aria-label": "Dismiss explorer", "data-redevplugin-action": "close-explorer" }, children: [] } : "";
}

function explorer(): PluginUIVNode {
  return { type: "element", key: "memos-explorer", tag: "aside", attributes: { class: "memos-explorer", "aria-label": "Explore memos", "data-redevplugin-escape-action": "close-explorer" }, children: [
    { type: "element", key: "explorer-header", tag: "header", attributes: { class: "explorer-header" }, children: [
      brand("explorer"),
      { type: "element", key: "explorer-close", tag: "button", attributes: { class: "icon-button explorer-close", type: "button", title: "Close explorer", "aria-label": "Close explorer", "data-redevplugin-action": "close-explorer" }, children: [{ type: "element", key: "explorer-close-icon", tag: "span", attributes: { class: "icon icon-close", "aria-hidden": true }, children: [] }] },
    ] },
    searchForm(),
    { type: "element", key: "view-nav", tag: "nav", attributes: { class: "view-nav", "aria-label": "Memo views" }, children: [
      viewButton("all", "All memos", "icon-inbox", state.facets.allTotal),
      viewButton("pinned", "Pinned", "icon-pin", state.facets.pinnedTotal),
      viewButton("archived", "Archived", "icon-archive", state.facets.archivedTotal),
    ] },
    calendar(),
    tagsPanel(),
  ] };
}

function brand(prefix: string): PluginUIVNode {
  return { type: "element", key: `${prefix}-brand`, tag: "div", attributes: { class: "brand-lockup" }, children: [
    { type: "element", key: `${prefix}-brand-mark`, tag: "span", attributes: { class: "brand-mark", "aria-hidden": true }, children: [] },
    { type: "element", key: `${prefix}-brand-name`, tag: "strong", children: ["Memos"] },
  ] };
}

function searchForm(): PluginUIVNode {
  return { type: "element", key: "search-form", tag: "form", attributes: { class: "search-form", "data-redevplugin-action": "search-memos" }, children: [
    { type: "element", key: "search-symbol", tag: "span", attributes: { class: "icon icon-search", "aria-hidden": true }, children: [] },
    { type: "element", key: "search-input", tag: "input", attributes: { type: "search", name: "query", value: state.feed.query, placeholder: "Search memos", autocomplete: "off", "aria-label": "Search memos", disabled: state.ui.busy, "data-redevplugin-action": "search-query" }, children: [] },
    state.feed.query ? { type: "element", key: "search-clear", tag: "button", attributes: { class: "search-clear", type: "button", title: "Clear search", "aria-label": "Clear search", "data-redevplugin-action": "clear-search" }, children: [{ type: "element", key: "search-clear-icon", tag: "span", attributes: { class: "icon icon-close", "aria-hidden": true }, children: [] }] } : "",
  ] };
}

function viewButton(value: FeedView, label: string, icon: string, count?: number): PluginUIVNode {
  return { type: "element", key: `view-${value}`, tag: "button", attributes: { type: "button", value, "aria-pressed": state.feed.view === value, disabled: state.ui.busy, "data-redevplugin-action": "filter-view" }, children: [
    { type: "element", key: `view-${value}-icon`, tag: "span", attributes: { class: `icon ${icon}`, "aria-hidden": true }, children: [] },
    { type: "element", key: `view-${value}-label`, tag: "span", children: [label] },
    count !== undefined ? { type: "element", key: `view-${value}-count`, tag: "small", children: [String(count)] } : "",
  ] };
}

function calendar(): PluginUIVNode {
  const dayCounts = new Map(state.facets.days.map((day) => [day.date, day.count]));
  return { type: "element", key: "calendar", tag: "section", attributes: { class: "calendar", "aria-label": "Memo calendar" }, children: [
    { type: "element", key: "calendar-heading", tag: "header", children: [
      { type: "element", key: "calendar-title", tag: "h2", children: [formatMonth(state.facets.month)] },
      { type: "element", key: "calendar-controls", tag: "div", children: [
        calendarMoveButton("previous-month", "Previous month", "icon-chevron-left"),
        calendarMoveButton("next-month", "Next month", "icon-chevron-right"),
      ] },
    ] },
    { type: "element", key: "calendar-weekdays", tag: "div", attributes: { class: "calendar-weekdays", "aria-hidden": true }, children: ["M", "T", "W", "T", "F", "S", "S"].map((label, index) => ({ type: "element", key: `weekday-${index}`, tag: "span", children: [label] })) },
    { type: "element", key: "calendar-grid", tag: "div", attributes: { class: "calendar-grid" }, children: calendarCells(state.facets.month).map<PluginUIVNode>((cell, index) => {
      if (!cell) return { type: "element", key: `calendar-blank-${index}`, tag: "span", attributes: { class: "calendar-blank", "aria-hidden": true }, children: [] } as PluginUIVNode;
      const count = dayCounts.get(cell.date) ?? 0;
      return { type: "element", key: `calendar-${cell.date}`, tag: "button", attributes: { class: `${count ? "has-memos " : ""}${cell.today ? "today" : ""}`.trim(), type: "button", value: cell.date, title: count ? `${count} ${count === 1 ? "memo" : "memos"}` : "No memos", "aria-label": `${formatCalendarDate(cell.date)}, ${count} ${count === 1 ? "memo" : "memos"}`, "aria-pressed": state.feed.date === cell.date, disabled: state.ui.busy, "data-redevplugin-action": "filter-date" }, children: [String(cell.day)] } as PluginUIVNode;
    }) },
    state.feed.date ? { type: "element", key: "calendar-clear", tag: "button", attributes: { class: "facet-clear", type: "button", value: "", "data-redevplugin-action": "filter-date" }, children: ["Clear date"] } : "",
    state.facets.errorMessage ? { type: "element", key: "calendar-error", tag: "p", attributes: { class: "facet-error", role: "status" }, children: [state.facets.errorMessage] } : "",
  ] };
}

function calendarMoveButton(action: string, label: string, icon: string): PluginUIVNode {
  return { type: "element", key: action, tag: "button", attributes: { class: "calendar-button", type: "button", title: label, "aria-label": label, disabled: state.facets.loading, "data-redevplugin-action": action }, children: [{ type: "element", key: `${action}-icon`, tag: "span", attributes: { class: `icon ${icon}`, "aria-hidden": true }, children: [] }] };
}

function tagsPanel(): PluginUIVNode {
  return { type: "element", key: "tags-panel", tag: "section", attributes: { class: "tags-panel", "aria-label": "Tags" }, children: [
    { type: "element", key: "tags-heading", tag: "header", children: [
      { type: "element", key: "tags-title", tag: "h2", children: ["Tags"] },
      state.feed.tag ? { type: "element", key: "tags-clear", tag: "button", attributes: { class: "facet-clear", type: "button", value: "", "data-redevplugin-action": "filter-tag" }, children: ["Clear"] } : "",
    ] },
    state.facets.tags.length ? { type: "element", key: "tag-list", tag: "ul", attributes: { class: "tag-list" }, children: state.facets.tags.map((facet) => ({ type: "element", key: `tag-${facet.tag}`, tag: "li", children: [
      { type: "element", key: `tag-${facet.tag}-button`, tag: "button", attributes: { type: "button", value: facet.tag, "aria-pressed": state.feed.tag === facet.tag, disabled: state.ui.busy, "data-redevplugin-action": "filter-tag" }, children: [
        { type: "element", key: `tag-${facet.tag}-hash`, tag: "span", attributes: { class: "tag-hash", "aria-hidden": true }, children: ["#"] },
        { type: "element", key: `tag-${facet.tag}-label`, tag: "span", children: [facet.tag] },
        { type: "element", key: `tag-${facet.tag}-count`, tag: "small", children: [String(facet.count)] },
      ] },
    ] })) } : { type: "element", key: "tags-empty", tag: "p", attributes: { class: "tags-empty" }, children: ["Tags in your memos appear here."] },
  ] };
}

function workspace(): PluginUIVNode {
  return { type: "element", key: "workspace", tag: "section", attributes: { class: "memos-workspace", "aria-label": "Memos timeline" }, children: [
    { type: "element", key: "mobile-header", tag: "header", attributes: { class: "mobile-header" }, children: [
      { type: "element", key: "mobile-menu", tag: "button", attributes: { class: "icon-button", type: "button", title: "Open explorer", "aria-label": "Open explorer", "aria-expanded": state.ui.drawerOpen, "data-redevplugin-action": "toggle-explorer" }, children: [{ type: "element", key: "mobile-menu-icon", tag: "span", attributes: { class: "icon icon-menu", "aria-hidden": true }, children: [] }] },
      brand("mobile"),
      { type: "element", key: "mobile-spacer", tag: "span", attributes: { class: "mobile-spacer", "aria-hidden": true }, children: [] },
    ] },
    { type: "element", key: "feed-shell", tag: "div", attributes: { class: "feed-shell" }, children: [composer(), feedHeader(), feedContent()] },
  ] };
}

function composer(): PluginUIVNode {
  const expanded = state.composer.expanded || Boolean(state.composer.content);
  return { type: "element", key: "memo-composer", tag: "section", attributes: { class: `memo-composer${expanded ? " expanded" : ""}`, "aria-label": "Create a memo" }, children: [
    { type: "element", key: "composer-main", tag: "div", attributes: { class: "composer-main" }, children: [
      { type: "element", key: "composer-avatar", tag: "span", attributes: { class: "composer-avatar", "aria-hidden": true }, children: ["M"] },
      { type: "element", key: "composer-copy", tag: "div", attributes: { class: "composer-copy" }, children: [
        { type: "element", key: "composer-input", tag: "textarea", attributes: { name: "content", value: state.composer.content, maxlength: MAX_CONTENT_CHARS, rows: expanded ? 7 : 2, placeholder: "What's on your mind?", "aria-label": "Memo content", autofocus: state.ui.focusTarget === "composer", disabled: state.ui.busy, "data-redevplugin-action": "composer-content" }, children: [] },
        !expanded ? { type: "element", key: "composer-expand", tag: "button", attributes: { class: "composer-expand", type: "button", "data-redevplugin-action": "expand-composer" }, children: ["Create a memo"] } : "",
      ] },
    ] },
    expanded ? { type: "element", key: "composer-footer", tag: "footer", attributes: { class: "composer-footer" }, children: [
      { type: "element", key: "composer-meta", tag: "div", attributes: { class: "composer-meta" }, children: [
        { type: "element", key: "markdown-label", tag: "span", attributes: { class: "markdown-label" }, children: ["Markdown"] },
        { type: "element", key: "composer-count", tag: "span", children: [`${characterCount(state.composer.content)} / ${MAX_CONTENT_CHARS}`] },
        draftStatus(),
      ] },
      { type: "element", key: "publish", tag: "button", attributes: { class: "primary-button", type: "button", disabled: state.ui.busy || !state.composer.content.trim() || state.composer.saveState === "saving", "data-redevplugin-action": "publish-memo" }, children: [state.ui.busy ? "Saving..." : "Save"] },
    ] } : "",
  ] };
}

function draftStatus(): PluginUIVNode | string {
  if (state.composer.saveState === "idle") return "";
  const label = state.composer.saveState === "saving" ? "Protecting draft..." : state.composer.saveState === "unsaved" ? "Draft pending" : state.composer.saveState === "saved" ? "Draft protected" : state.composer.errorMessage;
  return { type: "element", key: "draft-status", tag: "span", attributes: { class: `save-state ${state.composer.saveState}`, role: "status" }, children: [
    { type: "element", key: "draft-state-mark", tag: "span", attributes: { class: "state-dot", "aria-hidden": true }, children: [] },
    label,
    state.composer.saveState === "error" ? { type: "element", key: "retry-draft", tag: "button", attributes: { type: "button", "data-redevplugin-action": "retry-draft" }, children: ["Retry"] } : "",
  ] };
}

function feedHeader(): PluginUIVNode {
  const label = activeFeedLabel();
  const filtered = state.feed.view !== "all" || Boolean(state.feed.query || state.feed.tag || state.feed.date);
  return { type: "element", key: "feed-header", tag: "header", attributes: { class: "feed-header" }, children: [
    { type: "element", key: "feed-heading-copy", tag: "div", children: [
      { type: "element", key: "feed-title", tag: "h1", children: [label] },
      { type: "element", key: "feed-count", tag: "p", children: [state.feed.loading && !state.feed.memos.length ? "Updating timeline..." : `${state.feed.total} ${state.feed.total === 1 ? "memo" : "memos"}`] },
    ] },
    filtered ? { type: "element", key: "clear-filters", tag: "button", attributes: { class: "quiet-button", type: "button", "data-redevplugin-action": "clear-filters" }, children: ["Clear filters"] } : "",
  ] };
}

function feedContent(): PluginUIVNode {
  return { type: "element", key: "feed-content", tag: "div", attributes: { class: "memo-feed", "aria-busy": state.feed.loading }, children: [
    state.feed.errorMessage ? feedMessage("feed-error", "Timeline unavailable", state.feed.errorMessage, "error") : "",
    !state.feed.errorMessage && !state.feed.memos.length && state.feed.loading ? feedLoading() : "",
    !state.feed.errorMessage && !state.feed.memos.length && !state.feed.loading ? feedEmpty() : "",
    ...state.feed.memos.map(memoCard),
    state.feed.hasMore ? { type: "element", key: "load-more", tag: "button", attributes: { class: "load-more", type: "button", disabled: state.feed.loading || state.ui.busy, "data-redevplugin-action": "load-more-memos" }, children: [state.feed.loading ? "Loading..." : "Load more"] } : "",
  ] };
}

function memoCard(memo: Memo): PluginUIVNode {
  const editing = state.editing.id === memo.id;
  const pending = state.ui.pendingIds.has(memo.id);
  const expanded = state.ui.expandedIds.has(memo.id);
  const markdown = renderMarkdown(memo.content, `md-${memo.id}`, { expanded, taskMemoId: memo.id, interactiveTasks: !editing && !pending && !memo.archived });
  return { type: "element", key: `memo-${memo.id}`, tag: "article", attributes: { class: `memo-card${memo.pinned ? " pinned" : ""}${memo.archived ? " archived" : ""}${editing ? " editing" : ""}`, "aria-label": `Memo from ${formatDocumentDate(memo.created_at)}` }, children: [
    { type: "element", key: `memo-${memo.id}-header`, tag: "header", attributes: { class: "memo-card-header" }, children: [
      { type: "element", key: `memo-${memo.id}-identity`, tag: "div", attributes: { class: "memo-identity" }, children: [
        { type: "element", key: `memo-${memo.id}-avatar`, tag: "span", attributes: { class: "memo-avatar", "aria-hidden": true }, children: ["M"] },
        { type: "element", key: `memo-${memo.id}-byline`, tag: "div", children: [
          { type: "element", key: `memo-${memo.id}-author`, tag: "strong", children: [memo.archived ? "Archived memo" : "Memos"] },
          { type: "element", key: `memo-${memo.id}-date`, tag: "time", attributes: { title: formatDocumentDate(memo.created_at) }, children: [formatMemoDate(memo.created_at)] },
        ] },
      ] },
      { type: "element", key: `memo-${memo.id}-actions`, tag: "div", attributes: { class: "memo-card-actions" }, children: [
        { type: "element", key: `memo-${memo.id}-pin`, tag: "button", attributes: { class: `icon-button pin-button${memo.pinned ? " active" : ""}`, type: "button", value: memo.id, title: memo.pinned ? "Unpin memo" : "Pin memo", "aria-label": memo.pinned ? "Unpin memo" : "Pin memo", "aria-pressed": memo.pinned, disabled: pending || state.ui.busy, "data-redevplugin-action": "set-pinned" }, children: [{ type: "element", key: `memo-${memo.id}-pin-icon`, tag: "span", attributes: { class: "icon icon-pin", "aria-hidden": true }, children: [] }] },
        { type: "element", key: `memo-${memo.id}-more`, tag: "button", attributes: { class: "icon-button memo-more", type: "button", value: memo.id, title: "More memo actions", "aria-label": "More memo actions", "aria-expanded": state.ui.menuId === memo.id, autofocus: state.ui.focusTarget === "menu-button" && state.ui.focusId === memo.id && !state.ui.deleteId, disabled: pending || state.ui.busy, "data-redevplugin-action": "toggle-memo-menu" }, children: [{ type: "element", key: `memo-${memo.id}-more-icon`, tag: "span", attributes: { class: "icon icon-more", "aria-hidden": true }, children: [] }] },
        state.ui.menuId === memo.id ? memoMenu(memo) : "",
      ] },
    ] },
    editing ? editMemo(memo) : { type: "element", key: `memo-${memo.id}-body`, tag: "div", attributes: { class: "markdown-body" }, children: markdown.nodes },
    !editing && markdown.truncated ? { type: "element", key: `memo-${memo.id}-expand`, tag: "button", attributes: { class: "expand-content", type: "button", value: memo.id, "data-redevplugin-action": "toggle-expanded" }, children: [expanded ? "Show less" : "Show more"] } : "",
    memo.tags.length ? { type: "element", key: `memo-${memo.id}-tags`, tag: "footer", attributes: { class: "memo-tags" }, children: memo.tags.map((tag) => ({ type: "element", key: `memo-${memo.id}-tag-${tag}`, tag: "button", attributes: { type: "button", value: tag, "data-redevplugin-action": "filter-tag" }, children: [`#${tag}`] })) } : "",
  ] };
}

function editMemo(memo: Memo): PluginUIVNode {
  return { type: "element", key: `memo-${memo.id}-editor`, tag: "div", attributes: { class: "inline-editor" }, children: [
    { type: "element", key: `memo-${memo.id}-textarea`, tag: "textarea", attributes: { name: "content", value: state.editing.content, maxlength: MAX_CONTENT_CHARS, rows: 8, "aria-label": "Edit memo content", disabled: state.ui.busy, "data-redevplugin-action": "edit-content" }, children: [] },
    { type: "element", key: `memo-${memo.id}-edit-footer`, tag: "footer", children: [
      editStatus(),
      { type: "element", key: `memo-${memo.id}-edit-count`, tag: "span", children: [`${characterCount(state.editing.content)} / ${MAX_CONTENT_CHARS}`] },
      { type: "element", key: `memo-${memo.id}-done`, tag: "button", attributes: { class: "primary-button compact", type: "button", disabled: state.editing.saveState === "saving", "data-redevplugin-action": "finish-edit" }, children: ["Done"] },
    ] },
  ] };
}

function editStatus(): PluginUIVNode {
  const label = state.editing.saveState === "saving" ? "Saving..." : state.editing.saveState === "unsaved" ? "Unsaved" : state.editing.saveState === "saved" ? "Saved" : state.editing.errorMessage;
  return { type: "element", key: "edit-save-indicator", tag: "span", attributes: { class: `save-state ${state.editing.saveState} save-indicator`, role: "status" }, children: [
    { type: "element", key: "edit-state-dot", tag: "span", attributes: { class: "state-dot", "aria-hidden": true }, children: [] },
    label,
    state.editing.saveState === "error" ? { type: "element", key: "retry-edit", tag: "button", attributes: { type: "button", "data-redevplugin-action": "retry-edit" }, children: ["Retry"] } : "",
  ] };
}

function memoMenu(memo: Memo): PluginUIVNode {
  return { type: "element", key: `memo-${memo.id}-menu`, tag: "div", attributes: { class: "memo-menu", role: "menu", "aria-label": "Memo actions", "data-redevplugin-escape-action": "close-memo-menu" }, children: [
    menuButton(memo.id, "edit-memo", "Edit", "icon-edit", true),
    menuButton(memo.id, "set-archived", memo.archived ? "Restore" : "Archive", "icon-archive"),
    menuButton(memo.id, "request-delete", "Delete", "icon-trash", false, true),
  ] };
}

function menuButton(id: string, action: string, label: string, icon: string, autofocus = false, danger = false): PluginUIVNode {
  return { type: "element", key: `memo-${id}-menu-${action}`, tag: "button", attributes: { class: danger ? "danger" : "", type: "button", role: "menuitem", value: id, autofocus: autofocus && state.ui.focusTarget === "menu-item", "data-redevplugin-action": action }, children: [
    { type: "element", key: `memo-${id}-menu-${action}-icon`, tag: "span", attributes: { class: `icon ${icon}`, "aria-hidden": true }, children: [] },
    label,
  ] };
}

function deleteDialog(): PluginUIVNode | string {
  if (!state.ui.deleteId) return "";
  return { type: "element", key: "delete-layer", tag: "div", attributes: { class: "dialog-layer" }, children: [
    { type: "element", key: "delete-scrim", tag: "button", attributes: { class: "dialog-scrim", type: "button", tabindex: -1, "aria-label": "Cancel delete", "data-redevplugin-action": "cancel-delete" }, children: [] },
    { type: "element", key: "delete-dialog", tag: "section", attributes: { class: "delete-dialog", role: "dialog", "aria-modal": true, "aria-label": "Delete memo", "data-redevplugin-escape-action": "cancel-delete" }, children: [
      { type: "element", key: "delete-mark", tag: "span", attributes: { class: "delete-mark", "aria-hidden": true }, children: ["!"] },
      { type: "element", key: "delete-copy", tag: "div", children: [
        { type: "element", key: "delete-title", tag: "h2", children: ["Delete this memo?"] },
        { type: "element", key: "delete-message", tag: "p", children: ["This action cannot be undone."] },
      ] },
      { type: "element", key: "delete-actions", tag: "div", attributes: { class: "delete-actions" }, children: [
        { type: "element", key: "delete-cancel", tag: "button", attributes: { class: "quiet-button", type: "button", autofocus: true, "data-redevplugin-action": "cancel-delete" }, children: ["Keep memo"] },
        { type: "element", key: "delete-confirm", tag: "button", attributes: { class: "danger-button", type: "button", "data-redevplugin-action": "confirm-delete" }, children: ["Delete memo"] },
      ] },
    ] },
  ] };
}

function feedLoading(): PluginUIVNode {
  return { type: "element", key: "feed-loading", tag: "div", attributes: { class: "feed-loading", role: "status" }, children: [
    { type: "element", key: "loading-line-1", tag: "span", children: [] },
    { type: "element", key: "loading-line-2", tag: "span", children: [] },
    { type: "element", key: "loading-line-3", tag: "span", children: [] },
  ] };
}

function feedEmpty(): PluginUIVNode {
  const filtered = Boolean(state.feed.query || state.feed.tag || state.feed.date || state.feed.view !== "all");
  return feedMessage("feed-empty", filtered ? "No matching memos" : "Your timeline is ready", filtered ? "Try clearing a filter or searching for something else." : "Write above and save your first memo. The editor is always within reach.", "empty");
}

function feedMessage(key: string, title: string, message: string, variant: string): PluginUIVNode {
  return { type: "element", key, tag: "section", attributes: { class: `feed-message ${variant}`, role: variant === "error" ? "status" : "region" }, children: [
    { type: "element", key: `${key}-mark`, tag: "span", attributes: { class: "message-mark", "aria-hidden": true }, children: [variant === "error" ? "!" : "+"] },
    { type: "element", key: `${key}-copy`, tag: "div", children: [
      { type: "element", key: `${key}-title`, tag: "h2", children: [title] },
      { type: "element", key: `${key}-message`, tag: "p", children: [message] },
    ] },
  ] };
}

function toast(): PluginUIVNode | string {
  return state.ui.toast ? { type: "element", key: "memos-toast", tag: "div", attributes: { class: "memos-toast", role: "status" }, children: [state.ui.toast] } : "";
}

function applyList(result: ListResult): void {
  state.feed.memos = result.memos;
  state.feed.total = result.total;
  state.feed.hasMore = result.has_more;
  state.feed.loading = false;
  state.feed.errorMessage = "";
}

function applyFacets(result: FacetResult): void {
  state.facets.month = result.month;
  state.facets.tags = result.tags;
  state.facets.days = result.days;
  state.facets.allTotal = result.all_total;
  state.facets.pinnedTotal = result.pinned_total;
  state.facets.archivedTotal = result.archived_total;
  state.facets.loading = false;
  state.facets.errorMessage = "";
}

function applyMemoTransition(previous: Memo | undefined, next: Memo | undefined): boolean {
  const previousActive = Boolean(previous && !previous.archived);
  const nextActive = Boolean(next && !next.archived);
  const previousPinned = Boolean(previous && !previous.archived && previous.pinned);
  const nextPinned = Boolean(next && !next.archived && next.pinned);
  const previousArchived = Boolean(previous?.archived);
  const nextArchived = Boolean(next?.archived);

  state.facets.allTotal = adjustedCount(state.facets.allTotal, previousActive, nextActive);
  state.facets.pinnedTotal = adjustedCount(state.facets.pinnedTotal, previousPinned, nextPinned);
  state.facets.archivedTotal = adjustedCount(state.facets.archivedTotal, previousArchived, nextArchived);
  applyFeedTransition(previous, next);
  const tagFacetWasCapped = state.facets.tags.length >= 64;
  const tagsChanged = applyTagTransition(previousActive ? previous?.tags ?? [] : [], nextActive ? next?.tags ?? [] : []);
  applyDayTransition(previousActive ? memoFacetDate(previous) : "", nextActive ? memoFacetDate(next) : "");
  return tagsChanged && tagFacetWasCapped;
}

function applyFeedTransition(previous: Memo | undefined, next: Memo | undefined): void {
  const previousMatches = Boolean(previous && memoMatchesCurrentFeed(previous));
  const nextMatches = Boolean(next && memoMatchesCurrentFeed(next));
  state.feed.total = adjustedCount(state.feed.total, previousMatches, nextMatches);

  const previousIndex = previous ? state.feed.memos.findIndex((memo) => memo.id === previous.id) : -1;
  const capacity = Math.max(PAGE_SIZE, state.feed.memos.length);
  const transitionIds = new Set([previous?.id, next?.id].filter((id): id is string => Boolean(id)));
  const memos = state.feed.memos.filter((memo) => !transitionIds.has(memo.id));
  if (next && nextMatches && (previousIndex >= 0 || !previous || !previousMatches)) memos.push(next);
  memos.sort(compareMemos);
  state.feed.memos = memos.slice(0, capacity);
  state.feed.hasMore = state.feed.memos.length < state.feed.total;
}

function memoMatchesCurrentFeed(memo: Memo): boolean {
  if (state.feed.view === "archived" ? !memo.archived : memo.archived) return false;
  if (state.feed.view === "pinned" && !memo.pinned) return false;
  const query = state.feed.query.trim().toLowerCase();
  if (query && !memo.content.toLowerCase().includes(query)) return false;
  if (state.feed.tag && !memo.tags.includes(state.feed.tag)) return false;
  return !state.feed.date || memoFacetDate(memo) === state.feed.date;
}

function compareMemos(left: Memo, right: Memo): number {
  if (left.pinned !== right.pinned) return left.pinned ? -1 : 1;
  const created = right.created_at.localeCompare(left.created_at);
  return created || right.id.localeCompare(left.id);
}

function applyTagTransition(previousTags: string[], nextTags: string[]): boolean {
  const previous = new Set(previousTags);
  const next = new Set(nextTags);
  const changed = previous.size !== next.size || [...previous].some((tag) => !next.has(tag));
  if (!changed) return false;

  const counts = new Map(state.facets.tags.map((facet) => [facet.tag, facet.count]));
  for (const tag of new Set([...previous, ...next])) {
    const count = (counts.get(tag) ?? 0) - Number(previous.has(tag)) + Number(next.has(tag));
    if (count > 0) counts.set(tag, count);
    else counts.delete(tag);
  }
  state.facets.tags = [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((left, right) => right.count - left.count || left.tag.localeCompare(right.tag))
    .slice(0, 64);
  return true;
}

function applyDayTransition(previousDate: string, nextDate: string): void {
  if (previousDate === nextDate) return;
  const counts = new Map(state.facets.days.map((day) => [day.date, day.count]));
  for (const [date, delta] of [[previousDate, -1], [nextDate, 1]] as const) {
    if (!date.startsWith(`${state.facets.month}-`)) continue;
    const count = (counts.get(date) ?? 0) + delta;
    if (count > 0) counts.set(date, count);
    else counts.delete(date);
  }
  state.facets.days = [...counts.entries()]
    .map(([date, count]) => ({ date, count }))
    .sort((left, right) => left.date.localeCompare(right.date));
}

function memoFacetDate(memo: Memo | undefined): string {
  if (!memo) return "";
  const createdAt = new Date(memo.created_at);
  if (Number.isNaN(createdAt.getTime())) return "";
  const shifted = new Date(createdAt.getTime() + utcOffsetMinutes * 60_000);
  return `${shifted.getUTCFullYear()}-${pad(shifted.getUTCMonth() + 1)}-${pad(shifted.getUTCDate())}`;
}

function adjustedCount(current: number, previous: boolean, next: boolean): number {
  return Math.max(0, current - Number(previous) + Number(next));
}

function scheduleReconciliation(feed: boolean, facets: boolean): void {
  if (!feed && !facets) return;
  void (async () => {
    let changed = false;
    if (feed) {
      try {
        changed = await refreshFeed(false) || changed;
      } catch {
        // The mutation result already projected a usable local state.
      }
    }
    if (facets) {
      try {
        changed = await refreshFacets() || changed;
      } catch {
        // A future bootstrap or month change will reconcile capped tag facets.
      }
    }
    if (changed) await render();
  })();
}

function memoById(id: string): Memo | undefined {
  return state.feed.memos.find((memo) => memo.id === id);
}

function resetEditing(): void {
  clearEditTimer();
  state.editing = { id: "", content: "", originalContent: "", dirty: false, revision: state.editing.revision, saveState: "idle", errorMessage: "" };
}

function dedupeMemos(memos: Memo[]): Memo[] {
  const seen = new Set<string>();
  return memos.filter((memo) => !seen.has(memo.id) && Boolean(seen.add(memo.id)));
}

async function renderWithFocus(target: FocusTarget): Promise<void> {
  state.ui.focusTarget = target;
  await render();
  state.ui.focusTarget = "none";
}

function activeFeedLabel(): string {
  if (state.feed.query) return `Search: ${state.feed.query}`;
  if (state.feed.tag) return `#${state.feed.tag}`;
  if (state.feed.date) return formatCalendarDate(state.feed.date);
  if (state.feed.view === "pinned") return "Pinned";
  if (state.feed.view === "archived") return "Archived";
  return "Timeline";
}

function currentMonth(): string {
  const now = new Date();
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}`;
}

function calendarCells(month: string): Array<{ date: string; day: number; today: boolean } | null> {
  const [year, monthNumber] = month.split("-").map(Number);
  const days = new Date(Date.UTC(year, monthNumber, 0)).getUTCDate();
  const weekday = new Date(Date.UTC(year, monthNumber - 1, 1)).getUTCDay();
  const leading = (weekday + 6) % 7;
  const today = localDateKey(new Date());
  const cells: Array<{ date: string; day: number; today: boolean } | null> = Array.from({ length: leading }, () => null);
  for (let day = 1; day <= days; day += 1) {
    const date = `${year}-${pad(monthNumber)}-${pad(day)}`;
    cells.push({ date, day, today: date === today });
  }
  return cells;
}

function localDateKey(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function formatMonth(value: string): string {
  const [year, month] = value.split("-").map(Number);
  return new Intl.DateTimeFormat("en", { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(Date.UTC(year, month - 1, 1)));
}

function formatCalendarDate(value: string): string {
  const [year, month, day] = value.split("-").map(Number);
  return new Intl.DateTimeFormat("en", { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(Date.UTC(year, month - 1, day)));
}

function formatDocumentDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Recently";
  return new Intl.DateTimeFormat("en", { month: "long", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }).format(date);
}

function formatMemoDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Just now";
  const now = new Date();
  const delta = now.getTime() - date.getTime();
  if (delta >= 0 && delta < 60_000) return "Just now";
  if (delta >= 0 && delta < 3_600_000) return `${Math.max(1, Math.floor(delta / 60_000))}m`;
  if (date.toDateString() === now.toDateString()) return new Intl.DateTimeFormat("en", { hour: "numeric", minute: "2-digit" }).format(date);
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(date);
}

function limitCharacters(value: string, maximum: number): string {
  return Array.from(value).slice(0, maximum).join("");
}

function characterCount(value: string): number {
  return Array.from(value).length;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

function clearTimers(): void {
  clearDraftTimer();
  clearEditTimer();
  clearSearchTimer();
  if (toastTimer !== undefined) clearTimeout(toastTimer);
  toastTimer = undefined;
}

function showToast(message: string): void {
  if (toastTimer !== undefined) clearTimeout(toastTimer);
  state.ui.toast = message;
  toastTimer = setTimeout(() => {
    toastTimer = undefined;
    if (state.ui.toast !== message) return;
    state.ui.toast = "";
    void render();
  }, 2_600);
}

function clearDraftTimer(): void {
  if (draftTimer !== undefined) clearTimeout(draftTimer);
  draftTimer = undefined;
}

function clearEditTimer(): void {
  if (editTimer !== undefined) clearTimeout(editTimer);
  editTimer = undefined;
}

function clearSearchTimer(): void {
  if (searchTimer !== undefined) clearTimeout(searchTimer);
  searchTimer = undefined;
}

function readableError(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message.trim() : "";
  if (!message || /PLUGIN_|runtime|broker|permission|rpc|worker|wasm/i.test(message)) return fallback;
  return message;
}
