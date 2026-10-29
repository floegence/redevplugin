import { For, Show, createEffect, createMemo, createSignal, type JSX } from "solid-js";
import { createMutable } from "solid-js/store";
import { render as mount } from "solid-js/web";
import { connectTheme } from "./theme.js";
import { PluginBridgeClient, PluginBridgeError, type PluginMethodResult } from "../../packages/redevplugin-ui/src/plugin.js";
import { createMarkdownIdentity, renderMarkdown, toggleTaskMarker, type MarkdownIdentity } from "./memos-markdown.js";

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
type ListResult = { memos: Memo[]; next_cursor: string | null };
type BootstrapResult = ListResult & { draft: Draft | null; facets: FacetResult };
type DeleteResult = { deleted_id: string };
type SaveState = "idle" | "unsaved" | "saving" | "saved" | "error";
type FeedView = "all" | "pinned" | "archived";
type FocusTarget = "none" | "composer" | "menu-item" | "menu-button";
type SyncState = "ready" | "syncing" | "error";
type UnknownMutationReconciliation =
  | { kind: "delete" }
  | { kind: "publish"; content: string };

type MemosState = {
  feed: {
    memos: Memo[];
    hasMore: boolean;
    nextCursor: string | null;
    windowed: boolean;
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
    deleteError: string;
    syncState: SyncState;
    syncError: string;
    focusTarget: FocusTarget;
    focusId: string;
    toast: string;
    expandedIds: Set<string>;
    pendingIds: Set<string>;
  };
};

const PAGE_SIZE = 10;
const MAX_VISIBLE_MEMOS = PAGE_SIZE;
const DRAFT_DELAY_MS = 500;
const EDIT_DELAY_MS = 700;
const SEARCH_DELAY_MS = 250;
const MAX_CONTENT_CHARS = 20_000;
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const utcOffsetMinutes = -new Date().getTimezoneOffset();
const state = createMutable<MemosState>({
  feed: { memos: [], hasMore: false, nextCursor: null, windowed: false, query: "", view: "all", tag: "", date: "", loading: false, errorMessage: "" },
  composer: { content: "", dirty: false, revision: 0, saveState: "idle", errorMessage: "", updatedAt: "", expanded: false },
  facets: { month: currentMonth(), tags: [], days: [], allTotal: 0, pinnedTotal: 0, archivedTotal: 0, loading: false, errorMessage: "" },
  editing: { id: "", content: "", originalContent: "", dirty: false, revision: 0, saveState: "idle", errorMessage: "" },
  ui: { ready: false, busy: false, drawerOpen: false, menuId: "", deleteId: "", deleteError: "", syncState: "ready", syncError: "", focusTarget: "none", focusId: "", toast: "", expandedIds: new Set(), pendingIds: new Set() },
});
const markdownIdentities = new Map<string, MarkdownIdentity>();

let draftTimer: ReturnType<typeof setTimeout> | undefined;
let editTimer: ReturnType<typeof setTimeout> | undefined;
let searchTimer: ReturnType<typeof setTimeout> | undefined;
let toastTimer: ReturnType<typeof setTimeout> | undefined;
let draftSaveInFlight: Promise<boolean> | undefined;
let editSaveInFlight: Promise<boolean> | undefined;
let feedSequence = 0;
let facetsSequence = 0;
let unknownMutationReconciliation: UnknownMutationReconciliation | undefined;
let disposed = false;

const [revision, setRevision] = createSignal(0);
connectTheme(bridge);
document.body.replaceChildren();
const unmount = mount(() => <MemosApp />, document.body);
const initialization = initialize();
bridge.onBeforeClose(async () => {
  await initialization.catch(() => undefined);
  if (state.ui.busy || state.ui.syncState !== "ready") return false;
  const [draftSaved, editSaved] = await Promise.all([flushComposer(), flushEdit()]);
  return draftSaved && editSaved;
});

bridge.onLifecycle(async (event) => {
  if (event.type === "dispose") {
    disposed = true;
    clearTimers();
    await initialization.catch(() => undefined);
    await Promise.all([flushComposer(), flushEdit()]);
    unmount();
  } else if (event.type === "hidden") {
    await Promise.all([flushComposer(), flushEdit()]);
  }
});

void initialization.catch(reportUnhandledFailure);

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

async function refreshFeed(advance: boolean, sequence = ++feedSequence): Promise<boolean> {
  let response: PluginMethodResult<ListResult>;
  try {
    response = await bridge.call<PluginMethodResult<ListResult>>("memos.list", {
      query: state.feed.query,
      view: state.feed.view,
      tag: state.feed.tag,
      date: state.feed.date,
      utc_offset_minutes: utcOffsetMinutes,
      cursor: advance ? state.feed.nextCursor : null,
      limit: PAGE_SIZE,
    });
  } catch (error) {
    if (sequence !== feedSequence) return false;
    throw error;
  }
  if (sequence !== feedSequence) return false;
  state.feed.memos = response.data.memos.slice(0, MAX_VISIBLE_MEMOS);
  state.feed.nextCursor = response.data.next_cursor;
  state.feed.hasMore = response.data.next_cursor !== null;
  state.feed.windowed = advance;
  retainVisibleMemoState();
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

async function reloadFeed(defaultMessage: string): Promise<void> {
  const sequence = ++feedSequence;
  state.feed.loading = true;
  state.feed.errorMessage = "";
  await render();
  try {
    await refreshFeed(false, sequence);
  } catch (error) {
    state.feed.loading = false;
    state.feed.errorMessage = readableError(error, defaultMessage);
  }
  await render();
}

function updateSearch(value: string): void {
  if (interactionBlocked()) return;
  state.feed.query = value.slice(0, 200);
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

function submitSearch(): void {
  if (interactionBlocked()) return;
  state.feed.query = state.feed.query.slice(0, 200);
  const sequence = ++feedSequence;
  clearSearchTimer();
  void performSearch(sequence);
}

function clearSearch(): void {
  if (interactionBlocked()) return;
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
  if (interactionBlocked()) return;
  const next: FeedView = value === "pinned" ? "pinned" : value === "archived" ? "archived" : "all";
  if (next === state.feed.view) return;
  if (!(await canLeaveEdit())) return;
  state.feed.view = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not update this view");
}

async function setTag(value?: string): Promise<void> {
  if (interactionBlocked()) return;
  const next = (value ?? "").toLowerCase().slice(0, 40);
  if (next === state.feed.tag) return;
  if (!(await canLeaveEdit())) return;
  state.feed.tag = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not filter this tag");
}

async function setDate(value?: string): Promise<void> {
  if (interactionBlocked()) return;
  const next = value ?? "";
  if (next === state.feed.date) return;
  if (!(await canLeaveEdit())) return;
  state.feed.date = next;
  state.ui.drawerOpen = false;
  await reloadFeed("Memos could not filter this date");
}

async function clearFilters(): Promise<void> {
  if (interactionBlocked()) return;
  if (!(await canLeaveEdit())) return;
  state.feed.query = "";
  state.feed.tag = "";
  state.feed.date = "";
  state.feed.view = "all";
  clearSearchTimer();
  await reloadFeed("Memos could not clear these filters");
}

async function moveMonth(direction: -1 | 1): Promise<void> {
  if (interactionBlocked()) return;
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

async function loadOlder(): Promise<void> {
  if (interactionBlocked() || state.feed.loading || !state.feed.hasMore) return;
  if (state.ui.deleteId || !(await canLeaveEdit())) return;
  const sequence = ++feedSequence;
  state.feed.loading = true;
  await render();
  try {
    await refreshFeed(true, sequence);
  } catch (error) {
    state.feed.loading = false;
    state.feed.errorMessage = readableError(error, "Older memos could not be loaded");
  }
  await render();
}

async function showNewest(): Promise<void> {
  if (interactionBlocked() || state.feed.loading || !state.feed.windowed) return;
  if (state.ui.deleteId || !(await canLeaveEdit())) return;
  await reloadFeed("The newest memos could not be loaded");
}

function updateComposer(value: string): void {
  if (interactionBlocked()) return;
  const content = limitCharacters(value, MAX_CONTENT_CHARS);
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

function scheduleDraftSave(): void {
  clearDraftTimer();
  draftTimer = setTimeout(() => {
    draftTimer = undefined;
    void flushComposer();
  }, DRAFT_DELAY_MS);
}

async function flushComposer(): Promise<boolean> {
  if (state.ui.syncState !== "ready") return false;
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
  if (interactionBlocked() || !state.composer.content.trim()) return;
  if (!(await flushComposer())) return;
  const content = state.composer.content;
  state.ui.busy = true;
  state.ui.toast = "";
  await render();
  let outcomeUnknown = false;
  try {
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>("memos.publish", { content });
    const reconcileFacets = applyMemoTransition(undefined, response.data.memo);
    state.composer = { content: "", dirty: false, revision: state.composer.revision + 1, saveState: "idle", errorMessage: "", updatedAt: "", expanded: false };
    showToast("Memo published");
    scheduleReconciliation(true, reconcileFacets);
  } catch (error) {
    if (error instanceof PluginBridgeError && error.mutationOutcome === "unknown") {
      state.composer.saveState = "saving";
      state.composer.errorMessage = "";
      state.ui.syncState = "syncing";
      unknownMutationReconciliation = { kind: "publish", content };
      outcomeUnknown = true;
    } else {
      state.composer.saveState = "error";
      state.composer.errorMessage = readableError(error, "Memos could not publish this memo");
    }
  } finally {
    state.ui.busy = false;
    await render();
  }
  if (outcomeUnknown) await reconcileUnknownMutationOutcome();
}

async function beginEdit(id?: string): Promise<void> {
  if (interactionBlocked() || !id || state.ui.pendingIds.has(id)) return;
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

function updateEdit(value: string): void {
  if (interactionBlocked() || !state.editing.id) return;
  const content = limitCharacters(value, MAX_CONTENT_CHARS);
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
  if (state.ui.syncState !== "ready") return false;
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
      scheduleReconciliation(true, reconcileFacets);
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
  if (interactionBlocked()) return;
  const memo = id ? memoById(id) : undefined;
  if (!memo || state.ui.pendingIds.has(memo.id)) return;
  if (state.editing.id === memo.id && !(await flushEdit())) return;
  await mutateMemo(memo.id, "memos.setPinned", { id: memo.id, value: !memo.pinned }, "Memos could not change this pin");
}

async function setArchived(id?: string): Promise<void> {
  if (interactionBlocked()) return;
  const memo = id ? memoById(id) : undefined;
  if (!memo || state.ui.pendingIds.has(memo.id)) return;
  if (state.editing.id === memo.id && !(await flushEdit())) return;
  state.ui.menuId = "";
  await mutateMemo(memo.id, "memos.setArchived", { id: memo.id, value: !memo.archived }, "Memos could not change this archive");
}

async function mutateMemo(id: string, method: string, params: Record<string, string | boolean>, defaultMessage: string): Promise<void> {
  if (interactionBlocked()) return;
  const previousMemo = memoById(id);
  if (!previousMemo) return;
  state.ui.pendingIds.add(id);
  state.ui.toast = "";
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>(method, params);
    const reconcileFacets = applyMemoTransition(previousMemo, response.data.memo);
    scheduleReconciliation(true, reconcileFacets);
  } catch (error) {
    showToast(readableError(error, defaultMessage));
  } finally {
    state.ui.pendingIds.delete(id);
    await render();
  }
}

async function toggleMemoMenu(id?: string): Promise<void> {
  if (interactionBlocked() || !id) return;
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
  if (interactionBlocked() || !id) return;
  if (state.editing.id === id && !(await flushEdit())) return;
  state.ui.menuId = "";
  state.ui.deleteId = id;
  state.ui.deleteError = "";
  state.ui.focusId = id;
  await render();
}

async function cancelDelete(): Promise<void> {
  if (state.ui.busy) return;
  state.ui.deleteId = "";
  state.ui.deleteError = "";
  await renderWithFocus("menu-button");
}

async function confirmDelete(): Promise<void> {
  const id = state.ui.deleteId;
  if (!id || state.ui.busy) return;
  const previousMemo = memoById(id);
  if (!previousMemo) return;
  state.ui.deleteError = "";
  state.ui.busy = true;
  await render();
  let outcomeUnknown = false;
  try {
    const response = await bridge.call<PluginMethodResult<DeleteResult>>("memos.delete", { id });
    if (response.data.deleted_id !== id) {
      throw new PluginBridgeError(
        "PLUGIN_CONTRACT_MISMATCH",
        "Memos delete returned a mismatched memo identifier",
        undefined,
        undefined,
        "unknown",
      );
    }
    if (state.editing.id === id) resetEditing();
    state.ui.expandedIds.delete(id);
    const reconcileFacets = applyMemoTransition(previousMemo, undefined);
    state.ui.deleteId = "";
    showToast("Memo deleted");
    scheduleReconciliation(true, reconcileFacets);
  } catch (error) {
    if (error instanceof PluginBridgeError && error.mutationOutcome === "unknown") {
      state.ui.deleteId = "";
      state.ui.deleteError = "";
      state.ui.syncState = "syncing";
      unknownMutationReconciliation = { kind: "delete" };
      outcomeUnknown = true;
    } else {
      state.ui.deleteError = readableError(error, "Memos could not delete this memo");
    }
  } finally {
    state.ui.busy = false;
    await render();
  }
  if (outcomeUnknown) await reconcileUnknownMutationOutcome();
}

async function reconcileUnknownMutationOutcome(): Promise<void> {
  const reconciliation = unknownMutationReconciliation;
  if (!reconciliation || state.ui.syncState === "ready" || state.ui.busy) return;
  const feedRequest = ++feedSequence;
  const facetsRequest = ++facetsSequence;
  state.ui.syncState = "syncing";
  state.ui.syncError = "";
  state.ui.busy = true;
  state.feed.loading = true;
  state.facets.loading = true;
  await render();
  try {
    if (reconciliation.kind === "publish") {
      const [bootstrap, feedApplied] = await Promise.all([
        bridge.call<PluginMethodResult<BootstrapResult>>("memos.bootstrap", {
          month: state.facets.month,
          utc_offset_minutes: utcOffsetMinutes,
        }),
        refreshFeed(false, feedRequest),
      ]);
      if (!feedApplied || facetsRequest !== facetsSequence) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Memos publish reconciliation was superseded");
      }
      applyFacets(bootstrap.data.facets);
      if (bootstrap.data.draft === null) {
        state.composer = { content: "", dirty: false, revision: state.composer.revision + 1, saveState: "idle", errorMessage: "", updatedAt: "", expanded: false };
        showToast("Memo published");
      } else if (bootstrap.data.draft.content === reconciliation.content) {
        state.composer.content = bootstrap.data.draft.content;
        state.composer.dirty = false;
        state.composer.saveState = "saved";
        state.composer.errorMessage = "";
        state.composer.updatedAt = bootstrap.data.draft.updated_at;
        state.composer.expanded = true;
        showToast("Memo was not published");
      } else {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Memos publish reconciliation returned an unexpected draft");
      }
    } else {
      const [feedApplied, facetsApplied] = await Promise.all([
        refreshFeed(false, feedRequest),
        refreshFacets(facetsRequest),
      ]);
      if (!feedApplied || !facetsApplied) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Memos delete reconciliation was superseded");
      }
      showToast("Memos refreshed");
    }
    unknownMutationReconciliation = undefined;
    state.ui.syncState = "ready";
  } catch (error) {
    state.feed.loading = false;
    state.facets.loading = false;
    state.ui.syncState = "error";
    state.ui.syncError = readableError(error, reconciliation.kind === "publish"
      ? "Memos could not confirm the publish result"
      : "Memos could not confirm the delete result");
  } finally {
    state.ui.busy = false;
    await render();
  }
}

async function toggleTask(value: string, checked: boolean): Promise<void> {
  if (interactionBlocked()) return;
  const [id, rawIndex] = value.split(":");
  const memo = memoById(id);
  const index = Number(rawIndex);
  if (!memo || !Number.isInteger(index) || index < 0 || state.ui.pendingIds.has(id)) return;
  const content = toggleTaskMarker(memo.content, index, checked);
  if (content === memo.content) return;
  state.ui.pendingIds.add(id);
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<{ memo: Memo }>>("memos.update", { id, content });
    const reconcileFacets = applyMemoTransition(memo, response.data.memo);
    scheduleReconciliation(true, reconcileFacets);
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
  if (!disposed) setRevision((value) => value + 1);
  return Promise.resolve();
}
function reportUnhandledFailure(error: unknown): void {
  if (disposed && error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED") return;
  state.feed.errorMessage = readableError(error, "Memos is temporarily unavailable");
}
function interactionBlocked(): boolean { return state.ui.busy || state.ui.syncState !== "ready"; }
function isPending(id: string): boolean { revision(); return state.ui.pendingIds.has(id); }
function isExpanded(id: string): boolean { revision(); return state.ui.expandedIds.has(id); }

function MemosApp() {
  let composerInput!: HTMLTextAreaElement;
  createEffect(() => { revision(); if (state.ui.focusTarget === "composer") composerInput?.focus({ preventScroll: true }); });
  return <main class={"memos-app" + (state.ui.drawerOpen ? " explorer-open" : "")}>
    <Show when={state.ui.drawerOpen}><button class="explorer-scrim" aria-label="Dismiss explorer" onClick={() => void closeExplorer()} /></Show>
    <aside class="memos-explorer" aria-label="Explore memos" onKeyDown={(event) => { if (event.key === "Escape") void closeExplorer(); }}>
      <header class="explorer-header"><strong>Memos</strong><button class="explorer-close" aria-label="Close explorer" onClick={() => void closeExplorer()}>Close</button></header>
      <form class="search-form" onSubmit={(event) => { event.preventDefault(); submitSearch(); }}>
        <input type="search" name="query" aria-label="Search memos" placeholder="Search memos" value={state.feed.query} onInput={(event) => updateSearch(event.currentTarget.value)} />
        <Show when={state.feed.query}><button type="button" aria-label="Clear search" onClick={clearSearch}>Clear</button></Show>
      </form>
      <nav class="view-nav" aria-label="Memo views"><For each={['all', 'pinned', 'archived'] as FeedView[]}>{(view) => <button aria-pressed={state.feed.view === view} disabled={interactionBlocked()} onClick={() => void setView(view)}><span>{view === "all" ? "All memos" : view === "pinned" ? "Pinned" : "Archived"}</span><small>{view === "all" ? state.facets.allTotal : view === "pinned" ? state.facets.pinnedTotal : state.facets.archivedTotal}</small></button>}</For></nav>
      <section class="calendar" aria-label="Memo calendar"><header><h2>{formatMonth(state.facets.month)}</h2><div><button aria-label="Previous month" disabled={state.facets.loading || interactionBlocked()} onClick={() => void moveMonth(-1)}>‹</button><button aria-label="Next month" disabled={state.facets.loading || interactionBlocked()} onClick={() => void moveMonth(1)}>›</button></div></header>
        <div class="calendar-weekdays" aria-hidden="true"><For each={['M','T','W','T','F','S','S']}>{(day) => <span>{day}</span>}</For></div>
        <div class="calendar-grid"><For each={calendarCells(state.facets.month)}>{(cell) => <Show when={cell} fallback={<span />}>{(day) => <button classList={{ today: day().today, 'has-memos': state.facets.days.some((entry) => entry.date === day().date && entry.count > 0) }} aria-label={formatCalendarDate(day().date)} aria-pressed={state.feed.date === day().date} disabled={interactionBlocked()} onClick={() => void setDate(day().date)}>{day().day}</button>}</Show>}</For></div>
        <Show when={state.feed.date}><button onClick={() => void setDate("")}>Clear date</button></Show>
        <Show when={state.facets.errorMessage}><p role="status">{state.facets.errorMessage}</p></Show>
      </section>
      <section class="tags-panel"><header><h2>Tags</h2><Show when={state.feed.tag}><button onClick={() => void setTag("")}>Clear</button></Show></header><ul class="tag-list"><For each={state.facets.tags}>{(facet) => <li><button aria-pressed={state.feed.tag === facet.tag} disabled={interactionBlocked()} onClick={() => void setTag(facet.tag)}><span>#{facet.tag}</span><small>{facet.count}</small></button></li>}</For></ul><Show when={!state.facets.tags.length}><p class="muted">Tags in your memos appear here.</p></Show></section>
    </aside>
    <section class="memos-workspace" aria-label="Memos timeline">
      <header class="mobile-header"><button aria-label="Open explorer" onClick={() => void toggleExplorer()}>Explore</button><strong>Memos</strong></header>
      <Show when={state.ui.syncState !== "ready"}><section class="sync-notice" role="status"><strong>{state.ui.syncState === "syncing" ? "Refreshing timeline" : "Timeline refresh required"}</strong><p>{state.ui.syncState === "syncing" ? "Confirming the latest saved state..." : state.ui.syncError}</p><Show when={state.ui.syncState === "error"}><button onClick={() => void reconcileUnknownMutationOutcome()}>Retry</button></Show></section></Show>
      <div class="feed-shell"><section class="memo-composer" data-floe-surface="raised" aria-label="Create a memo">
        <textarea ref={composerInput} aria-label="Memo content" name="content" value={state.composer.content} onInput={(event) => updateComposer(event.currentTarget.value)} onFocus={() => { state.composer.expanded = true; }} rows={state.composer.expanded || state.composer.content ? 7 : 2} maxlength={MAX_CONTENT_CHARS} placeholder="What's on your mind?" disabled={interactionBlocked()} />
        <Show when={state.composer.expanded || state.composer.content}><footer class="composer-footer"><span class="muted">Markdown · {characterCount(state.composer.content)} / {MAX_CONTENT_CHARS}</span><SaveStatus kind="draft" /><button class="primary-button" disabled={interactionBlocked() || !state.composer.content.trim() || state.composer.saveState === "saving"} onClick={() => void publishMemo()}>Save</button></footer></Show>
      </section>
      <header class="feed-header"><div><h1>{activeFeedLabel()}</h1><p>{state.feed.loading && !state.feed.memos.length ? "Updating timeline..." : state.feed.memos.length + (state.feed.windowed ? " older memos" : " recent memos")}</p></div><div><Show when={state.feed.windowed}><button disabled={interactionBlocked()} onClick={() => void showNewest()}>Back to newest</button></Show><Show when={state.feed.view !== "all" || state.feed.query || state.feed.tag || state.feed.date}><button disabled={interactionBlocked()} onClick={() => void clearFilters()}>Clear filters</button></Show></div></header>
      <div class="memo-feed" aria-busy={state.feed.loading}><Show when={state.feed.errorMessage}><section role="status" class="feed-message"><h2>Timeline unavailable</h2><p>{state.feed.errorMessage}</p><button onClick={() => void reloadFeed("The timeline could not be loaded")}>Retry</button></section></Show><Show when={!state.feed.errorMessage && !state.feed.memos.length}><section class="feed-message"><h2>{state.feed.loading ? "Loading memos..." : "A little space for your thoughts"}</h2><p>{state.feed.loading ? "Bringing your timeline up to date." : "Write your first memo, or try another filter."}</p></section></Show>
        <For each={state.feed.memos.map((memo) => memo.id)}>{(id) => <MemoCard id={id} />}</For>
        <Show when={state.feed.hasMore}><button class="feed-pagination" disabled={state.feed.loading || interactionBlocked()} onClick={() => void loadOlder()}>Show older memos</button></Show>
      </div></div>
    </section>
    <DeleteDialog />
    <Show when={state.ui.toast}><div class="memos-toast toast" role="status">{state.ui.toast}</div></Show>
  </main>;
}
function SaveStatus(props: { kind: "draft" | "edit" }) {
  const target = () => props.kind === "draft" ? state.composer : state.editing;
  const label = () => target().saveState === "saving" ? "Saving..." : target().saveState === "unsaved" ? props.kind === "draft" ? "Draft pending" : "Unsaved" : target().saveState === "saved" ? props.kind === "draft" ? "Draft protected" : "Saved" : target().saveState === "error" ? target().errorMessage : "";
  return <span class="save-state" classList={{ error: target().saveState === "error" }} role="status">{label()}<Show when={target().saveState === "error"}><button onClick={() => void (props.kind === "draft" ? flushComposer() : flushEdit())}>Retry</button></Show></span>;
}
function MemoCard(props: { id: string }) {
  const memo = () => memoById(props.id)!;
  const editing = () => state.editing.id === props.id;
  const markdown = createMemo(() => renderMarkdown(memo()?.content || "", markdownIdentityFor(props.id), { expanded: isExpanded(props.id), taskMemoId: props.id, interactiveTasks: !editing() && !isPending(props.id) && !memo()?.archived && !interactionBlocked() }));
  let menu!: HTMLDivElement;
  let more!: HTMLButtonElement;
  let editor!: HTMLTextAreaElement;
  createEffect(() => { revision(); if (state.ui.focusId === props.id && state.ui.focusTarget === "menu-button") more?.focus({ preventScroll: true }); if (state.ui.menuId === props.id && state.ui.focusTarget === "menu-item") menu?.querySelector<HTMLButtonElement>("button")?.focus({ preventScroll: true }); });
  createEffect(() => { if (editing()) queueMicrotask(() => editor?.focus({ preventScroll: true })); });
  return <Show when={memo()}><article class="memo-card" data-memo-id={props.id} classList={{ pinned: memo().pinned, archived: memo().archived, editing: editing() }} data-floe-surface="raised" aria-label={"Memo from " + formatDocumentDate(memo().created_at)}>
    <header class="memo-card-header"><div><strong>{memo().archived ? "Archived memo" : "Memos"}</strong><time title={formatDocumentDate(memo().created_at)}>{formatMemoDate(memo().created_at)}</time></div><div class="memo-card-actions"><button title={memo().pinned ? "Unpin memo" : "Pin memo"} aria-label={memo().pinned ? "Unpin memo" : "Pin memo"} aria-pressed={memo().pinned} disabled={isPending(props.id) || interactionBlocked()} onClick={() => void setPinned(props.id)}>Pin</button><button ref={more} aria-label="More memo actions" aria-expanded={state.ui.menuId === props.id} disabled={isPending(props.id) || interactionBlocked()} onClick={() => void toggleMemoMenu(props.id)}>More</button>
    <Show when={state.ui.menuId === props.id}><div ref={menu} class="memo-menu" data-floe-surface="floating" role="menu" aria-label="Memo actions" onKeyDown={(event) => { if (event.key === "Escape") { event.preventDefault(); void closeMemoMenu(); } if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); const buttons = Array.from(menu.querySelectorAll("button")); const index = buttons.indexOf(document.activeElement as HTMLButtonElement); buttons[(index + (event.key === "ArrowDown" ? 1 : buttons.length - 1)) % buttons.length]?.focus(); } }}><button role="menuitem" onClick={() => void beginEdit(props.id)}>Edit</button><button role="menuitem" onClick={() => void setArchived(props.id)}>{memo().archived ? "Restore" : "Archive"}</button><button role="menuitem" class="danger" onClick={() => void requestDelete(props.id)}>Delete</button></div></Show></div></header>
    <Show when={editing()} fallback={<div class="markdown-body" onChange={(event) => { const target = event.target; if (target instanceof HTMLInputElement && target.hasAttribute("data-memo-task")) void toggleTask(target.value, target.checked); }}>{markdown().nodes as JSX.Element}</div>}><div class="inline-editor"><textarea ref={editor} aria-label="Edit memo content" value={state.editing.content} onInput={(event) => updateEdit(event.currentTarget.value)} maxlength={MAX_CONTENT_CHARS} rows={8} disabled={interactionBlocked()} /><footer><SaveStatus kind="edit" /><span class="muted">{characterCount(state.editing.content)} / {MAX_CONTENT_CHARS}</span><button class="primary-button" disabled={state.editing.saveState === "saving"} onClick={() => void finishEdit()}>Done</button></footer></div></Show>
    <Show when={!editing() && (markdown().truncated || isExpanded(props.id))}><button class="expand-content" onClick={() => void toggleExpanded(props.id)}>{isExpanded(props.id) ? "Show less" : "Show more"}</button></Show>
    <footer class="memo-tags"><For each={memo().tags}>{(tag) => <button disabled={interactionBlocked()} onClick={() => void setTag(tag)}>#{tag}</button>}</For></footer>
  </article></Show>;
}
function DeleteDialog() {
  let dialog!: HTMLDialogElement;
  let cancel!: HTMLButtonElement;
  createEffect(() => {
    if (state.ui.deleteId) {
      if (!dialog.open) {
        dialog.showModal();
        cancel.focus({ preventScroll: true });
      }
    } else if (dialog.open) dialog.close();
  });
  const trapFocus: JSX.EventHandler<HTMLDialogElement, KeyboardEvent> = (event) => {
    if (event.key !== "Tab") return;
    const controls = Array.from(dialog.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"));
    const first = controls[0], last = controls.at(-1);
    if (!first || !last) { event.preventDefault(); return; }
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  };
  return <dialog ref={dialog} class="delete-dialog" data-floe-surface="floating" aria-label="Delete memo" aria-modal="true" onKeyDown={trapFocus} onCancel={(event) => { event.preventDefault(); void cancelDelete(); }}><h2>Delete this memo?</h2><p>This action cannot be undone.</p><Show when={state.ui.deleteError}><p role="status" class="danger">{state.ui.deleteError}</p></Show><div class="delete-actions"><button ref={cancel} disabled={state.ui.busy} onClick={() => void cancelDelete()}>Keep memo</button><button class="danger-button" disabled={state.ui.busy} onClick={() => void confirmDelete()}>{state.ui.busy ? "Deleting..." : "Delete memo"}</button></div></dialog>;
}

function applyList(result: ListResult): void {
  state.feed.memos = result.memos.slice(0, MAX_VISIBLE_MEMOS);
  state.feed.nextCursor = result.next_cursor;
  state.feed.hasMore = result.next_cursor !== null;
  state.feed.windowed = false;
  retainVisibleMemoState();
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
  const previousIndex = previous ? state.feed.memos.findIndex((memo) => memo.id === previous.id) : -1;
  const transitionIds = new Set([previous?.id, next?.id].filter((id): id is string => Boolean(id)));
  const memos = state.feed.memos.filter((memo) => !transitionIds.has(memo.id));
  if (next && nextMatches && (previousIndex >= 0 || !previous || !previousMatches)) memos.push(next);
  memos.sort(compareMemos);
  state.feed.memos = memos.slice(0, MAX_VISIBLE_MEMOS);
  state.feed.nextCursor = null;
  state.feed.hasMore = false;
  pruneMarkdownIdentities(new Set(state.feed.memos.map((memo) => memo.id)));
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

function retainVisibleMemoState(): void {
  const visible = new Set(state.feed.memos.map((memo) => memo.id));
  state.ui.expandedIds = new Set([...state.ui.expandedIds].filter((id) => visible.has(id)));
  if (!visible.has(state.ui.menuId)) state.ui.menuId = "";
  pruneMarkdownIdentities(visible);
}

function markdownIdentityFor(memoId: string): MarkdownIdentity {
  const existing = markdownIdentities.get(memoId);
  if (existing !== undefined) return existing;
  const identity = createMarkdownIdentity(`md-${memoId}`);
  markdownIdentities.set(memoId, identity);
  return identity;
}

function pruneMarkdownIdentities(visibleMemoIds: ReadonlySet<string>): void {
  for (const memoId of markdownIdentities.keys()) {
    if (!visibleMemoIds.has(memoId)) markdownIdentities.delete(memoId);
  }
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

function readableError(error: unknown, defaultMessage: string): string {
  if (error instanceof PluginBridgeError) return defaultMessage;
  const message = error instanceof Error ? error.message.trim() : "";
  return message || defaultMessage;
}
