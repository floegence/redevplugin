package examples_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemosUsesSafeDraftAndSerializedEditing(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := source + styles

	if strings.Count(source, `onClick={() => void setPinned(props.id)}`) != 1 {
		t.Fatal("Memos must expose pin as the one explicit card-header action")
	}
	for _, required := range []string{
		`DRAFT_DELAY_MS = 500`,
		`EDIT_DELAY_MS = 700`,
		`SEARCH_DELAY_MS = 250`,
		`draftSaveInFlight`,
		`editSaveInFlight`,
		`return state.composer.dirty ? flushComposer() : true`,
		`return state.editing.dirty ? flushEdit() : true`,
		`if (!(await canLeaveEdit())) return`,
		`memos.draft.save`,
		`memos.publish`,
		`memos.update`,
		`save-state`,
		`Memos could not protect this draft`,
		`Memos could not save your changes`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos persistence flow is missing %q", required)
		}
	}
	for _, forbidden := range []string{`memos.save`, `memos.get`, `memos.togglePin`, `edit-title`, `Untitled memo`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("Memos retained the old document contract %q", forbidden)
		}
	}
}

func TestMemosUsesTimelineExplorerAndControlledMarkdown(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	markdown := readMemosProductFile(t, root, "examples/plugin-ui/memos-markdown.ts")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := source + markdown + styles

	for _, required := range []string{
		`feed: {`,
		`composer: {`,
		`facets: {`,
		`editing: {`,
		`ui: {`,
		`if (sequence !== feedSequence) return false`,
		`memos-explorer`,
		`memo-composer`,
		`memo-feed`,
		`calendar-grid`,
		`tag-list`,
		`explorer-scrim`,
		`parseBlocks`,
		`toggleTaskMarker`,
		`markdown-table`,
		`markdown-code-block`,
		`markdown-raw`,
		`data-memo-task`,
		`<dialog`,
		`aria-modal="true"`,
		`@media (max-width: 700px)`,
		`data-floe-surface`,
		`grid-template-columns: 240px minmax(0, 1fr)`,
		`max-width: 760px`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos timeline product flow is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`memos-library`,
		`empty-welcome`,
		`editor-canvas`,
		`library-overview`,
		`memo-context-rail`,
		`Private library`,
		`At a glance`,
		`tag: "a"`,
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Memos retained forbidden or unsafe UI structure %q", forbidden)
		}
	}
}

func TestMemosMarkdownUsesCallerOwnedStableIdentity(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	markdown := readMemosProductFile(t, root, "examples/plugin-ui/memos-markdown.ts")

	for _, required := range []string{
		`createMarkdownIdentity`,
		`markdownIdentityFor(props.id)`,
		`pruneMarkdownIdentities`,
	} {
		if !strings.Contains(source+markdown, required) {
			t.Fatalf("Memos markdown identity contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`token.raw`,
		`stableKeyFragment`,
		`tokenIdentity`,
		`occurrences`,
	} {
		if strings.Contains(markdown, forbidden) {
			t.Fatalf("Memos markdown derives DOM identity from mutable token content via %q", forbidden)
		}
	}
}

func TestMemosDeleteDialogKeepsRecoverableFailureState(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")

	for _, required := range []string{
		`deleteError: string`,
		`if (state.ui.busy) return`,
		`cancel.focus({ preventScroll: true })`,
		`disabled={state.ui.busy}`,
		`state.ui.busy ? "Deleting..." : "Delete memo"`,
		`<p role="status" class="danger">{state.ui.deleteError}`,
		`response.data.deleted_id !== id`,
		`state.ui.deleteError = readableError(error, "Memos could not delete this memo")`,
		`state.ui.syncState = "syncing"`,
		`unknownMutationReconciliation = { kind: "delete" }`,
		`if (outcomeUnknown) await reconcileUnknownMutationOutcome()`,
		`refreshFeed(false, feedRequest)`,
		`refreshFacets(facetsRequest)`,
		`state.ui.syncState = "error"`,
		`onClick={() => void reconcileUnknownMutationOutcome()}`,
		`return state.ui.busy || state.ui.syncState !== "ready"`,
		`trapFocus`,
	} {
		if !strings.Contains(source+styles, required) {
			t.Fatalf("Memos recoverable delete flow is missing %q", required)
		}
	}

	callIndex := strings.Index(source, `bridge.call<PluginMethodResult<DeleteResult>>("memos.delete", { id })`)
	validationIndex := strings.Index(source, `response.data.deleted_id !== id`)
	closeAfterCallIndex := -1
	if callIndex >= 0 {
		if relative := strings.Index(source[callIndex:], `state.ui.deleteId = ""`); relative >= 0 {
			closeAfterCallIndex = callIndex + relative
		}
	}
	if callIndex < 0 || validationIndex <= callIndex || closeAfterCallIndex <= validationIndex {
		t.Fatalf("Memos must keep the delete dialog bound to its target until the response ID is validated")
	}
	if strings.Contains(source, `showToast(readableError(error, "Memos could not delete this memo"))`) {
		t.Fatal("Memos must keep delete failures in the retryable dialog instead of a transient toast")
	}
}

func TestMemosUnknownPublishOutcomeUsesAuthoritativeDraftReconciliation(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	worker := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")

	for _, required := range []string{
		`type UnknownMutationReconciliation =`,
		`{ kind: "publish"; content: string }`,
		`unknownMutationReconciliation = { kind: "publish", content }`,
		`bridge.call<PluginMethodResult<BootstrapResult>>("memos.bootstrap"`,
		`bootstrap.data.draft === null`,
		`bootstrap.data.draft.content === reconciliation.content`,
		`"Memos could not confirm the publish result"`,
		`CREATE TRIGGER IF NOT EXISTS clear_memos_draft_after_publish`,
	} {
		if !strings.Contains(source+worker, required) {
			t.Fatalf("Memos unknown publish reconciliation is missing %q", required)
		}
	}
	if strings.Contains(source, `mutationOutcome === "unknown") return publishMemo()`) {
		t.Fatal("Memos must not retry a publish whose commit outcome is unknown")
	}
}

func TestMemosKeepsNavigationCountsIndependentFromTheActiveFeed(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	manifest := readMemosProductFile(t, root, "examples/plugins/memos/manifest.json")
	combined := uiSource + workerSource + manifest

	for _, required := range []string{
		`all_total`,
		`pinned_total`,
		`archived_total`,
		`allTotal: number`,
		`pinnedTotal: number`,
		`view === "all" ? state.facets.allTotal`,
		`view === "pinned" ? state.facets.pinnedTotal`,
		`applyMemoTransition`,
		`applyFeedTransition`,
		`adjustedCount`,
		`SUM(CASE WHEN archived = 0 AND pinned = 1 THEN 1 ELSE 0 END)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos navigation count flow is missing %q", required)
		}
	}
	if strings.Contains(uiSource, `viewButton("pinned", "Pinned", "icon-pin", undefined)`) {
		t.Fatal("Memos must render a zero pinned count instead of omitting the count node")
	}
}

func TestMemosKeepsBoundedStorageAndCurrentBootstrap(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	manifest := readMemosProductFile(t, root, "examples/plugins/memos/manifest.json")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := uiSource + workerSource + manifest + styles

	for _, required := range []string{
		`DEFAULT_PAGE_SIZE: usize = 10`,
		`params.limit.clamp(1, 10).saturating_add(1)`,
		`ORDER BY pinned DESC, created_at DESC, id DESC LIMIT ?`,
		`MAX_VISIBLE_MEMOS = PAGE_SIZE`,
		`MAX_CONTENT_CHARS: usize = 20_000`,
		`MAX_QUERY_CHARS: usize = 200`,
		`MAX_TAGS: usize = 32`,
		`MAX_TAG_LENGTH: usize = 40`,
		`CREATE TABLE IF NOT EXISTS drafts`,
		`clear_memos_draft_after_publish`,
		`title = ?, body = ?, content = ?`,
		`"schema_version": 1`,
		`memos.setArchived`,
		`confirmDelete()`,
		`loadOlder()`,
		`min-height: 44px`,
		`onInput={(event) => updateComposer(event.currentTarget.value)}`,
		`width: min(360px, 100vw)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos bounded storage or current bootstrap flow is missing %q", required)
		}
	}
	if strings.Contains(workerSource, `"max_rows": 500`) {
		t.Fatal("Memos list must not expose an unbounded full-library worker response")
	}
}

func TestMemosUsesBoundedKeysetFeedWindows(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.tsx")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	manifest := readMemosProductFile(t, root, "examples/plugins/memos/manifest.json")
	combined := uiSource + workerSource + manifest

	for _, required := range []string{
		`const MAX_VISIBLE_MEMOS = PAGE_SIZE`,
		`nextCursor: string | null`,
		`cursor: advance ? state.feed.nextCursor : null`,
		`state.feed.memos = response.data.memos.slice(0, MAX_VISIBLE_MEMOS)`,
		`loadOlder()`,
		`showNewest()`,
		`CURSOR_PREFIX: &str = "memos_cursor_v1_"`,
		`filter_sha256`,
		`filter_fingerprint(`,
		`decode_cursor(`,
		`params.limit.clamp(1, 10).saturating_add(1)`,
		`pinned < ? OR (pinned = ? AND created_at < ?) OR (pinned = ? AND created_at = ? AND id < ?)`,
		`ORDER BY pinned DESC, created_at DESC, id DESC LIMIT ?`,
		`"next_cursor"`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos bounded keyset feed is missing %q", required)
		}
	}
	for _, forbidden := range []string{`type MemoCursor`, `cursorForMemo`, `OFFSET ?`, `load-more-memos`, `dedupeMemos`, `SELECT count(*) FROM notes WHERE`} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Memos retained forbidden pagination logic %q", forbidden)
		}
	}
	for _, source := range []string{uiSource, manifest} {
		if strings.Contains(source, `"offset"`) {
			t.Fatal("Memos retained the public offset pagination field")
		}
	}
}

func readMemosProductFile(t *testing.T, root, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
