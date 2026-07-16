package examples_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemosUsesSafeDraftAndSerializedEditing(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := source + styles

	if strings.Count(source, `data-redevplugin-action": "set-pinned"`) != 1 {
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
		`save-indicator`,
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
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
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
		`marked.lexer`,
		`toggleTaskMarker`,
		`markdown-table`,
		`markdown-code-block`,
		`markdown-raw`,
		`data-redevplugin-action": "toggle-task"`,
		`role: "dialog"`,
		`"aria-modal": true`,
		`autofocus: true`,
		`@media (max-width: 640px)`,
		`@media (prefers-color-scheme: dark)`,
		`grid-template-columns: 256px minmax(0, 1fr)`,
		`width: min(100%, 784px)`,
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
			t.Fatalf("Memos retained obsolete or unsafe UI structure %q", forbidden)
		}
	}
}

func TestMemosKeepsNavigationCountsIndependentFromTheActiveFeed(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	manifest := readMemosProductFile(t, root, "examples/plugins/memos/manifest.json")
	combined := uiSource + workerSource + manifest

	for _, required := range []string{
		`all_total`,
		`pinned_total`,
		`archived_total`,
		`allTotal: number`,
		`pinnedTotal: number`,
		`viewButton("all", "All memos", "icon-inbox", state.facets.allTotal)`,
		`viewButton("pinned", "Pinned", "icon-pin", state.facets.pinnedTotal)`,
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

func TestMemosKeepsBoundedStorageAndCompatibleMigration(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	manifest := readMemosProductFile(t, root, "examples/plugins/memos/manifest.json")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := uiSource + workerSource + manifest + styles

	for _, required := range []string{
		`DEFAULT_PAGE_SIZE: usize = 10`,
		`params.limit.clamp(1, 10)`,
		`LIMIT ? OFFSET ?`,
		`MAX_CONTENT_CHARS: usize = 20_000`,
		`MAX_QUERY_CHARS: usize = 200`,
		`MAX_TAGS: usize = 32`,
		`MAX_TAG_LENGTH: usize = 40`,
		`MAX_SQLITE_RESPONSE_BYTES: u64 = 393_216`,
		`PRAGMA table_info(notes)`,
		`ALTER TABLE notes ADD COLUMN content`,
		`CREATE TABLE IF NOT EXISTS drafts`,
		`clear_memos_draft_after_publish`,
		`title = ?, body = ?, content = ?`,
		`"schema_version": 2`,
		`"from_version": 1, "to_version": 2`,
		`memos.setArchived`,
		`confirm-delete`,
		`load-more-memos`,
		`min-height: 44px`,
		`button[value] > * { pointer-events: none; }`,
		`@media (max-width: 380px)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos bounded storage or migration flow is missing %q", required)
		}
	}
	if strings.Contains(workerSource, `"max_rows": 500`) {
		t.Fatal("Memos list must not expose an unbounded full-library worker response")
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
