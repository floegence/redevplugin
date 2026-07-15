package examples_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemosUsesOneAutosaveAndPinInteractionModel(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")

	if strings.Count(source, `data-redevplugin-action": "set-pinned"`) != 1 {
		t.Fatal("Memos must expose exactly one explicit pin action")
	}
	for _, required := range []string{
		`scheduleAutosave`,
		`scheduleAutosave();
  void render();`,
		`flushDraft`,
		`if (!(await flushDraft())) return`,
		`state.editor.dirty && state.editor.saveState === "error"`,
		`.memo-title`,
		`.editor-pin`,
		`.save-indicator`,
		`cursor: pointer`,
	} {
		if !strings.Contains(source+styles, required) {
			t.Fatalf("Memos autosave interaction is missing %q", required)
		}
	}
	for _, forbidden := range []string{`save-now`, `toggle-pin`, `edit-pinned`, `Save now`, `children: ["Done"]`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("Memos still exposes duplicate save or pin interaction %q", forbidden)
		}
	}
}

func TestMemosUsesConsumerFirstInformationArchitecture(t *testing.T) {
	root := repositoryRoot(t)
	source := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := source + styles

	for _, required := range []string{
		`library: {`,
		`editor: {`,
		`ui: {`,
		`SEARCH_DELAY_MS = 250`,
		`if (sequence !== searchSequence) return false;`,
		`data-redevplugin-action": "search-query"`,
		`groupedNotes`,
		`pinned-group`,
		`recent-group`,
		`empty-welcome`,
		`Write a memo`,
		`autofocus: true`,
		`editor-canvas`,
		`editor-footer`,
		`field-sizing: content`,
		`role: "dialog"`,
		`"aria-modal": true`,
		`backgroundDisabled`,
		`@media (max-width: 640px)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos consumer product flow is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`libraryOverview`,
		`library-overview`,
		`overview-stats`,
		`memoContextRail`,
		`memo-context-rail`,
		`contextStat`,
		`context-stat`,
		`context-ribbon`,
		`Private library`,
		`At a glance`,
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Memos still contains dashboard-oriented structure %q", forbidden)
		}
	}
}

func TestMemosKeepsBoundedStorageAndCompleteMobileEditing(t *testing.T) {
	root := repositoryRoot(t)
	uiSource := readMemosProductFile(t, root, "examples/plugin-ui/memos.ts")
	workerSource := readMemosProductFile(t, root, "examples/workers/memos/src/lib.rs")
	styles := readMemosProductFile(t, root, "examples/plugins/memos/ui/assets/styles.css")
	combined := uiSource + workerSource + styles

	for _, required := range []string{
		`memos.get`,
		`confirm-delete`,
		`cancel-delete`,
		`back-to-list`,
		`load-more-memos`,
		`view-editor`,
		`toggle-memo-menu`,
		`max-width: none`,
		`border-radius: 0`,
		`LIMIT ? OFFSET ?`,
		`substr(body, 1, 180)`,
		`@media (max-width: 640px)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos bounded mobile flow is missing %q", required)
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
