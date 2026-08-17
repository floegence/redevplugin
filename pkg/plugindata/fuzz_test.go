package plugindata

import (
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/storage"
)

func TestSQLiteTokensRejectsOversizedInput(t *testing.T) {
	_, err := sqliteTokens(strings.Repeat("x", maxSQLiteSQLBytes+1))
	if !errors.Is(err, storage.ErrInvalidSQLite) {
		t.Fatalf("sqliteTokens() error = %v, want ErrInvalidSQLite", err)
	}
}

// FuzzSQLiteTokens exercises the SQL tokenizer used before every broker
// request. Unterminated comments/quotes are ordinary validation failures;
// arbitrary input must never panic or loop indefinitely.
func FuzzSQLiteTokens(f *testing.F) {
	f.Add("SELECT id FROM notes WHERE title = 'memo'")
	f.Add("/* unterminated")
	f.Add("CREATE TRIGGER t BEGIN SELECT 1; END;")
	f.Fuzz(func(t *testing.T, query string) {
		_, _ = sqliteTokens(query)
	})
}
