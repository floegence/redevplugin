package protocol

import (
	"testing"
)

func TestOwnerScopeSchemasValidateClosedContracts(t *testing.T) {
	inventorySchema := compilePlatformPackageSchema(t, "owner-scope-inventory-v1.schema.json")
	migrationSchema := compilePlatformPackageSchema(t, "owner-scope-migration-v1.schema.json")
	cleanupSchema := compilePlatformPackageSchema(t, "quarantine-cleanup-v1.schema.json")

	if err := inventorySchema.Validate(readPlatformPackageJSON(t, "owner-scope-inventories-v1.json")); err != nil {
		t.Fatalf("valid owner scope inventory rejected: %v", err)
	}
	if err := migrationSchema.Validate(validOwnerScopeMigration()); err != nil {
		t.Fatalf("valid owner scope migration rejected: %v", err)
	}
	if err := cleanupSchema.Validate(validQuarantineCleanup()); err != nil {
		t.Fatalf("valid quarantine cleanup rejected: %v", err)
	}
}

func TestOwnerScopeSchemasRejectUnknownStateTraversalAndOversizedEntries(t *testing.T) {
	inventorySchema := compilePlatformPackageSchema(t, "owner-scope-inventory-v1.schema.json")
	migrationSchema := compilePlatformPackageSchema(t, "owner-scope-migration-v1.schema.json")
	cleanupSchema := compilePlatformPackageSchema(t, "quarantine-cleanup-v1.schema.json")

	inventory := readPlatformPackageJSON(t, "owner-scope-inventories-v1.json")
	inventory["unknown"] = true
	if err := inventorySchema.Validate(inventory); err == nil {
		t.Fatal("inventory schema accepted an unknown field")
	}
	inventory = readPlatformPackageJSON(t, "owner-scope-inventories-v1.json")
	inventory["inventories"].([]any)[0].(map[string]any)["sqlite_databases"].([]any)[0].(map[string]any)["path"] = "db/../registry.sqlite"
	if err := inventorySchema.Validate(inventory); err == nil {
		t.Fatal("inventory schema accepted path traversal")
	}

	migration := validOwnerScopeMigration()
	migration["unknown"] = true
	if err := migrationSchema.Validate(migration); err == nil {
		t.Fatal("migration schema accepted an unknown field")
	}
	migration = validOwnerScopeMigration()
	migration["state"] = "guessed"
	if err := migrationSchema.Validate(migration); err == nil {
		t.Fatal("migration schema accepted an invalid state")
	}
	migration = validOwnerScopeMigration()
	migration["stores"] = make([]any, 65)
	if err := migrationSchema.Validate(migration); err == nil {
		t.Fatal("migration schema accepted an oversized store set")
	}

	cleanup := validQuarantineCleanup()
	cleanup["unknown"] = true
	if err := cleanupSchema.Validate(cleanup); err == nil {
		t.Fatal("cleanup schema accepted an unknown field")
	}
	cleanup = validQuarantineCleanup()
	cleanup["state"] = "rolled_back"
	if err := cleanupSchema.Validate(cleanup); err == nil {
		t.Fatal("cleanup schema accepted an invalid state")
	}
	for _, path := range []string{"../assets/file.bin", "assets/../file.bin", "/assets/file.bin", "assets\\file.bin"} {
		cleanup = validQuarantineCleanup()
		cleanup["entries"].([]any)[0].(map[string]any)["path"] = path
		if err := cleanupSchema.Validate(cleanup); err == nil {
			t.Fatalf("cleanup schema accepted unsafe path %q", path)
		}
	}
	cleanup = validQuarantineCleanup()
	entry := cleanup["entries"].([]any)[0]
	cleanup["entries"] = make([]any, 200001)
	for index := range cleanup["entries"].([]any) {
		cleanup["entries"].([]any)[index] = entry
	}
	if err := cleanupSchema.Validate(cleanup); err == nil {
		t.Fatal("cleanup schema accepted an oversized entry set")
	}
}

func validOwnerScopeMigration() map[string]any {
	return map[string]any{
		"schema_version":          "owner-scope-migration-v1",
		"migration_id":            "migration_0123456789abcdef0123456789abcdef",
		"root_identity_sha256":    repeatedHex("1f"),
		"legacy_snapshot_sha256":  repeatedHex("2f"),
		"inventory_id":            "redeven-redevplugin-v0.1.0-v0.1.5-layout-v1",
		"inventory_sha256":        repeatedHex("3f"),
		"state":                   "prepared",
		"quarantine_id":           "",
		"quarantine_sha256":       "",
		"fresh_generation_id":     "",
		"fresh_generation_sha256": "",
		"stores": []any{
			map[string]any{"id": "db", "scope": "durable", "disposition": "quarantine", "generation": "", "outcome": ""},
		},
	}
}

func validQuarantineCleanup() map[string]any {
	return map[string]any{
		"schema_version":       "quarantine-cleanup-v1",
		"migration_id":         "migration_0123456789abcdef0123456789abcdef",
		"root_identity_sha256": repeatedHex("1f"),
		"quarantine_id":        "quarantine_0123456789abcdef0123456789abcdef",
		"quarantine_sha256":    repeatedHex("2f"),
		"state":                "delete_prepared",
		"entries": []any{
			map[string]any{"path": "assets/file.bin", "kind": "file", "device": 1, "inode": 2, "uid": 1000, "mode": 384, "size": 5, "nlink": 1, "sha256": repeatedHex("3f")},
		},
	}
}

func repeatedHex(pair string) string {
	value := ""
	for len(value) < 64 {
		value += pair
	}
	return value[:64]
}
