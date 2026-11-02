package main

import "github.com/floegence/redevplugin/v3/pkg/authorapi"

func generateAuthorAPI(input, output string, check bool) error {
	if err := authorapi.Write(input, output, check); err != nil {
		return err
	}
	return writeJSON(map[string]any{"ok": true, "checked": check, "files": []string{"actions.rs", "actions.ts", "manifest.json", "source-map.json"}})
}
