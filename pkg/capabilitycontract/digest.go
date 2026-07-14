package capabilitycontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func DetailSchemaSHA256(schema map[string]any) (string, error) {
	return SchemaSHA256(schema)
}

func SchemaSHA256(schema map[string]any) (string, error) {
	raw, err := json.Marshal(schema)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
