package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactResponseDataRedactsContainerShapedSecrets(t *testing.T) {
	input := map[string]any{
		"containers": []any{
			map[string]any{
				"id":    "container_1",
				"image": "postgres:16",
				"env": []any{
					"PATH=/usr/bin",
					"DB_PASSWORD=super-secret-password",
					"API_TOKEN=token-value",
				},
				"labels": map[string]any{
					"com.example.owner":        "platform",
					"com.example.secret.token": "label-secret",
				},
				"mounts": []any{
					map[string]any{
						"type":   "bind",
						"source": "/srv/app/data",
						"target": "/data",
					},
					map[string]any{
						"type":   "bind",
						"source": "/run/secrets/db_password",
						"target": "/run/secrets/db_password",
					},
				},
			},
		},
		"secret_ref":              "api_token",
		"token_id":                "token_id_is_not_a_credential",
		"session_channel_id_hash": "sha256:session_hash",
	}

	redacted := RedactResponseData(input)
	raw, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, leaked := range []string{
		"super-secret-password",
		"token-value",
		"label-secret",
		"/run/secrets/db_password",
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted response leaked %q: %s", leaked, got)
		}
	}
	for _, kept := range []string{
		"PATH=/usr/bin",
		"platform",
		"/srv/app/data",
		"api_token",
		"token_id_is_not_a_credential",
		"sha256:session_hash",
	} {
		if !strings.Contains(got, kept) {
			t.Fatalf("redacted response dropped safe value %q: %s", kept, got)
		}
	}
}

func TestRedactResponseDataDoesNotMutateOriginal(t *testing.T) {
	input := map[string]any{
		"env": []any{"PASSWORD=plaintext"},
	}

	redacted := RedactResponseData(input)
	rawRedacted, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawRedacted), "plaintext") {
		t.Fatalf("redacted response still contains plaintext: %s", rawRedacted)
	}

	rawOriginal, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawOriginal), "plaintext") {
		t.Fatalf("original response was mutated: %s", rawOriginal)
	}
}

func TestResponseRedactionPolicyHonorsCustomReplacementAndDepth(t *testing.T) {
	policy := ResponseRedactionPolicy{Replacement: "***", MaxDepth: 1}

	got := policy.Redact(map[string]any{
		"outer": map[string]any{
			"inner": map[string]any{
				"token": "secret",
			},
		},
	})

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "***") || strings.Contains(string(raw), "secret") {
		t.Fatalf("depth-limited redaction mismatch: %s", raw)
	}
}
