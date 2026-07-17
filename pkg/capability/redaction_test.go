package capability

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

type responseTestContainer struct {
	Env []string `json:"env"`
}

type responseTestPayload struct {
	Containers []*responseTestContainer `json:"containers"`
	Optional   *string                  `json:"optional,omitempty"`
}

type responseTestJSON string

func (value responseTestJSON) MarshalJSON() ([]byte, error) {
	return []byte(value), nil
}

type responseTestPanicJSON struct{}

func (responseTestPanicJSON) MarshalJSON() ([]byte, error) {
	panic("marshal panic")
}

type responseTestCollisionKey int

type responseTestMarshalProbe struct {
	called *bool
}

type responsePointerJSON struct {
	Nodes []any                    `json:"nodes"`
	Probe responseTestMarshalProbe `json:"probe"`
}

type responsePointerText struct {
	Hidden chan int
}

type responseUnexportedEmbedded struct {
	Nodes []any                    `json:"nodes"`
	Probe responseTestMarshalProbe `json:"probe"`
}

type responseUnexportedEnvelope struct {
	responseUnexportedEmbedded
}

type ResponseConflictA struct {
	Hidden chan int
}

type ResponseConflictB struct {
	Hidden chan int
}

type responseConflictEnvelope struct {
	ResponseConflictA
	ResponseConflictB
}

type responseZeroPayload struct {
	Hidden chan int
}

type responseOmitZeroEnvelope struct {
	Payload responseZeroPayload `json:"payload,omitzero"`
}

type responseStatefulZero struct {
	calls *int
}

type responseStatefulZeroEnvelope struct {
	Value responseStatefulZero `json:"value,omitzero"`
}

type responsePointerJSONByte byte

type responsePointerTextByte byte

var (
	responsePointerJSONByteCalls int
	responsePointerTextByteCalls int
)

func (responseTestCollisionKey) MarshalText() ([]byte, error) {
	return []byte("collision"), nil
}

func (probe responseTestMarshalProbe) MarshalJSON() ([]byte, error) {
	*probe.called = true
	return []byte(`"called"`), nil
}

func (*responsePointerJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"custom":true}`), nil
}

func (*responsePointerText) MarshalText() ([]byte, error) {
	return []byte("custom"), nil
}

func (value responseStatefulZero) IsZero() bool {
	(*value.calls)++
	return *value.calls == 1
}

func (*responsePointerJSONByte) MarshalJSON() ([]byte, error) {
	responsePointerJSONByteCalls++
	return []byte(`"json-byte"`), nil
}

func (*responsePointerTextByte) MarshalText() ([]byte, error) {
	responsePointerTextByteCalls++
	return []byte("text-byte"), nil
}

func TestPrepareResponseDataRedactsContainerShapedSecrets(t *testing.T) {
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

	redacted, err := PrepareResponseData(input)
	if err != nil {
		t.Fatal(err)
	}
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

func TestPrepareResponseDataDoesNotMutateOriginal(t *testing.T) {
	input := map[string]any{
		"env": []any{"PASSWORD=plaintext"},
	}

	redacted, err := PrepareResponseData(input)
	if err != nil {
		t.Fatal(err)
	}
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

func TestPrepareResponseDataNormalizesTypedJSONWithoutMutatingInput(t *testing.T) {
	input := &responseTestPayload{Containers: []*responseTestContainer{{Env: []string{
		"PATH=/usr/bin", "DB_PASSWORD=plaintext",
	}}}}

	prepared, err := PrepareResponseData(input)
	if err != nil {
		t.Fatal(err)
	}
	object, ok := prepared.(map[string]any)
	if !ok {
		t.Fatalf("PrepareResponseData() type = %T, want map[string]any", prepared)
	}
	if _, present := object["optional"]; present {
		t.Fatalf("omitempty field remained in canonical response: %#v", object)
	}
	raw, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "plaintext") || !strings.Contains(got, ResponseRedactedValue) {
		t.Fatalf("typed response was not redacted: %s", got)
	}
	if input.Containers[0].Env[1] != "DB_PASSWORD=plaintext" {
		t.Fatalf("input was mutated: %#v", input)
	}
}

func TestPrepareResponseDataUsesCustomJSONRepresentation(t *testing.T) {
	prepared, err := PrepareResponseData(responseTestJSON(`{"env":["API_TOKEN=secret"]}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "secret") || !strings.Contains(got, ResponseRedactedValue) {
		t.Fatalf("custom JSON representation was not redacted: %s", got)
	}
}

func TestPrepareResponseDataRejectsInvalidJSONBeforeRedaction(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	tests := []struct {
		name  string
		value any
	}{
		{name: "channel", value: make(chan int)},
		{name: "function", value: func() {}},
		{name: "complex", value: complex(1, 2)},
		{name: "nan", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
		{name: "cycle", value: cycle},
		{name: "panic", value: responseTestPanicJSON{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PrepareResponseData(map[string]any{"secret_token": tc.value}); err == nil {
				t.Fatal("PrepareResponseData() accepted invalid JSON value")
			}
		})
	}
}

func TestPrepareResponseDataRejectsAmbiguousOrUnsafeJSON(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "duplicate custom keys", value: responseTestJSON(`{"ok":true,"ok":false}`)},
		{name: "prototype key", value: responseTestJSON(`{"__proto__":{"polluted":true}}`)},
		{name: "unsafe integer", value: int64(1 << 53)},
		{name: "text key collision", value: map[responseTestCollisionKey]string{1: "one", 2: "two"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PrepareResponseData(tc.value); err == nil {
				t.Fatal("PrepareResponseData() accepted ambiguous or unsafe JSON")
			}
		})
	}
}

func TestPrepareResponseDataEnforcesStructuralAndByteLimits(t *testing.T) {
	deep := any("leaf")
	for range 65 {
		deep = []any{deep}
	}
	if _, err := PrepareResponseData(deep); err == nil {
		t.Fatal("PrepareResponseData() accepted excessive depth")
	}

	nodes := make([]any, 32768)
	if _, err := PrepareResponseData(nodes); err == nil {
		t.Fatal("PrepareResponseData() accepted excessive node count")
	}

	if _, err := PrepareResponseData(strings.Repeat("x", 512*1024)); err == nil {
		t.Fatal("PrepareResponseData() accepted excessive encoded bytes")
	}
}

func TestPrepareResponseDataEnforcesLimitAfterRedaction(t *testing.T) {
	input := make(map[string]any, 30000)
	for index := range 30000 {
		input[fmt.Sprintf("token%d", index)] = ""
	}
	rawInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawInput) >= 512*1024 {
		t.Fatalf("test input is already oversized: %d bytes", len(rawInput))
	}

	if _, err := PrepareResponseData(input); err == nil {
		t.Fatal("PrepareResponseData() accepted a response expanded beyond the byte limit by redaction")
	}
}

func TestPrepareResponseDataRejectsNativeStructureBeforeMarshalingLaterFields(t *testing.T) {
	probeCalled := false
	value := struct {
		Nodes []any                    `json:"nodes"`
		Probe responseTestMarshalProbe `json:"probe"`
	}{
		Nodes: make([]any, 32768),
		Probe: responseTestMarshalProbe{called: &probeCalled},
	}

	if _, err := PrepareResponseData(value); err == nil {
		t.Fatal("PrepareResponseData() accepted an oversized native structure")
	}
	if probeCalled {
		t.Fatal("PrepareResponseData() invoked a later custom marshaler before rejecting the native structure")
	}
}

func TestPrepareResponseDataRejectsUnsafeNativeIntegerBeforeMarshalingLaterFields(t *testing.T) {
	for _, value := range []any{int64(1 << 53), uint64(1 << 53)} {
		probeCalled := false
		payload := struct {
			Unsafe any                      `json:"unsafe"`
			Probe  responseTestMarshalProbe `json:"probe"`
		}{Unsafe: value, Probe: responseTestMarshalProbe{called: &probeCalled}}

		if _, err := PrepareResponseData(payload); err == nil {
			t.Fatalf("PrepareResponseData() accepted unsafe integer %T", value)
		}
		if probeCalled {
			t.Fatalf("PrepareResponseData() invoked a later custom marshaler for %T", value)
		}
	}
}

func TestPrepareResponseDataRejectsUnsafeNativeFloatBeforeMarshalingLaterFields(t *testing.T) {
	for _, value := range []any{float32(1 << 54), float64(1 << 53)} {
		probeCalled := false
		payload := struct {
			Unsafe any                      `json:"unsafe"`
			Probe  responseTestMarshalProbe `json:"probe"`
		}{Unsafe: value, Probe: responseTestMarshalProbe{called: &probeCalled}}

		if _, err := PrepareResponseData(payload); err == nil {
			t.Fatalf("PrepareResponseData() accepted unsafe float %T", value)
		}
		if probeCalled {
			t.Fatalf("PrepareResponseData() invoked a later custom marshaler for %T", value)
		}
	}
}

func TestPrepareResponseDataRejectsCustomIsZeroWithoutInvokingIt(t *testing.T) {
	calls := 0
	if _, err := PrepareResponseData(responseStatefulZeroEnvelope{
		Value: responseStatefulZero{calls: &calls},
	}); err == nil {
		t.Fatal("PrepareResponseData() accepted an omitzero field with custom IsZero semantics")
	}
	if calls != 0 {
		t.Fatalf("custom IsZero calls = %d, want 0", calls)
	}
}

func TestPrepareResponseDataCountsNamedByteSlicesWithElementMarshalers(t *testing.T) {
	responsePointerJSONByteCalls = 0
	if _, err := PrepareResponseData(make([]responsePointerJSONByte, 32768)); err == nil {
		t.Fatal("PrepareResponseData() accepted an excessive named byte slice with JSON element marshalers")
	}
	if responsePointerJSONByteCalls != 0 {
		t.Fatalf("pointer JSON byte marshaler calls = %d, want 0", responsePointerJSONByteCalls)
	}

	responsePointerTextByteCalls = 0
	if _, err := PrepareResponseData(make([]responsePointerTextByte, 32768)); err == nil {
		t.Fatal("PrepareResponseData() accepted an excessive named byte slice with text element marshalers")
	}
	if responsePointerTextByteCalls != 0 {
		t.Fatalf("pointer text byte marshaler calls = %d, want 0", responsePointerTextByteCalls)
	}

	responsePointerJSONByteCalls = 0
	prepared, err := PrepareResponseData([]responsePointerJSONByte{1})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected named JSON byte slice: %v", err)
	}
	if values, ok := prepared.([]any); !ok || len(values) != 1 || values[0] != "json-byte" || responsePointerJSONByteCalls != 1 {
		t.Fatalf("named JSON byte slice = %#v, calls=%d", prepared, responsePointerJSONByteCalls)
	}

	responsePointerTextByteCalls = 0
	prepared, err = PrepareResponseData([]responsePointerTextByte{1})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected named text byte slice: %v", err)
	}
	if values, ok := prepared.([]any); !ok || len(values) != 1 || values[0] != "text-byte" || responsePointerTextByteCalls != 1 {
		t.Fatalf("named text byte slice = %#v, calls=%d", prepared, responsePointerTextByteCalls)
	}
}

func TestPrepareResponseDataDistinguishesOverlappingSliceFromCycle(t *testing.T) {
	overlapping := make([]any, 2)
	overlapping[0] = "value"
	overlapping[1] = overlapping[:1]
	prepared, err := PrepareResponseData(overlapping)
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected finite overlapping slices: %v", err)
	}
	if raw, marshalErr := json.Marshal(prepared); marshalErr != nil || string(raw) != `["value",["value"]]` {
		t.Fatalf("prepared overlapping slices = %s, err=%v", raw, marshalErr)
	}

	cyclic := make([]any, 1)
	cyclic[0] = cyclic
	if _, err := PrepareResponseData(cyclic); err == nil {
		t.Fatal("PrepareResponseData() accepted a self-referential slice")
	}
}

func TestPrepareResponseDataMatchesPointerOnlyCustomEncodingAddressability(t *testing.T) {
	probeCalled := false
	value := responsePointerJSON{
		Nodes: make([]any, 32768),
		Probe: responseTestMarshalProbe{called: &probeCalled},
	}
	if _, err := PrepareResponseData(value); err == nil {
		t.Fatal("PrepareResponseData() accepted oversized top-level native value")
	}
	if probeCalled {
		t.Fatal("top-level pointer-only marshaler bypassed native preflight")
	}

	probeCalled = false
	if _, err := PrepareResponseData(map[string]responsePointerJSON{"value": value}); err == nil {
		t.Fatal("PrepareResponseData() accepted oversized native map value")
	}
	if probeCalled {
		t.Fatal("map value pointer-only marshaler bypassed native preflight")
	}

	prepared, err := PrepareResponseData(&value)
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected addressable pointer custom JSON: %v", err)
	}
	if object, ok := prepared.(map[string]any); !ok || object["custom"] != true {
		t.Fatalf("pointer custom JSON = %#v", prepared)
	}

	textValues := []responsePointerText{{Hidden: make(chan int)}}
	prepared, err = PrepareResponseData(textValues)
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected addressable pointer text marshaler: %v", err)
	}
	if values, ok := prepared.([]any); !ok || len(values) != 1 || values[0] != "custom" {
		t.Fatalf("pointer custom text = %#v", prepared)
	}
}

func TestPrepareResponseDataUsesEncodingJSONStructFieldPlan(t *testing.T) {
	probeCalled := false
	embedded := responseUnexportedEnvelope{responseUnexportedEmbedded: responseUnexportedEmbedded{
		Nodes: make([]any, 32768), Probe: responseTestMarshalProbe{called: &probeCalled},
	}}
	if _, err := PrepareResponseData(embedded); err == nil {
		t.Fatal("PrepareResponseData() ignored exported fields of an unexported anonymous struct")
	}
	if probeCalled {
		t.Fatal("unexported anonymous struct bypassed native preflight")
	}

	prepared, err := PrepareResponseData(responseConflictEnvelope{
		ResponseConflictA: ResponseConflictA{Hidden: make(chan int)},
		ResponseConflictB: ResponseConflictB{Hidden: make(chan int)},
	})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected fields ignored by JSON dominance: %v", err)
	}
	if object, ok := prepared.(map[string]any); !ok || len(object) != 0 {
		t.Fatalf("conflicting JSON fields = %#v", prepared)
	}

	prepared, err = PrepareResponseData(responseOmitZeroEnvelope{})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected omitzero field: %v", err)
	}
	if object, ok := prepared.(map[string]any); !ok || len(object) != 0 {
		t.Fatalf("omitzero JSON fields = %#v", prepared)
	}
}

func TestPrepareResponseDataPreflightsWireScalarSemantics(t *testing.T) {
	zeroNumber, err := PrepareResponseData(struct {
		Value json.Number `json:"value"`
	}{})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected zero json.Number: %v", err)
	}
	if object, ok := zeroNumber.(map[string]any); !ok || object["value"] != float64(0) {
		t.Fatalf("zero json.Number JSON = %#v", zeroNumber)
	}

	prepared, err := PrepareResponseData(struct {
		Value int64 `json:"value,string"`
	}{Value: 1 << 53})
	if err != nil {
		t.Fatalf("PrepareResponseData() rejected quoted integer: %v", err)
	}
	if object, ok := prepared.(map[string]any); !ok || object["value"] != "9007199254740992" {
		t.Fatalf("quoted integer JSON = %#v", prepared)
	}

	probeCalled := false
	invalidNumber := struct {
		Value json.Number              `json:"value"`
		Probe responseTestMarshalProbe `json:"probe"`
	}{Value: json.Number("9007199254740992"), Probe: responseTestMarshalProbe{called: &probeCalled}}
	if _, err := PrepareResponseData(invalidNumber); err == nil {
		t.Fatal("PrepareResponseData() accepted unsafe json.Number")
	}
	if probeCalled {
		t.Fatal("unsafe json.Number reached a later custom marshaler")
	}

	probeCalled = false
	oversizedNumber := struct {
		Value json.Number              `json:"value"`
		Probe responseTestMarshalProbe `json:"probe"`
	}{Value: json.Number(strings.Repeat("1", 512*1024)), Probe: responseTestMarshalProbe{called: &probeCalled}}
	if _, err := PrepareResponseData(oversizedNumber); err == nil || !strings.Contains(err.Error(), "encoded value exceeds") {
		t.Fatalf("PrepareResponseData() oversized json.Number error = %v, want byte-limit rejection", err)
	}
	if probeCalled {
		t.Fatal("oversized json.Number reached a later custom marshaler")
	}

	preciseUnsafeNumber := json.Number("9007199254740991." + strings.Repeat("0", 200) + "1")
	if _, err := PrepareResponseData(preciseUnsafeNumber); err == nil {
		t.Fatal("PrepareResponseData() rounded an unsafe precise decimal down to the safe boundary")
	}

	probeCalled = false
	escaped := struct {
		Value string                   `json:"value"`
		Probe responseTestMarshalProbe `json:"probe"`
	}{Value: strings.Repeat("<", 90*1024), Probe: responseTestMarshalProbe{called: &probeCalled}}
	if _, err := PrepareResponseData(escaped); err == nil {
		t.Fatal("PrepareResponseData() accepted escaped JSON beyond the byte limit")
	}
	if probeCalled {
		t.Fatal("escaped byte overflow reached a later custom marshaler")
	}
}
