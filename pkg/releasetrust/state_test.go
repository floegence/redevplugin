package releasetrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
)

func TestReleaseTrustStateDecoderEnforcesCanonicalClosedState(t *testing.T) {
	state := validReleaseTrustStateFixture(t)
	raw, err := canonicalReleaseTrustState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeReleaseTrustState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Channels, state.Channels) {
		t.Fatalf("decoded channels = %#v", decoded.Channels)
	}

	tests := map[string][]byte{
		"unknown field":            bytes.Replace(raw, []byte(`"source_id":"example_source"`), []byte(`"source_id":"example_source","unknown":true`), 1),
		"duplicate field":          bytes.Replace(raw, []byte(`"source_id":"example_source"`), []byte(`"source_id":"example_source","source_id":"example_source"`), 1),
		"noncanonical field order": bytes.Replace(raw, []byte(`"schema_version":"redevplugin.release_trust_state.v1","source_id":"example_source"`), []byte(`"source_id":"example_source","schema_version":"redevplugin.release_trust_state.v1"`), 1),
		"oversized document":       append(slices.Clone(raw), bytes.Repeat([]byte(" "), MaxReleaseTrustStateBytes-len(raw)+1)...),
	}

	escaping := cloneReleaseTrustState(state)
	escaping.Channels[0].Policy.PointerLocator = "../escape"
	tests["escaping locator"], _ = json.Marshal(escaping)

	unsorted := cloneReleaseTrustState(state)
	unsorted.Channels[0], unsorted.Channels[1] = unsorted.Channels[1], unsorted.Channels[0]
	tests["unsorted channels"], _ = json.Marshal(unsorted)

	for name, invalid := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeReleaseTrustState(invalid); !errors.Is(err, ErrInvalidReleaseTrustState) {
				t.Fatalf("decodeReleaseTrustState() error = %v", err)
			}
		})
	}
}

func validReleaseTrustStateFixture(t *testing.T) ReleaseTrustStateV1 {
	t.Helper()
	checkpoint := TrustedTimeCheckpointV1{
		SchemaVersion:  TrustedTimeCheckpointSchemaVersion,
		LogID:          "time_log",
		TreeSize:       1,
		RootHash:       hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
		CheckpointTime: "2026-07-21T02:00:00Z",
		KeyID:          "time_key",
		Signature:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64)),
	}
	checkpointBytes, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	documentHead := func(channel string) *ReleaseTrustDocumentHeadV1 {
		return &ReleaseTrustDocumentHeadV1{
			PointerLocator: channel + "/pointer.json", PointerTransportToken: "pointer-etag", PointerEpoch: "1",
			PointerSHA256: hex.EncodeToString(bytes.Repeat([]byte{3}, sha256.Size)), DocumentLocator: channel + "/document.json",
			DocumentTransportToken: "document-etag", DocumentSHA256: hex.EncodeToString(bytes.Repeat([]byte{4}, sha256.Size)),
			GeneratedAt: "2026-07-21T01:00:00Z", ExpiresAt: "2026-07-22T01:00:00Z", KeyID: "policy_key",
		}
	}
	return ReleaseTrustStateV1{
		SchemaVersion: ReleaseTrustStateSchemaVersion, SourceID: "example_source", Revision: 1,
		TrustedTime: ReleaseTrustedTimeStateV1{
			Floor: checkpoint.CheckpointTime, CheckpointSHA256: digestHex(checkpointBytes), Checkpoint: checkpoint,
		},
		Channels: []ReleaseTrustChannelStateV1{
			{Channel: "beta", Policy: documentHead("beta")},
			{Channel: "stable", Policy: documentHead("stable")},
		},
	}
}
