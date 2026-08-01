package capabilitypublisher

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
)

func TestPublisherLifecycleIsResumableAndVerifiesOutput(t *testing.T) {
	t.Parallel()
	config, privateKey := testConfig(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	output := filepath.Join(root, "output")

	status, err := Prepare(config, workspace)
	if err != nil || status.Phase != "awaiting_signature" || status.PendingRequests != 1 {
		t.Fatalf("prepare status = %#v, err = %v", status, err)
	}
	request := readOnlyRequest(t, workspace)
	requestRaw, err := CanonicalSignerRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeSignerRequest(requestRaw); err != nil || decoded != request {
		t.Fatalf("decode request = %#v, err = %v", decoded, err)
	}
	response := responseFor(t, request, privateKey)
	responseRaw, err := CanonicalSignerResponse(response)
	if err != nil {
		t.Fatal(err)
	}

	status, err = ApplySignature(workspace, responseRaw)
	if err != nil || status.Phase != "ready" || status.PendingRequests != 0 {
		t.Fatalf("apply status = %#v, err = %v", status, err)
	}
	if _, err := ApplySignature(workspace, responseRaw); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	status, err = Finalize(workspace, output)
	if err != nil || status.Phase != "complete" {
		t.Fatalf("finalize status = %#v, err = %v", status, err)
	}
	if _, err := Finalize(workspace, output); err != nil {
		t.Fatalf("idempotent finalize: %v", err)
	}
	if err := VerifyOutput(output); err != nil {
		t.Fatalf("verify output: %v", err)
	}
}

func TestPublisherRejectsWrongResponseAndWorkspaceConflicts(t *testing.T) {
	t.Parallel()
	config, privateKey := testConfig(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if _, err := Prepare(config, workspace); err != nil {
		t.Fatal(err)
	}
	request := readOnlyRequest(t, workspace)
	response := responseFor(t, request, privateKey)
	response.ManifestSHA256 = strings.Repeat("0", 64)
	response.SigningPreimageSHA256 = response.ManifestSHA256
	raw, _ := json.Marshal(response)
	if _, err := ApplySignature(workspace, raw); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("wrong response error = %v", err)
	}

	changed := config
	changed.SourceCommit = strings.Repeat("b", 40)
	if _, err := Prepare(changed, workspace); !errors.Is(err, ErrWorkspaceConflict) {
		t.Fatalf("prepare conflict error = %v", err)
	}
}

func TestPublisherRejectsTamperedWorkspaceAfterSignature(t *testing.T) {
	t.Parallel()
	config, privateKey := testConfig(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if _, err := Prepare(config, workspace); err != nil {
		t.Fatal(err)
	}
	request := readOnlyRequest(t, workspace)
	responseRaw, _ := json.Marshal(responseFor(t, request, privateKey))
	if _, err := ApplySignature(workspace, responseRaw); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(workspace, workspaceStateFile)
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(stateRaw), config.SourceCommit, strings.Repeat("c", 40), 1)
	if err := os.WriteFile(statePath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Finalize(workspace, filepath.Join(t.TempDir(), "output")); !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("tampered workspace error = %v", err)
	}
}

func testConfig(t *testing.T) (ConfigV1, ed25519.PrivateKey) {
	t.Helper()
	contractRaw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "host-capability", "sample-documents-v1", "capabilities", "example.documents", "v1.0.0", "example.documents.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract capabilitycontract.Contract
	if err := json.Unmarshal(contractRaw, &contract); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ConfigV1{
		SchemaVersion: ConfigSchemaVersion, Contract: contract,
		ArtifactBaseRef: "capabilities/example.documents/v1.0.0", GeneratedAt: "2026-08-01T00:00:00Z",
		SourceCommit: strings.Repeat("a", 40), MinReDevPluginVersion: "0.6.22",
		SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1", Notices: []capabilitycontract.Notice{},
		PublicKey: PublicKeyV1{SchemaVersion: "redevplugin.ed25519_signing_key.v1", Algorithm: "ed25519", KeyID: "example_documents_2026", PublisherID: contract.PublisherID,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey)},
	}, privateKey
}

func readOnlyRequest(t *testing.T, workspace string) SignerRequestV1 {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(workspace, requestDirectory))
	if err != nil || len(entries) != 1 {
		t.Fatalf("request entries = %d, err = %v", len(entries), err)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, requestDirectory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var request SignerRequestV1
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func responseFor(t *testing.T, request SignerRequestV1, privateKey ed25519.PrivateKey) SignerResponseV1 {
	t.Helper()
	preimage, err := base64.StdEncoding.DecodeString(request.SigningPreimage)
	if err != nil {
		t.Fatal(err)
	}
	return SignerResponseV1{
		SchemaVersion: ResponseSchemaVersion, RequestID: request.RequestID, Usage: request.Usage, KeyID: request.KeyID,
		PublisherID: request.PublisherID, ContractID: request.ContractID, ContractVersion: request.ContractVersion,
		ManifestSHA256: request.ManifestSHA256, SigningPreimageSHA256: request.SigningPreimageSHA256,
		Algorithm: "ed25519", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, preimage)),
	}
}
