package releasepublisher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

func TestExternalSignerSchemasMatchCurrentExchange(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, name := range []string{"external-signer-request-v1.schema.json", "external-signer-response-v1.schema.json"} {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range [][]byte{[]byte("subject_identity_sha256"), []byte("release-signing-subject"), []byte("ledger-checkpoint"), []byte("ledger-receipt")} {
			if bytes.Contains(raw, retired) {
				t.Fatalf("%s retains retired %q", name, retired)
			}
		}
	}
}

func TestExternalSignerExchangeRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	preimage := []byte("canonical public signing preimage")
	request, err := NewExternalSignerRequest(
		releasecontract.SigningUsagePackage,
		"official_signing_2026",
		preimage,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := CanonicalExternalSignerRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := DecodeExternalSignerRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(decodedRequest.SigningPreimageSHA256)
	response := ExternalSignerResponseV1{
		SchemaVersion: ExternalSignerResponseSchemaVersion,
		RequestID:     request.RequestID, Usage: request.Usage, KeyID: request.KeyID,
		SigningPreimageSHA256: request.SigningPreimageSHA256,
		Algorithm:             releasecontract.SignatureAlgorithmEd25519,
		Signature:             base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest)),
	}
	responseBytes, err := CanonicalExternalSignerResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := DecodeExternalSignerResponse(responseBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExternalSignerResponse(decodedRequest, decodedResponse, publicKey); err != nil {
		t.Fatal(err)
	}

	tampered := decodedResponse
	tampered.SigningPreimageSHA256 = hex.EncodeToString(bytesOf(1, sha256.Size))
	if _, err := VerifyExternalSignerResponse(decodedRequest, tampered, publicKey); err == nil {
		t.Fatal("tampered response was accepted")
	}
}

func TestExternalSignerExchangeRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"schema_version":"redevplugin.external_signer_response.v1","request_id":"` + hex.EncodeToString(make([]byte, 32)) + `","usage":"redevplugin.release-signing.package.v1","key_id":"key","signing_preimage_sha256":"` + hex.EncodeToString(make([]byte, 32)) + `","algorithm":"ed25519","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `","unexpected":true}`)
	if _, err := DecodeExternalSignerResponse(raw); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
