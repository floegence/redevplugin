package runtimeclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/observability"
)

func TestCanonicalRuntimeLeaseSignaturePayloadExcludesSecrets(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 30, 0, 123000000, time.UTC)
	lease := runtimeLeaseSignatureTestLease(now)
	lease.LeaseToken = "runtime_execution_lease.rel_1.secret"
	lease.Signature = "ed25519:secret-signature-bytes"

	payload, err := CanonicalRuntimeLeaseSignaturePayload(lease, "worker.echo")
	if err != nil {
		t.Fatalf("CanonicalRuntimeLeaseSignaturePayload() error = %v", err)
	}
	encoded := string(payload)
	for _, secret := range []string{"runtime_execution_lease.rel_1.secret", "secret-signature-bytes"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("canonical payload leaked secret %q: %s", secret, encoded)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode canonical payload: %v", err)
	}
	for _, omitted := range []string{"lease_token", "signature"} {
		if _, ok := decoded[omitted]; ok {
			t.Fatalf("canonical payload includes %s: %#v", omitted, decoded)
		}
	}
	if decoded["schema_version"] != RuntimeLeaseSignatureSchemaVersion ||
		decoded["token_kind"] != RuntimeLeaseTokenKind ||
		decoded["key_id"] != lease.KeyID ||
		decoded["method"] != "worker.echo" ||
		decoded["expires_at_unix_ms"] != float64(unixMillis(lease.ExpiresAt)) {
		t.Fatalf("canonical payload mismatch: %#v", decoded)
	}
}

func TestEd25519RuntimeLeaseVerifierChecksSignatureAndAudience(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 45, 0, 0, time.UTC)
	privateKey := runtimeLeaseSignatureTestPrivateKey(7)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	lease := runtimeLeaseSignatureTestLease(now)
	signed, err := SignRuntimeLease(lease, "worker.echo", lease.KeyID, privateKey)
	if err != nil {
		t.Fatalf("SignRuntimeLease() error = %v", err)
	}
	verifier := Ed25519RuntimeLeaseVerifier{
		Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
			KeyID:               signed.KeyID,
			PublicKey:           publicKey,
			RuntimeShardID:      signed.RuntimeShardID,
			RuntimeInstanceID:   signed.RuntimeInstanceID,
			RuntimeGenerationID: signed.RuntimeGenerationID,
			IPCChannelID:        signed.IPCChannelID,
			ConnectionNonce:     signed.ConnectionNonce,
		}}},
		Now: func() time.Time { return now },
	}
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{
		Lease:  signed,
		Method: "worker.echo",
		Now:    now,
	}); err != nil {
		t.Fatalf("VerifyRuntimeLease() error = %v", err)
	}

	tampered := signed
	tampered.RevokeEpoch++
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{Lease: tampered, Method: "worker.echo", Now: now}); !errors.Is(err, ErrRuntimeLeaseSignatureInvalid) {
		t.Fatalf("VerifyRuntimeLease(tampered revoke_epoch) error = %v, want %v", err, ErrRuntimeLeaseSignatureInvalid)
	}
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{Lease: signed, Method: "worker.other", Now: now}); !errors.Is(err, ErrRuntimeLeaseSignatureInvalid) {
		t.Fatalf("VerifyRuntimeLease(wrong method) error = %v, want %v", err, ErrRuntimeLeaseSignatureInvalid)
	}

	wrongRuntime := signed
	wrongRuntime.RuntimeGenerationID = "rtgen_other"
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{Lease: wrongRuntime, Method: "worker.echo", Now: now}); !errors.Is(err, ErrRuntimeLeaseSigningKeyNotFound) {
		t.Fatalf("VerifyRuntimeLease(wrong runtime) error = %v, want %v", err, ErrRuntimeLeaseSigningKeyNotFound)
	}

	wrongKey := signed
	wrongKeyVerifier := Ed25519RuntimeLeaseVerifier{
		Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
			KeyID:     wrongKey.KeyID,
			PublicKey: runtimeLeaseSignatureTestPrivateKey(99).Public().(ed25519.PublicKey),
		}}},
		Now: func() time.Time { return now },
	}
	if err := wrongKeyVerifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{Lease: wrongKey, Method: "worker.echo", Now: now}); !errors.Is(err, ErrRuntimeLeaseSignatureInvalid) {
		t.Fatalf("VerifyRuntimeLease(wrong key) error = %v, want %v", err, ErrRuntimeLeaseSignatureInvalid)
	}

	expired := signed
	expired.ExpiresAt = now.Add(-time.Second)
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{Lease: expired, Method: "worker.echo", Now: now}); !errors.Is(err, ErrRuntimeLeaseInvalid) {
		t.Fatalf("VerifyRuntimeLease(expired) error = %v, want %v", err, ErrRuntimeLeaseInvalid)
	}
}

func TestProcessSupervisorRuntimeLeaseVerifierRejectsInvalidSignatureBeforeIPC(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 0, 0, 0, time.UTC)
	privateKey := runtimeLeaseSignatureTestPrivateKey(11)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	diagnostics := observability.NewMemoryStore()
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE=1",
		),
		Diagnostics: diagnostics,
		RuntimeLeaseVerifier: Ed25519RuntimeLeaseVerifier{
			Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
				KeyID:     "host_ephemeral_key_1",
				PublicKey: publicKey,
			}}},
			Now: func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	lease := runtimeLeaseSignatureTestLease(now)
	lease.RuntimeGenerationID = health.RuntimeGenerationID
	lease.RuntimeInstanceID = health.RuntimeInstanceID
	lease.IPCChannelID = health.IPCChannelID
	lease.ConnectionNonce = health.ConnectionNonce
	signed, err := SignRuntimeLease(lease, "worker.echo", "host_ephemeral_key_1", privateKey)
	if err != nil {
		t.Fatalf("SignRuntimeLease() error = %v", err)
	}
	signed.PolicyRevision++

	if _, err := supervisor.InvokeWorker(context.Background(), signed, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeLeaseSignatureInvalid) {
		t.Fatalf("InvokeWorker(invalid signature) error = %v, want %v", err, ErrRuntimeLeaseSignatureInvalid)
	}
	waitForDiagnostic(t, diagnostics, "plugin.runtime.lease.signature_rejected")
	stopRuntimeSupervisor(t, supervisor)
}

func runtimeLeaseSignatureTestLease(now time.Time) Lease {
	return Lease{
		LeaseID:             "rel_lease_signature",
		LeaseToken:          "runtime_execution_lease.rel_lease_signature.secret",
		LeaseNonce:          "nonce_1234567890",
		RuntimeGenerationID: "rtgen_1",
		PluginInstanceID:    "plugini_1",
		Method:              "worker.echo",
		TargetDescriptorHashes: []string{
			"method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		PolicyRevision:     11,
		ManagementRevision: 12,
		RevokeEpoch:        13,
		RuntimeShardID:     "rtshard_1",
		RuntimeInstanceID:  "rtinst_1",
		IPCChannelID:       "ipc_1",
		ConnectionNonce:    "connection_nonce_1234567890",
		KeyID:              "host_ephemeral_key_1",
		ExpiresAt:          now.Add(30 * time.Second),
	}
}

func runtimeLeaseSignatureTestPrivateKey(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	return ed25519.NewKeyFromSeed(seed)
}
