package runtimeclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
		decoded["lease_id"] != lease.LeaseID ||
		decoded["token_id"] != lease.TokenID ||
		decoded["plugin_id"] != lease.PluginID ||
		decoded["plugin_version"] != lease.PluginVersion ||
		decoded["active_fingerprint"] != lease.ActiveFingerprint ||
		decoded["issued_at_unix_ms"] != float64(lease.IssuedAtUnixMillis) ||
		decoded["key_id"] != lease.KeyID ||
		decoded["method"] != "worker.echo" ||
		decoded["effect"] != lease.Effect ||
		decoded["execution"] != lease.Execution ||
		decoded["audit_correlation_id"] != lease.AuditCorrelationID ||
		decoded["surface_instance_id"] != lease.SurfaceInstanceID ||
		decoded["owner_session_hash"] != lease.OwnerSessionHash ||
		decoded["owner_user_hash"] != lease.OwnerUserHash ||
		decoded["session_channel_id_hash"] != lease.SessionChannelIDHash ||
		decoded["bridge_channel_id"] != lease.BridgeChannelID ||
		decoded["expires_at_unix_ms"] != float64(unixMillis(lease.ExpiresAt)) {
		t.Fatalf("canonical payload mismatch: %#v", decoded)
	}
	limits, ok := decoded["limits"].(map[string]any)
	if !ok ||
		limits["timeout_ms"] != float64(2000) ||
		limits["memory_bytes"] != float64(65536) ||
		limits["max_payload_bytes"] != float64(4096) ||
		limits["max_stream_bytes_per_sec"] != float64(1024) {
		t.Fatalf("canonical payload limits mismatch: %#v", decoded["limits"])
	}
}

func TestRuntimeLeaseSignatureSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts/runtime-lease-signature-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Method          string `json:"method"`
		PublicKeyBase64 string `json:"public_key_base64"`
		Canonical       string `json:"canonical_payload"`
		Signature       string `json:"signature"`
		Lease           Lease  `json:"lease"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalRuntimeLeaseSignaturePayload(fixture.Lease, fixture.Method)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != fixture.Canonical || fixture.Lease.Signature != fixture.Signature {
		t.Fatalf("shared fixture canonical payload mismatch:\n got: %s\nwant: %s", payload, fixture.Canonical)
	}
	publicKey, err := base64.StdEncoding.DecodeString(fixture.PublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	verifier := Ed25519RuntimeLeaseVerifier{Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
		KeyID: fixture.Lease.KeyID, PublicKey: ed25519.PublicKey(publicKey),
	}}}}
	if err := verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{
		Lease: fixture.Lease, Method: fixture.Method, Now: fixture.Lease.IssuedAt.Add(time.Second),
	}); err != nil {
		t.Fatalf("shared fixture signature verification failed: %v", err)
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

func TestProcessSupervisorRejectsInvalidLeaseBeforeIPC(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 0, 0, 0, time.UTC)
	diagnostics := observability.NewMemoryStore()
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE=1",
		),
		Diagnostics: diagnostics,
		Now:         func() time.Time { return now },
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
	lease.Execution = "subscription"
	lease.OperationID = ""
	lease.StreamID = ""

	if _, err := supervisor.InvokeWorker(context.Background(), lease, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeLeaseInvalid) {
		t.Fatalf("InvokeWorker(invalid lease) error = %v, want %v", err, ErrRuntimeLeaseInvalid)
	}
	waitForDiagnostic(t, diagnostics, "plugin.runtime.lease.signature_rejected")
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorSendsRuntimeLeasePublicKeysInHello(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_LEASE_PUBLIC_KEY=1",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_SIGNED_LEASE=1",
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_auto_signed"}, "worker.echo", workerInvocationFixture()); err != nil {
		t.Fatalf("InvokeWorker() automatic signature error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func runtimeLeaseSignatureTestLease(now time.Time) Lease {
	return Lease{
		LeaseID:              "rel_lease_signature",
		TokenID:              "rel_token_signature",
		LeaseToken:           "runtime_execution_lease.rel_lease_signature.secret",
		LeaseNonce:           "nonce_1234567890",
		PluginID:             "com.example.worker",
		PluginVersion:        "1.2.3",
		ActiveFingerprint:    "sha256:active",
		SurfaceInstanceID:    "surface_runtime",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_runtime",
		RuntimeGenerationID:  "rtgen_1",
		PluginInstanceID:     "plugini_1",
		Method:               "worker.echo",
		Effect:               "read",
		Execution:            "sync",
		AuditCorrelationID:   "audit_lease_signature",
		TargetDescriptorHashes: []string{
			"method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		Limits:             LeaseLimits{TimeoutMillis: 2000, MemoryBytes: 65536, MaxPayloadBytes: 4096, MaxStreamBytesPerSecond: 1024},
		PolicyRevision:     11,
		ManagementRevision: 12,
		RevokeEpoch:        13,
		RuntimeShardID:     "rtshard_1",
		RuntimeInstanceID:  "rtinst_1",
		IPCChannelID:       "ipc_1",
		ConnectionNonce:    "connection_nonce_1234567890",
		KeyID:              "host_ephemeral_key_1",
		IssuedAt:           now,
		IssuedAtUnixMillis: unixMillis(now),
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
