package releasetrust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestReleaseTrustServiceRefreshSourceVerifiesOneAtomicSnapshot(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	snapshot, err := fixture.service.RefreshSource(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceTrustKey() != fixture.key || snapshot.StateSHA256() == "" ||
		snapshot.SourcePolicy().Epoch != "1" || snapshot.Revocation().Epoch != "1" ||
		snapshot.RootDelegation().RootEpoch != "1" {
		t.Fatalf("verified snapshot = %#v", snapshot)
	}
	committed := fixture.state.committedState(t)
	if committed.Root == nil || committed.SigningLedger == nil || len(committed.Channels) != 1 ||
		committed.Channels[0].Policy == nil || committed.Channels[0].Revocation == nil ||
		committed.Channels[0].Policy.PointerTransportToken == "" || committed.Channels[0].Policy.DocumentTransportToken == "" {
		t.Fatalf("committed source snapshot = %#v", committed)
	}
	current, ok := fixture.service.CurrentVerifiedSource(fixture.key)
	if !ok || current.StateSHA256() != snapshot.StateSHA256() {
		t.Fatalf("current snapshot = %#v, %v", current, ok)
	}
	policy := current.SourcePolicy()
	policy.AllowedPublishers[0] = "mutated"
	if fixture.service.verified[fixture.key].policy.AllowedPublishers[0] != "example.publisher" {
		t.Fatal("CurrentVerifiedSource exposed mutable policy storage")
	}
}

func TestReleaseTrustServiceRefreshSourceRejectsLedgerEvidenceSubstitution(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	for locator, value := range fixture.ledger.values {
		if !bytes.Contains(value, []byte(`"schema_version":"redevplugin.release_signing_ledger_evidence.v1"`)) {
			continue
		}
		tampered := slices.Clone(value)
		needle := []byte(`"signing_preimage_sha256":"`)
		index := bytes.Index(tampered, needle)
		if index < 0 {
			t.Fatal("evidence fixture is missing signing_preimage_sha256")
		}
		if tampered[index+len(needle)] == 'f' {
			tampered[index+len(needle)] = 'e'
		} else {
			tampered[index+len(needle)] = 'f'
		}
		fixture.ledger.values[locator] = tampered
	}
	if _, err := fixture.service.RefreshSource(context.Background(), fixture.key); !errors.Is(err, ErrReleaseTrustVerification) {
		t.Fatalf("RefreshSource(tampered evidence) error = %v", err)
	}
	if len(fixture.state.committed) != 0 || len(fixture.state.pending) != 0 {
		t.Fatal("failed refresh mutated durable trust state")
	}
}

func TestReleaseTrustServiceRejectsPolicyPointerIdentitySubstitution(t *testing.T) {
	for name, mutate := range map[string]func(*releasecontract.ReleasePointerInput){
		"source":  func(input *releasecontract.ReleasePointerInput) { input.SourceID = "other_source" },
		"channel": func(input *releasecontract.ReleasePointerInput) { input.Channel = "other" },
		"key":     func(input *releasecontract.ReleasePointerInput) { input.KeyID = "other_key" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFullRefreshFixture(t)
			locator := "sources/example_source/stable/policy/current.json"
			pointer, err := releasecontract.DecodeSourcePolicyPointer(fixture.documents.values[locator])
			if err != nil {
				t.Fatal(err)
			}
			input := releasecontract.ReleasePointerInput{
				SourceID: pointer.SourceID, Channel: pointer.Channel, Epoch: pointer.Epoch, PreviousEpoch: pointer.PreviousEpoch,
				PreviousDocumentSHA256: pointer.PreviousDocumentSHA256, Ref: pointer.Ref, DocumentSHA256: pointer.DocumentSHA256,
				GeneratedAt: pointer.GeneratedAt, ExpiresAt: pointer.ExpiresAt, KeyID: pointer.KeyID,
			}
			mutate(&input)
			preimage, err := releasecontract.SourcePolicyPointerSigningPreimage(input)
			if err != nil {
				t.Fatal(err)
			}
			pointer, err = releasecontract.BuildSourcePolicyPointer(input, signDigest(fixture.signingPrivate, preimage))
			if err != nil {
				t.Fatal(err)
			}
			fixture.documents.values[locator], err = releasecontract.CanonicalSourcePolicyPointer(pointer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.RefreshSource(context.Background(), fixture.key); !errors.Is(err, ErrReleaseTrustVerification) {
				t.Fatalf("RefreshSource(substituted pointer) error = %v", err)
			}
		})
	}
}

func TestReleaseTrustAdvanceRejectsEpochReplayForkAndSkip(t *testing.T) {
	rootHead := &ReleaseTrustRootHeadV1{Epoch: "4", DocumentSHA256: strings.Repeat("a", 64)}
	for name, root := range map[string]releasecontract.RootDelegationV1{
		"same epoch fork": {RootEpoch: "4", PreviousRootEpoch: "3", PreviousDelegationSHA256: strings.Repeat("9", 64)},
		"skipped epoch":   {RootEpoch: "6", PreviousRootEpoch: "4", PreviousDelegationSHA256: rootHead.DocumentSHA256},
		"wrong previous":  {RootEpoch: "5", PreviousRootEpoch: "3", PreviousDelegationSHA256: rootHead.DocumentSHA256},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyRootAdvance(rootHead, root, strings.Repeat("b", 64)); !errors.Is(err, ErrReleaseTrustRollback) {
				t.Fatalf("verifyRootAdvance() error = %v", err)
			}
		})
	}
	documentHead := &ReleaseTrustDocumentHeadV1{
		PointerEpoch: "7", PointerSHA256: strings.Repeat("c", 64), DocumentSHA256: strings.Repeat("d", 64),
	}
	for name, values := range map[string][5]string{
		"same epoch fork": {"7", "6", strings.Repeat("a", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)},
		"skipped epoch":   {"9", "7", documentHead.DocumentSHA256, strings.Repeat("e", 64), strings.Repeat("f", 64)},
		"wrong previous":  {"8", "6", documentHead.DocumentSHA256, strings.Repeat("e", 64), strings.Repeat("f", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyPointerAdvance(documentHead, values[0], values[1], values[2], values[3], values[4]); !errors.Is(err, ErrReleaseTrustRollback) {
				t.Fatalf("verifyPointerAdvance() error = %v", err)
			}
		})
	}
}

func TestActivationLeaseUsesOnlyProcessLocalElapsedState(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	elapsed := time.Duration(0)
	fixture.service.elapsedNow = func() time.Duration { return elapsed }
	snapshot, err := fixture.service.RefreshSource(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.service.authorizeActivation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if lease.RefreshAfter() != time.Minute || lease.ValidFor() != 5*time.Minute {
		t.Fatalf("lease timing = refresh %s valid %s", lease.RefreshAfter(), lease.ValidFor())
	}
	if err := fixture.service.ValidateActivationLease(lease); err != nil {
		t.Fatal(err)
	}
	elapsed = 5*time.Minute - time.Nanosecond
	if err := fixture.service.ValidateActivationLease(lease); err != nil {
		t.Fatalf("lease expired before monotonic deadline: %v", err)
	}
	elapsed = 5 * time.Minute
	if err := fixture.service.ValidateActivationLease(lease); !errors.Is(err, ErrActivationLeaseExpired) {
		t.Fatalf("lease expiry error = %v", err)
	}

	restarted, err := NewReleaseTrustService(fixture.service.options, fixture.service.adapters)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ValidateActivationLease(lease); !errors.Is(err, ErrActivationLeaseInvalid) {
		t.Fatalf("cross-process lease error = %v", err)
	}
}

func TestActivationLeaseValidationPerformsNoAdapterIO(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	snapshot, err := fixture.service.RefreshSource(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.service.authorizeActivation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	documentCalls := fixture.documents.calls
	ledgerCalls := fixture.ledger.calls
	fixture.state.mu.Lock()
	stateCalls := [3]int{fixture.state.loadCalls, fixture.state.prepareCalls, fixture.state.commitCalls}
	fixture.state.mu.Unlock()
	fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).mu.Lock()
	timeCalls := fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).calls
	fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).mu.Unlock()

	for range 1000 {
		if err := fixture.service.ValidateActivationLease(lease); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.documents.calls != documentCalls || fixture.ledger.calls != ledgerCalls {
		t.Fatal("lease validation performed release transport I/O")
	}
	fixture.state.mu.Lock()
	gotStateCalls := [3]int{fixture.state.loadCalls, fixture.state.prepareCalls, fixture.state.commitCalls}
	fixture.state.mu.Unlock()
	if gotStateCalls != stateCalls {
		t.Fatalf("lease validation state calls = %v, want %v", gotStateCalls, stateCalls)
	}
	fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).mu.Lock()
	gotTimeCalls := fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).calls
	fixture.service.adapters.TrustedTime.(*testTransparencyTimeAdapter).mu.Unlock()
	if gotTimeCalls != timeCalls {
		t.Fatalf("lease validation time calls = %d, want %d", gotTimeCalls, timeCalls)
	}
}

func TestTrustAdvanceDurablyFencesOldHeadBeforeTeardown(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	snapshot, err := fixture.service.RefreshSource(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.authorizeActivation(snapshot); err != nil {
		t.Fatal(err)
	}
	documents := fixture.verifiedDocuments(t)
	documents.policyPointer.Epoch = "2"
	documents.policy.Epoch = "2"
	fixture.fence.inspect = func(request SourceFenceRequest) {
		committed := fixture.state.committedState(t)
		channel := findChannelState(committed, fixture.key.channel)
		if channel == nil || channel.Fence == nil || channel.Fence.Reason != "trust_advanced" || channel.Policy.PointerEpoch != "1" {
			t.Fatalf("state visible to teardown = %#v", channel)
		}
		if request.TeardownDeadline() != 30*time.Second {
			t.Fatalf("teardown deadline = %s", request.TeardownDeadline())
		}
	}
	current, currentSHA256, err := fixture.service.loadAndRecover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.refreshMu.Lock()
	advanced, err := fixture.service.commitVerifiedDocumentSetLocked(
		context.Background(), fixture.key, current, currentSHA256, documents,
	)
	fixture.service.refreshMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if advanced.SourcePolicy().Epoch != "2" || fixture.fence.calls != 1 {
		t.Fatalf("advanced snapshot = %#v, teardown calls = %d", advanced, fixture.fence.calls)
	}
	committed := fixture.state.committedState(t)
	channel := findChannelState(committed, fixture.key.channel)
	if channel == nil || channel.Fence != nil || channel.FenceGeneration != 1 || channel.Policy.PointerEpoch != "2" {
		t.Fatalf("committed advanced state = %#v", channel)
	}
}

func TestReleaseTrustServiceReconcilesDurableFenceAfterRestart(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	if _, err := fixture.service.RefreshSource(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	fixture.fence.err = errors.New("teardown interrupted")
	status, err := fixture.service.FenceSource(context.Background(), fixture.key, "refresh_failed")
	if err == nil {
		t.Fatal("FenceSource() unexpectedly completed teardown")
	}
	if channel := findChannelState(fixture.state.committedState(t), fixture.key.channel); channel == nil || channel.Fence == nil {
		t.Fatal("failed teardown did not retain durable fence")
	}

	fixture.fence.err = nil
	restarted, err := NewReleaseTrustService(fixture.service.options, fixture.service.adapters)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RefreshSource(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	channel := findChannelState(fixture.state.committedState(t), fixture.key.channel)
	if channel == nil || channel.Fence != nil || channel.FenceGeneration != status.Generation() || fixture.fence.calls != 2 {
		t.Fatalf("reconciled channel = %#v, teardown calls = %d", channel, fixture.fence.calls)
	}
}

func TestSourceFenceGenerationRejectsStaleAcknowledgement(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	if _, err := fixture.service.RefreshSource(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.service.FenceSource(context.Background(), fixture.key, "refresh_failed")
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.refreshMu.Lock()
	current, currentSHA256, err := fixture.service.loadAndRecover(context.Background())
	if err == nil {
		_, _, err = fixture.service.acknowledgeSourceFenceLocked(context.Background(), fixture.key, first.Generation(), current, currentSHA256)
	}
	fixture.service.refreshMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.service.FenceSource(context.Background(), fixture.key, "expired")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation() != first.Generation()+1 {
		t.Fatalf("second generation = %d, want %d", second.Generation(), first.Generation()+1)
	}
	fixture.service.refreshMu.Lock()
	current, currentSHA256, err = fixture.service.loadAndRecover(context.Background())
	if err == nil {
		_, _, err = fixture.service.acknowledgeSourceFenceLocked(context.Background(), fixture.key, first.Generation(), current, currentSHA256)
	}
	fixture.service.refreshMu.Unlock()
	if !errors.Is(err, ErrSourceTrustFenced) {
		t.Fatalf("stale acknowledgement error = %v", err)
	}
	channel := findChannelState(fixture.state.committedState(t), fixture.key.channel)
	if channel == nil || channel.Fence == nil || channel.Fence.Generation != second.Generation() {
		t.Fatalf("stale acknowledgement cleared fence: %#v", channel)
	}
}

func TestRefreshFailureDurablyFencesBeforeTeardown(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	snapshot, err := fixture.service.RefreshSource(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.service.authorizeActivation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.documents.values["sources/example_source/stable/policy/current.json"] = []byte("not canonical JSON")
	if _, err := fixture.service.RefreshActivationLease(context.Background(), lease); err == nil {
		t.Fatal("RefreshActivationLease() unexpectedly accepted corrupt policy pointer")
	}
	committed := fixture.state.committedState(t)
	if len(committed.Channels) != 1 || committed.Channels[0].Fence == nil || committed.Channels[0].Fence.Reason != "refresh_failed" {
		t.Fatalf("committed fence = %#v", committed.Channels)
	}
	if fixture.fence.calls != 1 || fixture.fence.last.Generation() != committed.Channels[0].Fence.Generation {
		t.Fatalf("fence coordinator calls=%d last=%#v", fixture.fence.calls, fixture.fence.last)
	}
	if err := fixture.service.ValidateActivationLease(lease); !errors.Is(err, ErrActivationLeaseInvalid) {
		t.Fatalf("fenced lease error = %v", err)
	}
}

func TestServiceSetVerifiesReleaseMetadataAndPackageAgainstPreparedSnapshot(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	services, err := NewServiceSet(fixture.service)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := services.PrepareRelease(context.Background(), fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := services.VerifyReleaseMetadata(context.Background(), prepared, fixture.metadataBytes, fixture.metadataSignature)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := services.VerifyPackage(context.Background(), metadata, fixture.packageSignature)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PackageSignature().KeyID != "signing_key" || verified.ReleaseMetadata().Document().PluginID != "example.plugin" {
		t.Fatalf("verified release = %#v", verified)
	}
	if _, err := verified.AuthorizeActivation(); err != nil {
		t.Fatal(err)
	}
	if _, ok := any(prepared).(interface {
		AuthorizeActivation() (ActivationLease, error)
	}); ok {
		t.Fatal("PreparedRelease exposed activation before package verification")
	}

	tampered := slices.Clone(fixture.metadataSignature)
	tampered[0] ^= 0xff
	if _, err := services.VerifyReleaseMetadata(context.Background(), prepared, fixture.metadataBytes, tampered); !errors.Is(err, ErrReleaseTrustVerification) {
		t.Fatalf("tampered metadata signature error = %v", err)
	}
}

func TestServiceSetBindsOneFenceCoordinatorBeforeActivation(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	adapters := fixture.service.adapters
	adapters.Fence = nil
	service, err := NewReleaseTrustService(fixture.service.options, adapters)
	if err != nil {
		t.Fatal(err)
	}
	services, err := NewServiceSet(service)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := services.PrepareRelease(context.Background(), fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := services.VerifyReleaseMetadata(context.Background(), prepared, fixture.metadataBytes, fixture.metadataSignature)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := services.VerifyPackage(context.Background(), metadata, fixture.packageSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.AuthorizeActivation(); !errors.Is(err, ErrActivationLeaseInvalid) {
		t.Fatalf("activation before fence bind error = %v", err)
	}
	if err := services.BindFenceCoordinator(fixture.fence); err != nil {
		t.Fatal(err)
	}
	lease, err := verified.AuthorizeActivation()
	if err != nil {
		t.Fatal(err)
	}
	if err := services.ValidateActivationLease(lease); err != nil {
		t.Fatal(err)
	}
	if err := services.BindFenceCoordinator(fixture.fence); !errors.Is(err, ErrServiceSetFenceBound) {
		t.Fatalf("second fence bind error = %v", err)
	}
}

func TestServiceSetRejectsMetadataAndPackageSubstitution(t *testing.T) {
	fixture := newFullRefreshFixture(t)
	services, err := NewServiceSet(fixture.service)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := services.PrepareRelease(context.Background(), fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	document, err := releasecontract.DecodeReleaseMetadata(fixture.metadataBytes)
	if err != nil {
		t.Fatal(err)
	}
	document.Metadata = map[string]string{"substituted": "true"}
	document, err = releasecontract.BuildReleaseMetadata(document)
	if err != nil {
		t.Fatal(err)
	}
	substitutedBytes, err := releasecontract.CanonicalReleaseMetadata(document)
	if err != nil {
		t.Fatal(err)
	}
	substitutedPreimage, err := releasecontract.ReleaseMetadataSigningPreimage("stable", document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.VerifyReleaseMetadata(
		context.Background(), prepared, substitutedBytes, signDigest(fixture.signingPrivate, substitutedPreimage),
	); !errors.Is(err, ErrInvalidReleaseIdentity) {
		t.Fatalf("substituted metadata error = %v", err)
	}

	metadata, err := services.VerifyReleaseMetadata(context.Background(), prepared, fixture.metadataBytes, fixture.metadataSignature)
	if err != nil {
		t.Fatal(err)
	}
	substitutedInput := releasecontract.PackageSigningInput{
		SourceID: "example_source", Channel: "stable", Version: "1.2.3", Algorithm: releasecontract.SignatureAlgorithmEd25519,
		KeyID: "signing_key", PublisherID: "other.publisher", PluginID: "example.plugin",
		PackageHash: "sha256:" + strings.Repeat("a", 64), ManifestHash: "sha256:" + strings.Repeat("b", 64),
		EntriesHash: "sha256:" + strings.Repeat("c", 64), SignedAt: "2026-07-21T01:00:00Z",
	}
	packagePreimage, err := releasecontract.PackageSigningPreimage(substitutedInput)
	if err != nil {
		t.Fatal(err)
	}
	substitutedPackage, err := releasecontract.BuildPackageSignature(substitutedInput, signDigest(fixture.signingPrivate, packagePreimage))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.VerifyPackage(context.Background(), metadata, substitutedPackage); !errors.Is(err, ErrInvalidReleaseIdentity) {
		t.Fatalf("substituted package error = %v", err)
	}
}

func TestServiceSetRejectsLedgerCheckpointDriftAcrossReleaseVerification(t *testing.T) {
	t.Run("release metadata", func(t *testing.T) {
		fixture := newFullRefreshFixture(t)
		services, err := NewServiceSet(fixture.service)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := services.PrepareRelease(context.Background(), fixture.identity)
		if err != nil {
			t.Fatal(err)
		}
		subject := releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageReleaseMetadata,
			SourceID: fixture.identity.SourceID, Channel: fixture.identity.Channel, PublisherID: fixture.identity.PublisherID,
			PluginID: fixture.identity.PluginID, Version: fixture.identity.Version, ArtifactIdentitySHA256: fixture.identity.ReleaseMetadataSHA256,
		}
		fixture.retargetLedgerCheckpoint(t, subject, "2026-07-21T02:01:00Z")
		if _, err := services.VerifyReleaseMetadata(
			context.Background(), prepared, fixture.metadataBytes, fixture.metadataSignature,
		); !errors.Is(err, ErrReleaseTrustRollback) {
			t.Fatalf("metadata checkpoint drift error = %v", err)
		}
	})

	t.Run("package", func(t *testing.T) {
		fixture := newFullRefreshFixture(t)
		services, err := NewServiceSet(fixture.service)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := services.PrepareRelease(context.Background(), fixture.identity)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := services.VerifyReleaseMetadata(context.Background(), prepared, fixture.metadataBytes, fixture.metadataSignature)
		if err != nil {
			t.Fatal(err)
		}
		subject := releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsagePackage,
			SourceID: fixture.identity.SourceID, Channel: fixture.identity.Channel, PublisherID: fixture.identity.PublisherID,
			PluginID: fixture.identity.PluginID, Version: fixture.identity.Version,
			ArtifactIdentitySHA256: normalizeReleaseSHA256(metadata.document.Hashes.PackageSHA256),
		}
		fixture.retargetLedgerCheckpoint(t, subject, "2026-07-21T02:01:00Z")
		if _, err := services.VerifyPackage(context.Background(), metadata, fixture.packageSignature); !errors.Is(err, ErrReleaseTrustRollback) {
			t.Fatalf("package checkpoint drift error = %v", err)
		}
	})
}

type fullRefreshFixture struct {
	service           *ReleaseTrustService
	key               SourceTrustKey
	state             *memorySourceTrustStateStore
	documents         *fixtureDocumentTransport
	ledger            *fixtureLedgerTransport
	fence             *fixtureFenceCoordinator
	identity          ReleaseIdentity
	metadataBytes     []byte
	metadataSignature []byte
	packageSignature  releasecontract.PackageSignatureV1
	signingPrivate    ed25519.PrivateKey
	ledgerPrivate     ed25519.PrivateKey
}

type fixtureDocumentTransport struct {
	values map[string][]byte
	tokens map[string]string
	calls  int
}

func (transport *fixtureDocumentTransport) FetchReleaseDocument(_ context.Context, request ReleaseDocumentRequest) (ReleaseDocumentResult, error) {
	transport.calls++
	locator := request.Locator().String()
	value := transport.values[locator]
	if value == nil {
		return ReleaseDocumentResult{}, fmt.Errorf("missing document fixture %s", locator)
	}
	return NewReleaseDocumentResult(request, transport.tokens[locator], value)
}

type fixtureLedgerTransport struct {
	values map[string][]byte
	calls  int
}

func (transport *fixtureLedgerTransport) FetchSigningLedgerArtifact(_ context.Context, request SigningLedgerRequest) (SigningLedgerResult, error) {
	transport.calls++
	value := transport.values[request.Locator().String()]
	if value == nil {
		return SigningLedgerResult{}, fmt.Errorf("missing ledger fixture %s", request.Locator())
	}
	return NewSigningLedgerResult(request, value)
}

type fixtureFenceCoordinator struct {
	calls   int
	last    SourceFenceRequest
	err     error
	inspect func(SourceFenceRequest)
}

func (coordinator *fixtureFenceCoordinator) TeardownSourceTrust(_ context.Context, request SourceFenceRequest) error {
	coordinator.calls++
	coordinator.last = request
	if coordinator.inspect != nil {
		coordinator.inspect(request)
	}
	return coordinator.err
}

func (fixture fullRefreshFixture) verifiedDocuments(t *testing.T) verifiedReleaseDocumentSet {
	t.Helper()
	rootBytes := fixture.documents.values["sources/example_source/root/current.json"]
	policyPointerBytes := fixture.documents.values["sources/example_source/stable/policy/current.json"]
	revocationPointerBytes := fixture.documents.values["sources/example_source/stable/revocation/current.json"]
	root, err := releasecontract.DecodeRootDelegation(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	policyPointer, err := releasecontract.DecodeSourcePolicyPointer(policyPointerBytes)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes := fixture.documents.values[policyPointer.Ref]
	policy, err := releasecontract.DecodeSourcePolicy(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	revocationPointer, err := releasecontract.DecodeRevocationPointer(revocationPointerBytes)
	if err != nil {
		t.Fatal(err)
	}
	revocationBytes := fixture.documents.values[revocationPointer.Ref]
	revocation, err := releasecontract.DecodeRevocation(revocationBytes)
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.state.committedState(t)
	floor, err := parseCanonicalTime(state.TrustedTime.Floor)
	if err != nil {
		t.Fatal(err)
	}
	return verifiedReleaseDocumentSet{
		root: root, rootBytes: slices.Clone(rootBytes), policyPointer: policyPointer,
		policyPointerBytes: slices.Clone(policyPointerBytes), policyPointerToken: fixture.documents.tokens["sources/example_source/stable/policy/current.json"],
		policy: policy, policyBytes: slices.Clone(policyBytes), policyToken: fixture.documents.tokens[policyPointer.Ref],
		revocationPointer: revocationPointer, revocationPointerBytes: slices.Clone(revocationPointerBytes),
		revocationPointerToken: fixture.documents.tokens["sources/example_source/stable/revocation/current.json"],
		revocation:             revocation, revocationBytes: slices.Clone(revocationBytes), revocationToken: fixture.documents.tokens[revocationPointer.Ref],
		trustedTime: VerifiedTrustedTime{
			floor: floor, checkpointSHA256: state.TrustedTime.CheckpointSHA256,
			checkpoint: cloneCheckpoint(state.TrustedTime.Checkpoint),
		},
		ledgerCheckpoint: state.SigningLedger.Checkpoint, ledgerCheckpointSHA256: state.SigningLedger.CheckpointSHA256,
	}
}

func newFullRefreshFixture(t *testing.T) fullRefreshFixture {
	t.Helper()
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := configuration.TrustKey("stable")
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	signingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	timePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))
	ledgerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, ed25519.SeedSize))

	rootAnchor, _ := NewEd25519TrustAnchor("root_key", rootPrivate.Public().(ed25519.PublicKey))
	timeAnchor, _ := NewEd25519TrustAnchor("time_key", timePrivate.Public().(ed25519.PublicKey))
	timeRoot, _ := NewTransparencyRoot("time_log", timeAnchor)
	ledgerAnchor, _ := NewEd25519TrustAnchor("ledger_key", ledgerPrivate.Public().(ed25519.PublicKey))
	ledgerRoot, _ := NewPinnedSigningLedgerRoot("signing_log", ledgerAnchor)
	options, err := NewReleaseTrustOptions(configuration, rootAnchor, []TransparencyRoot{timeRoot}, ledgerRoot, SourceRelativeLocatorPolicyV1)
	if err != nil {
		t.Fatal(err)
	}

	generatedAt := "2026-07-21T01:00:00Z"
	expiresAt := "2026-07-22T01:00:00Z"
	rootInput := releasecontract.RootDelegationInput{
		SourceID: "example_source", RootEpoch: "1", PreviousRootEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDelegationSHA256: releasecontract.GenesisPreviousDocumentSHA256,
		GeneratedAt:              generatedAt, ExpiresAt: expiresAt,
		DelegatedKeys: []releasecontract.RootDelegatedKey{{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: "signing_key",
			PublicKey: base64.StdEncoding.EncodeToString(signingPrivate.Public().(ed25519.PublicKey)),
			Usages: []releasecontract.DelegatedKeyUsage{
				releasecontract.DelegatedKeyUsagePackage,
				releasecontract.DelegatedKeyUsageReleaseMetadata,
				releasecontract.DelegatedKeyUsageRevocation,
				releasecontract.DelegatedKeyUsageRevocationPointer,
				releasecontract.DelegatedKeyUsageSourcePolicy,
				releasecontract.DelegatedKeyUsageSourcePolicyPointer,
			},
			Channels: []string{"stable"}, ValidFrom: "2026-07-20T00:00:00Z", ValidUntil: expiresAt,
		}},
		KeyID: "root_key",
	}
	rootPreimage, _ := releasecontract.RootDelegationSigningPreimage(rootInput)
	root, err := releasecontract.BuildRootDelegation(rootInput, signDigest(rootPrivate, rootPreimage))
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, _ := releasecontract.CanonicalRootDelegation(root)

	policyInput := releasecontract.SourcePolicyInput{
		SourceID: "example_source", Channel: "stable", Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
		SourceType: "registry", SourceClass: "official", AllowedPublishers: []string{"example.publisher"},
		AllowedArtifactHosts: []string{"packages.example.com"},
		ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			Package: []string{"signing_key"}, ReleaseMetadata: []string{"signing_key"},
			SourcePolicyPointer: []string{"signing_key"}, Revocation: []string{"signing_key"}, RevocationPointer: []string{"signing_key"},
		},
		RequireSignature: true, InstallPolicy: "allow", UnsignedPolicy: "block", DowngradePolicy: "block",
		MinimumRevocationEpoch: "1", Limits: releasecontract.DefaultSourcePolicyLimits(),
		GeneratedAt: generatedAt, ExpiresAt: expiresAt, KeyID: "signing_key",
	}
	policyPreimage, _ := releasecontract.SourcePolicySigningPreimage(policyInput)
	policy, err := releasecontract.BuildSourcePolicy(policyInput, signDigest(signingPrivate, policyPreimage))
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, _ := releasecontract.CanonicalSourcePolicy(policy)
	policyRef := "sources/example_source/stable/policy/1.json"
	policyPointerInput := releasecontract.ReleasePointerInput{
		SourceID: "example_source", Channel: "stable", Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, Ref: policyRef, DocumentSHA256: digestHex(policyBytes),
		GeneratedAt: generatedAt, ExpiresAt: expiresAt, KeyID: "signing_key",
	}
	policyPointerPreimage, _ := releasecontract.SourcePolicyPointerSigningPreimage(policyPointerInput)
	policyPointer, err := releasecontract.BuildSourcePolicyPointer(policyPointerInput, signDigest(signingPrivate, policyPointerPreimage))
	if err != nil {
		t.Fatal(err)
	}
	policyPointerBytes, _ := releasecontract.CanonicalSourcePolicyPointer(policyPointer)

	revocationInput := releasecontract.RevocationInput{
		SourceID: "example_source", Channel: "stable", Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
		GeneratedAt: generatedAt, ExpiresAt: expiresAt, RevokedKeyIDs: []string{}, RevokedReleases: []releasecontract.RevokedRelease{},
		KeyID: "signing_key",
	}
	revocationPreimage, _ := releasecontract.RevocationSigningPreimage(revocationInput)
	revocation, err := releasecontract.BuildRevocation(revocationInput, signDigest(signingPrivate, revocationPreimage))
	if err != nil {
		t.Fatal(err)
	}
	revocationBytes, _ := releasecontract.CanonicalRevocation(revocation)
	revocationRef := "sources/example_source/stable/revocation/1.json"
	revocationPointerInput := releasecontract.ReleasePointerInput{
		SourceID: "example_source", Channel: "stable", Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, Ref: revocationRef, DocumentSHA256: digestHex(revocationBytes),
		GeneratedAt: generatedAt, ExpiresAt: expiresAt, KeyID: "signing_key",
	}
	revocationPointerPreimage, _ := releasecontract.RevocationPointerSigningPreimage(revocationPointerInput)
	revocationPointer, err := releasecontract.BuildRevocationPointer(revocationPointerInput, signDigest(signingPrivate, revocationPointerPreimage))
	if err != nil {
		t.Fatal(err)
	}
	revocationPointerBytes, _ := releasecontract.CanonicalRevocationPointer(revocationPointer)

	releaseMetadata := releasecontract.ReleaseMetadataV5{
		SchemaVersion: releasecontract.ReleaseMetadataSchemaVersion, SourceID: "example_source",
		ReleaseMetadataRef: "plugins/example.publisher/example.plugin/1.2.3/release.json",
		PublisherID:        "example.publisher", PluginID: "example.plugin", Version: "1.2.3",
		DistributionRef: releasecontract.ReleaseDistributionRef{Distribution: "registry_ref", ArtifactRef: "plugins/example.publisher/example.plugin/1.2.3/package.zip"},
		Hashes: releasecontract.ReleasePackageHashSet{
			PackageSHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), EntriesSHA256: strings.Repeat("c", 64),
		},
		ReleaseMetadataSignature: releasecontract.ReleaseMetadataSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: "signing_key",
			SignatureRef: "plugins/example.publisher/example.plugin/1.2.3/release.sig", SourcePolicyEpoch: "1", RevocationEpoch: "1",
		},
		PackageSignature: releasecontract.PackageReleaseSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: "signing_key",
			SignatureBundleRef: "plugins/example.publisher/example.plugin/1.2.3/package.sig", SourcePolicyEpoch: "1", RevocationEpoch: "1",
		},
		Compatibility: releasecontract.ReleaseCompatibility{
			MinReDevPluginVersion: "0.6.0", MinRuntimeVersion: "0.6.0", UIProtocolVersion: "plugin-ui-v5",
		},
	}
	releaseMetadata, err = releasecontract.BuildReleaseMetadata(releaseMetadata)
	if err != nil {
		t.Fatal(err)
	}
	metadataBytes, _ := releasecontract.CanonicalReleaseMetadata(releaseMetadata)
	metadataPreimage, _ := releasecontract.ReleaseMetadataSigningPreimage("stable", releaseMetadata)
	metadataSignature := signDigest(signingPrivate, metadataPreimage)
	metadataDigest := digestHex(metadataBytes)
	identity := ReleaseIdentity{
		SourceID: "example_source", Channel: "stable", ReleaseMetadataRef: releaseMetadata.ReleaseMetadataRef,
		ReleaseMetadataSHA256: metadataDigest, PublisherID: "example.publisher", PluginID: "example.plugin", Version: "1.2.3",
	}
	packageInput := releasecontract.PackageSigningInput{
		SourceID: "example_source", Channel: "stable", Version: "1.2.3", Algorithm: releasecontract.SignatureAlgorithmEd25519,
		KeyID: "signing_key", PublisherID: "example.publisher", PluginID: "example.plugin",
		PackageHash: "sha256:" + strings.Repeat("a", 64), ManifestHash: "sha256:" + strings.Repeat("b", 64),
		EntriesHash: "sha256:" + strings.Repeat("c", 64), SignedAt: generatedAt,
	}
	packagePreimage, _ := releasecontract.PackageSigningPreimage(packageInput)
	packageSignature, err := releasecontract.BuildPackageSignature(packageInput, signDigest(signingPrivate, packagePreimage))
	if err != nil {
		t.Fatal(err)
	}

	documents := &fixtureDocumentTransport{values: map[string][]byte{}, tokens: map[string]string{}}
	for locator, value := range map[string][]byte{
		"sources/example_source/root/current.json":          rootBytes,
		"sources/example_source/stable/policy/current.json": policyPointerBytes,
		policyRef: policyBytes,
		"sources/example_source/stable/revocation/current.json": revocationPointerBytes,
		revocationRef: revocationBytes,
	} {
		documents.values[locator] = value
		documents.tokens[locator] = "etag-" + hex.EncodeToString([]byte{byte(len(documents.tokens) + 1)})
	}

	signed := []fixtureSignedDocument{
		{subject: rootSigningSubject(root), preimage: rootPreimage, keyID: root.KeyID, signature: root.Signature},
		{subject: epochSigningSubject(key, releasecontract.SigningSubjectUsageSourcePolicyPointer, "1"), preimage: policyPointerPreimage, keyID: policyPointer.KeyID, signature: policyPointer.Signature},
		{subject: epochSigningSubject(key, releasecontract.SigningSubjectUsageSourcePolicy, "1"), preimage: policyPreimage, keyID: policy.KeyID, signature: policy.Signature},
		{subject: epochSigningSubject(key, releasecontract.SigningSubjectUsageRevocationPointer, "1"), preimage: revocationPointerPreimage, keyID: revocationPointer.KeyID, signature: revocationPointer.Signature},
		{subject: epochSigningSubject(key, releasecontract.SigningSubjectUsageRevocation, "1"), preimage: revocationPreimage, keyID: revocation.KeyID, signature: revocation.Signature},
		{subject: releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageReleaseMetadata,
			SourceID: "example_source", Channel: "stable", PublisherID: "example.publisher", PluginID: "example.plugin",
			Version: "1.2.3", ArtifactIdentitySHA256: metadataDigest,
		}, preimage: metadataPreimage, keyID: "signing_key", signature: base64.StdEncoding.EncodeToString(metadataSignature)},
		{subject: releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsagePackage,
			SourceID: "example_source", Channel: "stable", PublisherID: "example.publisher", PluginID: "example.plugin",
			Version: "1.2.3", ArtifactIdentitySHA256: strings.Repeat("a", 64),
		}, preimage: packagePreimage, keyID: "signing_key", signature: packageSignature.Signature},
	}
	ledger := buildFixtureLedger(t, configuration, signed, ledgerPrivate, "2026-07-21T02:00:00Z")
	state := &memorySourceTrustStateStore{}
	fence := &fixtureFenceCoordinator{}
	timeAdapter := &testTransparencyTimeAdapter{
		t: t, privateKey: timePrivate, start: time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC),
	}
	service, err := NewReleaseTrustService(options, ReleaseTrustAdapters{
		Documents: documents, Ledger: ledger, State: state, TrustedTime: timeAdapter, Fence: fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fullRefreshFixture{
		service: service, key: key, state: state, documents: documents, ledger: ledger, fence: fence,
		identity: identity, metadataBytes: metadataBytes, metadataSignature: metadataSignature, packageSignature: packageSignature,
		signingPrivate: signingPrivate, ledgerPrivate: ledgerPrivate,
	}
}

func (fixture fullRefreshFixture) retargetLedgerCheckpoint(t *testing.T, subject releasecontract.SigningSubjectV1, checkpointTime string) {
	t.Helper()
	subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(subject)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := newSigningLedgerSubjectScope(fixture.service.options.sourceConfiguration, subject)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRequest, err := fixedSigningLedgerRequest(
		fixture.service.options.sourceConfiguration, scope, SigningLedgerEvidence, subjectDigest, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := releasecontract.DecodeSigningLedgerEvidence(fixture.ledger.values[evidenceRequest.Locator().String()])
	if err != nil {
		t.Fatal(err)
	}
	receiptRequest, _ := fixedSigningLedgerRequest(
		fixture.service.options.sourceConfiguration, scope, SigningLedgerReceipt, subjectDigest, "", "",
	)
	receipt, err := releasecontract.DecodeSigningLedgerReceipt(fixture.ledger.values[receiptRequest.Locator().String()])
	if err != nil {
		t.Fatal(err)
	}
	oldCheckpoint := fixture.state.committedState(t).SigningLedger.Checkpoint
	oldCheckpointSHA256 := fixture.state.committedState(t).SigningLedger.CheckpointSHA256
	checkpoint := oldCheckpoint
	checkpoint.CheckpointTime = checkpointTime
	checkpointPreimage, err := releasecontract.SigningLedgerCheckpointSigningPreimage(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(signDigest(fixture.ledgerPrivate, checkpointPreimage))
	checkpointBytes, err := releasecontract.CanonicalSigningLedgerCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointSHA256 := digestHex(checkpointBytes)
	checkpointRequest, _ := fixedSigningLedgerRequest(
		fixture.service.options.sourceConfiguration, scope, SigningLedgerCheckpoint, "", "", checkpointSHA256,
	)

	receipt.CheckpointSHA256 = checkpointSHA256
	receipt.CheckpointTime = checkpointTime
	receiptPreimage, err := releasecontract.SigningLedgerReceiptSigningPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = base64.StdEncoding.EncodeToString(signDigest(fixture.ledgerPrivate, receiptPreimage))
	receiptBytes, err := releasecontract.CanonicalSigningLedgerReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	consistencyRequest, err := fixedSigningLedgerRequest(
		fixture.service.options.sourceConfiguration, scope, SigningLedgerConsistencyProof, "", oldCheckpointSHA256, checkpointSHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	consistency := releasecontract.SigningLedgerConsistencyProofV1{
		SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactConsistencyProof,
		LogID: checkpoint.LogID, OldTreeSize: oldCheckpoint.TreeSize, NewTreeSize: checkpoint.TreeSize, Nodes: []string{},
	}
	consistencyBytes, err := releasecontract.CanonicalSigningLedgerConsistencyProof(consistency)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ReceiptSHA256 = digestHex(receiptBytes)
	evidence.CheckpointRef = checkpointRequest.Locator().String()
	evidence.CheckpointSHA256 = checkpointSHA256
	evidence.ConsistencyProofRef = consistencyRequest.Locator().String()
	evidence.ConsistencyProofSHA256 = digestHex(consistencyBytes)
	evidenceBytes, err := releasecontract.CanonicalSigningLedgerEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ledger.values[evidenceRequest.Locator().String()] = evidenceBytes
	fixture.ledger.values[receiptRequest.Locator().String()] = receiptBytes
	fixture.ledger.values[checkpointRequest.Locator().String()] = checkpointBytes
	fixture.ledger.values[consistencyRequest.Locator().String()] = consistencyBytes
}

type fixtureSignedDocument struct {
	subject   releasecontract.SigningSubjectV1
	preimage  []byte
	keyID     string
	signature string
}

type fixtureLedgerValue struct {
	subject       releasecontract.SigningSubjectV1
	subjectDigest string
	preimageHash  string
	envelopeHash  string
	envelope      releasecontract.SignatureEnvelopeV1
	sequence      uint64
	channel       string
}

func buildFixtureLedger(
	t *testing.T,
	configuration SourceConfiguration,
	documents []fixtureSignedDocument,
	privateKey ed25519.PrivateKey,
	checkpointTime string,
) *fixtureLedgerTransport {
	t.Helper()
	values := make([]fixtureLedgerValue, len(documents))
	logLeaves := make([][]byte, len(documents))
	for index, document := range documents {
		subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(document.subject)
		if err != nil {
			t.Fatal(err)
		}
		preimageDigest := sha256.Sum256(document.preimage)
		envelope := releasecontract.SignatureEnvelopeV1{
			SchemaVersion: releasecontract.SigningEnvelopeSchemaVersion, SubjectIdentitySHA256: subjectDigest,
			SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]), Algorithm: releasecontract.SignatureAlgorithmEd25519,
			KeyID: document.keyID, Signature: document.signature,
		}
		envelopeBytes, err := releasecontract.CanonicalSignatureEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		sequence := uint64(index + 1)
		leaf := releasecontract.SigningLedgerLogLeafV1{
			SchemaVersion: releasecontract.SigningLedgerLogLeafSchemaVersion, SourceID: document.subject.SourceID,
			Channel: document.subject.Channel, SubjectIdentitySHA256: subjectDigest,
			SigningPreimageSHA256: envelope.SigningPreimageSHA256, SignatureEnvelopeSHA256: digestHex(envelopeBytes), Sequence: sequence,
		}
		leafBytes, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		logLeaves[index] = fixtureLogLeafHash(leafBytes)
		values[index] = fixtureLedgerValue{
			subject: document.subject, subjectDigest: subjectDigest, preimageHash: envelope.SigningPreimageSHA256,
			envelopeHash: digestHex(envelopeBytes), envelope: envelope, sequence: sequence, channel: document.subject.Channel,
		}
	}
	logRoot := fixtureMerkleRoot(logLeaves)
	latestRoot, latestProofs := fixtureLatestMap(values)
	checkpoint := releasecontract.SigningLedgerCheckpointV1{
		SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactCheckpoint,
		LogID: "signing_log", TreeSize: uint64(len(values)), LogRootHash: hex.EncodeToString(logRoot),
		LatestMapRootHash: hex.EncodeToString(latestRoot), CheckpointTime: checkpointTime, KeyID: "ledger_key",
	}
	checkpointPreimage, _ := releasecontract.SigningLedgerCheckpointSigningPreimage(checkpoint)
	checkpoint.Signature = base64.StdEncoding.EncodeToString(signDigest(privateKey, checkpointPreimage))
	checkpointBytes, _ := releasecontract.CanonicalSigningLedgerCheckpoint(checkpoint)
	checkpointSHA256 := digestHex(checkpointBytes)
	transport := &fixtureLedgerTransport{values: map[string][]byte{
		"sources/example_source/signing-ledger/checkpoints/" + checkpointSHA256 + ".json": checkpointBytes,
	}}

	for index, value := range values {
		receipt := releasecontract.SigningLedgerReceiptV1{
			SchemaVersion: releasecontract.SigningLedgerReceiptSchemaVersion, LogID: "signing_log",
			SourceID: value.subject.SourceID, Channel: value.channel, SubjectIdentitySHA256: value.subjectDigest,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash,
			Sequence: value.sequence, LeafIndex: uint64(index), TreeSize: uint64(len(values)),
			LogRootHash: checkpoint.LogRootHash, LatestMapRootHash: checkpoint.LatestMapRootHash,
			CheckpointSHA256: checkpointSHA256, CheckpointTime: checkpointTime, KeyID: "ledger_key",
		}
		receiptPreimage, _ := releasecontract.SigningLedgerReceiptSigningPreimage(receipt)
		receipt.Signature = base64.StdEncoding.EncodeToString(signDigest(privateKey, receiptPreimage))
		receiptBytes, _ := releasecontract.CanonicalSigningLedgerReceipt(receipt)
		inclusion := releasecontract.SigningLedgerInclusionProofV1{
			SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactInclusionProof,
			LogID: "signing_log", LeafIndex: uint64(index), TreeSize: uint64(len(values)), Nodes: fixtureInclusionProof(logLeaves, index),
		}
		inclusionBytes, _ := releasecontract.CanonicalSigningLedgerInclusionProof(inclusion)
		latest := releasecontract.SigningLedgerLatestProofV1{
			SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactLatestProof,
			LogID: "signing_log", SubjectIdentitySHA256: value.subjectDigest, Present: true, Sequence: value.sequence,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash, Siblings: latestProofs[value.subjectDigest],
		}
		latestBytes, _ := releasecontract.CanonicalSigningLedgerLatestProof(latest)
		scope, err := newSigningLedgerSubjectScope(configuration, value.subject)
		if err != nil {
			t.Fatal(err)
		}
		receiptRequest, _ := fixedSigningLedgerRequest(configuration, scope, SigningLedgerReceipt, value.subjectDigest, "", "")
		inclusionRequest, _ := fixedSigningLedgerRequest(configuration, scope, SigningLedgerInclusionProof, value.subjectDigest, "", "")
		latestRequest, _ := fixedSigningLedgerRequest(configuration, scope, SigningLedgerLatestProof, value.subjectDigest, "", "")
		checkpointRequest, _ := fixedSigningLedgerRequest(configuration, scope, SigningLedgerCheckpoint, "", "", checkpointSHA256)
		evidence := releasecontract.SigningLedgerEvidenceV1{
			SchemaVersion: releasecontract.SigningLedgerEvidenceSchemaVersion, SourceID: value.subject.SourceID, Channel: value.channel,
			SubjectIdentitySHA256: value.subjectDigest, SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash,
			ReceiptRef: receiptRequest.Locator().String(), ReceiptSHA256: digestHex(receiptBytes),
			CheckpointRef: checkpointRequest.Locator().String(), CheckpointSHA256: checkpointSHA256,
			InclusionProofRef: inclusionRequest.Locator().String(), InclusionProofSHA256: digestHex(inclusionBytes),
			LatestProofRef: latestRequest.Locator().String(), LatestProofSHA256: digestHex(latestBytes),
		}
		evidenceBytes, err := releasecontract.CanonicalSigningLedgerEvidence(evidence)
		if err != nil {
			t.Fatal(err)
		}
		evidenceRequest, _ := fixedSigningLedgerRequest(configuration, scope, SigningLedgerEvidence, value.subjectDigest, "", "")
		transport.values[evidenceRequest.Locator().String()] = evidenceBytes
		transport.values[receiptRequest.Locator().String()] = receiptBytes
		transport.values[inclusionRequest.Locator().String()] = inclusionBytes
		transport.values[latestRequest.Locator().String()] = latestBytes
	}
	return transport
}

func signDigest(privateKey ed25519.PrivateKey, preimage []byte) []byte {
	digest := sha256.Sum256(preimage)
	return ed25519.Sign(privateKey, digest[:])
}

func fixtureLogLeafHash(value []byte) []byte {
	digest := sha256.Sum256(append([]byte{0}, value...))
	return digest[:]
}

func fixtureLogNode(left, right []byte) []byte {
	value := append([]byte{1}, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func fixtureMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return slices.Clone(leaves[0])
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	return fixtureLogNode(fixtureMerkleRoot(leaves[:k]), fixtureMerkleRoot(leaves[k:]))
}

func fixtureInclusionProof(leaves [][]byte, index int) []string {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	var proof []string
	if index < k {
		proof = fixtureInclusionProof(leaves[:k], index)
		proof = append(proof, hex.EncodeToString(fixtureMerkleRoot(leaves[k:])))
	} else {
		proof = fixtureInclusionProof(leaves[k:], index-k)
		proof = append(proof, hex.EncodeToString(fixtureMerkleRoot(leaves[:k])))
	}
	return proof
}

func largestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}

type fixtureLatestLeaf struct {
	key   [sha256.Size]byte
	value []byte
}

func fixtureLatestMap(values []fixtureLedgerValue) ([]byte, map[string][]string) {
	leaves := make([]fixtureLatestLeaf, len(values))
	for index, value := range values {
		keyBytes, _ := hex.DecodeString(value.subjectDigest)
		copy(leaves[index].key[:], keyBytes)
		sequence := make([]byte, 8)
		binary.BigEndian.PutUint64(sequence, value.sequence)
		preimage, _ := hex.DecodeString(value.preimageHash)
		envelope, _ := hex.DecodeString(value.envelopeHash)
		encoded := append([]byte{3}, keyBytes...)
		encoded = append(encoded, sequence...)
		encoded = append(encoded, preimage...)
		encoded = append(encoded, envelope...)
		digest := sha256.Sum256(encoded)
		leaves[index].value = digest[:]
	}
	root := fixtureLatestSubtree(leaves, 0)
	proofs := make(map[string][]string, len(leaves))
	for _, leaf := range leaves {
		nodes := fixtureLatestProof(leaves, leaf.key, 0)
		slices.Reverse(nodes)
		encoded := make([]string, len(nodes))
		for index, node := range nodes {
			encoded[index] = hex.EncodeToString(node)
		}
		proofs[hex.EncodeToString(leaf.key[:])] = encoded
	}
	return root, proofs
}

func fixtureLatestSubtree(leaves []fixtureLatestLeaf, depth int) []byte {
	if len(leaves) == 0 {
		return make([]byte, sha256.Size)
	}
	if depth == sha256.Size*8 {
		return slices.Clone(leaves[0].value)
	}
	left, right := splitLatestLeaves(leaves, depth)
	return fixtureLatestNode(fixtureLatestSubtree(left, depth+1), fixtureLatestSubtree(right, depth+1))
}

func fixtureLatestProof(leaves []fixtureLatestLeaf, key [sha256.Size]byte, depth int) [][]byte {
	if depth == sha256.Size*8 {
		return nil
	}
	left, right := splitLatestLeaves(leaves, depth)
	if fixtureKeyBit(key, depth) == 0 {
		return append([][]byte{fixtureLatestSubtree(right, depth+1)}, fixtureLatestProof(left, key, depth+1)...)
	}
	return append([][]byte{fixtureLatestSubtree(left, depth+1)}, fixtureLatestProof(right, key, depth+1)...)
}

func splitLatestLeaves(leaves []fixtureLatestLeaf, depth int) ([]fixtureLatestLeaf, []fixtureLatestLeaf) {
	left := make([]fixtureLatestLeaf, 0, len(leaves))
	right := make([]fixtureLatestLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		if fixtureKeyBit(leaf.key, depth) == 0 {
			left = append(left, leaf)
		} else {
			right = append(right, leaf)
		}
	}
	return left, right
}

func fixtureKeyBit(key [sha256.Size]byte, depth int) byte {
	return (key[depth/8] >> uint(7-depth%8)) & 1
}

func fixtureLatestNode(left, right []byte) []byte {
	value := append([]byte{4}, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}
