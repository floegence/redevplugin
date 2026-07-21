package releasetrust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSourceConfigurationProducesOnlyConfiguredTrustKeys(t *testing.T) {
	channels := []string{"stable", "beta"}
	configuration, err := NewSourceConfiguration("example_source", channels)
	if err != nil {
		t.Fatal(err)
	}
	channels[0] = "mutated"

	if got := configuration.SourceID(); got != "example_source" {
		t.Fatalf("SourceID() = %q", got)
	}
	if got := configuration.AllowedChannels(); !slices.Equal(got, []string{"beta", "stable"}) {
		t.Fatalf("AllowedChannels() = %#v", got)
	}
	stable, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}
	if stable.SourceID() != "example_source" || stable.Channel() != "stable" || stable.String() != "example_source/stable" {
		t.Fatalf("trust key = %q/%q", stable.SourceID(), stable.Channel())
	}
	if _, err := configuration.TrustKey("nightly"); !errors.Is(err, ErrSourceChannelNotAllowed) {
		t.Fatalf("TrustKey(nightly) error = %v", err)
	}

	for _, testCase := range []struct {
		sourceID string
		channels []string
	}{
		{"", []string{"stable"}},
		{"Example", []string{"stable"}},
		{"example", nil},
		{"example", []string{"stable", "stable"}},
		{"example", []string{"../stable"}},
	} {
		if _, err := NewSourceConfiguration(testCase.sourceID, testCase.channels); !errors.Is(err, ErrInvalidSourceConfiguration) {
			t.Fatalf("NewSourceConfiguration(%q, %#v) error = %v", testCase.sourceID, testCase.channels, err)
		}
	}
}

func TestReleaseTrustOptionsAreClosedValidatedAndOwned(t *testing.T) {
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	rootKey := make([]byte, ed25519.PublicKeySize)
	rootKey[0] = 1
	root, err := NewEd25519TrustAnchor("root_key", rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEd25519TrustAnchor("zero_key", make([]byte, ed25519.PublicKeySize)); !errors.Is(err, ErrInvalidTrustAnchor) {
		t.Fatalf("all-zero trust anchor error = %v", err)
	}
	transparencyKey := make([]byte, ed25519.PublicKeySize)
	transparencyKey[0] = 2
	transparencyAnchor, err := NewEd25519TrustAnchor("time_key", transparencyKey)
	if err != nil {
		t.Fatal(err)
	}
	transparency, err := NewTransparencyRoot("time_log", transparencyAnchor)
	if err != nil {
		t.Fatal(err)
	}
	ledgerKey := make([]byte, ed25519.PublicKeySize)
	ledgerKey[0] = 3
	ledgerAnchor, err := NewEd25519TrustAnchor("ledger_key", ledgerKey)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewPinnedSigningLedgerRoot("signing_log", ledgerAnchor)
	if err != nil {
		t.Fatal(err)
	}
	delegatedLedger, err := NewDelegatedSigningLedgerRoot("signing_log", "delegated_ledger_key")
	if err != nil {
		t.Fatal(err)
	}
	if delegatedLedger.Mode() != SigningLedgerRootRootDelegated || delegatedLedger.DelegatedKeyID() != "delegated_ledger_key" {
		t.Fatalf("delegated ledger root = %#v", delegatedLedger)
	}
	if _, ok := delegatedLedger.PinnedAnchor(); ok {
		t.Fatal("delegated ledger root exposed a pinned anchor")
	}

	options, err := NewReleaseTrustOptions(configuration, root, []TransparencyRoot{transparency}, ledger, SourceRelativeLocatorPolicyV1)
	if err != nil {
		t.Fatal(err)
	}
	rootKey[0] = 9
	transparencyKey[0] = 9
	ledgerKey[0] = 9

	if options.SourceConfiguration().SourceID() != "example_source" || options.LocatorPolicy() != SourceRelativeLocatorPolicyV1 {
		t.Fatalf("options = %#v", options)
	}
	if options.RootAnchor().PublicKey()[0] != 1 || options.TransparencyRoots()[0].Anchor().PublicKey()[0] != 2 {
		t.Fatal("options retained caller-mutable trust anchor bytes")
	}
	if pinned, ok := options.SigningLedgerRoot().PinnedAnchor(); !ok || pinned.PublicKey()[0] != 3 {
		t.Fatal("options lost the pinned signing ledger root")
	}
	mutated := options.TransparencyRoots()
	mutated[0] = TransparencyRoot{}
	if options.TransparencyRoots()[0].LogID() != "time_log" {
		t.Fatal("TransparencyRoots() shares caller-mutable storage")
	}

	if _, err := NewReleaseTrustOptions(configuration, root, nil, ledger, SourceRelativeLocatorPolicyV1); !errors.Is(err, ErrInvalidReleaseTrustOptions) {
		t.Fatalf("missing transparency roots error = %v", err)
	}
	if _, err := NewReleaseTrustOptions(configuration, root, []TransparencyRoot{transparency, transparency}, ledger, SourceRelativeLocatorPolicyV1); !errors.Is(err, ErrInvalidReleaseTrustOptions) {
		t.Fatalf("duplicate transparency roots error = %v", err)
	}
	if _, err := NewReleaseTrustOptions(configuration, root, []TransparencyRoot{transparency}, ledger, 0); !errors.Is(err, ErrInvalidReleaseTrustOptions) {
		t.Fatalf("zero locator policy error = %v", err)
	}
	if _, err := NewReleaseTrustOptions(configuration, root, []TransparencyRoot{transparency}, delegatedLedger, SourceRelativeLocatorPolicyV1); err != nil {
		t.Fatalf("delegated signing ledger options error = %v", err)
	}
}

func TestSourceRelativeLocatorPolicyBuildsFixedBoundedRequests(t *testing.T) {
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}

	documentCases := []struct {
		kind ReleaseDocumentKind
		want string
		max  int64
	}{
		{ReleaseDocumentRootDelegation, "sources/example_source/root/current.json", MaxReleaseDocumentBytes},
		{ReleaseDocumentSourcePolicyPointer, "sources/example_source/stable/policy/current.json", MaxReleasePointerBytes},
		{ReleaseDocumentRevocationPointer, "sources/example_source/stable/revocation/current.json", MaxReleasePointerBytes},
	}
	for _, testCase := range documentCases {
		request, err := fixedReleaseDocumentRequest(configuration, key, testCase.kind)
		if err != nil {
			t.Fatalf("fixedReleaseDocumentRequest(%s) error = %v", testCase.kind, err)
		}
		if request.Locator().String() != testCase.want || request.MaxBytes() != testCase.max || request.Kind() != testCase.kind {
			t.Fatalf("request = kind=%s locator=%q max=%d", request.Kind(), request.Locator(), request.MaxBytes())
		}
		wantChannel := "stable"
		if testCase.kind == ReleaseDocumentRootDelegation {
			wantChannel = ""
		}
		if request.SourceID() != "example_source" || request.Channel() != wantChannel {
			t.Fatalf("request source scope = %q/%q", request.SourceID(), request.Channel())
		}
		assertSafeRelativeLocator(t, request.Locator())
	}

	policyDocument, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentSourcePolicy, "sources/example_source/stable/policy/2.json")
	if err != nil {
		t.Fatal(err)
	}
	if policyDocument.MaxBytes() != MaxReleaseDocumentBytes {
		t.Fatalf("policy max bytes = %d", policyDocument.MaxBytes())
	}
	for _, ref := range []string{
		"https://example.invalid/policy.json",
		"/sources/example_source/stable/policy/2.json",
		"sources/example_source/stable/policy/../2.json",
		"sources/other_source/stable/policy/2.json",
		"sources/example_source/beta/policy/2.json",
		"sources/example_source/stable/revocation/2.json",
		"sources/example_source/stable/policy/2.json?raw=1",
	} {
		if _, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentSourcePolicy, ref); !errors.Is(err, ErrInvalidLocator) {
			t.Fatalf("signed ref %q error = %v", ref, err)
		}
	}

	subjectDigest := strings.Repeat("1", 64)
	previousCheckpoint := strings.Repeat("2", 64)
	currentCheckpoint := strings.Repeat("3", 64)
	ledgerCases := []struct {
		kind SigningLedgerArtifactKind
		want string
		max  int64
	}{
		{SigningLedgerCheckpoint, "sources/example_source/signing-ledger/checkpoints/current.json", MaxSigningLedgerCheckpointBytes},
		{SigningLedgerReceipt, "sources/example_source/signing-ledger/receipts/" + subjectDigest + ".json", MaxSigningLedgerEvidenceBytes},
		{SigningLedgerInclusionProof, "sources/example_source/signing-ledger/proofs/inclusion/" + subjectDigest + ".json", MaxSigningLedgerEvidenceBytes},
		{SigningLedgerLatestProof, "sources/example_source/signing-ledger/proofs/latest/" + subjectDigest + ".json", MaxSigningLedgerEvidenceBytes},
		{SigningLedgerConsistencyProof, "sources/example_source/signing-ledger/proofs/consistency/" + previousCheckpoint + "/" + currentCheckpoint + ".json", MaxSigningLedgerEvidenceBytes},
	}
	for _, testCase := range ledgerCases {
		request, err := fixedSigningLedgerRequest(configuration, key, testCase.kind, subjectDigest, previousCheckpoint, currentCheckpoint)
		if err != nil {
			t.Fatalf("fixedSigningLedgerRequest(%s) error = %v", testCase.kind, err)
		}
		wantChannel := "stable"
		if testCase.kind == SigningLedgerCheckpoint || testCase.kind == SigningLedgerConsistencyProof {
			wantChannel = ""
		}
		if request.Locator().String() != testCase.want || request.MaxBytes() != testCase.max || request.SourceID() != "example_source" || request.Channel() != wantChannel {
			t.Fatalf("ledger request = %#v locator=%q", request, request.Locator())
		}
		assertSafeRelativeLocator(t, request.Locator())
	}
	if _, err := fixedSigningLedgerRequest(configuration, key, SigningLedgerReceipt, "https://example.invalid", previousCheckpoint, currentCheckpoint); !errors.Is(err, ErrInvalidLocator) {
		t.Fatalf("caller locator override error = %v", err)
	}
}

func TestTransportCapabilitiesExposeNoCallerWritableRequestFields(t *testing.T) {
	for _, value := range []any{
		SourceTrustKey{},
		SourceConfiguration{},
		SourceRelativeLocator{},
		ReleaseDocumentRequest{},
		SigningLedgerRequest{},
		ReleaseDocumentResult{},
		SigningLedgerResult{},
		ReleaseTrustOptions{},
		TrustedTimeRequest{},
		TrustedTimeObservation{},
		VerifiedTrustedTime{},
		TrustedTimeStatus{},
		SourceTrustStateLoadRequest{},
		SourceTrustStateLoadResult{},
		SourceTrustStatePrepareRequest{},
		SourceTrustStateCommitRequest{},
		MonotonicStateReadRequest{},
		MonotonicStateReadResult{},
		MonotonicStateCASRequest{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Fatalf("%s exposes caller-writable field %s", typeOf, typeOf.Field(index).Name)
			}
		}
	}
	var _ ReleaseDocumentTransport = documentTransportStub{}
	var _ SigningLedgerTransport = ledgerTransportStub{}
}

type documentTransportStub struct{}

func (documentTransportStub) FetchReleaseDocument(context.Context, ReleaseDocumentRequest) (ReleaseDocumentResult, error) {
	return ReleaseDocumentResult{}, nil
}

type ledgerTransportStub struct{}

func (ledgerTransportStub) FetchSigningLedgerArtifact(context.Context, SigningLedgerRequest) (SigningLedgerResult, error) {
	return SigningLedgerResult{}, nil
}

func TestTransportResultsAreBoundedAndOwned(t *testing.T) {
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}
	documentRequest, err := fixedReleaseDocumentRequest(configuration, key, ReleaseDocumentSourcePolicyPointer)
	if err != nil {
		t.Fatal(err)
	}
	documentBytes := []byte("document")
	document, err := NewReleaseDocumentResult(documentRequest, documentBytes)
	if err != nil {
		t.Fatal(err)
	}
	documentBytes[0] = 'x'
	gotDocument, err := document.bytesFor(documentRequest)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDocument) != "document" {
		t.Fatalf("document bytes = %q", gotDocument)
	}
	gotDocument[0] = 'x'
	freshDocument, err := document.bytesFor(documentRequest)
	if err != nil {
		t.Fatal(err)
	}
	if string(freshDocument) != "document" {
		t.Fatal("ReleaseDocumentResult shares mutable storage")
	}
	otherDocumentRequest, err := fixedReleaseDocumentRequest(configuration, key, ReleaseDocumentRevocationPointer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := document.bytesFor(otherDocumentRequest); !errors.Is(err, ErrInvalidTransportPayload) {
		t.Fatalf("cross-request document result error = %v", err)
	}
	if _, err := NewReleaseDocumentResult(documentRequest, make([]byte, MaxReleasePointerBytes+1)); !errors.Is(err, ErrInvalidTransportPayload) {
		t.Fatalf("oversized document error = %v", err)
	}

	ledgerRequest, err := fixedSigningLedgerRequest(configuration, key, SigningLedgerCheckpoint, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ledgerBytes := []byte("checkpoint")
	ledger, err := NewSigningLedgerResult(ledgerRequest, ledgerBytes)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBytes[0] = 'x'
	gotLedger, err := ledger.bytesFor(ledgerRequest)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotLedger) != "checkpoint" {
		t.Fatal("SigningLedgerResult retained caller-mutable bytes")
	}
	receiptRequest, err := fixedSigningLedgerRequest(configuration, key, SigningLedgerReceipt, strings.Repeat("4", 64), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.bytesFor(receiptRequest); !errors.Is(err, ErrInvalidTransportPayload) {
		t.Fatalf("cross-request ledger result error = %v", err)
	}
	if _, err := NewSigningLedgerResult(ledgerRequest, make([]byte, MaxSigningLedgerCheckpointBytes+1)); !errors.Is(err, ErrInvalidTransportPayload) {
		t.Fatalf("oversized checkpoint error = %v", err)
	}
}

func assertSafeRelativeLocator(t *testing.T, locator SourceRelativeLocator) {
	t.Helper()
	value := locator.String()
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "://") || strings.ContainsAny(value, "\\?#") {
		t.Fatalf("unsafe locator %q", value)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			t.Fatalf("unsafe locator segment in %q", value)
		}
	}
}
