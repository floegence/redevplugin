package releasetrust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReleaseTrustServiceRefreshesTimeAndRequiresFreshEvidenceAfterRestart(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	first, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if first.Floor() != fixture.timeAdapter.start || first.StateSHA256() == "" || first.ProcessInstanceID() == "" || fixture.timeAdapter.calls != 1 {
		t.Fatalf("first trusted time status = %#v calls=%d", first, fixture.timeAdapter.calls)
	}
	committed := fixture.state.committedState(t)
	if committed.TrustedTime.Floor != first.Floor().Format(time.RFC3339Nano) || committed.ExternalCounter != 0 || len(fixture.state.pending) != 0 {
		t.Fatalf("committed trust state = %#v pending=%d", committed, len(fixture.state.pending))
	}

	restarted, err := NewReleaseTrustService(fixture.options, ReleaseTrustAdapters{
		Documents: documentTransportStub{}, Ledger: ledgerTransportStub{}, State: fixture.state, TrustedTime: fixture.timeAdapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.RefreshTrustedTime(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Floor().After(first.Floor()) || second.ProcessInstanceID() == first.ProcessInstanceID() || fixture.timeAdapter.calls != 2 {
		t.Fatalf("second trusted time status = %#v calls=%d", second, fixture.timeAdapter.calls)
	}
}

func TestReleaseTrustServiceRecoversTrustedTimeOrphanBeforeInitialCheckpoint(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	fixture.timeAdapter.failAfterAppendOnce = errors.New("simulated response loss after trusted-time append")
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err == nil {
		t.Fatal("RefreshTrustedTime() unexpectedly succeeded after response loss")
	}
	if len(fixture.state.committed) != 0 || len(fixture.state.pending) != 0 {
		t.Fatal("failed initial observation mutated trusted-time state")
	}

	_, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if treeSize := fixture.state.committedState(t).TrustedTime.Checkpoint.TreeSize; treeSize != 2 {
		t.Fatalf("recovered checkpoint tree size = %d", treeSize)
	}
	if got := fixture.timeAdapter.previousTreeSizes; !slices.Equal(got, []uint64{0, 0}) {
		t.Fatalf("previous checkpoint tree sizes = %v", got)
	}
}

func TestReleaseTrustServiceRecoversTrustedTimeOrphanAfterCommittedCheckpoint(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	firstTreeSize := fixture.state.committedState(t).TrustedTime.Checkpoint.TreeSize
	fixture.timeAdapter.failAfterAppendOnce = errors.New("simulated response loss after trusted-time append")
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err == nil {
		t.Fatal("RefreshTrustedTime() unexpectedly succeeded after response loss")
	}

	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	recoveredTreeSize := fixture.state.committedState(t).TrustedTime.Checkpoint.TreeSize
	if firstTreeSize != 1 || recoveredTreeSize != 3 {
		t.Fatalf("checkpoint sizes = %d -> %d", firstTreeSize, recoveredTreeSize)
	}
	if got := fixture.timeAdapter.previousTreeSizes; !slices.Equal(got, []uint64{0, 1, 1}) {
		t.Fatalf("previous checkpoint tree sizes = %v", got)
	}
}

func TestReleaseTrustServiceRejectsTrustedTimeCheckpointBeyondAdapterLog(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	fixture.timeAdapter.mu.Lock()
	fixture.timeAdapter.leaves = nil
	fixture.timeAdapter.mu.Unlock()
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); !errors.Is(err, ErrInvalidTrustedTimeRequest) {
		t.Fatalf("RefreshTrustedTime() error = %v", err)
	}
	if treeSize := fixture.state.committedState(t).TrustedTime.Checkpoint.TreeSize; treeSize != 1 {
		t.Fatalf("failed observation changed committed checkpoint tree size to %d", treeSize)
	}
}

func TestReleaseTrustServiceRecoversExternalCASAheadOfLocalCommit(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, true)
	fixture.state.commitErrOnce = errors.New("simulated local fsync failure")
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err == nil {
		t.Fatal("RefreshTrustedTime() unexpectedly succeeded across local commit failure")
	}
	if len(fixture.state.pending) == 0 || fixture.monotonic.counter != 1 || fixture.monotonic.stateSHA256 == emptyReleaseTrustStateSHA256 {
		t.Fatalf("crash state pending=%d external=%d/%s", len(fixture.state.pending), fixture.monotonic.counter, fixture.monotonic.stateSHA256)
	}

	restarted, err := NewReleaseTrustService(fixture.options, ReleaseTrustAdapters{
		Documents: documentTransportStub{}, Ledger: ledgerTransportStub{}, State: fixture.state, TrustedTime: fixture.timeAdapter, Monotonic: fixture.monotonic,
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted.mu.Lock()
	recovered, recoveredSHA256, err := restarted.loadAndRecover(context.Background())
	restarted.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ExternalCounter != 1 || recoveredSHA256 != fixture.monotonic.stateSHA256 || len(fixture.state.pending) != 0 {
		t.Fatalf("recovered state = %#v digest=%s pending=%d", recovered, recoveredSHA256, len(fixture.state.pending))
	}
}

func TestReleaseTrustServiceReadbackResolvesUnknownMutations(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, true)
	fixture.state.prepareOutcome = StateMutationUnknown
	fixture.state.prepareUnknownApplied = true
	fixture.state.commitOutcome = StateMutationUnknown
	fixture.state.commitUnknownApplied = true
	fixture.monotonic.casOutcome = StateMutationUnknown
	fixture.monotonic.unknownApplied = true
	status, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if status.StateSHA256() != fixture.monotonic.stateSHA256 || len(fixture.state.pending) != 0 {
		t.Fatalf("unknown-outcome status = %#v pending=%d", status, len(fixture.state.pending))
	}
}

func TestReleaseTrustServiceRejectsUnknownPrepareWithLocalAheadOfExternalState(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, true)
	fixture.state.prepareOutcome = StateMutationUnknown
	fixture.state.prepareUnknownCommitted = true
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); !errors.Is(err, ErrReleaseTrustSplitView) {
		t.Fatalf("RefreshTrustedTime(local ahead) error = %v", err)
	}
	if fixture.monotonic.counter != 0 || fixture.monotonic.stateSHA256 != emptyReleaseTrustStateSHA256 {
		t.Fatalf("external state unexpectedly advanced to %d/%s", fixture.monotonic.counter, fixture.monotonic.stateSHA256)
	}
}

func TestReleaseTrustServiceFencesLocalExternalSplitBeforeTimeObservation(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, true)
	if _, err := fixture.service.RefreshTrustedTime(context.Background(), fixture.key); err != nil {
		t.Fatal(err)
	}
	fixture.monotonic.mu.Lock()
	fixture.monotonic.stateSHA256 = emptyReleaseTrustStateSHA256
	fixture.monotonic.mu.Unlock()
	before := fixture.timeAdapter.calls
	restarted, err := NewReleaseTrustService(fixture.options, ReleaseTrustAdapters{
		Documents: documentTransportStub{}, Ledger: ledgerTransportStub{}, State: fixture.state, TrustedTime: fixture.timeAdapter, Monotonic: fixture.monotonic,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RefreshTrustedTime(context.Background(), fixture.key); !errors.Is(err, ErrReleaseTrustSplitView) {
		t.Fatalf("RefreshTrustedTime(split) error = %v", err)
	}
	if fixture.timeAdapter.calls != before {
		t.Fatal("split-view state reached the trusted time transport")
	}
}

func TestReleaseTrustServiceRejectsTypedNilAdapters(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	valid := ReleaseTrustAdapters{
		Documents: documentTransportStub{}, Ledger: ledgerTransportStub{}, State: fixture.state, TrustedTime: fixture.timeAdapter,
	}
	var nilDocuments *typedNilDocumentTransport
	var nilLedger *typedNilLedgerTransport
	var nilState *memorySourceTrustStateStore
	var nilTrustedTime *testTransparencyTimeAdapter
	var nilMonotonic *memoryMonotonicStateAdapter

	for name, mutate := range map[string]func(ReleaseTrustAdapters) ReleaseTrustAdapters{
		"documents": func(adapters ReleaseTrustAdapters) ReleaseTrustAdapters {
			adapters.Documents = nilDocuments
			return adapters
		},
		"ledger": func(adapters ReleaseTrustAdapters) ReleaseTrustAdapters { adapters.Ledger = nilLedger; return adapters },
		"state":  func(adapters ReleaseTrustAdapters) ReleaseTrustAdapters { adapters.State = nilState; return adapters },
		"trusted time": func(adapters ReleaseTrustAdapters) ReleaseTrustAdapters {
			adapters.TrustedTime = nilTrustedTime
			return adapters
		},
		"monotonic": func(adapters ReleaseTrustAdapters) ReleaseTrustAdapters {
			adapters.Monotonic = nilMonotonic
			return adapters
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReleaseTrustService(fixture.options, mutate(valid)); !errors.Is(err, ErrInvalidReleaseTrustOptions) {
				t.Fatalf("NewReleaseTrustService(typed nil %s) error = %v", name, err)
			}
		})
	}
}

func TestReleaseTrustServiceMergesIndependentChannelCASConflict(t *testing.T) {
	fixture := newReleaseTrustServiceFixture(t, false)
	base := validReleaseTrustStateFixture(t)
	base.Revision = 1
	baseBytes, err := canonicalReleaseTrustState(base)
	if err != nil {
		t.Fatal(err)
	}
	proposed := cloneReleaseTrustState(base)
	proposed.Revision = 2
	proposed.Channels[1].Policy.PointerTransportToken = "stable-v2"
	latest := cloneReleaseTrustState(base)
	latest.Revision = 2
	latest.Channels[0].Policy.PointerTransportToken = "beta-v2"
	latestBytes, err := canonicalReleaseTrustState(latest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.state.committed = latestBytes

	merged, _, err := fixture.service.commitState(
		context.Background(), base, digestHex(baseBytes), proposed, strings.Repeat("a", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Revision != 3 || merged.Channels[0].Policy.PointerTransportToken != "beta-v2" ||
		merged.Channels[1].Policy.PointerTransportToken != "stable-v2" {
		t.Fatalf("merged state = %#v", merged)
	}
}

func TestReleaseTrustStateMergeRejectsSameChannelAndSourceWideConflicts(t *testing.T) {
	base := validReleaseTrustStateFixture(t)
	proposed := cloneReleaseTrustState(base)
	proposed.Channels[1].Policy.PointerTransportToken = "stable-proposed"
	latest := cloneReleaseTrustState(base)
	latest.Channels[1].Policy.PointerTransportToken = "stable-latest"
	if _, err := mergeReleaseTrustStates(base, proposed, latest); !errors.Is(err, ErrReleaseTrustStateConflict) {
		t.Fatalf("same-channel merge error = %v", err)
	}

	proposed = cloneReleaseTrustState(base)
	latest = cloneReleaseTrustState(base)
	proposed.TrustedTime.CheckpointSHA256 = strings.Repeat("a", 64)
	latest.TrustedTime.CheckpointSHA256 = strings.Repeat("b", 64)
	if _, err := mergeReleaseTrustStates(base, proposed, latest); !errors.Is(err, ErrReleaseTrustStateConflict) {
		t.Fatalf("source-wide merge error = %v", err)
	}
}

type releaseTrustServiceFixture struct {
	options     ReleaseTrustOptions
	key         SourceTrustKey
	service     *ReleaseTrustService
	state       *memorySourceTrustStateStore
	monotonic   *memoryMonotonicStateAdapter
	timeAdapter *testTransparencyTimeAdapter
}

func newReleaseTrustServiceFixture(t *testing.T, withMonotonic bool) releaseTrustServiceFixture {
	t.Helper()
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	rootAnchor, _ := NewEd25519TrustAnchor("root_key", rootPrivate.Public().(ed25519.PublicKey))
	timePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	timeAnchor, _ := NewEd25519TrustAnchor("time_key", timePrivate.Public().(ed25519.PublicKey))
	timeRoot, _ := NewTransparencyRoot("time_log", timeAnchor)
	ledgerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	ledgerAnchor, _ := NewEd25519TrustAnchor("ledger_key", ledgerPrivate.Public().(ed25519.PublicKey))
	ledgerRoot, _ := NewPinnedSigningLedgerRoot("signing_log", ledgerAnchor)
	options, err := NewReleaseTrustOptions(configuration, rootAnchor, []TransparencyRoot{timeRoot}, ledgerRoot, SourceRelativeLocatorPolicyV1)
	if err != nil {
		t.Fatal(err)
	}
	state := &memorySourceTrustStateStore{}
	timeAdapter := &testTransparencyTimeAdapter{t: t, privateKey: timePrivate, start: time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)}
	var monotonic *memoryMonotonicStateAdapter
	adapters := ReleaseTrustAdapters{Documents: documentTransportStub{}, Ledger: ledgerTransportStub{}, State: state, TrustedTime: timeAdapter}
	if withMonotonic {
		monotonic = &memoryMonotonicStateAdapter{stateSHA256: emptyReleaseTrustStateSHA256}
		adapters.Monotonic = monotonic
	}
	service, err := NewReleaseTrustService(options, adapters)
	if err != nil {
		t.Fatal(err)
	}
	return releaseTrustServiceFixture{options: options, key: key, service: service, state: state, monotonic: monotonic, timeAdapter: timeAdapter}
}

type testTransparencyTimeAdapter struct {
	t                   *testing.T
	privateKey          ed25519.PrivateKey
	start               time.Time
	mu                  sync.Mutex
	calls               int
	leaves              [][]byte
	previousTreeSizes   []uint64
	failAfterAppendOnce error
}

func (adapter *testTransparencyTimeAdapter) Observe(_ context.Context, request TrustedTimeRequest) (TrustedTimeObservation, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	integrated := adapter.start.Add(time.Duration(adapter.calls) * time.Minute)
	adapter.previousTreeSizes = append(adapter.previousTreeSizes, request.PreviousCheckpointTreeSize())
	leaf := trustedTimeTestLeafBytes(adapter.t, request, integrated.Add(365*24*time.Hour))
	leafHashes := make([][]byte, 0, len(adapter.leaves)+1)
	for _, previous := range adapter.leaves {
		leafHashes = append(leafHashes, merkleLeafHash(previous))
	}
	leafHashes = append(leafHashes, merkleLeafHash(leaf))
	previousTreeSize := request.PreviousCheckpointTreeSize()
	if previousTreeSize > uint64(len(adapter.leaves)) {
		return TrustedTimeObservation{}, ErrInvalidTrustedTimeRequest
	}
	var consistency [][]byte
	if previousTreeSize != 0 {
		consistency = trustedTimeTestConsistencyProof(leafHashes, int(previousTreeSize))
	}
	evidence, leaf := buildTrustedTimeEvidence(
		adapter.t, request, adapter.privateKey, integrated, integrated.Add(365*24*time.Hour),
		uint64(len(leafHashes)), trustedTimeTestInclusionProof(leafHashes, len(leafHashes)-1), consistency,
	)
	adapter.leaves = append(adapter.leaves, slices.Clone(leaf))
	adapter.calls++
	if adapter.failAfterAppendOnce != nil {
		err := adapter.failAfterAppendOnce
		adapter.failAfterAppendOnce = nil
		return TrustedTimeObservation{}, err
	}
	return NewTransparencyTimeObservation(request, evidence)
}

type memorySourceTrustStateStore struct {
	mu                      sync.Mutex
	committed               []byte
	pending                 []byte
	loadCalls               int
	prepareCalls            int
	commitCalls             int
	prepareOutcome          StateMutationOutcome
	prepareUnknownApplied   bool
	prepareUnknownCommitted bool
	commitOutcome           StateMutationOutcome
	commitUnknownApplied    bool
	commitErrOnce           error
}

func (store *memorySourceTrustStateStore) LoadSourceTrustState(_ context.Context, request SourceTrustStateLoadRequest) (SourceTrustStateLoadResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loadCalls++
	return NewSourceTrustStateLoadResult(request, store.committed, store.pending)
}

func (store *memorySourceTrustStateStore) PrepareSourceTrustState(_ context.Context, request SourceTrustStatePrepareRequest) (StateMutationOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.prepareCalls++
	if digestOrEmpty(store.committed) != request.ExpectedCommittedSHA256() {
		return StateMutationConflict, nil
	}
	if len(store.pending) != 0 && digestHex(store.pending) != request.PendingSHA256() {
		return StateMutationConflict, nil
	}
	outcome := store.prepareOutcome
	if outcome == "" {
		outcome = StateMutationApplied
	}
	if outcome == StateMutationApplied || outcome == StateMutationUnknown && store.prepareUnknownApplied {
		store.pending = request.PendingBytes()
	}
	if outcome == StateMutationUnknown && store.prepareUnknownCommitted {
		pending, _, err := decodePendingState(request.PendingBytes(), request.SourceID())
		if err != nil {
			return "", err
		}
		store.committed, err = canonicalReleaseTrustState(pending.NextState)
		if err != nil {
			return "", err
		}
		store.pending = nil
	}
	return outcome, nil
}

func (store *memorySourceTrustStateStore) CommitSourceTrustState(_ context.Context, request SourceTrustStateCommitRequest) (StateMutationOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commitCalls++
	if store.commitErrOnce != nil {
		err := store.commitErrOnce
		store.commitErrOnce = nil
		return "", err
	}
	if len(store.pending) == 0 || digestHex(store.pending) != request.PendingSHA256() || digestHex(request.NextStateBytes()) != request.NextStateSHA256() {
		return StateMutationConflict, nil
	}
	outcome := store.commitOutcome
	if outcome == "" {
		outcome = StateMutationApplied
	}
	if outcome == StateMutationApplied || outcome == StateMutationUnknown && store.commitUnknownApplied {
		store.committed = request.NextStateBytes()
		store.pending = nil
	}
	return outcome, nil
}

func (store *memorySourceTrustStateStore) committedState(t *testing.T) ReleaseTrustStateV1 {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := decodeReleaseTrustState(store.committed)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

type memoryMonotonicStateAdapter struct {
	mu             sync.Mutex
	counter        uint64
	stateSHA256    string
	casOutcome     StateMutationOutcome
	unknownApplied bool
}

func (adapter *memoryMonotonicStateAdapter) ReadMonotonicState(_ context.Context, request MonotonicStateReadRequest) (MonotonicStateReadResult, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return NewMonotonicStateReadResult(request, adapter.counter, adapter.stateSHA256)
}

func (adapter *memoryMonotonicStateAdapter) CompareAndSwapMonotonicState(_ context.Context, request MonotonicStateCASRequest) (StateMutationOutcome, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.counter != request.ExpectedCounter() || adapter.stateSHA256 != request.PreviousSHA256() {
		return StateMutationConflict, nil
	}
	outcome := adapter.casOutcome
	if outcome == "" {
		outcome = StateMutationApplied
	}
	if outcome == StateMutationApplied || outcome == StateMutationUnknown && adapter.unknownApplied {
		adapter.counter = request.NextCounter()
		adapter.stateSHA256 = request.NextSHA256()
	}
	return outcome, nil
}

var _ SourceTrustStateStore = (*memorySourceTrustStateStore)(nil)
var _ MonotonicStateAdapter = (*memoryMonotonicStateAdapter)(nil)
var _ TrustedTimeAdapter = (*testTransparencyTimeAdapter)(nil)

type typedNilDocumentTransport struct{}

func (*typedNilDocumentTransport) FetchReleaseDocument(context.Context, ReleaseDocumentRequest) (ReleaseDocumentResult, error) {
	panic("typed nil document transport must be rejected")
}

type typedNilLedgerTransport struct{}

func (*typedNilLedgerTransport) FetchSigningLedgerArtifact(context.Context, SigningLedgerRequest) (SigningLedgerResult, error) {
	panic("typed nil ledger transport must be rejected")
}
