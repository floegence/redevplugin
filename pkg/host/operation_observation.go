package host

import (
	"math"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const (
	SurfaceOperationSnapshotPerOperationRate  = 2
	SurfaceOperationSnapshotPerOperationBurst = 2
	SurfaceOperationSnapshotPerSurfaceRate    = 8
	SurfaceOperationSnapshotPerSurfaceBurst   = 8
	SurfaceOperationSnapshotRetryMinMS        = 500
	SurfaceOperationSnapshotRetryMaxMS        = 10_000

	surfaceOperationObservationIdleTTL               = 2 * time.Minute
	surfaceOperationObservationPruneInterval         = 30 * time.Second
	surfaceOperationObservationMaxSurfacesPerOwner   = 64
	surfaceOperationObservationMaxOperationsPerOwner = 4_096
	surfaceOperationObservationMaxSurfacesGlobal     = 8_192
	surfaceOperationObservationMaxOperationsGlobal   = 32_768
	surfaceOperationObservationMaxPerSurface         = 1_024
)

type GetSurfaceOperationRequest struct {
	OperationID       string    `json:"operation_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	BridgeChannelID   string    `json:"bridge_channel_id"`
	Now               time.Time `json:"-"`
}

// PluginOperationSnapshot is the sandbox-safe projection of an operation.
// TerminalAt and FailureCode are populated only for the status branches that
// require them; the HTTP and TypeScript contracts define the closed union.
type PluginOperationSnapshot struct {
	OperationID  string                           `json:"operation_id"`
	Status       operation.Status                 `json:"status"`
	Cancelable   bool                             `json:"cancelable"`
	CreatedAt    time.Time                        `json:"created_at"`
	UpdatedAt    time.Time                        `json:"updated_at"`
	RetryAfterMS int                              `json:"retry_after_ms"`
	TerminalAt   *time.Time                       `json:"terminal_at,omitempty"`
	FailureCode  *capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Progress     *capability.OperationProgress    `json:"progress,omitempty"`
}

type SurfaceOperationRateLimitError struct {
	RetryAfterMS int
}

func (e *SurfaceOperationRateLimitError) Error() string {
	return "surface operation snapshot rate limited"
}

type surfaceOperationObservationKey struct {
	owner             operation.OwnerScope
	surfaceInstanceID string
}

type observationBucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

type operationObservationState struct {
	bucket   observationBucket
	inFlight bool
}

type surfaceOperationObservationState struct {
	bucket     observationBucket
	operations map[string]*operationObservationState
}

type surfaceOperationObservationRegistry struct {
	mu              sync.Mutex
	surfaces        map[surfaceOperationObservationKey]*surfaceOperationObservationState
	operationCount  int
	ownerSurfaces   map[operation.OwnerScope]int
	ownerOperations map[operation.OwnerScope]int
	nextPrune       time.Time
}

func newSurfaceOperationObservationRegistry() *surfaceOperationObservationRegistry {
	return &surfaceOperationObservationRegistry{
		surfaces:        make(map[surfaceOperationObservationKey]*surfaceOperationObservationState),
		ownerSurfaces:   make(map[operation.OwnerScope]int),
		ownerOperations: make(map[operation.OwnerScope]int),
	}
}

func newObservationBucket(now time.Time, burst int) observationBucket {
	return observationBucket{tokens: float64(burst), lastRefill: now, lastSeen: now}
}

func refillObservationBucket(bucket *observationBucket, now time.Time, rate, burst int) {
	if now.Before(bucket.lastRefill) {
		now = bucket.lastRefill
	}
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = math.Min(float64(burst), bucket.tokens+elapsed*float64(rate))
	bucket.lastRefill = now
	bucket.lastSeen = now
}

func observationRetryAfterMS(tokens float64, rate int) int {
	waitMS := int(math.Ceil((1 - tokens) / float64(rate) * 1000))
	if waitMS < SurfaceOperationSnapshotRetryMinMS {
		return SurfaceOperationSnapshotRetryMinMS
	}
	if waitMS > SurfaceOperationSnapshotRetryMaxMS {
		return SurfaceOperationSnapshotRetryMaxMS
	}
	return waitMS
}

func (r *surfaceOperationObservationRegistry) acquire(key surfaceOperationObservationKey, operationID string, now time.Time) (func(), error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	surfaceState := r.surfaces[key]
	if surfaceState == nil {
		r.pruneIdleIfDueLocked(now)
		if r.ownerSurfaces[key.owner] >= surfaceOperationObservationMaxSurfacesPerOwner ||
			len(r.surfaces) >= surfaceOperationObservationMaxSurfacesGlobal {
			return nil, &SurfaceOperationRateLimitError{RetryAfterMS: SurfaceOperationSnapshotRetryMaxMS}
		}
		surfaceState = &surfaceOperationObservationState{
			bucket:     newObservationBucket(now, SurfaceOperationSnapshotPerSurfaceBurst),
			operations: make(map[string]*operationObservationState),
		}
		r.surfaces[key] = surfaceState
		r.ownerSurfaces[key.owner]++
	}
	operationState := surfaceState.operations[operationID]
	refillObservationBucket(&surfaceState.bucket, now, SurfaceOperationSnapshotPerSurfaceRate, SurfaceOperationSnapshotPerSurfaceBurst)
	if surfaceState.bucket.tokens < 1 {
		return nil, &SurfaceOperationRateLimitError{
			RetryAfterMS: observationRetryAfterMS(surfaceState.bucket.tokens, SurfaceOperationSnapshotPerSurfaceRate),
		}
	}
	surfaceState.bucket.tokens--
	if operationState == nil {
		r.pruneIdleIfDueLocked(now)
		surfaceState = r.surfaces[key]
		if surfaceState == nil {
			surfaceState = &surfaceOperationObservationState{
				bucket:     observationBucket{tokens: float64(SurfaceOperationSnapshotPerSurfaceBurst - 1), lastRefill: now, lastSeen: now},
				operations: make(map[string]*operationObservationState),
			}
			r.surfaces[key] = surfaceState
			r.ownerSurfaces[key.owner]++
		}
		if len(surfaceState.operations) >= surfaceOperationObservationMaxPerSurface ||
			r.ownerOperations[key.owner] >= surfaceOperationObservationMaxOperationsPerOwner ||
			r.operationCount >= surfaceOperationObservationMaxOperationsGlobal {
			return nil, &SurfaceOperationRateLimitError{RetryAfterMS: SurfaceOperationSnapshotRetryMaxMS}
		}
		operationState = &operationObservationState{bucket: newObservationBucket(now, SurfaceOperationSnapshotPerOperationBurst)}
		surfaceState.operations[operationID] = operationState
		r.operationCount++
		r.ownerOperations[key.owner]++
	}
	refillObservationBucket(&operationState.bucket, now, SurfaceOperationSnapshotPerOperationRate, SurfaceOperationSnapshotPerOperationBurst)
	retryAfterMS := 0
	if operationState.inFlight {
		retryAfterMS = SurfaceOperationSnapshotRetryMinMS
	}
	if operationState.bucket.tokens < 1 {
		retryAfterMS = max(retryAfterMS, observationRetryAfterMS(operationState.bucket.tokens, SurfaceOperationSnapshotPerOperationRate))
	}
	if retryAfterMS > 0 {
		return nil, &SurfaceOperationRateLimitError{RetryAfterMS: retryAfterMS}
	}
	operationState.bucket.tokens--
	operationState.inFlight = true
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		currentSurface := r.surfaces[key]
		if currentSurface == nil {
			return
		}
		if currentOperation := currentSurface.operations[operationID]; currentOperation == operationState {
			currentOperation.inFlight = false
		}
	}, nil
}

func (r *surfaceOperationObservationRegistry) dispose(key surfaceOperationObservationKey) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.removeSurfaceLocked(key)
	r.mu.Unlock()
}

func (r *surfaceOperationObservationRegistry) disposeSession(scope sessionctx.SessionScope) {
	if r == nil {
		return
	}
	r.mu.Lock()
	for key := range r.surfaces {
		if key.owner.OwnerSessionHash == scope.OwnerSessionHash && key.owner.OwnerUserHash == scope.OwnerUserHash &&
			key.owner.OwnerEnvHash == scope.OwnerEnvHash && key.owner.SessionChannelIDHash == scope.SessionChannelIDHash {
			r.removeSurfaceLocked(key)
		}
	}
	r.mu.Unlock()
}

func (r *surfaceOperationObservationRegistry) pruneIdleIfDueLocked(now time.Time) {
	if !r.nextPrune.IsZero() && now.Before(r.nextPrune) {
		return
	}
	for key, surface := range r.surfaces {
		for operationID, state := range surface.operations {
			if !state.inFlight && now.Sub(state.bucket.lastSeen) >= surfaceOperationObservationIdleTTL {
				delete(surface.operations, operationID)
				r.operationCount--
				r.ownerOperations[key.owner]--
				if r.ownerOperations[key.owner] == 0 {
					delete(r.ownerOperations, key.owner)
				}
			}
		}
		if len(surface.operations) == 0 && now.Sub(surface.bucket.lastSeen) >= surfaceOperationObservationIdleTTL {
			r.removeSurfaceLocked(key)
		}
	}
	r.nextPrune = now.Add(surfaceOperationObservationPruneInterval)
}

func (r *surfaceOperationObservationRegistry) removeSurfaceLocked(key surfaceOperationObservationKey) {
	surface := r.surfaces[key]
	if surface == nil {
		return
	}
	operationCount := len(surface.operations)
	r.operationCount -= operationCount
	r.ownerOperations[key.owner] -= operationCount
	if r.ownerOperations[key.owner] == 0 {
		delete(r.ownerOperations, key.owner)
	}
	r.ownerSurfaces[key.owner]--
	if r.ownerSurfaces[key.owner] == 0 {
		delete(r.ownerSurfaces, key.owner)
	}
	delete(r.surfaces, key)
}

func surfaceOperationObservationKeyFor(session sessionctx.Context, surfaceInstanceID string) surfaceOperationObservationKey {
	return surfaceOperationObservationKey{
		owner:             operationOwnerScope(session),
		surfaceInstanceID: strings.TrimSpace(surfaceInstanceID),
	}
}

func surfaceOperationMatchesAudience(record operation.Record, session sessionctx.Context, surfaceInstanceID, bridgeChannelID string) bool {
	return operationOwnedBySession(record, session) &&
		record.SurfaceInstanceID == strings.TrimSpace(surfaceInstanceID) &&
		record.BridgeChannelID == strings.TrimSpace(bridgeChannelID)
}

func projectPluginOperationSnapshot(record operation.Record) (PluginOperationSnapshot, error) {
	snapshot := PluginOperationSnapshot{
		OperationID:  record.OperationID,
		Status:       record.Status,
		Cancelable:   record.Cancelable,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
		RetryAfterMS: SurfaceOperationSnapshotRetryMinMS,
	}
	if record.Progress != nil {
		progress := *record.Progress
		if progress.CompletedUnits != nil {
			value := *progress.CompletedUnits
			progress.CompletedUnits = &value
		}
		if progress.TotalUnits != nil {
			value := *progress.TotalUnits
			progress.TotalUnits = &value
		}
		snapshot.Progress = &progress
	}
	switch record.Status {
	case operation.StatusRunning, operation.StatusCancelRequested:
		if record.TerminalAt != nil || record.FailureCode != "" {
			return PluginOperationSnapshot{}, operation.ErrInvalidOperation
		}
	case operation.StatusCompleted, operation.StatusCanceled,
		operation.StatusOrphanedAfterDisable, operation.StatusOrphanedAfterUninstall:
		if record.TerminalAt == nil || record.FailureCode != "" {
			return PluginOperationSnapshot{}, operation.ErrInvalidOperation
		}
		terminalAt := *record.TerminalAt
		snapshot.TerminalAt = &terminalAt
	case operation.StatusFailed:
		if record.TerminalAt == nil || !record.FailureCode.Valid() {
			return PluginOperationSnapshot{}, operation.ErrInvalidOperation
		}
		terminalAt := *record.TerminalAt
		failureCode := record.FailureCode
		snapshot.TerminalAt = &terminalAt
		snapshot.FailureCode = &failureCode
	default:
		return PluginOperationSnapshot{}, operation.ErrInvalidOperation
	}
	return snapshot, nil
}
