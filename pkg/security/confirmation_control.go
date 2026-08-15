package security

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
)

// ConfirmationIntentControlStore is the atomic persistence boundary used by
// Host's single control database. It deliberately accepts the public intent
// model so the security adapter remains the sole owner of request validation.
type ConfirmationIntentControlStore interface {
	PutConfirmationIntentRecord(context.Context, ConfirmationIntentRecord, time.Time, ConfirmationIntentStoreOptions) error
	ConsumeConfirmationIntentRecord(context.Context, string, sessionctx.SessionScope, time.Time) (ConfirmationIntentRecord, error)
	RejectConfirmationIntentRecord(context.Context, RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	ListConfirmationIntentRecords(context.Context, string) ([]ConfirmationIntentRecord, error)
	RevokePluginConfirmationIntentRecords(context.Context, string, string) (int, error)
	RevokeSessionConfirmationIntentRecords(context.Context, sessionctx.SessionScope, string, int) (int, error)
	FinalizeSessionConfirmationIntentRevocation(context.Context, sessionctx.SessionScope, string) error
}

type controlConfirmationIntentStore struct {
	backend ConfirmationIntentControlStore
	options ConfirmationIntentStoreOptions
}

func NewControlConfirmationIntentStore(backend ConfirmationIntentControlStore, options ConfirmationIntentStoreOptions) (ConfirmationIntentStore, error) {
	if backend == nil {
		return nil, errors.New("confirmation intent control store is required")
	}
	normalized, err := normalizeConfirmationIntentStoreOptions(options)
	if err != nil {
		return nil, err
	}
	return &controlConfirmationIntentStore{backend: backend, options: normalized}, nil
}

func (*controlConfirmationIntentStore) Durable() bool { return true }

func (s *controlConfirmationIntentStore) PutConfirmationIntent(ctx context.Context, req PutConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := confirmationIntentFromPut(req, now)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if err := s.backend.PutConfirmationIntentRecord(ctx, record, now, s.options); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	return record, nil
}

func (s *controlConfirmationIntentStore) ConsumeConfirmationIntent(ctx context.Context, req ConsumeConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	id := strings.TrimSpace(req.ConfirmationID)
	if id == "" {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return s.backend.ConsumeConfirmationIntentRecord(ctx, id, req.SessionScope, now)
}

func (s *controlConfirmationIntentStore) RejectConfirmationIntent(ctx context.Context, req RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	normalized, err := normalizeRejectConfirmationIntentRequest(req)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if normalized.Now.IsZero() {
		normalized.Now = time.Now().UTC()
	}
	return s.backend.RejectConfirmationIntentRecord(ctx, normalized)
}

func (s *controlConfirmationIntentStore) ListConfirmationIntents(ctx context.Context, req ListConfirmationIntentsRequest) ([]ConfirmationIntentRecord, error) {
	records, err := s.backend.ListConfirmationIntentRecords(ctx, strings.TrimSpace(req.PluginInstanceID))
	if err != nil {
		return nil, err
	}
	sortConfirmationIntentRecords(records)
	return records, nil
}

func (s *controlConfirmationIntentStore) RevokePluginConfirmationIntents(ctx context.Context, req RevokePluginConfirmationIntentsRequest) (int, error) {
	pluginID := strings.TrimSpace(req.PluginInstanceID)
	ownerEnv := strings.TrimSpace(req.OwnerEnvHash)
	if pluginID == "" || !(sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEnv}).Valid() {
		return 0, ErrInvalidConfirmationIntent
	}
	return s.backend.RevokePluginConfirmationIntentRecords(ctx, ownerEnv, pluginID)
}

func (s *controlConfirmationIntentStore) RevokeSessionConfirmationIntents(ctx context.Context, req RevokeSessionConfirmationIntentsRequest) (int, error) {
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if req.SessionScope.Validate() != nil || operationID == "" || len(operationID) > 256 {
		return 0, ErrInvalidConfirmationIntent
	}
	return s.backend.RevokeSessionConfirmationIntentRecords(ctx, req.SessionScope, operationID, s.options.MaxSessionRevocations)
}

func (s *controlConfirmationIntentStore) FinalizeSessionConfirmationRevocation(ctx context.Context, req FinalizeSessionConfirmationRevocationRequest) error {
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if req.SessionScope.Validate() != nil || operationID == "" || len(operationID) > 256 {
		return ErrInvalidConfirmationIntent
	}
	return s.backend.FinalizeSessionConfirmationIntentRevocation(ctx, req.SessionScope, operationID)
}

var _ ConfirmationIntentStore = (*controlConfirmationIntentStore)(nil)
