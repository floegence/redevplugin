package host

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
)

const securityAuditExportInterval = time.Second

// securityAuditMutation keeps the journal identity separate from the public
// audit event. The identity is stable even when the operation returns an
// unknown outcome and must therefore be completed exactly once.
type securityAuditMutation struct {
	journal observability.SecurityAuditJournal
	eventID string
}

func (m securityAuditMutation) active() bool {
	return m.journal != nil && m.eventID != ""
}

func (h *Host) beginSecurityMutation(ctx context.Context, event AuditEvent) (securityAuditMutation, error) {
	if h == nil || h.securityJournal == nil {
		return securityAuditMutation{}, nil
	}
	record, err := h.securityJournal.BeginSecurityAudit(ctx, event)
	if err != nil {
		return securityAuditMutation{}, fmt.Errorf("%w: begin security audit: %v", ErrSecurityEventPersistence, err)
	}
	return securityAuditMutation{journal: h.securityJournal, eventID: record.EventID}, nil
}

func (m securityAuditMutation) complete(ctx context.Context, operationErr error) error {
	if !m.active() {
		return operationErr
	}
	outcome := mutation.OutcomeCommitted
	if operationErr != nil {
		outcome = mutation.ForError(operationErr)
	}
	var details map[string]any
	if operationErr != nil {
		details = map[string]any{"error": operationErr.Error()}
	}
	if err := m.journal.CompleteSecurityAudit(ctx, m.eventID, outcome, details); err != nil {
		persistenceErr := fmt.Errorf("%w: complete security audit: %v", ErrSecurityEventPersistence, err)
		if operationErr == nil {
			return mutation.Unknown(persistenceErr)
		}
		return mutation.Unknown(errors.Join(operationErr, persistenceErr))
	}
	return operationErr
}

// runSecurityMutation establishes the pending record before the supplied
// state-changing callback and completes it after the callback returns. Hosts
// without a durable journal retain the legacy audit sink behavior until their
// adapter is upgraded; configured journals never permit a silent persistence
// failure.
func (h *Host) runSecurityMutation(ctx context.Context, event AuditEvent, mutate func() error) error {
	if mutate == nil {
		return errors.New("security mutation callback is required")
	}
	audit, err := h.beginSecurityMutation(ctx, event)
	if err != nil {
		return err
	}
	return audit.complete(ctx, mutate())
}

func (h *Host) startSecurityAuditExporter() {
	if h == nil || h.securityExporter == nil || h.lifecycleCtx == nil {
		return
	}
	h.lifecycleWG.Add(1)
	go func() {
		defer h.lifecycleWG.Done()
		ticker := time.NewTicker(securityAuditExportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-h.lifecycleCtx.Done():
				return
			case <-ticker.C:
				if err := h.securityExporter.Export(h.lifecycleCtx); err != nil {
					h.diagnostic(context.WithoutCancel(h.lifecycleCtx), observability.DiagnosticEvent{
						Type:            "plugin.security_audit.export_failed",
						Severity:        observability.DiagnosticSeverityWarning,
						Message:         "security audit export failed",
						InternalDetails: map[string]any{"error": err.Error()},
					})
				}
			}
		}
	}()
}
