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
	export  func(context.Context) error
}

func (h *Host) beginSecurityMutation(ctx context.Context, event AuditEvent) (securityAuditMutation, error) {
	if h == nil || h.securityJournal == nil {
		return securityAuditMutation{}, fmt.Errorf("%w: security audit journal is required", ErrSecurityEventPersistence)
	}
	record, err := h.securityJournal.BeginSecurityAudit(ctx, event)
	if err != nil {
		return securityAuditMutation{}, fmt.Errorf("%w: begin security audit: %v", ErrSecurityEventPersistence, err)
	}
	if record.EventID == "" {
		return securityAuditMutation{}, fmt.Errorf("%w: begin security audit returned an empty event id", ErrSecurityEventPersistence)
	}
	return securityAuditMutation{journal: h.securityJournal, eventID: record.EventID, export: h.exportSecurityAudits}, nil
}

func (m securityAuditMutation) complete(ctx context.Context, operationErr error) error {
	return m.completeWithDetails(ctx, operationErr, nil)
}

func (m securityAuditMutation) completeWithDetails(ctx context.Context, operationErr error, details map[string]any) error {
	if m.journal == nil || m.eventID == "" {
		persistenceErr := fmt.Errorf("%w: incomplete security audit transaction", ErrSecurityEventPersistence)
		if operationErr == nil {
			return mutation.Unknown(persistenceErr)
		}
		return mutation.Unknown(errors.Join(operationErr, persistenceErr))
	}
	outcome := mutation.OutcomeCommitted
	if operationErr != nil {
		outcome = mutation.ForError(operationErr)
	}
	if operationErr != nil {
		if details == nil {
			details = make(map[string]any, 1)
		} else {
			cloned := make(map[string]any, len(details)+1)
			for key, value := range details {
				cloned[key] = value
			}
			details = cloned
		}
		details["failure"] = observability.FailureFromError(
			observability.FailureAction,
			observability.FailureComponentSecurity,
			observability.FailureOperationSecurityMutationComplete,
			operationErr,
		)
	}
	if err := m.journal.CompleteSecurityAudit(ctx, m.eventID, outcome, details); err != nil {
		persistenceErr := fmt.Errorf("%w: complete security audit: %v", ErrSecurityEventPersistence, err)
		if operationErr == nil {
			return mutation.Unknown(persistenceErr)
		}
		return mutation.Unknown(errors.Join(operationErr, persistenceErr))
	}
	if m.export != nil {
		if err := m.export(ctx); err != nil {
			persistenceErr := fmt.Errorf("%w: export security audit: %v", ErrSecurityEventPersistence, err)
			if operationErr == nil {
				return mutation.Unknown(persistenceErr)
			}
			return mutation.Unknown(errors.Join(operationErr, persistenceErr))
		}
	}
	return operationErr
}

// runSecurityMutation establishes the pending record before the supplied
// state-changing callback and completes it after the callback returns.
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

// recordSecurityEvent persists a completed security observation through the
// same journal/exporter path as mutations. It never bypasses the journal by
// writing directly to the host audit sink.
func (h *Host) recordSecurityEvent(ctx context.Context, event AuditEvent) error {
	audit, err := h.beginSecurityMutation(ctx, event)
	if err != nil {
		return err
	}
	return audit.complete(context.WithoutCancel(ctx), nil)
}

func (h *Host) exportSecurityAudits(ctx context.Context) error {
	if h == nil || h.securityExporter == nil {
		return nil
	}
	h.securityExportMu.Lock()
	defer h.securityExportMu.Unlock()
	return h.securityExporter.Export(ctx)
}

func (h *Host) startSecurityAuditExporter() {
	if h == nil || h.securityExporter == nil || h.lifecycleCtx == nil {
		return
	}
	h.securityAuditWG.Add(1)
	go func() {
		defer h.securityAuditWG.Done()
		ticker := time.NewTicker(securityAuditExportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-h.lifecycleCtx.Done():
				return
			case <-ticker.C:
				if err := h.exportSecurityAudits(h.lifecycleCtx); err != nil {
					h.diagnostic(context.WithoutCancel(h.lifecycleCtx), observability.DiagnosticEvent{
						Type:     "plugin.security_audit.export_failed",
						Severity: observability.DiagnosticSeverityWarning,
						Message:  "security audit export failed",
						Failure: observability.FailureFromError(
							observability.FailureAdapter,
							observability.FailureComponentSecurity,
							observability.FailureOperationSecurityAuditExport,
							err,
						),
					})
				}
			}
		}
	}()
}
