package httpadapter

import (
	"net/http"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func (h Handler) handleInspectRetainedRecovery(w http.ResponseWriter, r *http.Request) {
	var req host.InspectRetainedRecoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	result, err := h.host.InspectRetainedRecovery(r.Context(), req)
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeJSON(w, httpStatusForDataLifecycleError(err), errorResponse{OK: false, Code: code, Message: h.publicFailureMessage(r.Context(), "retained-data.inspect-recovery", code, err)})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: result})
}

func (h Handler) handleCommitRetainedRecovery(w http.ResponseWriter, r *http.Request) {
	var req host.RetainedRecoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.CommitRetainedRecovery(r.Context(), req)
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "retained-data.commit-recovery", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, result)
}

func (h Handler) handleRetainedRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	var req host.RetainedRecoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	result, err := h.host.GetRetainedRecoveryStatus(r.Context(), req)
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeJSON(w, httpStatusForDataLifecycleError(err), errorResponse{OK: false, Code: code, Message: h.publicFailureMessage(r.Context(), "retained-data.recovery-status", code, err)})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: result})
}
