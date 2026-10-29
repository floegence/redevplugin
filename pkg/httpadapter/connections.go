package httpadapter

import (
	"errors"
	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"net/http"
)

func (h Handler) connectionFailure(w http.ResponseWriter, r *http.Request, err error, mutates bool) {
	code, status := errorCodeForPermissionError(err), httpStatusForPermissionError(err)
	if errors.Is(err, host.ErrConnectionUnavailable) {
		code, status = security.ErrConnectionUnavailable, http.StatusConflict
	} else if errors.Is(err, connectivity.ErrConnectorDenied) || errors.Is(err, connectivity.ErrTargetDenied) {
		code, status = security.ErrNetworkTargetDenied, http.StatusForbidden
	}
	if errors.Is(err, controlstore.ErrRevisionConflict) {
		code, status = security.ErrConnectionConflict, http.StatusConflict
	}
	if errors.Is(err, connectivity.ErrInvalidConnector) {
		code, status = security.ErrInvalidRequest, http.StatusBadRequest
	}
	message := h.publicFailureMessage(r.Context(), "connection", code, err)
	if mutates {
		writeMutationError(w, status, code, message, errorDetails{}, mutation.ForError(err))
		return
	}
	writeJSON(w, status, errorResponse{OK: false, Code: code, Message: message})
}
func (h Handler) handleReviewConnection(w http.ResponseWriter, r *http.Request) {
	var req host.ReviewConnectionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	value, err := h.host.ReviewConnection(r.Context(), req)
	if err != nil {
		h.connectionFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]any{"review": value})
}
func (h Handler) handleApproveConnection(w http.ResponseWriter, r *http.Request) {
	var req host.ConnectionReviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	value, err := h.host.ApproveConnection(r.Context(), req)
	if err != nil {
		h.connectionFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, value)
}
func (h Handler) handleCancelConnectionReview(w http.ResponseWriter, r *http.Request) {
	var req host.ConnectionReviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	err := h.host.CancelConnectionReview(r.Context(), req)
	if err != nil {
		h.connectionFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]bool{"canceled": true})
}
func (h Handler) handleListConnections(w http.ResponseWriter, r *http.Request) {
	var req host.ConnectionListRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	value, err := h.host.ListConnections(r.Context(), req)
	if err != nil {
		h.connectionFailure(w, r, err, false)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: map[string]any{"connections": value}})
}
func (h Handler) handleRevokeConnection(w http.ResponseWriter, r *http.Request) {
	var req host.RevokeConnectionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	err := h.host.RevokeConnection(r.Context(), req)
	if err != nil {
		h.connectionFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]bool{"revoked": true})
}
