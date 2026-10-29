package httpadapter

import (
	"errors"
	"net/http"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func validFileErrorCode(code string) bool {
	switch code {
	case "INVALID_ARGUMENT", "PERMISSION_DENIED", "NOT_FOUND", "NOT_EMPTY", "ALREADY_EXISTS", "RESOURCE_CLOSED", "RESOURCE_LIMIT", "CROSS_DEVICE", "MOUNT_UNAVAILABLE", "RUNTIME_UNAVAILABLE", "CANCELED", "TIMEOUT", "IO_ERROR":
		return true
	default:
		return false
	}
}

func (h Handler) fileResourceFailure(w http.ResponseWriter, r *http.Request, err error, mutates bool) {
	var fileError *host.FileOperationError
	if errors.As(err, &fileError) {
		details := errorDetails{FileErrorCode: fileError.Code, FileRetryable: &fileError.Retryable}
		if mutates {
			writeMutationError(w, http.StatusConflict, security.ErrFileOperationFailed, fileError.Error(), details, mutation.ForError(err))
		} else {
			writeError(w, http.StatusConflict, security.ErrFileOperationFailed, fileError.Error(), details)
		}
		return
	}
	code := errorCodeForPermissionError(err)
	status := httpStatusForPermissionError(err)
	if errors.Is(err, host.ErrFileResourceUnavailable) {
		code = security.ErrPermissionDenied
		status = http.StatusGone
	}
	if errors.Is(err, host.ErrFileSelectionCanceled) {
		code = security.ErrInvalidRequest
		status = http.StatusConflict
	}
	message := h.publicFailureMessage(r.Context(), "file_resource", code, err)
	if mutates {
		writeMutationError(w, status, code, message, errorDetails{}, mutation.ForError(err))
		return
	}
	writeJSON(w, status, errorResponse{OK: false, Code: code, Message: message})
}
func (h Handler) handleSelectFileResource(w http.ResponseWriter, r *http.Request) {
	var req host.SelectFileResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	value, err := h.host.SelectFileResource(r.Context(), req)
	if errors.Is(err, host.ErrFileSelectionCanceled) {
		writeMutationSuccess(w, map[string]bool{"canceled": true})
		return
	}
	if err != nil {
		h.fileResourceFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]any{"review": value})
}
func (h Handler) handleSurfaceFile(w http.ResponseWriter, r *http.Request) {
	var req host.SurfaceFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	value, err := h.host.SurfaceFile(r.Context(), req)
	if err != nil {
		h.fileResourceFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, value)
}
func (h Handler) handleApproveFileResource(w http.ResponseWriter, r *http.Request) {
	var req host.ApproveFileResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	value, err := h.host.ApproveFileResource(r.Context(), req)
	if err != nil {
		h.fileResourceFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, value)
}
func (h Handler) handleCancelFileResource(w http.ResponseWriter, r *http.Request) {
	var req host.CancelFileResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.CancelFileResource(r.Context(), req); err != nil {
		h.fileResourceFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]bool{"canceled": true})
}
func (h Handler) handleListFileResources(w http.ResponseWriter, r *http.Request) {
	var req host.ListFileResourcesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	value, err := h.host.ListFileResources(r.Context(), req)
	if err != nil {
		h.fileResourceFailure(w, r, err, false)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: map[string]any{"resources": value}})
}
func (h Handler) handleRevokeFileResource(w http.ResponseWriter, r *http.Request) {
	var req host.RevokeFileResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.RevokeFileResource(r.Context(), req); err != nil {
		h.fileResourceFailure(w, r, err, true)
		return
	}
	writeMutationSuccess(w, map[string]bool{"revoked": true})
}
