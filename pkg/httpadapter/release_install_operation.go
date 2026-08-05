package httpadapter

import (
	"net/http"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
)

type startReleaseInstallOperationRequest struct {
	RequestID        string            `json:"request_id"`
	PluginInstanceID string            `json:"plugin_instance_id"`
	ReleaseRef       releaseRefRequest `json:"release_ref"`
}

type releaseInstallOperationResponse struct {
	RequestID        string                                 `json:"request_id"`
	OperationID      string                                 `json:"operation_id"`
	PluginInstanceID string                                 `json:"plugin_instance_id"`
	RequestSHA256    string                                 `json:"request_sha256"`
	Status           registry.ReleaseInstallOperationStatus `json:"status"`
	Phase            string                                 `json:"phase"`
	Progress         registry.ReleaseInstallProgress        `json:"progress"`
	Attempt          int                                    `json:"attempt"`
	RetryAfterMS     int64                                  `json:"retry_after_ms"`
	MutationOutcome  mutation.Outcome                       `json:"mutation_outcome"`
	Failure          *registry.ReleaseInstallFailure        `json:"failure,omitempty"`
	PluginRecord     *pluginRecordResponse                  `json:"plugin_record,omitempty"`
	CreatedAt        time.Time                              `json:"created_at"`
	UpdatedAt        time.Time                              `json:"updated_at"`
	TerminalAt       *time.Time                             `json:"terminal_at,omitempty"`
}

type releaseInstallOperationListResponse struct {
	Operations []releaseInstallOperationResponse `json:"operations"`
}

func publicReleaseInstallOperation(operation registry.ReleaseInstallOperation) (releaseInstallOperationResponse, error) {
	response := releaseInstallOperationResponse{
		RequestID: operation.RequestID, OperationID: operation.OperationID,
		PluginInstanceID: operation.PluginInstanceID, RequestSHA256: operation.RequestSHA256,
		Status: operation.Status, Phase: operation.Phase, Progress: operation.Progress,
		Attempt: operation.Attempt, RetryAfterMS: operation.RetryAfterMS,
		MutationOutcome: operation.MutationOutcome, Failure: operation.Failure,
		CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
		TerminalAt: cloneWireTime(operation.TerminalAt),
	}
	if operation.PluginRecord != nil {
		projected, err := publicPluginRecord(*operation.PluginRecord)
		if err != nil {
			return releaseInstallOperationResponse{}, err
		}
		response.PluginRecord = &projected
	}
	return response, nil
}

func (h Handler) handleStartReleaseInstallOperation(w http.ResponseWriter, r *http.Request) {
	var req startReleaseInstallOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	operation, err := h.host.StartReleaseInstallOperation(r.Context(), host.StartReleaseInstallOperationRequest{
		RequestID: req.RequestID, PluginInstanceID: req.PluginInstanceID, ReleaseRef: req.ReleaseRef.domain(),
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "release.install_operation.start", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	response, err := publicReleaseInstallOperation(operation)
	if err != nil {
		h.writeProjectionError(w, r, "release.install_operation.start.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handleListReleaseInstallOperations(w http.ResponseWriter, r *http.Request) {
	operations, err := h.host.ListReleaseInstallOperations(r.Context())
	if err != nil {
		code := errorCodeForManagementError(err)
		writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "release.install_operation.list", code, err), errorDetailsForManagementError(err))
		return
	}
	responses := make([]releaseInstallOperationResponse, len(operations))
	for index, operation := range operations {
		responses[index], err = publicReleaseInstallOperation(operation)
		if err != nil {
			h.writeProjectionError(w, r, "release.install_operation.list.response", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: releaseInstallOperationListResponse{Operations: responses}})
}

func (h Handler) handleGetReleaseInstallOperation(w http.ResponseWriter, r *http.Request) {
	h.handleGetReleaseInstallOperationValue(w, r, releaseInstallPathValue(r.URL.Path, "/_redevplugin/api/plugins/release-install-operations/"), false)
}

func (h Handler) handleGetReleaseInstallOperationByRequest(w http.ResponseWriter, r *http.Request) {
	h.handleGetReleaseInstallOperationValue(w, r, releaseInstallPathValue(r.URL.Path, "/_redevplugin/api/plugins/release-install-operations/by-request/"), true)
}

func releaseInstallPathValue(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	value := strings.TrimPrefix(path, prefix)
	if value == "" || strings.Contains(value, "/") {
		return ""
	}
	return value
}

func (h Handler) handleGetReleaseInstallOperationValue(w http.ResponseWriter, r *http.Request, value string, byRequest bool) {
	if value == "" {
		writeError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{})
		return
	}
	var operation registry.ReleaseInstallOperation
	var err error
	if byRequest {
		operation, err = h.host.GetReleaseInstallOperationByRequest(r.Context(), value)
	} else {
		operation, err = h.host.GetReleaseInstallOperation(r.Context(), value)
	}
	if err != nil {
		code := errorCodeForManagementError(err)
		writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "release.install_operation.get", code, err), errorDetailsForManagementError(err))
		return
	}
	response, err := publicReleaseInstallOperation(operation)
	if err != nil {
		h.writeProjectionError(w, r, "release.install_operation.get.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: response})
}
