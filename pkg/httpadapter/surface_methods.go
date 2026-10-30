package httpadapter

import (
	"net/http"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

func (h Handler) handleSurfaceMethods(w http.ResponseWriter, r *http.Request) {
	var req host.SurfaceMethodsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.SurfaceMethods(r.Context(), req)
	if err != nil {
		code := errorCodeForRPCError(err)
		h.writeRPCMutationError(w, r, "surface.methods", httpStatusForRPCError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	writeMutationSuccess(w, result)
}
func (h Handler) handlePrepareIntentConfirmation(w http.ResponseWriter, r *http.Request) {
	var req invokeIntentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.PrepareIntentConfirmation(r.Context(), host.InvokeIntentRequest{PluginInstanceID: req.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: req.IntentID, Params: req.Params})
	if err != nil {
		code := errorCodeForRPCError(err)
		h.writeRPCMutationError(w, r, "intent.prepare_confirmation", httpStatusForRPCError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	response, err := publicConfirmationPreparation(result)
	if err != nil {
		h.writeProjectionError(w, r, "intent.confirmation.response", err)
		return
	}
	writeMutationSuccess(w, response)
}
