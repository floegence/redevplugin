package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// SurfaceFileRequest uses the same authenticated surface gateway as method
// calls. File handles use decimal strings because their 63 bits exceed JS's
// exact integer range. Applications never receive the gateway credential.
type SurfaceFileRequest struct {
	PluginInstanceID  string          `json:"plugin_instance_id"`
	SurfaceInstanceID string          `json:"surface_instance_id"`
	BridgeChannelID   string          `json:"bridge_channel_id"`
	GatewayToken      string          `json:"plugin_gateway_token"`
	Operation         string          `json:"operation"`
	Arguments         json.RawMessage `json:"arguments"`
}
type SurfaceFileResult struct {
	Canceled bool                `json:"canceled,omitempty"`
	Review   *FileResourceReview `json:"review,omitempty"`
	Handle   string              `json:"handle,omitempty"`
	Data     *string             `json:"data,omitempty"`
	Count    *int                `json:"count,omitempty"`
	EOF      *bool               `json:"eof,omitempty"`
	Offset   string              `json:"offset,omitempty"`
	Value    any                 `json:"value,omitempty"`
}

// FileOperationError exposes only a stable I/O code, never a filesystem path.
type FileOperationError struct {
	Code      string
	Retryable bool
}

func (e *FileOperationError) Error() string { return "file operation failed: " + e.Code }

func (h *Host) liveFileSurface(id, plugin string, session sessionctx.SessionScope) bool {
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	for _, binding := range h.webSurfaces.byOrigin {
		if binding.request.SurfaceInstanceID == id && binding.pluginInstanceID == plugin && binding.owner.OwnerSessionHash == session.OwnerSessionHash && binding.owner.OwnerUserHash == session.OwnerUserHash && binding.owner.OwnerEnvHash == session.OwnerEnvHash && binding.owner.SessionChannelIDHash == session.SessionChannelIDHash && binding.gatewayReady && binding.expiresAt.After(time.Now()) {
			return true
		}
	}
	return false
}

func (h *Host) SurfaceFile(ctx context.Context, req SurfaceFileRequest) (result SurfaceFileResult, retErr error) {
	defer func() {
		if retErr == nil {
			return
		}
		if errors.Is(retErr, errRuntimeIOInvalidRequest) {
			retErr = resourceio.ErrInvalidOptions
		}
		code, retryable := resourceio.StableError(retErr)
		if code == "IO_ERROR" {
			var pathError *os.PathError
			var linkError *os.LinkError
			if !errors.As(retErr, &pathError) && !errors.As(retErr, &linkError) && !errors.Is(retErr, io.ErrShortWrite) {
				return
			}
		}
		outcome, explicit := mutation.Explicit(retErr)
		retErr = &FileOperationError{Code: code, Retryable: retryable}
		if explicit {
			retErr = &mutation.Error{Outcome: outcome, Err: retErr}
		}
	}()
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionSurfaceFile, req.PluginInstanceID)
	if err != nil {
		return SurfaceFileResult{}, err
	}
	defer release()
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return SurfaceFileResult{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return SurfaceFileResult{}, ErrFileResourceUnavailable
	}
	if err := h.canRun(ctx, record); err != nil {
		return SurfaceFileResult{}, err
	}
	// Policy checks may revoke surfaces. Acquire the file-operation fence only
	// after those checks; token and resource authority are revalidated below.
	if req.Operation != "select" {
		h.webSurfaces.fileMu.RLock()
		defer h.webSurfaces.fileMu.RUnlock()
	}
	token, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{GatewayToken: req.GatewayToken, PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash, BridgeChannelID: req.BridgeChannelID, Revision: bridge.RevisionBinding{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}, Now: time.Now()})
	if err != nil {
		return SurfaceFileResult{}, err
	}
	if err := h.requireSurfaceGeneration(req.SurfaceInstanceID, token.Audience.RuntimeGenerationID, time.Now()); err != nil {
		return SurfaceFileResult{}, err
	}
	scope, err := session.ResourceScope(sessionctx.ScopeUser)
	if err != nil {
		return SurfaceFileResult{}, err
	}
	sessionScope, err := session.SessionScope()
	if err != nil {
		return SurfaceFileResult{}, err
	}
	if !h.liveFileSurface(req.SurfaceInstanceID, req.PluginInstanceID, sessionScope) {
		return SurfaceFileResult{}, ErrFileResourceUnavailable
	}
	ceiling := map[string]bool{}
	for _, p := range record.Manifest.Permissions {
		if permissions.ResourceScoped(string(p)) {
			ceiling[string(p)] = true
		}
	}
	inv := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: sessionScope, RuntimeGeneration: token.Audience.RuntimeGenerationID, InvocationID: "surface-files:" + req.SurfaceInstanceID, Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: record.PluginID, InstanceID: record.PluginInstanceID, Version: record.Version}, Permissions: ceiling, CanRead: session.CanRead, CanWrite: session.CanWrite}
	if len(req.Arguments) > 96<<10 {
		return SurfaceFileResult{}, resourceio.ErrResourceLimit
	}
	if err := validateRuntimeIOJSON(req.Arguments); err != nil {
		return SurfaceFileResult{}, errRuntimeIOInvalidRequest
	}
	switch req.Operation {
	case "select":
		var args struct {
			Kind      string `json:"kind"`
			Recursive bool   `json:"recursive"`
			Writable  bool   `json:"writable"`
		}
		if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		review, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: req.PluginInstanceID, Kind: args.Kind, Recursive: args.Recursive, Writable: args.Writable})
		if errors.Is(err, ErrFileSelectionCanceled) {
			return SurfaceFileResult{Canceled: true}, nil
		}
		if err != nil {
			return SurfaceFileResult{}, err
		}
		h.webSurfaces.fileMu.RLock()
		defer h.webSurfaces.fileMu.RUnlock()
		h.selectedFiles.mu.Lock()
		defer h.selectedFiles.mu.Unlock()
		pending := h.selectedFiles.reviews[review.ReviewID]
		if pending == nil || ctx.Err() != nil || !h.liveFileSurface(req.SurfaceInstanceID, req.PluginInstanceID, sessionScope) {
			if pending != nil {
				_ = pending.selection.Close()
				delete(h.selectedFiles.reviews, review.ReviewID)
			}
			return SurfaceFileResult{}, ErrFileResourceUnavailable
		}
		pending.surfaceID = req.SurfaceInstanceID
		return SurfaceFileResult{Review: &review}, nil
	case "read", "write", "seek", "close", "sync", "read_dir.next":
		return h.surfaceFileHandle(ctx, inv, req)
	default:
		if !strings.HasPrefix(req.Operation, "fs.") {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		// This entry point exposes only selected file operations, never general
		// mounts, network, storage, processes, or platform discovery.
		switch req.Operation {
		case "fs.open", "fs.stat", "fs.mkdir", "fs.remove", "fs.rename", "fs.copy", "fs.read_dir.open", "fs.set_times":
		default:
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		control, _ := json.Marshal(runtimeIOControlRequest{PluginAPI: resourceio.PluginAPI, Operation: req.Operation, Arguments: req.Arguments})
		raw, err := h.runtimeIO.service.Control(ctx, inv, control)
		if err != nil {
			return SurfaceFileResult{}, err
		}
		var response struct {
			OK     bool                       `json:"ok"`
			Result map[string]json.RawMessage `json:"result"`
			Error  *runtimeIOControlError     `json:"error"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			return SurfaceFileResult{}, err
		}
		if !response.OK {
			return SurfaceFileResult{}, surfaceFileControlError(response.Error)
		}
		if rawHandle, ok := response.Result["handle"]; ok {
			var handle uint64
			if err := json.Unmarshal(rawHandle, &handle); err != nil {
				return SurfaceFileResult{}, err
			}
			return SurfaceFileResult{Handle: strconv.FormatUint(handle, 10)}, nil
		}
		if req.Operation == "fs.stat" {
			var size int64
			if err := json.Unmarshal(response.Result["size"], &size); err != nil || size < 0 {
				return SurfaceFileResult{}, errRuntimeIOInvalidRequest
			}
			response.Result["size"], _ = json.Marshal(strconv.FormatInt(size, 10))
		}
		return SurfaceFileResult{Value: response.Result}, nil
	}
}

func (h *Host) surfaceFileHandle(ctx context.Context, inv resourceio.Invocation, req SurfaceFileRequest) (SurfaceFileResult, error) {
	fields := map[string][]string{
		"read": {"handle", "length"}, "write": {"handle", "data"}, "seek": {"handle", "offset", "whence"},
		"close": {"handle"}, "sync": {"handle"}, "read_dir.next": {"handle", "limit"},
	}
	var supplied map[string]json.RawMessage
	if err := json.Unmarshal(req.Arguments, &supplied); err != nil {
		return SurfaceFileResult{}, errRuntimeIOInvalidRequest
	}
	for key := range supplied {
		allowed := false
		for _, name := range fields[req.Operation] {
			if name == key {
				allowed = true
				break
			}
		}
		if !allowed {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
	}
	for _, key := range fields[req.Operation] {
		if _, ok := supplied[key]; !ok && key != "whence" {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
	}
	var args struct {
		Handle string `json:"handle"`
		Length int    `json:"length,omitempty"`
		Data   string `json:"data,omitempty"`
		Offset string `json:"offset,omitempty"`
		Whence int    `json:"whence,omitempty"`
		Limit  int    `json:"limit,omitempty"`
	}
	if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
		return SurfaceFileResult{}, errRuntimeIOInvalidRequest
	}
	handle, err := strconv.ParseUint(args.Handle, 10, 63)
	if err != nil || handle == 0 || strconv.FormatUint(handle, 10) != args.Handle {
		return SurfaceFileResult{}, errRuntimeIOInvalidRequest
	}
	service := h.runtimeIO.service
	if req.Operation != "read_dir.next" && args.Limit != 0 {
		return SurfaceFileResult{}, errRuntimeIOInvalidRequest
	}
	switch req.Operation {
	case "read":
		if args.Length < 1 || args.Length > resourceio.MaxIOChunkBytes || args.Data != "" || args.Offset != "" || args.Whence != 0 {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		data := make([]byte, args.Length)
		n, flags, err := service.Read(ctx, inv, handle, data)
		eof := flags&resourceio.IOFlagEOF != 0
		encoded := base64.StdEncoding.EncodeToString(data[:n])
		return SurfaceFileResult{Data: &encoded, Count: &n, EOF: &eof}, err
	case "write":
		if len(args.Data) > base64.StdEncoding.EncodedLen(resourceio.MaxIOChunkBytes) || args.Length != 0 || args.Offset != "" || args.Whence != 0 {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		data, err := base64.StdEncoding.Strict().DecodeString(args.Data)
		if err != nil || base64.StdEncoding.EncodeToString(data) != args.Data {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		n, err := service.Write(ctx, inv, handle, data, 0)
		if n > 0 && err != nil {
			err = mutation.Unknown(err)
		}
		return SurfaceFileResult{Count: &n}, err
	case "seek":
		offset, err := strconv.ParseInt(args.Offset, 10, 64)
		if err != nil || strconv.FormatInt(offset, 10) != args.Offset || args.Length != 0 || args.Data != "" {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		position, err := service.Seek(ctx, inv, handle, offset, args.Whence)
		return SurfaceFileResult{Offset: strconv.FormatInt(position, 10)}, err
	case "close", "sync", "read_dir.next":
		if args.Data != "" || args.Offset != "" || args.Length != 0 || args.Whence != 0 {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		if req.Operation == "close" {
			return SurfaceFileResult{}, service.Close(inv, handle)
		}
		operation, arguments := "fs.sync", json.RawMessage(`{"handle":`+args.Handle+`}`)
		if req.Operation == "read_dir.next" {
			if args.Limit < 1 || args.Limit > 256 {
				return SurfaceFileResult{}, errRuntimeIOInvalidRequest
			}
			operation = "fs.read_dir.next"
			arguments = json.RawMessage(`{"handle":` + args.Handle + `,"limit":` + strconv.Itoa(args.Limit) + `}`)
		}
		control, _ := json.Marshal(runtimeIOControlRequest{PluginAPI: resourceio.PluginAPI, Operation: operation, Arguments: arguments})
		raw, err := service.Control(ctx, inv, control)
		if err != nil {
			return SurfaceFileResult{}, err
		}
		var response struct {
			OK     bool                   `json:"ok"`
			Error  *runtimeIOControlError `json:"error"`
			Result any                    `json:"result"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			return SurfaceFileResult{}, errRuntimeIOInvalidRequest
		}
		if !response.OK {
			return SurfaceFileResult{}, surfaceFileControlError(response.Error)
		}
		return SurfaceFileResult{Value: response.Result}, nil
	}
	return SurfaceFileResult{}, errRuntimeIOInvalidRequest
}
func surfaceFileControlError(err *runtimeIOControlError) error {
	if err == nil {
		return errRuntimeIOInvalidRequest
	}
	failure := error(&FileOperationError{Code: err.Code, Retryable: err.Retryable})
	if outcome, ok := err.Details["mutation_outcome"].(string); ok && outcome == string(mutation.OutcomeUnknown) {
		return mutation.Unknown(failure)
	}
	return failure
}
