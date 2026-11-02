package host

import (
	"context"
	"io"
	"strconv"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type WebFileTransferRequest struct {
	WebSurfaceRequest
	Handle string
}

// TransferWebFile streams an existing selected-file handle. Writes are not
// atomic: an error after any write reports unknown and is never replayed.
// The caller supplies exactly one of source (write) and destination (read).
func (h *Host) TransferWebFile(ctx context.Context, req WebFileTransferRequest, source io.Reader, destination io.Writer) (count int64, retErr error) {
	done, err := h.ensureOpen()
	if err != nil {
		return 0, err
	}
	defer done()
	if (source == nil) == (destination == nil) {
		return 0, errRuntimeIOInvalidRequest
	}
	handle, err := strconv.ParseUint(req.Handle, 10, 63)
	if err != nil || handle == 0 || strconv.FormatUint(handle, 10) != req.Handle {
		return 0, errRuntimeIOInvalidRequest
	}
	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return 0, err
	}
	if !binding.gatewayReady {
		return 0, bridge.ErrAssetSessionRequired
	}
	ctx, expiryCancel := context.WithDeadline(ctx, binding.expiresAt)
	defer expiryCancel()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	stop := context.AfterFunc(binding.ctx, cancel)
	defer stop()
	for _, stream := range []any{source, destination} {
		if closer, ok := stream.(io.Closer); ok {
			stopIO := context.AfterFunc(ctx, func() { _ = closer.Close() })
			defer stopIO()
		}
	}

	releaseResource, err := h.reserveWebResource(req.WebSurfaceRequest, binding.ctx)
	if err != nil {
		return 0, err
	}
	defer releaseResource()
	defer func() {
		if source != nil && retErr != nil && count > 0 {
			retErr = mutation.Unknown(retErr)
		}
	}()
	chunk := make([]byte, resourceio.MaxIOChunkBytes)
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		n, eof := len(chunk), false
		if source != nil {
			n, err = source.Read(chunk)
			eof = err == io.EOF
			if err != nil && !eof {
				return count, err
			}
			if n == 0 {
				if eof {
					return count, nil
				}
				return count, io.ErrNoProgress
			}
		}
		written, flags, err := h.webFileChunk(ctx, req, handle, chunk[:n], source != nil)
		count += int64(written)
		if err != nil {
			return count, err
		}
		if source == nil {
			if written > 0 {
				n, err := destination.Write(chunk[:written])
				if err != nil {
					return count, err
				}
				if n != written {
					return count, io.ErrShortWrite
				}
			}
			if flags&resourceio.IOFlagEOF != 0 {
				return count, nil
			}
			if written == 0 {
				return count, io.ErrNoProgress
			}
		} else if written != n {
			return count, mutation.Unknown(io.ErrShortWrite)
		} else if eof {
			return count, nil
		}
	}
}

func (h *Host) webFileChunk(ctx context.Context, req WebFileTransferRequest, handle uint64, chunk []byte, write bool) (int, uint32, error) {
	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return 0, 0, err
	}
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionSurfaceFile, binding.pluginInstanceID)
	if err != nil {
		return 0, 0, err
	}
	defer release()
	record, err := h.getPluginRecord(ctx, binding.pluginInstanceID)
	if err != nil {
		return 0, 0, err
	}
	if err := h.canRun(ctx, record); err != nil {
		return 0, 0, err
	}
	if !featureDeclaredForWebFiles(record.Manifest.API.RequiredFeatures) {
		return 0, 0, permissions.ErrPermissionDenied
	}
	validation, _, err := h.validateSurfaceAssetSession(ctx, binding.request)
	if err != nil {
		return 0, 0, err
	}
	scope, err := session.ResourceScope(sessionctx.ScopeUser)
	if err != nil {
		return 0, 0, err
	}
	owner, err := session.SessionScope()
	if err != nil {
		return 0, 0, err
	}
	ceiling := map[string]bool{}
	for _, p := range record.Manifest.Permissions {
		if permissions.ResourceScoped(string(p)) {
			ceiling[string(p)] = true
		}
	}
	inv := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: owner, RuntimeGeneration: validation.Session.RuntimeGenerationID, InvocationID: "surface-files:" + binding.request.SurfaceInstanceID, Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: record.PluginID, InstanceID: record.PluginInstanceID, Version: record.Version}, Permissions: ceiling, CanRead: session.CanRead, CanWrite: session.CanWrite}
	h.webSurfaces.fileMu.RLock()
	defer h.webSurfaces.fileMu.RUnlock()
	if !h.liveFileSurface(binding.request.SurfaceInstanceID, record.PluginInstanceID, owner) || ctx.Err() != nil {
		return 0, 0, bridge.ErrTokenRevoked
	}
	if write {
		n, err := h.runtimeIO.service.Write(ctx, inv, handle, chunk, 0)
		return n, 0, err
	}
	return h.runtimeIO.service.Read(ctx, inv, handle, chunk)
}
func featureDeclaredForWebFiles(features []manifest.FeatureID) bool {
	for _, feature := range features {
		if feature == manifest.FeatureSurfaceResources {
			return true
		}
	}
	return false
}
