package resourceio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

const (
	PermissionFSWorkspaceRead    = "fs.workspace.read"
	PermissionFSWorkspaceWrite   = "fs.workspace.write"
	PermissionFSHomeRead         = "fs.home.read"
	PermissionFSHomeWrite        = "fs.home.write"
	PermissionFSEnvironmentRead  = "fs.environment.read"
	PermissionFSEnvironmentWrite = "fs.environment.write"
	PermissionNetworkClient      = "network.client"
	PermissionNetworkListen      = "network.listen"
)

type Plugin struct {
	ID         string
	InstanceID string
	Version    string
}

type Invocation struct {
	Owner       Owner
	Plugin      Plugin
	Permissions map[string]bool
	CanRead     bool
	CanWrite    bool
}

type MountSpec struct {
	ID       string
	Path     string
	ReadOnly bool
}

type MountResolver interface {
	ResolveMount(context.Context, Invocation, string) (MountSpec, error)
	ListMounts(context.Context, Invocation) ([]MountSpec, error)
}

type NetworkAuthorization struct {
	Invocation  Invocation
	Operation   string
	Destination *url.URL
	Listen      bool
}

type NetworkAuthorizer interface {
	AuthorizeNetwork(context.Context, NetworkAuthorization) error
}

type Service struct {
	table   *Table
	mounts  MountResolver
	network NetworkAuthorizer
}

func NewService(table *Table, mounts MountResolver, network NetworkAuthorizer) (*Service, error) {
	if table == nil {
		return nil, ErrInvalidHandle
	}
	return &Service{table: table, mounts: mounts, network: network}, nil
}

type controlRequest struct {
	API       int             `json:"api"`
	Operation string          `json:"operation"`
	Arguments json.RawMessage `json:"arguments"`
}

type controlResponse struct {
	OK     bool          `json:"ok"`
	Result any           `json:"result,omitempty"`
	Error  *serviceError `json:"error,omitempty"`
}

type serviceError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details"`
}

func (service *Service) Control(ctx context.Context, invocation Invocation, raw []byte) ([]byte, error) {
	if service == nil || service.table == nil || !invocation.Owner.valid() || invocation.Plugin.InstanceID != invocation.Owner.PluginInstanceID {
		return marshalControlFailure("INVALID_ARGUMENT", "trusted invocation context is invalid", false), nil
	}
	var request controlRequest
	if err := decodeClosedJSON(raw, &request); err != nil || request.API != 1 || request.Operation == "" || len(request.Arguments) == 0 {
		return marshalControlFailure("INVALID_ARGUMENT", "control request is invalid", false), nil
	}
	result, err := service.dispatch(ctx, invocation, request.Operation, request.Arguments)
	if err != nil {
		code, retryable := stableServiceError(err)
		return marshalControlFailure(code, publicServiceMessage(code), retryable), nil
	}
	return json.Marshal(controlResponse{OK: true, Result: result})
}

func marshalControlFailure(code, message string, retryable bool) []byte {
	raw, _ := json.Marshal(controlResponse{OK: false, Error: &serviceError{Code: code, Message: message, Retryable: retryable, Details: map[string]any{}}})
	return raw
}

func (service *Service) dispatch(ctx context.Context, invocation Invocation, operation string, arguments json.RawMessage) (any, error) {
	switch operation {
	case "fs.mounts":
		return service.listMounts(ctx, invocation)
	case "fs.stat":
		var args struct {
			URI            string `json:"uri"`
			FollowSymlinks bool   `json:"follow_symlinks"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, false)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		return mount.Stat(uri, args.FollowSymlinks)
	case "fs.open":
		var args struct {
			URI     string      `json:"uri"`
			Options OpenOptions `json:"options"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		write := args.Options.Write || args.Options.Create || args.Options.CreateNew || args.Options.Truncate || args.Options.Append
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, write)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		file, err := mount.OpenFile(uri, args.Options)
		if err != nil {
			return nil, err
		}
		handle, err := service.table.Open(invocation.Owner, KindFile, file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		return map[string]any{"handle": uint64(handle)}, nil
	case "fs.mkdir":
		var args struct {
			URI       string      `json:"uri"`
			Recursive bool        `json:"recursive"`
			Mode      fs.FileMode `json:"mode"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, true)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		return map[string]any{"ok": true}, mount.Mkdir(uri, args.Recursive, args.Mode)
	case "fs.remove":
		var args struct {
			URI       string `json:"uri"`
			Recursive bool   `json:"recursive"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, true)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		return map[string]any{"ok": true}, mount.Remove(uri, args.Recursive)
	case "fs.rename", "fs.copy":
		var args struct {
			From      string `json:"from"`
			To        string `json:"to"`
			Overwrite bool   `json:"overwrite"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		from, mount, err := service.resolveMount(ctx, invocation, args.From, true)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		to, err := ParseURI(args.To)
		if err != nil {
			return nil, err
		}
		if operation == "fs.rename" {
			err = mount.Rename(from, to, args.Overwrite)
		} else {
			err = mount.Copy(from, to, args.Overwrite, 0)
		}
		return map[string]any{"ok": true}, err
	case "fs.read_dir.open":
		var args struct {
			URI string `json:"uri"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, false)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		stream, err := mount.OpenDirectory(uri)
		if err != nil {
			return nil, err
		}
		handle, err := service.table.Open(invocation.Owner, KindDirectory, stream)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		return map[string]any{"handle": uint64(handle)}, nil
	case "fs.read_dir.next":
		var args struct {
			Handle uint64 `json:"handle"`
			Limit  int    `json:"limit"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidHandle
		}
		var page DirectoryPage
		err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindDirectory, func(resource io.Closer) error {
			stream, ok := resource.(*DirectoryStream)
			if !ok {
				return ErrInvalidHandle
			}
			var nextErr error
			page, nextErr = stream.Next(args.Limit)
			return nextErr
		})
		if err == nil && page.EOF {
			_ = service.table.Close(HandleID(args.Handle), invocation.Owner)
		}
		return page, err
	case "fs.watch":
		var args struct {
			URI       string `json:"uri"`
			Recursive bool   `json:"recursive"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil || args.Recursive {
			return nil, ErrInvalidOptions
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, false)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		watch, err := mount.OpenWatch(uri)
		if err != nil {
			return nil, err
		}
		handle, err := service.table.Open(invocation.Owner, KindWatch, watch)
		if err != nil {
			_ = watch.Close()
			return nil, err
		}
		return map[string]any{"handle": uint64(handle)}, nil
	case "fs.watch_next":
		var args struct {
			Handle    uint64 `json:"handle"`
			TimeoutMS uint32 `json:"timeout_ms"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil || args.Handle == 0 || args.TimeoutMS == 0 || args.TimeoutMS > 60_000 {
			return nil, ErrInvalidOptions
		}
		var event WatchEvent
		err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindWatch, func(resource io.Closer) error {
			watch, ok := resource.(*WatchStream)
			if !ok {
				return ErrInvalidHandle
			}
			var nextErr error
			event, nextErr = watch.Next(ctx, time.Duration(args.TimeoutMS)*time.Millisecond)
			return nextErr
		})
		return event, err
	case "fs.sync":
		var args struct {
			Handle uint64 `json:"handle"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidHandle
		}
		err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindFile, Sync)
		return map[string]any{"ok": true}, err
	case "fs.set_times":
		var args struct {
			URI            string `json:"uri"`
			AccessedUnixMS int64  `json:"accessed_unix_ms"`
			ModifiedUnixMS int64  `json:"modified_unix_ms"`
		}
		if err := decodeClosedJSON(arguments, &args); err != nil {
			return nil, ErrInvalidURI
		}
		uri, mount, err := service.resolveMount(ctx, invocation, args.URI, true)
		if err != nil {
			return nil, err
		}
		defer mount.Close()
		err = mount.SetTimes(uri, time.UnixMilli(args.AccessedUnixMS), time.UnixMilli(args.ModifiedUnixMS))
		return map[string]any{"ok": true}, err
	case "net.http.begin":
		return service.beginHTTP(ctx, invocation, arguments)
	case "net.http.finish":
		return service.finishHTTP(invocation, arguments)
	case "net.http.abort":
		return service.abortHTTP(invocation, arguments)
	case "net.websocket.open":
		return service.openWebSocket(ctx, invocation, arguments)
	case "net.websocket.ping":
		return service.pingWebSocket(ctx, invocation, arguments)
	case "net.websocket.close":
		return service.closeWebSocket(invocation, arguments)
	case "net.tcp.connect":
		return service.connectTCP(ctx, invocation, arguments)
	case "net.tcp.listen":
		return service.listenTCP(ctx, invocation, arguments)
	case "net.tcp.accept":
		return service.acceptTCP(ctx, invocation, arguments)
	case "net.tcp.shutdown":
		return service.shutdownTCP(invocation, arguments)
	case "net.udp.connect":
		return service.connectUDP(ctx, invocation, arguments)
	default:
		return nil, ErrInvalidHandle
	}
}

func (service *Service) listMounts(ctx context.Context, invocation Invocation) (any, error) {
	if service.mounts == nil || !invocation.CanRead {
		return nil, os.ErrPermission
	}
	mounts, err := service.mounts.ListMounts(ctx, invocation)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(mounts))
	for _, mount := range mounts {
		if !validMountID(mount.ID) || mount.Path == "" {
			return nil, ErrInvalidURI
		}
		if service.allowedMount(invocation, mount.ID, false) {
			result = append(result, map[string]any{"id": mount.ID, "uri": URI{MountID: mount.ID, Path: "."}.String(), "read_only": mount.ReadOnly || !service.allowedMount(invocation, mount.ID, true)})
		}
	}
	return map[string]any{"mounts": result}, nil
}

func (service *Service) resolveMount(ctx context.Context, invocation Invocation, rawURI string, write bool) (URI, Mount, error) {
	uri, err := ParseURI(rawURI)
	if err != nil {
		return URI{}, Mount{}, err
	}
	if service.mounts == nil || !service.allowedMount(invocation, uri.MountID, write) {
		return URI{}, Mount{}, os.ErrPermission
	}
	spec, err := service.mounts.ResolveMount(ctx, invocation, uri.MountID)
	if err != nil {
		return URI{}, Mount{}, err
	}
	if spec.ID != uri.MountID {
		return URI{}, Mount{}, ErrInvalidURI
	}
	mount, err := OpenMount(spec.ID, spec.Path, spec.ReadOnly, invocation.Owner.Scope)
	return uri, mount, err
}

func (service *Service) allowedMount(invocation Invocation, mountID string, write bool) bool {
	if !invocation.CanRead || write && !invocation.CanWrite {
		return false
	}
	readPermission, writePermission := "", ""
	switch mountID {
	case "workspace":
		readPermission, writePermission = PermissionFSWorkspaceRead, PermissionFSWorkspaceWrite
	case "home":
		readPermission, writePermission = PermissionFSHomeRead, PermissionFSHomeWrite
	case "environment":
		readPermission, writePermission = PermissionFSEnvironmentRead, PermissionFSEnvironmentWrite
	default:
		return false
	}
	if write {
		return invocation.Permissions[writePermission]
	}
	return invocation.Permissions[readPermission] || invocation.Permissions[writePermission]
}

func (service *Service) authorizeNetwork(ctx context.Context, invocation Invocation, operation, rawURL string, listen bool) error {
	permission := PermissionNetworkClient
	if listen {
		permission = PermissionNetworkListen
	}
	if !invocation.Permissions[permission] {
		return os.ErrPermission
	}
	if service.network == nil {
		return nil
	}
	var destination *url.URL
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		destination = parsed
	}
	return service.network.AuthorizeNetwork(ctx, NetworkAuthorization{Invocation: invocation, Operation: operation, Destination: destination, Listen: listen})
}

func (service *Service) beginHTTP(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Method    string       `json:"method"`
		URL       string       `json:"url"`
		Headers   []Header     `json:"headers"`
		Redirect  RedirectMode `json:"redirect"`
		TimeoutMS uint32       `json:"timeout_ms"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	authorize := func(ctx context.Context, target *url.URL) error {
		return service.authorizeNetwork(ctx, invocation, "net.http.begin", target.String(), false)
	}
	upload, err := BeginHTTP(ctx, HTTPRequest{Method: args.Method, URL: args.URL, Headers: args.Headers, Redirect: args.Redirect, Timeout: time.Duration(args.TimeoutMS) * time.Millisecond, Authorize: authorize})
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindHTTPUpload, upload)
	if err != nil {
		_ = upload.Close()
		return nil, err
	}
	return map[string]any{"upload_handle": uint64(handle)}, nil
}

func (service *Service) finishHTTP(invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle uint64 `json:"handle"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	var response *HTTPResponse
	err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindHTTPUpload, func(resource io.Closer) error {
		upload, ok := resource.(*HTTPUpload)
		if !ok {
			return ErrInvalidHandle
		}
		var finishErr error
		response, finishErr = upload.Finish()
		return finishErr
	})
	_ = service.table.Close(HandleID(args.Handle), invocation.Owner)
	if err != nil {
		return nil, err
	}
	bodyHandle, err := service.table.Open(invocation.Owner, KindHTTPBody, response.Body)
	if err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	return map[string]any{"status": response.Status, "headers": response.Headers, "final_url": response.FinalURL, "body_handle": uint64(bodyHandle)}, nil
}

func (service *Service) abortHTTP(invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle uint64 `json:"handle"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	return map[string]any{"ok": true}, service.table.Close(HandleID(args.Handle), invocation.Owner)
}

func (service *Service) openWebSocket(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		URL          string   `json:"url"`
		Headers      []Header `json:"headers"`
		Subprotocols []string `json:"subprotocols"`
		TimeoutMS    uint32   `json:"timeout_ms"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	authorize := func(ctx context.Context, target *url.URL) error {
		return service.authorizeNetwork(ctx, invocation, "net.websocket.open", target.String(), false)
	}
	opened, err := OpenWebSocket(ctx, WebSocketOpen{URL: args.URL, Headers: args.Headers, Subprotocols: args.Subprotocols, Timeout: time.Duration(args.TimeoutMS) * time.Millisecond, Authorize: authorize})
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindWebSocket, opened.Resource)
	if err != nil {
		_ = opened.Resource.Close()
		return nil, err
	}
	return map[string]any{"handle": uint64(handle), "protocol": opened.Protocol, "response_headers": opened.ResponseHeaders}, nil
}

func (service *Service) pingWebSocket(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle uint64 `json:"handle"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	err := service.table.UseControl(HandleID(args.Handle), invocation.Owner, KindWebSocket, func(resource io.Closer) error {
		websocket, ok := resource.(*WebSocketResource)
		if !ok {
			return ErrInvalidHandle
		}
		return websocket.Ping(ctx)
	})
	return map[string]any{"ok": true}, err
}

func (service *Service) closeWebSocket(invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle uint64 `json:"handle"`
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	err := service.table.UseControl(HandleID(args.Handle), invocation.Owner, KindWebSocket, func(resource io.Closer) error {
		websocketResource, ok := resource.(*WebSocketResource)
		if !ok {
			return ErrInvalidHandle
		}
		return websocketResource.GracefulClose(websocket.StatusCode(args.Code), args.Reason)
	})
	closeErr := service.table.Close(HandleID(args.Handle), invocation.Owner)
	return map[string]any{"ok": true}, errors.Join(err, closeErr)
}

func (service *Service) connectTCP(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Host        string `json:"host"`
		Port        uint16 `json:"port"`
		TimeoutMS   uint32 `json:"timeout_ms"`
		NoDelay     bool   `json:"no_delay"`
		KeepAliveMS uint32 `json:"keep_alive_ms"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil || args.Host == "" || args.Port == 0 {
		return nil, ErrInvalidHandle
	}
	address := fmt.Sprintf("%s:%d", args.Host, args.Port)
	if err := service.authorizeNetwork(ctx, invocation, "net.tcp.connect", "tcp://"+address, false); err != nil {
		return nil, err
	}
	stream, err := OpenTCP(ctx, TCPConnectOptions{Address: address, Timeout: time.Duration(args.TimeoutMS) * time.Millisecond, NoDelay: args.NoDelay, KeepAlive: time.Duration(args.KeepAliveMS) * time.Millisecond})
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindTCP, stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return map[string]any{"handle": uint64(handle)}, nil
}

func (service *Service) listenTCP(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil || args.Host == "" {
		return nil, ErrInvalidHandle
	}
	address := fmt.Sprintf("%s:%d", args.Host, args.Port)
	if err := service.authorizeNetwork(ctx, invocation, "net.tcp.listen", "tcp://"+address, true); err != nil {
		return nil, err
	}
	listener, err := ListenTCP(ctx, address)
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindTCPListener, listener)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return map[string]any{"handle": uint64(handle), "address": listener.Address()}, nil
}

func (service *Service) acceptTCP(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle      uint64 `json:"handle"`
		NoDelay     bool   `json:"no_delay"`
		KeepAliveMS uint32 `json:"keep_alive_ms"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	var stream *TCPStream
	err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindTCPListener, func(resource io.Closer) error {
		listener, ok := resource.(*TCPListener)
		if !ok {
			return ErrInvalidHandle
		}
		var acceptErr error
		stream, acceptErr = listener.Accept(ctx, args.NoDelay, time.Duration(args.KeepAliveMS)*time.Millisecond)
		return acceptErr
	})
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindTCP, stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return map[string]any{"handle": uint64(handle)}, nil
}

func (service *Service) shutdownTCP(invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Handle    uint64      `json:"handle"`
		Direction TCPShutdown `json:"direction"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil {
		return nil, ErrInvalidHandle
	}
	err := service.table.Use(HandleID(args.Handle), invocation.Owner, KindTCP, func(resource io.Closer) error {
		stream, ok := resource.(*TCPStream)
		if !ok {
			return ErrInvalidHandle
		}
		return stream.Shutdown(args.Direction)
	})
	return map[string]any{"ok": true}, err
}

func (service *Service) connectUDP(ctx context.Context, invocation Invocation, arguments json.RawMessage) (any, error) {
	var args struct {
		Host      string `json:"host"`
		Port      uint16 `json:"port"`
		TimeoutMS uint32 `json:"timeout_ms"`
	}
	if err := decodeClosedJSON(arguments, &args); err != nil || args.Host == "" || args.Port == 0 {
		return nil, ErrInvalidHandle
	}
	address := fmt.Sprintf("%s:%d", args.Host, args.Port)
	if err := service.authorizeNetwork(ctx, invocation, "net.udp.connect", "udp://"+address, false); err != nil {
		return nil, err
	}
	resource, err := OpenUDP(ctx, address, time.Duration(args.TimeoutMS)*time.Millisecond)
	if err != nil {
		return nil, err
	}
	handle, err := service.table.Open(invocation.Owner, KindUDP, resource)
	if err != nil {
		_ = resource.Close()
		return nil, err
	}
	return map[string]any{"handle": uint64(handle)}, nil
}

func (service *Service) Read(ctx context.Context, invocation Invocation, handle uint64, destination []byte) (int, uint32, error) {
	return service.table.ReadChunk(ctx, HandleID(handle), invocation.Owner, destination)
}

func (service *Service) Write(ctx context.Context, invocation Invocation, handle uint64, source []byte, flags uint32) (int, error) {
	return service.table.WriteChunk(ctx, HandleID(handle), invocation.Owner, source, flags)
}

func (service *Service) Seek(invocation Invocation, handle uint64, offset int64, whence int) (int64, error) {
	return service.table.Seek(HandleID(handle), invocation.Owner, offset, whence)
}

func (service *Service) Close(invocation Invocation, handle uint64) error {
	return service.table.Close(HandleID(handle), invocation.Owner)
}

func (service *Service) Revoke(predicate func(Owner) bool) error {
	return service.table.Revoke(predicate)
}

func decodeClosedJSON(raw []byte, target any) error {
	if err := validateJSONFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing data")
	}
	return nil
}

func validateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("JSON has trailing data")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON field")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func stableServiceError(err error) (string, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return "CANCELED", false
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT", true
	case errors.Is(err, os.ErrPermission):
		return "PERMISSION_DENIED", false
	case errors.Is(err, fs.ErrNotExist):
		return "NOT_FOUND", false
	case errors.Is(err, syscall.ENOTEMPTY):
		return "NOT_EMPTY", false
	case errors.Is(err, fs.ErrExist):
		return "ALREADY_EXISTS", false
	case errors.Is(err, ErrResourceClosed), errors.Is(err, ErrOwnerMismatch), errors.Is(err, net.ErrClosed):
		return "RESOURCE_CLOSED", false
	case errors.Is(err, ErrResourceLimit):
		return "RESOURCE_LIMIT", false
	case errors.Is(err, ErrCrossDevice):
		return "CROSS_DEVICE", false
	case errors.Is(err, ErrUnsafeFile):
		return "PERMISSION_DENIED", false
	case errors.Is(err, ErrRedirectRequiresReplay):
		return "REDIRECT_REQUIRES_REPLAY", false
	case errors.Is(err, ErrWatchUnsupported):
		return "RUNTIME_UNAVAILABLE", false
	case errors.Is(err, ErrInvalidHandle), errors.Is(err, ErrInvalidURI), errors.Is(err, ErrInvalidOptions):
		return "INVALID_ARGUMENT", false
	case isNetworkError(err):
		return "NETWORK_ERROR", false
	default:
		return "IO_ERROR", false
	}
}

// StableError projects broker failures onto the closed Worker API error set.
func StableError(err error) (string, bool) {
	return stableServiceError(err)
}

func isNetworkError(err error) bool {
	var networkError net.Error
	var dnsError *net.DNSError
	return errors.As(err, &networkError) || errors.As(err, &dnsError)
}

func publicServiceMessage(code string) string {
	return strings.ToLower(strings.ReplaceAll(code, "_", " "))
}
