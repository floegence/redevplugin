package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

var errRuntimeIOInvocationUnknown = errors.New("runtime I/O invocation is unknown")
var errRuntimeIOStorageDenied = errors.New("runtime storage access is denied")
var errRuntimeIOInvalidRequest = errors.New("runtime I/O request is invalid")

type hostRuntimeIORegistration struct {
	resource resourceio.Invocation
	storage  map[string]hostRuntimeIOStorageAccess
}

type hostRuntimeIOStorageAccess struct {
	kind       string
	scope      sessionctx.ResourceScope
	operations map[string]struct{}
}

type hostRuntimeIOBroker struct {
	mu            sync.RWMutex
	service       *resourceio.Service
	storageFiles  storage.FilesBroker
	storageKV     storage.KVBroker
	storageSQLite storage.SQLiteBroker
	invocations   map[string]hostRuntimeIORegistration
}

func newHostRuntimeIOBroker(adapters normalizedAdapters) (*hostRuntimeIOBroker, error) {
	table, err := resourceio.NewTableWithLimits(resourceio.DefaultLimits())
	if err != nil {
		return nil, err
	}
	var mounts resourceio.MountResolver
	if adapters.FileSystem != nil {
		mounts = hostMountResolver{adapter: adapters.FileSystem}
	}
	var network resourceio.NetworkAuthorizer
	if adapters.NetworkPolicy != nil {
		network = hostNetworkAuthorizer{adapter: adapters.NetworkPolicy}
	}
	service, err := resourceio.NewService(table, mounts, network)
	if err != nil {
		return nil, err
	}
	return &hostRuntimeIOBroker{
		service:       service,
		storageFiles:  adapters.PluginData,
		storageKV:     adapters.PluginData,
		storageSQLite: adapters.PluginData,
		invocations:   map[string]hostRuntimeIORegistration{},
	}, nil
}

func newHostRuntimeIORegistration(invocation resourceio.Invocation, access workerBrokerAccess, grants map[string]string) (hostRuntimeIORegistration, error) {
	if invocation.Owner.InvocationID == "" || invocation.Owner.PluginInstanceID == "" || invocation.Owner.ActiveFingerprint == "" ||
		invocation.Plugin.InstanceID != invocation.Owner.PluginInstanceID || !invocation.Owner.Scope.Valid() || !invocation.Owner.Session.Valid() {
		return hostRuntimeIORegistration{}, errRuntimeIOInvocationUnknown
	}
	registration := hostRuntimeIORegistration{
		resource: invocation,
		storage:  make(map[string]hostRuntimeIOStorageAccess, len(access.Storage)),
	}
	for _, declared := range access.Storage {
		storeID := strings.TrimSpace(declared.StoreID)
		kind := strings.TrimSpace(declared.Kind)
		if storeID == "" || strings.TrimSpace(grants[storeID]) == "" || !validRuntimeStorageKind(kind) {
			return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
		}
		if _, duplicate := registration.storage[storeID]; duplicate {
			return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
		}
		scope := sessionctx.ResourceScope{
			Kind:         sessionctx.ScopeKind(strings.TrimSpace(declared.Scope)),
			OwnerEnvHash: invocation.Owner.Session.OwnerEnvHash,
		}
		if scope.Kind == sessionctx.ScopeUser {
			scope.OwnerUserHash = invocation.Owner.Session.OwnerUserHash
		}
		if err := scope.Validate(); err != nil {
			return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
		}
		operations := make(map[string]struct{}, len(declared.Operations))
		for _, operation := range declared.Operations {
			operation = strings.TrimSpace(operation)
			if !validRuntimeStorageOperation(kind, operation) {
				return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
			}
			if _, duplicate := operations[operation]; duplicate {
				return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
			}
			operations[operation] = struct{}{}
		}
		if len(operations) == 0 {
			return hostRuntimeIORegistration{}, errRuntimeIOStorageDenied
		}
		registration.storage[storeID] = hostRuntimeIOStorageAccess{kind: kind, scope: scope, operations: operations}
	}
	return registration, nil
}

func validRuntimeStorageKind(kind string) bool {
	return kind == "files" || kind == "kv" || kind == "sqlite"
}

func validRuntimeStorageOperation(kind, operation string) bool {
	switch kind {
	case "files":
		return operation == "read" || operation == "write" || operation == "delete" || operation == "list"
	case "kv":
		return operation == "get" || operation == "put" || operation == "delete" || operation == "list"
	case "sqlite":
		return operation == "query" || operation == "exec"
	default:
		return false
	}
}

func (broker *hostRuntimeIOBroker) register(invocationID string, invocation hostRuntimeIORegistration) error {
	invocationID = strings.TrimSpace(invocationID)
	if broker == nil || broker.service == nil || invocationID == "" || invocation.resource.Owner.InvocationID != invocationID {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if _, exists := broker.invocations[invocationID]; exists {
		return errRuntimeIOInvocationUnknown
	}
	broker.invocations[invocationID] = invocation
	return nil
}

func (broker *hostRuntimeIOBroker) release(invocationID string) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	invocation, exists := broker.invocations[invocationID]
	delete(broker.invocations, invocationID)
	if !exists {
		return nil
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool {
		return owner.Lifetime == resourceio.LifetimeInvocation && owner.InvocationID == invocation.resource.Owner.InvocationID
	})
}

func (broker *hostRuntimeIOBroker) invocationLocked(invocationID string) (hostRuntimeIORegistration, error) {
	if broker == nil || broker.service == nil || strings.TrimSpace(invocationID) == "" {
		return hostRuntimeIORegistration{}, errRuntimeIOInvocationUnknown
	}
	invocation, ok := broker.invocations[invocationID]
	if !ok {
		return hostRuntimeIORegistration{}, errRuntimeIOInvocationUnknown
	}
	return invocation, nil
}

func (broker *hostRuntimeIOBroker) Control(ctx context.Context, invocationID string, raw []byte) ([]byte, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return nil, err
	}
	request, err := decodeRuntimeIOControlRequest(raw)
	if err != nil {
		return runtimeIOControlFailure("INVALID_ARGUMENT", false), nil
	}
	switch request.Operation {
	case "storage.files", "storage.kv", "storage.sqlite":
		result, dispatchErr := broker.dispatchStorage(ctx, invocation, request)
		if dispatchErr != nil {
			code, retryable := runtimeIOStorageError(dispatchErr)
			return runtimeIOControlFailure(code, retryable), nil
		}
		return runtimeIOControlSuccess(result), nil
	default:
		return broker.service.Control(ctx, invocation.resource, raw)
	}
}

type runtimeIOControlRequest struct {
	PluginAPI uint16          `json:"plugin_api"`
	Operation string          `json:"operation"`
	Arguments json.RawMessage `json:"arguments"`
}

type runtimeIOControlResponse struct {
	OK     bool                   `json:"ok"`
	Result any                    `json:"result,omitempty"`
	Error  *runtimeIOControlError `json:"error,omitempty"`
}

type runtimeIOControlError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details"`
}

func decodeRuntimeIOControlRequest(raw []byte) (runtimeIOControlRequest, error) {
	if err := validateRuntimeIOJSON(raw); err != nil {
		return runtimeIOControlRequest{}, err
	}
	var request runtimeIOControlRequest
	if err := decodeRuntimeIOJSON(raw, &request); err != nil || request.PluginAPI != resourceio.PluginAPI || strings.TrimSpace(request.Operation) == "" || len(request.Arguments) == 0 {
		return runtimeIOControlRequest{}, errRuntimeIOStorageDenied
	}
	return request, nil
}

func runtimeIOControlSuccess(result any) []byte {
	raw, _ := json.Marshal(runtimeIOControlResponse{OK: true, Result: result})
	return raw
}

func runtimeIOControlFailure(code string, retryable bool) []byte {
	raw, _ := json.Marshal(runtimeIOControlResponse{OK: false, Error: &runtimeIOControlError{
		Code: code, Message: strings.ToLower(strings.ReplaceAll(code, "_", " ")), Retryable: retryable, Details: map[string]any{},
	}})
	return raw
}

func runtimeIOStorageError(err error) (string, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return "CANCELED", false
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT", true
	case errors.Is(err, errRuntimeIOStorageDenied):
		return "PERMISSION_DENIED", false
	case errors.Is(err, errRuntimeIOInvalidRequest):
		return "INVALID_ARGUMENT", false
	case errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrInvalidFilePath), errors.Is(err, storage.ErrInvalidKVKey), errors.Is(err, storage.ErrInvalidSQLite):
		return "INVALID_ARGUMENT", false
	case errors.Is(err, storage.ErrNamespaceNotFound), errors.Is(err, storage.ErrFileNotFound), errors.Is(err, storage.ErrKVKeyNotFound):
		return "NOT_FOUND", false
	case errors.Is(err, storage.ErrQuotaExceeded), errors.Is(err, storage.ErrFileTooLarge), errors.Is(err, storage.ErrKVValueTooLarge), errors.Is(err, storage.ErrSQLiteResultTooLarge):
		return "RESOURCE_LIMIT", false
	default:
		return "IO_ERROR", false
	}
}

func (broker *hostRuntimeIOBroker) dispatchStorage(ctx context.Context, invocation hostRuntimeIORegistration, request runtimeIOControlRequest) (any, error) {
	var selector struct {
		Operation string `json:"operation"`
		StoreID   string `json:"store_id"`
	}
	if err := json.Unmarshal(request.Arguments, &selector); err != nil {
		return nil, errRuntimeIOStorageDenied
	}
	kind := strings.TrimPrefix(request.Operation, "storage.")
	access, ok := invocation.storage[strings.TrimSpace(selector.StoreID)]
	if !ok || access.kind != kind {
		return nil, errRuntimeIOStorageDenied
	}
	if _, ok := access.operations[strings.TrimSpace(selector.Operation)]; !ok {
		return nil, errRuntimeIOStorageDenied
	}
	if runtimeStorageOperationWrites(kind, selector.Operation) {
		if !invocation.resource.CanWrite {
			return nil, errRuntimeIOStorageDenied
		}
	} else if !invocation.resource.CanRead {
		return nil, errRuntimeIOStorageDenied
	}
	switch kind {
	case "files":
		return broker.dispatchStorageFiles(ctx, invocation.resource.Owner.PluginInstanceID, access.scope, selector.Operation, request.Arguments)
	case "kv":
		return broker.dispatchStorageKV(ctx, invocation.resource.Owner.PluginInstanceID, access.scope, selector.Operation, request.Arguments)
	case "sqlite":
		return broker.dispatchStorageSQLite(ctx, invocation.resource.Owner.PluginInstanceID, access.scope, selector.Operation, request.Arguments)
	default:
		return nil, errRuntimeIOStorageDenied
	}
}

func runtimeStorageOperationWrites(kind, operation string) bool {
	return !(kind == "files" && (operation == "read" || operation == "list") ||
		kind == "kv" && (operation == "get" || operation == "list") ||
		kind == "sqlite" && operation == "query")
}

func (broker *hostRuntimeIOBroker) dispatchStorageFiles(ctx context.Context, pluginInstanceID string, scope sessionctx.ResourceScope, operation string, raw []byte) (any, error) {
	if broker.storageFiles == nil {
		return nil, errRuntimeIOStorageDenied
	}
	switch operation {
	case "read":
		var args struct {
			Operation string  `json:"operation"`
			StoreID   string  `json:"store_id"`
			Path      string  `json:"path"`
			MaxBytes  *uint64 `json:"max_bytes"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		maxBytes, err := runtimeUint64ToInt64(args.MaxBytes)
		if err != nil {
			return nil, err
		}
		result, err := broker.storageFiles.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Path: args.Path, MaxBytes: maxBytes})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "path": result.Path, "data_base64": base64.StdEncoding.EncodeToString(result.Data), "size_bytes": result.SizeBytes, "usage": result.Usage}, nil
	case "write":
		var args struct {
			Operation  string `json:"operation"`
			StoreID    string `json:"store_id"`
			Path       string `json:"path"`
			DataBase64 string `json:"data_base64"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.Strict().DecodeString(args.DataBase64)
		if err != nil {
			return nil, storage.ErrInvalidFilePath
		}
		result, err := broker.storageFiles.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Path: args.Path, Data: data})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "path": result.Path, "size_bytes": result.SizeBytes, "usage": result.Usage}, nil
	case "delete":
		var args struct {
			Operation string `json:"operation"`
			StoreID   string `json:"store_id"`
			Path      string `json:"path"`
			Recursive bool   `json:"recursive"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		if err := broker.storageFiles.DeleteFile(ctx, storage.FileDeleteRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Path: args.Path, Recursive: args.Recursive}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "path": args.Path}, nil
	case "list":
		var args struct {
			Operation  string  `json:"operation"`
			StoreID    string  `json:"store_id"`
			Path       string  `json:"path"`
			MaxEntries *uint32 `json:"max_entries"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		result, err := broker.storageFiles.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Path: args.Path, MaxEntries: runtimeUint32ToInt(args.MaxEntries)})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "path": result.Path, "entries": result.Entries, "usage": result.Usage}, nil
	default:
		return nil, errRuntimeIOStorageDenied
	}
}

func (broker *hostRuntimeIOBroker) dispatchStorageKV(ctx context.Context, pluginInstanceID string, scope sessionctx.ResourceScope, operation string, raw []byte) (any, error) {
	if broker.storageKV == nil {
		return nil, errRuntimeIOStorageDenied
	}
	switch operation {
	case "get":
		var args struct {
			Operation string  `json:"operation"`
			StoreID   string  `json:"store_id"`
			Key       string  `json:"key"`
			MaxBytes  *uint64 `json:"max_bytes"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		maxBytes, err := runtimeUint64ToInt64(args.MaxBytes)
		if err != nil {
			return nil, err
		}
		result, err := broker.storageKV.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Key: args.Key, MaxBytes: maxBytes})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "key": result.Key, "value_base64": base64.StdEncoding.EncodeToString(result.Value), "size_bytes": result.SizeBytes, "usage": result.Usage}, nil
	case "put":
		var args struct {
			Operation   string `json:"operation"`
			StoreID     string `json:"store_id"`
			Key         string `json:"key"`
			ValueBase64 string `json:"value_base64"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		value, err := base64.StdEncoding.Strict().DecodeString(args.ValueBase64)
		if err != nil {
			return nil, storage.ErrInvalidKVKey
		}
		result, err := broker.storageKV.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Key: args.Key, Value: value})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "key": result.Key, "size_bytes": result.SizeBytes, "usage": result.Usage}, nil
	case "delete":
		var args struct {
			Operation string `json:"operation"`
			StoreID   string `json:"store_id"`
			Key       string `json:"key"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		if err := broker.storageKV.DeleteKV(ctx, storage.KVDeleteRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Key: args.Key}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "key": args.Key}, nil
	case "list":
		var args struct {
			Operation  string  `json:"operation"`
			StoreID    string  `json:"store_id"`
			Prefix     string  `json:"prefix"`
			MaxEntries *uint32 `json:"max_entries"`
		}
		if err := decodeRuntimeIOJSON(raw, &args); err != nil {
			return nil, err
		}
		result, err := broker.storageKV.ListKV(ctx, storage.KVListRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Prefix: args.Prefix, MaxEntries: runtimeUint32ToInt(args.MaxEntries)})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "prefix": result.Prefix, "entries": result.Entries, "usage": result.Usage}, nil
	default:
		return nil, errRuntimeIOStorageDenied
	}
}

type runtimeIOSQLiteValue struct {
	Null       bool     `json:"null,omitempty"`
	Int        *int64   `json:"int,omitempty"`
	Float      *float64 `json:"float,omitempty"`
	Text       *string  `json:"text,omitempty"`
	BlobBase64 *string  `json:"blob_base64,omitempty"`
}

func (value runtimeIOSQLiteValue) storageValue() (storage.SQLiteValue, error) {
	variants := 0
	if value.Null {
		variants++
	}
	if value.Int != nil {
		variants++
	}
	if value.Float != nil {
		variants++
	}
	if value.Text != nil {
		variants++
	}
	if value.BlobBase64 != nil {
		variants++
	}
	if variants != 1 {
		return storage.SQLiteValue{}, storage.ErrInvalidSQLite
	}
	result := storage.SQLiteValue{Null: value.Null, Int: value.Int, Float: value.Float, Text: value.Text}
	if value.BlobBase64 != nil {
		blob, err := base64.StdEncoding.Strict().DecodeString(*value.BlobBase64)
		if err != nil {
			return storage.SQLiteValue{}, storage.ErrInvalidSQLite
		}
		result.Blob = blob
	}
	return result, nil
}

func runtimeIOSQLiteValueFromStorage(value storage.SQLiteValue) runtimeIOSQLiteValue {
	result := runtimeIOSQLiteValue{Null: value.Null, Int: value.Int, Float: value.Float, Text: value.Text}
	if value.Blob != nil {
		encoded := base64.StdEncoding.EncodeToString(value.Blob)
		result.BlobBase64 = &encoded
	}
	return result
}

func runtimeIOSQLiteValues(values []runtimeIOSQLiteValue) ([]storage.SQLiteValue, error) {
	result := make([]storage.SQLiteValue, len(values))
	for index, value := range values {
		converted, err := value.storageValue()
		if err != nil {
			return nil, err
		}
		result[index] = converted
	}
	return result, nil
}

func (broker *hostRuntimeIOBroker) dispatchStorageSQLite(ctx context.Context, pluginInstanceID string, scope sessionctx.ResourceScope, operation string, raw []byte) (any, error) {
	if broker.storageSQLite == nil {
		return nil, errRuntimeIOStorageDenied
	}
	type sqliteArguments struct {
		Operation        string                 `json:"operation"`
		StoreID          string                 `json:"store_id"`
		Database         string                 `json:"database"`
		SQL              string                 `json:"sql"`
		Args             []runtimeIOSQLiteValue `json:"args"`
		MaxRows          *uint32                `json:"max_rows,omitempty"`
		MaxResponseBytes *uint64                `json:"max_response_bytes,omitempty"`
		TimeoutMS        *uint64                `json:"timeout_ms,omitempty"`
	}
	var args sqliteArguments
	if err := decodeRuntimeIOJSON(raw, &args); err != nil {
		return nil, err
	}
	values, err := runtimeIOSQLiteValues(args.Args)
	if err != nil {
		return nil, err
	}
	timeout, err := runtimeMilliseconds(args.TimeoutMS)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "exec":
		if args.MaxRows != nil || args.MaxResponseBytes != nil {
			return nil, storage.ErrInvalidSQLite
		}
		result, err := broker.storageSQLite.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Database: args.Database, SQL: args.SQL, Args: values, Timeout: timeout})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "database": result.Database, "rows_affected": result.RowsAffected, "last_insert_id": result.LastInsertID, "usage": result.Usage}, nil
	case "query":
		maxResponseBytes, err := runtimeUint64ToInt64(args.MaxResponseBytes)
		if err != nil {
			return nil, err
		}
		result, err := broker.storageSQLite.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: pluginInstanceID, ResourceScope: scope, StoreID: args.StoreID, Database: args.Database, SQL: args.SQL, Args: values, MaxRows: runtimeUint32ToInt(args.MaxRows), MaxResponseBytes: maxResponseBytes, Timeout: timeout})
		if err != nil {
			return nil, err
		}
		rows := make([][]runtimeIOSQLiteValue, len(result.Rows))
		for rowIndex, row := range result.Rows {
			rows[rowIndex] = make([]runtimeIOSQLiteValue, len(row))
			for columnIndex, value := range row {
				rows[rowIndex][columnIndex] = runtimeIOSQLiteValueFromStorage(value)
			}
		}
		return map[string]any{"ok": true, "database": result.Database, "columns": result.Columns, "rows": rows, "usage": result.Usage}, nil
	default:
		return nil, errRuntimeIOStorageDenied
	}
}

func runtimeUint64ToInt64(value *uint64) (int64, error) {
	if value == nil {
		return 0, nil
	}
	if *value > math.MaxInt64 {
		return 0, errRuntimeIOInvalidRequest
	}
	return int64(*value), nil
}

func runtimeUint32ToInt(value *uint32) int {
	if value == nil {
		return 0
	}
	return int(*value)
}

func runtimeMilliseconds(value *uint64) (time.Duration, error) {
	if value == nil {
		return 0, nil
	}
	if *value > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return 0, errRuntimeIOInvalidRequest
	}
	return time.Duration(*value) * time.Millisecond, nil
}

func decodeRuntimeIOJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.Join(errRuntimeIOInvalidRequest, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errRuntimeIOInvalidRequest
	}
	return nil
}

func validateRuntimeIOJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanRuntimeIOJSONValue(decoder, 0); err != nil {
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

func scanRuntimeIOJSONValue(decoder *json.Decoder, depth int) error {
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
			if err := scanRuntimeIOJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON field")
			}
			seen[key] = struct{}{}
			if err := scanRuntimeIOJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func (broker *hostRuntimeIOBroker) Read(ctx context.Context, invocationID string, handle uint64, destination []byte) (int, uint32, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, 0, err
	}
	return broker.service.Read(ctx, invocation.resource, handle, destination)
}

func (broker *hostRuntimeIOBroker) Write(ctx context.Context, invocationID string, handle uint64, source []byte, flags uint32) (int, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, err
	}
	return broker.service.Write(ctx, invocation.resource, handle, source, flags)
}

func (broker *hostRuntimeIOBroker) Seek(_ context.Context, invocationID string, handle uint64, offset int64, whence int) (int64, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, err
	}
	return broker.service.Seek(invocation.resource, handle, offset, whence)
}

func (broker *hostRuntimeIOBroker) Close(_ context.Context, invocationID string, handle uint64) error {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return err
	}
	return broker.service.Close(invocation.resource, handle)
}

func (broker *hostRuntimeIOBroker) closeAll() error {
	if broker == nil || broker.service == nil {
		return nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	clear(broker.invocations)
	return broker.service.Revoke(func(resourceio.Owner) bool { return true })
}

func (broker *hostRuntimeIOBroker) revokePlugin(ownerEnvHash, pluginInstanceID string) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	ownerEnvHash = strings.TrimSpace(ownerEnvHash)
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if ownerEnvHash == "" || pluginInstanceID == "" {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	for invocationID, invocation := range broker.invocations {
		if invocation.resource.Owner.PluginInstanceID == pluginInstanceID && invocation.resource.Owner.Scope.OwnerEnvHash == ownerEnvHash {
			delete(broker.invocations, invocationID)
		}
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool {
		return owner.PluginInstanceID == pluginInstanceID && owner.Scope.OwnerEnvHash == ownerEnvHash
	})
}

func (broker *hostRuntimeIOBroker) revokeSession(scope sessionctx.SessionScope) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	if !scope.Valid() {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	for invocationID, invocation := range broker.invocations {
		if invocation.resource.Owner.Session.Matches(scope) {
			delete(broker.invocations, invocationID)
		}
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool { return owner.Session.Matches(scope) })
}

type hostMountResolver struct {
	adapter FileSystemAdapter
}

func (resolver hostMountResolver) ResolveMount(ctx context.Context, invocation resourceio.Invocation, mountID string) (resourceio.MountSpec, error) {
	mount, err := resolver.adapter.ResolveMount(ctx, MountRequest{
		Session: resourceInvocationSession(invocation),
		Plugin:  resourceInvocationPlugin(invocation),
		MountID: mountID,
	})
	if err != nil {
		return resourceio.MountSpec{}, mapMountAdapterError(err)
	}
	return resourceio.MountSpec{ID: mount.ID, Path: mount.Path, ReadOnly: mount.ReadOnly}, nil
}

func (resolver hostMountResolver) ListMounts(ctx context.Context, invocation resourceio.Invocation) ([]resourceio.MountSpec, error) {
	mounts, err := resolver.adapter.ListMounts(ctx, MountListRequest{
		Session: resourceInvocationSession(invocation),
		Plugin:  resourceInvocationPlugin(invocation),
	})
	if err != nil {
		return nil, mapMountAdapterError(err)
	}
	result := make([]resourceio.MountSpec, len(mounts))
	for index, mount := range mounts {
		result[index] = resourceio.MountSpec{ID: mount.ID, Path: mount.Path, ReadOnly: mount.ReadOnly}
	}
	return result, nil
}

func mapMountAdapterError(err error) error {
	if errors.Is(err, ErrMountUnavailable) {
		return resourceio.ErrMountUnavailable
	}
	return err
}

type hostNetworkAuthorizer struct {
	adapter NetworkPolicyAdapter
}

func (authorizer hostNetworkAuthorizer) AuthorizeNetwork(ctx context.Context, request resourceio.NetworkAuthorization) error {
	return authorizer.adapter.AuthorizeNetwork(ctx, NetworkAuthorizationRequest{
		Session:     resourceInvocationSession(request.Invocation),
		Plugin:      resourceInvocationPlugin(request.Invocation),
		Operation:   request.Operation,
		Destination: publicNetworkDestination(request.Destination),
		Listen:      request.Listen,
	})
}

func resourceInvocationSession(invocation resourceio.Invocation) sessionctx.Context {
	return sessionctx.Context{
		OwnerSessionHash:     invocation.Owner.Session.OwnerSessionHash,
		OwnerUserHash:        invocation.Owner.Session.OwnerUserHash,
		OwnerEnvHash:         invocation.Owner.Session.OwnerEnvHash,
		SessionChannelIDHash: invocation.Owner.Session.SessionChannelIDHash,
		CanRead:              invocation.CanRead,
		CanWrite:             invocation.CanWrite,
	}
}

func resourceInvocationPlugin(invocation resourceio.Invocation) PluginRef {
	return PluginRef{
		PluginID:          invocation.Plugin.ID,
		PluginInstanceID:  invocation.Plugin.InstanceID,
		Version:           invocation.Plugin.Version,
		ActiveFingerprint: invocation.Owner.ActiveFingerprint,
	}
}

func publicNetworkDestination(destination *url.URL) NetworkDestination {
	if destination == nil {
		return NetworkDestination{}
	}
	port := 0
	if rawPort := destination.Port(); rawPort != "" {
		port, _ = strconv.Atoi(rawPort)
	} else {
		switch destination.Scheme {
		case "http", "ws":
			port = 80
		case "https", "wss":
			port = 443
		}
	}
	transport := destination.Scheme
	switch destination.Scheme {
	case "http", "https":
		transport = "http"
	case "ws", "wss":
		transport = "websocket"
	}
	return NetworkDestination{
		Transport: transport,
		Scheme:    destination.Scheme,
		Host:      destination.Hostname(),
		Port:      port,
		URL:       destination.String(),
	}
}
