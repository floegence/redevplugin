package storage

import (
	"context"
	"errors"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type StoreKind string

const (
	StoreKV     StoreKind = "kv"
	StoreFiles  StoreKind = "files"
	StoreSQLite StoreKind = "sqlite"
)

var (
	ErrInvalidNamespace     = errors.New("storage namespace is invalid")
	ErrInvalidFilePath      = errors.New("storage file path is invalid")
	ErrInvalidKVKey         = errors.New("storage kv key is invalid")
	ErrInvalidSQLite        = errors.New("storage sqlite request is invalid")
	ErrNamespaceNotFound    = errors.New("storage namespace not found")
	ErrQuotaExceeded        = errors.New("storage quota exceeded")
	ErrFileNotFound         = errors.New("storage file not found")
	ErrFileTooLarge         = errors.New("storage file too large")
	ErrKVKeyNotFound        = errors.New("storage kv key not found")
	ErrKVValueTooLarge      = errors.New("storage kv value too large")
	ErrSQLiteResultTooLarge = errors.New("storage sqlite result too large")
)

type Namespace struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	StoreID          string    `json:"store_id"`
	Kind             StoreKind `json:"kind"`
	Scope            string    `json:"scope"`
	QuotaBytes       int64     `json:"quota_bytes"`
	QuotaFiles       int64     `json:"quota_files,omitempty"`
	SchemaVersion    int       `json:"schema_version,omitempty"`
}

type NamespaceRecord struct {
	Namespace
	GenerationID string `json:"generation_id"`
	UsageBytes   int64  `json:"usage_bytes"`
	UsageFiles   int64  `json:"usage_files,omitempty"`
}

type Usage struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	UsageBytes       int64  `json:"usage_bytes"`
	QuotaBytes       int64  `json:"quota_bytes"`
	UsageFiles       int64  `json:"usage_files"`
	QuotaFiles       int64  `json:"quota_files"`
}

type FilesBroker interface {
	ReadFile(ctx context.Context, req FileReadRequest) (FileReadResult, error)
	WriteFile(ctx context.Context, req FileWriteRequest) (FileWriteResult, error)
	DeleteFile(ctx context.Context, req FileDeleteRequest) error
	ListFiles(ctx context.Context, req FileListRequest) (FileListResult, error)
}

type KVBroker interface {
	GetKV(ctx context.Context, req KVGetRequest) (KVGetResult, error)
	PutKV(ctx context.Context, req KVPutRequest) (KVPutResult, error)
	DeleteKV(ctx context.Context, req KVDeleteRequest) error
	ListKV(ctx context.Context, req KVListRequest) (KVListResult, error)
}

type SQLiteBroker interface {
	ExecSQLite(ctx context.Context, req SQLiteExecRequest) (SQLiteExecResult, error)
	QuerySQLite(ctx context.Context, req SQLiteQueryRequest) (SQLiteQueryResult, error)
}

type Inspector interface {
	ListNamespaces(ctx context.Context, pluginInstanceID string) ([]NamespaceRecord, error)
	Usage(ctx context.Context, pluginInstanceID string, storeID string) (Usage, error)
}

type FileReadRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Path             string                   `json:"path"`
	MaxBytes         int64                    `json:"max_bytes,omitempty"`
}

type FileReadResult struct {
	Path      string `json:"path"`
	Data      []byte `json:"-"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type FileWriteRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Path             string                   `json:"path"`
	Data             []byte                   `json:"-"`
}

type FileWriteResult struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type FileDeleteRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Path             string                   `json:"path"`
	Recursive        bool                     `json:"recursive,omitempty"`
}

type FileListRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Path             string                   `json:"path,omitempty"`
	MaxEntries       int                      `json:"max_entries,omitempty"`
	Cursor           string                   `json:"cursor,omitempty"`
}

type FileListResult struct {
	Path       string      `json:"path"`
	Entries    []FileEntry `json:"entries"`
	Usage      Usage       `json:"usage"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type FileEntry struct {
	Path      string    `json:"path"`
	Dir       bool      `json:"dir"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type KVGetRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Key              string                   `json:"key"`
	MaxBytes         int64                    `json:"max_bytes,omitempty"`
}

type KVGetResult struct {
	Key       string `json:"key"`
	Value     []byte `json:"-"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type KVPutRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Key              string                   `json:"key"`
	Value            []byte                   `json:"-"`
}

type KVPutResult struct {
	Key       string `json:"key"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type KVDeleteRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Key              string                   `json:"key"`
}

type KVListRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Prefix           string                   `json:"prefix,omitempty"`
	MaxEntries       int                      `json:"max_entries,omitempty"`
	Cursor           string                   `json:"cursor,omitempty"`
}

type KVListResult struct {
	Prefix     string    `json:"prefix,omitempty"`
	Entries    []KVEntry `json:"entries"`
	Usage      Usage     `json:"usage"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

type KVEntry struct {
	Key       string    `json:"key"`
	SizeBytes int64     `json:"size_bytes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SQLiteValue struct {
	Null  bool     `json:"null,omitempty"`
	Int   *int64   `json:"int,omitempty"`
	Float *float64 `json:"float,omitempty"`
	Text  *string  `json:"text,omitempty"`
	Blob  []byte   `json:"-"`
}

type SQLiteExecRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Database         string                   `json:"database,omitempty"`
	SQL              string                   `json:"sql"`
	Args             []SQLiteValue            `json:"args,omitempty"`
	Timeout          time.Duration            `json:"timeout,omitempty"`
}

type SQLiteExecResult struct {
	Database     string `json:"database"`
	RowsAffected int64  `json:"rows_affected"`
	LastInsertID int64  `json:"last_insert_id,omitempty"`
	Usage        Usage  `json:"usage"`
}

type SQLiteQueryRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	StoreID          string                   `json:"store_id"`
	Database         string                   `json:"database,omitempty"`
	SQL              string                   `json:"sql"`
	Args             []SQLiteValue            `json:"args,omitempty"`
	MaxRows          int                      `json:"max_rows,omitempty"`
	MaxResponseBytes int64                    `json:"max_response_bytes,omitempty"`
	Timeout          time.Duration            `json:"timeout,omitempty"`
}

type SQLiteQueryResult struct {
	Database string          `json:"database"`
	Columns  []string        `json:"columns"`
	Rows     [][]SQLiteValue `json:"rows"`
	Usage    Usage           `json:"usage"`
}

const MaxKVKeyBytes = 128
