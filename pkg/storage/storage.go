package storage

import "context"

type StoreKind string

const (
	StoreKV     StoreKind = "kv"
	StoreFiles  StoreKind = "files"
	StoreSQLite StoreKind = "sqlite"
)

type Namespace struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	StoreID          string    `json:"store_id"`
	Kind             StoreKind `json:"kind"`
	QuotaBytes       int64     `json:"quota_bytes"`
}

type ExportRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	IncludeSecrets   bool   `json:"include_secrets"`
}

type ImportRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ArchiveRef       string `json:"archive_ref"`
	DeleteExisting   bool   `json:"delete_existing"`
}

type Broker interface {
	EnsureNamespace(ctx context.Context, ns Namespace) error
	DeleteNamespace(ctx context.Context, pluginInstanceID string, deleteData bool) error
	ExportData(ctx context.Context, req ExportRequest) (string, error)
	ImportData(ctx context.Context, req ImportRequest) error
}
