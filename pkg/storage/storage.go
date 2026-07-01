package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type StoreKind string

const (
	StoreKV     StoreKind = "kv"
	StoreFiles  StoreKind = "files"
	StoreSQLite StoreKind = "sqlite"
)

type NamespaceState string

const (
	NamespaceActive   NamespaceState = "active"
	NamespaceRetained NamespaceState = "retained"
)

var (
	ErrInvalidNamespace     = errors.New("storage namespace is invalid")
	ErrInvalidFilePath      = errors.New("storage file path is invalid")
	ErrInvalidKVKey         = errors.New("storage kv key is invalid")
	ErrInvalidSQLite        = errors.New("storage sqlite request is invalid")
	ErrNamespaceNotFound    = errors.New("storage namespace not found")
	ErrQuotaExceeded        = errors.New("storage quota exceeded")
	ErrArchiveNotFound      = errors.New("storage archive not found")
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
	Scope            string    `json:"scope,omitempty"`
	QuotaBytes       int64     `json:"quota_bytes"`
	SchemaVersion    int       `json:"schema_version,omitempty"`
}

type NamespaceRecord struct {
	Namespace
	State      NamespaceState `json:"state"`
	UsageBytes int64          `json:"usage_bytes"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	RetainedAt *time.Time     `json:"retained_at,omitempty"`
}

type Usage struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	UsageBytes       int64  `json:"usage_bytes"`
	QuotaBytes       int64  `json:"quota_bytes"`
}

type ExportRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	IncludeSecrets   bool   `json:"include_secrets"`
}

type ImportRequest struct {
	PluginInstanceID string      `json:"plugin_instance_id"`
	ArchiveRef       string      `json:"archive_ref"`
	DeleteExisting   bool        `json:"delete_existing"`
	TargetNamespaces []Namespace `json:"target_namespaces,omitempty"`
}

type ArchiveRecord struct {
	ArchiveRef             string            `json:"archive_ref"`
	SourcePluginInstanceID string            `json:"source_plugin_instance_id"`
	IncludeSecrets         bool              `json:"include_secrets"`
	Namespaces             []NamespaceRecord `json:"namespaces"`
	CreatedAt              time.Time         `json:"created_at"`
}

type Broker interface {
	EnsureNamespace(ctx context.Context, ns Namespace) error
	DeleteNamespace(ctx context.Context, pluginInstanceID string, deleteData bool) error
	ExportData(ctx context.Context, req ExportRequest) (string, error)
	ImportData(ctx context.Context, req ImportRequest) error
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
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Path             string `json:"path"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
}

type FileReadResult struct {
	Path      string `json:"path"`
	Data      []byte `json:"-"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type FileWriteRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Path             string `json:"path"`
	Data             []byte `json:"-"`
}

type FileWriteResult struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type FileDeleteRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Path             string `json:"path"`
	Recursive        bool   `json:"recursive,omitempty"`
}

type FileListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Path             string `json:"path,omitempty"`
	MaxEntries       int    `json:"max_entries,omitempty"`
}

type FileListResult struct {
	Path    string      `json:"path"`
	Entries []FileEntry `json:"entries"`
	Usage   Usage       `json:"usage"`
}

type FileEntry struct {
	Path      string    `json:"path"`
	Dir       bool      `json:"dir"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type KVGetRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Key              string `json:"key"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
}

type KVGetResult struct {
	Key       string `json:"key"`
	Value     []byte `json:"-"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type KVPutRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Key              string `json:"key"`
	Value            []byte `json:"-"`
}

type KVPutResult struct {
	Key       string `json:"key"`
	SizeBytes int64  `json:"size_bytes"`
	Usage     Usage  `json:"usage"`
}

type KVDeleteRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Key              string `json:"key"`
}

type KVListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	StoreID          string `json:"store_id"`
	Prefix           string `json:"prefix,omitempty"`
	MaxEntries       int    `json:"max_entries,omitempty"`
}

type KVListResult struct {
	Prefix  string    `json:"prefix,omitempty"`
	Entries []KVEntry `json:"entries"`
	Usage   Usage     `json:"usage"`
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
	PluginInstanceID string        `json:"plugin_instance_id"`
	StoreID          string        `json:"store_id"`
	Database         string        `json:"database,omitempty"`
	SQL              string        `json:"sql"`
	Args             []SQLiteValue `json:"args,omitempty"`
	Timeout          time.Duration `json:"timeout,omitempty"`
}

type SQLiteExecResult struct {
	Database     string `json:"database"`
	RowsAffected int64  `json:"rows_affected"`
	LastInsertID int64  `json:"last_insert_id,omitempty"`
	Usage        Usage  `json:"usage"`
}

type SQLiteQueryRequest struct {
	PluginInstanceID string        `json:"plugin_instance_id"`
	StoreID          string        `json:"store_id"`
	Database         string        `json:"database,omitempty"`
	SQL              string        `json:"sql"`
	Args             []SQLiteValue `json:"args,omitempty"`
	MaxRows          int           `json:"max_rows,omitempty"`
	MaxResponseBytes int64         `json:"max_response_bytes,omitempty"`
	Timeout          time.Duration `json:"timeout,omitempty"`
}

type SQLiteQueryResult struct {
	Database string          `json:"database"`
	Columns  []string        `json:"columns"`
	Rows     [][]SQLiteValue `json:"rows"`
	Usage    Usage           `json:"usage"`
}

const MaxKVKeyBytes = 128

type MemoryBroker struct {
	mu         sync.Mutex
	now        func() time.Time
	nextExport int
	namespaces map[namespaceKey]NamespaceRecord
	archives   map[string]ArchiveRecord
	kv         map[namespaceKey]map[string][]byte
	kvArchives map[string]map[namespaceKey]map[string][]byte
}

type namespaceKey struct {
	pluginInstanceID string
	storeID          string
}

func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{
		now:        func() time.Time { return time.Now().UTC() },
		namespaces: map[namespaceKey]NamespaceRecord{},
		archives:   map[string]ArchiveRecord{},
		kv:         map[namespaceKey]map[string][]byte{},
		kvArchives: map[string]map[namespaceKey]map[string][]byte{},
	}
}

func (b *MemoryBroker) EnsureNamespace(_ context.Context, ns Namespace) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	normalized, err := normalizeNamespace(ns)
	if err != nil {
		return err
	}
	key := makeKey(normalized.PluginInstanceID, normalized.StoreID)

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if existing, ok := b.namespaces[key]; ok {
		if existing.UsageBytes > normalized.QuotaBytes {
			return fmt.Errorf("%w: current usage %d exceeds quota %d", ErrQuotaExceeded, existing.UsageBytes, normalized.QuotaBytes)
		}
		existing.Namespace = normalized
		existing.State = NamespaceActive
		existing.UpdatedAt = now
		existing.RetainedAt = nil
		b.namespaces[key] = existing
		return nil
	}

	b.namespaces[key] = NamespaceRecord{
		Namespace: normalized,
		State:     NamespaceActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return nil
}

func (b *MemoryBroker) DeleteNamespace(_ context.Context, pluginInstanceID string, deleteData bool) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	for key, record := range b.namespaces {
		if key.pluginInstanceID != pluginInstanceID {
			continue
		}
		if deleteData {
			delete(b.namespaces, key)
			delete(b.kv, key)
			continue
		}
		record.State = NamespaceRetained
		record.UpdatedAt = now
		record.RetainedAt = &now
		b.namespaces[key] = record
	}
	return nil
}

func (b *MemoryBroker) ExportData(_ context.Context, req ExportRequest) (string, error) {
	if b == nil {
		return "", errors.New("storage broker is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return "", fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	namespaces := b.listNamespacesLocked(pluginInstanceID)
	if len(namespaces) == 0 {
		return "", ErrNamespaceNotFound
	}
	b.nextExport++
	ref := fmt.Sprintf("archive_%06d", b.nextExport)
	kvArchive := map[namespaceKey]map[string][]byte{}
	for _, record := range namespaces {
		key := makeKey(record.PluginInstanceID, record.StoreID)
		if record.Kind == StoreKV {
			kvArchive[key] = cloneKVMap(b.kv[key])
		}
	}
	b.archives[ref] = ArchiveRecord{
		ArchiveRef:             ref,
		SourcePluginInstanceID: pluginInstanceID,
		IncludeSecrets:         req.IncludeSecrets,
		Namespaces:             cloneNamespaceRecords(namespaces),
		CreatedAt:              b.now(),
	}
	b.kvArchives[ref] = kvArchive
	return ref, nil
}

func (b *MemoryBroker) ImportData(_ context.Context, req ImportRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}
	archiveRef := strings.TrimSpace(req.ArchiveRef)
	if archiveRef == "" {
		return ErrArchiveNotFound
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	archive, ok := b.archives[archiveRef]
	if !ok {
		return ErrArchiveNotFound
	}
	if req.DeleteExisting {
		for key := range b.namespaces {
			if key.pluginInstanceID == pluginInstanceID {
				delete(b.namespaces, key)
				delete(b.kv, key)
			}
		}
	}

	now := b.now()
	targets, err := normalizeTargetNamespaces(req.TargetNamespaces, pluginInstanceID)
	if err != nil {
		return err
	}
	for _, archived := range archive.Namespaces {
		record := archived
		if len(targets) > 0 {
			target, ok := targets[archived.StoreID]
			if !ok {
				return fmt.Errorf("%w: archive store %q is not declared by target manifest", ErrInvalidNamespace, archived.StoreID)
			}
			record.Namespace = target
			if record.UsageBytes > target.QuotaBytes {
				return fmt.Errorf("%w: archive store %q usage %d exceeds target quota %d", ErrQuotaExceeded, archived.StoreID, record.UsageBytes, target.QuotaBytes)
			}
		} else {
			record.PluginInstanceID = pluginInstanceID
		}
		record.State = NamespaceActive
		record.CreatedAt = now
		record.UpdatedAt = now
		record.RetainedAt = nil
		key := makeKey(pluginInstanceID, record.StoreID)
		b.namespaces[key] = record
		sourceKey := makeKey(archive.SourcePluginInstanceID, archived.StoreID)
		if record.Kind == StoreKV {
			b.kv[key] = cloneKVMap(b.kvArchives[archiveRef][sourceKey])
		}
	}
	return nil
}

func (b *MemoryBroker) ListNamespaces(_ context.Context, pluginInstanceID string) ([]NamespaceRecord, error) {
	if b == nil {
		return nil, errors.New("storage broker is nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return cloneNamespaceRecords(b.listNamespacesLocked(pluginInstanceID)), nil
}

func (b *MemoryBroker) Usage(_ context.Context, pluginInstanceID string, storeID string) (Usage, error) {
	if b == nil {
		return Usage{}, errors.New("storage broker is nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, ok := b.namespaces[makeKey(pluginInstanceID, storeID)]
	if !ok {
		return Usage{}, ErrNamespaceNotFound
	}
	return Usage{
		PluginInstanceID: record.PluginInstanceID,
		StoreID:          record.StoreID,
		UsageBytes:       record.UsageBytes,
		QuotaBytes:       record.QuotaBytes,
	}, nil
}

func (b *MemoryBroker) SetUsage(_ context.Context, pluginInstanceID string, storeID string, usageBytes int64) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if usageBytes < 0 {
		return fmt.Errorf("%w: usage_bytes must be non-negative", ErrInvalidNamespace)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := makeKey(pluginInstanceID, storeID)
	record, ok := b.namespaces[key]
	if !ok {
		return ErrNamespaceNotFound
	}
	if usageBytes > record.QuotaBytes {
		return fmt.Errorf("%w: usage %d exceeds quota %d", ErrQuotaExceeded, usageBytes, record.QuotaBytes)
	}
	record.UsageBytes = usageBytes
	record.UpdatedAt = b.now()
	b.namespaces[key] = record
	return nil
}

func (b *MemoryBroker) GetKV(_ context.Context, req KVGetRequest) (KVGetResult, error) {
	if b == nil {
		return KVGetResult{}, errors.New("storage broker is nil")
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return KVGetResult{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, nsKey, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVGetResult{}, err
	}
	value, ok := b.kv[nsKey][key]
	if !ok {
		return KVGetResult{}, ErrKVKeyNotFound
	}
	if req.MaxBytes > 0 && int64(len(value)) > req.MaxBytes {
		return KVGetResult{}, fmt.Errorf("%w: %d > %d", ErrKVValueTooLarge, len(value), req.MaxBytes)
	}
	return KVGetResult{
		Key:       key,
		Value:     append([]byte(nil), value...),
		SizeBytes: int64(len(value)),
		Usage:     usageFromRecord(record),
	}, nil
}

func (b *MemoryBroker) PutKV(_ context.Context, req KVPutRequest) (KVPutResult, error) {
	if b == nil {
		return KVPutResult{}, errors.New("storage broker is nil")
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return KVPutResult{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, nsKey, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVPutResult{}, err
	}
	oldSize := int64(0)
	if old, ok := b.kv[nsKey][key]; ok {
		oldSize = int64(len(old))
	}
	projected := record.UsageBytes - oldSize + int64(len(req.Value))
	if projected > record.QuotaBytes {
		return KVPutResult{}, fmt.Errorf("%w: projected usage %d exceeds quota %d", ErrQuotaExceeded, projected, record.QuotaBytes)
	}
	if b.kv[nsKey] == nil {
		b.kv[nsKey] = map[string][]byte{}
	}
	b.kv[nsKey][key] = append([]byte(nil), req.Value...)
	record.UsageBytes = projected
	record.UpdatedAt = b.now()
	b.namespaces[nsKey] = record
	return KVPutResult{
		Key:       key,
		SizeBytes: int64(len(req.Value)),
		Usage:     usageFromRecord(record),
	}, nil
}

func (b *MemoryBroker) DeleteKV(_ context.Context, req KVDeleteRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, nsKey, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return err
	}
	if old, ok := b.kv[nsKey][key]; ok {
		delete(b.kv[nsKey], key)
		record.UsageBytes -= int64(len(old))
		if record.UsageBytes < 0 {
			record.UsageBytes = 0
		}
		record.UpdatedAt = b.now()
		b.namespaces[nsKey] = record
	}
	return nil
}

func (b *MemoryBroker) ListKV(_ context.Context, req KVListRequest) (KVListResult, error) {
	if b == nil {
		return KVListResult{}, errors.New("storage broker is nil")
	}
	prefix := strings.TrimSpace(req.Prefix)
	b.mu.Lock()
	defer b.mu.Unlock()
	record, nsKey, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVListResult{}, err
	}
	limit := req.MaxEntries
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	entries := make([]KVEntry, 0, len(b.kv[nsKey]))
	now := record.UpdatedAt
	for key, value := range b.kv[nsKey] {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		entries = append(entries, KVEntry{Key: key, SizeBytes: int64(len(value)), UpdatedAt: now})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return KVListResult{Prefix: prefix, Entries: entries, Usage: usageFromRecord(record)}, nil
}

func (b *MemoryBroker) Archive(ref string) (ArchiveRecord, bool) {
	if b == nil {
		return ArchiveRecord{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	archive, ok := b.archives[ref]
	if !ok {
		return ArchiveRecord{}, false
	}
	archive.Namespaces = cloneNamespaceRecords(archive.Namespaces)
	return archive, true
}

func (b *MemoryBroker) activeKVNamespaceLocked(pluginInstanceID string, storeID string) (NamespaceRecord, namespaceKey, error) {
	key := makeKey(pluginInstanceID, storeID)
	record, ok := b.namespaces[key]
	if !ok || record.State != NamespaceActive {
		return NamespaceRecord{}, namespaceKey{}, ErrNamespaceNotFound
	}
	if record.Kind != StoreKV {
		return NamespaceRecord{}, namespaceKey{}, fmt.Errorf("%w: store %q is %s, not kv", ErrInvalidNamespace, record.StoreID, record.Kind)
	}
	return record, key, nil
}

func (b *MemoryBroker) listNamespacesLocked(pluginInstanceID string) []NamespaceRecord {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	records := make([]NamespaceRecord, 0)
	for key, record := range b.namespaces {
		if pluginInstanceID != "" && key.pluginInstanceID != pluginInstanceID {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginInstanceID == records[j].PluginInstanceID {
			return records[i].StoreID < records[j].StoreID
		}
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
	return records
}

func normalizeNamespace(ns Namespace) (Namespace, error) {
	ns.PluginInstanceID = strings.TrimSpace(ns.PluginInstanceID)
	ns.StoreID = strings.TrimSpace(ns.StoreID)
	ns.Scope = strings.TrimSpace(ns.Scope)
	if ns.PluginInstanceID == "" {
		return Namespace{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}
	if ns.StoreID == "" {
		return Namespace{}, fmt.Errorf("%w: store_id is required", ErrInvalidNamespace)
	}
	switch ns.Kind {
	case StoreKV, StoreFiles, StoreSQLite:
	default:
		return Namespace{}, fmt.Errorf("%w: unsupported store kind %q", ErrInvalidNamespace, ns.Kind)
	}
	if ns.QuotaBytes <= 0 {
		return Namespace{}, fmt.Errorf("%w: quota_bytes must be positive", ErrInvalidNamespace)
	}
	if ns.SchemaVersion <= 0 {
		ns.SchemaVersion = 1
	}
	return ns, nil
}

func normalizeTargetNamespaces(namespaces []Namespace, pluginInstanceID string) (map[string]Namespace, error) {
	if len(namespaces) == 0 {
		return nil, nil
	}
	targets := make(map[string]Namespace, len(namespaces))
	for _, ns := range namespaces {
		ns.PluginInstanceID = pluginInstanceID
		normalized, err := normalizeNamespace(ns)
		if err != nil {
			return nil, err
		}
		if _, ok := targets[normalized.StoreID]; ok {
			return nil, fmt.Errorf("%w: duplicate target store %q", ErrInvalidNamespace, normalized.StoreID)
		}
		targets[normalized.StoreID] = normalized
	}
	return targets, nil
}

func makeKey(pluginInstanceID string, storeID string) namespaceKey {
	return namespaceKey{
		pluginInstanceID: strings.TrimSpace(pluginInstanceID),
		storeID:          strings.TrimSpace(storeID),
	}
}

func cloneNamespaceRecords(records []NamespaceRecord) []NamespaceRecord {
	cloned := make([]NamespaceRecord, len(records))
	copy(cloned, records)
	return cloned
}

func normalizeKVKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", fmt.Errorf("%w: key is required", ErrInvalidKVKey)
	}
	if len([]byte(key)) > MaxKVKeyBytes {
		return "", fmt.Errorf("%w: key exceeds %d bytes", ErrInvalidKVKey, MaxKVKeyBytes)
	}
	return key, nil
}

func cloneKVMap(values map[string][]byte) map[string][]byte {
	cloned := map[string][]byte{}
	for key, value := range values {
		cloned[key] = append([]byte(nil), value...)
	}
	return cloned
}

func usageFromRecord(record NamespaceRecord) Usage {
	return Usage{
		PluginInstanceID: record.PluginInstanceID,
		StoreID:          record.StoreID,
		UsageBytes:       record.UsageBytes,
		QuotaBytes:       record.QuotaBytes,
	}
}
