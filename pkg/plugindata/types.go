package plugindata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
)

var (
	ErrInvalidArgument         = errors.New("invalid plugin data argument")
	ErrBindingNotFound         = errors.New("plugin data binding not found")
	ErrBindingConflict         = errors.New("plugin data binding state conflicts with the operation")
	ErrBindingRevisionConflict = errors.New("plugin data binding revision changed")
	ErrShapeMismatch           = errors.New("plugin data shape does not match")
	ErrNotActive               = errors.New("plugin data binding is not active")
	ErrNotRetained             = errors.New("plugin data binding is not retained")
	ErrDatasetCorrupt          = errors.New("plugin data dataset is corrupt")
	ErrExportNotFound          = errors.New("plugin data export not found")
	ErrUnknownSetting          = errors.New("plugin data setting is not declared non-secret")
	ErrSettingScopeMismatch    = errors.New("plugin data setting scope does not match the request")
	ErrStorageScopeMismatch    = errors.New("plugin data storage scope does not match the request")
	ErrUnsafeFilesystem        = errors.New("plugin data filesystem entry is unsafe")
	ErrRevisionConflict        = errors.New("plugin data revision conflict")
)

type BindingRevisionConflictError struct {
	PluginInstanceID string
	Expected         uint64
	Actual           uint64
}

func (e *BindingRevisionConflictError) Error() string {
	return fmt.Sprintf("%v: plugin %s expected %d, actual %d", ErrBindingRevisionConflict, e.PluginInstanceID, e.Expected, e.Actual)
}

func (e *BindingRevisionConflictError) Unwrap() error {
	return ErrBindingRevisionConflict
}

type BindingState string

const (
	BindingActive   BindingState = "active"
	BindingRetained BindingState = "retained"
)

type NamespaceKind string

const (
	NamespaceFiles  NamespaceKind = "files"
	NamespaceKV     NamespaceKind = "kv"
	NamespaceSQLite NamespaceKind = "sqlite"
)

type Namespace struct {
	ID            string        `json:"id"`
	Kind          NamespaceKind `json:"kind"`
	Scope         string        `json:"scope"`
	SchemaVersion int           `json:"schema_version"`
	QuotaBytes    int64         `json:"quota_bytes"`
	QuotaFiles    int64         `json:"quota_files,omitempty"`
}

type Shape struct {
	PublisherID string                `json:"publisher_id"`
	PluginID    string                `json:"plugin_id"`
	Settings    settingsdomain.Schema `json:"settings"`
	Namespaces  []Namespace           `json:"namespaces"`
}

type Binding struct {
	PluginInstanceID string       `json:"plugin_instance_id"`
	GenerationID     string       `json:"generation_id"`
	State            BindingState `json:"state"`
	Revision         uint64       `json:"revision"`
	ShapeHash        string       `json:"shape_hash"`
	RetainedAt       *time.Time   `json:"retained_at,omitempty"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"`
}

type Object struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	ObjectID         string    `json:"object_id"`
	ContentHash      string    `json:"content_hash"`
	ShapeHash        string    `json:"shape_hash"`
	SizeBytes        int64     `json:"size_bytes"`
	CreatedAt        time.Time `json:"created_at"`
}

type MaintenanceBinding struct {
	Scope   sessionctx.ResourceScope
	Binding Binding
}

type MaintenanceObject struct {
	Scope  sessionctx.ResourceScope
	Object Object
}

type Catalog interface {
	GetBinding(ctx context.Context, pluginInstanceID string) (Binding, bool, error)
	ListBindings(ctx context.Context, cursor string, limit int) ([]Binding, string, error)
	ListAllBindingsForMaintenance(ctx context.Context, cursor string, limit int) ([]MaintenanceBinding, string, error)
	CommitEnable(ctx context.Context, expectedManagementRevision uint64, expected *Binding, next Binding, shape Shape, now time.Time) error
	SwapImport(ctx context.Context, expectedManagementRevision uint64, expected *Binding, next Binding, shape Shape, now time.Time) error
	BindRetained(ctx context.Context, expected Binding, targetPluginInstanceID string, targetExpectedManagementRevision uint64, targetShape Shape, now time.Time) (Binding, error)
	DeleteRetained(ctx context.Context, expected Binding) error
	CleanupExpired(ctx context.Context, now time.Time, expected []Binding) ([]Binding, error)
	CommitUninstall(ctx context.Context, req CommitUninstallRequest) (CommitUninstallResult, error)
	GetObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) (Object, bool, error)
	ListObjects(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, cursor string, limit int) ([]Object, string, error)
	ListAllObjectsForMaintenance(ctx context.Context, cursor string, limit int) ([]MaintenanceObject, string, error)
	CreateObject(ctx context.Context, scope sessionctx.ScopeKind, object Object) error
	DeleteObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) error
}

type Dataset struct {
	Binding Binding `json:"binding"`
	Shape   Shape   `json:"shape"`
}

type Settings struct {
	Scope    sessionctx.ScopeKind       `json:"scope"`
	Revision uint64                     `json:"revision"`
	Values   map[string]json.RawMessage `json:"values"`
}

type CommitEnableRequest struct {
	PluginInstanceID           string
	Shape                      Shape
	InitialSettings            map[string]json.RawMessage
	ExpectedManagementRevision uint64
	Now                        time.Time `json:"-"`
}

type ExportRequest struct {
	PluginInstanceID string
}

type DeleteExportRequest struct {
	PluginInstanceID string
	ObjectID         string
}

type Export struct {
	ObjectID    string
	ContentHash string
	SizeBytes   int64
	CreatedAt   time.Time
}

type ImportRequest struct {
	PluginInstanceID           string
	ObjectID                   string
	ExpectedShape              Shape
	ExpectedManagementRevision uint64
	Now                        time.Time `json:"-"`
}

type BindRetainedRequest struct {
	SourcePluginInstanceID           string
	ExpectedSourceBindingRevision    uint64
	TargetPluginInstanceID           string
	ExpectedShape                    Shape
	TargetExpectedManagementRevision uint64
	Now                              time.Time `json:"-"`
}

type DeleteRetainedRequest struct {
	PluginInstanceID        string
	ExpectedBindingRevision uint64
}

type RetainedFilter struct {
	PluginInstanceID string
}

type CleanupResult struct {
	Deleted []Binding
}

type CommitUninstallRequest struct {
	PluginInstanceID           string
	DeleteData                 bool
	ExpectedManagementRevision uint64
	RetainUntil                *time.Time
	Now                        time.Time `json:"-"`
}

type CommitUninstallResult struct {
	ManagementRevision uint64
	RevokeEpoch        uint64
	DeletedAt          time.Time
}

type PatchSettingsRequest struct {
	PluginInstanceID       string
	Scope                  sessionctx.ScopeKind
	ExpectedValuesRevision uint64
	Set                    map[string]json.RawMessage
	Remove                 []string
}

type Store interface {
	Durable() bool
	CommitEnable(ctx context.Context, req CommitEnableRequest) (Dataset, error)
	Export(ctx context.Context, req ExportRequest) (Export, error)
	DeleteExport(ctx context.Context, req DeleteExportRequest) error
	Import(ctx context.Context, req ImportRequest) (Dataset, error)
	BindRetained(ctx context.Context, req BindRetainedRequest) (Dataset, error)
	DeleteRetained(ctx context.Context, req DeleteRetainedRequest) error
	CommitUninstall(ctx context.Context, req CommitUninstallRequest) (CommitUninstallResult, error)
	ListRetained(ctx context.Context, filter RetainedFilter) ([]Binding, error)
	CleanupExpired(ctx context.Context, now time.Time) (CleanupResult, error)
	GetSettings(ctx context.Context, pluginInstanceID string, scope sessionctx.ScopeKind) (Settings, error)
	PatchSettings(ctx context.Context, req PatchSettingsRequest) (Settings, error)
}
