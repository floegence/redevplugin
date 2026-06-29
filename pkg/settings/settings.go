package settings

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

const (
	FieldString  = "string"
	FieldBoolean = "boolean"
	FieldNumber  = "number"
	FieldInteger = "integer"
	FieldEnum    = "enum"
	FieldSelect  = "select"
	FieldSecret  = "secret"
)

type State string

const (
	StateActive   State = "active"
	StateRetained State = "retained"
)

var (
	ErrNotDeclared    = errors.New("plugin settings are not declared")
	ErrInvalidSetting = errors.New("plugin setting is invalid")
)

type EnsureRequest struct {
	PluginInstanceID string
	Spec             *manifest.SettingsSpec
	Now              time.Time
}

type GetRequest struct {
	PluginInstanceID string
}

type PatchRequest struct {
	PluginInstanceID string
	Values           map[string]any
	Now              time.Time
}

type MarkSecretRequest struct {
	PluginInstanceID string
	SecretRef        string
	Set              bool
	LastTestStatus   string
	Now              time.Time
}

type DeleteRequest struct {
	PluginInstanceID string
	DeleteData       bool
	Now              time.Time
}

type SecretValue struct {
	Set            bool       `json:"set"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	LastTestStatus string     `json:"last_test_status,omitempty"`
}

type SecretState struct {
	SecretRef      string     `json:"secret_ref"`
	Set            bool       `json:"set"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	LastTestStatus string     `json:"last_test_status,omitempty"`
}

type Snapshot struct {
	PluginInstanceID string         `json:"plugin_instance_id"`
	SchemaVersion    int            `json:"schema_version"`
	SettingsRevision uint64         `json:"settings_revision"`
	Values           map[string]any `json:"values"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type Record struct {
	PluginInstanceID string                      `json:"plugin_instance_id"`
	SchemaVersion    int                         `json:"schema_version"`
	SettingsRevision uint64                      `json:"settings_revision"`
	State            State                       `json:"state"`
	Fields           []manifest.SettingFieldSpec `json:"fields"`
	Values           map[string]any              `json:"values"`
	Secrets          map[string]SecretState      `json:"secrets"`
	UpdatedAt        time.Time                   `json:"updated_at"`
	RetainedAt       *time.Time                  `json:"retained_at,omitempty"`
}

type Store interface {
	Ensure(ctx context.Context, req EnsureRequest) (Snapshot, error)
	Get(ctx context.Context, req GetRequest) (Snapshot, error)
	Patch(ctx context.Context, req PatchRequest) (Snapshot, error)
	MarkSecret(ctx context.Context, req MarkSecretRequest) (Snapshot, error)
	Delete(ctx context.Context, req DeleteRequest) error
}

type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:     func() time.Time { return time.Now().UTC() },
		records: map[string]Record{},
	}
}

func (s *MemoryStore) Ensure(_ context.Context, req EnsureRequest) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return Snapshot{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidSetting)
	}
	if req.Spec == nil {
		return Snapshot{}, ErrNotDeclared
	}
	if err := validateSpec(*req.Spec); err != nil {
		return Snapshot{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.records[pluginInstanceID]
	fields := cloneFields(req.Spec.Fields)
	record := Record{
		PluginInstanceID: pluginInstanceID,
		SchemaVersion:    req.Spec.SchemaVersion,
		SettingsRevision: 1,
		State:            StateActive,
		Fields:           fields,
		Values:           map[string]any{},
		Secrets:          map[string]SecretState{},
		UpdatedAt:        now,
	}
	if exists {
		record.SettingsRevision = existing.SettingsRevision
		record.Values = existing.Values
		record.Secrets = existing.Secrets
		record.UpdatedAt = existing.UpdatedAt
		if existing.SchemaVersion != req.Spec.SchemaVersion || !reflect.DeepEqual(existing.Fields, fields) || existing.State != StateActive {
			record.SettingsRevision++
			record.UpdatedAt = now
		}
	}
	record.Values = normalizedValuesForFields(req.Spec.Fields, record.Values)
	record.Secrets = normalizedSecretsForFields(req.Spec.Fields, record.Secrets)
	record.RetainedAt = nil
	s.records[pluginInstanceID] = record
	return snapshot(record), nil
}

func (s *MemoryStore) Get(_ context.Context, req GetRequest) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(req.PluginInstanceID)]
	if !ok || record.State != StateActive {
		return Snapshot{}, ErrNotDeclared
	}
	return snapshot(record), nil
}

func (s *MemoryStore) Patch(_ context.Context, req PatchRequest) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return Snapshot{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidSetting)
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.State != StateActive {
		return Snapshot{}, ErrNotDeclared
	}
	fields := fieldsByKey(record.Fields)
	for key, value := range req.Values {
		field, ok := fields[key]
		if !ok {
			return Snapshot{}, fmt.Errorf("%w: unknown setting %q", ErrInvalidSetting, key)
		}
		if field.Type == FieldSecret {
			return Snapshot{}, fmt.Errorf("%w: secret setting %q must be updated through the secret lifecycle", ErrInvalidSetting, key)
		}
		normalized, err := normalizeValue(field, value)
		if err != nil {
			return Snapshot{}, err
		}
		record.Values[key] = normalized
	}
	if len(req.Values) > 0 {
		record.SettingsRevision++
		record.UpdatedAt = now
		s.records[pluginInstanceID] = record
	}
	return snapshot(record), nil
}

func (s *MemoryStore) MarkSecret(_ context.Context, req MarkSecretRequest) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	secretRef := strings.TrimSpace(req.SecretRef)
	if pluginInstanceID == "" || secretRef == "" {
		return Snapshot{}, fmt.Errorf("%w: plugin_instance_id and secret_ref are required", ErrInvalidSetting)
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.State != StateActive {
		return Snapshot{}, ErrNotDeclared
	}
	if !secretRefDeclared(record.Fields, secretRef) {
		return Snapshot{}, fmt.Errorf("%w: secret_ref %q is not declared by settings", ErrInvalidSetting, secretRef)
	}
	updatedAt := now
	record.Secrets[secretRef] = SecretState{
		SecretRef:      secretRef,
		Set:            req.Set,
		UpdatedAt:      &updatedAt,
		LastTestStatus: strings.TrimSpace(req.LastTestStatus),
	}
	record.SettingsRevision++
	record.UpdatedAt = now
	s.records[pluginInstanceID] = record
	return snapshot(record), nil
}

func (s *MemoryStore) Delete(_ context.Context, req DeleteRequest) error {
	if s == nil {
		return errors.New("settings store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidSetting)
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
	if !ok {
		return nil
	}
	if req.DeleteData {
		delete(s.records, pluginInstanceID)
		return nil
	}
	record.State = StateRetained
	record.SettingsRevision++
	record.UpdatedAt = now
	record.RetainedAt = &now
	s.records[pluginInstanceID] = record
	return nil
}

func validateSpec(spec manifest.SettingsSpec) error {
	if spec.SchemaVersion <= 0 {
		return fmt.Errorf("%w: schema_version must be positive", ErrInvalidSetting)
	}
	seen := map[string]struct{}{}
	for i, field := range spec.Fields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			return fmt.Errorf("%w: fields[%d].key is required", ErrInvalidSetting, i)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: fields[%d].key must be unique", ErrInvalidSetting, i)
		}
		seen[key] = struct{}{}
		if field.Scope != "user" && field.Scope != "environment" {
			return fmt.Errorf("%w: fields[%d].scope must be user or environment", ErrInvalidSetting, i)
		}
		if !supportedType(field.Type) {
			return fmt.Errorf("%w: fields[%d].type is unsupported", ErrInvalidSetting, i)
		}
		if field.Type == FieldSecret && strings.TrimSpace(field.SecretRef) == "" {
			return fmt.Errorf("%w: fields[%d].secret_ref is required for secret settings", ErrInvalidSetting, i)
		}
		if field.Type != FieldSecret && strings.TrimSpace(field.SecretRef) != "" {
			return fmt.Errorf("%w: fields[%d].secret_ref is only allowed for secret settings", ErrInvalidSetting, i)
		}
		if (field.Type == FieldEnum || field.Type == FieldSelect) && len(field.Options) == 0 {
			return fmt.Errorf("%w: fields[%d].options is required for option settings", ErrInvalidSetting, i)
		}
		if field.Default != nil {
			if _, err := normalizeValue(field, field.Default); err != nil {
				return fmt.Errorf("fields[%d].default: %w", i, err)
			}
		}
	}
	return nil
}

func normalizedValuesForFields(fields []manifest.SettingFieldSpec, existing map[string]any) map[string]any {
	values := map[string]any{}
	for _, field := range fields {
		if field.Type == FieldSecret {
			continue
		}
		if value, ok := existing[field.Key]; ok {
			if normalized, err := normalizeValue(field, value); err == nil {
				values[field.Key] = normalized
				continue
			}
		}
		if field.Default != nil {
			if normalized, err := normalizeValue(field, field.Default); err == nil {
				values[field.Key] = normalized
			}
		}
	}
	return values
}

func normalizedSecretsForFields(fields []manifest.SettingFieldSpec, existing map[string]SecretState) map[string]SecretState {
	secrets := map[string]SecretState{}
	for _, field := range fields {
		if field.Type != FieldSecret {
			continue
		}
		secretRef := strings.TrimSpace(field.SecretRef)
		if secretRef == "" {
			continue
		}
		if state, ok := existing[secretRef]; ok {
			state.SecretRef = secretRef
			secrets[secretRef] = state
		}
	}
	return secrets
}

func snapshot(record Record) Snapshot {
	values := map[string]any{}
	for _, field := range record.Fields {
		if field.Type == FieldSecret {
			state := record.Secrets[strings.TrimSpace(field.SecretRef)]
			values[field.Key] = SecretValue{
				Set:            state.Set,
				UpdatedAt:      cloneTimePtr(state.UpdatedAt),
				LastTestStatus: state.LastTestStatus,
			}
			continue
		}
		if value, ok := record.Values[field.Key]; ok {
			values[field.Key] = cloneValue(value)
		}
	}
	return Snapshot{
		PluginInstanceID: record.PluginInstanceID,
		SchemaVersion:    record.SchemaVersion,
		SettingsRevision: record.SettingsRevision,
		Values:           values,
		UpdatedAt:        record.UpdatedAt,
	}
}

func normalizeValue(field manifest.SettingFieldSpec, value any) (any, error) {
	switch field.Type {
	case FieldString:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a string", ErrInvalidSetting, field.Key)
		}
		if err := validateString(field, text); err != nil {
			return nil, err
		}
		return text, nil
	case FieldBoolean:
		boolValue, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a boolean", ErrInvalidSetting, field.Key)
		}
		return boolValue, nil
	case FieldNumber:
		number, ok := numberValue(value)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a number", ErrInvalidSetting, field.Key)
		}
		if err := validateNumber(field, number); err != nil {
			return nil, err
		}
		return number, nil
	case FieldInteger:
		number, ok := numberValue(value)
		if !ok || math.Trunc(number) != number {
			return nil, fmt.Errorf("%w: setting %q must be an integer", ErrInvalidSetting, field.Key)
		}
		if err := validateNumber(field, number); err != nil {
			return nil, err
		}
		return int64(number), nil
	case FieldEnum, FieldSelect:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be an option string", ErrInvalidSetting, field.Key)
		}
		for _, option := range field.Options {
			if text == option {
				return text, nil
			}
		}
		return nil, fmt.Errorf("%w: setting %q must match a declared option", ErrInvalidSetting, field.Key)
	case FieldSecret:
		return nil, fmt.Errorf("%w: secret setting %q cannot store plaintext", ErrInvalidSetting, field.Key)
	default:
		return nil, fmt.Errorf("%w: setting %q has unsupported type %q", ErrInvalidSetting, field.Key, field.Type)
	}
}

func validateString(field manifest.SettingFieldSpec, value string) error {
	if min, ok := validationNumber(field.Validation, "min_length"); ok && len(value) < int(min) {
		return fmt.Errorf("%w: setting %q is shorter than min_length", ErrInvalidSetting, field.Key)
	}
	if max, ok := validationNumber(field.Validation, "max_length"); ok && len(value) > int(max) {
		return fmt.Errorf("%w: setting %q exceeds max_length", ErrInvalidSetting, field.Key)
	}
	return nil
}

func validateNumber(field manifest.SettingFieldSpec, value float64) error {
	if min, ok := validationNumber(field.Validation, "minimum"); ok && value < min {
		return fmt.Errorf("%w: setting %q is below minimum", ErrInvalidSetting, field.Key)
	}
	if max, ok := validationNumber(field.Validation, "maximum"); ok && value > max {
		return fmt.Errorf("%w: setting %q exceeds maximum", ErrInvalidSetting, field.Key)
	}
	return nil
}

func validationNumber(values map[string]any, key string) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	return numberValue(values[key])
}

func numberValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

func fieldsByKey(fields []manifest.SettingFieldSpec) map[string]manifest.SettingFieldSpec {
	byKey := make(map[string]manifest.SettingFieldSpec, len(fields))
	for _, field := range fields {
		byKey[field.Key] = field
	}
	return byKey
}

func secretRefDeclared(fields []manifest.SettingFieldSpec, secretRef string) bool {
	for _, field := range fields {
		if field.Type == FieldSecret && strings.TrimSpace(field.SecretRef) == secretRef {
			return true
		}
	}
	return false
}

func supportedType(fieldType string) bool {
	switch fieldType {
	case FieldString, FieldBoolean, FieldNumber, FieldInteger, FieldEnum, FieldSelect, FieldSecret:
		return true
	default:
		return false
	}
}

func cloneFields(fields []manifest.SettingFieldSpec) []manifest.SettingFieldSpec {
	cloned := make([]manifest.SettingFieldSpec, len(fields))
	copy(cloned, fields)
	sort.SliceStable(cloned, func(i, j int) bool { return cloned[i].Key < cloned[j].Key })
	return cloned
}

func cloneValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(v))
		for key, item := range v {
			cloned[key] = cloneValue(item)
		}
		return cloned
	case []any:
		cloned := make([]any, len(v))
		for i, item := range v {
			cloned[i] = cloneValue(item)
		}
		return cloned
	default:
		return v
	}
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
