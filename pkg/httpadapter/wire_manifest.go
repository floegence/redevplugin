package httpadapter

import (
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

type capabilityPinResponse struct {
	PublisherID     string `json:"publisher_id"`
	ContractID      string `json:"contract_id"`
	ContractVersion string `json:"contract_version"`
	ArtifactSHA256  string `json:"artifact_sha256"`
}

func publicCapabilityPin(pin capabilitycontract.Pin) capabilityPinResponse {
	return capabilityPinResponse{
		PublisherID: pin.PublisherID, ContractID: pin.ContractID, ContractVersion: pin.ContractVersion,
		ArtifactSHA256: pin.ArtifactSHA256,
	}
}

func publicCapabilityPins(pins []capabilitycontract.Pin) []capabilityPinResponse {
	responses := make([]capabilityPinResponse, len(pins))
	for index, pin := range pins {
		responses[index] = publicCapabilityPin(pin)
	}
	return responses
}

type packageEntryResponse struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Mode        string `json:"mode"`
	ContentType string `json:"content_type,omitempty"`
}

func publicPackageEntries(entries []pluginpkg.Entry) []packageEntryResponse {
	responses := make([]packageEntryResponse, len(entries))
	for index, entry := range entries {
		responses[index] = packageEntryResponse{
			Path: entry.Path, Size: entry.Size, SHA256: entry.SHA256, Mode: entry.Mode, ContentType: entry.ContentType,
		}
	}
	return responses
}

type manifestPublisherResponse struct {
	PublisherID string `json:"publisher_id"`
	DisplayName string `json:"display_name,omitempty"`
}

type manifestPluginResponse struct {
	PluginID    string `json:"plugin_id"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
}

type manifestAPIResponse struct {
	Major            uint16               `json:"major"`
	RequiredFeatures []manifest.FeatureID `json:"required_features,omitempty"`
	OptionalFeatures []manifest.FeatureID `json:"optional_features,omitempty"`
}

type manifestLocalizedSurfaceResponse struct {
	SurfaceID string `json:"surface_id"`
	Label     string `json:"label"`
}

type manifestLocalizedSettingResponse struct {
	Key     string                       `json:"key"`
	Label   string                       `json:"label"`
	Options []manifest.SettingOptionSpec `json:"options"`
}

type manifestPresentationLocalizationResponse struct {
	Locale        string                             `json:"locale"`
	PluginName    string                             `json:"plugin_name"`
	PublisherName string                             `json:"publisher_name,omitempty"`
	Summary       string                             `json:"summary"`
	Description   []string                           `json:"description"`
	Highlights    []string                           `json:"highlights"`
	Keywords      []string                           `json:"keywords"`
	Surfaces      []manifestLocalizedSurfaceResponse `json:"surfaces"`
	Settings      []manifestLocalizedSettingResponse `json:"settings"`
}

type manifestPresentationResponse struct {
	DefaultLocale string                                     `json:"default_locale"`
	Summary       string                                     `json:"summary"`
	Description   []string                                   `json:"description"`
	Highlights    []string                                   `json:"highlights"`
	Keywords      []string                                   `json:"keywords"`
	Icon          *manifestPresentationIconResponse          `json:"icon,omitempty"`
	Localizations []manifestPresentationLocalizationResponse `json:"localizations"`
}

type manifestPresentationIconResponse struct {
	Path string `json:"path"`
}

type presentationLocaleResponse struct {
	Locale        string                             `json:"locale"`
	PluginName    string                             `json:"plugin_name"`
	PublisherName string                             `json:"publisher_name,omitempty"`
	Summary       string                             `json:"summary"`
	Description   []string                           `json:"description"`
	Highlights    []string                           `json:"highlights"`
	Keywords      []string                           `json:"keywords"`
	Surfaces      []manifestLocalizedSurfaceResponse `json:"surfaces"`
	Settings      []manifestLocalizedSettingResponse `json:"settings"`
}

type presentationCatalogResponse struct {
	DefaultLocale string                            `json:"default_locale"`
	Locales       []presentationLocaleResponse      `json:"locales"`
	Icon          *manifestPresentationIconResponse `json:"icon,omitempty"`
}

type manifestWidgetSizeResponse struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type manifestSurfaceResponse struct {
	SurfaceID   string                      `json:"surface_id"`
	Kind        string                      `json:"kind"`
	Intent      string                      `json:"intent,omitempty"`
	Label       string                      `json:"label"`
	Entry       string                      `json:"entry"`
	Icon        string                      `json:"icon,omitempty"`
	DefaultSize *manifestWidgetSizeResponse `json:"default_size,omitempty"`
}

type manifestCapabilityBindingResponse struct {
	BindingID string                `json:"binding_id"`
	Contract  capabilityPinResponse `json:"contract"`
}

type manifestMethodRouteResponse struct {
	Kind         string `json:"kind"`
	BindingID    string `json:"binding_id,omitempty"`
	TargetMethod string `json:"target_method,omitempty"`
	WorkerID     string `json:"worker_id,omitempty"`
	ActionID     string `json:"action_id,omitempty"`
}

type manifestConfirmationResponse struct {
	Mode              string   `json:"mode"`
	PreflightMethod   *string  `json:"preflight_method,omitempty"`
	RequestHashFields []string `json:"request_hash_fields,omitempty"`
	PlanHashRequired  bool     `json:"plan_hash_required,omitempty"`
}

type manifestCancelPolicyResponse struct {
	Cancelable        bool   `json:"cancelable"`
	DisableBehavior   string `json:"disable_behavior,omitempty"`
	UninstallBehavior string `json:"uninstall_behavior,omitempty"`
	AckTimeoutMS      int    `json:"ack_timeout_ms,omitempty"`
}

type manifestStorageAccessResponse struct {
	StoreID    string   `json:"store_id"`
	Operations []string `json:"operations"`
}

type manifestNetworkAccessResponse struct {
	ConnectorID string   `json:"connector_id"`
	Transport   string   `json:"transport"`
	Scope       string   `json:"scope,omitempty"`
	Operations  []string `json:"operations"`
	HTTPMethods []string `json:"http_methods,omitempty"`
}

type manifestMethodBrokerAccessResponse struct {
	Storage []manifestStorageAccessResponse `json:"storage,omitempty"`
	Network []manifestNetworkAccessResponse `json:"network,omitempty"`
}

type manifestMethodResponse struct {
	Method         string                              `json:"method"`
	Effect         string                              `json:"effect,omitempty"`
	Execution      string                              `json:"execution,omitempty"`
	Dangerous      bool                                `json:"dangerous,omitempty"`
	PreflightOnly  bool                                `json:"preflight_only,omitempty"`
	Confirmation   *manifestConfirmationResponse       `json:"confirmation,omitempty"`
	CancelPolicy   *manifestCancelPolicyResponse       `json:"cancel_policy,omitempty"`
	RequestSchema  map[string]any                      `json:"request_schema,omitempty"`
	ResponseSchema map[string]any                      `json:"response_schema,omitempty"`
	Route          manifestMethodRouteResponse         `json:"route"`
	BrokerAccess   *manifestMethodBrokerAccessResponse `json:"broker_access,omitempty"`
}

type manifestWorkerResponse struct {
	WorkerID         string `json:"worker_id"`
	Artifact         string `json:"artifact"`
	Mode             string `json:"mode"`
	Scope            string `json:"scope"`
	MemoryLimitBytes int64  `json:"memory_limit_bytes"`
	IdleTimeoutMS    int    `json:"idle_timeout_ms,omitempty"`
}

type manifestStoreResponse struct {
	StoreID       string `json:"store_id"`
	Kind          string `json:"kind"`
	Scope         string `json:"scope"`
	QuotaBytes    int64  `json:"quota_bytes"`
	QuotaFiles    *int64 `json:"quota_files,omitempty"`
	SchemaVersion int    `json:"schema_version"`
}

type manifestStorageResponse struct {
	Stores []manifestStoreResponse `json:"stores,omitempty"`
}

type manifestConnectorResponse struct {
	ConnectorID  string         `json:"connector_id"`
	Transport    string         `json:"transport"`
	Scope        string         `json:"scope"`
	Destinations []string       `json:"destinations"`
	Auth         map[string]any `json:"auth,omitempty"`
	TLS          map[string]any `json:"tls,omitempty"`
}

type manifestNetworkResponse struct {
	Connectors []manifestConnectorResponse `json:"connectors,omitempty"`
}

type manifestSettingFieldResponse struct {
	Key        string                       `json:"key"`
	Type       string                       `json:"type"`
	Label      string                       `json:"label"`
	Scope      string                       `json:"scope"`
	Default    any                          `json:"default,omitempty"`
	SecretRef  string                       `json:"secret_ref,omitempty"`
	Options    []manifest.SettingOptionSpec `json:"options,omitempty"`
	Validation map[string]any               `json:"validation,omitempty"`
}

type manifestSettingsResponse struct {
	SchemaVersion int                            `json:"schema_version"`
	Fields        []manifestSettingFieldResponse `json:"fields,omitempty"`
}

type manifestIntentResponse struct {
	IntentID      string         `json:"intent_id"`
	Method        string         `json:"method"`
	PayloadSchema map[string]any `json:"payload_schema,omitempty"`
}

type manifestResponse struct {
	SchemaVersion      string                              `json:"schema_version"`
	Publisher          manifestPublisherResponse           `json:"publisher"`
	Plugin             manifestPluginResponse              `json:"plugin"`
	API                manifestAPIResponse                 `json:"api"`
	Permissions        []manifest.PermissionID             `json:"permissions"`
	Presentation       manifestPresentationResponse        `json:"presentation"`
	Surfaces           []manifestSurfaceResponse           `json:"surfaces,omitempty"`
	CapabilityBindings []manifestCapabilityBindingResponse `json:"capability_bindings,omitempty"`
	Methods            []manifestMethodResponse            `json:"methods,omitempty"`
	Workers            []manifestWorkerResponse            `json:"workers,omitempty"`
	Storage            *manifestStorageResponse            `json:"storage,omitempty"`
	NetworkAccess      *manifestNetworkResponse            `json:"network_access,omitempty"`
	Settings           *manifestSettingsResponse           `json:"settings,omitempty"`
	Intents            []manifestIntentResponse            `json:"intents,omitempty"`
}

func publicManifest(source manifest.Manifest) (manifestResponse, error) {
	response := manifestResponse{
		SchemaVersion: source.SchemaVersion,
		Publisher: manifestPublisherResponse{
			PublisherID: source.Publisher.PublisherID, DisplayName: source.Publisher.DisplayName,
		},
		Plugin: manifestPluginResponse{
			PluginID: source.Plugin.PluginID, DisplayName: source.Plugin.DisplayName, Version: source.Plugin.Version,
		},
		API: manifestAPIResponse{
			Major: source.API.Major, RequiredFeatures: append([]manifest.FeatureID(nil), source.API.RequiredFeatures...),
			OptionalFeatures: append([]manifest.FeatureID(nil), source.API.OptionalFeatures...),
		},
		Permissions:  append([]manifest.PermissionID(nil), source.Permissions...),
		Presentation: publicManifestPresentation(source.Presentation),
	}
	response.Surfaces = make([]manifestSurfaceResponse, len(source.Surfaces))
	for index, surface := range source.Surfaces {
		mapped := manifestSurfaceResponse{
			SurfaceID: surface.SurfaceID, Kind: string(surface.Kind), Intent: string(surface.Intent),
			Label: surface.Label, Entry: surface.Entry, Icon: surface.Icon,
		}
		if surface.DefaultSize != nil {
			mapped.DefaultSize = &manifestWidgetSizeResponse{Width: surface.DefaultSize.Width, Height: surface.DefaultSize.Height}
		}
		response.Surfaces[index] = mapped
	}
	response.CapabilityBindings = make([]manifestCapabilityBindingResponse, len(source.CapabilityBindings))
	for index, binding := range source.CapabilityBindings {
		response.CapabilityBindings[index] = manifestCapabilityBindingResponse{
			BindingID: binding.BindingID, Contract: publicCapabilityPin(binding.Contract),
		}
	}
	response.Methods = make([]manifestMethodResponse, len(source.Methods))
	for index, method := range source.Methods {
		requestSchema, err := cloneWireJSONMap(method.RequestSchema)
		if err != nil {
			return manifestResponse{}, err
		}
		responseSchema, err := cloneWireJSONMap(method.ResponseSchema)
		if err != nil {
			return manifestResponse{}, err
		}
		mapped := manifestMethodResponse{
			Method: method.Method, Effect: string(method.Effect), Execution: string(method.Execution),
			Dangerous: method.Dangerous, PreflightOnly: method.PreflightOnly,
			RequestSchema: requestSchema, ResponseSchema: responseSchema,
			Route: manifestMethodRouteResponse{
				Kind: string(method.Route.Kind), BindingID: method.Route.BindingID, TargetMethod: method.Route.TargetMethod,
				WorkerID: method.Route.WorkerID, ActionID: method.Route.ActionID,
			},
		}
		if method.Confirmation != nil {
			mapped.Confirmation = &manifestConfirmationResponse{
				Mode: string(method.Confirmation.Mode), PreflightMethod: cloneWireString(method.Confirmation.PreflightMethod),
				RequestHashFields: append([]string(nil), method.Confirmation.RequestHashFields...),
				PlanHashRequired:  method.Confirmation.PlanHashRequired,
			}
		}
		if method.CancelPolicy != nil {
			mapped.CancelPolicy = &manifestCancelPolicyResponse{
				Cancelable: method.CancelPolicy.Cancelable, DisableBehavior: method.CancelPolicy.DisableBehavior,
				UninstallBehavior: method.CancelPolicy.UninstallBehavior, AckTimeoutMS: method.CancelPolicy.AckTimeoutMS,
			}
		}
		if method.BrokerAccess != nil {
			access := &manifestMethodBrokerAccessResponse{
				Storage: make([]manifestStorageAccessResponse, len(method.BrokerAccess.Storage)),
				Network: make([]manifestNetworkAccessResponse, len(method.BrokerAccess.Network)),
			}
			for storageIndex, storage := range method.BrokerAccess.Storage {
				access.Storage[storageIndex] = manifestStorageAccessResponse{
					StoreID: storage.StoreID, Operations: append([]string(nil), storage.Operations...),
				}
			}
			for networkIndex, network := range method.BrokerAccess.Network {
				access.Network[networkIndex] = manifestNetworkAccessResponse{
					ConnectorID: network.ConnectorID, Transport: network.Transport, Scope: network.Scope,
					Operations: append([]string(nil), network.Operations...), HTTPMethods: append([]string(nil), network.HTTPMethods...),
				}
			}
			mapped.BrokerAccess = access
		}
		response.Methods[index] = mapped
	}
	response.Workers = make([]manifestWorkerResponse, len(source.Workers))
	for index, worker := range source.Workers {
		response.Workers[index] = manifestWorkerResponse{
			WorkerID: worker.WorkerID, Artifact: worker.Artifact, Mode: string(worker.Mode),
			Scope: worker.Scope, MemoryLimitBytes: worker.MemoryLimitBytes, IdleTimeoutMS: worker.IdleTimeoutMS,
		}
	}
	if source.Storage != nil {
		storage := &manifestStorageResponse{Stores: make([]manifestStoreResponse, len(source.Storage.Stores))}
		for index, store := range source.Storage.Stores {
			storage.Stores[index] = manifestStoreResponse{
				StoreID: store.StoreID, Kind: store.Kind, Scope: store.Scope, QuotaBytes: store.QuotaBytes,
				QuotaFiles: cloneWireInt64(store.QuotaFiles), SchemaVersion: store.SchemaVersion,
			}
		}
		response.Storage = storage
	}
	if source.NetworkAccess != nil {
		network := &manifestNetworkResponse{Connectors: make([]manifestConnectorResponse, len(source.NetworkAccess.Connectors))}
		for index, connector := range source.NetworkAccess.Connectors {
			auth, err := cloneWireJSONMap(connector.Auth)
			if err != nil {
				return manifestResponse{}, err
			}
			tls, err := cloneWireJSONMap(connector.TLS)
			if err != nil {
				return manifestResponse{}, err
			}
			network.Connectors[index] = manifestConnectorResponse{
				ConnectorID: connector.ConnectorID, Transport: connector.Transport, Scope: connector.Scope,
				Destinations: append([]string(nil), connector.Destinations...), Auth: auth, TLS: tls,
			}
		}
		response.NetworkAccess = network
	}
	if source.Settings != nil {
		settings := &manifestSettingsResponse{
			SchemaVersion: source.Settings.SchemaVersion,
			Fields:        make([]manifestSettingFieldResponse, len(source.Settings.Fields)),
		}
		for index, field := range source.Settings.Fields {
			defaultValue, err := cloneWireJSONValue(field.Default)
			if err != nil {
				return manifestResponse{}, err
			}
			validation, err := cloneWireJSONMap(field.Validation)
			if err != nil {
				return manifestResponse{}, err
			}
			settings.Fields[index] = manifestSettingFieldResponse{
				Key: field.Key, Type: field.Type, Label: field.Label, Scope: field.Scope, Default: defaultValue,
				SecretRef: field.SecretRef, Options: append([]manifest.SettingOptionSpec(nil), field.Options...), Validation: validation,
			}
		}
		response.Settings = settings
	}
	response.Intents = make([]manifestIntentResponse, len(source.Intents))
	for index, intent := range source.Intents {
		payloadSchema, err := cloneWireJSONMap(intent.PayloadSchema)
		if err != nil {
			return manifestResponse{}, err
		}
		response.Intents[index] = manifestIntentResponse{
			IntentID: intent.IntentID, Method: intent.Method, PayloadSchema: payloadSchema,
		}
	}
	return response, nil
}

func publicManifestPresentation(source manifest.PresentationSpec) manifestPresentationResponse {
	localizations := make([]manifestPresentationLocalizationResponse, len(source.Localizations))
	for index, localization := range source.Localizations {
		surfaces := make([]manifestLocalizedSurfaceResponse, len(localization.Surfaces))
		for surfaceIndex, surface := range localization.Surfaces {
			surfaces[surfaceIndex] = manifestLocalizedSurfaceResponse{SurfaceID: surface.SurfaceID, Label: surface.Label}
		}
		settings := make([]manifestLocalizedSettingResponse, len(localization.Settings))
		for settingIndex, setting := range localization.Settings {
			settings[settingIndex] = manifestLocalizedSettingResponse{
				Key: setting.Key, Label: setting.Label, Options: cloneRequiredWireArray(setting.Options),
			}
		}
		localizations[index] = manifestPresentationLocalizationResponse{
			Locale: localization.Locale, PluginName: localization.PluginName, PublisherName: localization.PublisherName,
			Summary: localization.Summary, Description: cloneRequiredWireArray(localization.Description),
			Highlights: cloneRequiredWireArray(localization.Highlights), Keywords: cloneRequiredWireArray(localization.Keywords),
			Surfaces: surfaces, Settings: settings,
		}
	}
	return manifestPresentationResponse{
		DefaultLocale: source.DefaultLocale, Summary: source.Summary,
		Description: cloneRequiredWireArray(source.Description), Highlights: cloneRequiredWireArray(source.Highlights),
		Keywords: cloneRequiredWireArray(source.Keywords), Icon: publicPresentationIcon(source.Icon), Localizations: localizations,
	}
}

func publicPresentationIcon(source *manifest.PresentationIconSpec) *manifestPresentationIconResponse {
	if source == nil {
		return nil
	}
	return &manifestPresentationIconResponse{Path: source.Path}
}

func publicPresentationCatalog(source manifest.PresentationCatalog) presentationCatalogResponse {
	locales := make([]presentationLocaleResponse, len(source.Locales))
	for index, locale := range source.Locales {
		surfaces := make([]manifestLocalizedSurfaceResponse, len(locale.Surfaces))
		for surfaceIndex, surface := range locale.Surfaces {
			surfaces[surfaceIndex] = manifestLocalizedSurfaceResponse{SurfaceID: surface.SurfaceID, Label: surface.Label}
		}
		settings := make([]manifestLocalizedSettingResponse, len(locale.Settings))
		for settingIndex, setting := range locale.Settings {
			settings[settingIndex] = manifestLocalizedSettingResponse{
				Key: setting.Key, Label: setting.Label, Options: cloneRequiredWireArray(setting.Options),
			}
		}
		locales[index] = presentationLocaleResponse{
			Locale: locale.Locale, PluginName: locale.PluginName, PublisherName: locale.PublisherName,
			Summary: locale.Summary, Description: cloneRequiredWireArray(locale.Description),
			Highlights: cloneRequiredWireArray(locale.Highlights), Keywords: cloneRequiredWireArray(locale.Keywords),
			Surfaces: surfaces, Settings: settings,
		}
	}
	return presentationCatalogResponse{DefaultLocale: source.DefaultLocale, Locales: locales, Icon: publicPresentationIcon(source.Icon)}
}

func cloneRequiredWireArray[T any](source []T) []T {
	result := make([]T, len(source))
	copy(result, source)
	return result
}

type opaqueSurfaceStyleResponse struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}

type opaqueSurfaceWorkerResponse struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type opaqueSurfaceAssetResponse struct {
	BindingID   string   `json:"binding_id"`
	LogicalIDs  []string `json:"logical_ids"`
	Path        string   `json:"path"`
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	ContentType string   `json:"content_type"`
}

type opaqueSurfaceDocumentResponse struct {
	SchemaVersion string                       `json:"schema_version"`
	EntryPath     string                       `json:"entry_path"`
	EntrySHA256   string                       `json:"entry_sha256"`
	Title         string                       `json:"title,omitempty"`
	Language      string                       `json:"language,omitempty"`
	Direction     string                       `json:"direction,omitempty"`
	BodyHTML      string                       `json:"body_html"`
	Styles        []opaqueSurfaceStyleResponse `json:"styles"`
	Worker        opaqueSurfaceWorkerResponse  `json:"worker"`
	Assets        []opaqueSurfaceAssetResponse `json:"assets"`
	CriticalBytes int64                        `json:"critical_bytes"`
}

func publicOpaqueSurfaceDocument(source pluginpkg.OpaqueSurfaceDocument) opaqueSurfaceDocumentResponse {
	response := opaqueSurfaceDocumentResponse{
		SchemaVersion: source.SchemaVersion, EntryPath: source.EntryPath, EntrySHA256: source.EntrySHA256,
		Title: source.Title, Language: source.Language, Direction: source.Direction, BodyHTML: source.BodyHTML,
		Worker: opaqueSurfaceWorkerResponse{
			Path: source.Worker.Path, SHA256: source.Worker.SHA256, Type: string(source.Worker.Type), Content: source.Worker.Content,
		},
		CriticalBytes: source.CriticalBytes,
	}
	response.Styles = make([]opaqueSurfaceStyleResponse, len(source.Styles))
	for index, style := range source.Styles {
		response.Styles[index] = opaqueSurfaceStyleResponse{Path: style.Path, SHA256: style.SHA256, Content: style.Content}
	}
	response.Assets = make([]opaqueSurfaceAssetResponse, len(source.Assets))
	for index, asset := range source.Assets {
		response.Assets[index] = opaqueSurfaceAssetResponse{
			BindingID: asset.BindingID, LogicalIDs: append([]string(nil), asset.LogicalIDs...),
			Path: asset.Path, SHA256: asset.SHA256, Size: asset.Size, ContentType: asset.ContentType,
		}
	}
	return response
}
