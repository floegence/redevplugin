package releaseprojection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

type PackageHashSet struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type ExternalPackageIntent struct {
	Action                     string `json:"action"`
	PluginInstanceID           string `json:"plugin_instance_id,omitempty"`
	ExpectedManagementRevision uint64 `json:"expected_management_revision,omitempty"`
}

type ExternalPackageSignatureAssessment struct {
	State           string         `json:"state"`
	ReasonCodes     []string       `json:"reason_codes"`
	AssessedHashes  PackageHashSet `json:"assessed_hashes"`
	Algorithm       string         `json:"algorithm,omitempty"`
	KeyID           string         `json:"key_id,omitempty"`
	AssessedAt      time.Time      `json:"assessed_at"`
	AssessmentEpoch string         `json:"assessment_epoch,omitempty"`
}

type ExternalPackageRedirectHop struct {
	Origin string `json:"origin"`
	Path   string `json:"path"`
}

type ExternalPackageSourceProvenance struct {
	Kind              string                       `json:"kind"`
	UploadID          string                       `json:"upload_id,omitempty"`
	SourceOrigin      string                       `json:"source_origin,omitempty"`
	SourcePath        string                       `json:"source_path,omitempty"`
	RedirectChain     []ExternalPackageRedirectHop `json:"redirect_chain,omitempty"`
	RepositoryID      string                       `json:"repository_id,omitempty"`
	ReleaseID         string                       `json:"release_id,omitempty"`
	AssetID           string                       `json:"asset_id,omitempty"`
	RepositoryURL     string                       `json:"repository_url,omitempty"`
	Owner             string                       `json:"owner,omitempty"`
	Repository        string                       `json:"repository,omitempty"`
	ResolvedCommitSHA string                       `json:"resolved_commit_sha,omitempty"`
	ReleaseTag        string                       `json:"release_tag,omitempty"`
	AssetName         string                       `json:"asset_name,omitempty"`
	PackageSHA256     string                       `json:"package_sha256"`
	ResolvedAt        time.Time                    `json:"resolved_at"`
}

func (provenance ExternalPackageSourceProvenance) MarshalJSON() ([]byte, error) {
	type packageURLProvenance struct {
		Kind          string                       `json:"kind"`
		SourceOrigin  string                       `json:"source_origin"`
		SourcePath    string                       `json:"source_path"`
		RedirectChain []ExternalPackageRedirectHop `json:"redirect_chain"`
		PackageSHA256 string                       `json:"package_sha256"`
		ResolvedAt    time.Time                    `json:"resolved_at"`
	}
	type packageUploadProvenance struct {
		Kind          string    `json:"kind"`
		UploadID      string    `json:"upload_id"`
		PackageSHA256 string    `json:"package_sha256"`
		ResolvedAt    time.Time `json:"resolved_at"`
	}
	type githubRepositoryProvenance struct {
		Kind              string    `json:"kind"`
		RepositoryID      string    `json:"repository_id"`
		ReleaseID         string    `json:"release_id"`
		AssetID           string    `json:"asset_id"`
		RepositoryURL     string    `json:"repository_url"`
		Owner             string    `json:"owner"`
		Repository        string    `json:"repository"`
		ResolvedCommitSHA string    `json:"resolved_commit_sha"`
		ReleaseTag        string    `json:"release_tag,omitempty"`
		AssetName         string    `json:"asset_name,omitempty"`
		PackageSHA256     string    `json:"package_sha256"`
		ResolvedAt        time.Time `json:"resolved_at"`
	}

	switch provenance.Kind {
	case "package_url":
		if provenance.UploadID != "" || provenance.RepositoryID != "" || provenance.ReleaseID != "" || provenance.AssetID != "" ||
			provenance.RepositoryURL != "" || provenance.Owner != "" || provenance.Repository != "" || provenance.ResolvedCommitSHA != "" ||
			provenance.ReleaseTag != "" || provenance.AssetName != "" {
			return nil, fmt.Errorf("package URL provenance contains fields for another source kind")
		}
		redirects := provenance.RedirectChain
		if redirects == nil {
			redirects = []ExternalPackageRedirectHop{}
		}
		return json.Marshal(packageURLProvenance{
			Kind: provenance.Kind, SourceOrigin: provenance.SourceOrigin, SourcePath: provenance.SourcePath,
			RedirectChain: redirects, PackageSHA256: provenance.PackageSHA256, ResolvedAt: provenance.ResolvedAt,
		})
	case "package_upload":
		if provenance.SourceOrigin != "" || provenance.SourcePath != "" || len(provenance.RedirectChain) != 0 ||
			provenance.RepositoryID != "" || provenance.ReleaseID != "" || provenance.AssetID != "" || provenance.RepositoryURL != "" ||
			provenance.Owner != "" || provenance.Repository != "" || provenance.ResolvedCommitSHA != "" || provenance.ReleaseTag != "" || provenance.AssetName != "" {
			return nil, fmt.Errorf("uploaded-package provenance contains fields for another source kind")
		}
		return json.Marshal(packageUploadProvenance{
			Kind: provenance.Kind, UploadID: provenance.UploadID, PackageSHA256: provenance.PackageSHA256, ResolvedAt: provenance.ResolvedAt,
		})
	case "github_repository":
		if provenance.UploadID != "" || provenance.SourceOrigin != "" || provenance.SourcePath != "" || len(provenance.RedirectChain) != 0 {
			return nil, fmt.Errorf("GitHub repository provenance contains fields for another source kind")
		}
		return json.Marshal(githubRepositoryProvenance{
			Kind: provenance.Kind, RepositoryID: provenance.RepositoryID, ReleaseID: provenance.ReleaseID, AssetID: provenance.AssetID,
			RepositoryURL: provenance.RepositoryURL, Owner: provenance.Owner, Repository: provenance.Repository,
			ResolvedCommitSHA: provenance.ResolvedCommitSHA, ReleaseTag: provenance.ReleaseTag, AssetName: provenance.AssetName,
			PackageSHA256: provenance.PackageSHA256, ResolvedAt: provenance.ResolvedAt,
		})
	default:
		return nil, fmt.Errorf("unsupported external package provenance kind %q", provenance.Kind)
	}
}

type ExternalPackageExecutionApproval struct {
	State       string     `json:"state"`
	ReasonCodes []string   `json:"reason_codes"`
	AssessedAt  time.Time  `json:"assessed_at"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
}

type ExternalPackageUpdateEligibility struct {
	State       string    `json:"state"`
	ReasonCodes []string  `json:"reason_codes"`
	AssessedAt  time.Time `json:"assessed_at"`
}

type ExternalPackagePermissionSummary struct {
	PermissionID string   `json:"permission_id"`
	Methods      []string `json:"methods"`
	Required     bool     `json:"required"`
	Effects      []string `json:"effects"`
}

type ExternalPackageMethodRouteSummary struct {
	Kind         string `json:"kind"`
	BindingID    string `json:"binding_id,omitempty"`
	TargetMethod string `json:"target_method,omitempty"`
	WorkerID     string `json:"worker_id,omitempty"`
	ActionID     string `json:"action_id,omitempty"`
}

type ExternalPackageConfirmationSummary struct {
	Mode              string   `json:"mode"`
	PreflightMethod   string   `json:"preflight_method,omitempty"`
	RequestHashFields []string `json:"request_hash_fields"`
	PlanHashRequired  bool     `json:"plan_hash_required"`
}

type ExternalPackageCancelSummary struct {
	Cancelable        bool   `json:"cancelable"`
	DisableBehavior   string `json:"disable_behavior"`
	UninstallBehavior string `json:"uninstall_behavior"`
	AckTimeoutMS      int    `json:"ack_timeout_ms"`
}

type ExternalPackageMethodSummary struct {
	Method              string                             `json:"method"`
	Route               ExternalPackageMethodRouteSummary  `json:"route"`
	Effect              string                             `json:"effect"`
	Execution           string                             `json:"execution"`
	Dangerous           bool                               `json:"dangerous"`
	PreflightOnly       bool                               `json:"preflight_only"`
	RequiredPermissions []string                           `json:"required_permissions"`
	Confirmation        ExternalPackageConfirmationSummary `json:"confirmation"`
	Cancel              *ExternalPackageCancelSummary      `json:"cancel,omitempty"`
}

type ExternalPackageCapabilityContractSummary struct {
	BindingID         string `json:"binding_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ContractSHA256    string `json:"contract_sha256"`
}

type ExternalPackageWorkerSummary struct {
	WorkerID         string `json:"worker_id"`
	Artifact         string `json:"artifact"`
	Mode             string `json:"mode"`
	Scope            string `json:"scope"`
	MemoryLimitBytes int64  `json:"memory_limit_bytes"`
	IdleTimeoutMS    int    `json:"idle_timeout_ms"`
}

type ExternalPackageNetworkMethodAccessSummary struct {
	Method      string   `json:"method"`
	Operations  []string `json:"operations"`
	HTTPMethods []string `json:"http_methods"`
}

type ExternalPackageNetworkSummary struct {
	ConnectorID  string                                      `json:"connector_id"`
	Transport    string                                      `json:"transport"`
	Scope        string                                      `json:"scope"`
	Destinations []string                                    `json:"destinations"`
	AuthDeclared bool                                        `json:"auth_declared"`
	TLSDeclared  bool                                        `json:"tls_declared"`
	MethodAccess []ExternalPackageNetworkMethodAccessSummary `json:"method_access"`
}

type ExternalPackageStorageMethodAccessSummary struct {
	Method     string   `json:"method"`
	Operations []string `json:"operations"`
}

type ExternalPackageStorageSummary struct {
	StoreID       string                                      `json:"store_id"`
	Kind          string                                      `json:"kind"`
	Scope         string                                      `json:"scope"`
	QuotaBytes    int64                                       `json:"quota_bytes"`
	QuotaFiles    *int64                                      `json:"quota_files,omitempty"`
	SchemaVersion int                                         `json:"schema_version"`
	MethodAccess  []ExternalPackageStorageMethodAccessSummary `json:"method_access"`
}

type ExternalPackageSecretRefSummary struct {
	SettingKey string `json:"setting_key"`
	SecretRef  string `json:"secret_ref"`
	Scope      string `json:"scope"`
}

type ExternalPackageCoreActionSummary struct {
	Method   string `json:"method"`
	ActionID string `json:"action_id"`
	Effect   string `json:"effect"`
}

type ExternalPackageIntentSummary struct {
	IntentID string `json:"intent_id"`
	Method   string `json:"method"`
}

type ExternalPackageSurfaceSummary struct {
	SurfaceID   string                      `json:"surface_id"`
	Kind        string                      `json:"kind"`
	Intent      string                      `json:"intent"`
	Label       string                      `json:"label"`
	Entry       string                      `json:"entry"`
	Icon        string                      `json:"icon,omitempty"`
	DefaultSize *ExternalPackageSizeSummary `json:"default_size,omitempty"`
}

type ExternalPackageSizeSummary struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type ExternalPackageSecuritySummary struct {
	SummarySHA256       string                                     `json:"summary_sha256"`
	Permissions         []ExternalPackagePermissionSummary         `json:"permissions"`
	Methods             []ExternalPackageMethodSummary             `json:"methods"`
	CapabilityContracts []ExternalPackageCapabilityContractSummary `json:"capability_contracts"`
	Workers             []ExternalPackageWorkerSummary             `json:"workers"`
	Network             []ExternalPackageNetworkSummary            `json:"network"`
	Storage             []ExternalPackageStorageSummary            `json:"storage"`
	SecretRefs          []ExternalPackageSecretRefSummary          `json:"secret_refs"`
	CoreActions         []ExternalPackageCoreActionSummary         `json:"core_actions"`
	Intents             []ExternalPackageIntentSummary             `json:"intents"`
	Surfaces            []ExternalPackageSurfaceSummary            `json:"surfaces"`
}

// buildExternalPackageSecuritySummary is deterministic for semantically equal
// inputs. Capability methods must already contain their resolved effective
// method policy; required supplies the separately resolved permission set.
func buildExternalPackageSecuritySummary(m manifest.Manifest, pins []capabilitycontract.Pin, required map[string][]string) (ExternalPackageSecuritySummary, error) {
	methodsByName := make(map[string]struct{}, len(m.Methods))
	for _, method := range m.Methods {
		methodsByName[method.Method] = struct{}{}
	}
	for method := range required {
		if _, ok := methodsByName[method]; !ok {
			return ExternalPackageSecuritySummary{}, fmt.Errorf("external package permissions reference unknown method %q", method)
		}
	}

	storageAccess := map[string][]ExternalPackageStorageMethodAccessSummary{}
	networkAccess := map[string][]ExternalPackageNetworkMethodAccessSummary{}
	methods := make([]ExternalPackageMethodSummary, 0, len(m.Methods))
	permissionMethods := map[string][]string{}
	permissionEffects := map[string][]string{}
	coreActions := make([]ExternalPackageCoreActionSummary, 0)
	for _, method := range m.Methods {
		permissions := canonicalExternalPackageStrings(required[method.Method])
		for _, permission := range permissions {
			permissionMethods[permission] = append(permissionMethods[permission], method.Method)
			permissionEffects[permission] = append(permissionEffects[permission], string(method.Effect))
		}
		confirmation := ExternalPackageConfirmationSummary{Mode: string(manifest.ConfirmationNone), RequestHashFields: []string{}}
		if method.Confirmation != nil {
			confirmation.Mode = string(method.Confirmation.Mode)
			if method.Confirmation.PreflightMethod != nil {
				confirmation.PreflightMethod = *method.Confirmation.PreflightMethod
			}
			confirmation.RequestHashFields = canonicalExternalPackageStrings(method.Confirmation.RequestHashFields)
			confirmation.PlanHashRequired = method.Confirmation.PlanHashRequired
		}
		var cancel *ExternalPackageCancelSummary
		if method.CancelPolicy != nil {
			cancel = &ExternalPackageCancelSummary{
				Cancelable:        method.CancelPolicy.Cancelable,
				DisableBehavior:   method.CancelPolicy.DisableBehavior,
				UninstallBehavior: method.CancelPolicy.UninstallBehavior,
				AckTimeoutMS:      method.CancelPolicy.AckTimeoutMS,
			}
		}
		methods = append(methods, ExternalPackageMethodSummary{
			Method: method.Method,
			Route: ExternalPackageMethodRouteSummary{
				Kind:         string(method.Route.Kind),
				BindingID:    method.Route.BindingID,
				TargetMethod: method.Route.TargetMethod,
				WorkerID:     method.Route.WorkerID,
				ActionID:     method.Route.ActionID,
			},
			Effect:              string(method.Effect),
			Execution:           string(method.Execution),
			Dangerous:           method.Dangerous,
			PreflightOnly:       method.PreflightOnly,
			RequiredPermissions: permissions,
			Confirmation:        confirmation,
			Cancel:              cancel,
		})
		if method.Route.Kind == manifest.MethodRouteCoreAction {
			coreActions = append(coreActions, ExternalPackageCoreActionSummary{Method: method.Method, ActionID: method.Route.ActionID, Effect: string(method.Effect)})
		}
		if method.BrokerAccess == nil {
			continue
		}
		for _, access := range method.BrokerAccess.Storage {
			storageAccess[access.StoreID] = append(storageAccess[access.StoreID], ExternalPackageStorageMethodAccessSummary{
				Method: method.Method, Operations: canonicalExternalPackageStrings(access.Operations),
			})
		}
		for _, access := range method.BrokerAccess.Network {
			key := externalPackageNetworkKey(access.ConnectorID, access.Transport)
			networkAccess[key] = append(networkAccess[key], ExternalPackageNetworkMethodAccessSummary{
				Method: method.Method, Operations: canonicalExternalPackageStrings(access.Operations), HTTPMethods: canonicalExternalPackageStrings(access.HTTPMethods),
			})
		}
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i].Method < methods[j].Method })
	sort.Slice(coreActions, func(i, j int) bool {
		if coreActions[i].ActionID == coreActions[j].ActionID {
			return coreActions[i].Method < coreActions[j].Method
		}
		return coreActions[i].ActionID < coreActions[j].ActionID
	})

	permissions := make([]ExternalPackagePermissionSummary, 0, len(permissionMethods))
	for permission, names := range permissionMethods {
		permissions = append(permissions, ExternalPackagePermissionSummary{
			PermissionID: permission,
			Methods:      canonicalExternalPackageStrings(names),
			Required:     true,
			Effects:      canonicalExternalPackageStrings(permissionEffects[permission]),
		})
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i].PermissionID < permissions[j].PermissionID })

	capabilityContracts, err := externalPackageCapabilitySummaries(m.CapabilityBindings, pins)
	if err != nil {
		return ExternalPackageSecuritySummary{}, err
	}

	workers := make([]ExternalPackageWorkerSummary, 0, len(m.Workers))
	for _, worker := range m.Workers {
		workers = append(workers, ExternalPackageWorkerSummary{
			WorkerID: worker.WorkerID, Artifact: worker.Artifact, Mode: string(worker.Mode), Scope: worker.Scope,
			MemoryLimitBytes: worker.MemoryLimitBytes, IdleTimeoutMS: worker.IdleTimeoutMS,
		})
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].WorkerID < workers[j].WorkerID })

	network, err := externalPackageNetworkSummaries(m.NetworkAccess, networkAccess)
	if err != nil {
		return ExternalPackageSecuritySummary{}, err
	}
	storage, err := externalPackageStorageSummaries(m.Storage, storageAccess)
	if err != nil {
		return ExternalPackageSecuritySummary{}, err
	}

	secretRefs := make([]ExternalPackageSecretRefSummary, 0)
	if m.Settings != nil {
		for _, field := range m.Settings.Fields {
			if field.SecretRef != "" {
				secretRefs = append(secretRefs, ExternalPackageSecretRefSummary{SettingKey: field.Key, SecretRef: field.SecretRef, Scope: field.Scope})
			}
		}
	}
	sort.Slice(secretRefs, func(i, j int) bool {
		if secretRefs[i].SettingKey == secretRefs[j].SettingKey {
			return secretRefs[i].Scope < secretRefs[j].Scope
		}
		return secretRefs[i].SettingKey < secretRefs[j].SettingKey
	})

	intents := make([]ExternalPackageIntentSummary, 0, len(m.Intents))
	for _, intent := range m.Intents {
		intents = append(intents, ExternalPackageIntentSummary{IntentID: intent.IntentID, Method: intent.Method})
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].IntentID < intents[j].IntentID })

	surfaces := make([]ExternalPackageSurfaceSummary, 0, len(m.Surfaces))
	for _, surface := range m.Surfaces {
		item := ExternalPackageSurfaceSummary{
			SurfaceID: surface.SurfaceID, Kind: string(surface.Kind), Intent: string(surface.Intent), Label: surface.Label,
			Entry: surface.Entry, Icon: surface.Icon,
		}
		if surface.DefaultSize != nil {
			item.DefaultSize = &ExternalPackageSizeSummary{Width: surface.DefaultSize.Width, Height: surface.DefaultSize.Height}
		}
		surfaces = append(surfaces, item)
	}
	sort.Slice(surfaces, func(i, j int) bool { return surfaces[i].SurfaceID < surfaces[j].SurfaceID })

	summary := ExternalPackageSecuritySummary{
		Permissions: permissions, Methods: methods, CapabilityContracts: capabilityContracts, Workers: workers,
		Network: network, Storage: storage, SecretRefs: secretRefs, CoreActions: coreActions, Intents: intents, Surfaces: surfaces,
	}
	hash, err := externalPackageSecuritySummaryHash(summary)
	if err != nil {
		return ExternalPackageSecuritySummary{}, err
	}
	summary.SummarySHA256 = hash
	return summary, nil
}

// BuildExternalPackageSecuritySummary is the host-neutral, deterministic
// permission projection used by release publishers, markets, and Hosts.
func BuildExternalPackageSecuritySummary(m manifest.Manifest, pins []capabilitycontract.Pin, required map[string][]string) (ExternalPackageSecuritySummary, error) {
	return buildExternalPackageSecuritySummary(m, pins, required)
}

// ProjectManifestWithCapabilityContracts resolves the signed capability
// bindings against the exact Host contract artifacts supplied by the caller.
// It is the single projection used when release evidence is produced and when
// a Host validates the same evidence during installation.
func ProjectManifestWithCapabilityContracts(m manifest.Manifest, contracts []capabilitycontract.KnownContract) (manifest.Manifest, map[string][]string, error) {
	known := make(map[capabilitycontract.Pin]capabilitycontract.KnownContract, len(contracts))
	for _, contract := range contracts {
		if _, duplicate := known[contract.Pin]; duplicate {
			return manifest.Manifest{}, nil, fmt.Errorf("capability contract %s@%s is duplicated", contract.Pin.ContractID, contract.Pin.ContractVersion)
		}
		known[contract.Pin] = contract
	}
	effective := m
	effective.Methods = append([]manifest.MethodSpec(nil), m.Methods...)
	required := make(map[string][]string, len(effective.Methods))
	for _, binding := range m.CapabilityBindings {
		if _, ok := known[binding.Contract]; !ok {
			return manifest.Manifest{}, nil, fmt.Errorf("capability contract %s@%s is not resolved", binding.Contract.ContractID, binding.Contract.ContractVersion)
		}
	}
	workerPermissions := make([]string, 0, len(m.Permissions))
	for _, permission := range m.Permissions {
		workerPermissions = append(workerPermissions, string(permission))
	}
	workerPermissions = canonicalExternalPackageStrings(workerPermissions)
	for index, declared := range m.Methods {
		if declared.Route.Kind == manifest.MethodRouteWorker {
			required[declared.Method] = append([]string(nil), workerPermissions...)
			continue
		}
		if declared.Route.Kind != manifest.MethodRouteCapability {
			required[declared.Method] = []string{}
			continue
		}
		var binding *manifest.CapabilityBinding
		for bindingIndex := range m.CapabilityBindings {
			if m.CapabilityBindings[bindingIndex].BindingID == declared.Route.BindingID {
				binding = &m.CapabilityBindings[bindingIndex]
				break
			}
		}
		if binding == nil {
			return manifest.Manifest{}, nil, fmt.Errorf("capability binding %q is not declared", declared.Route.BindingID)
		}
		knownContract, ok := known[binding.Contract]
		if !ok {
			return manifest.Manifest{}, nil, fmt.Errorf("capability contract %s@%s is not resolved", binding.Contract.ContractID, binding.Contract.ContractVersion)
		}
		var target *capabilitycontract.Method
		for methodIndex := range knownContract.Contract.Methods {
			if knownContract.Contract.Methods[methodIndex].Name == declared.Route.TargetMethod {
				target = &knownContract.Contract.Methods[methodIndex]
				break
			}
		}
		if target == nil {
			return manifest.Manifest{}, nil, fmt.Errorf("capability target method %q is not published", declared.Route.TargetMethod)
		}
		if declared.Method != declared.Route.TargetMethod {
			return manifest.Manifest{}, nil, fmt.Errorf("plugin method %q must match signed capability method %q", declared.Method, declared.Route.TargetMethod)
		}
		effective.Methods[index] = effectiveCapabilityMethod(declared, *target)
		required[declared.Method] = canonicalExternalPackageStrings(target.RequiredPermissions)
	}
	for pin := range known {
		found := false
		for _, binding := range m.CapabilityBindings {
			if binding.Contract == pin {
				found = true
				break
			}
		}
		if !found {
			return manifest.Manifest{}, nil, fmt.Errorf("capability contract %s@%s is not declared", pin.ContractID, pin.ContractVersion)
		}
	}
	return effective, required, nil
}

func effectiveCapabilityMethod(declared manifest.MethodSpec, target capabilitycontract.Method) manifest.MethodSpec {
	effective := declared
	effective.Effect = manifest.MethodEffect(target.Effect)
	effective.Execution = manifest.MethodExecutionMode(target.Execution)
	effective.PreflightOnly = target.PreflightOnly
	effective.RequestSchema = cloneJSONMap(target.RequestSchema)
	effective.ResponseSchema = cloneJSONMap(target.ResponseSchema)
	if target.Confirmation != nil {
		effective.Dangerous = true
		effective.Confirmation = &manifest.ConfirmationSpec{
			Mode:              manifest.ConfirmationMode(target.Confirmation.Mode),
			RequestHashFields: append([]string(nil), target.Confirmation.RequestHashFields...),
			PlanHashRequired:  target.Confirmation.PlanHashRequired,
		}
		if target.Confirmation.PreflightMethod != "" {
			preflight := target.Confirmation.PreflightMethod
			effective.Confirmation.PreflightMethod = &preflight
		}
	}
	if target.CancelPolicy != nil {
		effective.CancelPolicy = &manifest.CancelPolicySpec{
			Cancelable:        target.CancelPolicy.Cancelable,
			DisableBehavior:   target.CancelPolicy.DisableBehavior,
			UninstallBehavior: target.CancelPolicy.UninstallBehavior,
			AckTimeoutMS:      target.CancelPolicy.AckTimeoutMS,
		}
	}
	return effective
}

func cloneJSONMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var clone map[string]any
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil
	}
	return clone
}

// BuildExternalPackageSecuritySummaryFromContracts derives both effective
// method policy and permissions from exact capability contract artifacts.
func BuildExternalPackageSecuritySummaryFromContracts(m manifest.Manifest, contracts []capabilitycontract.KnownContract) (ExternalPackageSecuritySummary, error) {
	pins := make([]capabilitycontract.Pin, 0, len(m.CapabilityBindings))
	for _, binding := range m.CapabilityBindings {
		pins = append(pins, binding.Contract)
	}
	effective, required, err := ProjectManifestWithCapabilityContracts(m, contracts)
	if err != nil {
		return ExternalPackageSecuritySummary{}, err
	}
	return BuildExternalPackageSecuritySummary(effective, pins, required)
}

// CapabilityContractSetSHA256 returns the digest bound to the exact ordered
// capability contract projection shown to a user.
func CapabilityContractSetSHA256(summary ExternalPackageSecuritySummary) (string, error) {
	raw, err := json.Marshal(summary.CapabilityContracts)
	if err != nil {
		return "", fmt.Errorf("marshal capability contract set: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SecuritySummarySHA256 returns the digest of the canonical summary payload.
func SecuritySummarySHA256(summary ExternalPackageSecuritySummary) (string, error) {
	return externalPackageSecuritySummaryHash(summary)
}

func externalPackageCapabilitySummaries(bindings []manifest.CapabilityBinding, pins []capabilitycontract.Pin) ([]ExternalPackageCapabilityContractSummary, error) {
	resolved := make(map[capabilitycontract.Pin]struct{}, len(pins))
	for _, pin := range pins {
		if _, duplicate := resolved[pin]; duplicate {
			return nil, fmt.Errorf("resolved external package capability contract %s@%s is duplicated", pin.ContractID, pin.ContractVersion)
		}
		resolved[pin] = struct{}{}
	}
	items := make([]ExternalPackageCapabilityContractSummary, 0, len(bindings))
	for _, binding := range bindings {
		if _, ok := resolved[binding.Contract]; !ok {
			return nil, fmt.Errorf("external package capability binding %q was not resolved", binding.BindingID)
		}
		delete(resolved, binding.Contract)
		items = append(items, ExternalPackageCapabilityContractSummary{
			BindingID: binding.BindingID, CapabilityID: binding.Contract.ContractID, CapabilityVersion: binding.Contract.ContractVersion,
			ContractSHA256: externalPackageSHA256(binding.Contract.ArtifactSHA256),
		})
	}
	if len(resolved) != 0 {
		return nil, fmt.Errorf("resolved external package capability contracts contain %d undeclared pin(s)", len(resolved))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].BindingID < items[j].BindingID })
	return items, nil
}

func externalPackageNetworkSummaries(spec *manifest.NetworkAccessSpec, access map[string][]ExternalPackageNetworkMethodAccessSummary) ([]ExternalPackageNetworkSummary, error) {
	items := make([]ExternalPackageNetworkSummary, 0)
	if spec != nil {
		items = make([]ExternalPackageNetworkSummary, 0, len(spec.Connectors))
		for _, connector := range spec.Connectors {
			key := externalPackageNetworkKey(connector.ConnectorID, connector.Transport)
			methodAccess := append([]ExternalPackageNetworkMethodAccessSummary(nil), access[key]...)
			delete(access, key)
			sort.Slice(methodAccess, func(i, j int) bool { return methodAccess[i].Method < methodAccess[j].Method })
			items = append(items, ExternalPackageNetworkSummary{
				ConnectorID: connector.ConnectorID, Transport: connector.Transport, Scope: connector.Scope,
				Destinations: canonicalExternalPackageStrings(connector.Destinations), AuthDeclared: connector.Auth != nil,
				TLSDeclared: connector.TLS != nil, MethodAccess: methodAccess,
			})
		}
	}
	if len(access) != 0 {
		return nil, fmt.Errorf("external package methods reference %d undeclared network connector(s)", len(access))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ConnectorID < items[j].ConnectorID })
	return items, nil
}

func externalPackageStorageSummaries(spec *manifest.StorageSpec, access map[string][]ExternalPackageStorageMethodAccessSummary) ([]ExternalPackageStorageSummary, error) {
	items := make([]ExternalPackageStorageSummary, 0)
	if spec != nil {
		items = make([]ExternalPackageStorageSummary, 0, len(spec.Stores))
		for _, store := range spec.Stores {
			methodAccess := append([]ExternalPackageStorageMethodAccessSummary(nil), access[store.StoreID]...)
			delete(access, store.StoreID)
			sort.Slice(methodAccess, func(i, j int) bool { return methodAccess[i].Method < methodAccess[j].Method })
			items = append(items, ExternalPackageStorageSummary{
				StoreID: store.StoreID, Kind: store.Kind, Scope: store.Scope, QuotaBytes: store.QuotaBytes,
				QuotaFiles: store.QuotaFiles, SchemaVersion: store.SchemaVersion, MethodAccess: methodAccess,
			})
		}
	}
	if len(access) != 0 {
		return nil, fmt.Errorf("external package methods reference %d undeclared storage store(s)", len(access))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].StoreID < items[j].StoreID })
	return items, nil
}

func externalPackageSecuritySummaryHash(summary ExternalPackageSecuritySummary) (string, error) {
	payload := struct {
		Permissions         []ExternalPackagePermissionSummary         `json:"permissions"`
		Methods             []ExternalPackageMethodSummary             `json:"methods"`
		CapabilityContracts []ExternalPackageCapabilityContractSummary `json:"capability_contracts"`
		Workers             []ExternalPackageWorkerSummary             `json:"workers"`
		Network             []ExternalPackageNetworkSummary            `json:"network"`
		Storage             []ExternalPackageStorageSummary            `json:"storage"`
		SecretRefs          []ExternalPackageSecretRefSummary          `json:"secret_refs"`
		CoreActions         []ExternalPackageCoreActionSummary         `json:"core_actions"`
		Intents             []ExternalPackageIntentSummary             `json:"intents"`
		Surfaces            []ExternalPackageSurfaceSummary            `json:"surfaces"`
	}{
		Permissions: summary.Permissions, Methods: summary.Methods, CapabilityContracts: summary.CapabilityContracts,
		Workers: summary.Workers, Network: summary.Network, Storage: summary.Storage, SecretRefs: summary.SecretRefs,
		CoreActions: summary.CoreActions, Intents: summary.Intents, Surfaces: summary.Surfaces,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal external package security summary: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalExternalPackageStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func externalPackageNetworkKey(connectorID, transport string) string {
	return connectorID + "\x00" + transport
}

func externalPackageSHA256(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + value
}
