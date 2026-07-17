package capabilitycontract

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	platformversion "github.com/floegence/redevplugin/pkg/version"
)

const SchemaVersion = "redevplugin.host_capability_contract.v1"

var (
	ErrInvalidContract = errors.New("host capability contract is invalid")
	ErrInvalidBundle   = errors.New("host capability artifact bundle is invalid")
	ErrPinMismatch     = errors.New("host capability artifact pin mismatch")
	ErrSignature       = errors.New("host capability artifact signature is invalid")
	ErrCompatibility   = errors.New("host capability artifact is incompatible")
)

type Contract struct {
	SchemaVersion     string          `json:"schema_version"`
	ContractID        string          `json:"contract_id"`
	ContractVersion   string          `json:"contract_version"`
	PublisherID       string          `json:"publisher_id"`
	CapabilityID      string          `json:"capability_id"`
	CapabilityVersion string          `json:"capability_version"`
	ClientName        string          `json:"client_name"`
	Methods           []Method        `json:"methods"`
	Errors            []BusinessError `json:"errors,omitempty"`
}

type Method struct {
	Name                string         `json:"name"`
	ClientMethod        string         `json:"client_method"`
	Effect              string         `json:"effect"`
	Execution           string         `json:"execution"`
	PreflightOnly       bool           `json:"preflight_only,omitempty"`
	RequiredPermissions []string       `json:"required_permissions,omitempty"`
	TargetFields        []string       `json:"target_fields"`
	TargetSchema        map[string]any `json:"target_schema"`
	RequestTypeName     string         `json:"request_type_name"`
	ResponseTypeName    string         `json:"response_type_name"`
	RequestSchema       map[string]any `json:"request_schema"`
	ResponseSchema      map[string]any `json:"response_schema"`
	EventTypeName       string         `json:"event_type_name,omitempty"`
	EventSchema         map[string]any `json:"event_schema,omitempty"`
	Confirmation        *Confirmation  `json:"confirmation,omitempty"`
	CancelPolicy        *CancelPolicy  `json:"cancel_policy,omitempty"`
	Quota               Quota          `json:"quota"`
}

type Confirmation struct {
	Mode              string   `json:"mode"`
	PreflightMethod   string   `json:"preflight_method,omitempty"`
	RequestHashFields []string `json:"request_hash_fields,omitempty"`
	PlanHashRequired  bool     `json:"plan_hash_required,omitempty"`
}

type CancelPolicy struct {
	Cancelable        bool   `json:"cancelable"`
	DisableBehavior   string `json:"disable_behavior"`
	UninstallBehavior string `json:"uninstall_behavior"`
	AckTimeoutMS      int    `json:"ack_timeout_ms,omitempty"`
}

type Quota struct {
	MaxConcurrent  int   `json:"max_concurrent,omitempty"`
	MaxDurationMS  int   `json:"max_duration_ms,omitempty"`
	MaxStreamBytes int64 `json:"max_stream_bytes,omitempty"`
}

type BusinessError struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	DetailsSchema map[string]any `json:"details_schema,omitempty"`
}

type Notice struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license"`
	SourceURL string `json:"source_url,omitempty"`
}

type Pin struct {
	PublisherID              string `json:"publisher_id"`
	ContractID               string `json:"contract_id"`
	ContractVersion          string `json:"contract_version"`
	ArtifactRef              string `json:"artifact_ref"`
	ArtifactSHA256           string `json:"artifact_sha256"`
	ManifestRef              string `json:"manifest_ref"`
	ManifestSHA256           string `json:"manifest_sha256"`
	SignatureRef             string `json:"signature_ref"`
	SignatureSHA256          string `json:"signature_sha256"`
	SignatureKeyID           string `json:"signature_key_id"`
	SignaturePolicyEpoch     string `json:"signature_policy_epoch"`
	SignatureRevocationEpoch string `json:"signature_revocation_epoch"`
	CompatibilityRef         string `json:"compatibility_ref"`
	CompatibilitySHA256      string `json:"compatibility_sha256"`
	GeneratedClientRef       string `json:"generated_client_ref"`
	GeneratedClientSHA256    string `json:"generated_client_sha256"`
	NoticesRef               string `json:"notices_ref"`
	NoticesSHA256            string `json:"notices_sha256"`
}

type Bundle struct {
	Pin   Pin
	Files map[string][]byte
}

type TrustedKey struct {
	PublisherID     string
	KeyID           string
	PublicKey       []byte
	PolicyEpoch     string
	RevocationEpoch string
}

type VerifiedContract struct {
	Contract         Contract
	Pin              Pin
	Manifest         Manifest
	Compatibility    Compatibility
	GeneratedClient  []byte
	Notices          []Notice
	verificationSeal string
	publicKeySHA256  string
}

func (v VerifiedContract) PublicKeySHA256() string {
	if !v.authentic() {
		return ""
	}
	return v.publicKeySHA256
}

type Manifest struct {
	SchemaVersion            string          `json:"schema_version"`
	PublisherID              string          `json:"publisher_id"`
	ContractID               string          `json:"contract_id"`
	ContractVersion          string          `json:"contract_version"`
	CapabilityID             string          `json:"capability_id"`
	CapabilityVersion        string          `json:"capability_version"`
	GeneratedAt              string          `json:"generated_at"`
	SourceCommit             string          `json:"source_commit"`
	SignatureAlgorithm       string          `json:"signature_algorithm"`
	SignatureKeyID           string          `json:"signature_key_id"`
	SignaturePolicyEpoch     string          `json:"signature_policy_epoch"`
	SignatureRevocationEpoch string          `json:"signature_revocation_epoch"`
	Entries                  []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Role      string `json:"role"`
	Ref       string `json:"ref"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

type Compatibility struct {
	SchemaVersion         string `json:"schema_version"`
	ContractID            string `json:"contract_id"`
	ContractVersion       string `json:"contract_version"`
	CapabilityID          string `json:"capability_id"`
	CapabilityVersion     string `json:"capability_version"`
	MinReDevPluginVersion string `json:"min_redevplugin_version"`
}

type SignatureEnvelope struct {
	SchemaVersion   string `json:"schema_version"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	ManifestSHA256  string `json:"manifest_sha256"`
	SignatureBase64 string `json:"signature_base64"`
}

var (
	idPattern                     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	methodPattern                 = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+$`)
	identifierPattern             = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	errorCodePattern              = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	typeScriptReservedIdentifiers = map[string]struct{}{
		"abstract": {}, "accessor": {}, "any": {}, "as": {}, "assert": {}, "asserts": {}, "async": {}, "await": {},
		"bigint": {}, "boolean": {}, "break": {}, "case": {}, "catch": {}, "class": {}, "const": {}, "continue": {},
		"debugger": {}, "declare": {}, "default": {}, "delete": {}, "do": {}, "else": {}, "enum": {}, "export": {},
		"extends": {}, "false": {}, "finally": {}, "for": {}, "from": {}, "function": {}, "get": {}, "if": {},
		"implements": {}, "import": {}, "in": {}, "infer": {}, "instanceof": {}, "interface": {}, "intrinsic": {},
		"is": {}, "keyof": {}, "let": {}, "module": {}, "namespace": {}, "never": {}, "new": {}, "null": {},
		"number": {}, "object": {}, "of": {}, "out": {}, "override": {}, "package": {}, "private": {}, "protected": {},
		"public": {}, "readonly": {}, "require": {}, "return": {}, "satisfies": {}, "set": {}, "static": {}, "string": {},
		"super": {}, "switch": {}, "symbol": {}, "this": {}, "throw": {}, "true": {}, "try": {}, "type": {},
		"typeof": {}, "undefined": {}, "unique": {}, "unknown": {}, "using": {}, "var": {}, "void": {}, "while": {},
		"with": {}, "yield": {},
	}
	generatedTypeScriptReservedNames = map[string]struct{}{
		"PluginBridgeClient":        {},
		"PluginBridgeError":         {},
		"PluginOperation":           {},
		"PluginStream":              {},
		"callCapabilityOperation":   {},
		"callCapabilityStream":      {},
		"callCapabilitySync":        {},
		"decodePluginStreamText":    {},
		"isCapabilityBusinessError": {},
	}
)

func Validate(contract Contract) error {
	if contract.SchemaVersion != SchemaVersion {
		return invalid("schema_version must be %s", SchemaVersion)
	}
	for name, value := range map[string]string{
		"contract_id":   contract.ContractID,
		"publisher_id":  contract.PublisherID,
		"capability_id": contract.CapabilityID,
	} {
		if !idPattern.MatchString(value) || strings.TrimSpace(value) != value {
			return invalid("%s is invalid", name)
		}
	}
	if _, err := platformversion.ParseSemVer(contract.ContractVersion); err != nil {
		return invalid("contract_version is invalid")
	}
	if _, err := platformversion.ParseSemVer(contract.CapabilityVersion); err != nil {
		return invalid("capability_version is invalid")
	}
	if !validTypeScriptDeclarationIdentifier(contract.ClientName) {
		return invalid("client_name is invalid")
	}
	if _, reserved := generatedTypeScriptReservedNames[contract.ClientName]; reserved {
		return invalid("client_name is reserved by the generated SDK")
	}
	if len(contract.Methods) == 0 {
		return invalid("methods must not be empty")
	}
	methods := map[string]Method{}
	clientMethods := map[string]struct{}{}
	generatedNames := make(map[string]string, len(generatedTypeScriptReservedNames)+1)
	for name := range generatedTypeScriptReservedNames {
		generatedNames[name] = "SDK import or helper"
	}
	generatedNames[contract.ClientName] = "client_name"
	if len(contract.Errors) > 0 {
		baseName := strings.TrimSuffix(contract.ClientName, "Client")
		generatedNames[baseName+"BusinessErrorCode"] = "generated business error code type"
		generatedNames[baseName+"BusinessErrorDetails"] = "generated business error details type"
	}
	for index, method := range contract.Methods {
		if !methodPattern.MatchString(method.Name) {
			return invalid("methods[%d].name is invalid", index)
		}
		if _, ok := methods[method.Name]; ok {
			return invalid("methods[%d].name is duplicated", index)
		}
		methods[method.Name] = method
		if !validTypeScriptMemberIdentifier(method.ClientMethod) {
			return invalid("methods[%d].client_method is invalid", index)
		}
		if _, ok := clientMethods[method.ClientMethod]; ok {
			return invalid("methods[%d].client_method is duplicated", index)
		}
		clientMethods[method.ClientMethod] = struct{}{}
		switch method.Effect {
		case "read", "write", "execute", "delete", "admin":
		default:
			return invalid("methods[%d].effect is invalid", index)
		}
		switch method.Execution {
		case "sync", "operation", "subscription":
		default:
			return invalid("methods[%d].execution is invalid", index)
		}
		if !validTypeScriptDeclarationIdentifier(method.RequestTypeName) || !validTypeScriptDeclarationIdentifier(method.ResponseTypeName) {
			return invalid("methods[%d] type names are invalid", index)
		}
		for label, name := range map[string]string{
			"request_type_name":  method.RequestTypeName,
			"response_type_name": method.ResponseTypeName,
		} {
			if previous, exists := generatedNames[name]; exists {
				return invalid("methods[%d].%s duplicates %s %q", index, label, previous, name)
			}
			generatedNames[name] = fmt.Sprintf("methods[%d].%s", index, label)
		}
		if method.Execution == "subscription" {
			if !validTypeScriptDeclarationIdentifier(method.EventTypeName) {
				return invalid("methods[%d].event_type_name is invalid", index)
			}
			if previous, exists := generatedNames[method.EventTypeName]; exists {
				return invalid("methods[%d].event_type_name duplicates %s %q", index, previous, method.EventTypeName)
			}
			generatedNames[method.EventTypeName] = fmt.Sprintf("methods[%d].event_type_name", index)
			if err := validateSchema(method.EventSchema, fmt.Sprintf("methods[%d].event_schema", index)); err != nil {
				return err
			}
		} else if method.EventTypeName != "" || method.EventSchema != nil {
			return invalid("methods[%d] event contract requires subscription execution", index)
		}
		if err := validateSchema(method.RequestSchema, fmt.Sprintf("methods[%d].request_schema", index)); err != nil {
			return err
		}
		if !schemaAcceptsOnlyObjects(method.RequestSchema) {
			return invalid("methods[%d].request_schema must accept only objects", index)
		}
		if err := validateSchema(method.ResponseSchema, fmt.Sprintf("methods[%d].response_schema", index)); err != nil {
			return err
		}
		if err := validateSchema(method.TargetSchema, fmt.Sprintf("methods[%d].target_schema", index)); err != nil {
			return err
		}
		if !schemaAcceptsOnlyObjects(method.TargetSchema) {
			return invalid("methods[%d].target_schema must accept only objects", index)
		}
		if err := validateStringSet(method.RequiredPermissions, fmt.Sprintf("methods[%d].required_permissions", index)); err != nil {
			return err
		}
		if err := validateStringSet(method.TargetFields, fmt.Sprintf("methods[%d].target_fields", index)); err != nil {
			return err
		}
		requestProperties := schemaPropertyNames(method.RequestSchema)
		for _, field := range method.TargetFields {
			if _, ok := requestProperties[field]; !ok {
				return invalid("methods[%d].target_fields contains unknown field %q", index, field)
			}
		}
		if method.PreflightOnly {
			if method.Effect != "read" || method.Execution != "sync" || method.Confirmation != nil {
				return invalid("methods[%d] preflight_only method must be read-only sync without confirmation", index)
			}
		}
		if method.Confirmation != nil {
			switch method.Confirmation.Mode {
			case "required", "risk_based":
			default:
				return invalid("methods[%d].confirmation.mode is invalid", index)
			}
			if err := validateStringSet(method.Confirmation.RequestHashFields, fmt.Sprintf("methods[%d].confirmation.request_hash_fields", index)); err != nil {
				return err
			}
			for _, field := range method.Confirmation.RequestHashFields {
				if _, ok := requestProperties[field]; !ok {
					return invalid("methods[%d].confirmation.request_hash_fields contains unknown field %q", index, field)
				}
			}
			if method.Confirmation.PreflightMethod != "" && !method.Confirmation.PlanHashRequired {
				return invalid("methods[%d].confirmation.plan_hash_required must be true when preflight_method is set", index)
			}
		}
		if err := validateCancelPolicy(method, index); err != nil {
			return err
		}
		if method.Quota.MaxConcurrent < 0 || method.Quota.MaxDurationMS < 0 || method.Quota.MaxStreamBytes < 0 {
			return invalid("methods[%d].quota must not contain negative values", index)
		}
		if method.Execution != "subscription" && method.Quota.MaxStreamBytes != 0 {
			return invalid("methods[%d].quota.max_stream_bytes requires subscription execution", index)
		}
	}
	for index, method := range contract.Methods {
		if method.Confirmation == nil || method.Confirmation.PreflightMethod == "" {
			continue
		}
		preflight, ok := methods[method.Confirmation.PreflightMethod]
		if !ok {
			return invalid("methods[%d].confirmation.preflight_method is not published", index)
		}
		if !preflight.PreflightOnly {
			return invalid("methods[%d].confirmation.preflight_method must reference a preflight_only method", index)
		}
	}
	errorsSeen := map[string]struct{}{}
	for index, item := range contract.Errors {
		if !errorCodePattern.MatchString(item.Code) {
			return invalid("errors[%d].code is invalid", index)
		}
		if _, ok := errorsSeen[item.Code]; ok {
			return invalid("errors[%d].code is duplicated", index)
		}
		errorsSeen[item.Code] = struct{}{}
		if strings.TrimSpace(item.Message) == "" {
			return invalid("errors[%d].message is required", index)
		}
		if item.DetailsSchema != nil {
			if err := validateSchema(item.DetailsSchema, fmt.Sprintf("errors[%d].details_schema", index)); err != nil {
				return err
			}
			if !schemaAcceptsOnlyObjects(item.DetailsSchema) {
				return invalid("errors[%d].details_schema must accept only objects", index)
			}
		}
	}
	return nil
}

func validateCancelPolicy(method Method, index int) error {
	if method.Execution == "sync" {
		if method.CancelPolicy != nil {
			return invalid("methods[%d].cancel_policy is not allowed for sync execution", index)
		}
		return nil
	}
	if method.CancelPolicy == nil {
		return invalid("methods[%d].cancel_policy is required for asynchronous execution", index)
	}
	switch method.CancelPolicy.DisableBehavior {
	case "cancel", "orphan", "wait":
	default:
		return invalid("methods[%d].cancel_policy.disable_behavior is invalid", index)
	}
	switch method.CancelPolicy.UninstallBehavior {
	case "cancel_then_block_delete", "force_cleanup_allowed":
	default:
		return invalid("methods[%d].cancel_policy.uninstall_behavior is invalid", index)
	}
	if method.CancelPolicy.AckTimeoutMS < 0 {
		return invalid("methods[%d].cancel_policy.ack_timeout_ms must not be negative", index)
	}
	if method.CancelPolicy.Cancelable && method.CancelPolicy.AckTimeoutMS == 0 {
		return invalid("methods[%d].cancel_policy.ack_timeout_ms must be positive for cancelable methods", index)
	}
	if !method.CancelPolicy.Cancelable && method.CancelPolicy.AckTimeoutMS != 0 {
		return invalid("methods[%d].cancel_policy.ack_timeout_ms must be zero for non-cancelable methods", index)
	}
	if method.Execution == "subscription" && !method.CancelPolicy.Cancelable {
		return invalid("methods[%d] subscription execution must be cancelable", index)
	}
	return nil
}

func schemaAcceptsOnlyObjects(schema map[string]any) bool {
	if schema["type"] == "object" {
		return true
	}
	rawBranches, ok := schema["oneOf"]
	if !ok {
		return false
	}
	branches, err := schemaBranches(rawBranches, "oneOf")
	if err != nil {
		return false
	}
	for _, branch := range branches {
		if !schemaAcceptsOnlyObjects(branch) {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidContract, fmt.Sprintf(format, args...))
}

func validTypeScriptDeclarationIdentifier(value string) bool {
	if !identifierPattern.MatchString(value) {
		return false
	}
	_, reserved := typeScriptReservedIdentifiers[value]
	return !reserved
}

func validTypeScriptMemberIdentifier(value string) bool {
	return identifierPattern.MatchString(value) && value != "constructor"
}

func validateStringSet(values []string, label string) error {
	seen := map[string]struct{}{}
	for index, value := range values {
		if value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
			return invalid("%s[%d] must be a non-empty string without whitespace", label, index)
		}
		if _, ok := seen[value]; ok {
			return invalid("%s[%d] is duplicated", label, index)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func schemaPropertyNames(schema map[string]any) map[string]struct{} {
	out := map[string]struct{}{}
	properties, _ := schema["properties"].(map[string]any)
	for name := range properties {
		out[name] = struct{}{}
	}
	return out
}
