package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

type resolvedCapabilityMethod struct {
	binding      manifest.CapabilityBinding
	pin          capabilitycontract.Pin
	contract     capabilitycontract.VerifiedContract
	method       capabilitycontract.Method
	registration capability.Registration
}

type methodExecutionAuthorization struct {
	confirmation capability.ConfirmationEvidence
	target       capability.TargetDescriptor
	targetHash   string
}

func (h *Host) resolvePackageCapabilityPins(ctx context.Context, pkg manifest.Manifest, trustInput packageTrustInput) ([]capabilitycontract.Pin, error) {
	var pins []capabilitycontract.Pin
	if trustInput.Release != nil {
		resolved, err := h.ensureReleaseCapabilityContracts(ctx, *trustInput.Release, *trustInput.SourcePolicySnapshot)
		if err != nil {
			return nil, err
		}
		pins = resolved
	} else {
		if len(pkg.CapabilityBindings) == 0 {
			return nil, nil
		}
		if err := h.requireFeature(FeatureCapability); err != nil {
			return nil, err
		}
		pins = make([]capabilitycontract.Pin, 0, len(pkg.CapabilityBindings))
		for _, binding := range pkg.CapabilityBindings {
			contract, err := h.adapters.Capabilities.RequireContract(binding.Contract)
			if err != nil {
				return nil, fmt.Errorf("resolve local capability contract %s@%s: %w", binding.Contract.ContractID, binding.Contract.ContractVersion, err)
			}
			pins = append(pins, contract.Pin)
		}
	}
	if err := h.validateManifestCapabilityContracts(pkg, pins); err != nil {
		return nil, err
	}
	sort.Slice(pins, func(i, j int) bool {
		if pins[i].ContractID == pins[j].ContractID {
			return pins[i].ContractVersion < pins[j].ContractVersion
		}
		return pins[i].ContractID < pins[j].ContractID
	})
	return pins, nil
}

func (h *Host) ensureReleaseCapabilityContracts(ctx context.Context, release PluginPackageRelease, sourcePolicy SourcePolicySnapshot) ([]capabilitycontract.Pin, error) {
	requirement, err := h.selectHostRequirement(ctx, release)
	if err != nil {
		return nil, err
	}
	if requirement == nil || len(requirement.RequiredCapabilityContracts) == 0 {
		return nil, nil
	}
	pins := make([]capabilitycontract.Pin, 0, len(requirement.RequiredCapabilityContracts))
	for _, required := range requirement.RequiredCapabilityContracts {
		trusted, err := validateCapabilityContractSigningKey(sourcePolicy, required.Contract, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		verified, err := h.adapters.Capabilities.RequireContract(required.Contract)
		if err != nil {
			verified, err = h.resolveAndVerifyCapabilityContract(ctx, release, sourcePolicy, required)
			if err != nil {
				return nil, err
			}
			if err := h.adapters.Capabilities.AddContract(verified); err != nil {
				return nil, err
			}
		} else if !hashEqual(verified.PublicKeySHA256(), trusted.PublicKeySHA256) {
			return nil, fmt.Errorf("%w: cached capability contract signing key does not match current source policy", ErrReleaseRefVerificationFailed)
		}
		if verified.Contract.CapabilityID != required.CapabilityID || verified.Contract.CapabilityVersion != required.CapabilityVersion {
			return nil, fmt.Errorf("%w: capability requirement identity does not match the verified contract", ErrReleaseRefVerificationFailed)
		}
		pins = append(pins, verified.Pin)
	}
	return pins, nil
}

func (h *Host) resolveAndVerifyCapabilityContract(ctx context.Context, release PluginPackageRelease, sourcePolicy SourcePolicySnapshot, required HostCapabilityRequirement) (capabilitycontract.VerifiedContract, error) {
	if h.adapters.CapabilityContractArtifacts == nil || h.adapters.CapabilityContractKeys == nil {
		return capabilitycontract.VerifiedContract{}, fmt.Errorf("%w: capability contract resolver and key resolver are required", ErrReleaseRefVerificationFailed)
	}
	trusted, err := validateCapabilityContractSigningKey(sourcePolicy, required.Contract, time.Now().UTC())
	if err != nil {
		return capabilitycontract.VerifiedContract{}, err
	}
	resolved, err := h.adapters.CapabilityContractArtifacts.ResolveCapabilityContract(ctx, CapabilityContractResolveRequest{
		SourceID:             release.SourceID,
		PluginPublisherID:    release.PublisherID,
		Pin:                  required.Contract,
		SourcePolicySnapshot: sourcePolicy,
	})
	if err != nil {
		return capabilitycontract.VerifiedContract{}, err
	}
	bundle, err := loadCapabilityContractBundle(ctx, required.Contract, sourcePolicy, resolved)
	if err != nil {
		return capabilitycontract.VerifiedContract{}, err
	}
	publicKey, err := h.adapters.CapabilityContractKeys.ResolveCapabilityContractKey(ctx, CapabilityContractKeyRequest{
		SourceID:             release.SourceID,
		PublisherID:          required.Contract.PublisherID,
		KeyID:                required.Contract.SignatureKeyID,
		SourcePolicySnapshot: sourcePolicy,
	})
	if err != nil {
		return capabilitycontract.VerifiedContract{}, err
	}
	keyHash := sha256.Sum256(publicKey)
	if !hashEqual(hex.EncodeToString(keyHash[:]), trusted.PublicKeySHA256) {
		return capabilitycontract.VerifiedContract{}, fmt.Errorf("%w: capability contract public key hash mismatch", ErrReleaseRefVerificationFailed)
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: required.Contract,
		TrustedKey: capabilitycontract.TrustedKey{
			PublisherID:     required.Contract.PublisherID,
			KeyID:           required.Contract.SignatureKeyID,
			PublicKey:       publicKey,
			PolicyEpoch:     required.Contract.SignaturePolicyEpoch,
			RevocationEpoch: required.Contract.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: version.CurrentCompatibilityVersion(),
	})
	if err != nil {
		return capabilitycontract.VerifiedContract{}, fmt.Errorf("%w: %v", ErrReleaseRefVerificationFailed, err)
	}
	if verified.Contract.CapabilityID != required.CapabilityID || verified.Contract.CapabilityVersion != required.CapabilityVersion {
		return capabilitycontract.VerifiedContract{}, fmt.Errorf("%w: capability requirement identity does not match the verified contract", ErrReleaseRefVerificationFailed)
	}
	return verified, nil
}

const (
	capabilityArtifactReadTimeout  = 10 * time.Second
	maxCapabilityArtifactFetchHops = 5
)

func loadCapabilityContractBundle(ctx context.Context, pin capabilitycontract.Pin, sourcePolicy SourcePolicySnapshot, resolved ResolvedCapabilityContractArtifact) (capabilitycontract.Bundle, error) {
	if resolved.Artifacts == nil {
		return capabilitycontract.Bundle{}, fmt.Errorf("%w: capability contract artifact set is required", ErrReleaseRefVerificationFailed)
	}
	refs := []string{
		pin.ArtifactRef,
		pin.ManifestRef,
		pin.SignatureRef,
		pin.CompatibilityRef,
		pin.GeneratedClientRef,
		pin.NoticesRef,
	}
	files := make(map[string][]byte, len(refs))
	var totalBytes int64
	for _, ref := range refs {
		content, err := readCapabilityContractArtifact(ctx, resolved.Artifacts, sourcePolicy, pin, ref)
		if err != nil {
			return capabilitycontract.Bundle{}, err
		}
		totalBytes += int64(len(content))
		if totalBytes > capabilitycontract.MaxArtifactBundleBytes {
			return capabilitycontract.Bundle{}, fmt.Errorf("%w: capability contract bundle exceeds the total byte budget", ErrReleaseRefVerificationFailed)
		}
		files[ref] = content
	}
	return capabilitycontract.Bundle{Pin: pin, Files: files}, nil
}

func readCapabilityContractArtifact(ctx context.Context, artifacts CapabilityContractArtifactSet, sourcePolicy SourcePolicySnapshot, pin capabilitycontract.Pin, ref string) ([]byte, error) {
	readCtx, cancel := context.WithTimeout(ctx, capabilityArtifactReadTimeout)
	defer cancel()
	resolved, err := artifacts.OpenCapabilityContractArtifact(readCtx, ref)
	if err != nil {
		return nil, fmt.Errorf("%w: open capability contract artifact %s: %v", ErrReleaseRefVerificationFailed, ref, err)
	}
	if resolved.Reader == nil {
		return nil, fmt.Errorf("%w: capability contract artifact %s has no reader", ErrReleaseRefVerificationFailed, ref)
	}
	defer resolved.Reader.Close()
	if resolved.Size < 0 || resolved.Size > capabilitycontract.MaxArtifactFileBytes {
		return nil, fmt.Errorf("%w: capability contract artifact %s exceeds the per-file byte budget", ErrReleaseRefVerificationFailed, ref)
	}
	if err := validateCapabilityArtifactFetch(sourcePolicy, resolved.FetchChain); err != nil {
		return nil, err
	}
	wantMediaType, err := capabilityArtifactMediaType(pin, ref)
	if err != nil {
		return nil, err
	}
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(resolved.MediaType))
	if err != nil || mediaType != wantMediaType {
		return nil, fmt.Errorf("%w: capability contract artifact %s media type mismatch", ErrReleaseRefVerificationFailed, ref)
	}
	content, err := io.ReadAll(io.LimitReader(resolved.Reader, capabilitycontract.MaxArtifactFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read capability contract artifact %s: %v", ErrReleaseRefVerificationFailed, ref, err)
	}
	if err := readCtx.Err(); err != nil {
		return nil, fmt.Errorf("%w: capability contract artifact %s read deadline exceeded", ErrReleaseRefVerificationFailed, ref)
	}
	if int64(len(content)) != resolved.Size || int64(len(content)) > capabilitycontract.MaxArtifactFileBytes {
		return nil, fmt.Errorf("%w: capability contract artifact %s size mismatch", ErrReleaseRefVerificationFailed, ref)
	}
	return content, nil
}

func capabilityArtifactMediaType(pin capabilitycontract.Pin, ref string) (string, error) {
	switch ref {
	case pin.ArtifactRef:
		return "application/schema+json", nil
	case pin.ManifestRef, pin.SignatureRef, pin.CompatibilityRef, pin.NoticesRef:
		return "application/json", nil
	case pin.GeneratedClientRef:
		return "text/typescript", nil
	default:
		return "", fmt.Errorf("%w: undeclared capability contract artifact ref %q", ErrReleaseRefVerificationFailed, ref)
	}
}

func validateCapabilityArtifactFetch(sourcePolicy SourcePolicySnapshot, chain []CapabilityArtifactFetchHop) error {
	if len(sourcePolicy.AllowedArtifactHosts) == 0 {
		return fmt.Errorf("%w: source policy allowed_artifact_hosts are required for capability contracts", ErrReleaseRefVerificationFailed)
	}
	if len(chain) == 0 || len(chain) > maxCapabilityArtifactFetchHops {
		return fmt.Errorf("%w: capability contract fetch chain is invalid", ErrReleaseRefVerificationFailed)
	}
	allowedHosts := make(map[string]struct{}, len(sourcePolicy.AllowedArtifactHosts))
	for _, host := range sourcePolicy.AllowedArtifactHosts {
		allowedHosts[strings.ToLower(strings.TrimSpace(host))] = struct{}{}
	}
	for _, hop := range chain {
		parsed, err := url.Parse(strings.TrimSpace(hop.URL))
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
			return fmt.Errorf("%w: capability contract artifact URL is not an allowed HTTPS URL", ErrReleaseRefVerificationFailed)
		}
		if port := parsed.Port(); port != "" && port != "443" {
			return fmt.Errorf("%w: capability contract artifact URL uses a non-HTTPS port", ErrReleaseRefVerificationFailed)
		}
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if _, ok := allowedHosts[host]; !ok {
			return fmt.Errorf("%w: capability contract artifact host %q is not allowed", ErrReleaseRefVerificationFailed, host)
		}
		decodedPath, err := url.PathUnescape(parsed.EscapedPath())
		if err != nil || pathContainsParentTraversal(decodedPath) {
			return fmt.Errorf("%w: capability contract artifact URL path is invalid", ErrReleaseRefVerificationFailed)
		}
		resolvedIP := net.ParseIP(strings.TrimSpace(hop.ResolvedIP))
		if !publicArtifactIP(resolvedIP) {
			return fmt.Errorf("%w: capability contract artifact resolved to a non-public IP", ErrReleaseRefVerificationFailed)
		}
		if literalIP := net.ParseIP(host); literalIP != nil && !literalIP.Equal(resolvedIP) {
			return fmt.Errorf("%w: capability contract artifact IP evidence does not match its URL", ErrReleaseRefVerificationFailed)
		}
	}
	return nil
}

func pathContainsParentTraversal(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func publicArtifactIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicArtifactPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPublicArtifactPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

func validateCapabilityContractSigningKey(sourcePolicy SourcePolicySnapshot, pin capabilitycontract.Pin, now time.Time) (SourcePolicyTrustedKey, error) {
	trusted, err := requireTrustedSourceKey(sourcePolicy, pin.SignatureKeyID, "host_capability_contract", now)
	if err != nil {
		return SourcePolicyTrustedKey{}, fmt.Errorf("%w: capability contract signing key is not trusted: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := validateReleaseSignatureEpochBinding("capability contract signature", pin.SignaturePolicyEpoch, pin.SignatureRevocationEpoch, sourcePolicy); err != nil {
		return SourcePolicyTrustedKey{}, err
	}
	if !stringSliceContains(trusted.AllowedCapabilityPublishers, pin.PublisherID) {
		return SourcePolicyTrustedKey{}, fmt.Errorf("%w: capability contract publisher %q is outside the signing key scope", ErrReleaseRefVerificationFailed, pin.PublisherID)
	}
	return trusted, nil
}

func (h *Host) selectHostRequirement(ctx context.Context, release PluginPackageRelease) (*HostRequirement, error) {
	requirements := release.HostRequirements
	if len(requirements) == 0 {
		return nil, nil
	}
	if h.adapters.HostRequirements == nil {
		return nil, fmt.Errorf("%w: host requirement policy is required", ErrReleaseRefVerificationFailed)
	}
	cloned := cloneHostRequirements(requirements)
	selection, err := h.adapters.HostRequirements.SelectHostRequirement(ctx, HostRequirementSelectionRequest{
		SourceID: release.SourceID, PublisherID: release.PublisherID, PluginID: release.PluginID,
		PluginVersion: release.Version, Requirements: cloned,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: host requirement policy rejected the release: %v", ErrReleaseRefVerificationFailed, err)
	}
	hostID := strings.TrimSpace(selection.HostID)
	if hostID == "" {
		return nil, fmt.Errorf("%w: host requirement policy returned an empty host_id", ErrReleaseRefVerificationFailed)
	}
	var selected *HostRequirement
	for index := range requirements {
		if requirements[index].HostID != hostID {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("%w: host requirement is duplicated", ErrReleaseRefVerificationFailed)
		}
		copy := requirements[index]
		selected = &copy
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: host requirement policy selected undeclared host %q", ErrReleaseRefVerificationFailed, hostID)
	}
	return selected, nil
}

func cloneHostRequirements(requirements []HostRequirement) []HostRequirement {
	cloned := make([]HostRequirement, len(requirements))
	for index, requirement := range requirements {
		cloned[index] = requirement
		cloned[index].RequiredCapabilityContracts = append([]HostCapabilityRequirement(nil), requirement.RequiredCapabilityContracts...)
	}
	return cloned
}

func (h *Host) validateManifestCapabilityContracts(plugin manifest.Manifest, pins []capabilitycontract.Pin) error {
	declared := make(map[capabilitycontract.Pin]struct{}, len(plugin.CapabilityBindings))
	for _, binding := range plugin.CapabilityBindings {
		if _, duplicate := declared[binding.Contract]; duplicate {
			return fmt.Errorf("capability contract %s@%s is bound more than once", binding.Contract.ContractID, binding.Contract.ContractVersion)
		}
		declared[binding.Contract] = struct{}{}
		if _, err := h.resolvePinnedCapabilityContract(pins, binding); err != nil {
			return err
		}
	}
	for _, pin := range pins {
		if _, ok := declared[pin]; !ok {
			return fmt.Errorf("verified contract %s@%s is required by the host but not declared by the plugin", pin.ContractID, pin.ContractVersion)
		}
	}
	for _, method := range plugin.Methods {
		if method.Route.Kind != manifest.MethodRouteCapability {
			continue
		}
		binding, ok := manifestBinding(plugin, method.Route.BindingID)
		if !ok {
			return fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
		}
		verified, err := h.resolvePinnedCapabilityContract(pins, binding)
		if err != nil {
			return err
		}
		_, ok = contractMethod(verified.Contract, method.Route.TargetMethod)
		if !ok {
			return fmt.Errorf("capability target method %q is not published by %s", method.Route.TargetMethod, verified.Contract.ContractID)
		}
		if method.Method != method.Route.TargetMethod {
			return fmt.Errorf("plugin method %q must match signed capability method %q", method.Method, method.Route.TargetMethod)
		}
	}
	return nil
}

func (h *Host) resolveCapabilityMethod(record registry.PluginRecord, method manifest.MethodSpec) (resolvedCapabilityMethod, error) {
	if err := h.requireFeature(FeatureCapability); err != nil {
		return resolvedCapabilityMethod{}, err
	}
	binding, ok := manifestBinding(record.Manifest, method.Route.BindingID)
	if !ok {
		return resolvedCapabilityMethod{}, fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
	}
	verified, err := h.resolvePinnedCapabilityContract(record.CapabilityContracts, binding)
	if err != nil {
		return resolvedCapabilityMethod{}, err
	}
	contractMethod, ok := contractMethod(verified.Contract, method.Route.TargetMethod)
	if !ok {
		return resolvedCapabilityMethod{}, fmt.Errorf("capability target method %q is not published", method.Route.TargetMethod)
	}
	registration, err := h.adapters.Capabilities.Resolve(verified.Pin)
	if err != nil {
		return resolvedCapabilityMethod{}, err
	}
	return resolvedCapabilityMethod{binding: binding, pin: verified.Pin, contract: verified, method: contractMethod, registration: registration}, nil
}

func (h *Host) effectiveMethod(record registry.PluginRecord, declared manifest.MethodSpec) (manifest.MethodSpec, error) {
	if declared.Route.Kind != manifest.MethodRouteCapability {
		return declared, nil
	}
	resolved, err := h.resolveCapabilityMethod(record, declared)
	if err != nil {
		return manifest.MethodSpec{}, err
	}
	effective := manifest.MethodSpec{
		Method:         declared.Method,
		Effect:         manifest.MethodEffect(resolved.method.Effect),
		Execution:      manifest.MethodExecutionMode(resolved.method.Execution),
		PreflightOnly:  resolved.method.PreflightOnly,
		RequestSchema:  cloneParams(resolved.method.RequestSchema),
		ResponseSchema: cloneParams(resolved.method.ResponseSchema),
		Route:          declared.Route,
	}
	if resolved.method.Confirmation != nil {
		confirmation := resolved.method.Confirmation
		effective.Dangerous = true
		effective.Confirmation = &manifest.ConfirmationSpec{
			Mode:              manifest.ConfirmationMode(confirmation.Mode),
			RequestHashFields: append([]string(nil), confirmation.RequestHashFields...),
			PlanHashRequired:  confirmation.PlanHashRequired,
		}
		if confirmation.PreflightMethod != "" {
			preflight := confirmation.PreflightMethod
			effective.Confirmation.PreflightMethod = &preflight
		}
	}
	if resolved.method.CancelPolicy != nil {
		effective.CancelPolicy = &manifest.CancelPolicySpec{
			Cancelable:        resolved.method.CancelPolicy.Cancelable,
			DisableBehavior:   resolved.method.CancelPolicy.DisableBehavior,
			UninstallBehavior: resolved.method.CancelPolicy.UninstallBehavior,
			AckTimeoutMS:      resolved.method.CancelPolicy.AckTimeoutMS,
		}
	}
	return effective, nil
}

func (h *Host) resolveCapabilityTarget(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, resolved resolvedCapabilityMethod) (capability.TargetDescriptor, string, error) {
	targetInput, err := extractCapabilityTargetInput(req.Params, resolved.method.TargetFields)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	target, err := resolved.registration.TargetProjector.ProjectTarget(ctx, capability.TargetResolutionRequest{
		Identity: capability.PluginIdentity{
			PublisherID:       record.PublisherID,
			PluginID:          record.PluginID,
			PluginInstanceID:  record.PluginInstanceID,
			PluginVersion:     record.Version,
			ActiveFingerprint: record.ActiveFingerprint,
		},
		Surface: capability.SurfaceScope{
			SurfaceInstanceID:    req.SurfaceInstanceID,
			OwnerSessionHash:     req.session.OwnerSessionHash,
			OwnerUserHash:        req.session.OwnerUserHash,
			OwnerEnvHash:         req.session.OwnerEnvHash,
			SessionChannelIDHash: req.session.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
		},
		CapabilityID:      resolved.contract.Contract.CapabilityID,
		CapabilityVersion: resolved.contract.Contract.CapabilityVersion,
		BindingID:         resolved.binding.BindingID,
		Contract:          resolved.pin,
		Method:            method.Method,
		TargetMethod:      method.Route.TargetMethod,
		TargetInput:       targetInput,
	})
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	if strings.TrimSpace(target.Kind) == "" || target.Fields == nil {
		return capability.TargetDescriptor{}, "", errors.New("capability adapter returned an invalid target descriptor")
	}
	target, err = capability.CloneTargetDescriptor(target)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	if err := capabilitycontract.ValidateValue(resolved.method.TargetSchema, target.Fields); err != nil {
		return capability.TargetDescriptor{}, "", fmt.Errorf("capability target descriptor validation failed: %w", err)
	}
	hash, err := canonicalDescriptorHash(target)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	return target, hash, nil
}

func extractCapabilityTargetInput(params map[string]any, targetFields []string) (map[string]any, error) {
	input := make(map[string]any, len(targetFields))
	for _, field := range targetFields {
		value, ok := params[field]
		if !ok {
			continue
		}
		input[field] = value
	}
	return jsonvalue.CloneCanonicalMap(input)
}

func (h *Host) prepareCapabilityExecution(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, auth methodExecutionAuthorization, resolved resolvedCapabilityMethod) (capability.Invocation, context.Context, executionFinish, error) {
	target := auth.target
	targetHash := auth.targetHash
	if targetHash == "" {
		var err error
		target, targetHash, err = h.resolveCapabilityTarget(ctx, record, method, req, resolved)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
	}
	arguments, err := deepCloneParams(req.Params)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	invocationID, err := newCapabilityID("invoke")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	auditID, err := newCapabilityID("audit")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	now := lifecycleNow(req.Now)
	quota := capability.QuotaGrant{
		MaxConcurrent:  resolved.method.Quota.MaxConcurrent,
		MaxDurationMS:  resolved.method.Quota.MaxDurationMS,
		MaxStreamBytes: resolved.method.Quota.MaxStreamBytes,
	}
	if quota.MaxDurationMS > 0 {
		quota.ExpiresAt = now.Add(time.Duration(quota.MaxDurationMS) * time.Millisecond)
	}
	binding := capability.ExecutionBinding{
		InvocationID:         invocationID,
		AuditCorrelationID:   auditID,
		PublisherID:          record.PublisherID,
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		PluginVersion:        record.Version,
		ActiveFingerprint:    record.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.session.OwnerSessionHash,
		OwnerUserHash:        req.session.OwnerUserHash,
		OwnerEnvHash:         req.session.OwnerEnvHash,
		SessionChannelIDHash: req.session.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		RouteKind:            capability.RouteCapability,
		CapabilityID:         resolved.contract.Contract.CapabilityID,
		CapabilityVersion:    resolved.contract.Contract.CapabilityVersion,
		BindingID:            resolved.binding.BindingID,
		Contract:             &resolved.pin,
		Method:               method.Method,
		TargetMethod:         method.Route.TargetMethod,
		Effect:               capability.Effect(method.Effect),
		Execution:            string(method.Execution),
		Permissions: capability.PermissionEvidence{
			Required: normalizeStringSet(resolved.method.RequiredPermissions),
			Granted:  normalizeStringSet(resolved.method.RequiredPermissions),
		},
		Confirmation: auth.confirmation,
		Revision: capability.RevisionEvidence{
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		},
		Quota:                  quota,
		Target:                 target,
		TargetDescriptorSHA256: targetHash,
	}
	var streamContract *capability.StreamContract
	if method.Execution == manifest.MethodExecutionSubscription {
		schemaHash, err := capabilitycontract.SchemaSHA256(resolved.method.EventSchema)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		binding.StreamEventTypeName = resolved.method.EventTypeName
		binding.StreamEventSchemaSHA256 = schemaHash
		streamContract = &capability.StreamContract{
			EventTypeName: resolved.method.EventTypeName,
			EventSchema:   cloneParams(resolved.method.EventSchema),
		}
	}
	return h.startMethodExecution(ctx, record, method, binding, arguments, now, streamContract, operationCancelDispatchFor(resolved.registration.Adapter), false)
}

func (h *Host) resolvePinnedCapabilityContract(pins []capabilitycontract.Pin, binding manifest.CapabilityBinding) (capabilitycontract.VerifiedContract, error) {
	if err := h.requireFeature(FeatureCapability); err != nil {
		return capabilitycontract.VerifiedContract{}, err
	}
	for _, pin := range pins {
		if pin != binding.Contract {
			continue
		}
		candidate, err := h.adapters.Capabilities.RequireContract(pin)
		if err != nil {
			return capabilitycontract.VerifiedContract{}, err
		}
		return candidate, nil
	}
	return capabilitycontract.VerifiedContract{}, fmt.Errorf("verified contract %s@%s is required", binding.Contract.ContractID, binding.Contract.ContractVersion)
}

type executionFinish func(bool, error) error

func (h *Host) startMethodExecution(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, binding capability.ExecutionBinding, arguments map[string]any, now time.Time, streamContract *capability.StreamContract, cancelDispatch operationCancelDispatch, completeOnReturn bool) (capability.Invocation, context.Context, executionFinish, error) {
	if err := validateExecutionBindingShape(binding); err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	ownedBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	binding = ownedBinding
	if err := h.reconcilePendingExecutionSetups(ctx, record.PluginInstanceID); err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	if method.Execution == manifest.MethodExecutionOperation || method.Execution == manifest.MethodExecutionSubscription {
		operationID, err := newCapabilityID("operation")
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		binding.OperationID = operationID
	}
	if method.Execution == manifest.MethodExecutionSubscription {
		streamID, err := newCapabilityID("stream")
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		binding.StreamID = streamID
	}
	var operationRegistrationBinding capability.ExecutionBinding
	if method.Execution == manifest.MethodExecutionOperation || method.Execution == manifest.MethodExecutionSubscription {
		operationRegistrationBinding, err = capability.CloneExecutionBinding(binding)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
	}
	var streamRegistrationBinding capability.ExecutionBinding
	if method.Execution == manifest.MethodExecutionSubscription {
		streamRegistrationBinding, err = capability.CloneExecutionBinding(binding)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
	}
	leaseBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	validationBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	h.lifecycleMu.RLock()
	if h.closed {
		h.lifecycleMu.RUnlock()
		return capability.Invocation{}, nil, nil, ErrHostClosed
	}
	lifecycleLocked := true
	defer func() {
		if lifecycleLocked {
			h.lifecycleMu.RUnlock()
		}
	}()
	lease, err := h.executions.start(ctx, leaseBinding, func(validateCtx context.Context) error {
		return h.validateExecutionBinding(validateCtx, validationBinding)
	})
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	executionBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		lease.finish()
		return capability.Invocation{}, nil, nil, err
	}
	execution := capability.ExecutionContext{ExecutionBinding: executionBinding}
	if method.Execution == manifest.MethodExecutionOperation || method.Execution == manifest.MethodExecutionSubscription {
		cancelable := method.CancelPolicy.Cancelable
		auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
			Type:             "plugin.operation.started",
			PluginID:         record.PluginID,
			PluginInstanceID: record.PluginInstanceID,
			Details:          executionStartedAuditDetails(binding, "operation_id", binding.OperationID),
		})
		if err != nil {
			lease.finish()
			return capability.Invocation{}, nil, nil, err
		}
		_, registerErr := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
			OperationID:        binding.OperationID,
			ExecutionBinding:   operationRegistrationBinding,
			Cancelable:         &cancelable,
			CancelAckTimeoutMS: method.CancelPolicy.AckTimeoutMS,
			DisableBehavior:    cancelPolicyDisableBehavior(method.CancelPolicy),
			UninstallBehavior:  cancelPolicyUninstallBehavior(method.CancelPolicy),
			Now:                now,
		})
		if err := auditMutation.complete(context.WithoutCancel(ctx), registerErr); err != nil {
			lease.finish()
			return capability.Invocation{}, nil, nil, err
		}
		sink := &hostOperationSink{
			host: h, lease: lease, operationID: binding.OperationID,
			ackTimeout: time.Duration(method.CancelPolicy.AckTimeoutMS) * time.Millisecond,
		}
		lease.setOperation(sink, cancelDispatch)
		execution.Operation = sink
	}
	if method.Execution == manifest.MethodExecutionSubscription {
		auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
			Type:             "plugin.stream.started",
			PluginID:         record.PluginID,
			PluginInstanceID: record.PluginInstanceID,
			Details:          executionStartedAuditDetails(binding, "stream_id", binding.StreamID),
		})
		if err != nil {
			return capability.Invocation{}, nil, nil, h.rollbackMethodExecutionSetup(ctx, lease, err)
		}
		_, registerErr := h.adapters.Streams.Register(ctx, stream.RegisterRequest{
			StreamID:         binding.StreamID,
			ExecutionBinding: streamRegistrationBinding,
			Direction:        stream.DirectionRead,
			MaxBufferedBytes: binding.Quota.MaxStreamBytes,
			Now:              now,
		})
		if err := auditMutation.complete(context.WithoutCancel(ctx), registerErr); err != nil {
			return capability.Invocation{}, nil, nil, h.rollbackMethodExecutionSetup(ctx, lease, err)
		}
		sink := &hostStreamSink{host: h, lease: lease, streamID: binding.StreamID, maxBytes: binding.Quota.MaxStreamBytes}
		if streamContract != nil {
			sink.eventTypeName = strings.TrimSpace(streamContract.EventTypeName)
			sink.eventSchema = cloneParams(streamContract.EventSchema)
		}
		lease.setStream(sink)
		execution.Stream = sink
	}
	h.lifecycleMu.RUnlock()
	lifecycleLocked = false
	lease.armTimeout(h)
	finish := func(success bool, cause error) error {
		terminalCtx := context.WithoutCancel(ctx)
		terminalCause := cause
		if terminalCause == nil {
			terminalCause = context.Cause(lease.ctx)
		}
		switch method.Execution {
		case manifest.MethodExecutionSync:
			if success && terminalCause != nil {
				lease.finish()
				return terminalCause
			}
			lease.finish()
			return nil
		case manifest.MethodExecutionOperation:
			if success && terminalCause == nil {
				if completeOnReturn {
					operationSink, _, _ := lease.snapshotExecution()
					if operationSink != nil {
						return operationSink.Complete(terminalCtx)
					}
				}
				lease.detachParent()
				return nil
			}
			if operationSink, _, _ := lease.snapshotExecution(); operationSink != nil {
				if err := operationSink.terminateUnchecked(terminalCtx, executionFailureCode(binding, terminalCause), terminalCause); err != nil {
					if success {
						return errors.Join(terminalCause, err)
					}
					return err
				}
			}
			lease.finish()
			if success {
				return terminalCause
			}
			return nil
		case manifest.MethodExecutionSubscription:
			lease.markDispatchComplete()
			if success && terminalCause == nil {
				if _, streamSink, _ := lease.snapshotExecution(); streamSink != nil {
					if streamSink.isTerminal() {
						lease.finish()
						return nil
					}
					if completeOnReturn {
						return streamSink.closeWithStatus(terminalCtx, stream.StatusClosed, operation.StatusCompleted, "", "")
					}
				}
				lease.detachParent()
				return nil
			}
			if _, streamSink, _ := lease.snapshotExecution(); streamSink != nil {
				if err := streamSink.failCauseUnchecked(terminalCtx, executionFailureCode(binding, terminalCause), terminalCause); err != nil {
					if success {
						return errors.Join(terminalCause, err)
					}
					return err
				}
			}
			lease.finish()
			if success {
				return terminalCause
			}
			return nil
		}
		return nil
	}
	return capability.Invocation{Execution: execution, Arguments: arguments}, lease.ctx, finish, nil
}

func validateExecutionBindingShape(binding capability.ExecutionBinding) error {
	if strings.TrimSpace(string(binding.RouteKind)) == "" {
		return errors.New("execution route_kind is required")
	}
	switch binding.RouteKind {
	case capability.RouteCapability:
		if binding.Contract == nil {
			return errors.New("capability execution contract is required")
		}
	case capability.RouteWorker, capability.RouteCoreAction:
		if binding.Contract != nil {
			return errors.New("non-capability execution must not contain a capability contract")
		}
	default:
		return fmt.Errorf("execution route_kind %q is invalid", binding.RouteKind)
	}
	if binding.Permissions.Required == nil || binding.Permissions.Granted == nil {
		return errors.New("execution permission evidence must use arrays")
	}
	return nil
}

func executionStartedAuditDetails(binding capability.ExecutionBinding, idKey, id string) map[string]any {
	details := map[string]any{
		idKey:                      id,
		"route_kind":               binding.RouteKind,
		"invocation_id":            binding.InvocationID,
		"audit_correlation_id":     binding.AuditCorrelationID,
		"target_descriptor_sha256": binding.TargetDescriptorSHA256,
	}
	if binding.Contract != nil {
		details["capability_contract_artifact"] = binding.Contract.ArtifactSHA256
	}
	return details
}

func (h *Host) rollbackMethodExecutionSetup(ctx context.Context, lease *executionLease, cause error) error {
	operationSink, _, _ := lease.snapshotExecution()
	if operationSink == nil {
		lease.finish()
		return cause
	}
	cleanupErr := operationSink.failCauseUnchecked(context.WithoutCancel(ctx), capability.ExecutionFailurePlatformFailed, cause)
	if cleanupErr != nil {
		lease.markSetupRollbackPending(cause)
		auditErr := h.recordSecurityEvent(context.WithoutCancel(ctx), AuditEvent{
			Type:             "plugin.operation.setup_rollback_pending",
			PluginID:         lease.binding.PluginID,
			PluginInstanceID: lease.binding.PluginInstanceID,
			Details: map[string]any{
				"operation_id": lease.binding.OperationID,
				"stream_id":    lease.binding.StreamID,
			},
		})
		cleanupErr = errors.Join(cleanupErr, auditErr)
	}
	return errors.Join(cause, cleanupErr)
}

func (h *Host) reconcilePendingExecutionSetups(ctx context.Context, pluginInstanceID string) error {
	leases := h.executions.pendingSetupRollbacks(pluginInstanceID)
	var result error
	for _, lease := range leases {
		operationSink, streamSink, _ := lease.snapshotExecution()
		if operationSink == nil && streamSink == nil {
			lease.finish()
			continue
		}
		var err error
		if streamSink != nil {
			err = streamSink.failCauseUnchecked(ctx, capability.ExecutionFailurePlatformFailed, lease.setupRollbackCause())
		} else {
			err = operationSink.failCauseUnchecked(ctx, capability.ExecutionFailurePlatformFailed, lease.setupRollbackCause())
		}
		if err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (h *Host) reconcileDurableExecutionStates(ctx context.Context) error {
	var cursor *operation.Cursor
	var result error
	for {
		page, err := h.adapters.Operations.List(ctx, operation.ListRequest{Cursor: cursor, Limit: operation.MaxListLimit, AllOwners: true})
		if err != nil {
			return errors.Join(result, err)
		}
		result = errors.Join(result, h.reconcileDurableExecutionPage(ctx, page.Records))
		if page.NextCursor == nil {
			return result
		}
		cursor = page.NextCursor
	}
}

func (h *Host) pruneTerminalExecutionRecords(ctx context.Context, now time.Time) error {
	operationResult, operationErr := h.adapters.Operations.Prune(ctx, operation.PruneRequest{
		Before:                      now.Add(-operation.DefaultTerminalRetention),
		Limit:                       operation.DefaultPruneLimit,
		MaxTerminalRecordsPerPlugin: operation.DefaultMaxTerminalRecordsPerPlugin,
	})
	streamResult, streamErr := h.adapters.Streams.Prune(ctx, stream.PruneRequest{
		Before:                      now.Add(-stream.DefaultTerminalRetention),
		Limit:                       stream.DefaultPruneLimit,
		MaxTerminalRecordsPerPlugin: stream.DefaultMaxTerminalRecordsPerPlugin,
	})
	if operationResult.Deleted > 0 || streamResult.Deleted > 0 {
		h.diagnostic(ctx, observability.DiagnosticEvent{
			Type:     "plugin.execution.retention_pruned",
			Severity: "info",
			Message:  "terminal operation and stream retention was pruned",
			Details: map[string]any{
				"operations_deleted": operationResult.Deleted,
				"streams_deleted":    streamResult.Deleted,
			},
		})
	}
	return errors.Join(operationErr, streamErr)
}

func (h *Host) maintainTerminalExecutionRecords(_ context.Context, now time.Time) {
	if !h.executions.beginTerminalMaintenance(now) {
		return
	}
	started := h.startLifecycleJob(func(lifecycleCtx context.Context) {
		defer h.executions.finishTerminalMaintenance()
		if err := h.pruneTerminalExecutionRecords(lifecycleCtx, now); err != nil && lifecycleCtx.Err() == nil {
			h.diagnostic(lifecycleCtx, observability.DiagnosticEvent{
				Type:     "plugin.execution.retention_prune_failed",
				Severity: observability.DiagnosticSeverityWarning,
				Message:  "terminal execution retention pruning failed",
				InternalDetails: map[string]any{
					"failure": observability.FailureFromError(observability.FailureAdapter, "execution.retention_prune", err),
				},
			})
		}
	})
	if !started {
		h.executions.finishTerminalMaintenance()
	}
}

func (h *Host) reconcileDurableExecutionPage(ctx context.Context, records []operation.Record) error {
	var result error
	for _, operationRecord := range records {
		hasLiveOwner := h.executions.hasOperation(operationRecord.OperationID)
		var streamRecord stream.Record
		streamErr := stream.ErrNotFound
		if strings.TrimSpace(operationRecord.StreamID) != "" {
			streamRecord, streamErr = h.adapters.Streams.Get(ctx, operationRecord.StreamID)
		}
		if streamErr != nil {
			if errors.Is(streamErr, stream.ErrNotFound) {
				if operationTerminal(operationRecord.Status) || hasLiveOwner {
					continue
				}
				status := operation.StatusFailed
				reason := "execution owner is unavailable after host restart"
				failureCode := capability.ExecutionFailurePlatformFailed
				if operationRecord.Status == operation.StatusCancelRequested {
					status = operation.StatusCanceled
					reason = "canceled operation owner is unavailable after host restart"
					failureCode = ""
				}
				finished, finishErr := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
					OperationID: operationRecord.OperationID,
					Status:      status,
					FailureCode: failureCode,
					Reason:      reasonForTerminalStatus(status, reason),
				})
				if finishErr != nil {
					result = errors.Join(result, finishErr)
					continue
				}
				if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.reconciled", PluginID: finished.PluginID, PluginInstanceID: finished.PluginInstanceID, Details: map[string]any{"operation_id": finished.OperationID, "status": finished.Status}}); auditErr != nil {
					result = errors.Join(result, mutation.Unknown(auditErr))
				}
				continue
			}
			result = errors.Join(result, streamErr)
			continue
		}
		operationDone := operationTerminal(operationRecord.Status)
		streamDone := streamRecord.Status != stream.StatusOpen
		if operationDone && streamDone {
			expectedOperation, ok := operationStatusForStreamStatus(streamRecord.Status)
			if !ok || operationRecord.Status != expectedOperation {
				result = errors.Join(result, fmt.Errorf("%w: operation %s is %s while stream %s is %s", errExecutionTerminalConflict, operationRecord.OperationID, operationRecord.Status, streamRecord.StreamID, streamRecord.Status))
			}
			continue
		}
		if !operationDone && !hasLiveOwner {
			var operationStatus operation.Status
			streamStatus := stream.StatusFailed
			reason := "execution owner is unavailable after host restart"
			failureCode := capability.ExecutionFailurePlatformFailed
			if streamDone {
				var ok bool
				operationStatus, ok = operationStatusForStreamStatus(streamRecord.Status)
				if !ok {
					result = errors.Join(result, fmt.Errorf("%w: orphan operation %s cannot derive a terminal state from stream %s", errExecutionTerminalConflict, operationRecord.OperationID, streamRecord.StreamID))
					continue
				}
				reason = streamRecord.Reason
				failureCode = streamRecord.FailureCode
			} else {
				if operationRecord.Status == operation.StatusCancelRequested {
					streamStatus = stream.StatusCanceled
					reason = "canceled operation owner is unavailable after host restart"
					failureCode = ""
				}
				closed, closeErr := h.adapters.Streams.Close(ctx, stream.CloseRequest{
					StreamID: streamRecord.StreamID, Status: streamStatus, FailureCode: failureCode,
					Reason: reasonForStreamTerminalStatus(streamStatus, reason),
				})
				if closeErr != nil {
					result = errors.Join(result, closeErr)
					continue
				}
				var ok bool
				operationStatus, ok = operationStatusForStreamStatus(closed.Status)
				if !ok {
					result = errors.Join(result, fmt.Errorf("%w: closed stream %s has unsupported terminal state %s", errExecutionTerminalConflict, closed.StreamID, closed.Status))
					continue
				}
				reason = closed.Reason
				failureCode = closed.FailureCode
				if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.stream.reconciled", PluginID: closed.PluginID, PluginInstanceID: closed.PluginInstanceID, Details: map[string]any{"stream_id": closed.StreamID, "status": closed.Status}}); auditErr != nil {
					result = errors.Join(result, mutation.Unknown(auditErr))
				}
			}
			finished, finishErr := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
				OperationID: operationRecord.OperationID, Status: operationStatus, FailureCode: failureCode,
				Reason: reasonForTerminalStatus(operationStatus, reason),
			})
			if finishErr != nil {
				result = errors.Join(result, finishErr)
				continue
			}
			if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.reconciled", PluginID: finished.PluginID, PluginInstanceID: finished.PluginInstanceID, Details: map[string]any{"operation_id": finished.OperationID, "status": finished.Status}}); auditErr != nil {
				result = errors.Join(result, mutation.Unknown(auditErr))
			}
			continue
		}
		switch {
		case operationDone && !streamDone:
			status, ok := streamStatusForOperationStatus(operationRecord.Status)
			if !ok {
				continue
			}
			closed, closeErr := h.adapters.Streams.Close(ctx, stream.CloseRequest{
				StreamID: streamRecord.StreamID, Status: status, FailureCode: operationRecord.FailureCode,
				Reason: reasonForStreamTerminalStatus(status, operationRecord.Reason),
			})
			if closeErr != nil {
				result = errors.Join(result, closeErr)
				continue
			}
			if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.stream.reconciled", PluginID: closed.PluginID, PluginInstanceID: closed.PluginInstanceID, Details: map[string]any{"stream_id": closed.StreamID, "status": closed.Status}}); auditErr != nil {
				result = errors.Join(result, mutation.Unknown(auditErr))
			}
		case !operationDone && streamDone:
			status, ok := operationStatusForStreamStatus(streamRecord.Status)
			if !ok {
				continue
			}
			finished, finishErr := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
				OperationID: operationRecord.OperationID, Status: status, FailureCode: streamRecord.FailureCode,
				Reason: reasonForTerminalStatus(status, streamRecord.Reason),
			})
			if finishErr != nil {
				result = errors.Join(result, finishErr)
				continue
			}
			if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.reconciled", PluginID: finished.PluginID, PluginInstanceID: finished.PluginInstanceID, Details: map[string]any{"operation_id": finished.OperationID, "status": finished.Status}}); auditErr != nil {
				result = errors.Join(result, mutation.Unknown(auditErr))
			}
		}
	}
	return result
}

func operationStatusForStreamStatus(status stream.Status) (operation.Status, bool) {
	switch status {
	case stream.StatusClosed:
		return operation.StatusCompleted, true
	case stream.StatusCanceled:
		return operation.StatusCanceled, true
	case stream.StatusFailed:
		return operation.StatusFailed, true
	case stream.StatusOrphanedDisabled:
		return operation.StatusOrphanedAfterDisable, true
	case stream.StatusOrphanedRemoved:
		return operation.StatusOrphanedAfterUninstall, true
	default:
		return "", false
	}
}

func reasonForTerminalStatus(status operation.Status, reason string) string {
	if status == operation.StatusFailed {
		return ""
	}
	return reason
}

func reasonForStreamTerminalStatus(status stream.Status, reason string) string {
	if status == stream.StatusFailed {
		return ""
	}
	return reason
}

func streamStatusForOperationStatus(status operation.Status) (stream.Status, bool) {
	switch status {
	case operation.StatusCompleted:
		return stream.StatusClosed, true
	case operation.StatusCanceled:
		return stream.StatusCanceled, true
	case operation.StatusFailed:
		return stream.StatusFailed, true
	case operation.StatusOrphanedAfterDisable:
		return stream.StatusOrphanedDisabled, true
	case operation.StatusOrphanedAfterUninstall:
		return stream.StatusOrphanedRemoved, true
	default:
		return "", false
	}
}

func (h *Host) validateExecutionBinding(ctx context.Context, binding capability.ExecutionBinding) error {
	authorization, err := h.adapters.Registry.Authorize(ctx, registry.AuthorizeRequest{
		PluginInstanceID: binding.PluginInstanceID,
		Method:           binding.Method,
		PermissionIDs:    binding.Permissions.Required,
		Expected: registry.AuthorizationRevisions{
			PolicyRevision:     binding.Revision.PolicyRevision,
			ManagementRevision: binding.Revision.ManagementRevision,
			RevokeEpoch:        binding.Revision.RevokeEpoch,
		},
	})
	if err != nil {
		return capability.ErrExecutionRevoked
	}
	state := authorization.State
	if state.EnableState != registry.EnableEnabled || !registry.RunnableTrustState(state.TrustState) ||
		state.ActiveFingerprint != binding.ActiveFingerprint || state.PluginVersion != binding.PluginVersion ||
		state.Revisions.PolicyRevision != binding.Revision.PolicyRevision || state.Revisions.ManagementRevision != binding.Revision.ManagementRevision ||
		state.Revisions.RevokeEpoch != binding.Revision.RevokeEpoch {
		return capability.ErrExecutionRevoked
	}
	if err := authorizationDecisionError(authorization, binding.Method); err != nil {
		return err
	}
	if !binding.Quota.ExpiresAt.IsZero() && !time.Now().UTC().Before(binding.Quota.ExpiresAt) {
		return capability.ErrExecutionRevoked
	}
	return nil
}

func canonicalDescriptorHash(target capability.TargetDescriptor) (string, error) {
	raw, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func deepCloneParams(params map[string]any) (map[string]any, error) {
	if params == nil {
		return map[string]any{}, nil
	}
	return jsonvalue.CloneCanonicalMap(params)
}

func newCapabilityID(prefix string) (string, error) {
	raw := make([]byte, 24)
	if _, err := randRead(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

var randRead = func(raw []byte) (int, error) {
	return cryptoRandRead(raw)
}

func cryptoRandRead(raw []byte) (int, error) {
	return rand.Read(raw)
}

func contractMethod(contract capabilitycontract.Contract, targetMethod string) (capabilitycontract.Method, bool) {
	for _, method := range contract.Methods {
		if method.Name == targetMethod {
			return method, true
		}
	}
	return capabilitycontract.Method{}, false
}

func manifestBinding(plugin manifest.Manifest, bindingID string) (manifest.CapabilityBinding, bool) {
	for _, binding := range plugin.CapabilityBindings {
		if binding.BindingID == bindingID {
			return binding, true
		}
	}
	return manifest.CapabilityBinding{}, false
}

const (
	executionFailedReason   = capability.ExecutionFailureMessage
	executionCanceledReason = "operation canceled"
)

func (h *Host) reportExecutionFailure(ctx context.Context, binding capability.ExecutionBinding, code capability.ExecutionFailureCode, cause error) {
	if h == nil || !code.Valid() || cause == nil {
		return
	}
	details := map[string]any{
		"invocation_id": binding.InvocationID,
		"method":        binding.Method,
		"failure_code":  code,
	}
	if binding.OperationID != "" {
		details["operation_id"] = binding.OperationID
	}
	if binding.StreamID != "" {
		details["stream_id"] = binding.StreamID
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type:                 "plugin.execution.failed",
		Severity:             observability.DiagnosticSeverityWarning,
		Message:              executionFailedReason,
		PluginID:             binding.PluginID,
		PluginInstanceID:     binding.PluginInstanceID,
		SurfaceInstanceID:    binding.SurfaceInstanceID,
		ActiveFingerprint:    binding.ActiveFingerprint,
		OwnerSessionHash:     binding.OwnerSessionHash,
		OwnerUserHash:        binding.OwnerUserHash,
		OwnerEnvHash:         binding.OwnerEnvHash,
		SessionChannelIDHash: binding.SessionChannelIDHash,
		Details:              details,
		InternalDetails: map[string]any{
			"failure": observability.FailureFromError(observability.FailureAction, "execution.fail", cause),
		},
	})
}

type executionLeaseRegistry struct {
	mu                         sync.Mutex
	leases                     map[string]*executionLease
	leasesByPlugin             map[string]map[string]*executionLease
	operations                 map[string]*executionLease
	streams                    map[string]*hostStreamSink
	activeByQuotaKey           map[executionQuotaKey]int
	setupRollbacks             map[string]*executionLease
	pluginGates                map[string]*executionPluginGate
	terminalMaintenanceRunning bool
	terminalMaintenanceNext    time.Time
}

const terminalExecutionMaintenanceInterval = time.Minute

type executionQuotaKey struct {
	pluginInstanceID string
	capabilityID     string
	method           string
}

type executionPluginGate struct {
	mu   sync.RWMutex
	refs int
}

type executionLease struct {
	registry         *executionLeaseRegistry
	binding          capability.ExecutionBinding
	ctx              context.Context
	cancel           context.CancelCauseFunc
	done             chan struct{}
	cancelled        chan struct{}
	mu               sync.Mutex
	once             sync.Once
	cancelOnce       sync.Once
	cancelAckOnce    sync.Once
	timer            *time.Timer
	cancelAckTimer   *time.Timer
	parentStop       func() bool
	operation        *hostOperationSink
	stream           *hostStreamSink
	cancelDispatch   operationCancelDispatch
	dispatchComplete bool
	setupRollback    error
	validateBinding  func(context.Context) error
}

type operationCancelDispatch func(context.Context, capability.OperationCancellation) error

func newExecutionLeaseRegistry() *executionLeaseRegistry {
	return &executionLeaseRegistry{
		leases:           map[string]*executionLease{},
		leasesByPlugin:   map[string]map[string]*executionLease{},
		operations:       map[string]*executionLease{},
		streams:          map[string]*hostStreamSink{},
		activeByQuotaKey: map[executionQuotaKey]int{},
		setupRollbacks:   map[string]*executionLease{},
		pluginGates:      map[string]*executionPluginGate{},
	}
}

func (r *executionLeaseRegistry) beginTerminalMaintenance(now time.Time) bool {
	if r == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminalMaintenanceRunning || (!r.terminalMaintenanceNext.IsZero() && now.Before(r.terminalMaintenanceNext)) {
		return false
	}
	r.terminalMaintenanceRunning = true
	r.terminalMaintenanceNext = now.Add(terminalExecutionMaintenanceInterval)
	return true
}

func (r *executionLeaseRegistry) finishTerminalMaintenance() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.terminalMaintenanceRunning = false
	r.mu.Unlock()
}

func (r *executionLeaseRegistry) start(parent context.Context, binding capability.ExecutionBinding, validate func(context.Context) error) (*executionLease, error) {
	releasePlugin := r.lockPlugin(binding.PluginInstanceID, false)
	defer releasePlugin()
	if err := validate(parent); err != nil {
		return nil, err
	}
	quotaKey := executionQuotaKeyFor(binding)
	r.mu.Lock()
	defer r.mu.Unlock()
	if binding.Quota.MaxConcurrent > 0 {
		if r.activeByQuotaKey[quotaKey] >= binding.Quota.MaxConcurrent {
			return nil, capability.ErrQuotaExceeded
		}
	}
	base := parent
	async := binding.Execution == string(manifest.MethodExecutionOperation) || binding.Execution == string(manifest.MethodExecutionSubscription)
	if async {
		base = context.WithoutCancel(parent)
	}
	ctx, cancel := context.WithCancelCause(base)
	lease := &executionLease{
		registry:        r,
		binding:         binding,
		ctx:             ctx,
		cancel:          cancel,
		done:            make(chan struct{}),
		cancelled:       make(chan struct{}),
		validateBinding: validate,
	}
	if async {
		stop := context.AfterFunc(parent, func() {
			lease.requestCancel(context.Cause(parent))
		})
		lease.setParentStop(stop)
	}
	r.leases[binding.InvocationID] = lease
	pluginLeases := r.leasesByPlugin[binding.PluginInstanceID]
	if pluginLeases == nil {
		pluginLeases = map[string]*executionLease{}
		r.leasesByPlugin[binding.PluginInstanceID] = pluginLeases
	}
	pluginLeases[binding.InvocationID] = lease
	r.activeByQuotaKey[quotaKey]++
	return lease, nil
}

func (r *executionLeaseRegistry) cancelPlugin(pluginInstanceID string, cause error) []*executionLease {
	releasePlugin := r.lockPlugin(pluginInstanceID, true)
	defer releasePlugin()
	r.mu.Lock()
	pluginLeases := r.leasesByPlugin[pluginInstanceID]
	leasing := make([]*executionLease, 0, len(pluginLeases))
	for _, lease := range pluginLeases {
		leasing = append(leasing, lease)
	}
	r.mu.Unlock()
	for _, lease := range leasing {
		lease.requestCancel(cause)
	}
	return leasing
}

func (r *executionLeaseRegistry) cancelAll(cause error) []*executionLease {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	leasing := make([]*executionLease, 0, len(r.leases))
	for _, lease := range r.leases {
		leasing = append(leasing, lease)
	}
	r.mu.Unlock()
	for _, lease := range leasing {
		lease.requestCancel(cause)
	}
	return leasing
}

func (r *executionLeaseRegistry) finishAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	leases := make([]*executionLease, 0, len(r.leases))
	for _, lease := range r.leases {
		leases = append(leases, lease)
	}
	r.mu.Unlock()
	for _, lease := range leases {
		lease.finish()
	}
}

func reconcileRevokedExecutions(ctx context.Context, leases []*executionLease, cause error) {
	for _, lease := range leases {
		operationSink, streamSink, _ := lease.snapshotExecution()
		var err error
		if streamSink != nil {
			err = streamSink.failCauseUnchecked(ctx, capability.ExecutionFailurePlatformFailed, cause)
		} else if operationSink != nil {
			err = operationSink.terminateUnchecked(ctx, capability.ExecutionFailurePlatformFailed, cause)
		}
		if err != nil {
			lease.markSetupRollbackPending(cause)
		}
	}
}

func (r *executionLeaseRegistry) cancelOperation(ctx context.Context, req capability.OperationCancellation, cause error) (bool, error) {
	r.mu.Lock()
	matched := r.operations[strings.TrimSpace(req.OperationID)]
	r.mu.Unlock()
	if matched == nil {
		return false, nil
	}
	binding, err := capability.CloneExecutionBinding(matched.binding)
	if err != nil {
		return true, err
	}
	req.Execution = capability.ExecutionContext{ExecutionBinding: binding}
	req.OperationID = binding.OperationID
	matched.requestCancel(cause)
	operationSink, _, dispatch := matched.snapshotExecution()
	if operationSink != nil {
		matched.armCancelAckTimeout(operationSink.host, operationSink.ackTimeout)
	}
	if dispatch != nil {
		return true, dispatch(ctx, req)
	}
	return true, nil
}

func (r *executionLeaseRegistry) streamSink(streamID string) (*hostStreamSink, error) {
	if r == nil || strings.TrimSpace(streamID) == "" {
		return nil, stream.ErrNotFound
	}
	r.mu.Lock()
	streamSink := r.streams[strings.TrimSpace(streamID)]
	r.mu.Unlock()
	if streamSink != nil {
		return streamSink, nil
	}
	return nil, stream.ErrNotFound
}

func (r *executionLeaseRegistry) hasOperation(operationID string) bool {
	if r == nil || strings.TrimSpace(operationID) == "" {
		return false
	}
	r.mu.Lock()
	_, ok := r.operations[strings.TrimSpace(operationID)]
	r.mu.Unlock()
	return ok
}

func executionQuotaKeyFor(binding capability.ExecutionBinding) executionQuotaKey {
	return executionQuotaKey{
		pluginInstanceID: binding.PluginInstanceID,
		capabilityID:     binding.CapabilityID,
		method:           binding.Method,
	}
}

func (r *executionLeaseRegistry) lockPlugin(pluginInstanceID string, write bool) func() {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	r.mu.Lock()
	gate := r.pluginGates[pluginInstanceID]
	if gate == nil {
		gate = &executionPluginGate{}
		r.pluginGates[pluginInstanceID] = gate
	}
	gate.refs++
	r.mu.Unlock()
	if write {
		gate.mu.Lock()
	} else {
		gate.mu.RLock()
	}
	return func() {
		if write {
			gate.mu.Unlock()
		} else {
			gate.mu.RUnlock()
		}
		r.mu.Lock()
		gate.refs--
		if gate.refs == 0 && r.pluginGates[pluginInstanceID] == gate {
			delete(r.pluginGates, pluginInstanceID)
		}
		r.mu.Unlock()
	}
}

func (r *executionLeaseRegistry) indexOperation(lease *executionLease, operationSink *hostOperationSink) {
	if r == nil || lease == nil || operationSink == nil {
		return
	}
	r.mu.Lock()
	if r.leases[lease.binding.InvocationID] == lease {
		r.operations[operationSink.operationID] = lease
	}
	r.mu.Unlock()
}

func (r *executionLeaseRegistry) indexStream(lease *executionLease, streamSink *hostStreamSink) {
	if r == nil || lease == nil || streamSink == nil {
		return
	}
	r.mu.Lock()
	if r.leases[lease.binding.InvocationID] == lease {
		r.streams[streamSink.streamID] = streamSink
	}
	r.mu.Unlock()
}

func (l *executionLease) validate(ctx context.Context) error {
	select {
	case <-l.done:
		return capability.ErrExecutionRevoked
	default:
	}
	if err := context.Cause(l.ctx); err != nil {
		return capability.ErrExecutionRevoked
	}
	return l.validateBinding(ctx)
}

func (l *executionLease) requestCancel(cause error) {
	if cause == nil {
		cause = capability.ErrExecutionRevoked
	}
	l.cancelOnce.Do(func() {
		close(l.cancelled)
		l.cancel(cause)
	})
}

func (l *executionLease) finish() bool {
	finished := false
	l.once.Do(func() {
		finished = true
		l.mu.Lock()
		timer := l.timer
		l.timer = nil
		cancelAckTimer := l.cancelAckTimer
		l.cancelAckTimer = nil
		parentStop := l.parentStop
		l.parentStop = nil
		operationSink := l.operation
		streamSink := l.stream
		l.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if cancelAckTimer != nil {
			cancelAckTimer.Stop()
		}
		if parentStop != nil {
			parentStop()
		}
		l.cancel(nil)
		close(l.done)
		l.registry.mu.Lock()
		if l.registry.leases[l.binding.InvocationID] == l {
			delete(l.registry.leases, l.binding.InvocationID)
			pluginLeases := l.registry.leasesByPlugin[l.binding.PluginInstanceID]
			delete(pluginLeases, l.binding.InvocationID)
			if len(pluginLeases) == 0 {
				delete(l.registry.leasesByPlugin, l.binding.PluginInstanceID)
			}
			quotaKey := executionQuotaKeyFor(l.binding)
			if active := l.registry.activeByQuotaKey[quotaKey]; active <= 1 {
				delete(l.registry.activeByQuotaKey, quotaKey)
			} else {
				l.registry.activeByQuotaKey[quotaKey] = active - 1
			}
			if operationSink != nil && l.registry.operations[operationSink.operationID] == l {
				delete(l.registry.operations, operationSink.operationID)
			}
			if streamSink != nil && l.registry.streams[streamSink.streamID] == streamSink {
				delete(l.registry.streams, streamSink.streamID)
			}
			delete(l.registry.setupRollbacks, l.binding.InvocationID)
		}
		l.registry.mu.Unlock()
	})
	return finished
}

func (l *executionLease) detachParent() {
	l.mu.Lock()
	parentStop := l.parentStop
	l.parentStop = nil
	l.mu.Unlock()
	if parentStop != nil {
		parentStop()
	}
}

func (l *executionLease) markDispatchComplete() {
	l.mu.Lock()
	l.dispatchComplete = true
	l.mu.Unlock()
}

func (l *executionLease) markSetupRollbackPending(cause error) {
	l.mu.Lock()
	l.setupRollback = cause
	l.registry.mu.Lock()
	if l.registry.leases[l.binding.InvocationID] == l {
		l.registry.setupRollbacks[l.binding.InvocationID] = l
	}
	l.registry.mu.Unlock()
	l.mu.Unlock()
}

func (l *executionLease) setupRollbackCause() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.setupRollback
}

func (l *executionLease) dispatchCompleted() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dispatchComplete
}

func (l *executionLease) armTimeout(host *Host) {
	if host == nil || l.binding.Quota.ExpiresAt.IsZero() {
		return
	}
	delay := time.Until(l.binding.Quota.ExpiresAt)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		timer.Stop()
		return
	default:
		l.timer = timer
	}
	l.mu.Unlock()
	started := host.startLifecycleJob(func(ctx context.Context) {
		select {
		case <-timer.C:
			l.requestCancel(capability.ErrQuotaExceeded)
			operationSink, streamSink, _ := l.snapshotExecution()
			var err error
			if streamSink != nil {
				err = streamSink.failCauseUnchecked(ctx, capability.ExecutionFailureQuotaExceeded, capability.ErrQuotaExceeded)
			} else if operationSink != nil {
				err = operationSink.terminateUnchecked(ctx, capability.ExecutionFailureQuotaExceeded, capability.ErrQuotaExceeded)
			}
			if err != nil {
				host.diagnostic(ctx, observability.DiagnosticEvent{
					Type:                 "plugin.execution.duration_terminal_failed",
					Severity:             observability.DiagnosticSeverityWarning,
					Message:              "duration quota terminal state could not be persisted",
					PluginID:             l.binding.PluginID,
					PluginInstanceID:     l.binding.PluginInstanceID,
					SurfaceInstanceID:    l.binding.SurfaceInstanceID,
					OwnerSessionHash:     l.binding.OwnerSessionHash,
					OwnerUserHash:        l.binding.OwnerUserHash,
					OwnerEnvHash:         l.binding.OwnerEnvHash,
					SessionChannelIDHash: l.binding.SessionChannelIDHash,
					InternalDetails: map[string]any{
						"failure": observability.FailureFromError(observability.FailureAdapter, "execution.duration_terminal", err),
					},
				})
			}
			l.finish()
		case <-l.done:
		case <-ctx.Done():
		}
	})
	if !started {
		timer.Stop()
	}
}

func (l *executionLease) armCancelAckTimeout(host *Host, timeout time.Duration) {
	if host == nil || timeout <= 0 {
		return
	}
	l.cancelAckOnce.Do(func() {
		timer := time.NewTimer(timeout)
		l.mu.Lock()
		select {
		case <-l.done:
			l.mu.Unlock()
			timer.Stop()
			return
		default:
			l.cancelAckTimer = timer
		}
		l.mu.Unlock()
		started := host.startLifecycleJob(func(ctx context.Context) {
			select {
			case <-timer.C:
				operationSink, streamSink, _ := l.snapshotExecution()
				var err error
				if streamSink != nil {
					err = streamSink.closeWithStatus(ctx, stream.StatusCanceled, operation.StatusCanceled, "cancellation acknowledgement timed out", "")
				} else if operationSink != nil {
					err = operationSink.terminateUnchecked(ctx, capability.ExecutionFailurePlatformFailed, errors.New("cancellation acknowledgement timed out"))
				}
				if err != nil {
					l.finish()
				}
			case <-l.done:
			case <-ctx.Done():
			}
		})
		if !started {
			timer.Stop()
		}
	})
}

func waitForCancellationReconcile(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *executionLease) setOperation(operationSink *hostOperationSink, dispatch operationCancelDispatch) {
	l.mu.Lock()
	l.operation = operationSink
	l.cancelDispatch = dispatch
	l.mu.Unlock()
	l.registry.indexOperation(l, operationSink)
}

func (l *executionLease) setStream(streamSink *hostStreamSink) {
	l.mu.Lock()
	l.stream = streamSink
	l.mu.Unlock()
	l.registry.indexStream(l, streamSink)
}

func (l *executionLease) setParentStop(stop func() bool) {
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		stop()
		return
	default:
		l.parentStop = stop
		l.mu.Unlock()
	}
}

func (l *executionLease) snapshotExecution() (*hostOperationSink, *hostStreamSink, operationCancelDispatch) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.operation, l.stream, l.cancelDispatch
}

func (r *executionLeaseRegistry) pendingSetupRollbacks(pluginInstanceID string) []*executionLease {
	r.mu.Lock()
	leases := make([]*executionLease, 0, len(r.setupRollbacks))
	for _, lease := range r.setupRollbacks {
		if lease.binding.PluginInstanceID == pluginInstanceID {
			leases = append(leases, lease)
		}
	}
	r.mu.Unlock()
	return leases
}

type hostOperationSink struct {
	host        *Host
	lease       *executionLease
	operationID string
	ackTimeout  time.Duration
}

func (s *hostOperationSink) ID() string { return s.operationID }

func (s *hostOperationSink) Complete(ctx context.Context) error {
	if err := s.lease.validate(ctx); err != nil {
		return err
	}
	if _, streamSink, _ := s.lease.snapshotExecution(); streamSink != nil {
		return streamSink.closeWithStatus(ctx, stream.StatusClosed, operation.StatusCompleted, "", "")
	}
	record, err := s.host.adapters.Operations.Finish(ctx, operation.FinishRequest{OperationID: s.operationID, Status: operation.StatusCompleted})
	if err == nil && s.lease.finish() {
		if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Details: map[string]any{"operation_id": record.OperationID, "status": record.Status}}); auditErr != nil {
			err = mutation.Unknown(auditErr)
		}
		s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	}
	return err
}

func (s *hostOperationSink) Cancel(ctx context.Context, reason string) error {
	select {
	case <-s.lease.done:
		return capability.ErrExecutionRevoked
	default:
	}
	current, err := s.host.adapters.Operations.Get(ctx, s.operationID)
	if err != nil {
		return err
	}
	if current.Status != operation.StatusCancelRequested {
		return operation.ErrInvalidOperation
	}
	if _, streamSink, _ := s.lease.snapshotExecution(); streamSink != nil {
		return streamSink.closeWithStatus(ctx, stream.StatusCanceled, operation.StatusCanceled, reason, "")
	}
	record, err := s.host.adapters.Operations.Finish(ctx, operation.FinishRequest{OperationID: s.operationID, Status: operation.StatusCanceled, Reason: reason})
	if err == nil && s.lease.finish() {
		if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Details: map[string]any{"operation_id": record.OperationID, "status": record.Status}}); auditErr != nil {
			err = mutation.Unknown(auditErr)
		}
		s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	}
	return err
}

func (s *hostOperationSink) Fail(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	if err := s.lease.validate(ctx); err != nil {
		return err
	}
	if _, streamSink, _ := s.lease.snapshotExecution(); streamSink != nil {
		return streamSink.failCauseUnchecked(ctx, code, cause)
	}
	return s.failCauseUnchecked(ctx, code, cause)
}

func (s *hostOperationSink) failUnchecked(ctx context.Context, code capability.ExecutionFailureCode) error {
	record, err := s.host.adapters.Operations.Finish(ctx, operation.FinishRequest{OperationID: s.operationID, Status: operation.StatusFailed, FailureCode: code})
	if err == nil && s.lease.finish() {
		if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Details: map[string]any{"operation_id": record.OperationID, "status": record.Status}}); auditErr != nil {
			err = mutation.Unknown(auditErr)
		}
		s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	}
	return err
}

func (s *hostOperationSink) failCauseUnchecked(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	s.reportFailureCause(ctx, code, cause)
	return s.failUnchecked(ctx, code)
}

func (s *hostOperationSink) terminateUnchecked(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	current, err := s.host.adapters.Operations.Get(ctx, s.operationID)
	if err != nil {
		return err
	}
	if operationTerminal(current.Status) {
		if s.lease.finish() {
			s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
		}
		return nil
	}
	status := operation.StatusFailed
	reason := executionFailedReason
	if current.Status == operation.StatusCancelRequested {
		status = operation.StatusCanceled
		reason = executionCanceledReason
	}
	request := operation.FinishRequest{
		OperationID: s.operationID,
		Status:      status,
		Reason:      reason,
	}
	if status == operation.StatusFailed {
		s.reportFailureCause(ctx, code, cause)
		request.FailureCode = code
		request.Reason = ""
	}
	record, err := s.host.adapters.Operations.Finish(ctx, request)
	if err == nil && s.lease.finish() {
		if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Details: map[string]any{"operation_id": record.OperationID, "status": record.Status}}); auditErr != nil {
			err = mutation.Unknown(auditErr)
		}
		s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	}
	return err
}

func (s *hostOperationSink) reportFailureCause(ctx context.Context, code capability.ExecutionFailureCode, cause error) {
	if s == nil || s.host == nil || s.lease == nil || cause == nil {
		return
	}
	s.host.reportExecutionFailure(ctx, s.lease.binding, code, cause)
}

func (s *hostOperationSink) CancelRequested() <-chan struct{} { return s.lease.cancelled }

type hostStreamSink struct {
	host              *Host
	lease             *executionLease
	streamID          string
	maxBytes          int64
	mu                sync.Mutex
	written           int64
	terminalIntent    *streamTerminalIntent
	terminalCommitted bool
	eventTypeName     string
	eventSchema       map[string]any
}

var errExecutionTerminalConflict = errors.New("execution terminal state conflicts with the first terminal intent")

type streamTerminalIntent struct {
	streamStatus    stream.Status
	operationStatus operation.Status
	failureCode     capability.ExecutionFailureCode
	reason          string
}

func (s *hostStreamSink) ID() string { return s.streamID }

func (s *hostStreamSink) Append(ctx context.Context, event any) error {
	if err := s.lease.validate(ctx); err != nil {
		return err
	}
	return s.appendEvent(ctx, event)
}

func (s *hostStreamSink) appendEvent(ctx context.Context, event any) error {
	if s.eventSchema != nil {
		if err := capabilitycontract.ValidateValue(s.eventSchema, event); err != nil {
			return fmt.Errorf("stream event does not match its signed contract: %w", err)
		}
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode stream event: %w", err)
	}
	kind := s.eventTypeName
	if kind == "" {
		kind = "event"
	}
	return s.appendEncoded(ctx, kind, data)
}

func (s *hostStreamSink) appendEncoded(ctx context.Context, kind string, data []byte) error {
	s.mu.Lock()
	if s.terminalIntent != nil {
		s.mu.Unlock()
		return stream.ErrInvalidStream
	}
	next := s.written + int64(len(data))
	if s.maxBytes > 0 && next > s.maxBytes {
		s.mu.Unlock()
		return capability.ErrQuotaExceeded
	}
	s.written = next
	s.mu.Unlock()
	_, err := s.host.adapters.Streams.Append(ctx, stream.AppendRequest{StreamID: s.streamID, Kind: kind, Data: append([]byte(nil), data...)})
	if err != nil {
		s.mu.Lock()
		s.written -= int64(len(data))
		if s.written < 0 {
			s.written = 0
		}
		s.mu.Unlock()
	}
	return err
}

func (s *hostStreamSink) Close(ctx context.Context) error {
	if err := s.lease.validate(ctx); err != nil {
		if terminalErr, handled := s.terminalResult(stream.StatusClosed, operation.StatusCompleted, "", ""); handled {
			return terminalErr
		}
		return err
	}
	return s.closeWithStatus(ctx, stream.StatusClosed, operation.StatusCompleted, "", "")
}

func (s *hostStreamSink) Fail(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	if err := s.lease.validate(ctx); err != nil {
		if terminalErr, handled := s.terminalResult(stream.StatusFailed, operation.StatusFailed, "", code); handled {
			return terminalErr
		}
		return err
	}
	return s.failCauseUnchecked(ctx, code, cause)
}

func (s *hostStreamSink) terminalResult(streamStatus stream.Status, operationStatus operation.Status, reason string, failureCode capability.ExecutionFailureCode) (error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalIntent == nil {
		return nil, false
	}
	requested := streamTerminalIntent{streamStatus: streamStatus, operationStatus: operationStatus, failureCode: failureCode, reason: reason}
	if *s.terminalIntent != requested {
		return fmt.Errorf("%w: stream %s already selected %s/%s", errExecutionTerminalConflict, s.streamID, s.terminalIntent.streamStatus, s.terminalIntent.operationStatus), true
	}
	if s.terminalCommitted {
		return nil, true
	}
	return nil, false
}

func (s *hostStreamSink) failUnchecked(ctx context.Context, code capability.ExecutionFailureCode) error {
	return s.closeWithStatus(ctx, stream.StatusFailed, operation.StatusFailed, "", code)
}

func (s *hostStreamSink) failCauseUnchecked(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	if s != nil && s.host != nil && s.lease != nil {
		s.host.reportExecutionFailure(ctx, s.lease.binding, code, cause)
	}
	return s.failUnchecked(ctx, code)
}

func (s *hostStreamSink) closeWithStatus(ctx context.Context, streamStatus stream.Status, operationStatus operation.Status, reason string, failureCode capability.ExecutionFailureCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	requested := streamTerminalIntent{streamStatus: streamStatus, operationStatus: operationStatus, failureCode: failureCode, reason: reason}
	if s.terminalIntent != nil && *s.terminalIntent != requested {
		return fmt.Errorf("%w: stream %s already selected %s/%s", errExecutionTerminalConflict, s.streamID, s.terminalIntent.streamStatus, s.terminalIntent.operationStatus)
	}
	if s.terminalIntent == nil {
		s.terminalIntent = &requested
	}
	if s.terminalCommitted {
		return nil
	}
	streamRecord, streamErr := s.host.adapters.Streams.Close(ctx, stream.CloseRequest{StreamID: s.streamID, Status: streamStatus, FailureCode: failureCode, Reason: reason})
	operationSink, _, _ := s.lease.snapshotExecution()
	var operationRecord operation.Record
	var operationErr error
	if operationSink != nil {
		operationRecord, operationErr = s.host.adapters.Operations.Finish(ctx, operation.FinishRequest{
			OperationID: operationSink.operationID,
			Status:      operationStatus,
			FailureCode: failureCode,
			Reason:      reason,
		})
	}
	if streamErr != nil || operationErr != nil {
		s.lease.markSetupRollbackPending(errors.Join(streamErr, operationErr))
		return errors.Join(streamErr, operationErr)
	}
	if streamRecord.Status != streamStatus || operationSink != nil && operationRecord.Status != operationStatus {
		conflict := fmt.Errorf("%w: durable operation and stream stores rejected %s/%s", errExecutionTerminalConflict, streamStatus, operationStatus)
		s.lease.markSetupRollbackPending(conflict)
		return conflict
	}
	s.terminalCommitted = true
	if s.lease.dispatchCompleted() {
		s.lease.finish()
	}
	if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.stream.closed", PluginID: streamRecord.PluginID, PluginInstanceID: streamRecord.PluginInstanceID, Details: map[string]any{"stream_id": streamRecord.StreamID, "status": streamRecord.Status}}); auditErr != nil {
		return mutation.Unknown(auditErr)
	}
	if operationSink != nil {
		if auditErr := s.host.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: operationRecord.PluginID, PluginInstanceID: operationRecord.PluginInstanceID, Details: map[string]any{"operation_id": operationRecord.OperationID, "status": operationRecord.Status}}); auditErr != nil {
			return mutation.Unknown(auditErr)
		}
	}
	s.host.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	return nil
}

func validateExecutionFailure(code capability.ExecutionFailureCode, cause error) error {
	if !code.Valid() || cause == nil {
		return capability.ErrInvalidExecutionFailure
	}
	return nil
}

func executionFailureCode(binding capability.ExecutionBinding, cause error) capability.ExecutionFailureCode {
	switch {
	case errors.Is(cause, capability.ErrQuotaExceeded):
		return capability.ExecutionFailureQuotaExceeded
	case errors.Is(cause, ErrMethodResponseContract), errors.Is(cause, ErrMethodRequestContract):
		return capability.ExecutionFailureContractInvalid
	case binding.RouteKind == capability.RouteWorker:
		return capability.ExecutionFailureRuntimeFailed
	case binding.RouteKind == capability.RouteCapability, binding.RouteKind == capability.RouteCoreAction:
		return capability.ExecutionFailureAdapterFailed
	default:
		return capability.ExecutionFailurePlatformFailed
	}
}

func (s *hostStreamSink) isTerminal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalCommitted
}

func operationCancelDispatchFor(adapter any) operationCancelDispatch {
	canceler, ok := adapter.(capability.OperationCanceler)
	if !ok {
		return nil
	}
	return canceler.CancelOperation
}

type hostRuntimeStreamSink struct {
	executions *executionLeaseRegistry
}

func (s hostRuntimeStreamSink) AppendRuntimeStream(ctx context.Context, streamID, kind string, data []byte) error {
	sink, err := s.executions.streamSink(streamID)
	if err != nil {
		return err
	}
	if err := sink.lease.validate(ctx); err != nil {
		return err
	}
	if sink.eventSchema == nil {
		return sink.appendEncoded(ctx, kind, data)
	}
	if kind != sink.eventTypeName {
		return errors.New("runtime stream event type does not match its signed contract")
	}
	var event any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return fmt.Errorf("decode runtime stream event: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("runtime stream event must contain exactly one JSON value")
	}
	return sink.appendEvent(ctx, event)
}

func (s hostRuntimeStreamSink) CloseRuntimeStream(ctx context.Context, streamID string) error {
	sink, err := s.executions.streamSink(streamID)
	if err != nil {
		return err
	}
	return sink.Close(ctx)
}

func (s hostRuntimeStreamSink) FailRuntimeStream(ctx context.Context, streamID string, code capability.ExecutionFailureCode, cause error) error {
	sink, err := s.executions.streamSink(streamID)
	if err != nil {
		return err
	}
	return sink.Fail(ctx, code, cause)
}

func operationTerminal(status operation.Status) bool {
	switch status {
	case operation.StatusCanceled, operation.StatusCompleted, operation.StatusFailed, operation.StatusOrphanedAfterDisable, operation.StatusOrphanedAfterUninstall:
		return true
	default:
		return false
	}
}
