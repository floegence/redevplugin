package host

import (
	"context"
	"errors"
	"slices"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

const (
	installFailureInterrupted = string(security.ErrInstallInterrupted)
	installFailureConflict    = string(security.ErrInstallStateConflict)
	installFailureInternal    = string(security.ErrInternalFailure)
)

func installFailureCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return string(security.ErrReleaseTimeout)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return installFailureInterrupted
	}
	switch externalsource.CodeOf(err) {
	case externalsource.ErrorTargetBlocked, externalsource.ErrorRedirectDenied, externalsource.ErrorTooManyRedirects:
		return string(security.ErrNetworkTargetDenied)
	case externalsource.ErrorDNS, externalsource.ErrorTransport:
		return string(security.ErrReleaseNetwork)
	case externalsource.ErrorHTTPStatus:
		if externalsource.HTTPStatusOf(err) == 404 {
			return string(security.ErrReleaseAssetMissing)
		}
		return string(security.ErrReleaseNetwork)
	case externalsource.ErrorStageIntegrity:
		return string(security.ErrReleaseAssetIntegrity)
	}
	if errors.Is(err, ErrManagementRevisionMismatch) || errors.Is(err, registry.ErrManagementRevisionConflict) {
		return string(security.ErrManagementRevisionMismatch)
	}
	if errors.Is(err, ErrUpdateReviewRequired) {
		return string(security.ErrConfirmationRequired)
	}
	if errors.Is(err, ErrExternalPackageConfirmation) {
		return string(security.ErrConfirmationInvalid)
	}
	if errors.Is(err, ErrExternalPackageRequestInvalid) {
		return string(security.ErrInvalidRequest)
	}
	if errors.Is(err, ErrActionDenied) {
		return string(security.ErrActionDenied)
	}
	if errors.Is(err, ErrOwnerScopeMismatch) {
		return string(security.ErrOwnerScopeMismatch)
	}
	if errors.Is(err, ErrPluginAlreadyInstalled) {
		return installFailureConflict
	}
	if errors.Is(err, plugindata.ErrShapeMismatch) {
		return string(security.ErrRetainedDataIncompatible)
	}
	if errors.Is(err, plugindata.ErrBindingNotFound) || errors.Is(err, plugindata.ErrBindingConflict) ||
		errors.Is(err, plugindata.ErrBindingRevisionConflict) || errors.Is(err, plugindata.ErrNotActive) ||
		errors.Is(err, plugindata.ErrNotRetained) || errors.Is(err, plugindata.ErrRevisionConflict) {
		return installFailureConflict
	}
	if errors.Is(err, ErrPluginRuntimeNotConfigured) {
		return string(security.ErrRuntimeUnavailable)
	}
	if isWorkerRuntimeUnavailable(err) {
		return string(security.ErrRuntimeUnavailable)
	}
	if errors.Is(err, ErrPluginRuntimeIncompatible) {
		return string(security.ErrRuntimeVersionMismatch)
	}
	var missingFeatures FeatureNotConfiguredError
	if errors.As(err, &missingFeatures) {
		if slices.Contains(missingFeatures.MissingFeatures(), FeatureRuntime) {
			return string(security.ErrRuntimeUnavailable)
		}
		return string(security.ErrFeatureNotConfigured)
	}
	if errors.Is(err, ErrFeatureNotConfigured) {
		return string(security.ErrFeatureNotConfigured)
	}
	if errors.Is(err, ErrAdapterFailure) {
		return string(security.ErrAdapterFailure)
	}
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		switch packageValidationErr.Code {
		case pluginpkg.ValidationCodeManifestInvalid:
			return string(security.ErrManifestInvalid)
		case pluginpkg.ValidationCodePackageInvalid:
			return string(security.ErrPackageInvalid)
		case pluginpkg.ValidationCodePackageTooLarge:
			return string(security.ErrPackageTooLarge)
		case pluginpkg.ValidationCodePackagePathForbidden:
			return string(security.ErrPackagePathForbidden)
		}
	}
	return installFailureInternal
}

func isWorkerRuntimeUnavailable(err error) bool {
	return errors.Is(err, ErrRuntimeNotReady) || errors.Is(err, ErrRuntimeIPCUnavailable) ||
		errors.Is(err, ErrRuntimeRequestFailed) || errors.Is(err, ErrRuntimeHandshake)
}
