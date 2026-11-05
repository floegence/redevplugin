package host

import (
	"errors"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestInstallFailureClassifiesKnownPlatformFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		want      security.ErrorCode
		retryable bool
	}{
		{name: "adapter", err: ErrAdapterFailure, want: security.ErrAdapterFailure},
		{name: "feature", err: FeatureNotConfiguredError{Features: []Feature{FeatureCapability}}, want: security.ErrFeatureNotConfigured},
		{name: "feature sentinel", err: ErrFeatureNotConfigured, want: security.ErrFeatureNotConfigured},
		{name: "data binding", err: plugindata.ErrBindingConflict, want: security.ErrInstallStateConflict},
		{name: "data binding revision", err: plugindata.ErrBindingRevisionConflict, want: security.ErrInstallStateConflict},
		{name: "data not retained", err: plugindata.ErrNotRetained, want: security.ErrInstallStateConflict},
		{name: "runtime not configured", err: ErrPluginRuntimeNotConfigured, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime feature missing", err: FeatureNotConfiguredError{Features: []Feature{FeatureRuntime}}, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime not ready", err: ErrRuntimeNotReady, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime ipc", err: ErrRuntimeIPCUnavailable, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime request", err: ErrRuntimeRequestFailed, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime handshake", err: ErrRuntimeHandshake, want: security.ErrRuntimeUnavailable, retryable: true},
		{name: "runtime version mismatch", err: ErrPluginRuntimeIncompatible, want: security.ErrRuntimeVersionMismatch},
		{name: "unknown internal", err: errors.New("unexpected install failure"), want: security.ErrInternalFailure, retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := installFailureCode(test.err); got != string(test.want) {
				t.Fatalf("installFailureCode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallFailureClassifiesPackageValidationErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		code pluginpkg.ValidationErrorCode
		want security.ErrorCode
	}{
		{name: "manifest", code: pluginpkg.ValidationCodeManifestInvalid, want: security.ErrManifestInvalid},
		{name: "package", code: pluginpkg.ValidationCodePackageInvalid, want: security.ErrPackageInvalid},
		{name: "too large", code: pluginpkg.ValidationCodePackageTooLarge, want: security.ErrPackageTooLarge},
		{name: "path", code: pluginpkg.ValidationCodePackagePathForbidden, want: security.ErrPackagePathForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := &pluginpkg.ValidationError{Code: test.code, Message: "invalid package"}
			if got := installFailureCode(err); got != string(test.want) {
				t.Fatalf("installFailureCode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallFailureClassifiesRetainedDataShapeMismatch(t *testing.T) {
	if got := installFailureCode(plugindata.ErrShapeMismatch); got != string(security.ErrRetainedDataIncompatible) {
		t.Fatalf("installFailureCode() = %q, want %q", got, security.ErrRetainedDataIncompatible)
	}
}

func TestInstallFailureClassifiesNetworkPolicyDenials(t *testing.T) {
	for _, code := range []externalsource.ErrorCode{externalsource.ErrorTargetBlocked, externalsource.ErrorRedirectDenied, externalsource.ErrorTooManyRedirects} {
		err := &externalsource.Error{Code: code, Operation: "resolve"}
		if got := installFailureCode(err); got != string(security.ErrNetworkTargetDenied) {
			t.Fatalf("code %s mapped to %s; want explicit network policy denial", code, got)
		}
	}
}
