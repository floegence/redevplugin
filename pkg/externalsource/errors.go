package externalsource

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable classification for external-source admission failures.
type ErrorCode string

const (
	ErrorInvalidURL           ErrorCode = "external_source_invalid_url"
	ErrorInvalidSource        ErrorCode = "external_source_invalid_source"
	ErrorTargetBlocked        ErrorCode = "external_source_target_blocked"
	ErrorDNS                  ErrorCode = "external_source_dns_failed"
	ErrorRedirectDenied       ErrorCode = "external_source_redirect_denied"
	ErrorTooManyRedirects     ErrorCode = "external_source_too_many_redirects"
	ErrorCredentialDenied     ErrorCode = "external_source_credential_denied"
	ErrorTransport            ErrorCode = "external_source_transport_failed"
	ErrorHTTPStatus           ErrorCode = "external_source_http_status"
	ErrorUnsupportedEncoding  ErrorCode = "external_source_unsupported_encoding"
	ErrorArtifactTooLarge     ErrorCode = "external_source_artifact_too_large"
	ErrorArtifactEmpty        ErrorCode = "external_source_artifact_empty"
	ErrorGitHubRelease        ErrorCode = "external_source_github_release_failed"
	ErrorGitHubAssetMissing   ErrorCode = "external_source_github_asset_missing"
	ErrorGitHubAssetAmbiguous ErrorCode = "external_source_github_asset_ambiguous"
	ErrorStageInvalid         ErrorCode = "external_source_stage_invalid"
	ErrorStageIntegrity       ErrorCode = "external_source_stage_integrity_failed"
	ErrorQuotaExceeded        ErrorCode = "external_source_quota_exceeded"
)

// Error intentionally omits the wrapped cause from Error() so URL query
// credentials and transport headers cannot be copied into user-facing errors.
type Error struct {
	Code       ErrorCode
	Operation  string
	DisplayURL string
	cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return "external source error"
	}
	message := string(e.Code)
	if e.Operation != "" {
		message = e.Operation + ": " + message
	}
	if e.DisplayURL != "" {
		message += " (" + e.DisplayURL + ")"
	}
	return message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func externalError(code ErrorCode, operation, displayURL string, cause error) error {
	return &Error{Code: code, Operation: operation, DisplayURL: displayURL, cause: cause}
}

// CodeOf returns the stable external-source code carried by err.
func CodeOf(err error) ErrorCode {
	var external *Error
	if errors.As(err, &external) {
		return external.Code
	}
	return ""
}

func invalidSource(operation string, format string, args ...any) error {
	return externalError(ErrorInvalidSource, operation, "", fmt.Errorf(format, args...))
}
