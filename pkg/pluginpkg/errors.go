package pluginpkg

import "fmt"

type ValidationErrorCode string

const (
	ValidationCodeManifestInvalid      ValidationErrorCode = "PLUGIN_MANIFEST_INVALID"
	ValidationCodePackageInvalid       ValidationErrorCode = "PLUGIN_PACKAGE_INVALID"
	ValidationCodePackageTooLarge      ValidationErrorCode = "PLUGIN_PACKAGE_TOO_LARGE"
	ValidationCodePackagePathForbidden ValidationErrorCode = "PLUGIN_PACKAGE_PATH_FORBIDDEN"
)

type ValidationError struct {
	Code    ValidationErrorCode
	Reason  string
	Path    string
	Pointer string
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return string(e.Code)
}

func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *ValidationError) Details() map[string]any {
	if e == nil {
		return nil
	}
	details := map[string]any{}
	if e.Reason != "" {
		details["reason"] = e.Reason
	}
	if e.Path != "" {
		details["path"] = e.Path
	}
	if e.Pointer != "" {
		details["pointer"] = e.Pointer
	}
	if len(details) == 0 {
		return nil
	}
	return details
}

func validationErrorf(code ValidationErrorCode, reason string, entryPath string, pointer string, format string, args ...any) *ValidationError {
	return &ValidationError{
		Code:    code,
		Reason:  reason,
		Path:    entryPath,
		Pointer: pointer,
		Message: fmt.Sprintf(format, args...),
	}
}

func wrapValidationError(code ValidationErrorCode, reason string, entryPath string, pointer string, err error) *ValidationError {
	if err == nil {
		return nil
	}
	return &ValidationError{
		Code:    code,
		Reason:  reason,
		Path:    entryPath,
		Pointer: pointer,
		Message: err.Error(),
		Cause:   err,
	}
}
