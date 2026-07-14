package security

type ErrorCode string

const (
	ErrInvalidRequest               ErrorCode = "PLUGIN_INVALID_REQUEST"
	ErrManifestInvalid              ErrorCode = "PLUGIN_MANIFEST_INVALID"
	ErrPackageInvalid               ErrorCode = "PLUGIN_PACKAGE_INVALID"
	ErrPackageTooLarge              ErrorCode = "PLUGIN_PACKAGE_TOO_LARGE"
	ErrPackagePathForbidden         ErrorCode = "PLUGIN_PACKAGE_PATH_FORBIDDEN"
	ErrSignatureInvalid             ErrorCode = "PLUGIN_SIGNATURE_INVALID"
	ErrTrustStateDenied             ErrorCode = "PLUGIN_TRUST_STATE_DENIED"
	ErrTrustVerificationRequired    ErrorCode = "PLUGIN_TRUST_VERIFICATION_REQUIRED"
	ErrTrustVerificationInvalid     ErrorCode = "PLUGIN_TRUST_VERIFICATION_INVALID"
	ErrReleaseRefVerificationFailed ErrorCode = "PLUGIN_RELEASE_REF_VERIFICATION_FAILED"
	ErrReleaseRefPolicyDenied       ErrorCode = "PLUGIN_RELEASE_REF_POLICY_DENIED"
	ErrDisabled                     ErrorCode = "PLUGIN_DISABLED"
	ErrDisabledByPolicy             ErrorCode = "PLUGIN_DISABLED_BY_POLICY"
	ErrPermissionDenied             ErrorCode = "PLUGIN_PERMISSION_DENIED"
	ErrConfirmationRequired         ErrorCode = "PLUGIN_CONFIRMATION_REQUIRED"
	ErrConfirmationInvalid          ErrorCode = "PLUGIN_CONFIRMATION_INVALID"
	ErrConfirmationRejected         ErrorCode = "PLUGIN_CONFIRMATION_REJECTED"
	ErrTokenExpired                 ErrorCode = "PLUGIN_TOKEN_EXPIRED"
	ErrTokenReplay                  ErrorCode = "PLUGIN_TOKEN_REPLAY"
	ErrGatewayTokenInvalid          ErrorCode = "PLUGIN_GATEWAY_TOKEN_INVALID"
	ErrGatewayTokenReplayed         ErrorCode = "PLUGIN_GATEWAY_TOKEN_REPLAYED"
	ErrGatewayTokenChannelMismatch  ErrorCode = "PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH"
	ErrAssetTicketInvalid           ErrorCode = "PLUGIN_ASSET_TICKET_INVALID"
	ErrAssetSessionInvalid          ErrorCode = "PLUGIN_ASSET_SESSION_INVALID"
	ErrStreamTicketInvalid          ErrorCode = "PLUGIN_STREAM_TICKET_INVALID"
	ErrStreamCancelled              ErrorCode = "PLUGIN_STREAM_CANCELLED"
	ErrLeaseInvalid                 ErrorCode = "PLUGIN_LEASE_INVALID"
	ErrLeaseReplayed                ErrorCode = "PLUGIN_LEASE_REPLAYED"
	ErrGrantInvalid                 ErrorCode = "PLUGIN_GRANT_INVALID"
	ErrStorageQuotaExceeded         ErrorCode = "PLUGIN_STORAGE_QUOTA_EXCEEDED"
	ErrOperationBlocked             ErrorCode = "PLUGIN_OPERATION_BLOCKED"
	ErrOperationNotFound            ErrorCode = "PLUGIN_OPERATION_NOT_FOUND"
	ErrOperationNotCancelable       ErrorCode = "PLUGIN_OPERATION_NOT_CANCELABLE"
	ErrNetworkTargetDenied          ErrorCode = "PLUGIN_NETWORK_TARGET_DENIED"
	ErrNetworkRateLimited           ErrorCode = "PLUGIN_NETWORK_RATE_LIMITED"
	ErrRuntimeUnavailable           ErrorCode = "PLUGIN_RUNTIME_UNAVAILABLE"
	ErrRuntimeVersionMismatch       ErrorCode = "PLUGIN_RUNTIME_VERSION_MISMATCH"
	ErrJSONLimitExceeded            ErrorCode = "PLUGIN_JSON_LIMIT_EXCEEDED"
	ErrCapabilityError              ErrorCode = "PLUGIN_CAPABILITY_ERROR"
	ErrContractMismatch             ErrorCode = "PLUGIN_CONTRACT_MISMATCH"
	ErrStateVersionMismatch         ErrorCode = "PLUGIN_STATE_VERSION_MISMATCH"
	ErrCSRFRequired                 ErrorCode = "PLUGIN_CSRF_REQUIRED"
	ErrRetainedDataCleanupFailed    ErrorCode = "PLUGIN_RETAINED_DATA_CLEANUP_FAILED"
	ErrRetainedDataBindFailed       ErrorCode = "PLUGIN_RETAINED_DATA_BIND_FAILED"

	ErrBridgeTimeout           ErrorCode = "PLUGIN_BRIDGE_TIMEOUT"
	ErrBridgeDisposed          ErrorCode = "PLUGIN_BRIDGE_DISPOSED"
	ErrBridgeHandshakeFailed   ErrorCode = "PLUGIN_BRIDGE_HANDSHAKE_FAILED"
	ErrBridgeHandshakeRequired ErrorCode = "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED"
	ErrPlatformRequestFailed   ErrorCode = "PLUGIN_PLATFORM_REQUEST_FAILED"
	ErrStreamFailed            ErrorCode = "PLUGIN_STREAM_FAILED"
)

var platformErrorCodes = []ErrorCode{
	ErrInvalidRequest,
	ErrManifestInvalid,
	ErrPackageInvalid,
	ErrPackageTooLarge,
	ErrPackagePathForbidden,
	ErrSignatureInvalid,
	ErrTrustStateDenied,
	ErrTrustVerificationRequired,
	ErrTrustVerificationInvalid,
	ErrReleaseRefVerificationFailed,
	ErrReleaseRefPolicyDenied,
	ErrDisabled,
	ErrDisabledByPolicy,
	ErrPermissionDenied,
	ErrConfirmationRequired,
	ErrConfirmationInvalid,
	ErrTokenExpired,
	ErrTokenReplay,
	ErrGatewayTokenInvalid,
	ErrGatewayTokenReplayed,
	ErrGatewayTokenChannelMismatch,
	ErrAssetTicketInvalid,
	ErrAssetSessionInvalid,
	ErrStreamTicketInvalid,
	ErrStreamCancelled,
	ErrLeaseInvalid,
	ErrLeaseReplayed,
	ErrGrantInvalid,
	ErrStorageQuotaExceeded,
	ErrOperationBlocked,
	ErrOperationNotFound,
	ErrOperationNotCancelable,
	ErrNetworkTargetDenied,
	ErrNetworkRateLimited,
	ErrRuntimeUnavailable,
	ErrRuntimeVersionMismatch,
	ErrJSONLimitExceeded,
	ErrCapabilityError,
	ErrContractMismatch,
	ErrStateVersionMismatch,
	ErrCSRFRequired,
	ErrRetainedDataCleanupFailed,
	ErrRetainedDataBindFailed,
}

var bridgeErrorCodes = append(platformErrorCodes, []ErrorCode{
	ErrConfirmationRejected,
	ErrBridgeTimeout,
	ErrBridgeDisposed,
	ErrBridgeHandshakeFailed,
	ErrBridgeHandshakeRequired,
}...)

var typeScriptClientErrorCodes = append(bridgeErrorCodes, []ErrorCode{
	ErrPlatformRequestFailed,
	ErrStreamFailed,
}...)

func PlatformErrorCodes() []ErrorCode {
	return cloneErrorCodes(platformErrorCodes)
}

func BridgeErrorCodes() []ErrorCode {
	return cloneErrorCodes(bridgeErrorCodes)
}

func TypeScriptClientErrorCodes() []ErrorCode {
	return cloneErrorCodes(typeScriptClientErrorCodes)
}

func cloneErrorCodes(codes []ErrorCode) []ErrorCode {
	out := make([]ErrorCode, len(codes))
	copy(out, codes)
	return out
}
