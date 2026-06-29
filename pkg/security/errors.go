package security

type ErrorCode string

const (
	ErrInvalidRequest              ErrorCode = "PLUGIN_INVALID_REQUEST"
	ErrPermissionDenied            ErrorCode = "PLUGIN_PERMISSION_DENIED"
	ErrConfirmationRequired        ErrorCode = "PLUGIN_CONFIRMATION_REQUIRED"
	ErrTokenExpired                ErrorCode = "PLUGIN_TOKEN_EXPIRED"
	ErrTokenReplay                 ErrorCode = "PLUGIN_TOKEN_REPLAY"
	ErrGatewayTokenChannelMismatch ErrorCode = "PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH"
	ErrStorageQuotaExceeded        ErrorCode = "PLUGIN_STORAGE_QUOTA_EXCEEDED"
	ErrNetworkTargetDenied         ErrorCode = "PLUGIN_NETWORK_TARGET_DENIED"
	ErrRuntimeUnavailable          ErrorCode = "PLUGIN_RUNTIME_UNAVAILABLE"
	ErrContractMismatch            ErrorCode = "PLUGIN_CONTRACT_MISMATCH"
)
