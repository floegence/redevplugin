use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    ResourceClosed,
    Canceled,
    Timeout,
    WouldBlock,
    IoError,
    MountUnavailable,
    NetworkError,
    ResourceLimit,
    Internal,
    RuntimeUnavailable,
    RedirectRequiresReplay,
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::ResourceClosed => "RESOURCE_CLOSED",
            Self::Canceled => "CANCELED",
            Self::Timeout => "TIMEOUT",
            Self::WouldBlock => "WOULD_BLOCK",
            Self::IoError => "IO_ERROR",
            Self::MountUnavailable => "MOUNT_UNAVAILABLE",
            Self::NetworkError => "NETWORK_ERROR",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::Internal => "INTERNAL",
            Self::RuntimeUnavailable => "RUNTIME_UNAVAILABLE",
            Self::RedirectRequiresReplay => "REDIRECT_REQUIRES_REPLAY",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default)]
    pub details: Value,
}

impl Error {
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Internal,
            message: message.into(),
            retryable: false,
            details: Value::Null,
        }
    }

    pub(crate) fn from_abi_status(status: i32) -> Self {
        let code = match status {
            -1 => ErrorCode::InvalidArgument,
            -2 => ErrorCode::PermissionDenied,
            -3 => ErrorCode::NotFound,
            -4 => ErrorCode::AlreadyExists,
            -5 => ErrorCode::ResourceClosed,
            -6 => ErrorCode::Canceled,
            -7 => ErrorCode::Timeout,
            -8 => ErrorCode::WouldBlock,
            -9 => ErrorCode::IoError,
            -10 => ErrorCode::NetworkError,
            -11 => ErrorCode::ResourceLimit,
            -12 => ErrorCode::Internal,
            -13 => ErrorCode::RuntimeUnavailable,
            -14 => ErrorCode::RedirectRequiresReplay,
            -15 => ErrorCode::MountUnavailable,
            _ => ErrorCode::Unknown,
        };
        Self {
            code,
            message: format!("Worker API hostcall failed with ABI status {status}"),
            retryable: false,
            details: Value::Null,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::{Error, ErrorCode};

    #[test]
    fn preserves_mount_unavailable_abi_status() {
        assert_eq!(
            Error::from_abi_status(-15).code,
            ErrorCode::MountUnavailable
        );
    }
}
