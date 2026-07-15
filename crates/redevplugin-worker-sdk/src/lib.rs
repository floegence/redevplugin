use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ptr;

mod hostcalls;

pub use hostcalls::{network, storage};

pub const WORKER_ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
pub const WORKER_REQUEST_SCHEMA_VERSION: &str = "redevplugin.worker_request.v2";
const MAX_HOSTCALL_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub schema_version: String,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerError {
    pub code: String,
    pub message: String,
}

impl WorkerError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("INVALID_REQUEST", message)
    }

    pub fn hostcall(message: impl Into<String>) -> Self {
        Self::new("HOSTCALL_FAILED", message)
    }
}

pub type WorkerResult = Result<Value, WorkerError>;

#[derive(Serialize)]
#[serde(untagged)]
enum WorkerResponse<'a> {
    Success {
        ok: bool,
        data: &'a Value,
    },
    Failure {
        ok: bool,
        error_code: &'a str,
        message: &'a str,
    },
}

pub fn decode_base64(value: &str) -> Result<Vec<u8>, WorkerError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| WorkerError::hostcall(format!("decode base64 response: {err}")))
}

pub fn decode_base64_text(value: &str) -> Result<String, WorkerError> {
    String::from_utf8(decode_base64(value)?)
        .map_err(|_| WorkerError::hostcall("decoded response is not UTF-8"))
}

#[doc(hidden)]
pub fn allocate(length: u32) -> u32 {
    if length == 0 {
        return 0;
    }
    let (pointer, _) = leak_buffer(vec![0_u8; length as usize].into_boxed_slice());
    pointer as u32
}

#[doc(hidden)]
pub unsafe fn deallocate(pointer: u32, length: u32) {
    if pointer == 0 || length == 0 {
        return;
    }
    unsafe { drop_buffer(pointer as *mut u8, length as usize) }
}

#[doc(hidden)]
pub unsafe fn invoke(pointer: u32, length: u32, handler: fn(WorkerRequest) -> WorkerResult) -> u64 {
    let request_bytes = if pointer == 0 || length == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pointer as *const u8, length as usize) }
    };
    let result = serde_json::from_slice::<WorkerRequest>(request_bytes)
        .map_err(|err| WorkerError::invalid_request(format!("decode worker request: {err}")))
        .and_then(|request| {
            if request.schema_version != WORKER_REQUEST_SCHEMA_VERSION {
                return Err(WorkerError::invalid_request(
                    "worker request schema version is unsupported",
                ));
            }
            if request.method.trim().is_empty() || !request.params.is_object() {
                return Err(WorkerError::invalid_request(
                    "worker method and object params are required",
                ));
            }
            handler(request)
        });
    let response = match &result {
        Ok(data) => WorkerResponse::Success { ok: true, data },
        Err(error) => WorkerResponse::Failure {
            ok: false,
            error_code: &error.code,
            message: &error.message,
        },
    };
    let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| {
        br#"{"ok":false,"error_code":"WORKER_SERIALIZATION_FAILED","message":"worker response serialization failed"}"#.to_vec()
    });
    let (pointer, length) = leak_buffer(bytes.into_boxed_slice());
    let pointer = pointer as u32;
    let length = length as u32;
    ((pointer as u64) << 32) | length as u64
}

fn leak_buffer(buffer: Box<[u8]>) -> (*mut u8, usize) {
    let length = buffer.len();
    let pointer = Box::into_raw(buffer) as *mut u8;
    (pointer, length)
}

unsafe fn drop_buffer(pointer: *mut u8, length: usize) {
    let slice = ptr::slice_from_raw_parts_mut(pointer, length);
    unsafe { drop(Box::from_raw(slice)) }
}

#[macro_export]
macro_rules! export_worker {
    ($handler:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn redevplugin_worker_alloc(length: u32) -> u32 {
            $crate::allocate(length)
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn redevplugin_worker_dealloc(pointer: u32, length: u32) {
            unsafe { $crate::deallocate(pointer, length) }
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn redevplugin_worker_invoke(pointer: u32, length: u32) -> u64 {
            unsafe { $crate::invoke(pointer, length, $handler) }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn worker_error_helpers_are_stable() {
        assert_eq!(
            WorkerError::invalid_request("missing title"),
            WorkerError::new("INVALID_REQUEST", "missing title")
        );
    }

    #[test]
    fn base64_helpers_decode_network_payloads() {
        assert_eq!(decode_base64_text("SGVsbG8=").unwrap(), "Hello");
        assert!(decode_base64_text("not-base64").is_err());
    }

    #[test]
    fn request_shape_is_closed() {
        let valid: WorkerRequest = serde_json::from_value(json!({
            "schema_version": WORKER_REQUEST_SCHEMA_VERSION,
            "method": "notes.list",
            "params": {}
        }))
        .unwrap();
        assert_eq!(valid.method, "notes.list");
        assert!(
            serde_json::from_value::<WorkerRequest>(json!({
                "schema_version": WORKER_REQUEST_SCHEMA_VERSION,
                "method": "notes.list",
                "params": {},
                "gateway_token": "secret"
            }))
            .is_err()
        );
    }

    #[test]
    fn exact_layout_buffers_round_trip_across_response_sizes() {
        for length in [1_usize, 7, 255, 4096, 65_537] {
            let expected = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let (pointer, actual_length) = leak_buffer(expected.clone().into_boxed_slice());
            assert_eq!(actual_length, length);
            let actual = unsafe { std::slice::from_raw_parts(pointer, actual_length) };
            assert_eq!(actual, expected);
            unsafe { drop_buffer(pointer, actual_length) };
        }
    }
}
