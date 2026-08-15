use crate::error::{Error, Result};
use serde::Deserialize;

pub const IO_FLAG_EOF: u32 = 1 << 0;
pub const IO_FLAG_TEXT: u32 = 1 << 1;
pub const IO_FLAG_BINARY: u32 = 1 << 2;
pub const IO_FLAG_MESSAGE_END: u32 = 1 << 3;
pub const IO_FLAG_DATAGRAM_END: u32 = 1 << 4;
pub const MAX_IO_CHUNK_BYTES: usize = 64 * 1024;

#[link(wasm_import_module = "redevplugin.io")]
unsafe extern "C" {
    #[link_name = "rdp_call_v1"]
    fn rdp_call_v1(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_capacity: i32,
    ) -> i32;
    #[link_name = "rdp_read_v1"]
    fn rdp_read_v1(
        handle: i64,
        destination_ptr: i32,
        destination_capacity: i32,
        flags_ptr: i32,
    ) -> i32;
    #[link_name = "rdp_write_v1"]
    fn rdp_write_v1(handle: i64, source_ptr: i32, source_len: i32, flags: i32) -> i32;
    #[link_name = "rdp_seek_v1"]
    fn rdp_seek_v1(handle: i64, offset: i64, whence: i32) -> i64;
    #[link_name = "rdp_close_v1"]
    fn rdp_close_v1(handle: i64) -> i32;
    #[link_name = "rdp_last_error_v1"]
    fn rdp_last_error_v1(response_ptr: i32, response_capacity: i32) -> i32;
}

#[derive(Debug)]
pub(crate) struct Handle {
    value: Option<u64>,
}

impl Handle {
    pub(crate) fn new(value: u64) -> Result<Self> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(Error::internal("Host returned an invalid resource handle"));
        }
        Ok(Self { value: Some(value) })
    }

    pub fn id(&self) -> u64 {
        self.value.unwrap_or(0)
    }

    pub(crate) fn disarm(&mut self) {
        self.value = None;
    }

    pub(crate) fn read(&mut self, capacity: usize) -> Result<(Vec<u8>, u32)> {
        if capacity == 0 || capacity > MAX_IO_CHUNK_BYTES {
            return Err(Error::from_abi_status(-1));
        }
        let handle = self.require_open()?;
        let mut bytes = vec![0_u8; capacity];
        let mut flags = 0_u32;
        let status = unsafe {
            rdp_read_v1(
                handle as i64,
                bytes.as_mut_ptr() as i32,
                bytes.len() as i32,
                (&mut flags as *mut u32) as i32,
            )
        };
        let written = status_result(status)?;
        if written > bytes.len() {
            return Err(Error::internal("Host returned an oversized read result"));
        }
        bytes.truncate(written);
        Ok((bytes, flags))
    }

    pub(crate) fn write(&mut self, source: &[u8], flags: u32) -> Result<()> {
        if source.len() > MAX_IO_CHUNK_BYTES {
            return Err(Error::from_abi_status(-11));
        }
        let handle = self.require_open()?;
        let status = unsafe {
            rdp_write_v1(
                handle as i64,
                source.as_ptr() as i32,
                source.len() as i32,
                flags as i32,
            )
        };
        let written = status_result(status)?;
        if written != source.len() {
            return Err(Error::internal("Host returned a forbidden partial write"));
        }
        Ok(())
    }

    pub(crate) fn seek(&mut self, offset: i64, whence: u32) -> Result<u64> {
        let handle = self.require_open()?;
        let status = unsafe { rdp_seek_v1(handle as i64, offset, whence as i32) };
        if status < 0 {
            return Err(last_error(status as i32));
        }
        Ok(status as u64)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        let Some(handle) = self.value.take() else {
            return Ok(());
        };
        let status = unsafe { rdp_close_v1(handle as i64) };
        status_result(status).map(|_| ())
    }

    fn require_open(&self) -> Result<u64> {
        self.value.ok_or_else(|| Error::from_abi_status(-5))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) fn call_control_raw(request: &[u8]) -> Result<Vec<u8>> {
    if request.is_empty() || request.len() > MAX_IO_CHUNK_BYTES {
        return Err(Error::from_abi_status(-1));
    }
    let mut response = vec![0_u8; MAX_IO_CHUNK_BYTES];
    let status = unsafe {
        rdp_call_v1(
            request.as_ptr() as i32,
            request.len() as i32,
            response.as_mut_ptr() as i32,
            response.len() as i32,
        )
    };
    let written = status_result(status)?;
    if written > response.len() {
        return Err(Error::internal(
            "Host returned an oversized control response",
        ));
    }
    response.truncate(written);
    Ok(response)
}

fn status_result(status: i32) -> Result<usize> {
    if status < 0 {
        return Err(last_error(status));
    }
    usize::try_from(status).map_err(|_| Error::internal("ABI result does not fit usize"))
}

fn last_error(status: i32) -> Error {
    let mut response = vec![0_u8; MAX_IO_CHUNK_BYTES];
    let written = unsafe { rdp_last_error_v1(response.as_mut_ptr() as i32, response.len() as i32) };
    if written > 0 && (written as usize) <= response.len() {
        response.truncate(written as usize);
        #[derive(Deserialize)]
        struct LastError {
            code: crate::error::ErrorCode,
            message: String,
            #[serde(default)]
            retryable: bool,
            #[serde(default)]
            details: serde_json::Value,
        }
        if let Ok(error) = serde_json::from_slice::<LastError>(&response) {
            return Error {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
                details: error.details,
            };
        }
    }
    Error::from_abi_status(status)
}
