use crate::api;
use crate::error::{Error, Result};
use crate::resource::{Handle, IO_FLAG_EOF, MAX_IO_CHUNK_BYTES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectMode {
    #[default]
    Follow,
    Manual,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub redirect: RedirectMode,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
}

pub type RequestOptions = HttpRequest;

#[derive(Deserialize)]
struct BeginResult {
    upload_handle: u64,
}

#[derive(Deserialize)]
struct FinishResult {
    status: u16,
    #[serde(default)]
    headers: Vec<Header>,
    final_url: String,
    body_handle: u64,
}

pub struct RequestBody {
    handle: Handle,
}

impl RequestBody {
    pub fn begin(options: HttpRequest) -> Result<Self> {
        let opened: BeginResult = api::call("net.http.begin", &options)?;
        Ok(Self {
            handle: Handle::new(opened.upload_handle)?,
        })
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(MAX_IO_CHUNK_BYTES) {
            self.handle.write(chunk, 0)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Response> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
        }
        let finished: FinishResult = api::call(
            "net.http.finish",
            &Arguments {
                handle: self.handle.id(),
            },
        )?;
        self.handle.disarm();
        Ok(Response {
            status: finished.status,
            headers: finished.headers,
            final_url: finished.final_url,
            body: ResponseBody {
                handle: Handle::new(finished.body_handle)?,
            },
        })
    }

    pub fn abort(mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
        }
        let _: serde_json::Value = api::call(
            "net.http.abort",
            &Arguments {
                handle: self.handle.id(),
            },
        )?;
        self.handle.disarm();
        Ok(())
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub final_url: String,
    pub body: ResponseBody,
}

pub type Response = HttpResponse;

pub struct ResponseBody {
    handle: Handle,
}

impl ResponseBody {
    pub fn read(&mut self, capacity: usize) -> Result<(Vec<u8>, u32)> {
        self.handle.read(capacity)
    }

    pub fn read_all(mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            let (chunk, flags) = self.handle.read(MAX_IO_CHUNK_BYTES)?;
            if chunk.is_empty() && flags & IO_FLAG_EOF == 0 {
                return Err(Error::internal("HTTP response body made no progress"));
            }
            result.extend_from_slice(&chunk);
            if flags & IO_FLAG_EOF != 0 {
                self.handle.close()?;
                return Ok(result);
            }
        }
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}
