use crate::api;
use crate::error::{Error, Result};
use crate::http::Header;
use crate::resource::{
    Handle, IO_FLAG_BINARY, IO_FLAG_EOF, IO_FLAG_MESSAGE_END, IO_FLAG_TEXT, MAX_IO_CHUNK_BYTES,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketOpen {
    pub url: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub subprotocols: Vec<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
}

pub type OpenOptions = WebSocketOpen;

#[derive(Deserialize)]
struct OpenResult {
    handle: u64,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    response_headers: Vec<Header>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}

pub struct WebSocket {
    handle: Handle,
    pub protocol: String,
    pub response_headers: Vec<Header>,
}

impl WebSocket {
    pub fn open(options: WebSocketOpen) -> Result<Self> {
        let opened: OpenResult = api::call("net.websocket.open", &options)?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
            protocol: opened.protocol,
            response_headers: opened.response_headers,
        })
    }

    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_message(text.as_bytes(), IO_FLAG_TEXT)
    }

    pub fn send_binary(&mut self, bytes: &[u8]) -> Result<()> {
        self.send_message(bytes, IO_FLAG_BINARY)
    }

    fn send_message(&mut self, bytes: &[u8], kind: u32) -> Result<()> {
        if bytes.is_empty() {
            return self.handle.write(bytes, kind | IO_FLAG_MESSAGE_END);
        }
        let chunk_count = bytes.len().div_ceil(MAX_IO_CHUNK_BYTES);
        for (index, chunk) in bytes.chunks(MAX_IO_CHUNK_BYTES).enumerate() {
            let mut flags = if index == 0 { kind } else { 0 };
            if index + 1 == chunk_count {
                flags |= IO_FLAG_MESSAGE_END;
            }
            self.handle.write(chunk, flags)?;
        }
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Message> {
        let mut body = Vec::new();
        let mut kind = 0;
        loop {
            let (chunk, flags) = self.handle.read(MAX_IO_CHUNK_BYTES)?;
            let message_kind = flags & (IO_FLAG_TEXT | IO_FLAG_BINARY);
            if flags & IO_FLAG_EOF != 0 {
                return Err(Error::from_abi_status(-5));
            }
            if message_kind == IO_FLAG_TEXT | IO_FLAG_BINARY {
                return Err(Error::internal("WebSocket message type is invalid"));
            }
            if message_kind != 0 {
                if kind != 0 {
                    return Err(Error::internal(
                        "WebSocket message type changed mid-message",
                    ));
                }
                kind = message_kind;
            }
            body.extend_from_slice(&chunk);
            if flags & IO_FLAG_MESSAGE_END != 0 {
                return match kind {
                    IO_FLAG_TEXT => String::from_utf8(body)
                        .map(Message::Text)
                        .map_err(|_| Error::internal("WebSocket text message is not UTF-8")),
                    IO_FLAG_BINARY => Ok(Message::Binary(body)),
                    _ => Err(Error::internal("WebSocket message type is missing")),
                };
            }
            if chunk.is_empty() {
                return Err(Error::internal("WebSocket receive made no progress"));
            }
        }
    }

    pub fn ping(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
        }
        let _: serde_json::Value = api::call(
            "net.websocket.ping",
            &Arguments {
                handle: self.handle.id(),
            },
        )?;
        Ok(())
    }

    pub fn close(mut self, code: u16, reason: &str) -> Result<()> {
        #[derive(Serialize)]
        struct Arguments<'a> {
            handle: u64,
            code: u16,
            reason: &'a str,
        }
        let _: serde_json::Value = api::call(
            "net.websocket.close",
            &Arguments {
                handle: self.handle.id(),
                code,
                reason,
            },
        )?;
        self.handle.disarm();
        Ok(())
    }
}
