use crate::api;
use crate::error::Result;
use crate::resource::{Handle, MAX_IO_CHUNK_BYTES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TcpConnect {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    #[serde(default)]
    pub no_delay: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_ms: Option<u32>,
}

pub type ConnectOptions = TcpConnect;

#[derive(Deserialize)]
struct HandleResult {
    handle: u64,
}

pub struct TcpStream {
    handle: Handle,
}

impl TcpStream {
    pub fn connect(options: TcpConnect) -> Result<Self> {
        let opened: HandleResult = api::call("net.tcp.connect", &options)?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn read(&mut self, capacity: usize) -> Result<(Vec<u8>, u32)> {
        self.handle.read(capacity)
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(MAX_IO_CHUNK_BYTES) {
            self.handle.write(chunk, 0)?;
        }
        Ok(())
    }

    pub fn shutdown(&mut self, direction: Shutdown) -> Result<()> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
            direction: Shutdown,
        }
        let _: serde_json::Value = api::call(
            "net.tcp.shutdown",
            &Arguments {
                handle: self.handle.id(),
                direction,
            },
        )?;
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Shutdown {
    Read,
    Write,
    Both,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpListen {
    pub host: String,
    pub port: u16,
}

pub type ListenOptions = TcpListen;

#[derive(Deserialize)]
struct ListenResult {
    handle: u64,
    address: String,
}

pub struct TcpListener {
    handle: Handle,
    pub address: String,
}

impl TcpListener {
    pub fn listen(options: TcpListen) -> Result<Self> {
        let opened: ListenResult = api::call("net.tcp.listen", &options)?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
            address: opened.address,
        })
    }

    pub fn accept(&mut self, no_delay: bool, keep_alive_ms: Option<u32>) -> Result<TcpStream> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
            no_delay: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            keep_alive_ms: Option<u32>,
        }
        let opened: HandleResult = api::call(
            "net.tcp.accept",
            &Arguments {
                handle: self.handle.id(),
                no_delay,
                keep_alive_ms,
            },
        )?;
        Ok(TcpStream {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}
