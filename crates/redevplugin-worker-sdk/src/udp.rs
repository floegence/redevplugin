use crate::api;
use crate::error::{Error, Result};
use crate::resource::{Handle, IO_FLAG_DATAGRAM_END, MAX_IO_CHUNK_BYTES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct UdpConnect {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
}

pub type ConnectOptions = UdpConnect;

#[derive(Deserialize)]
struct HandleResult {
    handle: u64,
}

pub struct UdpSocket {
    handle: Handle,
}

impl UdpSocket {
    pub fn connect(options: UdpConnect) -> Result<Self> {
        let opened: HandleResult = api::call("net.udp.connect", &options)?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn send(&mut self, datagram: &[u8]) -> Result<()> {
        if datagram.len() > MAX_IO_CHUNK_BYTES {
            return Err(Error::from_abi_status(-11));
        }
        self.handle.write(datagram, IO_FLAG_DATAGRAM_END)
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        let (body, flags) = self.handle.read(MAX_IO_CHUNK_BYTES)?;
        if flags & IO_FLAG_DATAGRAM_END == 0 {
            return Err(Error::internal("UDP datagram boundary is missing"));
        }
        Ok(body)
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}
