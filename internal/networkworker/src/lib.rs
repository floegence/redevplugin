use redevplugin_worker_sdk::{
    WorkerError, WorkerRequest, WorkerResult, export_worker, http, tcp, udp, websocket,
};
use serde_json::json;

fn run(request: WorkerRequest) -> WorkerResult {
    let connector = request.params["connector"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let url = request.params["url"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let host = request.params["host"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let port = request.params["port"].as_u64().unwrap_or_default() as u16;
    let bytes = match request.params["transport"].as_str().unwrap_or_default() {
        "http" => {
            let upload = http::RequestBody::begin(http::HttpRequest {
                connector_id: connector,
                method: request.params["method"]
                    .as_str()
                    .unwrap_or("GET")
                    .to_owned(),
                url,
                headers: vec![],
                redirect: http::RedirectMode::Error,
                timeout_ms: Some(3000),
            })?;
            upload.finish()?.body.read_all()?
        }
        "tcp" => {
            let mut stream = tcp::TcpStream::connect(tcp::TcpConnect {
                connector_id: connector,
                host,
                port,
                timeout_ms: Some(3000),
                no_delay: true,
                keep_alive_ms: None,
            })?;
            stream.write_all(b"hello")?;
            stream.shutdown(tcp::Shutdown::Write)?;
            let (bytes, _) = stream.read(64)?;
            stream.close()?;
            bytes
        }
        "udp" => {
            let mut socket = udp::UdpSocket::connect(udp::UdpConnect {
                connector_id: connector,
                host,
                port,
                timeout_ms: Some(3000),
            })?;
            socket.send(b"hello")?;
            let bytes = socket.receive()?;
            socket.close()?;
            bytes
        }
        "websocket" => {
            let mut socket = websocket::WebSocket::open(websocket::WebSocketOpen {
                connector_id: connector,
                url,
                headers: vec![],
                subprotocols: vec![],
                timeout_ms: Some(3000),
            })?;
            socket.send_text("hello")?;
            let bytes = match socket.receive()? {
                websocket::Message::Text(text) => text.into_bytes(),
                websocket::Message::Binary(bytes) => bytes,
            };
            socket.close(1000, "done")?;
            bytes
        }
        _ => return Err(WorkerError::invalid_request("transport required")),
    };
    Ok(json!({"body":String::from_utf8_lossy(&bytes)}))
}
fn handle(request: WorkerRequest) -> WorkerResult {
    match run(request) {
        Ok(value) => Ok(value),
        Err(error) => Ok(json!({"code":error.code,"message":error.message})),
    }
}
export_worker!(handle);
