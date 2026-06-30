use std::io::{self, BufRead, Write};

fn main() {
    if let Err(err) = run() {
        eprintln!("redevplugin-runtime startup error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| format!("read hello frame: {err}"))?;
    let (request_id, runtime_generation_id) =
        redevplugin_ipc::validate_hello_frame(&line).map_err(|err| err.to_string())?;
    let ack = redevplugin_ipc::hello_ack_frame(
        &request_id,
        &runtime_generation_id,
        env!("CARGO_PKG_VERSION"),
        redevplugin_ipc::WASM_ABI_VERSION,
    );
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(ack.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write hello ack: {err}"))?;

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("read ipc frame: {err}"))?;
        if read == 0 {
            break;
        }
        let (frame_type, request_id, frame_generation_id) =
            redevplugin_ipc::parse_frame_identity(&line).map_err(|err| err.to_string())?;
        if frame_generation_id != runtime_generation_id {
            return Err("runtime_generation_id mismatch".to_string());
        }
        let response = match frame_type.as_str() {
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER => handle_worker_invocation(
                &mut reader,
                &mut stdout,
                &request_id,
                &runtime_generation_id,
                &line,
            )?,
            redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH => redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
                &request_id,
                &runtime_generation_id,
                true,
                None,
                None,
                None,
            ),
            _ => redevplugin_ipc::response_frame(
                "diagnostic",
                &request_id,
                &runtime_generation_id,
                false,
                None,
                Some("UNSUPPORTED_FRAME"),
                Some("runtime frame type is not supported"),
            ),
        };
        stdout
            .write_all(response.as_bytes())
            .and_then(|_| stdout.write_all(b"\n"))
            .and_then(|_| stdout.flush())
            .map_err(|err| format!("write ipc response: {err}"))?;
    }
    Ok(())
}

fn handle_worker_invocation<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> Result<String, String> {
    let identity = match redevplugin_ipc::parse_worker_invocation_identity(line) {
        Ok(identity) => identity,
        Err(err) => {
            return Ok(redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID),
                Some(err),
            ));
        }
    };
    let artifact_request_id = format!("{request_id}:artifact");
    let open_handle =
        redevplugin_ipc::open_handle_frame(&artifact_request_id, runtime_generation_id, &identity);
    stdout
        .write_all(open_handle.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write open_handle request: {err}"))?;

    let mut artifact_response = String::new();
    reader
        .read_line(&mut artifact_response)
        .map_err(|err| format!("read open_handle response: {err}"))?;
    if artifact_response.is_empty() {
        return Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED),
            Some("runtime artifact handle response is empty"),
        ));
    }
    if let Err(err) = redevplugin_ipc::validate_open_handle_response(
        &artifact_response,
        &artifact_request_id,
        runtime_generation_id,
        &identity,
    ) {
        return Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED),
            Some(err.as_str()),
        ));
    }

    let message = redevplugin_ipc::worker_invocation_not_implemented_message(&identity);
    Ok(redevplugin_ipc::response_frame(
        redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
        request_id,
        runtime_generation_id,
        false,
        None,
        Some(redevplugin_ipc::ERR_WASM_NOT_IMPLEMENTED),
        Some(message.as_str()),
    ))
}
