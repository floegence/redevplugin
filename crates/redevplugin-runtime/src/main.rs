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
    let content_base64 = match redevplugin_ipc::open_handle_content_base64(
        &artifact_response,
        &artifact_request_id,
        runtime_generation_id,
        &identity,
    ) {
        Ok(content_base64) => content_base64,
        Err(err) => {
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
    };
    let wasm_bytes = match decode_base64(&content_base64) {
        Ok(wasm_bytes) => wasm_bytes,
        Err(err) => {
            return Ok(redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WASM_WORKER_INVALID),
                Some(err.as_str()),
            ));
        }
    };
    let execution = match execute_worker_module(&wasm_bytes, &identity.export) {
        Ok(execution) => execution,
        Err(err) => {
            return Ok(redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WASM_WORKER_INVALID),
                Some(err.as_str()),
            ));
        }
    };
    let storage_file_result = if execution.storage_file_write_demo_requested {
        match perform_storage_file_write_demo(
            reader,
            stdout,
            request_id,
            runtime_generation_id,
            line,
        ) {
            Ok(result) => Some(result),
            Err(err) => {
                return Ok(redevplugin_ipc::response_frame(
                    redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                    request_id,
                    runtime_generation_id,
                    false,
                    None,
                    Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                    Some(err.as_str()),
                ));
            }
        }
    } else {
        None
    };
    let network_execute_result = if execution.network_http_request_demo_requested {
        match perform_network_http_request_demo(
            reader,
            stdout,
            request_id,
            runtime_generation_id,
            line,
        ) {
            Ok(result) => Some(result),
            Err(err) => {
                return Ok(redevplugin_ipc::response_frame(
                    redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                    request_id,
                    runtime_generation_id,
                    false,
                    None,
                    Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                    Some(err.as_str()),
                ));
            }
        }
    } else {
        None
    };
    let result = redevplugin_ipc::worker_success_result_json(
        &identity,
        execution.validated.byte_len,
        storage_file_result.as_deref(),
        network_execute_result.as_deref(),
    );
    Ok(redevplugin_ipc::response_frame(
        redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
        request_id,
        runtime_generation_id,
        true,
        Some(result.as_str()),
        None,
        None,
    ))
}

#[derive(Debug)]
struct WorkerExecution {
    validated: redevplugin_wasm_abi::ValidatedWorkerModule,
    storage_file_write_demo_requested: bool,
    network_http_request_demo_requested: bool,
}

#[derive(Default)]
struct WorkerHostState {
    storage_file_write_demo_requested: bool,
    network_http_request_demo_requested: bool,
}

fn execute_worker_module(wasm_bytes: &[u8], export_name: &str) -> Result<WorkerExecution, String> {
    let validated = redevplugin_wasm_abi::validate_worker_module(wasm_bytes, export_name)?;
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, wasm_bytes)
        .map_err(|err| format!("compile wasm worker module: {err}"))?;
    let mut linker = <wasmi::Linker<WorkerHostState>>::new(&engine);
    linker
        .func_wrap(
            "redeven.storage",
            "files_write_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().storage_file_write_demo_requested = true;
            },
        )
        .map_err(|err| format!("define storage hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redeven.network",
            "http_request_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().network_http_request_demo_requested = true;
            },
        )
        .map_err(|err| format!("define network hostcall import: {err}"))?;
    let mut store = wasmi::Store::new(&engine, WorkerHostState::default());
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|err| format!("instantiate wasm worker module: {err}"))?;
    let invoke = instance
        .get_typed_func::<(), ()>(&store, export_name)
        .map_err(|err| format!("resolve wasm worker export {export_name:?}: {err}"))?;
    invoke
        .call(&mut store, ())
        .map_err(|err| format!("execute wasm worker export {export_name:?}: {err}"))?;
    let storage_file_write_demo_requested = store.data().storage_file_write_demo_requested;
    let network_http_request_demo_requested = store.data().network_http_request_demo_requested;
    Ok(WorkerExecution {
        validated,
        storage_file_write_demo_requested,
        network_http_request_demo_requested,
    })
}

fn perform_storage_file_write_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
) -> Result<String, String> {
    let req = storage_file_write_demo_request(invocation_frame, runtime_generation_id)?;
    let storage_request_id = format!("{request_id}:storage_file");
    let frame =
        redevplugin_ipc::storage_file_frame(&storage_request_id, runtime_generation_id, &req);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write storage_file request: {err}"))?;
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("read storage_file response: {err}"))?;
    if response.is_empty() {
        return Err("storage_file response is empty".to_string());
    }
    redevplugin_ipc::validate_storage_file_response(
        &response,
        &storage_request_id,
        runtime_generation_id,
    )?;
    redevplugin_ipc::storage_file_payload_json(&response)
}

fn storage_file_write_demo_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
) -> Result<redevplugin_ipc::StorageFileRequest, String> {
    let handle_grant_token = required_json_string(invocation_frame, "storage_handle_grant_token")?;
    let store_id = required_json_string(invocation_frame, "storage_store_id")?;
    let path = required_json_string(invocation_frame, "storage_path")?;
    let data_base64 = required_json_string(invocation_frame, "storage_data_base64")?;
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::StorageFileRequest {
        handle_grant_token,
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.files".to_string(),
        policy_revision,
        management_revision,
        revoke_epoch,
        operation: "write".to_string(),
        store_id,
        path,
        data_base64,
        max_bytes: 0,
        max_entries: 0,
        recursive: false,
    })
}

fn perform_network_http_request_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
) -> Result<String, String> {
    let req = network_http_request_demo(invocation_frame, runtime_generation_id)?;
    let network_request_id = format!("{request_id}:network_execute");
    let frame =
        redevplugin_ipc::network_execute_frame(&network_request_id, runtime_generation_id, &req);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write network_execute request: {err}"))?;
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("read network_execute response: {err}"))?;
    if response.is_empty() {
        return Err("network_execute response is empty".to_string());
    }
    redevplugin_ipc::validate_network_execute_response(
        &response,
        &network_request_id,
        runtime_generation_id,
        "api",
        "http",
    )?;
    redevplugin_ipc::network_execute_payload_json(&response)
}

fn network_http_request_demo(
    invocation_frame: &str,
    runtime_generation_id: &str,
) -> Result<redevplugin_ipc::NetworkExecuteRequest, String> {
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    let body_base64 = redevplugin_ipc::extract_json_string(invocation_frame, "network_body_base64")
        .unwrap_or_default();
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        policy_revision,
        management_revision,
        revoke_epoch,
        connector_id: "api".to_string(),
        transport: "http".to_string(),
        destination: "https://api.example.com".to_string(),
        ttl_ms: 30_000,
        operation: "http".to_string(),
        method: "POST".to_string(),
        path: "/v1/worker".to_string(),
        headers_json: r#"{"Content-Type":["text/plain"]}"#.to_string(),
        message_type: String::new(),
        body_base64,
        payload_base64: String::new(),
        max_request_bytes: 1024,
        max_response_bytes: 4096,
        timeout_ms: 1000,
    })
}

fn required_json_string(input: &str, key: &str) -> Result<String, String> {
    let value =
        redevplugin_ipc::extract_json_string(input, key).ok_or_else(|| format!("missing {key}"))?;
    if value.trim().is_empty() {
        return Err(format!("empty {key}"));
    }
    Ok(value)
}

fn required_json_number(input: &str, key: &str) -> Result<u64, String> {
    redevplugin_ipc::extract_json_number_u64(input, key).ok_or_else(|| format!("missing {key}"))
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    let mut padding_started = false;
    for ch in input.bytes() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch == b'=' {
            padding_started = true;
            continue;
        }
        if padding_started {
            return Err("base64 content has data after padding".to_string());
        }
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("base64 content contains an invalid character".to_string()),
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err("base64 content has non-zero trailing bits".to_string());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_base64() {
        assert_eq!(decode_base64("aGVsbG8=").expect("base64"), b"hello");
        assert_eq!(decode_base64("AAECAw==").expect("base64"), &[0, 1, 2, 3]);
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_base64("abc$").expect_err("invalid base64");
        assert!(err.contains("invalid character"));
    }

    #[test]
    fn executes_minimal_wasm_worker_export() {
        let module = minimal_worker_wasm("redeven_worker_invoke");
        let execution = execute_worker_module(&module, "redeven_worker_invoke")
            .expect("minimal worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(!execution.network_http_request_demo_requested);
    }

    #[test]
    fn executes_storage_hostcall_wasm_worker_export() {
        let module = storage_hostcall_worker_wasm("redeven_worker_invoke");
        let execution = execute_worker_module(&module, "redeven_worker_invoke")
            .expect("storage hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(execution.storage_file_write_demo_requested);
        assert!(!execution.network_http_request_demo_requested);
    }

    #[test]
    fn executes_network_hostcall_wasm_worker_export() {
        let module = imported_hostcall_worker_wasm(
            "redeven.network",
            "http_request_demo",
            "redeven_worker_invoke",
        );
        let execution = execute_worker_module(&module, "redeven_worker_invoke")
            .expect("network hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(execution.network_http_request_demo_requested);
    }

    #[test]
    fn rejects_wasm_worker_with_missing_export() {
        let module = minimal_worker_wasm("other_export");
        let err = execute_worker_module(&module, "redeven_worker_invoke")
            .expect_err("missing worker export");
        assert!(err.contains("required function export"));
    }

    fn minimal_worker_wasm(export_name: &str) -> Vec<u8> {
        let export_name_bytes = export_name.as_bytes();
        let mut module = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x07,
        ];
        let mut export_payload = vec![0x01, export_name_bytes.len() as u8];
        export_payload.extend_from_slice(export_name_bytes);
        export_payload.extend_from_slice(&[0x00, 0x00]);
        module.push(export_payload.len() as u8);
        module.extend_from_slice(&export_payload);
        module.extend_from_slice(&[0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b]);
        module
    }

    fn storage_hostcall_worker_wasm(export_name: &str) -> Vec<u8> {
        imported_hostcall_worker_wasm("redeven.storage", "files_write_demo", export_name)
    }

    fn imported_hostcall_worker_wasm(
        import_module: &str,
        import_name: &str,
        export_name: &str,
    ) -> Vec<u8> {
        let export_name_bytes = export_name.as_bytes();
        let import_module = import_module.as_bytes();
        let import_name = import_name.as_bytes();
        let mut module = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x02, 0x60, 0x00, 0x00,
            0x60, 0x00, 0x00, 0x02,
        ];
        let mut import_payload = vec![0x01, import_module.len() as u8];
        import_payload.extend_from_slice(import_module);
        import_payload.push(import_name.len() as u8);
        import_payload.extend_from_slice(import_name);
        import_payload.extend_from_slice(&[0x00, 0x00]);
        module.push(import_payload.len() as u8);
        module.extend_from_slice(&import_payload);
        module.extend_from_slice(&[0x03, 0x02, 0x01, 0x01, 0x07]);
        let mut export_payload = vec![0x01, export_name_bytes.len() as u8];
        export_payload.extend_from_slice(export_name_bytes);
        export_payload.extend_from_slice(&[0x00, 0x01]);
        module.push(export_payload.len() as u8);
        module.extend_from_slice(&export_payload);
        module.extend_from_slice(&[0x0a, 0x06, 0x01, 0x04, 0x00, 0x10, 0x00, 0x0b]);
        module
    }
}
