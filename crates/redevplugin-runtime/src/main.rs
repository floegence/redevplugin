use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use wasmi::{AsContext, AsContextMut, Config};

const DEFAULT_WASM_WORKER_FUEL: u64 = 5_000_000;

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
    let (request_id, runtime_generation_id, channel_nonce) =
        redevplugin_ipc::validate_hello_frame(&line).map_err(|err| err.to_string())?;
    let runtime_version =
        option_env!("REDEVPLUGIN_RUNTIME_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    let ack = redevplugin_ipc::hello_ack_frame(
        &request_id,
        &runtime_generation_id,
        &channel_nonce,
        runtime_version,
        redevplugin_ipc::WASM_ABI_VERSION,
    );
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(ack.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write hello ack: {err}"))?;

    let mut revocations = RuntimeRevocations::default();
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
                &revocations,
                &request_id,
                &runtime_generation_id,
                &line,
            )?,
            redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH => {
                handle_revoke_epoch(&mut revocations, &request_id, &runtime_generation_id, &line)
            }
            _ => redevplugin_ipc::response_frame(
                "diagnostic",
                &request_id,
                &runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_UNSUPPORTED_FRAME),
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
    revocations: &RuntimeRevocations,
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
    if let Err(err) = revocations.validate_invocation_frame(line) {
        let code = err.code();
        let message = err.to_string();
        return Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(code),
            Some(message.as_str()),
        ));
    }
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
    let execution =
        match execute_worker_module(&wasm_bytes, &identity.export, |request| match request {
            WorkerHostcallRequest::StorageFile(request_json) => perform_storage_file_request(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                &request_json,
            ),
            WorkerHostcallRequest::StorageKV(request_json) => perform_storage_kv_request(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                &request_json,
            ),
            WorkerHostcallRequest::StorageSQLite(request_json) => perform_storage_sqlite_request(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                &request_json,
            ),
            WorkerHostcallRequest::NetworkExecute(request_json) => perform_network_execute_request(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                &request_json,
            ),
        }) {
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
    let mut memory_network_results = Vec::new();
    if execution.network_execute_requested {
        for result in execution.network_execute_results {
            match result {
                Ok(result) => {
                    memory_network_results.push(result);
                }
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
        }
        if memory_network_results.is_empty() {
            return Ok(redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                Some("network hostcall did not produce a response"),
            ));
        }
    }
    let mut memory_storage_file_result = None;
    if execution.storage_file_requested {
        match execution.storage_file_result {
            Some(Ok(result)) => {
                memory_storage_file_result = Some(result);
            }
            Some(Err(err)) => {
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
            None => {
                return Ok(redevplugin_ipc::response_frame(
                    redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                    request_id,
                    runtime_generation_id,
                    false,
                    None,
                    Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                    Some("storage hostcall did not produce a response"),
                ));
            }
        }
    }
    let mut memory_storage_kv_result = None;
    if execution.storage_kv_requested {
        match execution.storage_kv_result {
            Some(Ok(result)) => {
                memory_storage_kv_result = Some(result);
            }
            Some(Err(err)) => {
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
            None => {
                return Ok(redevplugin_ipc::response_frame(
                    redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                    request_id,
                    runtime_generation_id,
                    false,
                    None,
                    Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                    Some("storage kv hostcall did not produce a response"),
                ));
            }
        }
    }
    let mut memory_storage_sqlite_result = None;
    if execution.storage_sqlite_requested {
        match execution.storage_sqlite_result {
            Some(Ok(result)) => {
                memory_storage_sqlite_result = Some(result);
            }
            Some(Err(err)) => {
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
            None => {
                return Ok(redevplugin_ipc::response_frame(
                    redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                    request_id,
                    runtime_generation_id,
                    false,
                    None,
                    Some(redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED),
                    Some("storage sqlite hostcall did not produce a response"),
                ));
            }
        }
    }
    let storage_file_result = match memory_storage_file_result {
        Some(result) => Some(result),
        None if execution.storage_file_write_demo_requested => {
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
        }
        None => None,
    };
    let storage_kv_result = match memory_storage_kv_result {
        Some(result) => Some(result),
        None if execution.storage_kv_put_demo_requested => {
            match perform_storage_kv_put_demo(
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
        }
        None => None,
    };
    let storage_sqlite_result = match memory_storage_sqlite_result {
        Some(result) => Some(result),
        None if execution.storage_sqlite_exec_demo_requested => {
            match perform_storage_sqlite_exec_demo(
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
        }
        None => None,
    };
    let network_execute_result =
        if memory_network_results.is_empty() && execution.network_http_request_demo_requested {
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
    if let Some(result) = network_execute_result {
        memory_network_results.push(result);
    }
    let network_result_refs: Vec<&str> = memory_network_results
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let result = redevplugin_ipc::worker_success_result_json_with_network_results(
        &identity,
        execution.validated.byte_len,
        storage_file_result.as_deref(),
        storage_kv_result.as_deref(),
        storage_sqlite_result.as_deref(),
        network_result_refs,
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

#[derive(Default)]
struct RuntimeRevocations {
    revoked_epoch_by_plugin: HashMap<String, u64>,
}

impl RuntimeRevocations {
    fn revoke_plugin(&mut self, plugin_instance_id: &str, revoke_epoch: u64) {
        self.revoked_epoch_by_plugin
            .entry(plugin_instance_id.to_string())
            .and_modify(|current| *current = (*current).max(revoke_epoch))
            .or_insert(revoke_epoch);
    }

    fn validate_invocation_frame(&self, frame: &str) -> Result<(), RuntimeRevocationError> {
        let plugin_instance_id = required_json_string(frame, "plugin_instance_id")
            .map_err(|_| RuntimeRevocationError::InvalidInvocation)?;
        let invocation_epoch = required_json_number(frame, "revoke_epoch")
            .map_err(|_| RuntimeRevocationError::InvalidInvocation)?;
        match self.revoked_epoch_by_plugin.get(&plugin_instance_id) {
            Some(revoked_epoch) if invocation_epoch < *revoked_epoch => {
                Err(RuntimeRevocationError::Revoked {
                    plugin_instance_id,
                    invocation_epoch,
                    revoked_epoch: *revoked_epoch,
                })
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeRevocationError {
    InvalidInvocation,
    Revoked {
        plugin_instance_id: String,
        invocation_epoch: u64,
        revoked_epoch: u64,
    },
}

impl RuntimeRevocationError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInvocation => redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
            Self::Revoked { .. } => redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED,
        }
    }
}

impl std::fmt::Display for RuntimeRevocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInvocation => write!(
                formatter,
                "worker invocation is missing a valid plugin_instance_id or revoke_epoch"
            ),
            Self::Revoked {
                plugin_instance_id,
                invocation_epoch,
                revoked_epoch,
            } => write!(
                formatter,
                "runtime capability for plugin {plugin_instance_id} was revoked at epoch {revoked_epoch}; invocation epoch {invocation_epoch} is stale"
            ),
        }
    }
}

fn handle_revoke_epoch(
    revocations: &mut RuntimeRevocations,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> String {
    let plugin_instance_id = match required_json_string(line, "plugin_instance_id") {
        Ok(value) => value,
        Err(err) => {
            return redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID),
                Some(err.as_str()),
            );
        }
    };
    let revoke_epoch = match required_last_json_number(line, "revoke_epoch") {
        Ok(value) => value,
        Err(err) => {
            return redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID),
                Some(err.as_str()),
            );
        }
    };
    revocations.revoke_plugin(&plugin_instance_id, revoke_epoch);
    redevplugin_ipc::response_frame(
        redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
        request_id,
        runtime_generation_id,
        true,
        None,
        None,
        None,
    )
}

#[derive(Debug)]
struct WorkerExecution {
    validated: redevplugin_wasm_abi::ValidatedWorkerModule,
    storage_file_write_demo_requested: bool,
    storage_file_requested: bool,
    storage_file_result: Option<Result<String, String>>,
    storage_kv_put_demo_requested: bool,
    storage_kv_requested: bool,
    storage_kv_result: Option<Result<String, String>>,
    storage_sqlite_exec_demo_requested: bool,
    storage_sqlite_requested: bool,
    storage_sqlite_result: Option<Result<String, String>>,
    network_http_request_demo_requested: bool,
    network_execute_requested: bool,
    network_execute_results: Vec<Result<String, String>>,
}

enum WorkerHostcallRequest {
    StorageFile(String),
    StorageKV(String),
    StorageSQLite(String),
    NetworkExecute(String),
}

type WorkerBrokerHostcall<'a> = dyn FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a;

struct WorkerHostState<'a> {
    storage_file_write_demo_requested: bool,
    storage_file_requested: bool,
    storage_file_result: Option<Result<String, String>>,
    storage_kv_put_demo_requested: bool,
    storage_kv_requested: bool,
    storage_kv_result: Option<Result<String, String>>,
    storage_sqlite_exec_demo_requested: bool,
    storage_sqlite_requested: bool,
    storage_sqlite_result: Option<Result<String, String>>,
    network_http_request_demo_requested: bool,
    network_execute_requested: bool,
    network_execute_results: Vec<Result<String, String>>,
    broker_hostcall: Box<WorkerBrokerHostcall<'a>>,
}

impl<'a> WorkerHostState<'a> {
    fn new(
        broker_hostcall: impl FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a,
    ) -> Self {
        Self {
            storage_file_write_demo_requested: false,
            storage_file_requested: false,
            storage_file_result: None,
            storage_kv_put_demo_requested: false,
            storage_kv_requested: false,
            storage_kv_result: None,
            storage_sqlite_exec_demo_requested: false,
            storage_sqlite_requested: false,
            storage_sqlite_result: None,
            network_http_request_demo_requested: false,
            network_execute_requested: false,
            network_execute_results: Vec::new(),
            broker_hostcall: Box::new(broker_hostcall),
        }
    }
}

fn execute_worker_module<'a>(
    wasm_bytes: &[u8],
    export_name: &str,
    broker_hostcall: impl FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a,
) -> Result<WorkerExecution, String> {
    let validated = redevplugin_wasm_abi::validate_worker_module(wasm_bytes, export_name)?;
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = wasmi::Engine::new(&config);
    let module = wasmi::Module::new(&engine, wasm_bytes)
        .map_err(|err| format!("compile wasm worker module: {err}"))?;
    let mut linker = <wasmi::Linker<WorkerHostState<'a>>>::new(&engine);
    linker
        .func_wrap(
            "redevplugin.storage",
            "files_write_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().storage_file_write_demo_requested = true;
            },
        )
        .map_err(|err| format!("define storage hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.storage",
            "files",
            |mut caller: wasmi::Caller<'_, WorkerHostState<'a>>,
             request_ptr: i32,
             request_len: i32,
             response_ptr: i32,
             response_len: i32|
             -> i32 {
                perform_storage_file_request_hostcall(
                    &mut caller,
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_len,
                )
            },
        )
        .map_err(|err| format!("define storage memory hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.storage",
            "kv_put_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().storage_kv_put_demo_requested = true;
            },
        )
        .map_err(|err| format!("define storage kv demo hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.storage",
            "kv",
            |mut caller: wasmi::Caller<'_, WorkerHostState<'a>>,
             request_ptr: i32,
             request_len: i32,
             response_ptr: i32,
             response_len: i32|
             -> i32 {
                perform_storage_kv_request_hostcall(
                    &mut caller,
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_len,
                )
            },
        )
        .map_err(|err| format!("define storage kv memory hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.storage",
            "sqlite_exec_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().storage_sqlite_exec_demo_requested = true;
            },
        )
        .map_err(|err| format!("define storage sqlite demo hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.storage",
            "sqlite",
            |mut caller: wasmi::Caller<'_, WorkerHostState<'a>>,
             request_ptr: i32,
             request_len: i32,
             response_ptr: i32,
             response_len: i32|
             -> i32 {
                perform_storage_sqlite_request_hostcall(
                    &mut caller,
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_len,
                )
            },
        )
        .map_err(|err| format!("define storage sqlite memory hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.network",
            "http_request_demo",
            |mut caller: wasmi::Caller<'_, WorkerHostState>| {
                caller.data_mut().network_http_request_demo_requested = true;
            },
        )
        .map_err(|err| format!("define network hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.network",
            "execute",
            |mut caller: wasmi::Caller<'_, WorkerHostState<'a>>,
             request_ptr: i32,
             request_len: i32,
             response_ptr: i32,
             response_len: i32|
             -> i32 {
                perform_network_execute_request_hostcall(
                    &mut caller,
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_len,
                )
            },
        )
        .map_err(|err| format!("define network execute memory hostcall import: {err}"))?;
    linker
        .func_wrap(
            "redevplugin.network",
            "http_request",
            |mut caller: wasmi::Caller<'_, WorkerHostState<'a>>,
             request_ptr: i32,
             request_len: i32,
             response_ptr: i32,
             response_len: i32|
             -> i32 {
                perform_network_execute_request_hostcall(
                    &mut caller,
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_len,
                )
            },
        )
        .map_err(|err| format!("define network memory hostcall import: {err}"))?;
    let mut store = wasmi::Store::new(&engine, WorkerHostState::new(broker_hostcall));
    store
        .set_fuel(DEFAULT_WASM_WORKER_FUEL)
        .map_err(|err| format!("configure wasm worker fuel: {err}"))?;
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
    let storage_file_requested = store.data().storage_file_requested;
    let storage_file_result = store.data().storage_file_result.clone();
    let storage_kv_put_demo_requested = store.data().storage_kv_put_demo_requested;
    let storage_kv_requested = store.data().storage_kv_requested;
    let storage_kv_result = store.data().storage_kv_result.clone();
    let storage_sqlite_exec_demo_requested = store.data().storage_sqlite_exec_demo_requested;
    let storage_sqlite_requested = store.data().storage_sqlite_requested;
    let storage_sqlite_result = store.data().storage_sqlite_result.clone();
    let network_http_request_demo_requested = store.data().network_http_request_demo_requested;
    let network_execute_requested = store.data().network_execute_requested;
    let network_execute_results = store.data().network_execute_results.clone();
    Ok(WorkerExecution {
        validated,
        storage_file_write_demo_requested,
        storage_file_requested,
        storage_file_result,
        storage_kv_put_demo_requested,
        storage_kv_requested,
        storage_kv_result,
        storage_sqlite_exec_demo_requested,
        storage_sqlite_requested,
        storage_sqlite_result,
        network_http_request_demo_requested,
        network_execute_requested,
        network_execute_results,
    })
}

fn perform_storage_file_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
    caller.data_mut().storage_file_requested = true;
    let request_ptr = match usize::try_from(request_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -1),
    };
    let request_len = match usize::try_from(request_len) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -1),
    };
    let response_ptr = match usize::try_from(response_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -1),
    };
    let response_len = match usize::try_from(response_len) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -1),
    };
    if request_len == 0 || request_len > 64 * 1024 || response_len == 0 || response_len > 256 * 1024
    {
        return record_storage_hostcall_error(caller, -2);
    }
    let Some(memory) = caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
    else {
        return record_storage_hostcall_error(caller, -3);
    };
    let mut request = vec![0_u8; request_len];
    if memory
        .read(caller.as_context(), request_ptr, &mut request)
        .is_err()
    {
        return record_storage_hostcall_error(caller, -4);
    }
    let request_json = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -5),
    };
    let response_json = {
        let state = caller.data_mut();
        (state.broker_hostcall)(WorkerHostcallRequest::StorageFile(request_json.to_string()))
    };
    let response_json = match response_json {
        Ok(value) => value,
        Err(err) => {
            caller.data_mut().storage_file_result = Some(Err(err));
            return -6;
        }
    };
    let response = response_json.as_bytes();
    if response.len() > response_len {
        caller.data_mut().storage_file_result = Some(Err(
            "storage files response does not fit in the output buffer".to_string(),
        ));
        return -7;
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_hostcall_error(caller, -8);
    }
    let written = match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => return record_storage_hostcall_error(caller, -9),
    };
    caller.data_mut().storage_file_result = Some(Ok(response_json));
    written
}

fn record_storage_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    caller.data_mut().storage_file_result = Some(Err(format!(
        "storage files hostcall failed with ABI code {code}"
    )));
    code
}

fn perform_storage_kv_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
    caller.data_mut().storage_kv_requested = true;
    let request_ptr = match usize::try_from(request_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -1),
    };
    let request_len = match usize::try_from(request_len) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -1),
    };
    let response_ptr = match usize::try_from(response_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -1),
    };
    let response_len = match usize::try_from(response_len) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -1),
    };
    if request_len == 0 || request_len > 64 * 1024 || response_len == 0 || response_len > 256 * 1024
    {
        return record_storage_kv_hostcall_error(caller, -2);
    }
    let Some(memory) = caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
    else {
        return record_storage_kv_hostcall_error(caller, -3);
    };
    let mut request = vec![0_u8; request_len];
    if memory
        .read(caller.as_context(), request_ptr, &mut request)
        .is_err()
    {
        return record_storage_kv_hostcall_error(caller, -4);
    }
    let request_json = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -5),
    };
    let response_json = {
        let state = caller.data_mut();
        (state.broker_hostcall)(WorkerHostcallRequest::StorageKV(request_json.to_string()))
    };
    let response_json = match response_json {
        Ok(value) => value,
        Err(err) => {
            caller.data_mut().storage_kv_result = Some(Err(err));
            return -6;
        }
    };
    let response = response_json.as_bytes();
    if response.len() > response_len {
        caller.data_mut().storage_kv_result = Some(Err(
            "storage kv response does not fit in the output buffer".to_string(),
        ));
        return -7;
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_kv_hostcall_error(caller, -8);
    }
    let written = match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => return record_storage_kv_hostcall_error(caller, -9),
    };
    caller.data_mut().storage_kv_result = Some(Ok(response_json));
    written
}

fn record_storage_kv_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    caller.data_mut().storage_kv_result.replace(Err(format!(
        "storage kv hostcall failed with ABI code {code}"
    )));
    code
}

fn perform_storage_sqlite_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
    caller.data_mut().storage_sqlite_requested = true;
    let request_ptr = match usize::try_from(request_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -1),
    };
    let request_len = match usize::try_from(request_len) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -1),
    };
    let response_ptr = match usize::try_from(response_ptr) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -1),
    };
    let response_len = match usize::try_from(response_len) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -1),
    };
    if request_len == 0 || request_len > 64 * 1024 || response_len == 0 || response_len > 256 * 1024
    {
        return record_storage_sqlite_hostcall_error(caller, -2);
    }
    let Some(memory) = caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
    else {
        return record_storage_sqlite_hostcall_error(caller, -3);
    };
    let mut request = vec![0_u8; request_len];
    if memory
        .read(caller.as_context(), request_ptr, &mut request)
        .is_err()
    {
        return record_storage_sqlite_hostcall_error(caller, -4);
    }
    let request_json = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -5),
    };
    let response_json = {
        let state = caller.data_mut();
        (state.broker_hostcall)(WorkerHostcallRequest::StorageSQLite(
            request_json.to_string(),
        ))
    };
    let response_json = match response_json {
        Ok(value) => value,
        Err(err) => {
            caller.data_mut().storage_sqlite_result = Some(Err(err));
            return -6;
        }
    };
    let response = response_json.as_bytes();
    if response.len() > response_len {
        caller.data_mut().storage_sqlite_result = Some(Err(
            "storage sqlite response does not fit in the output buffer".to_string(),
        ));
        return -7;
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_sqlite_hostcall_error(caller, -8);
    }
    let written = match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => return record_storage_sqlite_hostcall_error(caller, -9),
    };
    caller.data_mut().storage_sqlite_result = Some(Ok(response_json));
    written
}

fn record_storage_sqlite_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    caller.data_mut().storage_sqlite_result.replace(Err(format!(
        "storage sqlite hostcall failed with ABI code {code}"
    )));
    code
}

fn perform_network_execute_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
    caller.data_mut().network_execute_requested = true;
    let request_ptr = match usize::try_from(request_ptr) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -1),
    };
    let request_len = match usize::try_from(request_len) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -1),
    };
    let response_ptr = match usize::try_from(response_ptr) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -1),
    };
    let response_len = match usize::try_from(response_len) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -1),
    };
    if request_len == 0 || request_len > 64 * 1024 || response_len == 0 || response_len > 256 * 1024
    {
        return record_network_hostcall_error(caller, -2);
    }
    let Some(memory) = caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
    else {
        return record_network_hostcall_error(caller, -3);
    };
    let mut request = vec![0_u8; request_len];
    if memory
        .read(caller.as_context(), request_ptr, &mut request)
        .is_err()
    {
        return record_network_hostcall_error(caller, -4);
    }
    let request_json = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -5),
    };
    let response_json = {
        let state = caller.data_mut();
        (state.broker_hostcall)(WorkerHostcallRequest::NetworkExecute(
            request_json.to_string(),
        ))
    };
    let response_json = match response_json {
        Ok(value) => value,
        Err(err) => {
            caller.data_mut().network_execute_results.push(Err(err));
            return -6;
        }
    };
    let response = response_json.as_bytes();
    if response.len() > response_len {
        caller.data_mut().network_execute_results.push(Err(
            "network execute response does not fit in the output buffer".to_string(),
        ));
        return -7;
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_network_hostcall_error(caller, -8);
    }
    let written = match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => return record_network_hostcall_error(caller, -9),
    };
    caller
        .data_mut()
        .network_execute_results
        .push(Ok(response_json));
    written
}

fn record_network_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    caller.data_mut().network_execute_results.push(Err(format!(
        "network execute hostcall failed with ABI code {code}"
    )));
    code
}

fn perform_storage_file_write_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
) -> Result<String, String> {
    let req = storage_file_write_demo_request(invocation_frame, runtime_generation_id)?;
    dispatch_storage_file_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn perform_storage_file_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
) -> Result<String, String> {
    let req = storage_file_request(invocation_frame, runtime_generation_id, request_json)?;
    dispatch_storage_file_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn perform_storage_kv_put_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
) -> Result<String, String> {
    let req = storage_kv_put_demo_request(invocation_frame, runtime_generation_id)?;
    dispatch_storage_kv_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn perform_storage_kv_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
) -> Result<String, String> {
    let req = storage_kv_request(invocation_frame, runtime_generation_id, request_json)?;
    dispatch_storage_kv_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn perform_storage_sqlite_exec_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
) -> Result<String, String> {
    let req = storage_sqlite_exec_demo_request(invocation_frame, runtime_generation_id)?;
    dispatch_storage_sqlite_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn perform_storage_sqlite_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
) -> Result<String, String> {
    let req = storage_sqlite_request(invocation_frame, runtime_generation_id, request_json)?;
    dispatch_storage_sqlite_request(reader, stdout, request_id, runtime_generation_id, req)
}

fn dispatch_storage_file_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    req: redevplugin_ipc::StorageFileRequest,
) -> Result<String, String> {
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

fn dispatch_storage_kv_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    req: redevplugin_ipc::StorageKVRequest,
) -> Result<String, String> {
    let storage_request_id = format!("{request_id}:storage_kv");
    let frame = redevplugin_ipc::storage_kv_frame(&storage_request_id, runtime_generation_id, &req);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write storage_kv request: {err}"))?;
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("read storage_kv response: {err}"))?;
    if response.is_empty() {
        return Err("storage_kv response is empty".to_string());
    }
    redevplugin_ipc::validate_storage_kv_response(
        &response,
        &storage_request_id,
        runtime_generation_id,
    )?;
    redevplugin_ipc::storage_kv_payload_json(&response)
}

fn dispatch_storage_sqlite_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    req: redevplugin_ipc::StorageSQLiteRequest,
) -> Result<String, String> {
    let storage_request_id = format!("{request_id}:storage_sqlite");
    let frame =
        redevplugin_ipc::storage_sqlite_frame(&storage_request_id, runtime_generation_id, &req);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write storage_sqlite request: {err}"))?;
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("read storage_sqlite response: {err}"))?;
    if response.is_empty() {
        return Err("storage_sqlite response is empty".to_string());
    }
    redevplugin_ipc::validate_storage_sqlite_response(
        &response,
        &storage_request_id,
        runtime_generation_id,
    )?;
    redevplugin_ipc::storage_sqlite_payload_json(&response)
}

fn storage_file_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageFileRequest, String> {
    let store_id = request_or_invocation_string(
        request_json,
        "store_id",
        invocation_frame,
        "storage_store_id",
    )?;
    let handle_grant_token = required_json_string(invocation_frame, "storage_handle_grant_token")?;
    let path =
        request_or_invocation_string(request_json, "path", invocation_frame, "storage_path")?;
    let data_base64 = request_json_string(request_json, "data_base64")
        .or_else(|| request_json_string(invocation_frame, "storage_data_base64"))
        .unwrap_or_default();
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
        operation: request_json_string(request_json, "operation")
            .unwrap_or_else(|| "write".to_string()),
        store_id,
        path,
        data_base64,
        max_bytes: request_json_number(request_json, "max_bytes").unwrap_or(0),
        max_entries: request_json_number(request_json, "max_entries").unwrap_or(0),
        recursive: request_json_bool(request_json, "recursive").unwrap_or(false),
    })
}

fn storage_kv_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageKVRequest, String> {
    let store_id = request_or_invocation_string(
        request_json,
        "store_id",
        invocation_frame,
        "storage_kv_store_id",
    )
    .or_else(|_| {
        request_or_invocation_string(
            request_json,
            "store_id",
            invocation_frame,
            "storage_store_id",
        )
    })?;
    let handle_grant_token =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_kv_handle_grant_token")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                redevplugin_ipc::extract_json_string(invocation_frame, "storage_handle_grant_token")
            })
            .ok_or_else(|| "missing storage_kv_handle_grant_token".to_string())?;
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::StorageKVRequest {
        handle_grant_token,
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.kv".to_string(),
        policy_revision,
        management_revision,
        revoke_epoch,
        operation: request_json_string(request_json, "operation")
            .unwrap_or_else(|| "put".to_string()),
        store_id,
        key: request_json_string(request_json, "key")
            .or_else(|| request_json_string(invocation_frame, "storage_kv_key"))
            .unwrap_or_default(),
        value_base64: request_json_string(request_json, "value_base64")
            .or_else(|| request_json_string(invocation_frame, "storage_kv_value_base64"))
            .unwrap_or_default(),
        prefix: request_json_string(request_json, "prefix").unwrap_or_default(),
        max_bytes: request_json_number(request_json, "max_bytes").unwrap_or(0),
        max_entries: request_json_number(request_json, "max_entries").unwrap_or(0),
    })
}

fn storage_sqlite_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageSQLiteRequest, String> {
    let store_id = request_or_invocation_string(
        request_json,
        "store_id",
        invocation_frame,
        "storage_sqlite_store_id",
    )
    .or_else(|_| {
        request_or_invocation_string(
            request_json,
            "store_id",
            invocation_frame,
            "storage_store_id",
        )
    })?;
    let handle_grant_token =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_sqlite_handle_grant_token")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                redevplugin_ipc::extract_json_string(invocation_frame, "storage_handle_grant_token")
            })
            .ok_or_else(|| "missing storage_sqlite_handle_grant_token".to_string())?;
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::StorageSQLiteRequest {
        handle_grant_token,
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.sqlite".to_string(),
        policy_revision,
        management_revision,
        revoke_epoch,
        operation: request_json_string(request_json, "operation")
            .unwrap_or_else(|| "query".to_string()),
        store_id,
        database: request_json_string(request_json, "database")
            .or_else(|| request_json_string(invocation_frame, "storage_sqlite_database"))
            .unwrap_or_default(),
        sql: request_json_string(request_json, "sql")
            .or_else(|| request_json_string(invocation_frame, "storage_sqlite_sql"))
            .ok_or_else(|| "missing storage sqlite sql".to_string())?,
        args_json: request_json_array(request_json, "args").unwrap_or_else(|| "[]".to_string()),
        max_rows: request_json_number(request_json, "max_rows").unwrap_or(0),
        max_response_bytes: request_json_number(request_json, "max_response_bytes").unwrap_or(0),
        timeout_ms: request_json_number(request_json, "timeout_ms").unwrap_or(0),
    })
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

fn storage_sqlite_exec_demo_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
) -> Result<redevplugin_ipc::StorageSQLiteRequest, String> {
    let handle_grant_token =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_sqlite_handle_grant_token")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                redevplugin_ipc::extract_json_string(invocation_frame, "storage_handle_grant_token")
            })
            .ok_or_else(|| "missing storage_sqlite_handle_grant_token".to_string())?;
    let store_id =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_sqlite_store_id")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| redevplugin_ipc::extract_json_string(invocation_frame, "storage_store_id"))
            .ok_or_else(|| "missing storage_sqlite_store_id".to_string())?;
    let sql = redevplugin_ipc::extract_json_string(invocation_frame, "storage_sqlite_sql")
        .unwrap_or_else(|| {
            "CREATE TABLE IF NOT EXISTS worker_runs (id INTEGER PRIMARY KEY, note TEXT NOT NULL)"
                .to_string()
        });
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::StorageSQLiteRequest {
        handle_grant_token,
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.sqlite".to_string(),
        policy_revision,
        management_revision,
        revoke_epoch,
        operation: "exec".to_string(),
        store_id,
        database: redevplugin_ipc::extract_json_string(invocation_frame, "storage_sqlite_database")
            .unwrap_or_default(),
        sql,
        args_json: "[]".to_string(),
        max_rows: 0,
        max_response_bytes: 0,
        timeout_ms: 1000,
    })
}

fn storage_kv_put_demo_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
) -> Result<redevplugin_ipc::StorageKVRequest, String> {
    let handle_grant_token =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_kv_handle_grant_token")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                redevplugin_ipc::extract_json_string(invocation_frame, "storage_handle_grant_token")
            })
            .ok_or_else(|| "missing storage_kv_handle_grant_token".to_string())?;
    let store_id = redevplugin_ipc::extract_json_string(invocation_frame, "storage_kv_store_id")
        .filter(|value| !value.trim().is_empty())
        .or_else(|| redevplugin_ipc::extract_json_string(invocation_frame, "storage_store_id"))
        .ok_or_else(|| "missing storage_kv_store_id".to_string())?;
    let key = redevplugin_ipc::extract_json_string(invocation_frame, "storage_kv_key")
        .unwrap_or_else(|| "demo/last_broker_run".to_string());
    let value_base64 =
        redevplugin_ipc::extract_json_string(invocation_frame, "storage_kv_value_base64")
            .unwrap_or_else(|| "Z2VuZXJhdGVkIGJhY2tlbmQga3Ygc2FtcGxl".to_string());
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::StorageKVRequest {
        handle_grant_token,
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.kv".to_string(),
        policy_revision,
        management_revision,
        revoke_epoch,
        operation: "put".to_string(),
        store_id,
        key,
        value_base64,
        prefix: String::new(),
        max_bytes: 0,
        max_entries: 0,
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

fn perform_network_execute_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
) -> Result<String, String> {
    let req = network_execute_request(invocation_frame, runtime_generation_id, request_json)?;
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
    let connector_id =
        request_json_string(request_json, "connector_id").unwrap_or_else(|| "api".to_string());
    let transport =
        request_json_string(request_json, "transport").unwrap_or_else(|| "http".to_string());
    redevplugin_ipc::validate_network_execute_response(
        &response,
        &network_request_id,
        runtime_generation_id,
        &connector_id,
        &transport,
    )?;
    redevplugin_ipc::network_execute_payload_json(&response)
}

fn network_execute_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::NetworkExecuteRequest, String> {
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_instance_id,
        active_fingerprint,
        runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        policy_revision,
        management_revision,
        revoke_epoch,
        connector_id: request_json_string(request_json, "connector_id")
            .unwrap_or_else(|| "api".to_string()),
        transport: request_json_string(request_json, "transport")
            .unwrap_or_else(|| "http".to_string()),
        destination: request_json_string(request_json, "destination")
            .unwrap_or_else(|| "https://api.example.com".to_string()),
        ttl_ms: request_json_number(request_json, "ttl_ms").unwrap_or(30_000),
        operation: request_json_string(request_json, "operation")
            .unwrap_or_else(|| "http".to_string()),
        method: request_json_string(request_json, "method").unwrap_or_else(|| "GET".to_string()),
        path: request_json_string(request_json, "path").unwrap_or_else(|| "/".to_string()),
        headers_json: request_json_object(request_json, "headers")
            .unwrap_or_else(|| "{}".to_string()),
        message_type: request_json_string(request_json, "message_type").unwrap_or_default(),
        body_base64: request_json_string(request_json, "body_base64").unwrap_or_default(),
        payload_base64: request_json_string(request_json, "payload_base64").unwrap_or_default(),
        max_request_bytes: request_json_number(request_json, "max_request_bytes")
            .unwrap_or(64 * 1024),
        max_response_bytes: request_json_number(request_json, "max_response_bytes")
            .unwrap_or(256 * 1024),
        timeout_ms: request_json_number(request_json, "timeout_ms").unwrap_or(5_000),
    })
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

fn required_last_json_number(input: &str, key: &str) -> Result<u64, String> {
    let pattern = format!("\"{key}\"");
    let key_start = input
        .rfind(&pattern)
        .ok_or_else(|| format!("missing {key}"))?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key
        .find(':')
        .ok_or_else(|| format!("missing {key}"))?;
    let after_colon = after_key[colon + 1..].trim_start();
    let digits: String = after_colon
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return Err(format!("missing {key}"));
    }
    digits.parse().map_err(|_| format!("invalid {key}"))
}

fn request_json_string(input: &str, key: &str) -> Option<String> {
    redevplugin_ipc::extract_json_string(input, key).filter(|value| !value.trim().is_empty())
}

fn request_json_number(input: &str, key: &str) -> Option<u64> {
    redevplugin_ipc::extract_json_number_u64(input, key)
}

fn request_json_bool(input: &str, key: &str) -> Option<bool> {
    redevplugin_ipc::extract_json_bool(input, key)
}

fn request_json_object(input: &str, key: &str) -> Option<String> {
    redevplugin_ipc::extract_json_object(input, key)
}

fn request_json_array(input: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = &input[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let value = after_key[colon + 1..].trim_start();
    json_array_prefix(value)
}

fn json_array_prefix(input: &str) -> Option<String> {
    if !input.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '[' => depth += 1,
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(input[..=idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn request_or_invocation_string(
    request_json: &str,
    request_key: &str,
    invocation_frame: &str,
    invocation_key: &str,
) -> Result<String, String> {
    request_json_string(request_json, request_key)
        .or_else(|| request_json_string(invocation_frame, invocation_key))
        .ok_or_else(|| format!("missing {request_key}"))
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
    fn runtime_revocations_keep_highest_epoch_per_plugin() {
        let mut revocations = RuntimeRevocations::default();
        revocations.revoke_plugin("plugini_1", 4);
        revocations.revoke_plugin("plugini_1", 2);
        revocations.revoke_plugin("plugini_2", 1);

        let stale = revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 3))
            .expect_err("old epoch should be stale");
        assert_eq!(
            stale.code(),
            redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED
        );
        assert!(stale.to_string().contains("epoch 4"));
        revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 4))
            .expect("equal epoch is allowed for freshly issued leases");
        revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 5))
            .expect("newer epoch is allowed");
        revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_2", 1))
            .expect("another plugin has an independent revoke epoch");
    }

    #[test]
    fn runtime_revocations_reject_invalid_invocation_context() {
        let revocations = RuntimeRevocations::default();
        let missing_plugin = revocations
            .validate_invocation_frame(r#"{"payload":{"lease":{"revoke_epoch":1}}}"#)
            .expect_err("missing plugin should be invalid");
        assert_eq!(
            missing_plugin.code(),
            redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID
        );
        let missing_epoch = revocations
            .validate_invocation_frame(
                r#"{"payload":{"lease":{"plugin_instance_id":"plugini_1"}}}"#,
            )
            .expect_err("missing epoch should be invalid");
        assert_eq!(
            missing_epoch.code(),
            redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID
        );
    }

    #[test]
    fn handle_revoke_epoch_updates_runtime_revocation_state() {
        let mut revocations = RuntimeRevocations::default();
        let response = handle_revoke_epoch(
            &mut revocations,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":7}}"#,
        );
        assert!(response.contains(r#""frame_type":"revoke_epoch_ack""#));
        assert!(response.contains(r#""ok":true"#));
        let err = revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 6))
            .expect_err("old invocation should be revoked");
        assert_eq!(err.code(), redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED);
    }

    #[test]
    fn handle_revoke_epoch_fails_closed_for_invalid_frame() {
        let mut revocations = RuntimeRevocations::default();
        let response = handle_revoke_epoch(
            &mut revocations,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1"}}"#,
        );
        assert!(response.contains(r#""frame_type":"revoke_epoch_ack""#));
        assert!(response.contains(r#""ok":false"#));
        assert!(response.contains(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID));
        revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 0))
            .expect("invalid revoke frame must not create a revocation record");
    }

    #[test]
    fn worker_invocation_rejects_stale_epoch_before_opening_artifact() {
        let mut revocations = RuntimeRevocations::default();
        revocations.revoke_plugin("plugini_1", 5);
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &revocations,
            "r1",
            "g1",
            &worker_invocation_frame("plugini_1", 4),
        )
        .expect("worker invocation response");

        assert!(
            output.is_empty(),
            "stale invocation must not request an artifact"
        );
        assert!(response.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(response.contains(r#""ok":false"#));
        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED));
    }

    #[test]
    fn worker_invocation_allows_current_epoch_to_open_artifact() {
        let mut revocations = RuntimeRevocations::default();
        revocations.revoke_plugin("plugini_1", 5);
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &revocations,
            "r1",
            "g1",
            &worker_invocation_frame("plugini_1", 5),
        )
        .expect("worker invocation response");

        let output = String::from_utf8(output).expect("artifact request utf8");
        assert!(
            output.contains(r#""frame_type":"open_handle""#),
            "current invocation should request the bound worker artifact: {output}"
        );
        assert!(response.contains(redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED));
    }

    #[test]
    fn executes_minimal_wasm_worker_export() {
        let module = minimal_worker_wasm("redevplugin_worker_invoke");
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            unexpected_hostcall(request)
        })
        .expect("minimal worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(!execution.storage_file_requested);
        assert!(!execution.network_http_request_demo_requested);
        assert!(!execution.network_execute_requested);
    }

    #[test]
    fn executes_storage_hostcall_wasm_worker_export() {
        let module = storage_hostcall_worker_wasm("redevplugin_worker_invoke");
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            unexpected_hostcall(request)
        })
        .expect("storage hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(execution.storage_file_write_demo_requested);
        assert!(!execution.storage_file_requested);
        assert!(!execution.network_http_request_demo_requested);
        assert!(!execution.network_execute_requested);
    }

    #[test]
    fn executes_network_hostcall_wasm_worker_export() {
        let module = imported_hostcall_worker_wasm(
            "redevplugin.network",
            "http_request_demo",
            "redevplugin_worker_invoke",
        );
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            unexpected_hostcall(request)
        })
        .expect("network hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(!execution.storage_file_requested);
        assert!(execution.network_http_request_demo_requested);
        assert!(!execution.network_execute_requested);
    }

    #[test]
    fn executes_storage_memory_hostcall_wasm_worker_export() {
        let module = storage_memory_hostcall_worker_wasm("redevplugin_worker_invoke");
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            let WorkerHostcallRequest::StorageFile(request) = request else {
                panic!("expected storage hostcall request");
            };
            assert!(request.contains(r#""store_id":"workspace""#), "{request}");
            assert!(request.contains(r#""operation":"write""#), "{request}");
            Ok(r#"{"ok":true,"path":"notes/from-memory.txt","size_bytes":34}"#.to_string())
        })
        .expect("storage memory hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(execution.storage_file_requested);
        assert_eq!(
            execution.storage_file_result,
            Some(Ok(
                r#"{"ok":true,"path":"notes/from-memory.txt","size_bytes":34}"#.to_string()
            ))
        );
        assert!(!execution.network_http_request_demo_requested);
        assert!(!execution.network_execute_requested);
    }

    #[test]
    fn executes_network_memory_hostcall_wasm_worker_export() {
        let module = network_memory_hostcall_worker_wasm("redevplugin_worker_invoke");
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            let WorkerHostcallRequest::NetworkExecute(request) = request else {
                panic!("expected network hostcall request");
            };
            assert!(request.contains(r#""connector_id":"api""#), "{request}");
            assert!(request.contains(r#""method":"POST""#), "{request}");
            Ok(r#"{"ok":true,"transport":"http","status_code":202}"#.to_string())
        })
        .expect("network memory hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_file_write_demo_requested);
        assert!(!execution.storage_file_requested);
        assert!(!execution.network_http_request_demo_requested);
        assert!(execution.network_execute_requested);
        assert_eq!(
            execution.network_execute_results,
            vec![Ok(
                r#"{"ok":true,"transport":"http","status_code":202}"#.to_string()
            )]
        );
    }

    #[test]
    fn executes_legacy_network_http_request_memory_hostcall_wasm_worker_export() {
        let request = br#"{"connector_id":"stream","transport":"websocket","destination":"wss://stream.example.com","operation":"websocket_round_trip","message_type":"text","payload_base64":"aGVsbG8=","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}"#;
        let module = imported_memory_hostcall_worker_wasm(
            "redevplugin.network",
            "http_request",
            "redevplugin_worker_invoke",
            request,
        );
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            let WorkerHostcallRequest::NetworkExecute(request) = request else {
                panic!("expected network execute hostcall request");
            };
            assert!(request.contains(r#""transport":"websocket""#), "{request}");
            assert!(
                request.contains(r#""operation":"websocket_round_trip""#),
                "{request}"
            );
            Ok(r#"{"ok":true,"transport":"websocket","message_type":"text"}"#.to_string())
        })
        .expect("legacy network hostcall worker executes");
        assert!(execution.network_execute_requested);
        assert_eq!(
            execution.network_execute_results,
            vec![Ok(
                r#"{"ok":true,"transport":"websocket","message_type":"text"}"#.to_string()
            )]
        );
    }

    #[test]
    fn executes_storage_sqlite_memory_hostcall_wasm_worker_export() {
        let module = storage_sqlite_memory_hostcall_worker_wasm("redevplugin_worker_invoke");
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            let WorkerHostcallRequest::StorageSQLite(request) = request else {
                panic!("expected storage sqlite hostcall request");
            };
            assert!(request.contains(r#""store_id":"db""#), "{request}");
            assert!(request.contains(r#""operation":"query""#), "{request}");
            assert!(request.contains(r#""sql":"SELECT title FROM events WHERE score = ?""#), "{request}");
            Ok(r#"{"ok":true,"database":"plugin.sqlite","columns":["title"],"rows":[[{"text":"stored from wasm"}]]}"#.to_string())
        })
        .expect("storage sqlite memory hostcall worker executes");
        assert_eq!(execution.validated.byte_len, module.len());
        assert!(!execution.storage_sqlite_exec_demo_requested);
        assert!(execution.storage_sqlite_requested);
        assert_eq!(
            execution.storage_sqlite_result,
            Some(Ok(
                r#"{"ok":true,"database":"plugin.sqlite","columns":["title"],"rows":[[{"text":"stored from wasm"}]]}"#.to_string()
            ))
        );
        assert!(!execution.network_http_request_demo_requested);
        assert!(!execution.network_execute_requested);
    }

    #[test]
    fn rejects_wasm_worker_with_missing_export() {
        let module = minimal_worker_wasm("other_export");
        let err = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            unexpected_hostcall(request)
        })
        .expect_err("missing worker export");
        assert!(err.contains("required function export"));
    }

    fn unexpected_hostcall(request: WorkerHostcallRequest) -> Result<String, String> {
        match request {
            WorkerHostcallRequest::StorageFile(_) => Err("unexpected storage call".to_string()),
            WorkerHostcallRequest::StorageKV(_) => Err("unexpected storage kv call".to_string()),
            WorkerHostcallRequest::StorageSQLite(_) => {
                Err("unexpected storage sqlite call".to_string())
            }
            WorkerHostcallRequest::NetworkExecute(_) => Err("unexpected network call".to_string()),
        }
    }

    fn worker_invocation_frame(plugin_instance_id: &str, revoke_epoch: u64) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{"lease_id":"lease_1","lease_token":"token_1","runtime_generation_id":"g1","plugin_instance_id":"{plugin_instance_id}","revoke_epoch":{revoke_epoch}}},"method":"worker.echo","invocation":{{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}}}}}}"#
        )
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
        imported_hostcall_worker_wasm("redevplugin.storage", "files_write_demo", export_name)
    }

    fn storage_memory_hostcall_worker_wasm(export_name: &str) -> Vec<u8> {
        let request = br#"{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8gZnJvbSBtZW1vcnkgc3RvcmFnZSBob3N0Y2FsbA==","max_bytes":0,"max_entries":0,"recursive":false}"#;
        imported_memory_hostcall_worker_wasm("redevplugin.storage", "files", export_name, request)
    }

    fn network_memory_hostcall_worker_wasm(export_name: &str) -> Vec<u8> {
        let request = br#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"POST","path":"/v1/worker","headers":{"Content-Type":["text/plain"]},"body_base64":"aGVsbG8=","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}"#;
        imported_memory_hostcall_worker_wasm("redevplugin.network", "execute", export_name, request)
    }

    fn storage_sqlite_memory_hostcall_worker_wasm(export_name: &str) -> Vec<u8> {
        let request = br#"{"store_id":"db","operation":"query","database":"plugin.sqlite","sql":"SELECT title FROM events WHERE score = ?","args":[{"int":7}],"max_rows":10,"max_response_bytes":4096,"timeout_ms":1000}"#;
        imported_memory_hostcall_worker_wasm("redevplugin.storage", "sqlite", export_name, request)
    }

    fn imported_memory_hostcall_worker_wasm(
        import_module: &str,
        import_name: &str,
        export_name: &str,
        request: &[u8],
    ) -> Vec<u8> {
        let export_name_bytes = export_name.as_bytes();
        let import_module = import_module.as_bytes();
        let import_name = import_name.as_bytes();
        let mut module = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x60, 0x04, 0x7f,
            0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x00, 0x02,
        ];
        let mut import_payload = vec![0x01, import_module.len() as u8];
        import_payload.extend_from_slice(import_module);
        import_payload.push(import_name.len() as u8);
        import_payload.extend_from_slice(import_name);
        import_payload.extend_from_slice(&[0x00, 0x00]);
        push_leb_u32(&mut module, import_payload.len() as u32);
        module.extend_from_slice(&import_payload);
        module.extend_from_slice(&[0x03, 0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07]);
        let mut export_payload = vec![0x02, 0x06];
        export_payload.extend_from_slice(b"memory");
        export_payload.extend_from_slice(&[0x02, 0x00, export_name_bytes.len() as u8]);
        export_payload.extend_from_slice(export_name_bytes);
        export_payload.extend_from_slice(&[0x00, 0x01]);
        push_leb_u32(&mut module, export_payload.len() as u32);
        module.extend_from_slice(&export_payload);
        module.extend_from_slice(&[0x0a]);
        let mut code_payload = vec![0x01];
        let mut body = vec![0x00, 0x41, 0x00, 0x41];
        push_leb_u32(&mut body, request.len() as u32);
        body.extend_from_slice(&[0x41]);
        push_leb_u32(&mut body, 512);
        body.extend_from_slice(&[0x41]);
        push_leb_u32(&mut body, 512);
        body.extend_from_slice(&[0x10, 0x00, 0x1a, 0x0b]);
        push_leb_u32(&mut code_payload, body.len() as u32);
        code_payload.extend_from_slice(&body);
        push_leb_u32(&mut module, code_payload.len() as u32);
        module.extend_from_slice(&code_payload);
        module.extend_from_slice(&[0x0b]);
        let mut data_payload = vec![0x01, 0x00, 0x41, 0x00, 0x0b];
        push_leb_u32(&mut data_payload, request.len() as u32);
        data_payload.extend_from_slice(request);
        push_leb_u32(&mut module, data_payload.len() as u32);
        module.extend_from_slice(&data_payload);
        module
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

    fn push_leb_u32(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }
}
