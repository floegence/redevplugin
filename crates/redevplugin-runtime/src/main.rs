use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmi::{AsContext, AsContextMut, Config};

const DEFAULT_WASM_WORKER_FUEL: u64 = 5_000_000;
const DEFAULT_CONTROL_MAX_STALENESS: Duration = Duration::from_millis(5_000);
const DEFAULT_RUNTIME_LEASE_REPLAY_CAPACITY: usize = 16_384;
const RUNTIME_CONTROL_STALE_MESSAGE_PREFIX: &str = "runtime control channel is stale";

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
    let runtime_lease_public_keys =
        redevplugin_ipc::parse_runtime_lease_public_keys(&line).map_err(|err| err.to_string())?;
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
    let mut lease_replays = RuntimeLeaseReplayCache::default();
    let mut resources = RuntimeResourceRegistry::default();
    let mut control = ControlChannelState::new();
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
            redevplugin_ipc::FRAME_TYPE_HEARTBEAT => {
                handle_heartbeat(&mut control, &request_id, &runtime_generation_id, &line)
            }
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER => handle_worker_invocation(
                &mut reader,
                &mut stdout,
                &mut WorkerInvocationState {
                    revocations: &revocations,
                    lease_replays: &mut lease_replays,
                    resources: &mut resources,
                    control: &control,
                    runtime_lease_public_keys: &runtime_lease_public_keys,
                    now_unix_ms: current_unix_millis()?,
                },
                &request_id,
                &runtime_generation_id,
                &line,
            )?,
            redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH => handle_revoke_epoch(
                &mut revocations,
                &mut resources,
                &mut control,
                &request_id,
                &runtime_generation_id,
                &line,
            ),
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

fn handle_heartbeat(
    control: &mut ControlChannelState,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> String {
    let host_sent_unix_nano = match required_json_number(line, "sent_unix_nano") {
        Ok(value) => value,
        Err(err) => {
            return redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
                request_id,
                runtime_generation_id,
                false,
                None,
                None,
                Some(err.as_str()),
            );
        }
    };
    let max_staleness_ms = match required_json_number(line, "max_staleness_ms") {
        Ok(value) if value > 0 => value,
        Ok(_) => {
            return redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
                request_id,
                runtime_generation_id,
                false,
                None,
                None,
                Some("max_staleness_ms must be positive"),
            );
        }
        Err(err) => {
            return redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
                request_id,
                runtime_generation_id,
                false,
                None,
                None,
                Some(err.as_str()),
            );
        }
    };
    control.refresh(Duration::from_millis(max_staleness_ms));
    let runtime_unix_nano = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(1);
    let result_json = redevplugin_ipc::heartbeat_ack_result_json(
        runtime_generation_id,
        runtime_unix_nano.max(1),
        max_staleness_ms,
        host_sent_unix_nano,
    );
    redevplugin_ipc::response_frame(
        redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
        request_id,
        runtime_generation_id,
        true,
        Some(&result_json),
        None,
        None,
    )
}

#[derive(Debug)]
struct ControlChannelState {
    last_refresh: Instant,
    max_staleness: Duration,
}

impl ControlChannelState {
    fn new() -> Self {
        Self {
            last_refresh: Instant::now(),
            max_staleness: DEFAULT_CONTROL_MAX_STALENESS,
        }
    }

    fn refresh(&mut self, max_staleness: Duration) {
        self.max_staleness = max_staleness.max(Duration::from_millis(1));
        self.refresh_without_staleness_change();
    }

    fn refresh_without_staleness_change(&mut self) {
        self.last_refresh = Instant::now();
    }

    fn validate_fresh(&self) -> Result<(), RuntimeControlError> {
        let elapsed = self.last_refresh.elapsed();
        if elapsed > self.max_staleness {
            return Err(RuntimeControlError::Stale {
                elapsed_ms: duration_millis_u64(elapsed),
                max_staleness_ms: duration_millis_u64(self.max_staleness),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn force_stale_for_test(&mut self) {
        let stale_by = self.max_staleness + Duration::from_millis(1);
        self.last_refresh = Instant::now()
            .checked_sub(stale_by)
            .unwrap_or_else(Instant::now);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeControlError {
    Stale {
        elapsed_ms: u64,
        max_staleness_ms: u64,
    },
}

impl RuntimeControlError {
    fn code(&self) -> &'static str {
        match self {
            Self::Stale { .. } => redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE,
        }
    }
}

impl std::fmt::Display for RuntimeControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale {
                elapsed_ms,
                max_staleness_ms,
            } => write!(
                formatter,
                "{RUNTIME_CONTROL_STALE_MESSAGE_PREFIX} after {elapsed_ms}ms; max staleness is {max_staleness_ms}ms"
            ),
        }
    }
}

fn worker_hostcall_error_code(message: &str) -> &'static str {
    if message.starts_with(RUNTIME_CONTROL_STALE_MESSAGE_PREFIX) {
        return redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE;
    }
    redevplugin_ipc::ERR_WASM_HOSTCALL_FAILED
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn current_unix_millis() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time is before UNIX epoch: {err}"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| "system time exceeds i64 milliseconds".to_string())
}

struct WorkerInvocationState<'a> {
    revocations: &'a RuntimeRevocations,
    lease_replays: &'a mut RuntimeLeaseReplayCache,
    resources: &'a mut RuntimeResourceRegistry,
    control: &'a ControlChannelState,
    runtime_lease_public_keys: &'a [redevplugin_ipc::RuntimeLeasePublicKey],
    now_unix_ms: i64,
}

fn handle_worker_invocation<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    state: &mut WorkerInvocationState<'_>,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> Result<String, String> {
    if let Err(err) = state.control.validate_fresh() {
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
    if let Err(err) = state.revocations.validate_invocation_frame(line) {
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
    if let Err(err) = redevplugin_ipc::verify_worker_runtime_lease_signature(
        line,
        state.runtime_lease_public_keys,
    ) {
        return Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(redevplugin_ipc::ERR_RUNTIME_LEASE_SIGNATURE_INVALID),
            Some(err.as_str()),
        ));
    }
    if let Err(err) = redevplugin_ipc::validate_worker_runtime_lease(line, state.now_unix_ms) {
        return Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID),
            Some(err.as_str()),
        ));
    }
    if let Err(err) = state
        .lease_replays
        .consume_invocation_frame(line, state.now_unix_ms)
    {
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
    if let Err(err) = state.control.validate_fresh() {
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
    if let Err(err) = state.control.validate_fresh() {
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
            WorkerHostcallRequest::StorageFile(request_json) => {
                state
                    .control
                    .validate_fresh()
                    .map_err(|err| err.to_string())?;
                perform_storage_file_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                    state.resources,
                )
            }
            WorkerHostcallRequest::StorageKV(request_json) => {
                state
                    .control
                    .validate_fresh()
                    .map_err(|err| err.to_string())?;
                perform_storage_kv_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                    state.resources,
                )
            }
            WorkerHostcallRequest::StorageSQLite(request_json) => {
                state
                    .control
                    .validate_fresh()
                    .map_err(|err| err.to_string())?;
                perform_storage_sqlite_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                    state.resources,
                )
            }
            WorkerHostcallRequest::NetworkExecute(request_json) => {
                state
                    .control
                    .validate_fresh()
                    .map_err(|err| err.to_string())?;
                perform_network_execute_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                    state.resources,
                )
            }
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
    if let Ok(plugin_instance_id) = required_json_string(line, "plugin_instance_id") {
        state.resources.track_actor(
            &plugin_instance_id,
            &identity.worker_id,
            &identity.artifact,
            &identity.export,
        );
    }
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
                        Some(worker_hostcall_error_code(err.as_str())),
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
                    Some(worker_hostcall_error_code(err.as_str())),
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
                    Some(worker_hostcall_error_code(err.as_str())),
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
                    Some(worker_hostcall_error_code(err.as_str())),
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
            if let Err(err) = state.control.validate_fresh() {
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
            match perform_storage_file_write_demo(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                state.resources,
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
            if let Err(err) = state.control.validate_fresh() {
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
            match perform_storage_kv_put_demo(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                state.resources,
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
            if let Err(err) = state.control.validate_fresh() {
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
            match perform_storage_sqlite_exec_demo(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                state.resources,
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
            if let Err(err) = state.control.validate_fresh() {
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
            match perform_network_http_request_demo(
                reader,
                stdout,
                request_id,
                runtime_generation_id,
                line,
                state.resources,
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

#[derive(Debug, Default, PartialEq, Eq)]
struct RuntimeResourceCloseCounts {
    actor: u64,
    socket: u64,
    stream: u64,
    storage_handle: u64,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct RuntimeResourceKey {
    plugin_instance_id: String,
    resource_id: String,
}

impl RuntimeResourceKey {
    fn new(plugin_instance_id: &str, resource_id: String) -> Self {
        Self {
            plugin_instance_id: plugin_instance_id.to_string(),
            resource_id,
        }
    }
}

#[derive(Default)]
struct RuntimeResourceRegistry {
    actors: HashSet<RuntimeResourceKey>,
    sockets: HashSet<RuntimeResourceKey>,
    streams: HashSet<RuntimeResourceKey>,
    storage_handles: HashSet<RuntimeResourceKey>,
}

impl RuntimeResourceRegistry {
    fn track_actor(
        &mut self,
        plugin_instance_id: &str,
        worker_id: &str,
        artifact: &str,
        export: &str,
    ) {
        self.actors.insert(RuntimeResourceKey::new(
            plugin_instance_id,
            format!("worker:{worker_id}:{artifact}:{export}"),
        ));
    }

    fn track_storage_handle(&mut self, plugin_instance_id: &str, handle_id: &str, method: &str) {
        self.storage_handles.insert(RuntimeResourceKey::new(
            plugin_instance_id,
            format!("{method}:{handle_id}"),
        ));
    }

    fn track_socket(&mut self, req: &redevplugin_ipc::NetworkExecuteRequest) {
        self.sockets.insert(RuntimeResourceKey::new(
            &req.plugin_instance_id,
            format!("{}:{}:{}", req.transport, req.connector_id, req.destination),
        ));
    }

    fn track_stream(&mut self, req: &redevplugin_ipc::NetworkExecuteRequest, stream_id: &str) {
        if stream_id.trim().is_empty() {
            return;
        }
        self.streams.insert(RuntimeResourceKey::new(
            &req.plugin_instance_id,
            format!("{}:{}:{stream_id}", req.transport, req.connector_id),
        ));
    }

    fn revoke_plugin(&mut self, plugin_instance_id: &str) -> RuntimeResourceCloseCounts {
        RuntimeResourceCloseCounts {
            actor: remove_plugin_resources(&mut self.actors, plugin_instance_id),
            socket: remove_plugin_resources(&mut self.sockets, plugin_instance_id),
            stream: remove_plugin_resources(&mut self.streams, plugin_instance_id),
            storage_handle: remove_plugin_resources(&mut self.storage_handles, plugin_instance_id),
        }
    }
}

fn remove_plugin_resources(
    resources: &mut HashSet<RuntimeResourceKey>,
    plugin_instance_id: &str,
) -> u64 {
    let before = resources.len();
    resources.retain(|resource| resource.plugin_instance_id != plugin_instance_id);
    u64::try_from(before.saturating_sub(resources.len())).unwrap_or(u64::MAX)
}

struct RuntimeLeaseReplayCache {
    consumed_leases: HashMap<String, i64>,
    max_entries: usize,
}

impl Default for RuntimeLeaseReplayCache {
    fn default() -> Self {
        Self {
            consumed_leases: HashMap::new(),
            max_entries: DEFAULT_RUNTIME_LEASE_REPLAY_CAPACITY,
        }
    }
}

impl RuntimeLeaseReplayCache {
    #[cfg(test)]
    fn with_capacity(max_entries: usize) -> Self {
        Self {
            consumed_leases: HashMap::new(),
            max_entries,
        }
    }

    fn consume_invocation_frame(
        &mut self,
        frame: &str,
        now_unix_ms: i64,
    ) -> Result<(), RuntimeLeaseReplayError> {
        let key = redevplugin_ipc::parse_worker_lease_replay_key(frame)
            .map_err(|_| RuntimeLeaseReplayError::InvalidInvocation)?;
        self.consumed_leases
            .retain(|_, expires_at_unix_ms| *expires_at_unix_ms > now_unix_ms);
        let cache_key = format!("{}:{}", key.lease_id, key.lease_nonce);
        if self.consumed_leases.contains_key(&cache_key) {
            return Err(RuntimeLeaseReplayError::Replayed {
                lease_id: key.lease_id,
            });
        }
        if self.max_entries == 0 || self.consumed_leases.len() >= self.max_entries {
            return Err(RuntimeLeaseReplayError::CapacityExceeded);
        }
        self.consumed_leases
            .insert(cache_key, key.expires_at_unix_ms);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeLeaseReplayError {
    InvalidInvocation,
    Replayed { lease_id: String },
    CapacityExceeded,
}

impl RuntimeLeaseReplayError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInvocation => redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
            Self::Replayed { .. } => redevplugin_ipc::ERR_LEASE_REPLAYED,
            Self::CapacityExceeded => redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
        }
    }
}

impl std::fmt::Display for RuntimeLeaseReplayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInvocation => {
                write!(
                    formatter,
                    "worker invocation is missing a valid lease_id or lease_nonce"
                )
            }
            Self::Replayed { lease_id } => {
                write!(
                    formatter,
                    "runtime execution lease {lease_id} was already consumed"
                )
            }
            Self::CapacityExceeded => {
                write!(
                    formatter,
                    "runtime lease replay cache capacity is exhausted"
                )
            }
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
    resources: &mut RuntimeResourceRegistry,
    control: &mut ControlChannelState,
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
    let closed = resources.revoke_plugin(&plugin_instance_id);
    control.refresh_without_staleness_change();
    let result_json = redevplugin_ipc::revoke_epoch_ack_result_json(
        &plugin_instance_id,
        revoke_epoch,
        closed.actor,
        closed.socket,
        closed.stream,
        closed.storage_handle,
    );
    redevplugin_ipc::response_frame(
        redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
        request_id,
        runtime_generation_id,
        true,
        Some(&result_json),
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
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_file_write_demo_request(invocation_frame, runtime_generation_id)?;
    let result =
        dispatch_storage_file_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn perform_storage_file_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_file_request(invocation_frame, runtime_generation_id, request_json)?;
    let result =
        dispatch_storage_file_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn perform_storage_kv_put_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_kv_put_demo_request(invocation_frame, runtime_generation_id)?;
    let result =
        dispatch_storage_kv_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn perform_storage_kv_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_kv_request(invocation_frame, runtime_generation_id, request_json)?;
    let result =
        dispatch_storage_kv_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn perform_storage_sqlite_exec_demo<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_sqlite_exec_demo_request(invocation_frame, runtime_generation_id)?;
    let result =
        dispatch_storage_sqlite_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn perform_storage_sqlite_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
    resources: &mut RuntimeResourceRegistry,
) -> Result<String, String> {
    let req = storage_sqlite_request(invocation_frame, runtime_generation_id, request_json)?;
    let result =
        dispatch_storage_sqlite_request(reader, stdout, request_id, runtime_generation_id, &req)?;
    resources.track_storage_handle(&req.plugin_instance_id, &req.handle_id, &req.method);
    Ok(result)
}

fn dispatch_storage_file_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    req: &redevplugin_ipc::StorageFileRequest,
) -> Result<String, String> {
    let storage_request_id = format!("{request_id}:storage_file");
    let frame =
        redevplugin_ipc::storage_file_frame(&storage_request_id, runtime_generation_id, req);
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
    req: &redevplugin_ipc::StorageKVRequest,
) -> Result<String, String> {
    let storage_request_id = format!("{request_id}:storage_kv");
    let frame = redevplugin_ipc::storage_kv_frame(&storage_request_id, runtime_generation_id, req);
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
    req: &redevplugin_ipc::StorageSQLiteRequest,
) -> Result<String, String> {
    let storage_request_id = format!("{request_id}:storage_sqlite");
    let frame =
        redevplugin_ipc::storage_sqlite_frame(&storage_request_id, runtime_generation_id, req);
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
    resources: &mut RuntimeResourceRegistry,
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
    let result = redevplugin_ipc::network_execute_payload_json(&response)?;
    resources.track_socket(&req);
    if let Some(stream_id) = request_json_string(&result, "stream_id") {
        resources.track_stream(&req, &stream_id);
    }
    Ok(result)
}

fn perform_network_execute_request<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    request_id: &str,
    runtime_generation_id: &str,
    invocation_frame: &str,
    request_json: &str,
    resources: &mut RuntimeResourceRegistry,
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
    let result = redevplugin_ipc::network_execute_payload_json(&response)?;
    resources.track_socket(&req);
    if let Some(stream_id) = request_json_string(&result, "stream_id") {
        resources.track_stream(&req, &stream_id);
    }
    Ok(result)
}

fn network_execute_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::NetworkExecuteRequest, String> {
    for field in [
        "stream_method",
        "stream_effect",
        "stream_execution",
        "surface_instance_id",
        "owner_session_hash",
        "owner_user_hash",
        "session_channel_id_hash",
        "bridge_channel_id",
    ] {
        if request_json_string(request_json, field).is_some() {
            return Err(format!(
                "network request must not set host-owned invocation field {field}"
            ));
        }
    }
    let plugin_id = required_json_string(invocation_frame, "plugin_id")?;
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    let stream_method =
        redevplugin_ipc::extract_json_string(invocation_frame, "method").unwrap_or_default();
    let stream_effect =
        redevplugin_ipc::extract_json_string(invocation_frame, "effect").unwrap_or_default();
    let stream_execution =
        redevplugin_ipc::extract_json_string(invocation_frame, "execution").unwrap_or_default();
    let operation =
        request_json_string(request_json, "operation").unwrap_or_else(|| "http".to_string());
    let requested_stream_id = request_json_string(request_json, "stream_id");
    let stream_id = if operation == "http_stream" {
        if requested_stream_id.is_some() {
            return Err("http_stream request must not select the host-owned stream_id".to_string());
        }
        let host_stream_id =
            redevplugin_ipc::extract_json_string(invocation_frame, "stream_id").unwrap_or_default();
        if host_stream_id.is_empty() {
            return Err("http_stream invocation is missing the host-owned stream_id".to_string());
        }
        host_stream_id
    } else {
        requested_stream_id.unwrap_or_default()
    };
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_id,
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
        operation,
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
        max_chunk_bytes: request_json_number(request_json, "max_chunk_bytes").unwrap_or(32 * 1024),
        max_buffered_bytes: request_json_number(request_json, "max_buffered_bytes")
            .unwrap_or(1024 * 1024),
        timeout_ms: request_json_number(request_json, "timeout_ms").unwrap_or(5_000),
        stream_id,
        stream_method,
        stream_effect,
        stream_execution,
        surface_instance_id: redevplugin_ipc::extract_json_string(
            invocation_frame,
            "surface_instance_id",
        )
        .unwrap_or_default(),
        owner_session_hash: redevplugin_ipc::extract_json_string(
            invocation_frame,
            "owner_session_hash",
        )
        .unwrap_or_default(),
        owner_user_hash: redevplugin_ipc::extract_json_string(invocation_frame, "owner_user_hash")
            .unwrap_or_default(),
        session_channel_id_hash: redevplugin_ipc::extract_json_string(
            invocation_frame,
            "session_channel_id_hash",
        )
        .unwrap_or_default(),
        bridge_channel_id: redevplugin_ipc::extract_json_string(
            invocation_frame,
            "bridge_channel_id",
        )
        .unwrap_or_default(),
        content_type: request_json_string(request_json, "content_type").unwrap_or_default(),
    })
}

fn network_http_request_demo(
    invocation_frame: &str,
    runtime_generation_id: &str,
) -> Result<redevplugin_ipc::NetworkExecuteRequest, String> {
    let plugin_id = required_json_string(invocation_frame, "plugin_id")?;
    let plugin_instance_id = required_json_string(invocation_frame, "plugin_instance_id")?;
    let active_fingerprint = required_json_string(invocation_frame, "active_fingerprint")?;
    let runtime_instance_id = required_json_string(invocation_frame, "runtime_instance_id")?;
    let policy_revision = required_json_number(invocation_frame, "policy_revision")?;
    let management_revision = required_json_number(invocation_frame, "management_revision")?;
    let revoke_epoch = required_json_number(invocation_frame, "revoke_epoch")?;
    let body_base64 = redevplugin_ipc::extract_json_string(invocation_frame, "network_body_base64")
        .unwrap_or_default();
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_id,
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
        max_chunk_bytes: 0,
        max_buffered_bytes: 0,
        timeout_ms: 1000,
        stream_id: String::new(),
        stream_method: String::new(),
        stream_effect: String::new(),
        stream_execution: String::new(),
        surface_instance_id: String::new(),
        owner_session_hash: String::new(),
        owner_user_hash: String::new(),
        session_channel_id_hash: String::new(),
        bridge_channel_id: String::new(),
        content_type: String::new(),
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
    use std::sync::OnceLock;

    fn runtime_lease_fixture_public_keys() -> &'static [redevplugin_ipc::RuntimeLeasePublicKey] {
        static KEYS: OnceLock<Vec<redevplugin_ipc::RuntimeLeasePublicKey>> = OnceLock::new();
        KEYS.get_or_init(|| {
            let public_key: [u8; 32] =
                decode_base64("IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=")
                    .expect("fixture public key base64")
                    .try_into()
                    .expect("fixture public key length");
            vec![redevplugin_ipc::RuntimeLeasePublicKey {
                key_id: "host_ephemeral_fixture_v1".to_string(),
                public_key,
            }]
        })
    }

    fn signed_worker_invocation_fixture() -> &'static str {
        include_str!("../../../testdata/contracts/runtime-lease-signature-v1-invocation.json")
    }

    fn worker_invocation_state<'a>(
        revocations: &'a RuntimeRevocations,
        lease_replays: &'a mut RuntimeLeaseReplayCache,
        resources: &'a mut RuntimeResourceRegistry,
        control: &'a ControlChannelState,
    ) -> WorkerInvocationState<'a> {
        WorkerInvocationState {
            revocations,
            lease_replays,
            resources,
            control,
            runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
            now_unix_ms: 1_783_161_901_000,
        }
    }

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
    fn runtime_lease_replay_cache_rejects_repeated_lease() {
        let mut cache = RuntimeLeaseReplayCache::default();
        let frame = worker_invocation_frame("plugini_1", 1);
        cache
            .consume_invocation_frame(&frame, 1_000)
            .expect("first lease use should pass");
        let err = cache
            .consume_invocation_frame(&frame, 1_000)
            .expect_err("replayed lease should fail");
        assert_eq!(err.code(), redevplugin_ipc::ERR_LEASE_REPLAYED);
    }

    #[test]
    fn runtime_lease_replay_cache_requires_nonce() {
        let mut cache = RuntimeLeaseReplayCache::default();
        let err = cache
            .consume_invocation_frame(
                r#"{"payload":{"lease":{"lease_id":"lease_1","plugin_instance_id":"plugini_1","revoke_epoch":1}}}"#,
                1_000,
            )
            .expect_err("missing lease nonce should fail");
        assert_eq!(err.code(), redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID);
    }

    #[test]
    fn runtime_lease_replay_cache_prunes_expired_entries_before_enforcing_capacity() {
        let mut cache = RuntimeLeaseReplayCache::with_capacity(1);
        cache
            .consume_invocation_frame(
                &worker_invocation_frame_with_lease_expiry(
                    "plugini_1",
                    1,
                    "lease_1",
                    "nonce_1",
                    2_000,
                ),
                1_000,
            )
            .expect("first lease use should pass");
        let full = cache
            .consume_invocation_frame(
                &worker_invocation_frame_with_lease_expiry(
                    "plugini_1",
                    1,
                    "lease_2",
                    "nonce_2",
                    3_000,
                ),
                1_000,
            )
            .expect_err("live replay entries must enforce the hard capacity");
        assert_eq!(full.code(), redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID);
        cache
            .consume_invocation_frame(
                &worker_invocation_frame_with_lease_expiry(
                    "plugini_1",
                    1,
                    "lease_2",
                    "nonce_2",
                    3_000,
                ),
                2_000,
            )
            .expect("expired replay entries should be pruned");
    }

    #[test]
    fn control_channel_state_fails_closed_when_stale_and_recovers_on_refresh() {
        let mut control = ControlChannelState::new();
        control.refresh(Duration::from_millis(1));
        control.force_stale_for_test();
        let err = control
            .validate_fresh()
            .expect_err("stale control channel should fail closed");
        assert_eq!(
            err.code(),
            redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE
        );

        control.refresh(Duration::from_millis(5_000));
        control
            .validate_fresh()
            .expect("fresh heartbeat should restore control freshness");
    }

    #[test]
    fn handle_revoke_epoch_updates_runtime_revocation_state() {
        let mut revocations = RuntimeRevocations::default();
        let mut resources = RuntimeResourceRegistry::default();
        let mut control = ControlChannelState::new();
        control.force_stale_for_test();
        let response = handle_revoke_epoch(
            &mut revocations,
            &mut resources,
            &mut control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":7}}"#,
        );
        assert!(response.contains(r#""frame_type":"revoke_epoch_ack""#));
        assert!(response.contains(r#""ok":true"#));
        assert!(response.contains(r#""plugin_instance_id":"plugini_1""#));
        assert!(response.contains(r#""revoke_epoch":7"#));
        assert!(response.contains(r#""closed_actor_count":0"#));
        assert!(response.contains(r#""closed_socket_count":0"#));
        assert!(response.contains(r#""closed_stream_count":0"#));
        assert!(response.contains(r#""closed_storage_handle_count":0"#));
        let err = revocations
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 6))
            .expect_err("old invocation should be revoked");
        assert_eq!(err.code(), redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED);
        control
            .validate_fresh()
            .expect("valid revoke control frame should refresh control freshness");
    }

    #[test]
    fn handle_revoke_epoch_closes_registered_runtime_resources() {
        let mut revocations = RuntimeRevocations::default();
        let mut resources = RuntimeResourceRegistry::default();
        resources.track_actor(
            "plugini_1",
            "backend",
            "workers/backend.wasm",
            "redevplugin_worker_invoke",
        );
        resources.track_storage_handle("plugini_1", "storage:db", "storage.sqlite");
        resources.track_storage_handle("plugini_1", "storage:db", "storage.sqlite");
        resources.track_socket(&network_execute_request_for_test(
            "plugini_1",
            "http",
            "api",
            "https://api.example.com",
        ));
        resources.track_stream(
            &network_execute_request_for_test(
                "plugini_1",
                "http",
                "api",
                "https://api.example.com",
            ),
            "stream_1",
        );
        resources.track_actor(
            "plugini_2",
            "backend",
            "workers/backend.wasm",
            "redevplugin_worker_invoke",
        );

        let mut control = ControlChannelState::new();
        let response = handle_revoke_epoch(
            &mut revocations,
            &mut resources,
            &mut control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":7}}"#,
        );

        assert!(response.contains(r#""ok":true"#));
        assert!(response.contains(r#""closed_actor_count":1"#));
        assert!(response.contains(r#""closed_socket_count":1"#));
        assert!(response.contains(r#""closed_stream_count":1"#));
        assert!(response.contains(r#""closed_storage_handle_count":1"#));
        assert_eq!(resources.actors.len(), 1);
        assert!(resources.sockets.is_empty());
        assert!(resources.streams.is_empty());
        assert!(resources.storage_handles.is_empty());

        let second = handle_revoke_epoch(
            &mut revocations,
            &mut resources,
            &mut control,
            "r2",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"revoke_epoch","request_id":"r2","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":8}}"#,
        );
        assert!(second.contains(r#""closed_actor_count":0"#));
        assert!(second.contains(r#""closed_socket_count":0"#));
        assert!(second.contains(r#""closed_stream_count":0"#));
        assert!(second.contains(r#""closed_storage_handle_count":0"#));
    }

    #[test]
    fn successful_storage_request_registers_runtime_storage_handle() {
        let mut resources = RuntimeResourceRegistry::default();
        let mut input = std::io::Cursor::new(
            br#"{"ipc_version":"rust-ipc-v1","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/from-memory.txt","size_bytes":34}}"#
                .iter()
                .copied()
                .chain(std::iter::once(b'\n'))
                .collect::<Vec<u8>>(),
        );
        let mut output = Vec::<u8>::new();

        let result = perform_storage_file_request(
            &mut input,
            &mut output,
            "r1",
            "g1",
            &broker_invocation_frame("plugini_1"),
            r#"{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8="}"#,
            &mut resources,
        )
        .expect("storage request should succeed");

        assert!(result.contains(r#""path":"notes/from-memory.txt""#));
        let request = String::from_utf8(output).expect("storage request utf8");
        assert!(
            request.contains(r#""frame_type":"storage_file""#),
            "{request}"
        );
        let closed = resources.revoke_plugin("plugini_1");
        assert_eq!(closed.storage_handle, 1);
        assert_eq!(closed.actor, 0);
        assert_eq!(closed.socket, 0);
        assert_eq!(closed.stream, 0);
    }

    #[test]
    fn successful_network_stream_request_registers_socket_and_stream() {
        let mut resources = RuntimeResourceRegistry::default();
        let mut input = std::io::Cursor::new(
            br#"{"ipc_version":"rust-ipc-v1","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":true,"connector_id":"api","transport":"http","status_code":200,"stream_id":"stream_1"}}"#
                .iter()
                .copied()
                .chain(std::iter::once(b'\n'))
                .collect::<Vec<u8>>(),
        );
        let mut output = Vec::<u8>::new();

        let result = perform_network_execute_request(
            &mut input,
            &mut output,
            "r1",
            "g1",
            &broker_invocation_frame("plugini_1"),
            r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"GET","path":"/v1/stream","max_chunk_bytes":1024,"max_buffered_bytes":4096}"#,
            &mut resources,
        )
        .expect("network stream request should succeed");

        assert!(result.contains(r#""stream_id":"stream_1""#));
        let request = String::from_utf8(output).expect("network request utf8");
        assert!(
            request.contains(r#""frame_type":"network_execute""#),
            "{request}"
        );
        assert!(request.contains(r#""stream_id":"stream_1""#), "{request}");
        let closed = resources.revoke_plugin("plugini_1");
        assert_eq!(closed.socket, 1);
        assert_eq!(closed.stream, 1);
        assert_eq!(closed.actor, 0);
        assert_eq!(closed.storage_handle, 0);
    }

    #[test]
    fn handle_heartbeat_returns_structured_ack() {
        let mut control = ControlChannelState::new();
        control.force_stale_for_test();
        let response = handle_heartbeat(
            &mut control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100,"max_staleness_ms":5000}}"#,
        );
        assert!(response.contains(r#""frame_type":"heartbeat""#));
        assert!(response.contains(r#""ok":true"#));
        assert!(response.contains(r#""runtime_generation_id":"g1""#));
        assert!(response.contains(r#""max_staleness_ms":5000"#));
        assert!(response.contains(r#""host_sent_unix_nano":100"#));
        control
            .validate_fresh()
            .expect("valid heartbeat should refresh control freshness");
    }

    #[test]
    fn handle_heartbeat_fails_closed_for_invalid_frame() {
        let mut control = ControlChannelState::new();
        let response = handle_heartbeat(
            &mut control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v1","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100}}"#,
        );
        assert!(response.contains(r#""frame_type":"heartbeat""#));
        assert!(response.contains(r#""ok":false"#));
    }

    #[test]
    fn handle_revoke_epoch_fails_closed_for_invalid_frame() {
        let mut revocations = RuntimeRevocations::default();
        let mut resources = RuntimeResourceRegistry::default();
        let mut control = ControlChannelState::new();
        let response = handle_revoke_epoch(
            &mut revocations,
            &mut resources,
            &mut control,
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
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
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
    fn worker_invocation_rejects_stale_control_before_opening_artifact() {
        let revocations = RuntimeRevocations::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let mut control = ControlChannelState::new();
        control.force_stale_for_test();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        assert!(
            output.is_empty(),
            "stale control channel must not request an artifact"
        );
        assert!(response.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(response.contains(r#""ok":false"#));
        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE));
    }

    #[test]
    fn worker_invocation_rejects_unsigned_lease_before_opening_artifact_when_keys_configured() {
        let revocations = RuntimeRevocations::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let runtime_lease_public_keys = vec![redevplugin_ipc::RuntimeLeasePublicKey {
            key_id: "host_ephemeral_key_1".to_string(),
            public_key: [7u8; 32],
        }];
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut WorkerInvocationState {
                revocations: &revocations,
                lease_replays: &mut lease_replays,
                resources: &mut resources,
                control: &control,
                runtime_lease_public_keys: &runtime_lease_public_keys,
                now_unix_ms: 1_783_161_901_000,
            },
            "r1",
            "g1",
            &worker_invocation_frame("plugini_1", 1),
        )
        .expect("worker invocation response");

        assert!(
            output.is_empty(),
            "unsigned lease must not request an artifact when runtime keys are configured"
        );
        assert!(response.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(response.contains(r#""ok":false"#));
        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_SIGNATURE_INVALID));
    }

    #[test]
    fn worker_invocation_rejects_expired_lease_before_opening_artifact() {
        let revocations = RuntimeRevocations::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let mut state =
            worker_invocation_state(&revocations, &mut lease_replays, &mut resources, &control);
        state.now_unix_ms = 1_783_161_930_000;

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut state,
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        assert!(
            output.is_empty(),
            "expired lease must not request an artifact"
        );
        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID));
    }

    #[test]
    fn worker_invocation_rejects_execution_binding_mismatch_before_opening_artifact() {
        let revocations = RuntimeRevocations::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let (prefix, invocation) = signed_worker_invocation_fixture()
            .split_once("\"invocation\":{")
            .expect("signed invocation object");
        let invocation = invocation.replacen(
            "\"operation_id\":\"operation_fixture_v1\"",
            "\"operation_id\":\"operation_other\"",
            1,
        );
        let frame = format!("{prefix}\"invocation\":{{{invocation}");

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
            "r1",
            "g1",
            &frame,
        )
        .expect("worker invocation response");

        assert!(
            output.is_empty(),
            "mismatched execution binding must not request an artifact"
        );
        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID));
    }

    #[test]
    fn worker_invocation_allows_current_epoch_to_open_artifact() {
        let mut revocations = RuntimeRevocations::default();
        revocations.revoke_plugin("plugini_fixture_v1", 5);
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
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
    fn worker_invocation_rejects_replayed_lease_before_opening_artifact() {
        let revocations = RuntimeRevocations::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut resources = RuntimeResourceRegistry::default();
        let control = ControlChannelState::new();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let frame = signed_worker_invocation_fixture().to_string();

        let first = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
            "r1",
            "g1",
            &frame,
        )
        .expect("first worker invocation response");
        assert!(
            !output.is_empty(),
            "first invocation should request an artifact"
        );
        assert!(first.contains(redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED));

        let mut replay_input = std::io::Cursor::new(Vec::<u8>::new());
        let mut replay_output = Vec::<u8>::new();
        let replay = handle_worker_invocation(
            &mut replay_input,
            &mut replay_output,
            &mut worker_invocation_state(
                &revocations,
                &mut lease_replays,
                &mut resources,
                &control,
            ),
            "r2",
            "g1",
            &frame,
        )
        .expect("replayed worker invocation response");

        assert!(
            replay_output.is_empty(),
            "replayed invocation must not request an artifact"
        );
        assert!(replay.contains(r#""frame_type":"invoke_worker_result""#));
        assert!(replay.contains(r#""ok":false"#));
        assert!(replay.contains(redevplugin_ipc::ERR_LEASE_REPLAYED));
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
    fn stale_control_rejects_memory_hostcall_before_broker_dispatch() {
        let module = storage_memory_hostcall_worker_wasm("redevplugin_worker_invoke");
        let mut control = ControlChannelState::new();
        control.force_stale_for_test();
        let mut broker_called = false;
        let execution = execute_worker_module(&module, "redevplugin_worker_invoke", |request| {
            control.validate_fresh().map_err(|err| err.to_string())?;
            broker_called = true;
            unexpected_hostcall(request)
        })
        .expect("stale control still produces a worker execution result");

        assert!(execution.storage_file_requested);
        assert!(
            !broker_called,
            "stale control channel must stop new broker IO before dispatch"
        );
        let err = execution
            .storage_file_result
            .expect("storage hostcall result")
            .expect_err("stale control should reject the hostcall");
        assert_eq!(
            worker_hostcall_error_code(err.as_str()),
            redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE
        );
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
    fn network_execute_request_inherits_stream_audience_from_invocation() {
        let invocation = r#"{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"POST","path":"/v1/stream","max_chunk_bytes":4,"max_buffered_bytes":65536,"content_type":"text/plain"}"#;
        let got = network_execute_request(invocation, "g1", request)
            .expect("stream network execute request");

        assert_eq!(got.plugin_id, "com.example.worker");
        assert_eq!(got.operation, "http_stream");
        assert_eq!(got.stream_id, "stream_host_1");
        assert_eq!(got.stream_method, "worker.echo");
        assert_eq!(got.stream_effect, "read");
        assert_eq!(got.stream_execution, "subscription");
        assert_eq!(got.surface_instance_id, "surface_1");
        assert_eq!(got.owner_session_hash, "session_hash");
        assert_eq!(got.owner_user_hash, "user_hash");
        assert_eq!(got.session_channel_id_hash, "channel_hash");
        assert_eq!(got.bridge_channel_id, "bridge_1");
        assert_eq!(got.max_chunk_bytes, 4);
        assert_eq!(got.max_buffered_bytes, 65536);
        assert_eq!(got.content_type, "text/plain");
    }

    #[test]
    fn network_execute_request_rejects_plugin_owned_audience_overrides() {
        let invocation = r#"{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        for field in [
            "stream_method",
            "stream_effect",
            "stream_execution",
            "surface_instance_id",
            "owner_session_hash",
            "owner_user_hash",
            "session_channel_id_hash",
            "bridge_channel_id",
        ] {
            let request = format!(
                r#"{{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","{field}":"plugin-selected"}}"#
            );
            let err = network_execute_request(invocation, "g1", &request)
                .expect_err("plugin-owned audience override must fail closed");
            assert!(
                err.contains("host-owned invocation field"),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn network_execute_request_rejects_plugin_selected_stream_id() {
        let invocation = r#"{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","stream_id":"stream_plugin_selected"}"#;

        let err = network_execute_request(invocation, "g1", request)
            .expect_err("plugin-selected stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
    }

    #[test]
    fn network_execute_request_rejects_missing_host_owned_stream_id() {
        let invocation = r#"{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream"}"#;

        let err = network_execute_request(invocation, "g1", request)
            .expect_err("missing Host stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
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
        worker_invocation_frame_with_lease(plugin_instance_id, revoke_epoch, "lease_1", "nonce_1")
    }

    fn broker_invocation_frame(plugin_instance_id: &str) -> String {
        format!(
            r#"{{"plugin_id":"com.example.worker","plugin_instance_id":"{plugin_instance_id}","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":1,"revoke_epoch":1,"storage_handle_grant_token":"handle_grant.secret","method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}"#
        )
    }

    fn worker_invocation_frame_with_lease(
        plugin_instance_id: &str,
        revoke_epoch: u64,
        lease_id: &str,
        lease_nonce: &str,
    ) -> String {
        worker_invocation_frame_with_lease_expiry(
            plugin_instance_id,
            revoke_epoch,
            lease_id,
            lease_nonce,
            10_000,
        )
    }

    fn worker_invocation_frame_with_lease_expiry(
        plugin_instance_id: &str,
        revoke_epoch: u64,
        lease_id: &str,
        lease_nonce: &str,
        expires_at_unix_ms: i64,
    ) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v1","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{"lease_id":"{lease_id}","lease_token":"token_1","lease_nonce":"{lease_nonce}","runtime_generation_id":"g1","plugin_instance_id":"{plugin_instance_id}","revoke_epoch":{revoke_epoch},"expires_at_unix_ms":{expires_at_unix_ms}}},"method":"worker.echo","invocation":{{"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worker_id":"backend","method":"worker.echo","export":"redevplugin_worker_invoke"}}}}}}"#
        )
    }

    fn network_execute_request_for_test(
        plugin_instance_id: &str,
        transport: &str,
        connector_id: &str,
        destination: &str,
    ) -> redevplugin_ipc::NetworkExecuteRequest {
        redevplugin_ipc::NetworkExecuteRequest {
            plugin_id: "com.example.worker".to_string(),
            plugin_instance_id: plugin_instance_id.to_string(),
            active_fingerprint: "sha256:active".to_string(),
            runtime_instance_id: "runtime_1".to_string(),
            runtime_generation_id: "g1".to_string(),
            runtime_shard_id: String::new(),
            policy_revision: 1,
            management_revision: 1,
            revoke_epoch: 1,
            connector_id: connector_id.to_string(),
            transport: transport.to_string(),
            destination: destination.to_string(),
            ttl_ms: 30_000,
            operation: "http_stream".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers_json: "{}".to_string(),
            message_type: String::new(),
            body_base64: String::new(),
            payload_base64: String::new(),
            max_request_bytes: 1024,
            max_response_bytes: 4096,
            max_chunk_bytes: 1024,
            max_buffered_bytes: 4096,
            timeout_ms: 1000,
            stream_id: String::new(),
            stream_method: "worker.echo".to_string(),
            stream_effect: "read".to_string(),
            stream_execution: "subscription".to_string(),
            surface_instance_id: "surface_1".to_string(),
            owner_session_hash: "session_hash".to_string(),
            owner_user_hash: "user_hash".to_string(),
            session_channel_id_hash: "channel_hash".to_string(),
            bridge_channel_id: "bridge_1".to_string(),
            content_type: "text/plain".to_string(),
        }
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
