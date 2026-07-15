use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmi::{AsContext, AsContextMut, Config, StoreLimits, StoreLimitsBuilder};

const DEFAULT_WASM_WORKER_FUEL: u64 = 5_000_000;
const MAX_WASM_WORKER_REQUEST_BYTES: usize = 256 * 1024;
const MAX_WASM_WORKER_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_WASM_HOSTCALL_REQUEST_BYTES: usize = 64 * 1024;
const MAX_WASM_HOSTCALL_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_WASM_TABLE_ELEMENTS: usize = 65_536;
const MAX_IPC_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
const MAX_BROKER_RESPONSE_FRAME_BYTES: usize = 1024 * 1024;
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
    let mut line = read_bounded_line(&mut reader, MAX_IPC_FRAME_BYTES, "hello frame")?;
    if line.is_empty() {
        return Err("hello frame is empty".to_string());
    }
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

    let shared = Arc::new(RuntimeSharedState::default());
    start_control_channel(Arc::clone(&shared), runtime_generation_id.clone())?;
    let mut lease_replays = RuntimeLeaseReplayCache::default();
    let clock = current_unix_millis;
    loop {
        line = read_bounded_line(&mut reader, MAX_IPC_FRAME_BYTES, "ipc frame")?;
        if line.is_empty() {
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
                &mut WorkerInvocationState {
                    shared: &shared,
                    lease_replays: &mut lease_replays,
                    runtime_lease_public_keys: &runtime_lease_public_keys,
                    clock: &clock,
                },
                &request_id,
                &runtime_generation_id,
                &line,
            )?,
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

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(max_bytes)
        .map_err(|_| format!("{label} size limit exceeds this runtime"))?
        .saturating_add(1);
    let read = reader
        .take(limit)
        .read_until(b'\n', &mut bytes)
        .map_err(|err| format!("read {label}: {err}"))?;
    if read == 0 {
        return Ok(String::new());
    }
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} must be UTF-8"))
}

fn start_control_channel(
    shared: Arc<RuntimeSharedState>,
    runtime_generation_id: String,
) -> Result<(), String> {
    let read_file = inherited_control_file("REDEVPLUGIN_CONTROL_READ_FD")?;
    let write_file = inherited_control_file("REDEVPLUGIN_CONTROL_WRITE_FD")?;
    thread::Builder::new()
        .name("redevplugin-control".to_string())
        .spawn(move || {
            if let Err(err) =
                run_control_channel(read_file, write_file, &shared, &runtime_generation_id)
            {
                eprintln!("redevplugin-runtime control error: {err}");
                std::process::exit(1);
            }
        })
        .map_err(|err| format!("start runtime control channel: {err}"))?;
    Ok(())
}

fn inherited_control_file(variable: &str) -> Result<File, String> {
    let raw = std::env::var(variable).map_err(|_| format!("{variable} is required"))?;
    let fd: RawFd = raw
        .parse()
        .map_err(|_| format!("{variable} must be a file descriptor"))?;
    if fd < 3 {
        return Err(format!("{variable} must be an inherited file descriptor"));
    }
    // The Go supervisor transfers ownership of each dedicated control descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn run_control_channel(
    read_file: File,
    mut write_file: File,
    shared: &RuntimeSharedState,
    runtime_generation_id: &str,
) -> Result<(), String> {
    let mut reader = io::BufReader::new(read_file);
    loop {
        let line = read_bounded_line(&mut reader, MAX_CONTROL_FRAME_BYTES, "control frame")?;
        if line.is_empty() {
            return Ok(());
        }
        let (frame_type, request_id, frame_generation_id) =
            redevplugin_ipc::parse_frame_identity(&line).map_err(|err| err.to_string())?;
        if frame_generation_id != runtime_generation_id {
            return Err("control runtime_generation_id mismatch".to_string());
        }
        let response = match frame_type.as_str() {
            redevplugin_ipc::FRAME_TYPE_HEARTBEAT => {
                handle_heartbeat(&shared.control, &request_id, runtime_generation_id, &line)
            }
            redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH => {
                handle_revoke_epoch(shared, &request_id, runtime_generation_id, &line)
            }
            _ => redevplugin_ipc::response_frame(
                "diagnostic",
                &request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_UNSUPPORTED_FRAME),
                Some("runtime control frame type is not supported"),
            ),
        };
        write_file
            .write_all(response.as_bytes())
            .and_then(|_| write_file.write_all(b"\n"))
            .and_then(|_| write_file.flush())
            .map_err(|err| format!("write control response: {err}"))?;
    }
}

fn handle_heartbeat(
    control: &ControlChannelState,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> String {
    let request = match redevplugin_ipc::parse_heartbeat_request(line) {
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
    let max_staleness_ms = match request.max_staleness_ms {
        value if value > 0 => value,
        _ => {
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
        request.sent_unix_nano,
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
    timing: Mutex<ControlChannelTiming>,
}

#[derive(Debug)]
struct ControlChannelTiming {
    last_refresh: Instant,
    max_staleness: Duration,
}

impl ControlChannelState {
    fn new() -> Self {
        Self {
            timing: Mutex::new(ControlChannelTiming {
                last_refresh: Instant::now(),
                max_staleness: DEFAULT_CONTROL_MAX_STALENESS,
            }),
        }
    }

    fn refresh(&self, max_staleness: Duration) {
        let mut timing = self.timing.lock().expect("control timing mutex poisoned");
        timing.max_staleness = max_staleness.max(Duration::from_millis(1));
        timing.last_refresh = Instant::now();
    }

    fn refresh_without_staleness_change(&self) {
        self.timing
            .lock()
            .expect("control timing mutex poisoned")
            .last_refresh = Instant::now();
    }

    fn validate_fresh(&self) -> Result<(), RuntimeControlError> {
        let timing = self.timing.lock().expect("control timing mutex poisoned");
        let elapsed = timing.last_refresh.elapsed();
        let max_staleness = timing.max_staleness;
        if elapsed > max_staleness {
            return Err(RuntimeControlError::Stale {
                elapsed_ms: duration_millis_u64(elapsed),
                max_staleness_ms: duration_millis_u64(max_staleness),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn force_stale_for_test(&self) {
        let mut timing = self.timing.lock().expect("control timing mutex poisoned");
        let stale_by = timing.max_staleness + Duration::from_millis(1);
        timing.last_refresh = Instant::now()
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

struct RuntimeSharedState {
    revocations: Mutex<RuntimeRevocations>,
    control: ControlChannelState,
}

impl Default for RuntimeSharedState {
    fn default() -> Self {
        Self {
            revocations: Mutex::new(RuntimeRevocations::default()),
            control: ControlChannelState::new(),
        }
    }
}

impl RuntimeSharedState {
    fn validate_invocation_frame(&self, frame: &str) -> Result<(), RuntimeRevocationError> {
        self.revocations
            .lock()
            .expect("runtime revocation mutex poisoned")
            .validate_invocation_frame(frame)
    }

    fn validate_hostcall(&self, frame: &str, now_unix_ms: i64) -> Result<(), String> {
        self.control
            .validate_fresh()
            .map_err(|err| format!("{}: {err}", err.code()))?;
        self.validate_invocation_frame(frame)
            .map_err(|err| format!("{}: {err}", err.code()))?;
        redevplugin_ipc::validate_worker_runtime_lease(frame, now_unix_ms)
            .map_err(|err| format!("{}: {err}", redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID))
    }
}

struct WorkerInvocationState<'a> {
    shared: &'a RuntimeSharedState,
    lease_replays: &'a mut RuntimeLeaseReplayCache,
    runtime_lease_public_keys: &'a [redevplugin_ipc::RuntimeLeasePublicKey],
    clock: &'a dyn Fn() -> Result<i64, String>,
}

impl WorkerInvocationState<'_> {
    fn now_unix_ms(&self) -> Result<i64, String> {
        (self.clock)()
    }
}

fn handle_worker_invocation<R: BufRead, W: Write>(
    reader: &mut R,
    stdout: &mut W,
    state: &mut WorkerInvocationState<'_>,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> Result<String, String> {
    if let Err(err) = state.shared.control.validate_fresh() {
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
    if let Err(err) = state.shared.validate_invocation_frame(line) {
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
    let invocation_now_unix_ms = match state.now_unix_ms() {
        Ok(value) => value,
        Err(err) => {
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
    };
    if let Err(err) = redevplugin_ipc::validate_worker_runtime_lease(line, invocation_now_unix_ms) {
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
        .consume_invocation_frame(line, invocation_now_unix_ms)
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
    if let Err(err) = state.shared.control.validate_fresh() {
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

    let artifact_response = read_bounded_line(reader, MAX_IPC_FRAME_BYTES, "open_handle response")?;
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
    let post_artifact_now_unix_ms = match state.now_unix_ms() {
        Ok(value) => value,
        Err(err) => {
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
    };
    if let Err(err) =
        redevplugin_ipc::validate_worker_runtime_lease(line, post_artifact_now_unix_ms)
    {
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
    if let Err(err) = state.shared.control.validate_fresh() {
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
    let worker_request = match redevplugin_ipc::worker_request_json_v2(line) {
        Ok(request) => request,
        Err(err) => {
            return Ok(redevplugin_ipc::response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                false,
                None,
                Some(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID),
                Some(err.as_str()),
            ));
        }
    };
    let memory_limit_bytes = match redevplugin_ipc::runtime_lease_memory_limit_bytes(line) {
        Ok(value) => value,
        Err(err) => {
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
    };
    let shared = state.shared;
    let clock = state.clock;
    let execution = match execute_worker_module_v2(
        &wasm_bytes,
        &identity.export,
        worker_request.as_bytes(),
        memory_limit_bytes,
        |request| match request {
            WorkerHostcallRequest::StorageFile(request_json) => {
                shared.validate_hostcall(line, clock()?)?;
                perform_storage_file_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                )
            }
            WorkerHostcallRequest::StorageKV(request_json) => {
                shared.validate_hostcall(line, clock()?)?;
                perform_storage_kv_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                )
            }
            WorkerHostcallRequest::StorageSQLite(request_json) => {
                shared.validate_hostcall(line, clock()?)?;
                perform_storage_sqlite_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                )
            }
            WorkerHostcallRequest::NetworkExecute(request_json) => {
                shared.validate_hostcall(line, clock()?)?;
                perform_network_execute_request(
                    reader,
                    stdout,
                    request_id,
                    runtime_generation_id,
                    line,
                    &request_json,
                )
            }
        },
    ) {
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
    let completion_now_unix_ms = match state.now_unix_ms() {
        Ok(value) => value,
        Err(err) => {
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
    };
    if let Err(err) = redevplugin_ipc::validate_worker_runtime_lease(line, completion_now_unix_ms) {
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
    if let Err(err) = state.shared.control.validate_fresh() {
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
    if let Err(err) = state.shared.validate_invocation_frame(line) {
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
    match redevplugin_ipc::parse_worker_response_v2(&execution.response_json) {
        Ok(redevplugin_ipc::WorkerResponseV2::Success(data)) => {
            let result = format!("{{\"data\":{data}}}");
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
        Ok(redevplugin_ipc::WorkerResponseV2::Failure { code, message }) => {
            let error_origin = trusted_worker_error_origin(&execution, &code, &message);
            Ok(redevplugin_ipc::response_error_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ResponseError {
                    code: code.as_str(),
                    message: message.as_str(),
                    origin: error_origin,
                },
            ))
        }
        Err(err) => Ok(redevplugin_ipc::response_frame(
            redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
            request_id,
            runtime_generation_id,
            false,
            None,
            Some(redevplugin_ipc::ERR_WASM_WORKER_INVALID),
            Some(err.as_str()),
        )),
    }
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
        let invocation = redevplugin_ipc::parse_worker_invocation_context(frame)
            .map_err(|_| RuntimeRevocationError::InvalidInvocation)?;
        let plugin_instance_id = invocation.plugin_instance_id;
        let invocation_epoch = invocation.revoke_epoch;
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
    shared: &RuntimeSharedState,
    request_id: &str,
    runtime_generation_id: &str,
    line: &str,
) -> String {
    let request = match redevplugin_ipc::parse_revoke_epoch_request(line) {
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
    shared
        .revocations
        .lock()
        .expect("runtime revocation mutex poisoned")
        .revoke_plugin(&request.plugin_instance_id, request.revoke_epoch);
    shared.control.refresh_without_staleness_change();
    let result_json = redevplugin_ipc::revoke_epoch_ack_result_json(
        &request.plugin_instance_id,
        request.revoke_epoch,
        0,
        0,
        0,
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
struct WorkerExecutionV2 {
    response_json: String,
    hostcall_failures: Vec<TrustedWorkerFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedWorkerFailure {
    code: String,
    message: String,
}

enum WorkerHostcallRequest {
    StorageFile(String),
    StorageKV(String),
    StorageSQLite(String),
    NetworkExecute(String),
}

type WorkerBrokerHostcall<'a> = dyn FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a;

struct WorkerHostState<'a> {
    broker_hostcall: Box<WorkerBrokerHostcall<'a>>,
    limits: StoreLimits,
    hostcall_failures: Vec<TrustedWorkerFailure>,
}

impl<'a> WorkerHostState<'a> {
    fn new(
        broker_hostcall: impl FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a,
        memory_limit_bytes: usize,
    ) -> Self {
        Self {
            broker_hostcall: Box::new(broker_hostcall),
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_limit_bytes)
                .table_elements(MAX_WASM_TABLE_ELEMENTS)
                .instances(1)
                .memories(1)
                .tables(1)
                .trap_on_grow_failure(true)
                .build(),
            hostcall_failures: Vec::new(),
        }
    }
}

fn execute_worker_module_v2<'a>(
    wasm_bytes: &[u8],
    export_name: &str,
    request_json: &[u8],
    memory_limit_bytes: usize,
    broker_hostcall: impl FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a,
) -> Result<WorkerExecutionV2, String> {
    if request_json.is_empty() || request_json.len() > MAX_WASM_WORKER_REQUEST_BYTES {
        return Err("worker request exceeds the ABI v2 size limit".to_string());
    }
    if memory_limit_bytes == 0 {
        return Err("worker memory limit must be positive".to_string());
    }
    redevplugin_wasm_abi::validate_worker_module(wasm_bytes, export_name)?;
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = wasmi::Engine::new(&config);
    let module = wasmi::Module::new(&engine, wasm_bytes)
        .map_err(|err| format!("compile wasm worker module: {err}"))?;
    let mut linker = <wasmi::Linker<WorkerHostState<'a>>>::new(&engine);
    define_v2_worker_hostcalls(&mut linker)?;
    let mut store = wasmi::Store::new(
        &engine,
        WorkerHostState::new(broker_hostcall, memory_limit_bytes),
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(DEFAULT_WASM_WORKER_FUEL)
        .map_err(|err| format!("configure wasm worker fuel: {err}"))?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|err| format!("instantiate wasm worker module: {err}"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "ABI v2 worker must export memory".to_string())?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "redevplugin_worker_alloc")
        .map_err(|err| format!("resolve ABI v2 worker allocator: {err}"))?;
    let dealloc = instance
        .get_typed_func::<(i32, i32), ()>(&store, "redevplugin_worker_dealloc")
        .map_err(|err| format!("resolve ABI v2 worker deallocator: {err}"))?;
    let invoke = instance
        .get_typed_func::<(i32, i32), i64>(&store, export_name)
        .map_err(|err| format!("resolve ABI v2 worker export {export_name:?}: {err}"))?;

    let request_len = i32::try_from(request_json.len())
        .map_err(|_| "worker request length exceeds i32".to_string())?;
    let request_ptr = alloc
        .call(&mut store, request_len)
        .map_err(|err| format!("allocate ABI v2 worker request: {err}"))?;
    let request_offset = usize::try_from(request_ptr)
        .map_err(|_| "ABI v2 worker allocator returned a negative pointer".to_string())?;
    memory
        .write(store.as_context_mut(), request_offset, request_json)
        .map_err(|err| format!("write ABI v2 worker request memory: {err}"))?;

    let packed = match invoke.call(&mut store, (request_ptr, request_len)) {
        Ok(value) => value as u64,
        Err(err) => {
            let _ = dealloc.call(&mut store, (request_ptr, request_len));
            return Err(format!(
                "execute ABI v2 worker export {export_name:?}: {err}"
            ));
        }
    };
    let _ = dealloc.call(&mut store, (request_ptr, request_len));

    let response_ptr_u32 = u32::try_from(packed >> 32)
        .map_err(|_| "ABI v2 worker response pointer exceeds u32".to_string())?;
    let response_len_u32 = u32::try_from(packed & 0xffff_ffff)
        .map_err(|_| "ABI v2 worker response length exceeds u32".to_string())?;
    let response_ptr = i32::try_from(response_ptr_u32)
        .map_err(|_| "ABI v2 worker response pointer exceeds i32".to_string())?;
    let response_len = i32::try_from(response_len_u32)
        .map_err(|_| "ABI v2 worker response length exceeds i32".to_string())?;
    let response_size = usize::try_from(response_len)
        .map_err(|_| "ABI v2 worker response length is negative".to_string())?;
    if response_size == 0 || response_size > MAX_WASM_WORKER_RESPONSE_BYTES {
        return Err("ABI v2 worker response exceeds the size limit".to_string());
    }
    let response_offset = usize::try_from(response_ptr)
        .map_err(|_| "ABI v2 worker response pointer is negative".to_string())?;
    let mut response = vec![0_u8; response_size];
    let read_result = memory.read(store.as_context(), response_offset, &mut response);
    let _ = dealloc.call(&mut store, (response_ptr, response_len));
    read_result.map_err(|err| format!("read ABI v2 worker response memory: {err}"))?;
    let response_json = String::from_utf8(response)
        .map_err(|_| "ABI v2 worker response must be UTF-8 JSON".to_string())?;

    let hostcall_failures = store.data().hostcall_failures.clone();
    Ok(WorkerExecutionV2 {
        response_json,
        hostcall_failures,
    })
}

fn trusted_worker_error_origin(
    execution: &WorkerExecutionV2,
    code: &str,
    message: &str,
) -> &'static str {
    if execution
        .hostcall_failures
        .iter()
        .any(|failure| failure.code == code && failure.message == message)
    {
        redevplugin_ipc::ERROR_ORIGIN_HOSTCALL
    } else {
        redevplugin_ipc::ERROR_ORIGIN_PLUGIN
    }
}

fn define_v2_worker_hostcalls<'a>(
    linker: &mut wasmi::Linker<WorkerHostState<'a>>,
) -> Result<(), String> {
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
        .map_err(|err| format!("define storage files hostcall import: {err}"))?;
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
        .map_err(|err| format!("define storage kv hostcall import: {err}"))?;
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
        .map_err(|err| format!("define storage sqlite hostcall import: {err}"))?;
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
        .map_err(|err| format!("define network execute hostcall import: {err}"))?;
    Ok(())
}

fn worker_hostcall_error_json(error: &str) -> String {
    let error = error.trim();
    let (candidate, message) = error
        .split_once(": ")
        .map(|(code, message)| (code.trim(), message.trim()))
        .unwrap_or(("HOSTCALL_FAILED", error));
    let code = if stable_worker_error_code(candidate) {
        candidate
    } else {
        "HOSTCALL_FAILED"
    };
    let message = if message.is_empty() {
        "hostcall failed"
    } else {
        message
    };
    serde_json::json!({
        "ok": false,
        "error_code": code,
        "message": message,
    })
    .to_string()
}

fn record_hostcall_response(caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>, response: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(response) else {
        return;
    };
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(false) {
        return;
    }
    let code = value
        .get("error_code")
        .or_else(|| value.get("code"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| stable_worker_error_code(value))
        .unwrap_or("HOSTCALL_FAILED");
    let message = value
        .get("message")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("hostcall failed");
    let failures = &mut caller.data_mut().hostcall_failures;
    if failures.len() < 64
        && !failures
            .iter()
            .any(|failure| failure.code == code && failure.message == message)
    {
        failures.push(TrustedWorkerFailure {
            code: code.to_string(),
            message: message.to_string(),
        });
    }
}

fn record_hostcall_abi_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    let message = format!("hostcall failed with ABI code {code}");
    let failures = &mut caller.data_mut().hostcall_failures;
    if failures.len() < 64
        && !failures
            .iter()
            .any(|failure| failure.code == "HOSTCALL_FAILED" && failure.message == message)
    {
        failures.push(TrustedWorkerFailure {
            code: "HOSTCALL_FAILED".to_string(),
            message,
        });
    }
    code
}

fn stable_worker_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn perform_storage_file_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
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
    if request_len == 0
        || request_len > MAX_WASM_HOSTCALL_REQUEST_BYTES
        || response_len == 0
        || response_len > MAX_WASM_HOSTCALL_RESPONSE_BYTES
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
    let response_json = response_json.unwrap_or_else(|err| worker_hostcall_error_json(&err));
    record_hostcall_response(caller, &response_json);
    let response = response_json.as_bytes();
    if response.len() > response_len {
        return record_storage_hostcall_error(caller, -7);
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_hostcall_error(caller, -8);
    }
    match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => record_storage_hostcall_error(caller, -9),
    }
}

fn record_storage_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    record_hostcall_abi_error(caller, code)
}

fn perform_storage_kv_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
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
    if request_len == 0
        || request_len > MAX_WASM_HOSTCALL_REQUEST_BYTES
        || response_len == 0
        || response_len > MAX_WASM_HOSTCALL_RESPONSE_BYTES
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
    let response_json = response_json.unwrap_or_else(|err| worker_hostcall_error_json(&err));
    record_hostcall_response(caller, &response_json);
    let response = response_json.as_bytes();
    if response.len() > response_len {
        return record_storage_kv_hostcall_error(caller, -7);
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_kv_hostcall_error(caller, -8);
    }
    match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => record_storage_kv_hostcall_error(caller, -9),
    }
}

fn record_storage_kv_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    record_hostcall_abi_error(caller, code)
}

fn perform_storage_sqlite_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
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
    if request_len == 0
        || request_len > MAX_WASM_HOSTCALL_REQUEST_BYTES
        || response_len == 0
        || response_len > MAX_WASM_HOSTCALL_RESPONSE_BYTES
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
    let response_json = response_json.unwrap_or_else(|err| worker_hostcall_error_json(&err));
    record_hostcall_response(caller, &response_json);
    let response = response_json.as_bytes();
    if response.len() > response_len {
        return record_storage_sqlite_hostcall_error(caller, -7);
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_storage_sqlite_hostcall_error(caller, -8);
    }
    match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => record_storage_sqlite_hostcall_error(caller, -9),
    }
}

fn record_storage_sqlite_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    record_hostcall_abi_error(caller, code)
}

fn perform_network_execute_request_hostcall(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_len: i32,
) -> i32 {
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
    if request_len == 0
        || request_len > MAX_WASM_HOSTCALL_REQUEST_BYTES
        || response_len == 0
        || response_len > MAX_WASM_HOSTCALL_RESPONSE_BYTES
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
    let response_json = response_json.unwrap_or_else(|err| worker_hostcall_error_json(&err));
    record_hostcall_response(caller, &response_json);
    let response = response_json.as_bytes();
    if response.len() > response_len {
        return record_network_hostcall_error(caller, -7);
    }
    if memory
        .write(caller.as_context_mut(), response_ptr, response)
        .is_err()
    {
        return record_network_hostcall_error(caller, -8);
    }
    match i32::try_from(response.len()) {
        Ok(value) => value,
        Err(_) => record_network_hostcall_error(caller, -9),
    }
}

fn record_network_hostcall_error(
    caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>,
    code: i32,
) -> i32 {
    record_hostcall_abi_error(caller, code)
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
    redevplugin_ipc::validate_worker_storage_broker_access(
        invocation_frame,
        &req.store_id,
        &req.operation,
    )?;
    dispatch_storage_file_request(reader, stdout, request_id, runtime_generation_id, &req)
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
    redevplugin_ipc::validate_worker_storage_broker_access(
        invocation_frame,
        &req.store_id,
        &req.operation,
    )?;
    dispatch_storage_kv_request(reader, stdout, request_id, runtime_generation_id, &req)
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
    redevplugin_ipc::validate_worker_storage_broker_access(
        invocation_frame,
        &req.store_id,
        &req.operation,
    )?;
    dispatch_storage_sqlite_request(reader, stdout, request_id, runtime_generation_id, &req)
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
    let response = read_bounded_line(
        reader,
        MAX_BROKER_RESPONSE_FRAME_BYTES,
        "storage_file response",
    )?;
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
    let response = read_bounded_line(
        reader,
        MAX_BROKER_RESPONSE_FRAME_BYTES,
        "storage_kv response",
    )?;
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
    let response = read_bounded_line(
        reader,
        MAX_BROKER_RESPONSE_FRAME_BYTES,
        "storage_sqlite response",
    )?;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageFileHostcallRequest {
    operation: String,
    store_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    data_base64: String,
    max_bytes: Option<u64>,
    max_entries: Option<u64>,
    recursive: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageKVHostcallRequest {
    operation: String,
    store_id: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    value_base64: String,
    #[serde(default)]
    prefix: String,
    max_bytes: Option<u64>,
    max_entries: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageSQLiteHostcallRequest {
    operation: String,
    store_id: String,
    #[serde(default)]
    database: String,
    sql: String,
    #[serde(default)]
    args: Vec<serde_json::Value>,
    max_rows: Option<u64>,
    max_response_bytes: Option<u64>,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkExecuteHostcallRequest {
    connector_id: String,
    transport: String,
    destination: String,
    operation: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    headers: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    message_type: String,
    #[serde(default)]
    body_base64: String,
    #[serde(default)]
    payload_base64: String,
    ttl_ms: Option<u64>,
    max_request_bytes: Option<u64>,
    max_response_bytes: Option<u64>,
    max_chunk_bytes: Option<u64>,
    max_buffered_bytes: Option<u64>,
    timeout_ms: Option<u64>,
    stream_id: Option<String>,
    stream_method: Option<String>,
    stream_effect: Option<String>,
    stream_execution: Option<String>,
    surface_instance_id: Option<String>,
    owner_session_hash: Option<String>,
    owner_user_hash: Option<String>,
    session_channel_id_hash: Option<String>,
    bridge_channel_id: Option<String>,
    #[serde(default)]
    content_type: String,
}

fn decode_hostcall_request<T: for<'de> Deserialize<'de>>(
    input: &str,
    label: &str,
) -> Result<T, String> {
    serde_json::from_str(input).map_err(|err| format!("decode {label}: {err}"))
}

fn require_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("missing {field}"))
    } else {
        Ok(())
    }
}

fn storage_file_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageFileRequest, String> {
    let request: StorageFileHostcallRequest =
        decode_hostcall_request(request_json, "storage file hostcall request")?;
    require_non_empty(&request.operation, "operation")?;
    require_non_empty(&request.store_id, "store_id")?;
    if request.operation != "list" {
        require_non_empty(&request.path, "path")?;
    }
    let invocation = redevplugin_ipc::parse_worker_invocation_context(invocation_frame)?;
    let store_id = request.store_id;
    let handle_grant_token =
        redevplugin_ipc::worker_storage_handle_grant(invocation_frame, &store_id)?;
    Ok(redevplugin_ipc::StorageFileRequest {
        handle_grant_token,
        plugin_instance_id: invocation.plugin_instance_id,
        active_fingerprint: invocation.active_fingerprint,
        runtime_instance_id: invocation.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.files".to_string(),
        policy_revision: invocation.policy_revision,
        management_revision: invocation.management_revision,
        revoke_epoch: invocation.revoke_epoch,
        operation: request.operation,
        store_id,
        path: request.path,
        data_base64: request.data_base64,
        max_bytes: request.max_bytes.unwrap_or(0),
        max_entries: request.max_entries.unwrap_or(0),
        recursive: request.recursive.unwrap_or(false),
    })
}

fn storage_kv_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageKVRequest, String> {
    let request: StorageKVHostcallRequest =
        decode_hostcall_request(request_json, "storage KV hostcall request")?;
    require_non_empty(&request.operation, "operation")?;
    require_non_empty(&request.store_id, "store_id")?;
    if request.operation != "list" {
        require_non_empty(&request.key, "key")?;
    }
    let invocation = redevplugin_ipc::parse_worker_invocation_context(invocation_frame)?;
    let store_id = request.store_id;
    let handle_grant_token =
        redevplugin_ipc::worker_storage_handle_grant(invocation_frame, &store_id)?;
    Ok(redevplugin_ipc::StorageKVRequest {
        handle_grant_token,
        plugin_instance_id: invocation.plugin_instance_id,
        active_fingerprint: invocation.active_fingerprint,
        runtime_instance_id: invocation.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.kv".to_string(),
        policy_revision: invocation.policy_revision,
        management_revision: invocation.management_revision,
        revoke_epoch: invocation.revoke_epoch,
        operation: request.operation,
        store_id,
        key: request.key,
        value_base64: request.value_base64,
        prefix: request.prefix,
        max_bytes: request.max_bytes.unwrap_or(0),
        max_entries: request.max_entries.unwrap_or(0),
    })
}

fn storage_sqlite_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageSQLiteRequest, String> {
    let request: StorageSQLiteHostcallRequest =
        decode_hostcall_request(request_json, "storage SQLite hostcall request")?;
    require_non_empty(&request.operation, "operation")?;
    require_non_empty(&request.store_id, "store_id")?;
    require_non_empty(&request.sql, "sql")?;
    let invocation = redevplugin_ipc::parse_worker_invocation_context(invocation_frame)?;
    let store_id = request.store_id;
    let handle_grant_token =
        redevplugin_ipc::worker_storage_handle_grant(invocation_frame, &store_id)?;
    Ok(redevplugin_ipc::StorageSQLiteRequest {
        handle_grant_token,
        plugin_instance_id: invocation.plugin_instance_id,
        active_fingerprint: invocation.active_fingerprint,
        runtime_instance_id: invocation.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        handle_id: format!("storage:{store_id}"),
        method: "storage.sqlite".to_string(),
        policy_revision: invocation.policy_revision,
        management_revision: invocation.management_revision,
        revoke_epoch: invocation.revoke_epoch,
        operation: request.operation,
        store_id,
        database: request.database,
        sql: request.sql,
        args_json: serde_json::to_string(&request.args)
            .map_err(|err| format!("encode storage SQLite args: {err}"))?,
        max_rows: request.max_rows.unwrap_or(0),
        max_response_bytes: request.max_response_bytes.unwrap_or(0),
        timeout_ms: request.timeout_ms.unwrap_or(0),
    })
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
    redevplugin_ipc::validate_worker_network_broker_access(
        invocation_frame,
        &req.connector_id,
        &req.transport,
        &req.operation,
        &req.method,
    )?;
    let network_request_id = format!("{request_id}:network_execute");
    let frame =
        redevplugin_ipc::network_execute_frame(&network_request_id, runtime_generation_id, &req);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write network_execute request: {err}"))?;
    let response = read_bounded_line(
        reader,
        MAX_BROKER_RESPONSE_FRAME_BYTES,
        "network_execute response",
    )?;
    if response.is_empty() {
        return Err("network_execute response is empty".to_string());
    }
    redevplugin_ipc::validate_network_execute_response(
        &response,
        &network_request_id,
        runtime_generation_id,
        &req.connector_id,
        &req.transport,
    )?;
    redevplugin_ipc::network_execute_payload_json(&response)
}

fn network_execute_request(
    invocation_frame: &str,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::NetworkExecuteRequest, String> {
    let request: NetworkExecuteHostcallRequest =
        decode_hostcall_request(request_json, "network execute hostcall request")?;
    require_non_empty(&request.connector_id, "connector_id")?;
    require_non_empty(&request.transport, "transport")?;
    require_non_empty(&request.destination, "destination")?;
    require_non_empty(&request.operation, "operation")?;
    for (field, value) in [
        ("stream_method", request.stream_method.as_ref()),
        ("stream_effect", request.stream_effect.as_ref()),
        ("stream_execution", request.stream_execution.as_ref()),
        ("surface_instance_id", request.surface_instance_id.as_ref()),
        ("owner_session_hash", request.owner_session_hash.as_ref()),
        ("owner_user_hash", request.owner_user_hash.as_ref()),
        (
            "session_channel_id_hash",
            request.session_channel_id_hash.as_ref(),
        ),
        ("bridge_channel_id", request.bridge_channel_id.as_ref()),
    ] {
        if value.is_some() {
            return Err(format!(
                "network request must not set host-owned invocation field {field}"
            ));
        }
    }
    if request.stream_id.is_some() {
        return Err("network request must not set the host-owned stream_id".to_string());
    }
    let invocation = redevplugin_ipc::parse_worker_invocation_context(invocation_frame)?;
    let stream_id = if request.operation == "http_stream" {
        if invocation.stream_id.is_empty() {
            return Err("http_stream invocation is missing the host-owned stream_id".to_string());
        }
        invocation.stream_id.clone()
    } else {
        String::new()
    };
    let query_json = serde_json::to_string(&request.query)
        .map_err(|err| format!("encode network query: {err}"))?;
    let headers_json = serde_json::to_string(&request.headers)
        .map_err(|err| format!("encode network headers: {err}"))?;
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_id: invocation.plugin_id,
        plugin_instance_id: invocation.plugin_instance_id,
        active_fingerprint: invocation.active_fingerprint,
        runtime_instance_id: invocation.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: String::new(),
        policy_revision: invocation.policy_revision,
        management_revision: invocation.management_revision,
        revoke_epoch: invocation.revoke_epoch,
        connector_id: request.connector_id,
        transport: request.transport,
        destination: request.destination,
        ttl_ms: request.ttl_ms.unwrap_or(30_000),
        operation: request.operation,
        method: if request.method.trim().is_empty() {
            "GET".to_string()
        } else {
            request.method
        },
        path: if request.path.trim().is_empty() {
            "/".to_string()
        } else {
            request.path
        },
        query_json,
        headers_json,
        message_type: request.message_type,
        body_base64: request.body_base64,
        payload_base64: request.payload_base64,
        max_request_bytes: request.max_request_bytes.unwrap_or(64 * 1024),
        max_response_bytes: request.max_response_bytes.unwrap_or(256 * 1024),
        max_chunk_bytes: request.max_chunk_bytes.unwrap_or(32 * 1024),
        max_buffered_bytes: request.max_buffered_bytes.unwrap_or(1024 * 1024),
        timeout_ms: request.timeout_ms.unwrap_or(5_000),
        stream_id,
        stream_method: invocation.method,
        stream_effect: invocation.effect,
        stream_execution: invocation.execution,
        surface_instance_id: invocation.surface_instance_id,
        owner_session_hash: invocation.owner_session_hash,
        owner_user_hash: invocation.owner_user_hash,
        session_channel_id_hash: invocation.session_channel_id_hash,
        bridge_channel_id: invocation.bridge_channel_id,
        content_type: request.content_type,
    })
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
    use std::cell::Cell;
    use std::sync::OnceLock;

    const TEST_WORKER_MEMORY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

    fn runtime_lease_fixture_public_keys() -> &'static [redevplugin_ipc::RuntimeLeasePublicKey] {
        static KEYS: OnceLock<Vec<redevplugin_ipc::RuntimeLeasePublicKey>> = OnceLock::new();
        KEYS.get_or_init(|| {
            let public_key: [u8; 32] =
                decode_base64("6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=")
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
        shared: &'a RuntimeSharedState,
        lease_replays: &'a mut RuntimeLeaseReplayCache,
    ) -> WorkerInvocationState<'a> {
        WorkerInvocationState {
            shared,
            lease_replays,
            runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
            clock: &fixed_runtime_lease_clock,
        }
    }

    fn fixed_runtime_lease_clock() -> Result<i64, String> {
        Ok(1_783_161_901_000)
    }

    fn expired_runtime_lease_clock() -> Result<i64, String> {
        Ok(1_783_161_930_000)
    }

    fn sqlite_usage_fixture() -> serde_json::Value {
        serde_json::json!({
            "plugin_instance_id": "plugini_test",
            "store_id": "memos",
            "usage_bytes": 256,
            "quota_bytes": 1_048_576,
            "usage_files": 1,
            "quota_files": 1_000
        })
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
    fn bounded_line_reader_rejects_oversized_frames() {
        let mut reader = std::io::Cursor::new(b"123456789\n".to_vec());
        let err = read_bounded_line(&mut reader, 8, "test frame")
            .expect_err("oversized frame must fail closed");
        assert!(err.contains("exceeds 8 bytes"), "{err}");
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
        let control = ControlChannelState::new();
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
    fn revoked_invocation_cannot_reach_host_io() {
        let shared = RuntimeSharedState::default();
        shared
            .revocations
            .lock()
            .expect("runtime revocation mutex")
            .revoke_plugin("plugini_1", 2);
        let frame = worker_invocation_frame("plugini_1", 1);
        let mut host_io_calls = 0;
        let result = shared.validate_hostcall(&frame, 1_000).map(|()| {
            host_io_calls += 1;
        });

        let error = result.expect_err("revoked hostcall must fail before host io");
        assert!(error.contains(redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED));
        assert_eq!(host_io_calls, 0);
    }

    #[test]
    fn expired_invocation_cannot_reach_host_io() {
        let shared = RuntimeSharedState::default();
        let frame =
            worker_invocation_frame_with_lease_expiry("plugini_1", 1, "lease_1", "nonce_1", 2_000);
        let mut host_io_calls = 0;
        let result = shared.validate_hostcall(&frame, 2_000).map(|()| {
            host_io_calls += 1;
        });

        let error = result.expect_err("expired hostcall must fail before host io");
        assert!(error.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID));
        assert_eq!(host_io_calls, 0);
    }

    #[test]
    fn handle_revoke_epoch_updates_runtime_revocation_state() {
        let shared = RuntimeSharedState::default();
        shared.control.force_stale_for_test();
        let response = handle_revoke_epoch(
            &shared,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v2","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":7}}"#,
        );
        assert!(response.contains(r#""frame_type":"revoke_epoch_ack""#));
        assert!(response.contains(r#""ok":true"#));
        assert!(response.contains(r#""plugin_instance_id":"plugini_1""#));
        assert!(response.contains(r#""revoke_epoch":7"#));
        assert!(response.contains(r#""closed_socket_count":0"#));
        assert!(response.contains(r#""closed_stream_count":0"#));
        assert!(response.contains(r#""closed_storage_handle_count":0"#));
        let err = shared
            .revocations
            .lock()
            .expect("runtime revocation mutex")
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 6))
            .expect_err("old invocation should be revoked");
        assert_eq!(err.code(), redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED);
        shared
            .control
            .validate_fresh()
            .expect("valid revoke control frame should refresh control freshness");
    }

    #[test]
    fn successful_storage_request_round_trips_without_runtime_resource_tracking() {
        let mut input = std::io::Cursor::new(
            br#"{"ipc_version":"rust-ipc-v2","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/from-memory.txt","size_bytes":34}}"#
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
        )
        .expect("storage request should succeed");

        assert!(result.contains(r#""path":"notes/from-memory.txt""#));
        let request = String::from_utf8(output).expect("storage request utf8");
        assert!(
            request.contains(r#""frame_type":"storage_file""#),
            "{request}"
        );
    }

    #[test]
    fn method_scoped_storage_denial_happens_before_host_io() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let invocation = broker_invocation_frame("plugini_1")
            .replace(r#"["read","write","delete","list"]"#, r#"["read"]"#);

        let err = perform_storage_file_request(
            &mut input,
            &mut output,
            "r1",
            "g1",
            &invocation,
            r#"{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8="}"#,
        )
        .expect_err("write access must be denied");

        assert!(err.contains("not allowed"), "{err}");
        assert!(output.is_empty(), "denied storage access reached Host I/O");
    }

    #[test]
    fn successful_network_stream_request_round_trips_without_runtime_resource_tracking() {
        let mut input = std::io::Cursor::new(
            br#"{"ipc_version":"rust-ipc-v2","frame_type":"network_execute","request_id":"r1:network_execute","runtime_generation_id":"g1","payload":{"ok":true,"connector_id":"api","transport":"http","status_code":200,"stream_id":"stream_1"}}"#
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
        )
        .expect("network stream request should succeed");

        assert!(result.contains(r#""stream_id":"stream_1""#));
        let request = String::from_utf8(output).expect("network request utf8");
        assert!(
            request.contains(r#""frame_type":"network_execute""#),
            "{request}"
        );
        assert!(request.contains(r#""stream_id":"stream_1""#), "{request}");
    }

    #[test]
    fn method_scoped_http_denial_happens_before_host_io() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let err = perform_network_execute_request(
            &mut input,
            &mut output,
            "r1",
            "g1",
            &broker_invocation_frame("plugini_1"),
            r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"DELETE","path":"/v1/items/1"}"#,
        )
        .expect_err("DELETE access must be denied");

        assert!(err.contains("not allowed"), "{err}");
        assert!(output.is_empty(), "denied network access reached Host I/O");
    }

    #[test]
    fn handle_heartbeat_returns_structured_ack() {
        let control = ControlChannelState::new();
        control.force_stale_for_test();
        let response = handle_heartbeat(
            &control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v2","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100,"max_staleness_ms":5000}}"#,
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
        let control = ControlChannelState::new();
        let response = handle_heartbeat(
            &control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v2","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100}}"#,
        );
        assert!(response.contains(r#""frame_type":"heartbeat""#));
        assert!(response.contains(r#""ok":false"#));
    }

    #[test]
    fn handle_revoke_epoch_fails_closed_for_invalid_frame() {
        let shared = RuntimeSharedState::default();
        let response = handle_revoke_epoch(
            &shared,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v2","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1"}}"#,
        );
        assert!(response.contains(r#""frame_type":"revoke_epoch_ack""#));
        assert!(response.contains(r#""ok":false"#));
        assert!(response.contains(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID));
        shared
            .revocations
            .lock()
            .expect("runtime revocation mutex")
            .validate_invocation_frame(&worker_invocation_frame("plugini_1", 0))
            .expect("invalid revoke frame must not create a revocation record");
    }

    #[test]
    fn worker_invocation_rejects_stale_epoch_before_opening_artifact() {
        let shared = RuntimeSharedState::default();
        shared
            .revocations
            .lock()
            .expect("runtime revocation mutex")
            .revoke_plugin("plugini_1", 5);
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(&shared, &mut lease_replays),
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
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        shared.control.force_stale_for_test();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(&shared, &mut lease_replays),
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
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
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
                shared: &shared,
                lease_replays: &mut lease_replays,
                runtime_lease_public_keys: &runtime_lease_public_keys,
                clock: &fixed_runtime_lease_clock,
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
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let mut state = WorkerInvocationState {
            shared: &shared,
            lease_replays: &mut lease_replays,
            runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
            clock: &expired_runtime_lease_clock,
        };

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
    fn worker_invocation_revalidates_lease_before_returning_success() {
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let clock_calls = Cell::new(0_u32);
        let clock = || {
            let call = clock_calls.get();
            clock_calls.set(call + 1);
            if call < 2 {
                Ok(1_783_161_901_000)
            } else {
                Ok(1_783_161_930_000)
            }
        };
        let response_json = r#"{"ok":true,"data":{"value":"done"}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) {response_json:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const {}))"#,
            ((2048_u64) << 32) | response_json.len() as u64,
        ))
        .expect("compile lease expiry worker");
        let artifact_response = format!(
            "{{\"ipc_version\":\"rust-ipc-v2\",\"frame_type\":\"open_handle\",\"request_id\":\"r1:artifact\",\"runtime_generation_id\":\"g1\",\"payload\":{{\"ok\":true,\"package_hash\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"artifact\":\"workers/backend.wasm\",\"sha256\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"content_base64\":\"{}\"}}}}\n",
            encode_base64_for_test(&module),
        );
        let mut input = std::io::Cursor::new(artifact_response.into_bytes());
        let mut output = Vec::<u8>::new();
        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut WorkerInvocationState {
                shared: &shared,
                lease_replays: &mut lease_replays,
                runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
                clock: &clock,
            },
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID));
        assert!(!response.contains(r#""ok":true"#));
        assert!(clock_calls.get() >= 3);
    }

    #[test]
    fn worker_invocation_revalidates_revocation_before_returning_success() {
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let clock_calls = Cell::new(0_u32);
        let clock = || {
            let call = clock_calls.get();
            clock_calls.set(call + 1);
            if call == 2 {
                shared
                    .revocations
                    .lock()
                    .expect("runtime revocation mutex")
                    .revoke_plugin("plugini_fixture_v1", 14);
            }
            Ok(1_783_161_901_000)
        };
        let artifact_response = successful_worker_artifact_response();
        let mut input = std::io::Cursor::new(artifact_response.into_bytes());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut WorkerInvocationState {
                shared: &shared,
                lease_replays: &mut lease_replays,
                runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
                clock: &clock,
            },
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED));
        assert!(!response.contains(r#""ok":true"#));
        assert!(clock_calls.get() >= 3);
    }

    #[test]
    fn worker_invocation_revalidates_control_freshness_before_returning_success() {
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let clock_calls = Cell::new(0_u32);
        let clock = || {
            let call = clock_calls.get();
            clock_calls.set(call + 1);
            if call == 2 {
                shared.control.force_stale_for_test();
            }
            Ok(1_783_161_901_000)
        };
        let artifact_response = successful_worker_artifact_response();
        let mut input = std::io::Cursor::new(artifact_response.into_bytes());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut WorkerInvocationState {
                shared: &shared,
                lease_replays: &mut lease_replays,
                runtime_lease_public_keys: runtime_lease_fixture_public_keys(),
                clock: &clock,
            },
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE));
        assert!(!response.contains(r#""ok":true"#));
        assert!(clock_calls.get() >= 3);
    }

    #[test]
    fn worker_invocation_rejects_execution_binding_mismatch_before_opening_artifact() {
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let (prefix, invocation) = signed_worker_invocation_fixture()
            .split_once("\"invocation\": {")
            .expect("signed invocation object");
        let invocation = invocation.replacen(
            "\"operation_id\": \"operation_fixture_v1\"",
            "\"operation_id\": \"operation_other\"",
            1,
        );
        let frame = format!("{prefix}\"invocation\":{{{invocation}");

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(&shared, &mut lease_replays),
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
        let shared = RuntimeSharedState::default();
        shared
            .revocations
            .lock()
            .expect("runtime revocation mutex")
            .revoke_plugin("plugini_fixture_v1", 5);
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();

        let response = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(&shared, &mut lease_replays),
            "r1",
            "g1",
            signed_worker_invocation_fixture(),
        )
        .expect("worker invocation response");

        let output = String::from_utf8(output).expect("artifact request utf8");
        assert!(
            output.contains(r#""frame_type":"open_handle""#),
            "current invocation should request the bound worker artifact: output={output} response={response}"
        );
        assert!(response.contains(redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED));
    }

    #[test]
    fn worker_invocation_rejects_replayed_lease_before_opening_artifact() {
        let shared = RuntimeSharedState::default();
        let mut lease_replays = RuntimeLeaseReplayCache::default();
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let frame = signed_worker_invocation_fixture().to_string();

        let first = handle_worker_invocation(
            &mut input,
            &mut output,
            &mut worker_invocation_state(&shared, &mut lease_replays),
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
            &mut worker_invocation_state(&shared, &mut lease_replays),
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
    fn executes_v2_worker_with_dynamic_request_and_response() {
        let request = br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.save","params":{}}"#;
        let response = r#"{"ok":true,"data":{"saved":true,"title":"Launch notes"}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param $len i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param $ptr i32) (param $len i32) (result i64)
                    local.get $len
                    i32.const {}
                    i32.ne
                    if
                        unreachable
                    end
                    i64.const {})
            )"#,
            request.len(),
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile v2 worker fixture");

        let execution = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            request,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            unexpected_hostcall,
        )
        .expect("v2 worker executes");

        assert_eq!(execution.response_json, response);
    }

    #[test]
    fn executes_compiled_example_worker_with_portable_dispatch() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let execution = execute_worker_module_v2(
            module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"memos.list","params":{"query":""}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |request| match request {
                WorkerHostcallRequest::StorageSQLite(request_json) => {
                    if request_json.contains(r#""operation":"query""#) {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","columns":["id","title","body","pinned","created_at","updated_at"],"rows":[],"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":0,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    } else {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","rows_affected":0,"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":0,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    }
                }
                request => unexpected_hostcall(request),
            },
        )
        .expect("compiled example worker executes with portable dispatch");
        assert_eq!(
            execution.response_json,
            r#"{"ok":true,"data":{"has_more":false,"notes":[],"offset":0,"total":0}}"#
        );
    }

    #[test]
    fn executes_compiled_example_worker_save_with_portable_dispatch() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let mut hostcall_count = 0;
        let execution = execute_worker_module_v2(
            module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"memos.save","params":{"id":"","title":"Smoke memo","body":"Stored through SQLite","pinned":true}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |request| match request {
                WorkerHostcallRequest::StorageSQLite(request_json) => {
                    hostcall_count += 1;
                    if request_json.contains(r#""operation":"query""#) {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","columns":["id","title","body","pinned","created_at","updated_at"],"rows":[[{"text":"note_0123456789abcdef"},{"text":"Smoke memo"},{"text":"Stored through SQLite"},{"int":1},{"text":"2026-07-14T00:00:00Z"},{"text":"2026-07-14T00:00:00Z"}]],"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":256,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    } else {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","rows_affected":1,"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":256,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    }
                }
                request => unexpected_hostcall(request),
            },
        )
        .expect("compiled example worker save executes with portable dispatch");

        assert_eq!(hostcall_count, 2);
        let redevplugin_ipc::WorkerResponseV2::Success(data) =
            redevplugin_ipc::parse_worker_response_v2(&execution.response_json)
                .expect("valid worker response")
        else {
            panic!("save must return a successful worker response");
        };
        assert!(data.contains(r#""id":"note_0123456789abcdef""#), "{data}");
        assert!(data.contains(r#""pinned":true"#), "{data}");
    }

    #[test]
    fn compiled_memos_worker_pages_across_sixty_one_pinned_notes() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let execute_page = |offset: usize| {
            let request = format!(
                r#"{{"schema_version":"redevplugin.worker_request.v2","method":"memos.list","params":{{"query":"","offset":{offset},"limit":24,"pinned_only":true}}}}"#
            );
            execute_worker_module_v2(
                module,
                "redevplugin_worker_invoke",
                request.as_bytes(),
                TEST_WORKER_MEMORY_LIMIT_BYTES,
                |hostcall| {
                    let WorkerHostcallRequest::StorageSQLite(request_json) = hostcall else {
                        return Err("unexpected non-SQLite memos hostcall".to_string());
                    };
                    let request: serde_json::Value = serde_json::from_str(&request_json)
                        .map_err(|err| format!("decode memos SQLite request: {err}"))?;
                    let sql = request["sql"]
                        .as_str()
                        .ok_or_else(|| "memos SQLite request omitted sql".to_string())?;
                    if sql.starts_with("SELECT count(*)") {
                        return Ok(serde_json::json!({
                            "ok": true,
                            "database": "memos.sqlite",
                            "columns": ["count(*)"],
                            "rows": [[{"int": 61}]],
                            "usage": sqlite_usage_fixture()
                        })
                        .to_string());
                    }
                    if !sql.contains("WHERE pinned = 1") || !sql.contains("LIMIT ? OFFSET ?") {
                        return Err(format!("unexpected memos page query: {sql}"));
                    }
                    let request_offset = request["args"]
                        .as_array()
                        .and_then(|args| args.last())
                        .and_then(|value| value["int"].as_u64())
                        .ok_or_else(|| "memos page query omitted offset".to_string())?
                        as usize;
                    let page_len = if request_offset < 48 { 24 } else { 13 };
                    let rows = (0..page_len)
                        .map(|index| {
                            let absolute = request_offset + index;
                            serde_json::json!([
                                {"text": format!("note_{absolute:04}")},
                                {"text": format!("Pinned memo {}", absolute + 1)},
                                {"text": "A bounded summary"},
                                {"int": 1},
                                {"text": "2026-07-14T00:00:00Z"},
                                {"text": "2026-07-14T00:00:00Z"}
                            ])
                        })
                        .collect::<Vec<_>>();
                    Ok(serde_json::json!({
                        "ok": true,
                        "database": "memos.sqlite",
                        "columns": ["id", "title", "body", "pinned", "created_at", "updated_at"],
                        "rows": rows,
                        "usage": sqlite_usage_fixture()
                    })
                    .to_string())
                },
            )
            .expect("compiled memos page executes")
        };

        let first: serde_json::Value =
            serde_json::from_str(&execute_page(0).response_json).expect("decode first memos page");
        assert_eq!(first["data"]["notes"].as_array().map(Vec::len), Some(24));
        assert_eq!(first["data"]["has_more"], true);
        assert_eq!(first["data"]["total"], 61);

        let second: serde_json::Value = serde_json::from_str(&execute_page(24).response_json)
            .expect("decode second memos page");
        assert_eq!(second["data"]["notes"].as_array().map(Vec::len), Some(24));
        assert_eq!(second["data"]["has_more"], true);
        assert_eq!(second["data"]["offset"], 24);

        let third: serde_json::Value =
            serde_json::from_str(&execute_page(48).response_json).expect("decode third memos page");
        assert_eq!(third["data"]["notes"].as_array().map(Vec::len), Some(13));
        assert_eq!(third["data"]["has_more"], false);
        assert_eq!(third["data"]["offset"], 48);
    }

    #[test]
    fn rejects_v2_worker_response_outside_exported_memory() {
        let module = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "redevplugin_worker_alloc") (param i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const 281474976710672)
            )"#,
        )
        .expect("compile invalid v2 worker fixture");

        let error = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            unexpected_hostcall,
        )
        .expect_err("out-of-bounds response must fail closed");

        assert!(error.contains("response memory"), "{error}");
    }

    #[test]
    fn rejects_worker_module_above_signed_memory_limit() {
        let response = r#"{"ok":true,"data":{}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 2)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const {})
            )"#,
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile memory-limited worker fixture");

        let error = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            64 * 1024,
            unexpected_hostcall,
        )
        .expect_err("initial memory above the signed limit must fail closed");

        assert!(
            error.contains("resource limiter") || error.contains("memory"),
            "{error}"
        );
    }

    #[test]
    fn rejects_memory_grow_above_signed_memory_limit() {
        let response = r#"{"ok":true,"data":{}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1 4)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i32.const 1
                    memory.grow
                    drop
                    i64.const {})
            )"#,
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile memory-grow worker fixture");

        let error = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            64 * 1024,
            unexpected_hostcall,
        )
        .expect_err("memory.grow above the signed limit must fail closed");

        assert!(
            error.contains("resource limiter")
                || error.contains("memory")
                || error.contains("grow"),
            "{error}"
        );
    }

    #[test]
    fn rejects_worker_table_above_runtime_limit() {
        let response = r#"{"ok":true,"data":{}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (table 65537 funcref)
                (memory (export "memory") 1)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const {}))"#,
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile table-limited worker fixture");

        let error = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            unexpected_hostcall,
        )
        .expect_err("table above the runtime limit must fail closed");

        assert!(
            error.contains("table") || error.contains("resource limiter"),
            "{error}"
        );
    }

    #[test]
    fn broker_failures_are_encoded_for_worker_error_handling() {
        assert_eq!(
            worker_hostcall_error_json("NETWORK_TARGET_DENIED: destination is private"),
            r#"{"error_code":"NETWORK_TARGET_DENIED","message":"destination is private","ok":false}"#
        );
        assert_eq!(
            worker_hostcall_error_json("transport closed"),
            r#"{"error_code":"HOSTCALL_FAILED","message":"transport closed","ok":false}"#
        );
    }

    #[test]
    fn plugin_cannot_spoof_runtime_or_hostcall_error_origin() {
        let plugin_execution = WorkerExecutionV2 {
            response_json: String::new(),
            hostcall_failures: Vec::new(),
        };
        assert_eq!(
            trusted_worker_error_origin(
                &plugin_execution,
                "RUNTIME_CAPABILITY_REVOKED",
                "runtime capability was revoked",
            ),
            redevplugin_ipc::ERROR_ORIGIN_PLUGIN,
        );
        let hostcall_execution = WorkerExecutionV2 {
            response_json: String::new(),
            hostcall_failures: vec![TrustedWorkerFailure {
                code: "NETWORK_TARGET_DENIED".to_string(),
                message: "destination is private".to_string(),
            }],
        };
        assert_eq!(
            trusted_worker_error_origin(
                &hostcall_execution,
                "NETWORK_TARGET_DENIED",
                "destination is private",
            ),
            redevplugin_ipc::ERROR_ORIGIN_HOSTCALL,
        );
    }

    #[test]
    fn executes_v2_worker_storage_hostcall() {
        let hostcall_request = r#"{"store_id":"notes","operation":"query","database":"notes.sqlite","sql":"SELECT id FROM notes","args":[]}"#;
        let worker_response = r#"{"ok":true,"data":{"notes":[]}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (import "redevplugin.storage" "sqlite" (func $sqlite (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 4096) {hostcall_request:?})
                (data (i32.const 12288) {worker_response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i32.const 4096
                    i32.const {}
                    i32.const 8192
                    i32.const 1024
                    call $sqlite
                    drop
                    i64.const {})
            )"#,
            hostcall_request.len(),
            ((12288_u64) << 32) | worker_response.len() as u64,
        ))
        .expect("compile storage worker fixture");
        let mut called = false;

        let execution = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |request| {
                let WorkerHostcallRequest::StorageSQLite(request) = request else {
                    panic!("expected sqlite hostcall");
                };
                assert_eq!(request, hostcall_request);
                called = true;
                Ok(r#"{"ok":true,"database":"notes.sqlite","rows":[]}"#.to_string())
            },
        )
        .expect("storage worker executes");

        assert!(called);
        assert_eq!(execution.response_json, worker_response);
    }

    #[test]
    fn network_execute_request_inherits_stream_audience_from_invocation() {
        let invocation = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"POST","path":"/v1/stream","query":{"format":["json"],"timezone":["auto"]},"max_chunk_bytes":4,"max_buffered_bytes":65536,"content_type":"text/plain"}"#;
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
        assert_eq!(got.query_json, r#"{"format":["json"],"timezone":["auto"]}"#);
    }

    #[test]
    fn storage_request_uses_host_only_grant_map() {
        let invocation = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1"},"method":"notes.list","invocation":{"plugin_id":"com.example.notes","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"storage_handle_grants":{"notes":"handle_grant.host-only-secret"},"method":"notes.list","effect":"read","execution":"sync"}}}"#;
        let request = r#"{"store_id":"notes","operation":"query","database":"notes.sqlite","sql":"SELECT id FROM notes","args":[]}"#;

        let got = storage_sqlite_request(invocation, "g1", request)
            .expect("storage request with host-only grant map");

        assert_eq!(got.handle_grant_token, "handle_grant.host-only-secret");
        assert_eq!(got.store_id, "notes");
    }

    #[test]
    fn network_execute_request_rejects_plugin_owned_audience_overrides() {
        let invocation = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
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
        let invocation = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","stream_id":"stream_plugin_selected"}"#;

        let err = network_execute_request(invocation, "g1", request)
            .expect_err("plugin-selected stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
    }

    #[test]
    fn network_hostcall_request_rejects_unknown_duplicate_and_trailing_fields() {
        let invocation = broker_invocation_frame("plugini_1");
        let valid = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"GET"}"#;
        network_execute_request(&invocation, "g1", valid).expect("closed network request");

        for invalid in [
            format!("{valid}{{}}"),
            valid.replace(r#""method":"GET""#, r#""method":"GET","unknown":true"#),
            valid.replace(
                r#""connector_id":"api""#,
                r#""connector_id":"api","connector_id":"other""#,
            ),
        ] {
            assert!(
                network_execute_request(&invocation, "g1", &invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn network_execute_request_rejects_missing_host_owned_stream_id() {
        let invocation = r#"{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream"}"#;

        let err = network_execute_request(invocation, "g1", request)
            .expect_err("missing Host stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
    }

    #[test]
    fn rejects_wasm_worker_with_missing_export() {
        let module = minimal_worker_wasm("other_export");
        let err = execute_worker_module_v2(
            &module,
            "redevplugin_worker_invoke",
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"notes.list","params":{}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            unexpected_hostcall,
        )
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

    fn encode_base64_for_test(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            encoded.push(ALPHABET[(first >> 2) as usize] as char);
            encoded.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
            if chunk.len() > 1 {
                encoded.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
            } else {
                encoded.push('=');
            }
            if chunk.len() > 2 {
                encoded.push(ALPHABET[(third & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
        encoded
    }

    fn worker_invocation_frame(plugin_instance_id: &str, revoke_epoch: u64) -> String {
        worker_invocation_frame_with_lease(plugin_instance_id, revoke_epoch, "lease_1", "nonce_1")
    }

    fn broker_invocation_frame(plugin_instance_id: &str) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_id":"com.example.worker","plugin_instance_id":"{plugin_instance_id}","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":1,"revoke_epoch":1,"storage_handle_grants":{{"workspace":"handle_grant.secret"}},"broker_access":{{"storage":[{{"store_id":"workspace","operations":["read","write","delete","list"]}},{{"store_id":"notes","operations":["query","exec"]}}],"network":[{{"connector_id":"api","transport":"http","operations":["http","http_stream"],"http_methods":["GET","POST"]}}]}},"method":"worker.echo","effect":"write","execution":"subscription","stream_id":"stream_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}}}}"#
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

    fn successful_worker_artifact_response() -> String {
        let response_json = r#"{"ok":true,"data":{"value":"done"}}"#;
        let module = wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) {response_json:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const {}))"#,
            ((2048_u64) << 32) | response_json.len() as u64,
        ))
        .expect("compile successful worker");
        format!(
            "{{\"ipc_version\":\"rust-ipc-v2\",\"frame_type\":\"open_handle\",\"request_id\":\"r1:artifact\",\"runtime_generation_id\":\"g1\",\"payload\":{{\"ok\":true,\"package_hash\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"artifact\":\"workers/backend.wasm\",\"sha256\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"content_base64\":\"{}\"}}}}\n",
            encode_base64_for_test(&module),
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
            r#"{{"ipc_version":"rust-ipc-v2","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{"lease_id":"{lease_id}","lease_token":"token_1","lease_nonce":"{lease_nonce}","runtime_generation_id":"g1","plugin_instance_id":"{plugin_instance_id}","revoke_epoch":{revoke_epoch},"expires_at_unix_ms":{expires_at_unix_ms}}},"method":"worker.echo","invocation":{{"plugin_id":"com.example.worker","plugin_instance_id":"{plugin_instance_id}","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":1,"revoke_epoch":{revoke_epoch},"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","worker_id":"backend","worker_mode":"job","worker_scope":"user","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","abi":"redevplugin-wasm-worker-v2","method":"worker.echo","export":"redevplugin_worker_invoke","effect":"read","execution":"sync","audit_correlation_id":"audit_1","params_sha256":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","params":{{}},"broker_access":{{}},"broker_access_sha256":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}}}}}}"#
        )
    }

    fn minimal_worker_wasm(export_name: &str) -> Vec<u8> {
        let response = r#"{"ok":true,"data":{}}"#;
        wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32)
                    i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export {export_name:?}) (param i32 i32) (result i64)
                    i64.const {})
            )"#,
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile minimal ABI v2 worker")
    }
}
