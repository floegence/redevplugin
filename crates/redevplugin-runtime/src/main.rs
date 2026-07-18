mod module_cache;
mod scheduler;

use serde::Deserialize;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::fs::File;
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
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
const WASM_PAGE_BYTES: u64 = 64 * 1024;
const RUNTIME_CONTROL_STALE_MESSAGE_PREFIX: &str = "runtime control channel is stale";
const IPC_WRITER_CAPACITY_OVERHEAD: usize = 8;
const IPC_WRITER_MAX_BATCH_FRAMES: usize = 64;
const IPC_WRITER_MAX_BATCH_BYTES: usize = 256 * 1024;

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
    let hello = redevplugin_ipc::parse_hello_frame(&line).map_err(ipc_contract_error)?;
    let request_id = hello.request_id;
    let runtime_generation_id = hello.runtime_generation_id;
    let channel_nonce = hello.channel_nonce;
    let runtime_lease_public_keys = hello.runtime_lease_public_keys;
    let limits = hello.limits;
    let runtime_version =
        option_env!("REDEVPLUGIN_RUNTIME_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    let actual_target = compiled_runtime_target()?;
    let ack = redevplugin_ipc::hello_ack_frame(
        &request_id,
        &runtime_generation_id,
        &channel_nonce,
        runtime_version,
        &actual_target,
        redevplugin_ipc::WASM_ABI_VERSION,
        limits,
    )
    .map_err(ipc_contract_error)?;
    let (writer, writer_thread) = start_ipc_writer(limits)?;
    send_frame(&writer, ack)?;
    let shared = Arc::new(RuntimeSharedState::default());
    let scheduler = Arc::new(scheduler::InvocationScheduler::new(
        limits.queue_capacity,
        limits.per_plugin_concurrency,
    ));
    let module_cache = Arc::new(module_cache::ModuleCache::new(
        worker_engine(),
        limits.module_cache_entries,
        limits.module_cache_source_bytes,
    ));
    let status = Arc::new(RuntimeStatus {
        limits,
        scheduler: Arc::clone(&scheduler),
        module_cache: Arc::clone(&module_cache),
    });
    start_control_channel(
        Arc::clone(&shared),
        runtime_generation_id.clone(),
        Arc::clone(&status),
    )?;
    let execution = Arc::new(ConcurrentExecutionState {
        shared,
        lease_replays: Mutex::new(RuntimeLeaseReplayCache::default()),
        runtime_lease_public_keys,
        module_cache,
        clock: Arc::new(current_unix_millis),
        writer: writer.clone(),
        runtime_generation_id: runtime_generation_id.clone(),
        pending_artifacts: PendingArtifactRoutes::new(limits.compile_flight_route_capacity()),
        hostcall_routes: OutstandingHostcallRoutes::new(
            limits.hostcall_active_route_capacity(),
            limits
                .hostcall_canceled_route_capacity()
                .map_err(ipc_contract_error)?,
        ),
    });
    let workers = start_invocation_workers(
        limits.worker_count,
        Arc::clone(&scheduler),
        Arc::clone(&execution),
    )?;

    loop {
        line = read_bounded_line(&mut reader, MAX_IPC_FRAME_BYTES, "ipc frame")?;
        if line.is_empty() {
            break;
        }
        let input =
            redevplugin_ipc::decode_runtime_input_frame(&line).map_err(ipc_contract_error)?;
        dispatch_runtime_input(
            input,
            &runtime_generation_id,
            &scheduler,
            &execution,
            &writer,
        )?;
    }
    for job in scheduler.shutdown() {
        send_frame(
            &writer,
            canceled_invocation_frame(&job.request_id, &runtime_generation_id)?,
        )?;
    }
    execution.pending_artifacts.shutdown();
    execution.hostcall_routes.shutdown();
    for worker in workers {
        worker
            .join()
            .map_err(|_| "runtime invocation worker panicked".to_string())?;
    }
    drop(execution);
    drop(status);
    drop(scheduler);
    drop(writer);
    writer_thread
        .join()
        .map_err(|_| "runtime IPC writer panicked".to_string())??;
    Ok(())
}

fn compiled_runtime_target() -> Result<redevplugin_ipc::RuntimeTarget, String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => return Err(format!("unsupported compiled runtime os {other}")),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported compiled runtime arch {other}")),
    };
    redevplugin_ipc::RuntimeTarget::new(os, arch).map_err(ipc_contract_error)
}

fn dispatch_runtime_input(
    input: redevplugin_ipc::RuntimeInputFrame,
    runtime_generation_id: &str,
    scheduler: &scheduler::InvocationScheduler,
    execution: &ConcurrentExecutionState,
    writer: &FrameSender,
) -> Result<(), String> {
    match input {
        redevplugin_ipc::RuntimeInputFrame::InvokeWorker(worker) => {
            if worker.identity.runtime_generation_id != runtime_generation_id {
                return Err("runtime_generation_id mismatch".to_string());
            }
            let request_id = worker.identity.request_id;
            let invocation = match worker.invocation {
                Ok(invocation) => invocation,
                Err(_) => {
                    return send_frame(
                        writer,
                        invocation_error_frame(
                            &request_id,
                            runtime_generation_id,
                            redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                            "invalid worker invocation",
                        )?,
                    );
                }
            };
            match scheduler::InvocationJob::new(invocation) {
                Ok(job) => {
                    if let Err(err) = scheduler.enqueue(job) {
                        let (code, message) = match err {
                            scheduler::EnqueueError::Capacity => (
                                redevplugin_ipc::ERR_RUNTIME_CAPACITY_EXCEEDED,
                                "runtime invocation queue capacity is exceeded",
                            ),
                            scheduler::EnqueueError::PluginCapacity => (
                                redevplugin_ipc::ERR_RUNTIME_CAPACITY_EXCEEDED,
                                "plugin invocation queue capacity is exceeded",
                            ),
                            scheduler::EnqueueError::Duplicate => (
                                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                                "runtime invocation request_id is duplicated",
                            ),
                            scheduler::EnqueueError::Shutdown => (
                                redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED,
                                "runtime is shutting down",
                            ),
                        };
                        send_frame(
                            writer,
                            invocation_error_frame(
                                &request_id,
                                runtime_generation_id,
                                code,
                                message,
                            )?,
                        )?;
                    }
                }
                Err(err) => send_frame(
                    writer,
                    invocation_error_frame(
                        &request_id,
                        runtime_generation_id,
                        redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                        &err,
                    )?,
                )?,
            }
        }
        redevplugin_ipc::RuntimeInputFrame::CancelInvoke(cancel) => {
            if cancel.identity.runtime_generation_id != runtime_generation_id {
                return Err("runtime_generation_id mismatch".to_string());
            }
            let disposition = match scheduler.cancel(&cancel.invocation_request_id) {
                scheduler::CancelDisposition::Queued(job) => {
                    send_frame(
                        writer,
                        canceled_invocation_frame(&job.request_id, runtime_generation_id)?,
                    )?;
                    "queued"
                }
                scheduler::CancelDisposition::Running => {
                    execution
                        .hostcall_routes
                        .cancel_parent(&cancel.invocation_request_id, runtime_generation_id)?;
                    "running"
                }
                scheduler::CancelDisposition::Complete => "complete",
                scheduler::CancelDisposition::Missing => "complete",
            };
            send_frame(
                writer,
                ipc_frame(redevplugin_ipc::cancel_invoke_ack_frame(
                    &cancel.identity.request_id,
                    runtime_generation_id,
                    &cancel.invocation_request_id,
                    disposition,
                ))?,
            )?;
        }
        redevplugin_ipc::RuntimeInputFrame::HostcallResponse(response) => {
            if response.identity.runtime_generation_id != runtime_generation_id {
                return Err("runtime_generation_id mismatch".to_string());
            }
            let parent_request_id = response
                .identity
                .parent_request_id
                .as_deref()
                .ok_or_else(|| "hostcall response is missing parent_request_id".to_string())?;
            if response.identity.frame_type == redevplugin_ipc::FRAME_TYPE_OPEN_HANDLE {
                execution.pending_artifacts.consume(
                    &response.identity.request_id,
                    parent_request_id,
                    runtime_generation_id,
                    response.raw_frame,
                )?;
                return Ok(());
            }
            match execution.hostcall_routes.consume(
                &response.identity.request_id,
                parent_request_id,
                runtime_generation_id,
            )? {
                HostcallRouteDisposition::Deliver => {
                    if !scheduler.signal(
                        parent_request_id,
                        scheduler::InvocationSignal::HostcallResponse(response.raw_frame),
                    ) {
                        return Err("hostcall response parent_request_id is not active".to_string());
                    }
                }
                HostcallRouteDisposition::DiscardCanceled => {}
            }
        }
        redevplugin_ipc::RuntimeInputFrame::Unsupported(identity) => {
            if identity.runtime_generation_id != runtime_generation_id {
                return Err("runtime_generation_id mismatch".to_string());
            }
            send_frame(
                writer,
                runtime_error_frame(
                    "diagnostic",
                    &identity.request_id,
                    runtime_generation_id,
                    redevplugin_ipc::ERR_UNSUPPORTED_FRAME,
                    "runtime frame type is not supported",
                )?,
            )?;
        }
    }
    Ok(())
}

type FrameSender = SyncSender<String>;

struct RuntimeStatus {
    limits: redevplugin_ipc::RuntimeLimits,
    scheduler: Arc<scheduler::InvocationScheduler>,
    module_cache: Arc<module_cache::ModuleCache>,
}

struct ConcurrentExecutionState {
    shared: Arc<RuntimeSharedState>,
    lease_replays: Mutex<RuntimeLeaseReplayCache>,
    runtime_lease_public_keys: Vec<redevplugin_ipc::RuntimeLeasePublicKey>,
    module_cache: Arc<module_cache::ModuleCache>,
    clock: Arc<dyn Fn() -> Result<i64, String> + Send + Sync>,
    writer: FrameSender,
    runtime_generation_id: String,
    pending_artifacts: PendingArtifactRoutes,
    hostcall_routes: OutstandingHostcallRoutes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostcallRouteDisposition {
    Deliver,
    DiscardCanceled,
}

struct OutstandingHostcallRoute {
    parent_request_id: String,
    runtime_generation_id: String,
}

struct OutstandingHostcallRouteState {
    active: HashMap<String, OutstandingHostcallRoute>,
    canceled: HashMap<String, OutstandingHostcallRoute>,
    shutdown: bool,
}

struct OutstandingHostcallRoutes {
    active_capacity: usize,
    canceled_capacity: usize,
    state: Mutex<OutstandingHostcallRouteState>,
}

impl OutstandingHostcallRoutes {
    fn new(active_capacity: usize, canceled_capacity: usize) -> Self {
        assert!(
            active_capacity > 0,
            "active hostcall route capacity must be positive"
        );
        assert!(
            canceled_capacity > 0,
            "canceled hostcall route capacity must be positive"
        );
        Self {
            active_capacity,
            canceled_capacity,
            state: Mutex::new(OutstandingHostcallRouteState {
                active: HashMap::new(),
                canceled: HashMap::new(),
                shutdown: false,
            }),
        }
    }

    fn register(
        &self,
        request_id: &str,
        parent_request_id: &str,
        runtime_generation_id: &str,
    ) -> Result<(), String> {
        if request_id.trim().is_empty()
            || parent_request_id.trim().is_empty()
            || runtime_generation_id.trim().is_empty()
        {
            return Err("hostcall route identity is incomplete".to_string());
        }
        let mut state = self.state.lock().expect("hostcall route mutex poisoned");
        if state.shutdown {
            return Err("runtime is shutting down".to_string());
        }
        if state.active.contains_key(request_id) || state.canceled.contains_key(request_id) {
            return Err("hostcall request_id is already outstanding".to_string());
        }
        if state.active.len() >= self.active_capacity {
            return Err("active hostcall route capacity is exhausted".to_string());
        }
        state.active.insert(
            request_id.to_string(),
            OutstandingHostcallRoute {
                parent_request_id: parent_request_id.to_string(),
                runtime_generation_id: runtime_generation_id.to_string(),
            },
        );
        Ok(())
    }

    fn remove(&self, request_id: &str, parent_request_id: &str, runtime_generation_id: &str) {
        let mut state = self.state.lock().expect("hostcall route mutex poisoned");
        if hostcall_route_identity_matches(
            state.active.get(request_id),
            parent_request_id,
            runtime_generation_id,
        ) {
            state.active.remove(request_id);
        } else if hostcall_route_identity_matches(
            state.canceled.get(request_id),
            parent_request_id,
            runtime_generation_id,
        ) {
            state.canceled.remove(request_id);
        }
    }

    fn cancel_parent(
        &self,
        parent_request_id: &str,
        runtime_generation_id: &str,
    ) -> Result<(), String> {
        let mut state = self.state.lock().expect("hostcall route mutex poisoned");
        let request_ids = state
            .active
            .iter()
            .filter(|(_, route)| {
                route.parent_request_id == parent_request_id
                    && route.runtime_generation_id == runtime_generation_id
            })
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();
        let retained = state
            .canceled
            .len()
            .checked_add(request_ids.len())
            .ok_or_else(|| "canceled hostcall route count overflows usize".to_string())?;
        if retained > self.canceled_capacity {
            return Err("canceled hostcall route retention capacity is exhausted".to_string());
        }
        for request_id in request_ids {
            let route = state
                .active
                .remove(&request_id)
                .expect("selected active hostcall route exists");
            state.canceled.insert(request_id, route);
        }
        Ok(())
    }

    fn consume(
        &self,
        request_id: &str,
        parent_request_id: &str,
        runtime_generation_id: &str,
    ) -> Result<HostcallRouteDisposition, String> {
        let mut state = self.state.lock().expect("hostcall route mutex poisoned");
        if let Some(route) = state.active.get(request_id) {
            if route.parent_request_id != parent_request_id
                || route.runtime_generation_id != runtime_generation_id
            {
                return Err("hostcall response route identity mismatch".to_string());
            }
            state.active.remove(request_id);
            return Ok(HostcallRouteDisposition::Deliver);
        }
        if let Some(route) = state.canceled.get(request_id) {
            if route.parent_request_id != parent_request_id
                || route.runtime_generation_id != runtime_generation_id
            {
                return Err("hostcall response route identity mismatch".to_string());
            }
            state.canceled.remove(request_id);
            return Ok(HostcallRouteDisposition::DiscardCanceled);
        }
        Err("hostcall response request_id is not outstanding".to_string())
    }

    fn shutdown(&self) {
        let mut state = self.state.lock().expect("hostcall route mutex poisoned");
        state.shutdown = true;
        state.active.clear();
        state.canceled.clear();
    }

    #[cfg(test)]
    fn active_len(&self) -> usize {
        self.state
            .lock()
            .expect("hostcall route mutex poisoned")
            .active
            .len()
    }

    #[cfg(test)]
    fn canceled_len(&self) -> usize {
        self.state
            .lock()
            .expect("hostcall route mutex poisoned")
            .canceled
            .len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        let state = self.state.lock().expect("hostcall route mutex poisoned");
        state.active.len() + state.canceled.len()
    }
}

fn hostcall_route_identity_matches(
    route: Option<&OutstandingHostcallRoute>,
    parent_request_id: &str,
    runtime_generation_id: &str,
) -> bool {
    route.is_some_and(|route| {
        route.parent_request_id == parent_request_id
            && route.runtime_generation_id == runtime_generation_id
    })
}

struct PendingArtifactRoute {
    parent_request_id: String,
    runtime_generation_id: String,
    sender: Sender<String>,
}

struct PendingArtifactRouteState {
    routes: HashMap<String, PendingArtifactRoute>,
    shutdown: bool,
}

struct PendingArtifactRoutes {
    capacity: usize,
    state: Mutex<PendingArtifactRouteState>,
}

impl PendingArtifactRoutes {
    fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "compile flight route capacity must be positive"
        );
        Self {
            capacity,
            state: Mutex::new(PendingArtifactRouteState {
                routes: HashMap::new(),
                shutdown: false,
            }),
        }
    }

    fn register(
        &self,
        request_id: &str,
        parent_request_id: &str,
        runtime_generation_id: &str,
        sender: Sender<String>,
    ) -> Result<(), module_cache::ModuleCacheError> {
        if request_id.trim().is_empty()
            || parent_request_id.trim().is_empty()
            || runtime_generation_id.trim().is_empty()
        {
            return Err(module_cache::ModuleCacheError::Load(
                "artifact route identity is incomplete".to_string(),
            ));
        }
        let mut state = self.state.lock().expect("artifact route mutex poisoned");
        if state.shutdown {
            return Err(module_cache::ModuleCacheError::Load(
                "runtime is shutting down".to_string(),
            ));
        }
        if state.routes.contains_key(request_id) {
            return Err(module_cache::ModuleCacheError::Load(
                "artifact request_id is already pending".to_string(),
            ));
        }
        if state.routes.len() >= self.capacity {
            return Err(module_cache::ModuleCacheError::Load(
                "compile flight route capacity is exhausted".to_string(),
            ));
        }
        state.routes.insert(
            request_id.to_string(),
            PendingArtifactRoute {
                parent_request_id: parent_request_id.to_string(),
                runtime_generation_id: runtime_generation_id.to_string(),
                sender,
            },
        );
        Ok(())
    }

    fn remove(&self, request_id: &str, parent_request_id: &str, runtime_generation_id: &str) {
        let mut state = self.state.lock().expect("artifact route mutex poisoned");
        if state.routes.get(request_id).is_some_and(|route| {
            route.parent_request_id == parent_request_id
                && route.runtime_generation_id == runtime_generation_id
        }) {
            state.routes.remove(request_id);
        }
    }

    fn consume(
        &self,
        request_id: &str,
        parent_request_id: &str,
        runtime_generation_id: &str,
        response: String,
    ) -> Result<(), String> {
        let sender = {
            let mut state = self.state.lock().expect("artifact route mutex poisoned");
            let Some(route) = state.routes.get(request_id) else {
                return Err("artifact response request_id is not outstanding".to_string());
            };
            if route.parent_request_id != parent_request_id
                || route.runtime_generation_id != runtime_generation_id
            {
                return Err("artifact response route identity mismatch".to_string());
            }
            state
                .routes
                .remove(request_id)
                .expect("validated artifact route exists")
                .sender
        };
        sender
            .send(response)
            .map_err(|_| "artifact compile flight response channel closed".to_string())
    }

    fn shutdown(&self) {
        let mut state = self.state.lock().expect("artifact route mutex poisoned");
        state.shutdown = true;
        state.routes.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state
            .lock()
            .expect("artifact route mutex poisoned")
            .routes
            .len()
    }
}

impl ConcurrentExecutionState {
    fn now_unix_millis(&self) -> Result<i64, String> {
        (self.clock)()
    }
}

fn start_ipc_writer(
    limits: redevplugin_ipc::RuntimeLimits,
) -> Result<(FrameSender, thread::JoinHandle<Result<(), String>>), String> {
    let (sender, receiver) = mpsc::sync_channel::<String>(ipc_writer_capacity(limits)?);
    let handle = thread::Builder::new()
        .name("redevplugin-ipc-writer".to_string())
        .spawn(move || {
            let stdout = io::stdout();
            run_ipc_writer(receiver, stdout.lock())
        })
        .map_err(|err| format!("start runtime IPC writer: {err}"))?;
    Ok((sender, handle))
}

fn ipc_writer_capacity(limits: redevplugin_ipc::RuntimeLimits) -> Result<usize, String> {
    limits
        .worker_count
        .checked_add(limits.queue_capacity)
        .and_then(|capacity| capacity.checked_add(IPC_WRITER_CAPACITY_OVERHEAD))
        .ok_or_else(|| "runtime IPC writer capacity overflows usize".to_string())
}

fn run_ipc_writer<W: Write>(receiver: Receiver<String>, output: W) -> Result<(), String> {
    let mut output = BufWriter::with_capacity(IPC_WRITER_MAX_BATCH_BYTES, output);
    while let Ok(frame) = receiver.recv() {
        let mut frame_count = 0usize;
        let mut byte_count = 0usize;
        let mut next = Some(frame);
        loop {
            let frame = next.take().expect("IPC writer batch frame exists");
            output
                .write_all(frame.as_bytes())
                .and_then(|_| output.write_all(b"\n"))
                .map_err(|err| format!("write IPC frame: {err}"))?;
            frame_count += 1;
            byte_count = byte_count
                .checked_add(
                    frame
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| "IPC frame byte count overflows usize".to_string())?,
                )
                .ok_or_else(|| "IPC writer batch byte count overflows usize".to_string())?;
            if frame_count >= IPC_WRITER_MAX_BATCH_FRAMES
                || byte_count >= IPC_WRITER_MAX_BATCH_BYTES
            {
                break;
            }
            match receiver.try_recv() {
                Ok(frame) => next = Some(frame),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        output
            .flush()
            .map_err(|err| format!("flush IPC frames: {err}"))?;
    }
    Ok(())
}

fn send_frame(writer: &FrameSender, frame: String) -> Result<(), String> {
    writer
        .send(frame)
        .map_err(|_| "runtime IPC writer is unavailable".to_string())
}

fn ipc_frame(frame: redevplugin_ipc::IpcResult<String>) -> Result<String, String> {
    frame.map_err(ipc_contract_error)
}

fn ipc_contract_error(error: redevplugin_ipc::IpcError) -> String {
    format!("runtime IPC contract error: {error}")
}

fn response_error_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    error: redevplugin_ipc::IpcResult<redevplugin_ipc::ResponseError<'_>>,
) -> Result<String, String> {
    let error = error.map_err(|err| format!("build runtime IPC response error: {err}"))?;
    ipc_frame(redevplugin_ipc::error_response_frame(
        frame_type,
        request_id,
        runtime_generation_id,
        error,
    ))
}

fn runtime_error_frame(
    frame_type: &str,
    request_id: &str,
    runtime_generation_id: &str,
    code: &str,
    message: impl std::fmt::Display,
) -> Result<String, String> {
    let message = message.to_string();
    response_error_frame(
        frame_type,
        request_id,
        runtime_generation_id,
        redevplugin_ipc::ResponseError::runtime(code, &message),
    )
}

fn worker_engine() -> wasmi::Engine {
    let mut config = Config::default();
    config.consume_fuel(true);
    wasmi::Engine::new(&config)
}

fn module_cache_metrics(
    metrics: module_cache::ModuleCacheMetrics,
) -> redevplugin_ipc::ModuleCacheMetrics {
    redevplugin_ipc::ModuleCacheMetrics {
        hits: metrics.hits,
        misses: metrics.misses,
        compiles: metrics.compiles,
        entries: metrics.entries,
        source_bytes: metrics.source_bytes,
    }
}

fn invocation_error_frame(
    request_id: &str,
    runtime_generation_id: &str,
    code: &str,
    message: impl std::fmt::Display,
) -> Result<String, String> {
    runtime_error_frame(
        redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
        request_id,
        runtime_generation_id,
        code,
        message,
    )
}

fn canceled_invocation_frame(
    request_id: &str,
    runtime_generation_id: &str,
) -> Result<String, String> {
    invocation_error_frame(
        request_id,
        runtime_generation_id,
        redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED,
        "runtime invocation was canceled",
    )
}

fn start_invocation_workers(
    worker_count: usize,
    scheduler: Arc<scheduler::InvocationScheduler>,
    execution: Arc<ConcurrentExecutionState>,
) -> Result<Vec<thread::JoinHandle<()>>, String> {
    (0..worker_count)
        .map(|index| {
            let scheduler = Arc::clone(&scheduler);
            let execution = Arc::clone(&execution);
            thread::Builder::new()
                .name(format!("redevplugin-worker-{index}"))
                .spawn(move || {
                    while let Some(job) = scheduler.take() {
                        let request_id = job.request_id.clone();
                        let response = handle_scheduled_worker_invocation(&job, &execution)
                            .or_else(|err| {
                                invocation_error_frame(
                                    &request_id,
                                    &execution.runtime_generation_id,
                                    redevplugin_ipc::ERR_WASM_WORKER_FAILED,
                                    format!("runtime response frame failed: {err}"),
                                )
                            });
                        if let Ok(response) = response {
                            let _ = send_frame(&execution.writer, response);
                        }
                        scheduler.finish(&request_id);
                    }
                })
                .map_err(|err| format!("start runtime invocation worker: {err}"))
        })
        .collect()
}

fn wait_for_hostcall_response(
    job: &scheduler::InvocationJob,
    execution: &ConcurrentExecutionState,
    request_id: &str,
    frame: String,
) -> Result<String, String> {
    if job.cancellation.is_canceled() {
        return Err(format!(
            "{}: runtime invocation was canceled",
            redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED
        ));
    }
    let frame = redevplugin_ipc::bind_parent_request_id(&frame, &job.request_id)
        .map_err(ipc_contract_error)?;
    execution.hostcall_routes.register(
        request_id,
        &job.request_id,
        &execution.runtime_generation_id,
    )?;
    if job.cancellation.is_canceled() {
        execution.hostcall_routes.remove(
            request_id,
            &job.request_id,
            &execution.runtime_generation_id,
        );
        return Err(format!(
            "{}: runtime invocation was canceled",
            redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED
        ));
    }
    if let Err(err) = send_frame(&execution.writer, frame) {
        execution.hostcall_routes.remove(
            request_id,
            &job.request_id,
            &execution.runtime_generation_id,
        );
        return Err(err);
    }
    match job.signals.recv() {
        Ok(scheduler::InvocationSignal::HostcallResponse(response)) => {
            if response.len() > MAX_BROKER_RESPONSE_FRAME_BYTES {
                return Err("hostcall response exceeds the size limit".to_string());
            }
            Ok(response)
        }
        Ok(scheduler::InvocationSignal::Canceled) => {
            execution
                .hostcall_routes
                .cancel_parent(&job.request_id, &execution.runtime_generation_id)?;
            Err(format!(
                "{}: runtime invocation was canceled",
                redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED
            ))
        }
        Err(_) => {
            execution.hostcall_routes.remove(
                request_id,
                &job.request_id,
                &execution.runtime_generation_id,
            );
            Err("runtime invocation signal channel closed".to_string())
        }
    }
}

fn load_worker_artifact(
    execution: Arc<ConcurrentExecutionState>,
    parent_request_id: String,
    identity: redevplugin_ipc::WorkerInvocationIdentity,
    response_receiver: mpsc::Receiver<String>,
) -> Result<Vec<u8>, module_cache::ModuleCacheError> {
    let artifact_request_id = format!("{parent_request_id}:artifact");
    let frame = redevplugin_ipc::open_handle_frame(
        &artifact_request_id,
        &execution.runtime_generation_id,
        &identity,
    );
    let frame = match redevplugin_ipc::bind_parent_request_id(&frame, &parent_request_id) {
        Ok(frame) => frame,
        Err(err) => {
            execution.pending_artifacts.remove(
                &artifact_request_id,
                &parent_request_id,
                &execution.runtime_generation_id,
            );
            return Err(module_cache::ModuleCacheError::Load(ipc_contract_error(
                err,
            )));
        }
    };
    if let Err(err) = send_frame(&execution.writer, frame) {
        execution.pending_artifacts.remove(
            &artifact_request_id,
            &parent_request_id,
            &execution.runtime_generation_id,
        );
        return Err(module_cache::ModuleCacheError::Load(err));
    }
    let response = response_receiver.recv().map_err(|_| {
        module_cache::ModuleCacheError::Load(
            "artifact response route closed before completion".to_string(),
        )
    })?;
    let content_base64 = redevplugin_ipc::open_handle_content_base64(
        &response,
        &artifact_request_id,
        &parent_request_id,
        &execution.runtime_generation_id,
        &identity,
    )
    .map_err(|err| module_cache::ModuleCacheError::Load(ipc_contract_error(err)))?;
    let content =
        decode_base64(&content_base64).map_err(module_cache::ModuleCacheError::Invalid)?;
    redevplugin_ipc::validate_worker_artifact_bytes(&identity, &content)
        .map_err(|err| module_cache::ModuleCacheError::Invalid(ipc_contract_error(err)))?;
    Ok(content)
}

fn handle_scheduled_worker_invocation(
    job: &scheduler::InvocationJob,
    execution: &Arc<ConcurrentExecutionState>,
) -> Result<String, String> {
    let invocation = job.invocation.as_ref();
    let request_id = job.request_id.as_str();
    let runtime_generation_id = execution.runtime_generation_id.as_str();
    if job.cancellation.is_canceled() {
        return canceled_invocation_frame(request_id, runtime_generation_id);
    }
    if let Err(err) = execution.shared.control.validate_fresh() {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            err.code(),
            err.to_string(),
        );
    }
    let identity = match invocation.identity() {
        Ok(identity) => identity,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                err,
            );
        }
    };
    if let Err(err) = invocation.validate_worker_contract() {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
            &err,
        );
    }
    if let Err(err) = execution.shared.validate_parsed_invocation(invocation) {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            err.code(),
            err.to_string(),
        );
    }
    if let Err(err) =
        invocation.verify_runtime_lease_signature(&execution.runtime_lease_public_keys)
    {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            redevplugin_ipc::ERR_RUNTIME_LEASE_SIGNATURE_INVALID,
            &err,
        );
    }
    let invocation_now = match execution.now_unix_millis() {
        Ok(now) => now,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
                &err,
            );
        }
    };
    if let Err(err) = invocation.validate_runtime_lease(invocation_now) {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
            &err,
        );
    }
    let replay_key = match invocation.replay_key() {
        Ok(key) => key,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                err,
            );
        }
    };
    if let Err(err) = execution
        .lease_replays
        .lock()
        .expect("runtime lease replay mutex poisoned")
        .consume_key(replay_key, invocation_now)
    {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            err.code(),
            err.to_string(),
        );
    }
    let artifact_execution = Arc::clone(execution);
    let artifact_parent_request_id = job.request_id.clone();
    let artifact_identity = identity.clone();
    let artifact_request_id = format!("{}:artifact", job.request_id);
    let (artifact_response_sender, artifact_response_receiver) = mpsc::channel();
    let register_execution = Arc::clone(execution);
    let register_artifact_request_id = artifact_request_id.clone();
    let register_writer = execution.writer.clone();
    let register_parent_request_id = job.request_id.clone();
    let register_runtime_generation_id = execution.runtime_generation_id.clone();
    let register_identity = identity.clone();
    let complete_execution = Arc::clone(execution);
    let complete_artifact_request_id = artifact_request_id;
    let complete_writer = execution.writer.clone();
    let complete_parent_request_id = job.request_id.clone();
    let complete_runtime_generation_id = execution.runtime_generation_id.clone();
    let complete_identity = identity.clone();
    let flight_hooks = module_cache::CompileFlightHooks::new(
        move || {
            register_execution.pending_artifacts.register(
                &register_artifact_request_id,
                &register_parent_request_id,
                &register_runtime_generation_id,
                artifact_response_sender,
            )?;
            if let Err(err) = send_frame(
                &register_writer,
                redevplugin_ipc::compile_flight_register_frame(
                    &register_parent_request_id,
                    &register_runtime_generation_id,
                    &register_identity,
                ),
            ) {
                register_execution.pending_artifacts.remove(
                    &register_artifact_request_id,
                    &register_parent_request_id,
                    &register_runtime_generation_id,
                );
                return Err(module_cache::ModuleCacheError::Load(err));
            }
            Ok(())
        },
        move || {
            complete_execution.pending_artifacts.remove(
                &complete_artifact_request_id,
                &complete_parent_request_id,
                &complete_runtime_generation_id,
            );
            send_frame(
                &complete_writer,
                redevplugin_ipc::compile_flight_complete_frame(
                    &complete_parent_request_id,
                    &complete_runtime_generation_id,
                    &complete_identity,
                ),
            )
            .map_err(module_cache::ModuleCacheError::Load)
        },
    );
    let compiled = match execution.module_cache.get_or_compile_with_hooks(
        &identity.artifact_sha256,
        redevplugin_ipc::WASM_ABI_VERSION,
        &job.cancellation,
        flight_hooks,
        move || {
            load_worker_artifact(
                artifact_execution,
                artifact_parent_request_id,
                artifact_identity,
                artifact_response_receiver,
            )
        },
    ) {
        Ok(compiled) => compiled,
        Err(err) => {
            if job.cancellation.is_canceled() {
                return canceled_invocation_frame(request_id, runtime_generation_id);
            }
            let code = match err {
                module_cache::ModuleCacheError::Load(_) => {
                    redevplugin_ipc::ERR_ARTIFACT_HANDLE_FAILED
                }
                module_cache::ModuleCacheError::Invalid(_) => {
                    redevplugin_ipc::ERR_WASM_WORKER_INVALID
                }
                module_cache::ModuleCacheError::Canceled => {
                    redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED
                }
            };
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                code,
                err.to_string(),
            );
        }
    };
    let post_artifact_now = match execution.now_unix_millis() {
        Ok(now) => now,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
                &err,
            );
        }
    };
    if let Err(err) = execution
        .shared
        .validate_parsed_hostcall(invocation, post_artifact_now)
    {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            runtime_validation_code(&err),
            &err,
        );
    }
    let worker_request = match invocation.worker_request_json_v2() {
        Ok(request) => request,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                &err,
            );
        }
    };
    let memory_limit_bytes = match invocation.memory_limit_bytes() {
        Ok(limit) => limit,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
                &err,
            );
        }
    };
    if job.cancellation.is_canceled() {
        return canceled_invocation_frame(request_id, runtime_generation_id);
    }
    let result = execute_compiled_worker_module_v2(
        execution.module_cache.engine(),
        &compiled.module,
        &compiled.contract,
        worker_request.as_bytes(),
        memory_limit_bytes,
        |request| {
            if job.cancellation.is_canceled() {
                return Err(format!(
                    "{}: runtime invocation was canceled",
                    redevplugin_ipc::ERR_RUNTIME_INVOCATION_CANCELED
                ));
            }
            execution
                .shared
                .validate_parsed_hostcall(invocation, execution.now_unix_millis()?)?;
            perform_multiplexed_hostcall(job, execution, invocation, request)
        },
    );
    if job.cancellation.is_canceled() {
        return canceled_invocation_frame(request_id, runtime_generation_id);
    }
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WASM_WORKER_INVALID,
                &err,
            );
        }
    };
    let completion_now = match execution.now_unix_millis() {
        Ok(now) => now,
        Err(err) => {
            return invocation_error_frame(
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
                &err,
            );
        }
    };
    if let Err(err) = execution
        .shared
        .validate_parsed_hostcall(invocation, completion_now)
    {
        return invocation_error_frame(
            request_id,
            runtime_generation_id,
            runtime_validation_code(&err),
            &err,
        );
    }
    match redevplugin_ipc::parse_worker_response_v2(&result.response_json) {
        Ok(redevplugin_ipc::WorkerResponseV2::Success(data)) => {
            ipc_frame(redevplugin_ipc::success_response_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                &format!("{{\"data\":{data}}}"),
            ))
        }
        Ok(redevplugin_ipc::WorkerResponseV2::Failure { code, message }) => {
            let error = if worker_error_is_hostcall(&result, &code, &message) {
                redevplugin_ipc::ResponseError::hostcall(&code, &message)
            } else {
                redevplugin_ipc::ResponseError::plugin(&code, &message)
            };
            response_error_frame(
                redevplugin_ipc::FRAME_TYPE_INVOKE_WORKER_RESULT,
                request_id,
                runtime_generation_id,
                error,
            )
        }
        Err(err) => invocation_error_frame(
            request_id,
            runtime_generation_id,
            redevplugin_ipc::ERR_WASM_WORKER_INVALID,
            &err,
        ),
    }
}

fn runtime_validation_code(error: &str) -> &'static str {
    if error.starts_with(redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE) {
        redevplugin_ipc::ERR_RUNTIME_CONTROL_CHANNEL_STALE
    } else if error.starts_with(redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED) {
        redevplugin_ipc::ERR_RUNTIME_CAPABILITY_REVOKED
    } else {
        redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID
    }
}

fn perform_multiplexed_hostcall(
    job: &scheduler::InvocationJob,
    execution: &ConcurrentExecutionState,
    invocation: &redevplugin_ipc::ParsedWorkerInvocation,
    request: WorkerHostcallRequest,
) -> Result<String, String> {
    match request {
        WorkerHostcallRequest::StorageFile(request_json) => {
            let req = storage_file_request_parsed(
                invocation,
                &execution.runtime_generation_id,
                &request_json,
            )?;
            invocation
                .validate_storage_broker_access(&req.store_id, &req.operation)
                .map_err(ipc_contract_error)?;
            let request_id = format!("{}:storage_file", job.request_id);
            let frame = redevplugin_ipc::storage_file_frame(
                &request_id,
                &execution.runtime_generation_id,
                &req,
            );
            let response = wait_for_hostcall_response(job, execution, &request_id, frame)?;
            redevplugin_ipc::validate_storage_file_response(
                &response,
                &request_id,
                &execution.runtime_generation_id,
                &req.operation,
            )
            .map_err(ipc_contract_error)?;
            redevplugin_ipc::storage_file_payload_json(&response, &req.operation)
                .map_err(ipc_contract_error)
        }
        WorkerHostcallRequest::StorageKV(request_json) => {
            let req = storage_kv_request_parsed(
                invocation,
                &execution.runtime_generation_id,
                &request_json,
            )?;
            invocation
                .validate_storage_broker_access(&req.store_id, &req.operation)
                .map_err(ipc_contract_error)?;
            let request_id = format!("{}:storage_kv", job.request_id);
            let frame = redevplugin_ipc::storage_kv_frame(
                &request_id,
                &execution.runtime_generation_id,
                &req,
            );
            let response = wait_for_hostcall_response(job, execution, &request_id, frame)?;
            redevplugin_ipc::validate_storage_kv_response(
                &response,
                &request_id,
                &execution.runtime_generation_id,
                &req.operation,
            )
            .map_err(ipc_contract_error)?;
            redevplugin_ipc::storage_kv_payload_json(&response, &req.operation)
                .map_err(ipc_contract_error)
        }
        WorkerHostcallRequest::StorageSQLite(request_json) => {
            let req = storage_sqlite_request_parsed(
                invocation,
                &execution.runtime_generation_id,
                &request_json,
            )?;
            invocation
                .validate_storage_broker_access(&req.store_id, &req.operation)
                .map_err(ipc_contract_error)?;
            let request_id = format!("{}:storage_sqlite", job.request_id);
            let frame = redevplugin_ipc::storage_sqlite_frame(
                &request_id,
                &execution.runtime_generation_id,
                &req,
            );
            let response = wait_for_hostcall_response(job, execution, &request_id, frame)?;
            redevplugin_ipc::validate_storage_sqlite_response(
                &response,
                &request_id,
                &execution.runtime_generation_id,
                &req.operation,
            )
            .map_err(ipc_contract_error)?;
            redevplugin_ipc::storage_sqlite_payload_json(&response, &req.operation)
                .map_err(ipc_contract_error)
        }
        WorkerHostcallRequest::NetworkExecute(request_json) => {
            let req = network_execute_request_parsed(
                invocation,
                &execution.runtime_generation_id,
                &request_json,
            )?;
            invocation
                .validate_network_broker_access(
                    &req.connector_id,
                    &req.transport,
                    &req.operation,
                    &req.method,
                )
                .map_err(ipc_contract_error)?;
            let request_id = format!("{}:network_execute", job.request_id);
            let frame = redevplugin_ipc::network_execute_frame(
                &request_id,
                &execution.runtime_generation_id,
                &req,
            )
            .map_err(ipc_contract_error)?;
            let response = wait_for_hostcall_response(job, execution, &request_id, frame)?;
            redevplugin_ipc::validate_network_execute_response(
                &response,
                &request_id,
                &execution.runtime_generation_id,
                &req.connector_id,
                &req.transport,
            )
            .map_err(ipc_contract_error)?;
            redevplugin_ipc::network_execute_payload_json(&response).map_err(ipc_contract_error)
        }
    }
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
    status: Arc<RuntimeStatus>,
) -> Result<(), String> {
    let read_file = inherited_control_file("REDEVPLUGIN_CONTROL_READ_FD")?;
    let write_file = inherited_control_file("REDEVPLUGIN_CONTROL_WRITE_FD")?;
    thread::Builder::new()
        .name("redevplugin-control".to_string())
        .spawn(move || {
            if let Err(err) = run_control_channel(
                read_file,
                write_file,
                &shared,
                &runtime_generation_id,
                &status,
            ) {
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
    status: &RuntimeStatus,
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
            redevplugin_ipc::FRAME_TYPE_HEARTBEAT => handle_heartbeat(
                &shared.control,
                &request_id,
                runtime_generation_id,
                &line,
                status,
            ),
            redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH => {
                handle_revoke_epoch(shared, &request_id, runtime_generation_id, &line)
            }
            _ => runtime_error_frame(
                "diagnostic",
                &request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_UNSUPPORTED_FRAME,
                "runtime control frame type is not supported",
            ),
        }?;
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
    status: &RuntimeStatus,
) -> Result<String, String> {
    let request = match redevplugin_ipc::parse_heartbeat_request(line) {
        Ok(value) => value,
        Err(err) => {
            return runtime_error_frame(
                redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                err,
            );
        }
    };
    let max_staleness_ms = match request.max_staleness_ms {
        value if value > 0 => value,
        _ => {
            return runtime_error_frame(
                redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                "max_staleness_ms must be positive",
            );
        }
    };
    control.refresh(Duration::from_millis(max_staleness_ms));
    let runtime_unix_nano = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(1);
    let scheduler_metrics = status.scheduler.metrics();
    let result_json = redevplugin_ipc::heartbeat_ack_result_json(
        runtime_generation_id,
        runtime_unix_nano.max(1),
        max_staleness_ms,
        request.sent_unix_nano,
        redevplugin_ipc::RuntimeHeartbeatStatus {
            active_invocations: scheduler_metrics.active,
            queued_invocations: scheduler_metrics.queued,
            limits: status.limits,
            module_cache: module_cache_metrics(status.module_cache.metrics()),
        },
    );
    ipc_frame(redevplugin_ipc::success_response_frame(
        redevplugin_ipc::FRAME_TYPE_HEARTBEAT,
        request_id,
        runtime_generation_id,
        &result_json,
    ))
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
    #[cfg(test)]
    fn validate_invocation_frame(&self, frame: &str) -> Result<(), RuntimeRevocationError> {
        self.revocations
            .lock()
            .expect("runtime revocation mutex poisoned")
            .validate_invocation_frame(frame)
    }

    #[cfg(test)]
    fn validate_hostcall(&self, frame: &str, now_unix_ms: i64) -> Result<(), String> {
        self.control
            .validate_fresh()
            .map_err(|err| format!("{}: {err}", err.code()))?;
        self.validate_invocation_frame(frame)
            .map_err(|err| format!("{}: {err}", err.code()))?;
        redevplugin_ipc::validate_worker_runtime_lease(frame, now_unix_ms)
            .map_err(|err| format!("{}: {err}", redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID))
    }

    fn validate_parsed_invocation(
        &self,
        invocation: &redevplugin_ipc::ParsedWorkerInvocation,
    ) -> Result<(), RuntimeRevocationError> {
        let context = invocation
            .context()
            .map_err(|_| RuntimeRevocationError::InvalidInvocation)?;
        self.revocations
            .lock()
            .expect("runtime revocation mutex poisoned")
            .validate_context(&context)
    }

    fn validate_parsed_hostcall(
        &self,
        invocation: &redevplugin_ipc::ParsedWorkerInvocation,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        self.control
            .validate_fresh()
            .map_err(|err| format!("{}: {err}", err.code()))?;
        self.validate_parsed_invocation(invocation)
            .map_err(|err| format!("{}: {err}", err.code()))?;
        invocation
            .validate_runtime_lease(now_unix_ms)
            .map_err(|err| format!("{}: {err}", redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID))
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

    #[cfg(test)]
    fn validate_invocation_frame(&self, frame: &str) -> Result<(), RuntimeRevocationError> {
        let invocation = redevplugin_ipc::parse_worker_invocation_context(frame)
            .map_err(|_| RuntimeRevocationError::InvalidInvocation)?;
        self.validate_context(&invocation)
    }

    fn validate_context(
        &self,
        invocation: &redevplugin_ipc::WorkerInvocationContext,
    ) -> Result<(), RuntimeRevocationError> {
        let plugin_instance_id = invocation.plugin_instance_id.clone();
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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RuntimeLeaseReplayIdentity {
    lease_id: String,
    lease_nonce: String,
}

struct RuntimeLeaseReplayCache {
    consumed_leases: HashMap<RuntimeLeaseReplayIdentity, i64>,
    expiry_index: BinaryHeap<Reverse<(i64, RuntimeLeaseReplayIdentity)>>,
    max_entries: usize,
}

impl Default for RuntimeLeaseReplayCache {
    fn default() -> Self {
        Self {
            consumed_leases: HashMap::new(),
            expiry_index: BinaryHeap::new(),
            max_entries: DEFAULT_RUNTIME_LEASE_REPLAY_CAPACITY,
        }
    }
}

impl RuntimeLeaseReplayCache {
    #[cfg(test)]
    fn with_capacity(max_entries: usize) -> Self {
        Self {
            consumed_leases: HashMap::new(),
            expiry_index: BinaryHeap::new(),
            max_entries,
        }
    }

    fn prune_expired(&mut self, now_unix_ms: i64) {
        while let Some(Reverse((expires_at_unix_ms, _))) = self.expiry_index.peek() {
            if *expires_at_unix_ms > now_unix_ms {
                break;
            }
            let Some(Reverse((expires_at_unix_ms, identity))) = self.expiry_index.pop() else {
                break;
            };
            if self.consumed_leases.get(&identity) == Some(&expires_at_unix_ms) {
                self.consumed_leases.remove(&identity);
            }
        }
    }

    #[cfg(test)]
    fn consume_invocation_frame(
        &mut self,
        frame: &str,
        now_unix_ms: i64,
    ) -> Result<(), RuntimeLeaseReplayError> {
        let key = redevplugin_ipc::parse_worker_lease_replay_key(frame)
            .map_err(|_| RuntimeLeaseReplayError::InvalidInvocation)?;
        self.consume_key(key, now_unix_ms)
    }

    fn consume_key(
        &mut self,
        key: redevplugin_ipc::WorkerLeaseReplayKey,
        now_unix_ms: i64,
    ) -> Result<(), RuntimeLeaseReplayError> {
        self.prune_expired(now_unix_ms);
        let identity = RuntimeLeaseReplayIdentity {
            lease_id: key.lease_id.clone(),
            lease_nonce: key.lease_nonce,
        };
        if self.consumed_leases.contains_key(&identity) {
            return Err(RuntimeLeaseReplayError::Replayed {
                lease_id: key.lease_id,
            });
        }
        if self.max_entries == 0 || self.consumed_leases.len() >= self.max_entries {
            return Err(RuntimeLeaseReplayError::CapacityExceeded);
        }
        self.consumed_leases
            .insert(identity.clone(), key.expires_at_unix_ms);
        self.expiry_index
            .push(Reverse((key.expires_at_unix_ms, identity)));
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeLeaseReplayError {
    #[cfg(test)]
    InvalidInvocation,
    Replayed {
        lease_id: String,
    },
    CapacityExceeded,
}

impl RuntimeLeaseReplayError {
    fn code(&self) -> &'static str {
        match self {
            #[cfg(test)]
            Self::InvalidInvocation => redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
            Self::Replayed { .. } => redevplugin_ipc::ERR_LEASE_REPLAYED,
            Self::CapacityExceeded => redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID,
        }
    }
}

impl std::fmt::Display for RuntimeLeaseReplayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(test)]
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
) -> Result<String, String> {
    let request = match redevplugin_ipc::parse_revoke_epoch_request(line) {
        Ok(value) => value,
        Err(err) => {
            return runtime_error_frame(
                redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
                request_id,
                runtime_generation_id,
                redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID,
                err,
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
    ipc_frame(redevplugin_ipc::success_response_frame(
        redevplugin_ipc::FRAME_TYPE_REVOKE_EPOCH_ACK,
        request_id,
        runtime_generation_id,
        &result_json,
    ))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostcallFailureResponse {
    ok: bool,
    code: String,
    message: String,
    error_origin: String,
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

fn execute_compiled_worker_module_v2<'a>(
    engine: &wasmi::Engine,
    module: &wasmi::Module,
    contract: &redevplugin_wasm_abi::ValidatedWorkerModule,
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
    let initial_memory_bytes = contract
        .memory
        .initial_pages
        .checked_mul(WASM_PAGE_BYTES)
        .ok_or_else(|| "worker initial memory size overflows".to_string())?;
    if initial_memory_bytes > memory_limit_bytes as u64 {
        return Err(format!(
            "worker initial memory {initial_memory_bytes} exceeds lease limit {memory_limit_bytes}"
        ));
    }
    let mut linker = <wasmi::Linker<WorkerHostState<'a>>>::new(engine);
    define_v2_worker_hostcalls(&mut linker)?;
    let mut store = wasmi::Store::new(
        engine,
        WorkerHostState::new(broker_hostcall, memory_limit_bytes),
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(DEFAULT_WASM_WORKER_FUEL)
        .map_err(|err| format!("configure wasm worker fuel: {err}"))?;
    let instance = linker
        .instantiate_and_start(&mut store, module)
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
        .get_typed_func::<(i32, i32), i64>(&store, redevplugin_wasm_abi::EXPORT_WORKER_INVOKE)
        .map_err(|err| format!("resolve ABI v2 worker invoke export: {err}"))?;

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
            return Err(format!("execute ABI v2 worker invoke export: {err}"));
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

fn worker_error_is_hostcall(execution: &WorkerExecutionV2, code: &str, message: &str) -> bool {
    execution
        .hostcall_failures
        .iter()
        .any(|failure| failure.code == code && failure.message == message)
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
        "hostcall failed".to_string()
    } else {
        message.chars().take(4096).collect()
    };
    serde_json::json!({
        "ok": false,
        "code": code,
        "message": message,
        "error_origin": "hostcall",
    })
    .to_string()
}

fn record_hostcall_response(caller: &mut wasmi::Caller<'_, WorkerHostState<'_>>, response: &str) {
    let Ok(failure) = serde_json::from_str::<HostcallFailureResponse>(response) else {
        return;
    };
    if failure.ok
        || failure.error_origin != "hostcall"
        || !stable_worker_error_code(&failure.code)
        || failure.message.trim().is_empty()
        || failure.message.chars().count() > 4096
    {
        return;
    }
    let code = failure.code.trim();
    let message = failure.message.trim();
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
    owner_env_hash: Option<String>,
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

fn storage_file_request_parsed(
    invocation: &redevplugin_ipc::ParsedWorkerInvocation,
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
    let context = invocation.context().map_err(ipc_contract_error)?;
    let store_id = request.store_id;
    let handle_grant_token = invocation
        .storage_handle_grant(&store_id)
        .map_err(ipc_contract_error)?;
    Ok(redevplugin_ipc::StorageFileRequest {
        handle_grant_token,
        plugin_instance_id: context.plugin_instance_id,
        active_fingerprint: context.active_fingerprint,
        runtime_instance_id: context.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: context.runtime_shard_id,
        handle_id: format!("storage:{store_id}"),
        method: "storage.files".to_string(),
        policy_revision: context.policy_revision,
        management_revision: context.management_revision,
        revoke_epoch: context.revoke_epoch,
        operation: request.operation,
        store_id,
        path: request.path,
        data_base64: request.data_base64,
        max_bytes: request.max_bytes.unwrap_or(0),
        max_entries: request.max_entries.unwrap_or(0),
        recursive: request.recursive.unwrap_or(false),
    })
}

fn storage_kv_request_parsed(
    invocation: &redevplugin_ipc::ParsedWorkerInvocation,
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
    let context = invocation.context().map_err(ipc_contract_error)?;
    let store_id = request.store_id;
    let handle_grant_token = invocation
        .storage_handle_grant(&store_id)
        .map_err(ipc_contract_error)?;
    Ok(redevplugin_ipc::StorageKVRequest {
        handle_grant_token,
        plugin_instance_id: context.plugin_instance_id,
        active_fingerprint: context.active_fingerprint,
        runtime_instance_id: context.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: context.runtime_shard_id,
        handle_id: format!("storage:{store_id}"),
        method: "storage.kv".to_string(),
        policy_revision: context.policy_revision,
        management_revision: context.management_revision,
        revoke_epoch: context.revoke_epoch,
        operation: request.operation,
        store_id,
        key: request.key,
        value_base64: request.value_base64,
        prefix: request.prefix,
        max_bytes: request.max_bytes.unwrap_or(0),
        max_entries: request.max_entries.unwrap_or(0),
    })
}

fn storage_sqlite_request_parsed(
    invocation: &redevplugin_ipc::ParsedWorkerInvocation,
    runtime_generation_id: &str,
    request_json: &str,
) -> Result<redevplugin_ipc::StorageSQLiteRequest, String> {
    let request: StorageSQLiteHostcallRequest =
        decode_hostcall_request(request_json, "storage SQLite hostcall request")?;
    require_non_empty(&request.operation, "operation")?;
    require_non_empty(&request.store_id, "store_id")?;
    require_non_empty(&request.sql, "sql")?;
    let context = invocation.context().map_err(ipc_contract_error)?;
    let store_id = request.store_id;
    let handle_grant_token = invocation
        .storage_handle_grant(&store_id)
        .map_err(ipc_contract_error)?;
    Ok(redevplugin_ipc::StorageSQLiteRequest {
        handle_grant_token,
        plugin_instance_id: context.plugin_instance_id,
        active_fingerprint: context.active_fingerprint,
        runtime_instance_id: context.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: context.runtime_shard_id,
        handle_id: format!("storage:{store_id}"),
        method: "storage.sqlite".to_string(),
        policy_revision: context.policy_revision,
        management_revision: context.management_revision,
        revoke_epoch: context.revoke_epoch,
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

fn network_execute_request_parsed(
    invocation: &redevplugin_ipc::ParsedWorkerInvocation,
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
        ("owner_env_hash", request.owner_env_hash.as_ref()),
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
    let context = invocation.context().map_err(ipc_contract_error)?;
    let scope = invocation
        .network_broker_scope(&request.connector_id, &request.transport)
        .map_err(ipc_contract_error)?;
    let is_user_scope = scope == "user";
    let resource_scope = redevplugin_ipc::NetworkResourceScope {
        kind: scope,
        owner_env_hash: context.owner_env_hash.clone(),
        owner_user_hash: if is_user_scope {
            context.owner_user_hash.clone()
        } else {
            String::new()
        },
    };
    let stream_id = if request.operation == "http_stream" {
        if context.stream_id.is_empty() {
            return Err("http_stream invocation is missing the host-owned stream_id".to_string());
        }
        context.stream_id.clone()
    } else {
        String::new()
    };
    let query_json = serde_json::to_string(&request.query)
        .map_err(|err| format!("encode network query: {err}"))?;
    let headers_json = serde_json::to_string(&request.headers)
        .map_err(|err| format!("encode network headers: {err}"))?;
    Ok(redevplugin_ipc::NetworkExecuteRequest {
        plugin_id: context.plugin_id,
        plugin_instance_id: context.plugin_instance_id,
        active_fingerprint: context.active_fingerprint,
        resource_scope,
        runtime_instance_id: context.runtime_instance_id,
        runtime_generation_id: runtime_generation_id.to_string(),
        runtime_shard_id: context.runtime_shard_id,
        policy_revision: context.policy_revision,
        management_revision: context.management_revision,
        revoke_epoch: context.revoke_epoch,
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
        stream_method: context.method,
        stream_effect: context.effect,
        stream_execution: context.execution,
        surface_instance_id: context.surface_instance_id,
        owner_session_hash: context.owner_session_hash,
        owner_user_hash: context.owner_user_hash,
        owner_env_hash: context.owner_env_hash,
        session_channel_id_hash: context.session_channel_id_hash,
        bridge_channel_id: context.bridge_channel_id,
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
    use std::sync::atomic::Ordering;

    #[derive(Default)]
    struct FlushCountingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for FlushCountingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn ipc_writer_capacity_is_derived_from_validated_runtime_limits() {
        let limits = redevplugin_ipc::RuntimeLimits {
            worker_count: 64,
            queue_capacity: 64,
            per_plugin_concurrency: 1,
            module_cache_entries: 1,
            module_cache_source_bytes: 1,
        };
        assert_eq!(ipc_writer_capacity(limits).unwrap(), 136);
    }

    #[test]
    fn ipc_writer_batches_queued_frames_without_reordering() {
        let (sender, receiver) = mpsc::sync_channel(8);
        sender.send("one".to_string()).unwrap();
        sender.send("two".to_string()).unwrap();
        drop(sender);
        let mut output = FlushCountingWriter::default();
        run_ipc_writer(receiver, &mut output).unwrap();
        assert_eq!(output.bytes, b"one\ntwo\n");
        assert_eq!(output.flushes, 1);
    }

    #[test]
    fn ipc_writer_flushes_at_the_frame_batch_limit() {
        let (sender, receiver) = mpsc::sync_channel(IPC_WRITER_MAX_BATCH_FRAMES + 1);
        for index in 0..=IPC_WRITER_MAX_BATCH_FRAMES {
            sender.send(format!("frame-{index}")).unwrap();
        }
        drop(sender);
        let mut output = FlushCountingWriter::default();
        run_ipc_writer(receiver, &mut output).unwrap();
        assert_eq!(output.flushes, 2);
        assert_eq!(
            output.bytes.iter().filter(|byte| **byte == b'\n').count(),
            IPC_WRITER_MAX_BATCH_FRAMES + 1
        );
    }

    #[test]
    fn ipc_writer_flushes_at_the_byte_batch_limit() {
        let (sender, receiver) = mpsc::sync_channel(3);
        let frame = "x".repeat(IPC_WRITER_MAX_BATCH_BYTES / 2);
        for _ in 0..3 {
            sender.send(frame.clone()).unwrap();
        }
        drop(sender);
        let mut output = FlushCountingWriter::default();
        run_ipc_writer(receiver, &mut output).unwrap();
        assert_eq!(output.flushes, 2);
    }

    #[test]
    fn bounded_frame_sender_blocks_until_capacity_is_available() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender.send("first".to_string()).unwrap();
        let (done_sender, done_receiver) = mpsc::channel();
        let producer = thread::spawn(move || {
            let result = sender.send("second".to_string());
            done_sender.send(result).unwrap();
        });
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(receiver.recv().unwrap(), "first");
        done_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(receiver.recv().unwrap(), "second");
        producer.join().unwrap();
    }

    #[test]
    fn frame_sender_reports_writer_disconnect() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        assert_eq!(
            send_frame(&sender, "frame".to_string()).unwrap_err(),
            "runtime IPC writer is unavailable"
        );
    }

    #[test]
    fn compiled_runtime_target_uses_platform_canonical_names() {
        let target = compiled_runtime_target().expect("supported runtime build target");
        let expected_os = if cfg!(target_os = "macos") {
            "darwin"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else {
            panic!("test is running on an unsupported runtime os")
        };
        let expected_arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            panic!("test is running on an unsupported runtime architecture")
        };
        assert_eq!(target.os(), expected_os);
        assert_eq!(target.arch(), expected_arch);
    }

    #[test]
    fn canceled_outstanding_hostcall_consumes_late_exact_response() {
        let routes = OutstandingHostcallRoutes::new(2, 2);
        routes.register("r1:storage_file", "r1", "g1").unwrap();
        routes.cancel_parent("r1", "g1").unwrap();
        assert_eq!(
            routes.consume("r1:storage_file", "r1", "g1").unwrap(),
            HostcallRouteDisposition::DiscardCanceled
        );
        assert_eq!(routes.len(), 0);
    }

    #[test]
    fn outstanding_hostcall_rejects_unknown_or_wrong_bound_response() {
        let routes = OutstandingHostcallRoutes::new(2, 2);
        routes.register("r1:storage_file", "r1", "g1").unwrap();
        assert!(routes.consume("unknown", "r1", "g1").is_err());
        assert!(routes.consume("r1:storage_file", "other", "g1").is_err());
        assert!(routes.consume("r1:storage_file", "r1", "g2").is_err());
        assert_eq!(
            routes.len(),
            1,
            "wrong identities must not consume the route"
        );
        assert_eq!(
            routes.consume("r1:storage_file", "r1", "g1").unwrap(),
            HostcallRouteDisposition::Deliver
        );
    }

    #[test]
    fn outstanding_hostcall_capacity_and_shutdown_are_explicit() {
        let routes = OutstandingHostcallRoutes::new(1, 1);
        routes.register("r1:storage_file", "r1", "g1").unwrap();
        assert!(routes.register("r2:storage_file", "r2", "g1").is_err());
        routes.shutdown();
        assert_eq!(routes.len(), 0);
        assert!(routes.register("r3:storage_file", "r3", "g1").is_err());
    }

    #[test]
    fn canceled_hostcall_retention_does_not_consume_active_capacity() {
        let routes = OutstandingHostcallRoutes::new(1, 2);
        routes.register("r1:storage_file", "r1", "g1").unwrap();
        routes.cancel_parent("r1", "g1").unwrap();
        routes.register("r2:storage_file", "r2", "g1").unwrap();
        assert_eq!(routes.active_len(), 1);
        assert_eq!(routes.canceled_len(), 1);
    }

    #[test]
    fn canceled_hostcall_retention_overflow_is_atomic_and_fail_closed() {
        let routes = OutstandingHostcallRoutes::new(1, 1);
        routes.register("r1:storage_file", "r1", "g1").unwrap();
        routes.cancel_parent("r1", "g1").unwrap();
        routes.register("r2:storage_file", "r2", "g1").unwrap();
        assert!(routes.cancel_parent("r2", "g1").is_err());
        assert_eq!(routes.active_len(), 1);
        assert_eq!(routes.canceled_len(), 1);
        assert!(routes.consume("r1:storage_file", "wrong", "g1").is_err());
        assert_eq!(
            routes.consume("r1:storage_file", "r1", "g1").unwrap(),
            HostcallRouteDisposition::DiscardCanceled
        );
        routes.cancel_parent("r2", "g1").unwrap();
    }

    #[test]
    fn artifact_route_is_exact_bounded_and_wrong_identity_does_not_consume() {
        let routes = PendingArtifactRoutes::new(1);
        let (first_sender, first_receiver) = mpsc::channel();
        routes
            .register("r1:artifact", "r1", "g1", first_sender)
            .unwrap();
        let (second_sender, _second_receiver) = mpsc::channel();
        assert!(
            routes
                .register("r2:artifact", "r2", "g1", second_sender)
                .is_err()
        );
        assert!(
            routes
                .consume("r1:artifact", "wrong", "g1", "wrong".to_string())
                .is_err()
        );
        assert_eq!(routes.len(), 1);
        routes
            .consume("r1:artifact", "r1", "g1", "response".to_string())
            .unwrap();
        assert_eq!(first_receiver.recv().unwrap(), "response");
        assert_eq!(routes.len(), 0);
        routes.shutdown();
        let (after_sender, _after_receiver) = mpsc::channel();
        assert!(
            routes
                .register("r3:artifact", "r3", "g1", after_sender)
                .is_err()
        );
    }

    #[test]
    fn leader_cancel_keeps_shared_compile_route_until_follower_succeeds() {
        let cache = Arc::new(module_cache::ModuleCache::new(
            worker_engine(),
            1,
            1024 * 1024,
        ));
        let routes = Arc::new(PendingArtifactRoutes::new(1));
        let leader_cancellation = scheduler::Cancellation::new();
        let follower_cancellation = scheduler::Cancellation::new();
        let route_registered = Arc::new(std::sync::Barrier::new(2));
        let load_started = Arc::new(std::sync::Barrier::new(2));
        let source = response_worker_wasm(r#"{"ok":true,"data":{}}"#);
        let (artifact_sender, artifact_receiver) = mpsc::channel();
        let leader = {
            let cache = Arc::clone(&cache);
            let routes = Arc::clone(&routes);
            let completion_routes = Arc::clone(&routes);
            let cancellation = Arc::clone(&leader_cancellation);
            let route_registered = Arc::clone(&route_registered);
            let load_started = Arc::clone(&load_started);
            std::thread::spawn(move || {
                cache.get_or_compile_with_hooks(
                    "sha256:shared-route",
                    redevplugin_ipc::WASM_ABI_VERSION,
                    &cancellation,
                    module_cache::CompileFlightHooks::new(
                        move || {
                            routes.register("leader:artifact", "leader", "g1", artifact_sender)?;
                            route_registered.wait();
                            Ok(())
                        },
                        move || {
                            completion_routes.remove("leader:artifact", "leader", "g1");
                            Ok(())
                        },
                    ),
                    move || {
                        load_started.wait();
                        artifact_receiver.recv().map_err(|_| {
                            module_cache::ModuleCacheError::Load(
                                "artifact response route closed".to_string(),
                            )
                        })?;
                        Ok(source)
                    },
                )
            })
        };
        route_registered.wait();
        load_started.wait();
        let follower = {
            let cache = Arc::clone(&cache);
            let cancellation = Arc::clone(&follower_cancellation);
            std::thread::spawn(move || {
                cache.get_or_compile_with_hooks(
                    "sha256:shared-route",
                    redevplugin_ipc::WASM_ABI_VERSION,
                    &cancellation,
                    module_cache::CompileFlightHooks::new(
                        || panic!("follower must not register a second compile flight"),
                        || panic!("follower must not complete a second compile flight"),
                    ),
                    || panic!("follower must not load the artifact again"),
                )
            })
        };
        let join_deadline = Instant::now() + Duration::from_secs(1);
        while follower_cancellation.waiter_count() != 1 && Instant::now() < join_deadline {
            std::thread::yield_now();
        }
        assert_eq!(follower_cancellation.waiter_count(), 1);
        leader_cancellation.cancel();
        assert!(matches!(
            leader.join().unwrap(),
            Err(module_cache::ModuleCacheError::Canceled)
        ));
        assert_eq!(routes.len(), 1);
        routes
            .consume("leader:artifact", "leader", "g1", "response".to_string())
            .unwrap();
        assert!(follower.join().unwrap().is_ok());
        assert_eq!(routes.len(), 0);
    }

    #[test]
    fn canceled_late_hostcall_response_does_not_require_completed_job_tombstone() {
        let scheduler = scheduler::InvocationScheduler::new(2, 1);
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&worker_invocation_frame("plugini_1", 1))
                .expect("worker invocation");
        scheduler
            .enqueue(scheduler::InvocationJob::new(invocation).unwrap())
            .unwrap();
        let running = scheduler.take().unwrap();
        let (writer, outbound) = mpsc::sync_channel(64);
        let execution = ConcurrentExecutionState {
            shared: Arc::new(RuntimeSharedState::default()),
            lease_replays: Mutex::new(RuntimeLeaseReplayCache::default()),
            runtime_lease_public_keys: Vec::new(),
            module_cache: Arc::new(module_cache::ModuleCache::new(
                worker_engine(),
                1,
                1024 * 1024,
            )),
            clock: Arc::new(current_unix_millis),
            writer: writer.clone(),
            runtime_generation_id: "g1".to_string(),
            pending_artifacts: PendingArtifactRoutes::new(2),
            hostcall_routes: OutstandingHostcallRoutes::new(2, 4),
        };
        execution
            .hostcall_routes
            .register("r1:storage_file", "r1", "g1")
            .unwrap();

        let cancel = redevplugin_ipc::decode_runtime_input_frame(
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"cancel_invoke","request_id":"cancel-r1","runtime_generation_id":"g1","payload":{"invocation_request_id":"r1"}}"#,
        )
        .unwrap();
        dispatch_runtime_input(cancel, "g1", &scheduler, &execution, &writer).unwrap();
        let _cancel_ack = outbound.recv().unwrap();
        scheduler.finish(&running.request_id);

        let late_response = redevplugin_ipc::decode_runtime_input_frame(
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"storage_file","request_id":"r1:storage_file","parent_request_id":"r1","runtime_generation_id":"g1","payload":{}}"#,
        )
        .unwrap();
        dispatch_runtime_input(late_response, "g1", &scheduler, &execution, &writer)
            .expect("exact canceled route discards a late response after job cleanup");
        assert_eq!(execution.hostcall_routes.len(), 0);
    }

    fn runtime_status_for_test() -> RuntimeStatus {
        let limits = redevplugin_ipc::RuntimeLimits {
            worker_count: 2,
            queue_capacity: 4,
            per_plugin_concurrency: 1,
            module_cache_entries: 8,
            module_cache_source_bytes: 1024 * 1024,
        };
        RuntimeStatus {
            limits,
            scheduler: Arc::new(scheduler::InvocationScheduler::new(
                limits.queue_capacity,
                limits.per_plugin_concurrency,
            )),
            module_cache: Arc::new(module_cache::ModuleCache::new(
                worker_engine(),
                limits.module_cache_entries,
                limits.module_cache_source_bytes,
            )),
        }
    }

    #[test]
    fn multiplexed_hostcall_binds_parent_and_cancellation_stops_io() {
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&worker_invocation_frame("plugini_1", 1))
                .expect("worker invocation");
        let job = scheduler::InvocationJob::new(invocation).expect("invocation job");
        let (writer, outbound) = mpsc::sync_channel(64);
        let execution = ConcurrentExecutionState {
            shared: Arc::new(RuntimeSharedState::default()),
            lease_replays: Mutex::new(RuntimeLeaseReplayCache::default()),
            runtime_lease_public_keys: Vec::new(),
            module_cache: Arc::new(module_cache::ModuleCache::new(
                worker_engine(),
                1,
                1024 * 1024,
            )),
            clock: Arc::new(current_unix_millis),
            writer: writer.clone(),
            runtime_generation_id: "g1".to_string(),
            pending_artifacts: PendingArtifactRoutes::new(2),
            hostcall_routes: OutstandingHostcallRoutes::new(2, 4),
        };
        job.signal_sender
            .send(scheduler::InvocationSignal::HostcallResponse(
                "response".to_string(),
            ))
            .unwrap();
        assert_eq!(
            wait_for_hostcall_response(
                &job,
                &execution,
                "r1:artifact",
                r#"{"ipc_version":"rust-ipc-v4","frame_type":"open_handle","request_id":"r1:artifact","runtime_generation_id":"g1","payload":{}}"#.to_string(),
            )
            .unwrap(),
            "response"
        );
        let outbound_frame = outbound.recv().unwrap();
        assert_eq!(
            redevplugin_ipc::parse_frame_identity_v3(&outbound_frame)
                .unwrap()
                .parent_request_id
                .as_deref(),
            Some("r1")
        );

        job.cancellation.cancel();
        assert!(
            wait_for_hostcall_response(
                &job,
                &execution,
                "r1:artifact-after-cancel",
                "{}".to_string()
            )
            .is_err()
        );
        assert!(outbound.try_recv().is_err());
    }

    #[test]
    fn production_dispatch_rejects_invalid_worker_from_typed_input() {
        let limits = redevplugin_ipc::RuntimeLimits {
            worker_count: 1,
            queue_capacity: 1,
            per_plugin_concurrency: 1,
            module_cache_entries: 1,
            module_cache_source_bytes: 1024 * 1024,
        };
        let scheduler = Arc::new(scheduler::InvocationScheduler::new(1, 1));
        let (writer, outbound) = mpsc::sync_channel(64);
        let execution = Arc::new(ConcurrentExecutionState {
            shared: Arc::new(RuntimeSharedState::default()),
            lease_replays: Mutex::new(RuntimeLeaseReplayCache::default()),
            runtime_lease_public_keys: Vec::new(),
            module_cache: Arc::new(module_cache::ModuleCache::new(
                worker_engine(),
                limits.module_cache_entries,
                limits.module_cache_source_bytes,
            )),
            clock: Arc::new(current_unix_millis),
            writer: writer.clone(),
            runtime_generation_id: "g1".to_string(),
            pending_artifacts: PendingArtifactRoutes::new(2),
            hostcall_routes: OutstandingHostcallRoutes::new(2, 4),
        });
        let input = redevplugin_ipc::decode_runtime_input_frame(
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"invoke-invalid","runtime_generation_id":"g1","payload":{"method":"worker.echo","invocation":{}}}"#,
        )
        .expect("outer IPC frame decodes");

        dispatch_runtime_input(input, "g1", &scheduler, &execution, &writer)
            .expect("invalid invocation returns a closed response");

        let response = outbound.recv().expect("invalid invocation response");
        assert!(response.contains(r#""request_id":"invoke-invalid""#));
        assert!(response.contains(redevplugin_ipc::ERR_WORKER_INVOCATION_INVALID));
        assert_eq!(scheduler.metrics().queued, 0);
    }

    #[test]
    fn production_invocation_fails_closed_when_post_artifact_clock_fails() {
        let invocation =
            redevplugin_ipc::parse_worker_invocation(signed_worker_invocation_fixture())
                .expect("signed worker invocation");
        let identity = invocation.identity().expect("worker identity");
        let job = scheduler::InvocationJob::new(invocation).expect("invocation job");
        let module_cache = Arc::new(module_cache::ModuleCache::new(
            worker_engine(),
            1,
            1024 * 1024,
        ));
        let source = response_worker_wasm(r#"{"ok":true,"data":{"value":"done"}}"#);
        module_cache
            .get_or_compile(
                &identity.artifact_sha256,
                redevplugin_ipc::WASM_ABI_VERSION,
                &scheduler::Cancellation::new(),
                move || Ok(source),
            )
            .expect("prewarm production module cache");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let clock_calls = Arc::clone(&calls);
        let (writer, _outbound) = mpsc::sync_channel(64);
        let execution = Arc::new(ConcurrentExecutionState {
            shared: Arc::new(RuntimeSharedState::default()),
            lease_replays: Mutex::new(RuntimeLeaseReplayCache::default()),
            runtime_lease_public_keys: runtime_lease_fixture_public_keys().to_vec(),
            module_cache,
            clock: Arc::new(move || {
                if clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    fixed_runtime_lease_clock()
                } else {
                    Err("test clock unavailable".to_string())
                }
            }),
            writer,
            runtime_generation_id: "rtgen_fixture_v1".to_string(),
            pending_artifacts: PendingArtifactRoutes::new(2),
            hostcall_routes: OutstandingHostcallRoutes::new(2, 4),
        });

        let response = handle_scheduled_worker_invocation(&job, &execution)
            .expect("runtime invocation error response");

        assert!(response.contains(redevplugin_ipc::ERR_RUNTIME_LEASE_INVALID));
        assert!(response.contains("test clock unavailable"));
        assert!(!response.contains(r#""ok":true"#));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
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

    fn execute_worker_module_for_test<'a>(
        wasm_bytes: &[u8],
        request_json: &[u8],
        memory_limit_bytes: usize,
        broker_hostcall: impl FnMut(WorkerHostcallRequest) -> Result<String, String> + 'a,
    ) -> Result<WorkerExecutionV2, String> {
        let cache =
            module_cache::ModuleCache::new(worker_engine(), 1, wasm_bytes.len().saturating_add(1));
        let source = wasm_bytes.to_vec();
        let compiled = cache
            .get_or_compile(
                "sha256:test-artifact",
                redevplugin_ipc::WASM_ABI_VERSION,
                &scheduler::Cancellation::new(),
                move || Ok(source),
            )
            .map_err(|err| err.to_string())?;
        execute_compiled_worker_module_v2(
            cache.engine(),
            &compiled.module,
            &compiled.contract,
            request_json,
            memory_limit_bytes,
            broker_hostcall,
        )
    }

    fn fixed_runtime_lease_clock() -> Result<i64, String> {
        Ok(1_783_161_901_000)
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
    fn runtime_lease_replay_cache_stays_bounded_near_capacity() {
        const CAPACITY: usize = 256;
        let mut cache = RuntimeLeaseReplayCache::with_capacity(CAPACITY);
        for index in 0..CAPACITY {
            cache
                .consume_invocation_frame(
                    &worker_invocation_frame_with_lease_expiry(
                        "plugini_1",
                        1,
                        &format!("lease_initial_{index}"),
                        &format!("nonce_initial_{index}"),
                        2_000 + index as i64,
                    ),
                    1_000,
                )
                .expect("fill replay cache");
        }
        assert_eq!(cache.consumed_leases.len(), CAPACITY);
        assert_eq!(cache.expiry_index.len(), CAPACITY);

        for index in 0..CAPACITY {
            cache
                .consume_invocation_frame(
                    &worker_invocation_frame_with_lease_expiry(
                        "plugini_1",
                        1,
                        &format!("lease_replacement_{index}"),
                        &format!("nonce_replacement_{index}"),
                        100_000 + index as i64,
                    ),
                    2_000 + index as i64,
                )
                .expect("replace exactly one expired replay entry");
            assert_eq!(cache.consumed_leases.len(), CAPACITY);
            assert_eq!(cache.expiry_index.len(), CAPACITY);
        }
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
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1","revoke_epoch":7}}"#,
        )
        .expect("revoke epoch response");
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
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&broker_invocation_frame("plugini_1"))
                .expect("typed invocation");
        let request = storage_file_request_parsed(
            &invocation,
            "g1",
            r#"{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8="}"#,
        )
        .expect("typed storage request");
        invocation
            .validate_storage_broker_access(&request.store_id, &request.operation)
            .expect("storage access is authorized");
        let frame = redevplugin_ipc::storage_file_frame("r1:storage_file", "g1", &request);
        assert!(frame.contains(r#""frame_type":"storage_file""#), "{frame}");
        let response = r#"{"ipc_version":"rust-ipc-v4","frame_type":"storage_file","request_id":"r1:storage_file","runtime_generation_id":"g1","payload":{"ok":true,"path":"notes/from-memory.txt","size_bytes":34,"usage":{"plugin_instance_id":"plugini_1","store_id":"workspace","usage_bytes":34,"quota_bytes":4096,"usage_files":1,"quota_files":64}}}"#;
        redevplugin_ipc::validate_storage_file_response(
            response,
            "r1:storage_file",
            "g1",
            &request.operation,
        )
        .expect("storage response matches request");
        let result = redevplugin_ipc::storage_file_payload_json(response, &request.operation)
            .expect("storage response payload");
        assert!(result.contains(r#""path":"notes/from-memory.txt""#));
    }

    #[test]
    fn method_scoped_storage_denial_happens_before_host_io() {
        let invocation = broker_invocation_frame("plugini_1")
            .replace(r#"["read","write","delete","list"]"#, r#"["read"]"#);
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&invocation).expect("typed invocation");
        let request = storage_file_request_parsed(
            &invocation,
            "g1",
            r#"{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8="}"#,
        )
        .expect("typed storage request");
        let err = invocation
            .validate_storage_broker_access(&request.store_id, &request.operation)
            .expect_err("write access must be denied");
        assert_eq!(
            err,
            redevplugin_ipc::IpcError::ProtocolViolation {
                message: "worker method is not allowed to perform the storage operation"
            }
        );
    }

    #[test]
    fn successful_network_stream_request_round_trips_without_runtime_resource_tracking() {
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&broker_invocation_frame("plugini_1"))
                .expect("typed invocation");
        let request = network_execute_request_parsed(
            &invocation,
            "g1",
            r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"GET","path":"/v1/stream","max_chunk_bytes":1024,"max_buffered_bytes":4096}"#,
        )
        .expect("typed network request");
        invocation
            .validate_network_broker_access(
                &request.connector_id,
                &request.transport,
                &request.operation,
                &request.method,
            )
            .expect("network access is authorized");
        let frame = redevplugin_ipc::network_execute_frame("r1:network_execute", "g1", &request)
            .expect("network execute frame");
        assert!(
            frame.contains(r#""frame_type":"network_execute""#),
            "{frame}"
        );
        assert!(frame.contains(r#""stream_id":"stream_1""#), "{frame}");
    }

    #[test]
    fn method_scoped_http_denial_happens_before_host_io() {
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&broker_invocation_frame("plugini_1"))
                .expect("typed invocation");
        let request = network_execute_request_parsed(
            &invocation,
            "g1",
            r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"DELETE","path":"/v1/items/1"}"#,
        )
        .expect("typed network request");
        let err = invocation
            .validate_network_broker_access(
                &request.connector_id,
                &request.transport,
                &request.operation,
                &request.method,
            )
            .expect_err("DELETE access must be denied");
        assert_eq!(
            err,
            redevplugin_ipc::IpcError::ProtocolViolation {
                message: "worker method is not allowed to perform the network operation"
            }
        );
    }

    #[test]
    fn handle_heartbeat_returns_structured_ack() {
        let control = ControlChannelState::new();
        let status = runtime_status_for_test();
        control.force_stale_for_test();
        let response = handle_heartbeat(
            &control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100,"max_staleness_ms":5000}}"#,
            &status,
        )
        .expect("heartbeat response");
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
        let status = runtime_status_for_test();
        let response = handle_heartbeat(
            &control,
            "r1",
            "g1",
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"heartbeat","request_id":"r1","runtime_generation_id":"g1","payload":{"sent_unix_nano":100}}"#,
            &status,
        )
        .expect("invalid heartbeat error response");
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
            r#"{"ipc_version":"rust-ipc-v4","frame_type":"revoke_epoch","request_id":"r1","runtime_generation_id":"g1","payload":{"plugin_instance_id":"plugini_1"}}"#,
        )
        .expect("invalid revoke epoch error response");
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

        let execution = execute_worker_module_for_test(
            &module,
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
        let execution = execute_worker_module_for_test(
            module,
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"memos.list","params":{"query":"","view":"all","tag":"","date":"","utc_offset_minutes":0,"limit":10}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |request| match request {
                WorkerHostcallRequest::StorageSQLite(request_json) => {
                    if request_json.contains(r#""operation":"query""#) {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","columns":[],"rows":[],"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":0,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
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
            r#"{"ok":true,"data":{"memos":[],"next_cursor":null}}"#
        );
    }

    #[test]
    fn compiled_memos_worker_returns_distinct_navigation_totals() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let mut hostcall_count = 0;
        let execution = execute_worker_module_for_test(
            module,
            br#"{"schema_version":"redevplugin.worker_request.v2","method":"memos.facets","params":{"month":"2026-07","utc_offset_minutes":0}}"#,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |hostcall| {
                let WorkerHostcallRequest::StorageSQLite(request_json) = hostcall else {
                    return Err("unexpected non-SQLite memos hostcall".to_string());
                };
                hostcall_count += 1;
                let request: serde_json::Value = serde_json::from_str(&request_json)
                    .map_err(|err| format!("decode memos SQLite request: {err}"))?;
                let sql = request["sql"]
                    .as_str()
                    .ok_or_else(|| "memos SQLite request omitted sql".to_string())?;
                let (columns, rows) = if sql.starts_with("WITH RECURSIVE split") {
                    (serde_json::json!(["tag", "count(*)"]), serde_json::json!([]))
                } else if sql.starts_with("SELECT date(created_at") {
                    (serde_json::json!(["date", "count(*)"]), serde_json::json!([]))
                } else if sql.starts_with("SELECT COALESCE(SUM(CASE WHEN archived = 0") {
                    (
                        serde_json::json!(["all_total", "pinned_total", "archived_total"]),
                        serde_json::json!([[{"int": 2}, {"int": 1}, {"int": 3}]]),
                    )
                } else {
                    return Err(format!("unexpected memos facets query: {sql}"));
                };
                Ok(serde_json::json!({
                    "ok": true,
                    "database": "memos.sqlite",
                    "columns": columns,
                    "rows": rows,
                    "usage": sqlite_usage_fixture()
                })
                .to_string())
            },
        )
        .expect("compiled memos facets executes");

        assert_eq!(hostcall_count, 3);
        let response: serde_json::Value =
            serde_json::from_str(&execution.response_json).expect("decode memos facets response");
        assert_eq!(response["data"]["all_total"], 2);
        assert_eq!(response["data"]["pinned_total"], 1);
        assert_eq!(response["data"]["archived_total"], 3);
    }

    #[test]
    fn executes_compiled_example_worker_publish_with_portable_dispatch() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let mut hostcall_count = 0;
        let execution = execute_worker_module_for_test(
            module,
            br##"{"schema_version":"redevplugin.worker_request.v2","method":"memos.publish","params":{"content":"# Smoke memo\n\nStored through SQLite #work"}}"##,
            TEST_WORKER_MEMORY_LIMIT_BYTES,
            |request| match request {
                WorkerHostcallRequest::StorageSQLite(request_json) => {
                    hostcall_count += 1;
                    if request_json.contains(r#""operation":"query""#) {
                        Ok(r##"{"ok":true,"database":"memos.sqlite","columns":["id","content","pinned","archived","tags","created_at","updated_at"],"rows":[[{"text":"memo_000000000000000000000001"},{"text":"# Smoke memo\n\nStored through SQLite #work"},{"int":0},{"int":0},{"text":"work"},{"text":"2026-07-14T00:00:00Z"},{"text":"2026-07-14T00:00:00Z"}]],"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":256,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"##.to_string())
                    } else if request_json.contains("INSERT INTO memo_sequence") {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","rows_affected":1,"last_insert_id":1,"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":256,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    } else {
                        Ok(r#"{"ok":true,"database":"memos.sqlite","rows_affected":1,"usage":{"plugin_instance_id":"plugini_test","store_id":"memos","usage_bytes":256,"quota_bytes":1048576,"usage_files":1,"quota_files":1000}}"#.to_string())
                    }
                }
                request => unexpected_hostcall(request),
            },
        )
        .expect("compiled example worker publish executes with portable dispatch");

        assert_eq!(hostcall_count, 3);
        let redevplugin_ipc::WorkerResponseV2::Success(data) =
            redevplugin_ipc::parse_worker_response_v2(&execution.response_json)
                .expect("valid worker response")
        else {
            panic!("publish must return a successful worker response");
        };
        assert!(
            data.contains(r#""id":"memo_000000000000000000000001""#),
            "{data}"
        );
        assert!(data.contains(r#""tags":["work"]"#), "{data}");
        assert!(data.contains(r#""archived":false"#), "{data}");
    }

    #[test]
    fn compiled_memos_worker_pages_with_an_opaque_keyset_cursor() {
        let module = include_bytes!("../../../examples/plugins/memos/workers/memos.wasm");
        let execute_page = |cursor: Option<&str>| {
            let mut params = serde_json::json!({
                "query": "",
                "view": "pinned",
                "tag": "",
                "date": "",
                "utc_offset_minutes": 0,
                "limit": 10
            });
            if let Some(cursor) = cursor {
                params["cursor"] = serde_json::Value::String(cursor.to_string());
            }
            let request = serde_json::json!({
                "schema_version": "redevplugin.worker_request.v2",
                "method": "memos.list",
                "params": params
            })
            .to_string();
            let expects_keyset = cursor.is_some();
            execute_worker_module_for_test(
                module,
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
                    if sql.contains("count(*)") || sql.contains("OFFSET") {
                        return Err(format!("invalid memos pagination query: {sql}"));
                    }
                    let uses_keyset = sql.contains(
                        "pinned < ? OR (pinned = ? AND created_at < ?) OR (pinned = ? AND created_at = ? AND id < ?)",
                    );
                    if !sql.contains("archived = ? AND pinned = ?")
                        || !sql.contains("ORDER BY pinned DESC, created_at DESC, id DESC LIMIT ?")
                        || uses_keyset != expects_keyset
                    {
                        return Err(format!("unexpected memos page query: {sql}"));
                    }
                    let (page_start, page_len) = if expects_keyset { (0, 1) } else { (1, 11) };
                    let rows = (0..page_len)
                        .map(|index| {
                            let absolute = page_start + page_len - index;
                            serde_json::json!([
                                {"text": format!("memo_{absolute:04}")},
                                {"text": format!("Pinned memo {absolute} #work")},
                                {"int": 1},
                                {"int": 0},
                                {"text": "work"},
                                {"text": "2026-07-14T00:00:00Z"},
                                {"text": "2026-07-14T00:00:00Z"}
                            ])
                        })
                        .collect::<Vec<_>>();
                    Ok(serde_json::json!({
                        "ok": true,
                        "database": "memos.sqlite",
                        "columns": ["id", "content", "pinned", "archived", "tags", "created_at", "updated_at"],
                        "rows": rows,
                        "usage": sqlite_usage_fixture()
                    })
                    .to_string())
                },
            )
            .expect("compiled memos page executes")
        };

        let first: serde_json::Value = serde_json::from_str(&execute_page(None).response_json)
            .expect("decode first memos page");
        assert_eq!(first["data"]["memos"].as_array().map(Vec::len), Some(10));
        let next_cursor = first["data"]["next_cursor"]
            .as_str()
            .expect("first page has an opaque next cursor");
        assert!(next_cursor.starts_with("memos_cursor_v1_"));

        let second: serde_json::Value =
            serde_json::from_str(&execute_page(Some(next_cursor)).response_json)
                .expect("decode second memos page");
        assert_eq!(second["data"]["memos"].as_array().map(Vec::len), Some(1));
        assert!(second["data"]["next_cursor"].is_null());
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

        let error = execute_worker_module_for_test(
            &module,
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

        let error = execute_worker_module_for_test(
            &module,
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

        let error = execute_worker_module_for_test(
            &module,
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

        let error = execute_worker_module_for_test(
            &module,
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
            r#"{"code":"NETWORK_TARGET_DENIED","error_origin":"hostcall","message":"destination is private","ok":false}"#
        );
        assert_eq!(
            worker_hostcall_error_json("transport closed"),
            r#"{"code":"HOSTCALL_FAILED","error_origin":"hostcall","message":"transport closed","ok":false}"#
        );
    }

    #[test]
    fn plugin_cannot_spoof_runtime_or_hostcall_error_origin() {
        let plugin_execution = WorkerExecutionV2 {
            response_json: String::new(),
            hostcall_failures: Vec::new(),
        };
        assert!(!worker_error_is_hostcall(
            &plugin_execution,
            "RUNTIME_CAPABILITY_REVOKED",
            "runtime capability was revoked",
        ));
        let hostcall_execution = WorkerExecutionV2 {
            response_json: String::new(),
            hostcall_failures: vec![TrustedWorkerFailure {
                code: "NETWORK_TARGET_DENIED".to_string(),
                message: "destination is private".to_string(),
            }],
        };
        assert!(worker_error_is_hostcall(
            &hostcall_execution,
            "NETWORK_TARGET_DENIED",
            "destination is private",
        ));
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

        let execution = execute_worker_module_for_test(
            &module,
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
        let invocation = r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"broker_access":{"network":[{"connector_id":"api","transport":"http","scope":"user","operations":["http_stream"],"http_methods":["POST"]}]},"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"POST","path":"/v1/stream","query":{"format":["json"],"timezone":["auto"]},"max_chunk_bytes":4,"max_buffered_bytes":65536,"content_type":"text/plain"}"#;
        let invocation =
            redevplugin_ipc::parse_worker_invocation(invocation).expect("typed invocation");
        let got = network_execute_request_parsed(&invocation, "g1", request)
            .expect("stream network execute request");

        assert_eq!(got.plugin_id, "com.example.worker");
        assert_eq!(got.runtime_shard_id, "runtime_shard_signed");
        assert_eq!(got.operation, "http_stream");
        assert_eq!(got.stream_id, "stream_host_1");
        assert_eq!(got.stream_method, "worker.echo");
        assert_eq!(got.stream_effect, "read");
        assert_eq!(got.stream_execution, "subscription");
        assert_eq!(got.surface_instance_id, "surface_1");
        assert_eq!(got.owner_session_hash, "session_hash");
        assert_eq!(got.owner_user_hash, "user_hash");
        assert_eq!(got.owner_env_hash, "env_hash");
        assert_eq!(got.session_channel_id_hash, "channel_hash");
        assert_eq!(got.bridge_channel_id, "bridge_1");
        assert_eq!(got.max_chunk_bytes, 4);
        assert_eq!(got.max_buffered_bytes, 65536);
        assert_eq!(got.content_type, "text/plain");
        assert_eq!(got.query_json, r#"{"format":["json"],"timezone":["auto"]}"#);
    }

    #[test]
    fn storage_request_uses_host_only_grant_map() {
        let invocation = r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed"},"method":"notes.list","invocation":{"plugin_id":"com.example.notes","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"storage_handle_grants":{"notes":"handle_grant.host-only-secret"},"method":"notes.list","effect":"read","execution":"sync"}}}"#;
        let request = r#"{"store_id":"notes","operation":"query","database":"notes.sqlite","sql":"SELECT id FROM notes","args":[]}"#;
        let invocation =
            redevplugin_ipc::parse_worker_invocation(invocation).expect("typed invocation");
        let got = storage_sqlite_request_parsed(&invocation, "g1", request)
            .expect("storage request with host-only grant map");

        assert_eq!(got.handle_grant_token, "handle_grant.host-only-secret");
        assert_eq!(got.runtime_shard_id, "runtime_shard_signed");
        assert_eq!(got.store_id, "notes");
    }

    #[test]
    fn network_execute_request_rejects_plugin_owned_audience_overrides() {
        let invocation = r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let invocation =
            redevplugin_ipc::parse_worker_invocation(invocation).expect("typed invocation");
        for field in [
            "stream_method",
            "stream_effect",
            "stream_execution",
            "surface_instance_id",
            "owner_session_hash",
            "owner_user_hash",
            "owner_env_hash",
            "session_channel_id_hash",
            "bridge_channel_id",
        ] {
            let request = format!(
                r#"{{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","{field}":"plugin-selected"}}"#
            );
            let err = network_execute_request_parsed(&invocation, "g1", &request)
                .expect_err("plugin-owned audience override must fail closed");
            assert!(
                err.contains("host-owned invocation field"),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn network_execute_request_rejects_plugin_selected_stream_id() {
        let invocation = r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed","stream_id":"stream_host_1"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"method":"worker.echo","effect":"read","execution":"subscription","stream_id":"stream_host_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","stream_id":"stream_plugin_selected"}"#;
        let invocation =
            redevplugin_ipc::parse_worker_invocation(invocation).expect("typed invocation");
        let err = network_execute_request_parsed(&invocation, "g1", request)
            .expect_err("plugin-selected stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
    }

    #[test]
    fn network_hostcall_request_rejects_unknown_duplicate_and_trailing_fields() {
        let invocation = broker_invocation_frame("plugini_1");
        let invocation =
            redevplugin_ipc::parse_worker_invocation(&invocation).expect("typed invocation");
        let valid = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"GET"}"#;
        network_execute_request_parsed(&invocation, "g1", valid).expect("closed network request");

        for invalid in [
            format!("{valid}{{}}"),
            valid.replace(r#""method":"GET""#, r#""method":"GET","unknown":true"#),
            valid.replace(
                r#""connector_id":"api""#,
                r#""connector_id":"api","connector_id":"other""#,
            ),
        ] {
            assert!(
                network_execute_request_parsed(&invocation, "g1", &invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn network_execute_request_rejects_missing_host_owned_stream_id() {
        let invocation = r#"{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{"lease":{"plugin_instance_id":"plugini_1","runtime_shard_id":"runtime_shard_signed"},"method":"worker.echo","invocation":{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":2,"revoke_epoch":3,"broker_access":{"network":[{"connector_id":"api","transport":"http","scope":"user","operations":["http_stream"],"http_methods":["GET"]}]},"method":"worker.echo","effect":"read","execution":"subscription","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}"#;
        let request = r#"{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream"}"#;
        let invocation =
            redevplugin_ipc::parse_worker_invocation(invocation).expect("typed invocation");
        let err = network_execute_request_parsed(&invocation, "g1", request)
            .expect_err("missing Host stream id must fail closed");

        assert!(err.contains("host-owned stream_id"), "{err}");
    }

    #[test]
    fn rejects_wasm_worker_with_missing_export() {
        let module = minimal_worker_wasm("other_export");
        let err = execute_worker_module_for_test(
            &module,
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

    fn response_worker_wasm(response: &str) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) {response:?})
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
                    i64.const {}))"#,
            ((2048_u64) << 32) | response.len() as u64,
        ))
        .expect("compile response worker")
    }

    fn worker_invocation_frame(plugin_instance_id: &str, revoke_epoch: u64) -> String {
        worker_invocation_frame_with_lease(plugin_instance_id, revoke_epoch, "lease_1", "nonce_1")
    }

    fn broker_invocation_frame(plugin_instance_id: &str) -> String {
        format!(
            r#"{{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{"runtime_shard_id":"runtime_shard_signed"}},"method":"worker.echo","invocation":{{"plugin_id":"com.example.worker","plugin_instance_id":"{plugin_instance_id}","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":1,"revoke_epoch":1,"storage_handle_grants":{{"workspace":"handle_grant.secret"}},"broker_access":{{"storage":[{{"store_id":"workspace","operations":["read","write","delete","list"]}},{{"store_id":"notes","operations":["query","exec"]}}],"network":[{{"connector_id":"api","transport":"http","scope":"user","operations":["http","http_stream"],"http_methods":["GET","POST"]}}]}},"method":"worker.echo","effect":"write","execution":"subscription","stream_id":"stream_1","surface_instance_id":"surface_1","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_1"}}}}}}"#
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
            r#"{{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"r1","runtime_generation_id":"g1","payload":{{"lease":{{"lease_id":"{lease_id}","lease_nonce":"{lease_nonce}","runtime_generation_id":"g1","runtime_shard_id":"runtime_shard_signed","plugin_instance_id":"{plugin_instance_id}","revoke_epoch":{revoke_epoch},"expires_at_unix_ms":{expires_at_unix_ms}}},"method":"worker.echo","invocation":{{"plugin_id":"com.example.worker","plugin_instance_id":"{plugin_instance_id}","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"g1","policy_revision":1,"management_revision":1,"revoke_epoch":{revoke_epoch},"package_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","worker_id":"backend","worker_mode":"job","worker_scope":"user","artifact":"workers/backend.wasm","artifact_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","abi":"redevplugin-wasm-worker-v2","method":"worker.echo","effect":"read","execution":"sync","audit_correlation_id":"audit_1","params_sha256":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","params":{{}},"broker_access":{{}},"broker_access_sha256":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}}}}}}"#
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
