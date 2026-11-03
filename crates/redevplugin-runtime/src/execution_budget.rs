use crate::ipc;
use crate::scheduler::Cancellation;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Fuel is an engine-specific work ceiling, not CPU time. The signed Host
// timeout additionally bounds wall time; epoch checks never replenish fuel.
const FUEL_PER_MILLISECOND: u64 = 1_000_000;
const MAX_FUEL: u64 = 10_000_000_000;
const EPOCH_INTERVAL: Duration = Duration::from_millis(10);

pub struct ExecutionBudget {
    pub fuel: u64,
    pub deadline: Instant,
    pub cancellation: Arc<Cancellation>,
    authority: Option<Box<dyn Fn() -> Result<(), WorkerFailure> + Send + Sync>>,
}

impl ExecutionBudget {
    pub fn new(remaining: Duration, cancellation: Arc<Cancellation>) -> Self {
        let milliseconds = remaining.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            fuel: milliseconds
                .saturating_mul(FUEL_PER_MILLISECOND)
                .min(MAX_FUEL),
            deadline: Instant::now() + remaining,
            cancellation,
            authority: None,
        }
    }

    pub fn with_authority(
        mut self,
        check: impl Fn() -> Result<(), WorkerFailure> + Send + Sync + 'static,
    ) -> Self {
        self.authority = Some(Box::new(check));
        self
    }

    pub fn check(&self) -> Result<(), WorkerFailure> {
        if self.cancellation.is_canceled() {
            return Err(WorkerFailure::Canceled);
        }
        if Instant::now() >= self.deadline {
            return Err(WorkerFailure::Timeout);
        }
        if let Some(check) = &self.authority {
            check()?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WorkerFailure {
    Invalid(String),
    Authority { code: &'static str, message: String },
    Budget,
    Memory,
    Timeout,
    Canceled,
}

impl WorkerFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => ipc::ERR_WASM_WORKER_INVALID,
            Self::Authority { code, .. } => code,
            Self::Budget => ipc::ERR_WASM_WORKER_BUDGET_EXCEEDED,
            Self::Memory => ipc::ERR_WASM_WORKER_MEMORY_LIMIT,
            Self::Timeout => ipc::ERR_RUNTIME_INVOCATION_TIMEOUT,
            Self::Canceled => ipc::ERR_RUNTIME_INVOCATION_CANCELED,
        }
    }

    pub fn engine(error: wasmtime::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return match failure {
                Self::Invalid(message) => Self::Invalid(message.clone()),
                Self::Authority { code, message } => Self::Authority {
                    code,
                    message: message.clone(),
                },
                Self::Budget => Self::Budget,
                Self::Memory => Self::Memory,
                Self::Timeout => Self::Timeout,
                Self::Canceled => Self::Canceled,
            };
        }
        if error.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::OutOfFuel) {
            return Self::Budget;
        }
        Self::Invalid(format!("{error:#}"))
    }
}

impl From<String> for WorkerFailure {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

impl std::fmt::Display for WorkerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Authority { message, .. } => f.write_str(message),
            Self::Budget => f.write_str("worker computation budget exhausted"),
            Self::Memory => f.write_str("worker memory or table limit exceeded"),
            Self::Timeout => f.write_str("worker execution deadline exceeded"),
            Self::Canceled => f.write_str("runtime invocation was canceled"),
        }
    }
}
impl std::error::Error for WorkerFailure {}

// One timer per module cache, shared by its clones. Dropping the last cache
// stops and joins the timer; invocation churn cannot create timer threads.
pub struct EpochTicker {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}
impl EpochTicker {
    pub fn new(engine: wasmtime::Engine) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("redevplugin-epoch".into())
            .spawn(move || {
                let (lock, wake) = &*signal;
                let mut stopped = lock.lock().expect("epoch timer mutex poisoned");
                while !*stopped {
                    let result = wake
                        .wait_timeout(stopped, EPOCH_INTERVAL)
                        .expect("epoch timer wait poisoned");
                    stopped = result.0;
                    if !*stopped {
                        engine.increment_epoch();
                    }
                }
            })
            .expect("start bounded runtime epoch timer");
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for EpochTicker {
    fn drop(&mut self) {
        *self.stop.0.lock().expect("epoch timer mutex poisoned") = true;
        self.stop.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct WorkerLimits(pub wasmtime::StoreLimits);
impl wasmtime::ResourceLimiter for WorkerLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.0
            .memory_growing(current, desired, maximum)
            .map_err(|_| wasmtime::Error::new(WorkerFailure::Memory))
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.0
            .table_growing(current, desired, maximum)
            .map_err(|_| wasmtime::Error::new(WorkerFailure::Memory))
    }
    fn memory_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        Err(wasmtime::Error::new(WorkerFailure::Memory))
    }
    fn table_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        Err(wasmtime::Error::new(WorkerFailure::Memory))
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn execution_policy_matches_canonical_contract() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/execution-policy.json")).unwrap();
        assert_eq!(contract["engine"], "wasmtime-50.0.1");
        assert_eq!(
            contract["fuel_per_remaining_millisecond"],
            FUEL_PER_MILLISECOND
        );
        assert_eq!(contract["maximum_fuel"], MAX_FUEL);
        assert_eq!(
            contract["epoch_interval_milliseconds"],
            EPOCH_INTERVAL.as_millis() as u64
        );
        for (key, failure) in [
            ("fuel", WorkerFailure::Budget),
            ("memory", WorkerFailure::Memory),
            ("deadline", WorkerFailure::Timeout),
            ("cancel", WorkerFailure::Canceled),
        ] {
            assert_eq!(contract["errors"][key], failure.code());
        }
    }
}
