use crate::scheduler::Cancellation;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleCacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub compiles: u64,
    pub entries: usize,
    pub source_bytes: usize,
}

#[derive(Clone)]
pub struct ModuleCache {
    engine: wasmi::Engine,
    max_entries: usize,
    max_source_bytes: usize,
    state: Arc<Mutex<ModuleCacheState>>,
}

#[derive(Clone)]
pub struct CompiledModule {
    pub module: Arc<wasmi::Module>,
    pub contract: Arc<redevplugin_wasm_abi::ValidatedWorkerModule>,
    pub source_bytes: usize,
}

impl std::fmt::Debug for CompiledModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledModule")
            .field("source_bytes", &self.source_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleCacheError {
    Canceled,
    Load(String),
    Invalid(String),
}

pub struct CompileFlightHooks {
    register: Box<dyn FnOnce() -> Result<(), ModuleCacheError> + Send>,
    complete: Arc<dyn Fn() -> Result<(), ModuleCacheError> + Send + Sync>,
}

impl CompileFlightHooks {
    pub fn new(
        register: impl FnOnce() -> Result<(), ModuleCacheError> + Send + 'static,
        complete: impl Fn() -> Result<(), ModuleCacheError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            register: Box::new(register),
            complete: Arc::new(complete),
        }
    }

    #[cfg(test)]
    fn noop() -> Self {
        Self::new(|| Ok(()), || Ok(()))
    }
}

impl std::fmt::Display for ModuleCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canceled => formatter.write_str("module cache wait was canceled"),
            Self::Load(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

#[derive(Default)]
struct ModuleCacheState {
    entries: HashMap<ModuleKey, CacheEntry>,
    recency: BTreeSet<(u64, ModuleKey)>,
    flights: HashMap<ModuleKey, Arc<CompileFlight>>,
    tick: u64,
    source_bytes: usize,
    hits: u64,
    misses: u64,
    compiles: u64,
    #[cfg(test)]
    eviction_index_pops: u64,
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleKey {
    artifact_sha256: String,
    wasm_abi_version: String,
}

struct CacheEntry {
    compiled: CompiledModule,
    last_used: u64,
}

struct CompileFlight {
    result: Mutex<Option<Result<CompiledModule, ModuleCacheError>>>,
    ready: Condvar,
}

impl CompileFlight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<CompiledModule, ModuleCacheError>) {
        *self.result.lock().expect("compile flight mutex poisoned") = Some(result);
        self.ready.notify_all();
    }

    fn notify_canceled(&self) {
        let _result = self.result.lock().expect("compile flight mutex poisoned");
        self.ready.notify_all();
    }

    fn wait(
        self: &Arc<Self>,
        cancellation: &Arc<Cancellation>,
    ) -> Result<CompiledModule, ModuleCacheError> {
        let flight = Arc::downgrade(self);
        let _registration = cancellation.register(move || {
            if let Some(flight) = flight.upgrade() {
                flight.notify_canceled();
            }
        });
        let mut result = self.result.lock().expect("compile flight mutex poisoned");
        loop {
            if cancellation.is_canceled() {
                return Err(ModuleCacheError::Canceled);
            }
            if let Some(result) = result.as_ref() {
                return result.clone();
            }
            result = self
                .ready
                .wait(result)
                .expect("compile flight mutex poisoned while waiting");
        }
    }
}

impl ModuleCache {
    pub fn new(engine: wasmi::Engine, max_entries: usize, max_source_bytes: usize) -> Self {
        Self {
            engine,
            max_entries,
            max_source_bytes,
            state: Arc::new(Mutex::new(ModuleCacheState::default())),
        }
    }

    pub fn engine(&self) -> &wasmi::Engine {
        &self.engine
    }

    #[cfg(test)]
    pub fn get_or_compile(
        &self,
        artifact_sha256: &str,
        wasm_abi_version: &str,
        cancellation: &Arc<Cancellation>,
        load: impl FnOnce() -> Result<Vec<u8>, ModuleCacheError> + Send + 'static,
    ) -> Result<CompiledModule, ModuleCacheError> {
        self.get_or_compile_with_hooks(
            artifact_sha256,
            wasm_abi_version,
            cancellation,
            CompileFlightHooks::noop(),
            load,
        )
    }

    pub fn get_or_compile_with_hooks(
        &self,
        artifact_sha256: &str,
        wasm_abi_version: &str,
        cancellation: &Arc<Cancellation>,
        hooks: CompileFlightHooks,
        load: impl FnOnce() -> Result<Vec<u8>, ModuleCacheError> + Send + 'static,
    ) -> Result<CompiledModule, ModuleCacheError> {
        if cancellation.is_canceled() {
            return Err(ModuleCacheError::Canceled);
        }
        let key = ModuleKey {
            artifact_sha256: artifact_sha256.to_string(),
            wasm_abi_version: wasm_abi_version.to_string(),
        };
        let (flight, leader) = {
            let mut state = self.state.lock().expect("module cache mutex poisoned");
            state.tick += 1;
            let tick = state.tick;
            if let Some(entry) = state.entries.get_mut(&key) {
                let previous_last_used = entry.last_used;
                entry.last_used = tick;
                let compiled = entry.compiled.clone();
                let removed = state.recency.remove(&(previous_last_used, key.clone()));
                debug_assert!(removed);
                let inserted = state.recency.insert((tick, key.clone()));
                debug_assert!(inserted);
                state.hits += 1;
                return Ok(compiled);
            }
            state.misses += 1;
            if let Some(flight) = state.flights.get(&key) {
                (Arc::clone(flight), false)
            } else {
                let flight = Arc::new(CompileFlight::new());
                state.flights.insert(key.clone(), Arc::clone(&flight));
                (flight, true)
            }
        };
        if leader {
            let CompileFlightHooks { register, complete } = hooks;
            if let Err(error) = register() {
                self.finish_flight(&key, &flight, Err(error), false);
                return flight.wait(cancellation);
            }
            let cache = self.clone();
            let compile_key = key.clone();
            let compile_flight = Arc::clone(&flight);
            let thread_complete = Arc::clone(&complete);
            if let Err(err) = thread::Builder::new()
                .name("redevplugin-module-compile".to_string())
                .spawn(move || {
                    let result = cache.compile_module(load);
                    cache.finish_registered_flight(
                        &compile_key,
                        &compile_flight,
                        result,
                        thread_complete.as_ref(),
                    );
                })
            {
                let error =
                    ModuleCacheError::Load(format!("start WASM module compile flight: {err}"));
                self.finish_registered_flight(&key, &flight, Err(error), complete.as_ref());
            }
        }
        flight.wait(cancellation)
    }

    pub fn metrics(&self) -> ModuleCacheMetrics {
        let state = self.state.lock().expect("module cache mutex poisoned");
        ModuleCacheMetrics {
            hits: state.hits,
            misses: state.misses,
            compiles: state.compiles,
            entries: state.entries.len(),
            source_bytes: state.source_bytes,
        }
    }

    fn evict_locked(&self, state: &mut ModuleCacheState) {
        while state.entries.len() > self.max_entries || state.source_bytes > self.max_source_bytes {
            let Some((last_used, key)) = state.recency.pop_first() else {
                break;
            };
            #[cfg(test)]
            {
                state.eviction_index_pops += 1;
            }
            if let Some(entry) = state.entries.remove(&key) {
                debug_assert_eq!(entry.last_used, last_used);
                state.source_bytes -= entry.compiled.source_bytes;
            }
        }
    }

    fn compile_module(
        &self,
        load: impl FnOnce() -> Result<Vec<u8>, ModuleCacheError>,
    ) -> Result<CompiledModule, ModuleCacheError> {
        let source = load()?;
        if source.len() > self.max_source_bytes {
            return Err(ModuleCacheError::Invalid(format!(
                "WASM module source exceeds module cache source byte limit of {} bytes",
                self.max_source_bytes
            )));
        }
        let contract = redevplugin_wasm_abi::validate_worker_module(&source)
            .map_err(|err| ModuleCacheError::Invalid(err.to_string()))?;
        let module = wasmi::Module::new(&self.engine, &source).map_err(|err| {
            ModuleCacheError::Invalid(format!("compile wasm worker module: {err}"))
        })?;
        Ok(CompiledModule {
            module: Arc::new(module),
            contract: Arc::new(contract),
            source_bytes: source.len(),
        })
    }

    fn finish_flight(
        &self,
        key: &ModuleKey,
        flight: &Arc<CompileFlight>,
        result: Result<CompiledModule, ModuleCacheError>,
        compiled: bool,
    ) {
        let mut state = self.state.lock().expect("module cache mutex poisoned");
        if compiled {
            state.compiles += 1;
        }
        if let Ok(compiled) = &result {
            state.tick += 1;
            let last_used = state.tick;
            if let Some(previous) = state.entries.insert(
                key.clone(),
                CacheEntry {
                    compiled: compiled.clone(),
                    last_used,
                },
            ) {
                state.recency.remove(&(previous.last_used, key.clone()));
                state.source_bytes -= previous.compiled.source_bytes;
            }
            state.source_bytes += compiled.source_bytes;
            let inserted = state.recency.insert((last_used, key.clone()));
            debug_assert!(inserted);
            self.evict_locked(&mut state);
        }
        flight.complete(result);
        if state
            .flights
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            state.flights.remove(key);
        }
    }

    fn finish_registered_flight(
        &self,
        key: &ModuleKey,
        flight: &Arc<CompileFlight>,
        mut result: Result<CompiledModule, ModuleCacheError>,
        complete: &(dyn Fn() -> Result<(), ModuleCacheError> + Send + Sync),
    ) {
        let compiled = result.is_ok();
        if let Err(error) = complete() {
            result = Err(error);
        }
        self.finish_flight(key, flight, result, compiled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    const ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
    #[test]
    fn concurrent_first_load_compiles_once() {
        let cache = Arc::new(ModuleCache::new(engine(), 64, 128 * 1024 * 1024));
        let loads = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let loads = Arc::clone(&loads);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                let canceled = Cancellation::new();
                cache
                    .get_or_compile("sha256:a", ABI_VERSION, &canceled, move || {
                        loads.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(20));
                        Ok(worker_module())
                    })
                    .expect("module compiles")
            }));
        }
        let modules = threads
            .into_iter()
            .map(|thread| thread.join().expect("cache thread completes"))
            .collect::<Vec<_>>();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert!(
            modules
                .iter()
                .all(|module| Arc::ptr_eq(&module.module, &modules[0].module))
        );
        assert_eq!(
            cache.metrics(),
            ModuleCacheMetrics {
                hits: 0,
                misses: 8,
                compiles: 1,
                entries: 1,
                source_bytes: worker_module().len(),
            }
        );
    }

    #[test]
    fn cache_hit_does_not_reload_artifact() {
        let cache = ModuleCache::new(engine(), 64, 128 * 1024 * 1024);
        let loads = Arc::new(AtomicUsize::new(0));
        let canceled = Cancellation::new();
        let initial_loads = Arc::clone(&loads);
        cache
            .get_or_compile("sha256:a", ABI_VERSION, &canceled, move || {
                initial_loads.fetch_add(1, Ordering::SeqCst);
                Ok(worker_module())
            })
            .expect("initial module compiles");
        let reloads = Arc::clone(&loads);
        cache
            .get_or_compile("sha256:a", ABI_VERSION, &canceled, move || {
                reloads.fetch_add(1, Ordering::SeqCst);
                Err(ModuleCacheError::Load("unexpected reload".to_string()))
            })
            .expect("cached module loads");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(cache.metrics().hits, 1);
    }

    #[test]
    fn evicts_least_recently_used_module_deterministically() {
        let cache = ModuleCache::new(engine(), 2, 128 * 1024 * 1024);
        let loads = Arc::new(AtomicUsize::new(0));
        let canceled = Cancellation::new();
        let load = |key: &str| {
            let loads = Arc::clone(&loads);
            cache
                .get_or_compile(key, ABI_VERSION, &canceled, move || {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok(worker_module())
                })
                .expect("module compiles")
        };
        load("sha256:a");
        load("sha256:b");
        load("sha256:a");
        load("sha256:c");
        load("sha256:a");
        load("sha256:b");
        assert_eq!(loads.load(Ordering::SeqCst), 4);
        assert_eq!(cache.metrics().entries, 2);
    }

    #[test]
    fn recency_index_matches_cached_entries_after_hits_and_evictions() {
        let cache = ModuleCache::new(engine(), 4, 128 * 1024 * 1024);
        let canceled = Cancellation::new();
        for key in ["sha256:a", "sha256:b", "sha256:c", "sha256:d", "sha256:e"] {
            cache
                .get_or_compile(key, ABI_VERSION, &canceled, || Ok(worker_module()))
                .unwrap();
        }
        cache
            .get_or_compile("sha256:c", ABI_VERSION, &canceled, || {
                Err(ModuleCacheError::Load("unexpected reload".to_string()))
            })
            .unwrap();
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), state.recency.len());
        assert_eq!(
            state.source_bytes,
            state
                .entries
                .values()
                .map(|entry| entry.compiled.source_bytes)
                .sum::<usize>()
        );
        for (last_used, key) in &state.recency {
            assert_eq!(state.entries.get(key).unwrap().last_used, *last_used);
        }
    }

    #[test]
    fn compile_failure_is_not_cached() {
        let cache = ModuleCache::new(engine(), 64, 128 * 1024 * 1024);
        let loads = Arc::new(AtomicUsize::new(0));
        let canceled = Cancellation::new();
        for _ in 0..2 {
            let loads_for_attempt = Arc::clone(&loads);
            let error = cache
                .get_or_compile("sha256:invalid", ABI_VERSION, &canceled, move || {
                    loads_for_attempt.fetch_add(1, Ordering::SeqCst);
                    Ok(b"not wasm".to_vec())
                })
                .expect_err("invalid module must fail");
            assert!(matches!(error, ModuleCacheError::Invalid(_)));
        }
        assert_eq!(loads.load(Ordering::SeqCst), 2);
        assert_eq!(cache.metrics().entries, 0);
        assert_eq!(cache.metrics().compiles, 0);
    }

    #[test]
    fn completion_failure_does_not_publish_cache_entry() {
        let cache = ModuleCache::new(engine(), 64, 128 * 1024 * 1024);
        let loads = Arc::new(AtomicUsize::new(0));
        let canceled = Cancellation::new();
        let first_loads = Arc::clone(&loads);
        let error = cache
            .get_or_compile_with_hooks(
                "sha256:completion-failure",
                ABI_VERSION,
                &canceled,
                CompileFlightHooks::new(
                    || Ok(()),
                    || Err(ModuleCacheError::Load("publish completion".to_string())),
                ),
                move || {
                    first_loads.fetch_add(1, Ordering::SeqCst);
                    Ok(worker_module())
                },
            )
            .expect_err("failed completion must fail the compile flight");
        assert_eq!(
            error,
            ModuleCacheError::Load("publish completion".to_string())
        );

        let retry_loads = Arc::clone(&loads);
        cache
            .get_or_compile(
                "sha256:completion-failure",
                ABI_VERSION,
                &canceled,
                move || {
                    retry_loads.fetch_add(1, Ordering::SeqCst);
                    Ok(worker_module())
                },
            )
            .expect("retry compiles after completion failure");
        assert_eq!(loads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn source_larger_than_cache_budget_is_rejected() {
        let source = worker_module();
        let cache = ModuleCache::new(engine(), 64, source.len() - 1);
        let canceled = Cancellation::new();
        let error = cache
            .get_or_compile("sha256:oversized", ABI_VERSION, &canceled, move || {
                Ok(source)
            })
            .expect_err("source outside the cache budget must not execute uncached");
        assert!(matches!(error, ModuleCacheError::Invalid(_)));
        assert_eq!(cache.metrics().entries, 0);
        assert_eq!(cache.metrics().compiles, 0);
    }

    #[test]
    fn failed_completion_keeps_followers_on_the_registered_flight() {
        let cache = Arc::new(ModuleCache::new(engine(), 64, 128 * 1024 * 1024));
        let canceled = Cancellation::new();
        let completion_started = Arc::new(Barrier::new(2));
        let release_completion = Arc::new(Barrier::new(2));
        let retry_loads = Arc::new(AtomicUsize::new(0));

        let leader = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&canceled);
            let completion_started = Arc::clone(&completion_started);
            let release_completion = Arc::clone(&release_completion);
            thread::spawn(move || {
                cache.get_or_compile_with_hooks(
                    "sha256:completion-window",
                    ABI_VERSION,
                    &canceled,
                    CompileFlightHooks::new(
                        || Ok(()),
                        move || {
                            completion_started.wait();
                            release_completion.wait();
                            Err(ModuleCacheError::Load(
                                "publish completion window".to_string(),
                            ))
                        },
                    ),
                    || Ok(worker_module()),
                )
            })
        };
        completion_started.wait();
        let follower = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&canceled);
            let retry_loads = Arc::clone(&retry_loads);
            thread::spawn(move || {
                cache.get_or_compile(
                    "sha256:completion-window",
                    ABI_VERSION,
                    &canceled,
                    move || {
                        retry_loads.fetch_add(1, Ordering::SeqCst);
                        Ok(worker_module())
                    },
                )
            })
        };
        let join_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while canceled.waiter_count() != 2 && std::time::Instant::now() < join_deadline {
            thread::yield_now();
        }
        assert_eq!(
            canceled.waiter_count(),
            2,
            "leader and follower must both wait on the registered flight"
        );
        assert_eq!(
            retry_loads.load(Ordering::SeqCst),
            0,
            "a second leader started before the registered flight published its result"
        );
        release_completion.wait();
        assert_eq!(
            leader.join().unwrap().unwrap_err(),
            ModuleCacheError::Load("publish completion window".to_string())
        );
        assert_eq!(
            follower.join().unwrap().unwrap_err(),
            ModuleCacheError::Load("publish completion window".to_string())
        );
        assert_eq!(retry_loads.load(Ordering::SeqCst), 0);

        let retry_loads_after_completion = Arc::clone(&retry_loads);
        cache
            .get_or_compile(
                "sha256:completion-window",
                ABI_VERSION,
                &canceled,
                move || {
                    retry_loads_after_completion.fetch_add(1, Ordering::SeqCst);
                    Ok(worker_module())
                },
            )
            .expect("a new caller retries after the failed flight is fully published");
        assert_eq!(retry_loads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_flight_is_removed_before_completion_is_published() {
        let cache = Arc::new(ModuleCache::new(engine(), 64, 128 * 1024 * 1024));
        let canceled = Cancellation::new();
        let load_started = Arc::new(Barrier::new(2));
        let release_load = Arc::new(Barrier::new(2));
        let (load_returned_sender, load_returned_receiver) = std::sync::mpsc::channel();

        let caller = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&canceled);
            let load_started = Arc::clone(&load_started);
            let release_load = Arc::clone(&release_load);
            thread::spawn(move || {
                cache.get_or_compile(
                    "sha256:ordered-failure",
                    ABI_VERSION,
                    &canceled,
                    move || {
                        load_started.wait();
                        release_load.wait();
                        load_returned_sender.send(()).unwrap();
                        Ok(b"not wasm".to_vec())
                    },
                )
            })
        };
        load_started.wait();

        let state = cache.state.lock().expect("module cache mutex");
        let flight = Arc::clone(
            state
                .flights
                .values()
                .next()
                .expect("compile flight is registered"),
        );
        release_load.wait();
        load_returned_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("compile input returned");
        thread::sleep(Duration::from_millis(20));
        assert!(
            flight
                .result
                .lock()
                .expect("compile flight mutex")
                .is_none(),
            "failed completion became visible before the flight table deletion"
        );
        drop(state);

        assert!(matches!(
            caller.join().expect("compile caller completes"),
            Err(ModuleCacheError::Invalid(_))
        ));
        assert!(
            cache
                .state
                .lock()
                .expect("module cache mutex")
                .flights
                .is_empty()
        );
    }

    #[test]
    fn leader_cancellation_does_not_fail_other_waiters() {
        let cache = Arc::new(ModuleCache::new(engine(), 64, 128 * 1024 * 1024));
        let leader_canceled = Cancellation::new();
        let waiter_canceled = Cancellation::new();
        let load_started = Arc::new(Barrier::new(2));
        let release_load = Arc::new(Barrier::new(2));

        let leader = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&leader_canceled);
            let load_started = Arc::clone(&load_started);
            let release_load = Arc::clone(&release_load);
            thread::spawn(move || {
                cache.get_or_compile("sha256:cancel", ABI_VERSION, &canceled, move || {
                    load_started.wait();
                    release_load.wait();
                    Ok(worker_module())
                })
            })
        };
        load_started.wait();
        let waiter = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&waiter_canceled);
            thread::spawn(move || {
                cache.get_or_compile("sha256:cancel", ABI_VERSION, &canceled, || {
                    panic!("waiter must join the existing compile flight")
                })
            })
        };
        leader_canceled.cancel();
        let started = std::time::Instant::now();
        let leader_result = leader.join().unwrap();
        assert!(matches!(leader_result, Err(ModuleCacheError::Canceled)));
        assert_eq!(leader_canceled.waiter_count(), 0);
        assert!(started.elapsed() < Duration::from_millis(100));
        release_load.wait();
        assert!(waiter.join().unwrap().is_ok());
        assert_eq!(cache.metrics().compiles, 1);
    }

    #[test]
    fn canceled_waiter_releases_without_canceling_compile_flight() {
        let cache = Arc::new(ModuleCache::new(engine(), 64, 128 * 1024 * 1024));
        let leader_canceled = Cancellation::new();
        let waiter_canceled = Cancellation::new();
        let load_started = Arc::new(Barrier::new(2));
        let release_load = Arc::new(Barrier::new(2));
        let leader = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&leader_canceled);
            let load_started = Arc::clone(&load_started);
            let release_load = Arc::clone(&release_load);
            thread::spawn(move || {
                cache.get_or_compile("sha256:waiter", ABI_VERSION, &canceled, move || {
                    load_started.wait();
                    release_load.wait();
                    Ok(worker_module())
                })
            })
        };
        load_started.wait();
        let waiter = {
            let cache = Arc::clone(&cache);
            let canceled = Arc::clone(&waiter_canceled);
            thread::spawn(move || {
                cache.get_or_compile("sha256:waiter", ABI_VERSION, &canceled, || {
                    panic!("waiter must join the existing compile flight")
                })
            })
        };
        waiter_canceled.cancel();
        let started = std::time::Instant::now();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(ModuleCacheError::Canceled)
        ));
        assert_eq!(waiter_canceled.waiter_count(), 0);
        assert!(started.elapsed() < Duration::from_millis(100));
        release_load.wait();
        assert!(leader.join().unwrap().is_ok());
        assert_eq!(cache.metrics().compiles, 1);
    }

    #[test]
    fn indexed_eviction_performance_evidence() {
        const ENTRY_COUNT: usize = 10_000;
        const MAX_ENTRIES: usize = 128;
        let source = worker_module();
        let cache = ModuleCache::new(engine(), MAX_ENTRIES, source.len() * ENTRY_COUNT * 2);
        let compiled = cache.compile_module(|| Ok(source)).unwrap();
        let mut state = cache.state.lock().expect("module cache mutex poisoned");
        for index in 0..ENTRY_COUNT {
            let key = ModuleKey {
                artifact_sha256: format!("sha256:{index:064x}"),
                wasm_abi_version: ABI_VERSION.to_string(),
            };
            let last_used = index as u64 + 1;
            state.entries.insert(
                key.clone(),
                CacheEntry {
                    compiled: compiled.clone(),
                    last_used,
                },
            );
            assert!(state.recency.insert((last_used, key)));
            state.source_bytes += compiled.source_bytes;
        }
        cache.evict_locked(&mut state);
        let evicted = ENTRY_COUNT - MAX_ENTRIES;
        assert_eq!(state.entries.len(), MAX_ENTRIES);
        assert_eq!(state.recency.len(), MAX_ENTRIES);
        assert_eq!(state.eviction_index_pops, evicted as u64);
        let pops_per_eviction = state.eviction_index_pops as f64 / evicted as f64 * 10_000.0;
        crate::performance_evidence::record(serde_json::json!({
            "id": "runtime.module-cache-indexed-eviction",
            "sample_count": ENTRY_COUNT,
            "metrics": [
                {
                    "name": "index_pops_per_eviction",
                    "unit": "basis_points",
                    "observed": pops_per_eviction,
                    "limit": 10_000,
                    "comparator": "eq"
                },
                {
                    "name": "remaining_entries",
                    "unit": "count",
                    "observed": state.entries.len(),
                    "limit": MAX_ENTRIES,
                    "comparator": "eq"
                }
            ]
        }));
    }

    fn engine() -> wasmi::Engine {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        wasmi::Engine::new(&config)
    }

    fn worker_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64) i64.const 0))"#,
        )
        .expect("valid worker module")
    }
}

#[cfg(test)]
mod property_gates {
    use super::*;
    use proptest::prelude::*;

    const ABI_VERSION: &str = "redevplugin-wasm-worker-v2";

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn module_cache_respects_entry_and_source_budgets(
            max_entries in 1usize..=8,
            key_suffixes in prop::collection::vec("[a-z][a-z0-9]{0,8}", 1..=16),
        ) {
            let source = property_worker_module();
            let budget = source.len() * max_entries.max(1);
            let cache = ModuleCache::new(property_engine(), max_entries, budget);
            for (index, suffix) in key_suffixes.into_iter().enumerate() {
                let source = source.clone();
                let cancellation = Cancellation::new();
                let _ = cache.get_or_compile(
                    &format!("sha256:{index}:{suffix}"),
                    ABI_VERSION,
                    &cancellation,
                    move || Ok(source),
                );
                let metrics = cache.metrics();
                prop_assert!(metrics.entries <= max_entries);
                prop_assert!(metrics.source_bytes <= budget);
            }
        }
    }

    fn property_engine() -> wasmi::Engine {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        wasmi::Engine::new(&config)
    }

    fn property_worker_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "redevplugin_worker_dealloc") (param i32 i32))
                (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64) i64.const 0))"#,
        )
        .expect("valid worker module")
    }
}
