use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleCacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub compiles: u64,
    pub entries: usize,
    pub source_bytes: usize,
}

pub struct ModuleCache {
    engine: wasmi::Engine,
    max_entries: usize,
    max_source_bytes: usize,
    state: Mutex<ModuleCacheState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleCacheError {
    Load(String),
    Invalid(String),
}

impl std::fmt::Display for ModuleCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

#[derive(Default)]
struct ModuleCacheState {
    entries: HashMap<ModuleKey, CacheEntry>,
    flights: HashMap<ModuleKey, Arc<CompileFlight>>,
    tick: u64,
    source_bytes: usize,
    hits: u64,
    misses: u64,
    compiles: u64,
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleKey {
    artifact_sha256: String,
    wasm_abi_version: String,
}

struct CacheEntry {
    module: Arc<wasmi::Module>,
    source_bytes: usize,
    last_used: u64,
}

struct CompileFlight {
    result: Mutex<Option<Result<Arc<wasmi::Module>, ModuleCacheError>>>,
    ready: Condvar,
}

impl CompileFlight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<Arc<wasmi::Module>, ModuleCacheError>) {
        *self.result.lock().expect("compile flight mutex poisoned") = Some(result);
        self.ready.notify_all();
    }

    fn wait(&self) -> Result<Arc<wasmi::Module>, ModuleCacheError> {
        let mut result = self.result.lock().expect("compile flight mutex poisoned");
        while result.is_none() {
            result = self
                .ready
                .wait(result)
                .expect("compile flight mutex poisoned while waiting");
        }
        result
            .as_ref()
            .expect("compile flight result exists")
            .clone()
    }
}

impl ModuleCache {
    pub fn new(engine: wasmi::Engine, max_entries: usize, max_source_bytes: usize) -> Self {
        Self {
            engine,
            max_entries,
            max_source_bytes,
            state: Mutex::new(ModuleCacheState::default()),
        }
    }

    pub fn engine(&self) -> &wasmi::Engine {
        &self.engine
    }

    pub fn get_or_compile(
        &self,
        artifact_sha256: &str,
        wasm_abi_version: &str,
        load: impl FnOnce() -> Result<(Vec<u8>, String), ModuleCacheError>,
    ) -> Result<Arc<wasmi::Module>, ModuleCacheError> {
        let key = ModuleKey {
            artifact_sha256: artifact_sha256.to_string(),
            wasm_abi_version: wasm_abi_version.to_string(),
        };
        let flight = {
            let mut state = self.state.lock().expect("module cache mutex poisoned");
            state.tick += 1;
            let tick = state.tick;
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.last_used = tick;
                let module = Arc::clone(&entry.module);
                state.hits += 1;
                return Ok(module);
            }
            state.misses += 1;
            if let Some(flight) = state.flights.get(&key) {
                Arc::clone(flight)
            } else {
                let flight = Arc::new(CompileFlight::new());
                state.flights.insert(key.clone(), Arc::clone(&flight));
                drop(state);
                let result = load().and_then(|(source, export_name)| {
                    redevplugin_wasm_abi::validate_worker_module(&source, &export_name)
                        .map_err(ModuleCacheError::Invalid)?;
                    let module = wasmi::Module::new(&self.engine, &source).map_err(|err| {
                        ModuleCacheError::Invalid(format!("compile wasm worker module: {err}"))
                    })?;
                    let module = Arc::new(module);
                    let mut state = self.state.lock().expect("module cache mutex poisoned");
                    state.compiles += 1;
                    if source.len() <= self.max_source_bytes {
                        state.tick += 1;
                        let last_used = state.tick;
                        state.source_bytes += source.len();
                        state.entries.insert(
                            key.clone(),
                            CacheEntry {
                                module: Arc::clone(&module),
                                source_bytes: source.len(),
                                last_used,
                            },
                        );
                        self.evict_locked(&mut state);
                    }
                    Ok(module)
                });
                let mut state = self.state.lock().expect("module cache mutex poisoned");
                state.flights.remove(&key);
                drop(state);
                flight.complete(result.clone());
                return result;
            }
        };
        flight.wait()
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
            let Some(key) = state
                .entries
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_used
                        .cmp(&right.last_used)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = state.entries.remove(&key) {
                state.source_bytes -= entry.source_bytes;
            }
        }
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
    const EXPORT_NAME: &str = "redevplugin_worker_invoke";

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
                cache
                    .get_or_compile("sha256:a", ABI_VERSION, || {
                        loads.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(20));
                        Ok((worker_module(), EXPORT_NAME.to_string()))
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
                .all(|module| Arc::ptr_eq(module, &modules[0]))
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
        let loads = AtomicUsize::new(0);
        cache
            .get_or_compile("sha256:a", ABI_VERSION, || {
                loads.fetch_add(1, Ordering::SeqCst);
                Ok((worker_module(), EXPORT_NAME.to_string()))
            })
            .expect("initial module compiles");
        cache
            .get_or_compile("sha256:a", ABI_VERSION, || {
                loads.fetch_add(1, Ordering::SeqCst);
                Err(ModuleCacheError::Load("unexpected reload".to_string()))
            })
            .expect("cached module loads");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(cache.metrics().hits, 1);
    }

    #[test]
    fn evicts_least_recently_used_module_deterministically() {
        let cache = ModuleCache::new(engine(), 2, 128 * 1024 * 1024);
        let loads = AtomicUsize::new(0);
        let load = |key: &str| {
            cache
                .get_or_compile(key, ABI_VERSION, || {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok((worker_module(), EXPORT_NAME.to_string()))
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
    fn compile_failure_is_not_cached() {
        let cache = ModuleCache::new(engine(), 64, 128 * 1024 * 1024);
        let loads = AtomicUsize::new(0);
        for _ in 0..2 {
            let error = cache
                .get_or_compile("sha256:invalid", ABI_VERSION, || {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok((b"not wasm".to_vec(), EXPORT_NAME.to_string()))
                })
                .expect_err("invalid module must fail");
            assert!(matches!(error, ModuleCacheError::Invalid(_)));
        }
        assert_eq!(loads.load(Ordering::SeqCst), 2);
        assert_eq!(cache.metrics().entries, 0);
        assert_eq!(cache.metrics().compiles, 0);
    }

    fn engine() -> wasmi::Engine {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        wasmi::Engine::new(&config)
    }

    fn worker_module() -> Vec<u8> {
        wat::parse_str(format!(
            "(module (func (export \"{EXPORT_NAME}\") (param i32 i32) (result i64) i64.const 0))"
        ))
        .expect("valid worker module")
    }
}
