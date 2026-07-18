use redevplugin_ipc::ParsedWorkerInvocation;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, Weak};

type CancellationNotifier = Arc<dyn Fn() + Send + Sync>;
const RECENT_REQUEST_REPLAY_CAPACITY: usize = 1024;
const QUEUE_TOMBSTONE_COMPACT_MIN: usize = 16;
const ORDER_TOMBSTONE_COMPACT_MIN: usize = 16;

pub struct Cancellation {
    canceled: AtomicBool,
    state: Mutex<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    next_registration_id: u64,
    registrations: HashMap<u64, CancellationNotifier>,
}

pub struct CancellationRegistration {
    cancellation: Weak<Cancellation>,
    registration_id: Option<u64>,
}

impl Cancellation {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            canceled: AtomicBool::new(false),
            state: Mutex::new(CancellationState::default()),
        })
    }

    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        let notifications = {
            let mut state = self.state.lock().expect("cancellation mutex poisoned");
            if self.canceled.swap(true, Ordering::AcqRel) {
                return;
            }
            state
                .registrations
                .drain()
                .map(|(_, notify)| notify)
                .collect::<Vec<_>>()
        };
        for notify in notifications {
            notify();
        }
    }

    pub fn register(
        self: &Arc<Self>,
        notify: impl Fn() + Send + Sync + 'static,
    ) -> CancellationRegistration {
        let mut state = self.state.lock().expect("cancellation mutex poisoned");
        if self.canceled.load(Ordering::Acquire) {
            return CancellationRegistration {
                cancellation: Arc::downgrade(self),
                registration_id: None,
            };
        }
        state.next_registration_id = state
            .next_registration_id
            .checked_add(1)
            .expect("cancellation registration id exhausted");
        let registration_id = state.next_registration_id;
        state
            .registrations
            .insert(registration_id, Arc::new(notify));
        CancellationRegistration {
            cancellation: Arc::downgrade(self),
            registration_id: Some(registration_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn waiter_count(&self) -> usize {
        self.state
            .lock()
            .expect("cancellation mutex poisoned")
            .registrations
            .len()
    }
}

impl Drop for CancellationRegistration {
    fn drop(&mut self) {
        let Some(registration_id) = self.registration_id.take() else {
            return;
        };
        let Some(cancellation) = self.cancellation.upgrade() else {
            return;
        };
        cancellation
            .state
            .lock()
            .expect("cancellation mutex poisoned")
            .registrations
            .remove(&registration_id);
    }
}

pub enum InvocationSignal {
    HostcallResponse(String),
    Canceled,
}

pub struct InvocationJob {
    pub request_id: String,
    pub plugin_instance_id: String,
    pub invocation: Arc<ParsedWorkerInvocation>,
    pub cancellation: Arc<Cancellation>,
    pub signal_sender: Sender<InvocationSignal>,
    pub signals: Receiver<InvocationSignal>,
}

impl std::fmt::Debug for InvocationJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvocationJob")
            .field("request_id", &self.request_id)
            .field("plugin_instance_id", &self.plugin_instance_id)
            .field("canceled", &self.cancellation.is_canceled())
            .finish_non_exhaustive()
    }
}

impl InvocationJob {
    pub fn new(invocation: ParsedWorkerInvocation) -> Result<Self, String> {
        let (signal_sender, signals) = mpsc::channel();
        let request_id = invocation.request_id().to_string();
        let plugin_instance_id = invocation
            .plugin_instance_id()
            .map_err(|err| format!("runtime IPC contract error: {err}"))?
            .to_string();
        Ok(Self {
            request_id,
            plugin_instance_id,
            invocation: Arc::new(invocation),
            cancellation: Cancellation::new(),
            signal_sender,
            signals,
        })
    }
}

pub enum CancelDisposition {
    Queued(InvocationJob),
    Running,
    Complete,
    Missing,
}

#[derive(Debug)]
pub enum EnqueueError {
    Capacity,
    PluginCapacity,
    Duplicate,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerMetrics {
    pub active: usize,
    pub queued: usize,
}

pub struct InvocationScheduler {
    limits: SchedulerLimits,
    state: Mutex<SchedulerState>,
    available: Condvar,
}

#[derive(Clone, Copy)]
struct SchedulerLimits {
    queue_capacity: usize,
    per_plugin_concurrency: usize,
    per_plugin_capacity: usize,
}

#[derive(Default)]
struct SchedulerState {
    queues: HashMap<String, PluginQueue>,
    order: VecDeque<QueueToken>,
    queued_by_request: HashMap<String, InvocationJob>,
    active: HashMap<String, ActiveInvocation>,
    active_by_plugin: HashMap<String, usize>,
    recent_request_ids: HashSet<String>,
    recent_request_order: VecDeque<String>,
    next_queue_generation: u64,
    stale_order_tokens: usize,
    queued: usize,
    shutdown: bool,
}

struct PluginQueue {
    request_ids: VecDeque<String>,
    live: usize,
    tombstones: usize,
    generation: u64,
}

struct QueueToken {
    plugin_instance_id: String,
    generation: u64,
}

struct ActiveInvocation {
    plugin_instance_id: String,
    cancellation: Arc<Cancellation>,
    signal_sender: Sender<InvocationSignal>,
}

impl InvocationScheduler {
    pub fn new(queue_capacity: usize, per_plugin_concurrency: usize) -> Self {
        Self {
            limits: SchedulerLimits {
                queue_capacity,
                per_plugin_concurrency,
                per_plugin_capacity: per_plugin_concurrency
                    + queue_capacity.min(per_plugin_concurrency),
            },
            state: Mutex::new(SchedulerState::default()),
            available: Condvar::new(),
        }
    }

    pub fn enqueue(&self, job: InvocationJob) -> Result<(), EnqueueError> {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        if state.shutdown {
            return Err(EnqueueError::Shutdown);
        }
        if state.queued >= self.limits.queue_capacity {
            return Err(EnqueueError::Capacity);
        }
        let plugin_active = state
            .active_by_plugin
            .get(&job.plugin_instance_id)
            .copied()
            .unwrap_or_default();
        let plugin_queued = state
            .queues
            .get(&job.plugin_instance_id)
            .map(|queue| queue.live)
            .unwrap_or_default();
        if plugin_active.saturating_add(plugin_queued) >= self.limits.per_plugin_capacity {
            return Err(EnqueueError::PluginCapacity);
        }
        if state.active.contains_key(&job.request_id)
            || state.recent_request_ids.contains(&job.request_id)
            || state.queued_by_request.contains_key(&job.request_id)
        {
            return Err(EnqueueError::Duplicate);
        }
        let plugin_instance_id = job.plugin_instance_id.clone();
        let request_id = job.request_id.clone();
        if let Some(queue) = state.queues.get_mut(&plugin_instance_id) {
            queue.request_ids.push_back(request_id.clone());
            queue.live += 1;
        } else {
            state.next_queue_generation = state
                .next_queue_generation
                .checked_add(1)
                .expect("scheduler queue generation exhausted");
            let generation = state.next_queue_generation;
            state.queues.insert(
                plugin_instance_id.clone(),
                PluginQueue {
                    request_ids: VecDeque::from([request_id.clone()]),
                    live: 1,
                    tombstones: 0,
                    generation,
                },
            );
            state.order.push_back(QueueToken {
                plugin_instance_id,
                generation,
            });
        }
        state.queued_by_request.insert(request_id, job);
        state.queued += 1;
        self.available.notify_all();
        Ok(())
    }

    pub fn take(&self) -> Option<InvocationJob> {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        loop {
            let plugin_count = state.order.len();
            for _ in 0..plugin_count {
                let token = state.order.pop_front()?;
                let plugin_instance_id = token.plugin_instance_id;
                let valid_token = state
                    .queues
                    .get(&plugin_instance_id)
                    .is_some_and(|queue| queue.generation == token.generation);
                if !valid_token {
                    state.stale_order_tokens = state
                        .stale_order_tokens
                        .checked_sub(1)
                        .expect("stale scheduler order token is counted");
                    continue;
                };
                let active = state
                    .active_by_plugin
                    .get(&plugin_instance_id)
                    .copied()
                    .unwrap_or_default();
                if active >= self.limits.per_plugin_concurrency {
                    state.order.push_back(QueueToken {
                        plugin_instance_id,
                        generation: token.generation,
                    });
                    continue;
                }
                let job = loop {
                    let request_id = state
                        .queues
                        .get_mut(&plugin_instance_id)
                        .expect("scheduler order references a queue")
                        .request_ids
                        .pop_front()
                        .expect("scheduler live queue is not empty");
                    if let Some(job) = state.queued_by_request.remove(&request_id) {
                        break job;
                    }
                    let queue = state
                        .queues
                        .get_mut(&plugin_instance_id)
                        .expect("scheduler order references a queue");
                    queue.tombstones = queue
                        .tombstones
                        .checked_sub(1)
                        .expect("queued request tombstone is counted");
                };
                let queue = state
                    .queues
                    .get_mut(&plugin_instance_id)
                    .expect("scheduler order references a queue");
                queue.live -= 1;
                if queue.live == 0 {
                    state.queues.remove(&plugin_instance_id);
                } else {
                    state.order.push_back(QueueToken {
                        plugin_instance_id: plugin_instance_id.clone(),
                        generation: token.generation,
                    });
                }
                state.queued -= 1;
                *state
                    .active_by_plugin
                    .entry(plugin_instance_id.clone())
                    .or_default() += 1;
                state.active.insert(
                    job.request_id.clone(),
                    ActiveInvocation {
                        plugin_instance_id,
                        cancellation: Arc::clone(&job.cancellation),
                        signal_sender: job.signal_sender.clone(),
                    },
                );
                return Some(job);
            }
            if state.shutdown {
                return None;
            }
            state = self
                .available
                .wait(state)
                .expect("scheduler mutex poisoned while waiting");
        }
    }

    pub fn finish(&self, request_id: &str) {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        if let Some(active) = state.active.remove(request_id) {
            let count = state
                .active_by_plugin
                .get_mut(&active.plugin_instance_id)
                .expect("active plugin count exists");
            *count -= 1;
            if *count == 0 {
                state.active_by_plugin.remove(&active.plugin_instance_id);
            }
        }
        Self::remember_recent_request_id(&mut state, request_id);
        self.available.notify_all();
    }

    pub fn cancel(&self, request_id: &str) -> CancelDisposition {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        if let Some(job) = state.queued_by_request.remove(request_id) {
            let plugin_instance_id = job.plugin_instance_id.clone();
            let queue_empty = {
                let queue = state
                    .queues
                    .get_mut(&plugin_instance_id)
                    .expect("queued invocation references a plugin queue");
                queue.live -= 1;
                queue.tombstones += 1;
                queue.live == 0
            };
            state.queued -= 1;
            if queue_empty {
                state.queues.remove(&plugin_instance_id);
                state.stale_order_tokens += 1;
            } else {
                Self::compact_plugin_queue(&mut state, &plugin_instance_id);
            }
            Self::compact_order(&mut state);
            Self::remember_recent_request_id(&mut state, &job.request_id);
            drop(state);
            job.cancellation.cancel();
            return CancelDisposition::Queued(job);
        }
        if let Some(active) = state.active.get(request_id) {
            let cancellation = Arc::clone(&active.cancellation);
            let signal_sender = active.signal_sender.clone();
            drop(state);
            cancellation.cancel();
            let _ = signal_sender.send(InvocationSignal::Canceled);
            return CancelDisposition::Running;
        }
        if state.recent_request_ids.contains(request_id) {
            return CancelDisposition::Complete;
        }
        CancelDisposition::Missing
    }

    fn compact_plugin_queue(state: &mut SchedulerState, plugin_instance_id: &str) {
        let should_compact = state.queues.get(plugin_instance_id).is_some_and(|queue| {
            queue.tombstones >= QUEUE_TOMBSTONE_COMPACT_MIN && queue.tombstones > queue.live
        });
        if !should_compact {
            return;
        }
        let SchedulerState {
            queues,
            queued_by_request,
            ..
        } = state;
        let queue = queues
            .get_mut(plugin_instance_id)
            .expect("scheduler plugin queue exists for compaction");
        queue
            .request_ids
            .retain(|request_id| queued_by_request.contains_key(request_id));
        queue.tombstones = 0;
    }

    fn compact_order(state: &mut SchedulerState) {
        if state.stale_order_tokens < ORDER_TOMBSTONE_COMPACT_MIN
            || state.stale_order_tokens * 2 < state.order.len()
        {
            return;
        }
        state.order.retain(|token| {
            state
                .queues
                .get(&token.plugin_instance_id)
                .is_some_and(|queue| queue.generation == token.generation)
        });
        state.stale_order_tokens = 0;
    }

    fn remember_recent_request_id(state: &mut SchedulerState, request_id: &str) {
        if state.recent_request_ids.insert(request_id.to_string()) {
            state.recent_request_order.push_back(request_id.to_string());
            while state.recent_request_order.len() > RECENT_REQUEST_REPLAY_CAPACITY {
                if let Some(oldest) = state.recent_request_order.pop_front() {
                    state.recent_request_ids.remove(&oldest);
                }
            }
        }
    }

    pub fn signal(&self, request_id: &str, signal: InvocationSignal) -> bool {
        let state = self.state.lock().expect("scheduler mutex poisoned");
        state
            .active
            .get(request_id)
            .is_some_and(|active| active.signal_sender.send(signal).is_ok())
    }

    pub fn metrics(&self) -> SchedulerMetrics {
        let state = self.state.lock().expect("scheduler mutex poisoned");
        SchedulerMetrics {
            active: state.active.len(),
            queued: state.queued,
        }
    }

    pub fn shutdown(&self) -> Vec<InvocationJob> {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        state.shutdown = true;
        let mut plugin_instance_ids = state.queues.keys().cloned().collect::<Vec<_>>();
        plugin_instance_ids.sort_unstable();
        let mut canceled = Vec::with_capacity(state.queued);
        for plugin_instance_id in plugin_instance_ids {
            let queue = state
                .queues
                .remove(&plugin_instance_id)
                .expect("shutdown plugin queue exists");
            for request_id in queue.request_ids {
                if let Some(job) = state.queued_by_request.remove(&request_id) {
                    canceled.push(job);
                }
            }
        }
        debug_assert!(state.queued_by_request.is_empty());
        for job in &canceled {
            job.cancellation.cancel();
        }
        for active in state.active.values() {
            active.cancellation.cancel();
            let _ = active.signal_sender.send(InvocationSignal::Canceled);
        }
        state.order.clear();
        state.stale_order_tokens = 0;
        state.queued = 0;
        self.available.notify_all();
        canceled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn cancellation_notifies_registered_waiter_once_and_releases_registration() {
        let cancellation = Cancellation::new();
        let notified = Arc::new((Mutex::new(false), Condvar::new()));
        let notifications = Arc::new(AtomicUsize::new(0));
        let waiter_notified = Arc::clone(&notified);
        let waiter_notifications = Arc::clone(&notifications);
        let registration = cancellation.register(move || {
            waiter_notifications.fetch_add(1, Ordering::SeqCst);
            let (lock, ready) = &*waiter_notified;
            *lock.lock().unwrap() = true;
            ready.notify_all();
        });
        assert_eq!(cancellation.waiter_count(), 1);

        cancellation.cancel();
        let (lock, ready) = &*notified;
        let observed = ready
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(1), |value| {
                !*value
            })
            .unwrap();
        assert!(*observed.0);
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
        assert_eq!(cancellation.waiter_count(), 0);

        drop(registration);
        cancellation.cancel();
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rotates_plugins_while_respecting_per_plugin_concurrency() {
        let scheduler = InvocationScheduler::new(8, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        let first = scheduler.take().unwrap();
        for (request, plugin) in [("a2", "a"), ("b1", "b")] {
            scheduler.enqueue(job(request, plugin)).unwrap();
        }
        let second = scheduler.take().unwrap();
        assert_eq!(first.request_id, "a1");
        assert_eq!(second.request_id, "b1");
        scheduler.finish(&first.request_id);
        assert_eq!(scheduler.take().unwrap().request_id, "a2");
    }

    #[test]
    fn removes_queued_invocation_on_cancel() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        assert!(matches!(
            scheduler.cancel("a1"),
            CancelDisposition::Queued(_)
        ));
        assert_eq!(scheduler.metrics().queued, 0);
    }

    #[test]
    fn queued_cancel_tombstones_request_id_against_replay() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        assert!(matches!(
            scheduler.cancel("a1"),
            CancelDisposition::Queued(_)
        ));

        assert!(matches!(
            scheduler.enqueue(job("a1", "a")),
            Err(EnqueueError::Duplicate)
        ));
    }

    #[test]
    fn queued_cancel_replay_tombstones_remain_bounded() {
        let scheduler = InvocationScheduler::new(2, 1);
        for index in 0..=RECENT_REQUEST_REPLAY_CAPACITY {
            let request_id = format!("queued-{index}");
            scheduler.enqueue(job(&request_id, "a")).unwrap();
            assert!(matches!(
                scheduler.cancel(&request_id),
                CancelDisposition::Queued(_)
            ));
        }

        scheduler
            .enqueue(job("queued-0", "a"))
            .expect("the oldest replay tombstone is evicted at the fixed capacity");
        assert!(matches!(
            scheduler.enqueue(job(
                &format!("queued-{RECENT_REQUEST_REPLAY_CAPACITY}"),
                "a"
            )),
            Err(EnqueueError::Duplicate)
        ));
    }

    #[test]
    fn rejects_work_beyond_queue_capacity() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        scheduler.enqueue(job("b1", "b")).unwrap();
        assert!(scheduler.enqueue(job("c1", "c")).is_err());
        assert_eq!(scheduler.metrics().queued, 2);
    }

    #[test]
    fn rejects_duplicate_request_ids_across_queued_and_completed_work() {
        let scheduler = InvocationScheduler::new(4, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        assert!(matches!(
            scheduler.enqueue(job("a1", "b")),
            Err(EnqueueError::Duplicate)
        ));
        let invocation = scheduler.take().unwrap();
        scheduler.finish(&invocation.request_id);
        assert!(matches!(
            scheduler.enqueue(job("a1", "a")),
            Err(EnqueueError::Duplicate)
        ));
    }

    #[test]
    fn plugin_queue_saturation_does_not_block_other_plugins() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a-running", "a")).unwrap();
        let running = scheduler.take().unwrap();
        scheduler.enqueue(job("a-queued", "a")).unwrap();
        assert!(matches!(
            scheduler.enqueue(job("a-overflow", "a")),
            Err(EnqueueError::PluginCapacity)
        ));
        scheduler.enqueue(job("b-ready", "b")).unwrap();
        assert_eq!(scheduler.take().unwrap().request_id, "b-ready");
        scheduler.finish(&running.request_id);
        assert_eq!(scheduler.take().unwrap().request_id, "a-queued");
    }

    #[test]
    fn burst_admission_matches_active_plus_reserved_plugin_capacity() {
        let scheduler = InvocationScheduler::new(32, 4);
        for index in 0..8 {
            scheduler
                .enqueue(job(&format!("a-{index}"), "a"))
                .expect("active and reserved queue capacity accepts the burst");
        }
        assert!(matches!(
            scheduler.enqueue(job("a-overflow", "a")),
            Err(EnqueueError::PluginCapacity)
        ));
        scheduler
            .enqueue(job("b-ready", "b"))
            .expect("another plugin retains admission capacity");
    }

    #[test]
    fn marks_running_invocation_canceled_and_notifies_worker() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        let invocation = scheduler.take().unwrap();
        assert!(matches!(scheduler.cancel("a1"), CancelDisposition::Running));
        assert!(invocation.cancellation.is_canceled());
        assert!(matches!(
            invocation.signals.recv().unwrap(),
            InvocationSignal::Canceled
        ));
        scheduler.finish("a1");
        assert_eq!(
            scheduler.metrics(),
            SchedulerMetrics {
                active: 0,
                queued: 0
            }
        );
    }

    #[test]
    fn queued_cancel_preserves_round_robin_order() {
        let scheduler = InvocationScheduler::new(4, 2);
        scheduler.enqueue(job("a1", "a")).unwrap();
        scheduler.enqueue(job("a2", "a")).unwrap();
        scheduler.enqueue(job("b1", "b")).unwrap();
        assert!(matches!(
            scheduler.cancel("a1"),
            CancelDisposition::Queued(_)
        ));
        assert_eq!(scheduler.take().unwrap().request_id, "a2");
        assert_eq!(scheduler.take().unwrap().request_id, "b1");
    }

    #[test]
    fn queued_cancel_compacts_request_tombstones() {
        let scheduler = InvocationScheduler::new(64, 64);
        for index in 0..64 {
            scheduler
                .enqueue(job(&format!("a-{index:02}"), "a"))
                .unwrap();
        }
        for index in 0..40 {
            assert!(matches!(
                scheduler.cancel(&format!("a-{index:02}")),
                CancelDisposition::Queued(_)
            ));
        }
        let state = scheduler.state.lock().unwrap();
        let queue = state.queues.get("a").unwrap();
        assert_eq!(queue.live, 24);
        assert!(queue.tombstones < QUEUE_TOMBSTONE_COMPACT_MIN);
        assert!(queue.request_ids.len() < queue.live + QUEUE_TOMBSTONE_COMPACT_MIN);
        drop(state);
        assert_eq!(scheduler.take().unwrap().request_id, "a-40");
    }

    #[test]
    fn queued_cancel_compacts_stale_round_robin_tokens() {
        let scheduler = InvocationScheduler::new(1, 1);
        for index in 0..128 {
            let request_id = format!("request-{index:03}");
            let plugin_instance_id = format!("plugin-{index:03}");
            scheduler
                .enqueue(job(&request_id, &plugin_instance_id))
                .unwrap();
            assert!(matches!(
                scheduler.cancel(&request_id),
                CancelDisposition::Queued(_)
            ));
        }
        let state = scheduler.state.lock().unwrap();
        assert!(state.queues.is_empty());
        assert!(state.stale_order_tokens < ORDER_TOMBSTONE_COMPACT_MIN);
        assert!(state.order.len() < ORDER_TOMBSTONE_COMPACT_MIN);
    }

    #[test]
    fn shutdown_preserves_plugin_and_fifo_order_while_skipping_tombstones() {
        let scheduler = InvocationScheduler::new(8, 2);
        for (request_id, plugin_instance_id) in [("b1", "b"), ("a1", "a"), ("a2", "a"), ("b2", "b")]
        {
            scheduler
                .enqueue(job(request_id, plugin_instance_id))
                .unwrap();
        }
        assert!(matches!(
            scheduler.cancel("a1"),
            CancelDisposition::Queued(_)
        ));
        let canceled = scheduler
            .shutdown()
            .into_iter()
            .map(|job| job.request_id)
            .collect::<Vec<_>>();
        assert_eq!(canceled, ["a2", "b1", "b2"]);
    }

    fn job(request_id: &str, plugin_instance_id: &str) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo"}}}}}}"#
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }
}

#[cfg(test)]
mod property_gates {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn scheduler_never_exceeds_configured_queue_capacity(
            queue_capacity in 1usize..=32,
            jobs in prop::collection::vec(("[a-z][a-z0-9]{0,4}", "[a-z][a-z0-9]{0,4}"), 0..64),
        ) {
            let scheduler = InvocationScheduler::new(queue_capacity.max(1), 1);
            for (index, (plugin, _suffix)) in jobs.into_iter().enumerate() {
                let request = format!("r{index}");
                let _ = scheduler.enqueue(property_job(&request, &plugin));
                prop_assert!(scheduler.metrics().queued <= queue_capacity);
            }
        }

        #[test]
        fn scheduler_round_robin_never_repeats_a_plugin_while_another_is_ready(
            first in "[a-z][a-z0-9]{0,4}",
            second in "[a-z][a-z0-9]{0,4}",
        ) {
            prop_assume!(first != second);
            let scheduler = InvocationScheduler::new(8, 1);
            scheduler.enqueue(property_job("first-1", &first)).unwrap();
            scheduler.enqueue(property_job("first-2", &first)).unwrap();
            scheduler.enqueue(property_job("second-1", &second)).unwrap();
            let first_job = scheduler.take().unwrap();
            let second_job = scheduler.take().unwrap();
            prop_assert_ne!(first_job.plugin_instance_id, second_job.plugin_instance_id);
        }
    }

    fn property_job(request_id: &str, plugin_instance_id: &str) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v4","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo"}}}}}}"#
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }
}
