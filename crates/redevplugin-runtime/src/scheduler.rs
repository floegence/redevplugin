use redevplugin_ipc::ParsedWorkerInvocation;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

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
    pub session_scope: Option<redevplugin_ipc::SessionScope>,
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
    pub fn new(invocation: ParsedWorkerInvocation) -> redevplugin_ipc::IpcResult<Self> {
        let (signal_sender, signals) = mpsc::channel();
        let request_id = invocation.request_id().to_string();
        let plugin_instance_id = invocation.plugin_instance_id()?.to_string();
        let session_scope = invocation.session_scope()?;
        Ok(Self {
            request_id,
            plugin_instance_id,
            session_scope,
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
    SessionRevoked,
}

pub struct SessionRevokeDisposition {
    pub queued: Vec<InvocationJob>,
    pub running_request_ids: Vec<String>,
}

pub struct InvocationCompletion {
    request_id: String,
    session_scope: Option<redevplugin_ipc::SessionScope>,
    suppress_response: bool,
}

impl InvocationCompletion {
    pub fn suppress_response(&self) -> bool {
        self.suppress_response
    }
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
    queued_by_session: HashMap<redevplugin_ipc::SessionScope, HashSet<String>>,
    active_by_session: HashMap<redevplugin_ipc::SessionScope, HashSet<String>>,
    publishing_by_session: HashMap<redevplugin_ipc::SessionScope, HashSet<String>>,
    revoked_sessions: HashSet<redevplugin_ipc::SessionScope>,
    active_by_plugin: HashMap<String, usize>,
    recent_request_ids: HashSet<String>,
    recent_request_order: VecDeque<String>,
    next_queue_generation: u64,
    stale_order_tokens: usize,
    queued: usize,
    shutdown: bool,
    #[cfg(test)]
    cancel_request_index_lookups: u64,
    #[cfg(test)]
    cancel_plugin_compaction_entries: u64,
    #[cfg(test)]
    cancel_order_compaction_entries: u64,
    #[cfg(test)]
    cancel_plugin_compactions: u64,
    #[cfg(test)]
    cancel_order_compactions: u64,
    #[cfg(test)]
    session_revoke_index_lookups: u64,
    #[cfg(test)]
    session_revoke_affected_requests: u64,
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
    session_scope: Option<redevplugin_ipc::SessionScope>,
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
        if job
            .session_scope
            .as_ref()
            .is_some_and(|scope| state.revoked_sessions.contains(scope))
        {
            return Err(EnqueueError::SessionRevoked);
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
        if let Some(scope) = job.session_scope.as_ref() {
            state
                .queued_by_session
                .entry(scope.clone())
                .or_default()
                .insert(request_id.clone());
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
                Self::remove_session_request(
                    &mut state.queued_by_session,
                    job.session_scope.as_ref(),
                    &job.request_id,
                );
                if let Some(scope) = job.session_scope.as_ref() {
                    state
                        .active_by_session
                        .entry(scope.clone())
                        .or_default()
                        .insert(job.request_id.clone());
                }
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
                        session_scope: job.session_scope.clone(),
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

    #[cfg(test)]
    pub fn finish(&self, request_id: &str) {
        let completion = self.begin_completion(request_id);
        self.end_completion(completion);
    }

    pub fn begin_completion(&self, request_id: &str) -> InvocationCompletion {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        let session_scope = if let Some(active) = state.active.remove(request_id) {
            Self::remove_session_request(
                &mut state.active_by_session,
                active.session_scope.as_ref(),
                request_id,
            );
            let count = state
                .active_by_plugin
                .get_mut(&active.plugin_instance_id)
                .expect("active plugin count exists");
            *count -= 1;
            if *count == 0 {
                state.active_by_plugin.remove(&active.plugin_instance_id);
            }
            active.session_scope
        } else {
            None
        };
        let suppress_response = session_scope
            .as_ref()
            .is_some_and(|scope| state.revoked_sessions.contains(scope));
        if let Some(scope) = session_scope.as_ref() {
            state
                .publishing_by_session
                .entry(scope.clone())
                .or_default()
                .insert(request_id.to_string());
        }
        Self::remember_recent_request_id(&mut state, request_id);
        self.available.notify_all();
        InvocationCompletion {
            request_id: request_id.to_string(),
            session_scope,
            suppress_response,
        }
    }

    pub fn end_completion(&self, completion: InvocationCompletion) {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        Self::remove_session_request(
            &mut state.publishing_by_session,
            completion.session_scope.as_ref(),
            &completion.request_id,
        );
        self.available.notify_all();
    }

    pub fn cancel(&self, request_id: &str) -> CancelDisposition {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        if let Some(job) = Self::remove_queued_request_for_cancel(&mut state, request_id) {
            Self::remove_session_request(
                &mut state.queued_by_session,
                job.session_scope.as_ref(),
                request_id,
            );
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

    fn remove_queued_request_for_cancel(
        state: &mut SchedulerState,
        request_id: &str,
    ) -> Option<InvocationJob> {
        #[cfg(test)]
        {
            state.cancel_request_index_lookups += 1;
        }
        state.queued_by_request.remove(request_id)
    }

    fn remove_session_request(
        index: &mut HashMap<redevplugin_ipc::SessionScope, HashSet<String>>,
        scope: Option<&redevplugin_ipc::SessionScope>,
        request_id: &str,
    ) {
        let Some(scope) = scope else {
            return;
        };
        let empty = index.get_mut(scope).is_some_and(|request_ids| {
            request_ids.remove(request_id);
            request_ids.is_empty()
        });
        if empty {
            index.remove(scope);
        }
    }

    pub fn revoke_session(
        &self,
        scope: &redevplugin_ipc::SessionScope,
    ) -> SessionRevokeDisposition {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        state.revoked_sessions.insert(scope.clone());

        #[cfg(test)]
        {
            state.session_revoke_index_lookups += 1;
        }

        let queued_request_ids = state.queued_by_session.remove(scope).unwrap_or_default();
        #[cfg(test)]
        {
            state.session_revoke_affected_requests += queued_request_ids.len() as u64;
        }
        let mut queued = Vec::with_capacity(queued_request_ids.len());
        let mut affected_plugins = HashSet::new();
        for request_id in queued_request_ids {
            let Some(job) = state.queued_by_request.remove(&request_id) else {
                continue;
            };
            let plugin_instance_id = job.plugin_instance_id.clone();
            let queue = state
                .queues
                .get_mut(&plugin_instance_id)
                .expect("session-indexed queued invocation references a plugin queue");
            queue.live -= 1;
            queue.tombstones += 1;
            state.queued -= 1;
            affected_plugins.insert(plugin_instance_id);
            Self::remember_recent_request_id(&mut state, &request_id);
            queued.push(job);
        }
        for plugin_instance_id in affected_plugins {
            if state
                .queues
                .get(&plugin_instance_id)
                .is_some_and(|queue| queue.live == 0)
            {
                state.queues.remove(&plugin_instance_id);
                state.stale_order_tokens += 1;
            }
        }
        Self::compact_order(&mut state);

        let mut running_request_ids = state
            .active_by_session
            .get(scope)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        running_request_ids.extend(
            state
                .publishing_by_session
                .get(scope)
                .into_iter()
                .flat_map(|request_ids| request_ids.iter().cloned()),
        );
        let cancellations = running_request_ids
            .iter()
            .filter_map(|request_id| state.active.get(request_id))
            .map(|active| {
                (
                    Arc::clone(&active.cancellation),
                    active.signal_sender.clone(),
                )
            })
            .collect::<Vec<_>>();
        drop(state);

        for job in &queued {
            job.cancellation.cancel();
        }
        for (cancellation, signal_sender) in cancellations {
            cancellation.cancel();
            let _ = signal_sender.send(InvocationSignal::Canceled);
        }
        self.available.notify_all();
        SessionRevokeDisposition {
            queued,
            running_request_ids,
        }
    }

    pub fn wait_session_drained(
        &self,
        scope: &redevplugin_ipc::SessionScope,
        timeout: Duration,
    ) -> bool {
        let state = self.state.lock().expect("scheduler mutex poisoned");
        let drained = self
            .available
            .wait_timeout_while(state, timeout, |state| {
                state
                    .active_by_session
                    .get(scope)
                    .is_some_and(|request_ids| !request_ids.is_empty())
                    || state
                        .publishing_by_session
                        .get(scope)
                        .is_some_and(|request_ids| !request_ids.is_empty())
            })
            .expect("scheduler mutex poisoned while draining session");
        let still_active = drained
            .0
            .active_by_session
            .get(scope)
            .is_some_and(|request_ids| !request_ids.is_empty());
        let still_publishing = drained
            .0
            .publishing_by_session
            .get(scope)
            .is_some_and(|request_ids| !request_ids.is_empty());
        !still_active && !still_publishing
    }

    fn compact_plugin_queue(state: &mut SchedulerState, plugin_instance_id: &str) {
        let should_compact = state.queues.get(plugin_instance_id).is_some_and(|queue| {
            queue.tombstones >= QUEUE_TOMBSTONE_COMPACT_MIN && queue.tombstones > queue.live
        });
        if !should_compact {
            return;
        }
        let _scanned_entries = {
            let SchedulerState {
                queues,
                queued_by_request,
                ..
            } = state;
            let queue = queues
                .get_mut(plugin_instance_id)
                .expect("scheduler plugin queue exists for compaction");
            let scanned_entries = queue.request_ids.len();
            queue
                .request_ids
                .retain(|request_id| queued_by_request.contains_key(request_id));
            queue.tombstones = 0;
            scanned_entries
        };
        #[cfg(test)]
        {
            state.cancel_plugin_compaction_entries += _scanned_entries as u64;
            state.cancel_plugin_compactions += 1;
        }
    }

    fn compact_order(state: &mut SchedulerState) {
        if state.stale_order_tokens < ORDER_TOMBSTONE_COMPACT_MIN
            || state.stale_order_tokens * 2 < state.order.len()
        {
            return;
        }
        let _scanned_entries = state.order.len();
        state.order.retain(|token| {
            state
                .queues
                .get(&token.plugin_instance_id)
                .is_some_and(|queue| queue.generation == token.generation)
        });
        state.stale_order_tokens = 0;
        #[cfg(test)]
        {
            state.cancel_order_compaction_entries += _scanned_entries as u64;
            state.cancel_order_compactions += 1;
        }
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
        state.queued_by_session.clear();
        state.active_by_session.clear();
        state.publishing_by_session.clear();
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
    fn session_revoke_uses_exact_index_and_fences_future_admission() {
        let scheduler = InvocationScheduler::new(8, 2);
        let exact = scope("session-a", "user-a", "env-a", "channel-a");
        scheduler
            .enqueue(session_job("exact-running", "plugin-a", &exact))
            .unwrap();
        let running = scheduler.take().unwrap();
        scheduler
            .enqueue(session_job("exact-queued", "plugin-b", &exact))
            .unwrap();
        let sibling = scope("session-a", "user-a", "env-a", "channel-b");
        scheduler
            .enqueue(session_job("sibling", "plugin-c", &sibling))
            .unwrap();

        let revoked = scheduler.revoke_session(&exact);
        assert_eq!(revoked.queued.len(), 1);
        assert_eq!(revoked.queued[0].request_id, "exact-queued");
        assert_eq!(revoked.running_request_ids, ["exact-running"]);
        assert!(running.cancellation.is_canceled());
        assert!(matches!(
            running.signals.recv().unwrap(),
            InvocationSignal::Canceled
        ));
        assert_eq!(scheduler.take().unwrap().request_id, "sibling");
        assert!(matches!(
            scheduler.enqueue(session_job("future", "plugin-a", &exact)),
            Err(EnqueueError::SessionRevoked)
        ));

        let replay = scheduler.revoke_session(&exact);
        assert!(replay.queued.is_empty());
        assert_eq!(replay.running_request_ids, ["exact-running"]);
        scheduler.finish("exact-running");
        assert!(scheduler.wait_session_drained(&exact, Duration::from_millis(1)));
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
    fn indexed_cancel_performance_evidence() {
        const REQUESTS: usize = 10_000;
        const SHARED_PLUGIN_REQUESTS: usize = REQUESTS / 2;
        const UNIQUE_PLUGIN_REQUESTS: usize = REQUESTS - SHARED_PLUGIN_REQUESTS;
        let scheduler = InvocationScheduler::new(REQUESTS, REQUESTS / 2);
        for index in 0..SHARED_PLUGIN_REQUESTS {
            scheduler
                .enqueue(job(
                    &format!("indexed-shared-{index:05}"),
                    "indexed-shared-plugin",
                ))
                .unwrap();
        }
        for index in 0..UNIQUE_PLUGIN_REQUESTS {
            scheduler
                .enqueue(job(
                    &format!("indexed-unique-{index:05}"),
                    &format!("indexed-plugin-{index:05}"),
                ))
                .unwrap();
        }
        for index in 0..SHARED_PLUGIN_REQUESTS {
            assert!(matches!(
                scheduler.cancel(&format!("indexed-shared-{index:05}")),
                CancelDisposition::Queued(_)
            ));
        }
        for index in 0..UNIQUE_PLUGIN_REQUESTS {
            assert!(matches!(
                scheduler.cancel(&format!("indexed-unique-{index:05}")),
                CancelDisposition::Queued(_)
            ));
        }
        let state = scheduler.state.lock().expect("scheduler mutex poisoned");
        assert_eq!(state.cancel_request_index_lookups, REQUESTS as u64);
        assert!(state.cancel_plugin_compactions > 0);
        assert!(state.cancel_order_compactions > 0);
        assert!(state.cancel_plugin_compaction_entries > 0);
        assert!(state.cancel_order_compaction_entries > 0);
        assert!(state.queued_by_request.is_empty());
        assert!(state.queues.is_empty());
        assert!(state.order.len() < ORDER_TOMBSTONE_COMPACT_MIN);
        let compaction_entries = state
            .cancel_plugin_compaction_entries
            .checked_add(state.cancel_order_compaction_entries)
            .expect("scheduler compaction accounting overflow");
        let compaction_basis_points = compaction_entries as f64 / REQUESTS as f64 * 10_000.0;
        assert!(
            compaction_basis_points <= 25_000.0,
            "amortized compaction = {compaction_basis_points} basis points"
        );
        crate::performance_evidence::record(serde_json::json!({
            "id": "runtime.scheduler-indexed-cancel",
            "sample_count": REQUESTS,
            "metrics": [
                {
                    "name": "index_lookups",
                    "unit": "count",
                    "observed": state.cancel_request_index_lookups,
                    "limit": REQUESTS,
                    "comparator": "eq"
                },
                {
                    "name": "compaction_entries_per_cancel",
                    "unit": "basis_points",
                    "observed": compaction_basis_points,
                    "limit": 25_000,
                    "comparator": "lte"
                },
                {
                    "name": "remaining_requests",
                    "unit": "count",
                    "observed": state.queued_by_request.len(),
                    "limit": 0,
                    "comparator": "eq"
                }
            ]
        }));
    }

    #[test]
    fn indexed_session_revoke_does_not_scan_one_hundred_thousand_unrelated_jobs() {
        const UNRELATED: usize = 100_000;
        const AFFECTED: usize = 10_000;
        let scheduler = InvocationScheduler::new(UNRELATED + AFFECTED, UNRELATED + AFFECTED);
        let exact = scope("session-a", "user-a", "env-a", "channel-a");
        let sibling = scope("session-a", "user-a", "env-a", "channel-b");
        let template = Arc::new(
            redevplugin_ipc::parse_worker_invocation(
                r#"{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"template","runtime_generation_id":"g1","payload":{"lease":{},"method":"worker.echo","invocation":{"plugin_instance_id":"plugin","method":"worker.echo"}}}"#,
            )
            .unwrap(),
        );
        for index in 0..UNRELATED {
            scheduler
                .enqueue(indexed_session_job(
                    &format!("unrelated-{index}"),
                    &sibling,
                    &template,
                ))
                .unwrap();
        }
        for index in 0..AFFECTED {
            scheduler
                .enqueue(indexed_session_job(
                    &format!("affected-{index}"),
                    &exact,
                    &template,
                ))
                .unwrap();
        }

        let revoked = scheduler.revoke_session(&exact);
        assert_eq!(revoked.queued.len(), AFFECTED);
        assert_eq!(scheduler.metrics().queued, UNRELATED);
        let state = scheduler.state.lock().unwrap();
        assert_eq!(state.session_revoke_index_lookups, 1);
        assert_eq!(state.session_revoke_affected_requests, AFFECTED as u64);
        let queue = state.queues.get("plugin").unwrap();
        assert_eq!(queue.live, UNRELATED);
        assert_eq!(queue.tombstones, AFFECTED);
        assert_eq!(queue.request_ids.len(), UNRELATED + AFFECTED);
        crate::performance_evidence::record(serde_json::json!({
            "id": "runtime.session-revoke-exact-index",
            "sample_count": UNRELATED + AFFECTED,
            "metrics": [
                {
                    "name": "index_lookups",
                    "unit": "count",
                    "observed": state.session_revoke_index_lookups,
                    "limit": 1,
                    "comparator": "eq"
                },
                {
                    "name": "visited_affected_requests",
                    "unit": "count",
                    "observed": state.session_revoke_affected_requests,
                    "limit": AFFECTED,
                    "comparator": "eq"
                }
            ]
        }));
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

    #[test]
    fn invocation_job_builder_returns_typed_error_without_panicking() {
        let frame = r#"{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"missing-plugin","runtime_generation_id":"g1","payload":{"lease":{},"method":"worker.echo","invocation":{"method":"worker.echo"}}}"#;
        let invocation = redevplugin_ipc::parse_worker_invocation(frame).unwrap();
        let result = std::panic::catch_unwind(|| InvocationJob::new(invocation));
        assert_eq!(
            result.unwrap().unwrap_err(),
            redevplugin_ipc::IpcError::MissingField {
                field: "plugin_instance_id"
            }
        );
    }

    fn job(request_id: &str, plugin_instance_id: &str) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo"}}}}}}"#
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }

    fn scope(
        owner_session_hash: &str,
        owner_user_hash: &str,
        owner_env_hash: &str,
        session_channel_id_hash: &str,
    ) -> redevplugin_ipc::SessionScope {
        redevplugin_ipc::SessionScope::new(
            owner_session_hash,
            owner_user_hash,
            owner_env_hash,
            session_channel_id_hash,
        )
        .unwrap()
    }

    fn session_job(
        request_id: &str,
        plugin_instance_id: &str,
        scope: &redevplugin_ipc::SessionScope,
    ) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo","owner_session_hash":"{}","owner_user_hash":"{}","owner_env_hash":"{}","session_channel_id_hash":"{}"}}}}}}"#,
            scope.owner_session_hash,
            scope.owner_user_hash,
            scope.owner_env_hash,
            scope.session_channel_id_hash,
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }

    fn indexed_session_job(
        request_id: &str,
        scope: &redevplugin_ipc::SessionScope,
        invocation: &Arc<ParsedWorkerInvocation>,
    ) -> InvocationJob {
        let (signal_sender, signals) = mpsc::channel();
        InvocationJob {
            request_id: request_id.to_string(),
            plugin_instance_id: "plugin".to_string(),
            session_scope: Some(scope.clone()),
            invocation: Arc::clone(invocation),
            cancellation: Cancellation::new(),
            signal_sender,
            signals,
        }
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

        #[test]
        fn session_revoke_removes_only_exact_indexed_jobs(
            exact_membership in prop::collection::vec(any::<bool>(), 0..32),
        ) {
            let capacity = exact_membership.len().max(1);
            let scheduler = InvocationScheduler::new(capacity, capacity);
            let exact = property_scope("channel-a");
            let sibling = property_scope("channel-b");
            let mut expected = 0;
            for (index, is_exact) in exact_membership.into_iter().enumerate() {
                let scope = if is_exact { &exact } else { &sibling };
                expected += usize::from(is_exact);
                scheduler
                    .enqueue(property_session_job(
                        &format!("request-{index}"),
                        &format!("plugin-{index}"),
                        scope,
                    ))
                    .unwrap();
            }
            let revoked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scheduler.revoke_session(&exact)
            }));
            prop_assert!(revoked.is_ok());
            prop_assert_eq!(revoked.unwrap().queued.len(), expected);
            prop_assert!(matches!(
                scheduler.enqueue(property_session_job("future", "future-plugin", &exact)),
                Err(EnqueueError::SessionRevoked)
            ));
        }
    }

    fn property_job(request_id: &str, plugin_instance_id: &str) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo"}}}}}}"#
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }

    fn property_scope(session_channel_id_hash: &str) -> redevplugin_ipc::SessionScope {
        redevplugin_ipc::SessionScope::new("session", "user", "env", session_channel_id_hash)
            .unwrap()
    }

    fn property_session_job(
        request_id: &str,
        plugin_instance_id: &str,
        scope: &redevplugin_ipc::SessionScope,
    ) -> InvocationJob {
        let frame = format!(
            r#"{{"ipc_version":"rust-ipc-v6","frame_type":"invoke_worker","request_id":"{request_id}","runtime_generation_id":"g1","payload":{{"lease":{{}},"method":"worker.echo","invocation":{{"plugin_instance_id":"{plugin_instance_id}","method":"worker.echo","owner_session_hash":"{}","owner_user_hash":"{}","owner_env_hash":"{}","session_channel_id_hash":"{}"}}}}}}"#,
            scope.owner_session_hash,
            scope.owner_user_hash,
            scope.owner_env_hash,
            scope.session_channel_id_hash,
        );
        InvocationJob::new(redevplugin_ipc::parse_worker_invocation(&frame).unwrap()).unwrap()
    }
}
