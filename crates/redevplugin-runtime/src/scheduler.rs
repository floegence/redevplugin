use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

pub enum InvocationSignal {
    HostcallResponse(String),
    Canceled,
}

#[derive(Debug)]
pub struct InvocationJob {
    pub request_id: String,
    pub plugin_instance_id: String,
    pub frame: String,
    pub canceled: Arc<AtomicBool>,
    pub signal_sender: Sender<InvocationSignal>,
    pub signals: Receiver<InvocationSignal>,
}

impl InvocationJob {
    pub fn new(request_id: String, plugin_instance_id: String, frame: String) -> Self {
        let (signal_sender, signals) = mpsc::channel();
        Self {
            request_id,
            plugin_instance_id,
            frame,
            canceled: Arc::new(AtomicBool::new(false)),
            signal_sender,
            signals,
        }
    }
}

pub enum CancelDisposition {
    Queued,
    Running,
    Missing,
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
}

#[derive(Default)]
struct SchedulerState {
    queues: BTreeMap<String, VecDeque<InvocationJob>>,
    order: VecDeque<String>,
    active: HashMap<String, ActiveInvocation>,
    active_by_plugin: HashMap<String, usize>,
    queued: usize,
    shutdown: bool,
}

struct ActiveInvocation {
    plugin_instance_id: String,
    canceled: Arc<AtomicBool>,
    signal_sender: Sender<InvocationSignal>,
}

impl InvocationScheduler {
    pub fn new(queue_capacity: usize, per_plugin_concurrency: usize) -> Self {
        Self {
            limits: SchedulerLimits {
                queue_capacity,
                per_plugin_concurrency,
            },
            state: Mutex::new(SchedulerState::default()),
            available: Condvar::new(),
        }
    }

    pub fn enqueue(&self, job: InvocationJob) -> Result<(), InvocationJob> {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        if state.shutdown || state.queued >= self.limits.queue_capacity {
            return Err(job);
        }
        let plugin_instance_id = job.plugin_instance_id.clone();
        let queue = state.queues.entry(plugin_instance_id.clone()).or_default();
        let was_empty = queue.is_empty();
        queue.push_back(job);
        if was_empty {
            state.order.push_back(plugin_instance_id);
        }
        state.queued += 1;
        self.available.notify_all();
        Ok(())
    }

    pub fn take(&self) -> Option<InvocationJob> {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        loop {
            let plugin_count = state.order.len();
            for _ in 0..plugin_count {
                let plugin_instance_id = state.order.pop_front()?;
                let active = state
                    .active_by_plugin
                    .get(&plugin_instance_id)
                    .copied()
                    .unwrap_or_default();
                if active >= self.limits.per_plugin_concurrency {
                    state.order.push_back(plugin_instance_id);
                    continue;
                }
                let queue = state
                    .queues
                    .get_mut(&plugin_instance_id)
                    .expect("scheduler order references a queue");
                let job = queue.pop_front().expect("scheduler queue is not empty");
                if queue.is_empty() {
                    state.queues.remove(&plugin_instance_id);
                } else {
                    state.order.push_back(plugin_instance_id.clone());
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
                        canceled: Arc::clone(&job.canceled),
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
        self.available.notify_all();
    }

    pub fn cancel(&self, request_id: &str) -> CancelDisposition {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        let plugins = state.queues.keys().cloned().collect::<Vec<_>>();
        for plugin_instance_id in plugins {
            let removed = {
                let queue = state
                    .queues
                    .get_mut(&plugin_instance_id)
                    .expect("queued plugin exists");
                queue
                    .iter()
                    .position(|job| job.request_id == request_id)
                    .map(|position| {
                        let job = queue.remove(position).expect("queued invocation exists");
                        (job, queue.is_empty())
                    })
            };
            if let Some((job, queue_empty)) = removed {
                job.canceled.store(true, Ordering::Release);
                state.queued -= 1;
                if queue_empty {
                    state.queues.remove(&plugin_instance_id);
                    state.order.retain(|plugin| plugin != &plugin_instance_id);
                }
                return CancelDisposition::Queued;
            }
        }
        if let Some(active) = state.active.get(request_id) {
            active.canceled.store(true, Ordering::Release);
            let _ = active.signal_sender.send(InvocationSignal::Canceled);
            return CancelDisposition::Running;
        }
        CancelDisposition::Missing
    }

    pub fn metrics(&self) -> SchedulerMetrics {
        let state = self.state.lock().expect("scheduler mutex poisoned");
        SchedulerMetrics {
            active: state.active.len(),
            queued: state.queued,
        }
    }

    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("scheduler mutex poisoned");
        state.shutdown = true;
        for queue in state.queues.values() {
            for job in queue {
                job.canceled.store(true, Ordering::Release);
            }
        }
        state.queues.clear();
        state.order.clear();
        state.queued = 0;
        self.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_plugins_while_respecting_per_plugin_concurrency() {
        let scheduler = InvocationScheduler::new(8, 1);
        for (request, plugin) in [("a1", "a"), ("a2", "a"), ("b1", "b")] {
            scheduler
                .enqueue(InvocationJob::new(
                    request.to_string(),
                    plugin.to_string(),
                    "{}".to_string(),
                ))
                .unwrap();
        }
        let first = scheduler.take().unwrap();
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
        assert!(matches!(scheduler.cancel("a1"), CancelDisposition::Queued));
        assert_eq!(scheduler.metrics().queued, 0);
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
    fn marks_running_invocation_canceled_and_notifies_worker() {
        let scheduler = InvocationScheduler::new(2, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        let invocation = scheduler.take().unwrap();
        assert!(matches!(scheduler.cancel("a1"), CancelDisposition::Running));
        assert!(invocation.canceled.load(Ordering::Acquire));
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
        let scheduler = InvocationScheduler::new(4, 1);
        scheduler.enqueue(job("a1", "a")).unwrap();
        scheduler.enqueue(job("a2", "a")).unwrap();
        scheduler.enqueue(job("b1", "b")).unwrap();
        assert!(matches!(scheduler.cancel("a1"), CancelDisposition::Queued));
        assert_eq!(scheduler.take().unwrap().request_id, "a2");
        assert_eq!(scheduler.take().unwrap().request_id, "b1");
    }

    fn job(request_id: &str, plugin_instance_id: &str) -> InvocationJob {
        InvocationJob::new(
            request_id.to_string(),
            plugin_instance_id.to_string(),
            "{}".to_string(),
        )
    }
}
