use super::*;

#[test]
fn cpu_guest_revalidates_authority_without_hostcalls() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let engine = worker_engine();
    let _ticker = execution_budget::EpochTicker::new(engine.clone());
    let (module, contract) = spinning_module(&engine);
    let revoked = Arc::new(AtomicBool::new(false));
    let authority = Arc::clone(&revoked);
    let entered = Arc::new(AtomicBool::new(false));
    let entered_worker = Arc::clone(&entered);
    let mut budget = ExecutionBudget::new(Duration::from_secs(10), scheduler::Cancellation::new())
        .with_authority(move || {
            entered_worker.store(true, Ordering::Release);
            if authority.load(Ordering::Acquire) {
                Err(WorkerFailure::Authority {
                    code: ipc::ERR_RUNTIME_LEASE_INVALID,
                    message: "test authority revoked".into(),
                })
            } else {
                Ok(())
            }
        });
    budget.fuel = u64::MAX;
    let worker = thread::spawn(move || {
        execute_compiled_worker_module(&engine, &module, &contract, b"{}", 65536, budget, |_| {
            Err("unexpected hostcall".into())
        })
        .unwrap_err()
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !entered.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    let started = Instant::now();
    revoked.store(true, Ordering::Release);
    assert!(matches!(
        worker.join().unwrap(),
        WorkerFailure::Authority {
            code: ipc::ERR_RUNTIME_LEASE_INVALID,
            ..
        }
    ));
    assert!(started.elapsed() < Duration::from_millis(250));
}

fn spinning_module(
    engine: &wasmtime::Engine,
) -> (
    wasmtime::Module,
    redevplugin_wasm_abi::ValidatedWorkerModule,
) {
    let bytes = wat::parse_str(
        r#"(module
        (memory (export "memory") 1)
        (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "redevplugin_worker_dealloc") (param i32 i32))
        (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64)
            (loop $spin br $spin) i64.const 0))"#,
    )
    .unwrap();
    let contract = redevplugin_wasm_abi::validate_worker_module(&bytes).unwrap();
    (wasmtime::Module::new(engine, &bytes).unwrap(), contract)
}

#[test]
fn cpu_guest_cancellation_does_not_wait_for_fuel_or_cancel_sibling() {
    let engine = worker_engine();
    let _ticker = execution_budget::EpochTicker::new(engine.clone());
    let (module, contract) = spinning_module(&engine);
    let cancellation = scheduler::Cancellation::new();
    let child_cancel = Arc::clone(&cancellation);
    let child_engine = engine.clone();
    let worker = thread::spawn(move || {
        let mut budget = ExecutionBudget::new(Duration::from_secs(10), child_cancel);
        budget.fuel = u64::MAX;
        execute_compiled_worker_module(
            &child_engine,
            &module,
            &contract,
            b"{}",
            65536,
            budget,
            |_| Err("unexpected hostcall".into()),
        )
        .unwrap_err()
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while cancellation.waiter_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "guest did not register cancellation"
        );
        thread::yield_now();
    }
    let canceled_at = Instant::now();
    cancellation.cancel();
    assert!(matches!(worker.join().unwrap(), WorkerFailure::Canceled));
    assert!(canceled_at.elapsed() < Duration::from_millis(250));
    assert_eq!(cancellation.waiter_count(), 0);

    // The same engine has advanced; a different invocation keeps its own fence.
    let (module, contract) = spinning_module(&engine);
    let mut budget = ExecutionBudget::new(Duration::from_secs(2), scheduler::Cancellation::new());
    budget.fuel = 100;
    let failure =
        execute_compiled_worker_module(&engine, &module, &contract, b"{}", 65536, budget, |_| {
            Err("unexpected hostcall".into())
        })
        .unwrap_err();
    assert!(matches!(failure, WorkerFailure::Budget));
}

#[test]
fn cpu_guest_deadline_is_enforced_independently_of_fuel() {
    let engine = worker_engine();
    let _ticker = execution_budget::EpochTicker::new(engine.clone());
    let (module, contract) = spinning_module(&engine);
    let mut budget =
        ExecutionBudget::new(Duration::from_millis(30), scheduler::Cancellation::new());
    budget.fuel = u64::MAX;
    let started = Instant::now();
    let failure =
        execute_compiled_worker_module(&engine, &module, &contract, b"{}", 65536, budget, |_| {
            Err("unexpected hostcall".into())
        })
        .unwrap_err();
    assert!(matches!(failure, WorkerFailure::Timeout));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn already_canceled_guest_never_enters_wasm() {
    let engine = worker_engine();
    let (module, contract) = spinning_module(&engine);
    let cancellation = scheduler::Cancellation::new();
    cancellation.cancel();
    let budget = ExecutionBudget::new(Duration::from_secs(1), cancellation);
    let failure =
        execute_compiled_worker_module(&engine, &module, &contract, b"{}", 65536, budget, |_| {
            Err("unexpected hostcall".into())
        })
        .unwrap_err();
    assert!(matches!(failure, WorkerFailure::Canceled));
}
