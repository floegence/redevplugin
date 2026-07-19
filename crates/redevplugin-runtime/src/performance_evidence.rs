use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::{c_int, c_long};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::mem::MaybeUninit;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[repr(C)]
struct TimeVal {
    tv_sec: c_long,
    tv_usec: c_long,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[repr(C)]
struct ResourceUsage {
    user_time: TimeVal,
    system_time: TimeVal,
    max_rss: c_long,
    remaining_counters: [c_long; 13],
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe extern "C" {
    fn getrusage(who: c_int, usage: *mut ResourceUsage) -> c_int;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn peak_rss_bytes() -> Result<u64, String> {
    const RUSAGE_SELF: c_int = 0;

    let mut usage = MaybeUninit::<ResourceUsage>::zeroed();
    // SAFETY: usage points to writable storage with the platform rusage layout.
    if unsafe { getrusage(RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: getrusage returned success and initialized the output structure.
    let max_rss = unsafe { usage.assume_init() }.max_rss;
    let max_rss = u64::try_from(max_rss).map_err(|_| "peak RSS is negative".to_string())?;
    if max_rss == 0 {
        return Err("peak RSS is unavailable".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        max_rss
            .checked_mul(1024)
            .ok_or_else(|| "peak RSS overflows bytes".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        Ok(max_rss)
    }
}

pub fn gate() -> String {
    std::env::var("REDEVPLUGIN_PERFORMANCE_GATE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "full".to_string())
}

pub fn enforce_thresholds() -> bool {
    let measurements = std::env::var("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    measurements.is_some() && matches!(gate().as_str(), "full" | "release")
}

pub fn record(mut scenario: Value) {
    let Some(path) = std::env::var("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let object = scenario
        .as_object_mut()
        .expect("performance scenario must be an object");
    object.insert("gate".to_string(), Value::String(gate()));
    object.insert("status".to_string(), Value::String("pass".to_string()));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open performance measurements");
    serde_json::to_writer(&mut file, &scenario).expect("encode performance scenario");
    file.write_all(b"\n")
        .expect("append performance scenario newline");
}
