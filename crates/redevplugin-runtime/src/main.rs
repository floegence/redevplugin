use std::io::{self, BufRead, Write};

fn main() {
    if let Err(err) = run() {
        eprintln!("redevplugin-runtime startup error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|err| format!("read hello frame: {err}"))?;
    let (request_id, runtime_generation_id) =
        redevplugin_ipc::validate_hello_frame(&line).map_err(|err| err.to_string())?;
    let ack = redevplugin_ipc::hello_ack_frame(
        &request_id,
        &runtime_generation_id,
        env!("CARGO_PKG_VERSION"),
        redevplugin_ipc::WASM_ABI_VERSION,
    );
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(ack.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|err| format!("write hello ack: {err}"))?;

    for line in io::stdin().lock().lines() {
        let _ = line.map_err(|err| format!("read ipc frame: {err}"))?;
    }
    Ok(())
}
