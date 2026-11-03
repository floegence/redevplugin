#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn bench_noop(n: i32) -> i64 {
    n as i64 + 1
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn bench_mix(n: i32) -> i64 {
    let mut x = 17u32;
    for i in 0..n as u32 {
        x = (x ^ i).wrapping_mul(1664525).wrapping_add(1013904223);
    }
    x as i64
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn bench_sort(n: i32) -> i64 {
    let mut x = 17u32;
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        v.push(x);
    }
    v.sort_unstable();
    v.iter().enumerate().fold(0u64, |a, (i, x)| {
        a.wrapping_add((*x as u64).wrapping_mul(i as u64 + 1))
    }) as i64
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn bench_json(n: i32) -> i64 {
    let mut sum = 0i64;
    for _ in 0..n {
        let v: serde_json::Value = serde_json::from_str(include_str!("payload.json")).unwrap();
        sum += v
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_i64().unwrap())
            .sum::<i64>();
    }
    sum
}
