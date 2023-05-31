#![feature(array_chunks)]

use std::{
    ops::Range,
    sync::{atomic::AtomicU64, Arc},
};

use neuro_brute::{
    brute::attempt_range_aes_with_iv,
    util::{decode_base64, ChunkRangesExt, DivideUpRangeExt},
};

use num_format::{Locale, ToFormattedString};
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;

const RATE_CHUNK_SIZE: u64 = 100_000;
const RATE_WAIT_MS: u64 = 10_000;

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info,neuro_brute=debug");
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let thread_count = std::thread::available_parallelism().unwrap().get();

    let range = 0..10u64.pow(12);
    let data = decode_base64(include_str!("base64.txt"));
    let data = data.try_into().expect("data had incorrect length");

    let key = *b"1700000000000024";

    let iv = decode_base64("DQ5zl4ighWwiag7y+cWFQg==")
        .as_slice()
        .try_into()
        .expect("iv was incorrect size");

    let count = Arc::new(AtomicU64::new(0));

    let mut threads = vec![];

    let max_value = range.end;
    let rate_count = count.clone();
    let rate_thread = std::thread::spawn(move || {
        rate_thread(max_value, rate_count);
    });
    threads.push(rate_thread);

    for (thread_id, subrange) in range.divide_up(thread_count).enumerate() {
        let count = count.clone();
        let thread = std::thread::Builder::new()
            .name(format!("crack thread {}", thread_id))
            .spawn(move || {
                debug!("starting crack thread {}", thread_id);
                subrange_thread(subrange, data, key, iv, count);
                debug!("crack thread {} completed", thread_id);
            })
            .expect("failed to spawn crack thread");
        threads.push(thread);
    }

    for thread in threads {
        thread.join().expect("failed to join thread");
    }

    info!("done")
}

fn subrange_thread(
    range: Range<u64>,
    data: [u8; 1040],
    key: [u8; 16],
    iv: [u8; 16],
    count: Arc<AtomicU64>,
) {
    for subrange in range.chunk_ranges(RATE_CHUNK_SIZE) {
        let subrange_size = subrange.end - subrange.start;
        attempt_range_aes_with_iv::<1040, 2, 12, b'0'>(
            subrange.clone(),
            data,
            key,
            iv,
            |value, decrypted| {
                if let Ok(decrypted) = decrypted {
                    if let Ok(utf) = simdutf8::basic::from_utf8(decrypted) {
                        info!("key {} had value {}", String::from_utf8_lossy(&value), utf,);
                    }
                }
            },
        );
        count.fetch_add(subrange_size, std::sync::atomic::Ordering::Relaxed);
    }
}

fn rate_thread(max_value: u64, count: Arc<AtomicU64>) {
    let mut last_count = 0;
    loop {
        let new_count = count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            new_count >= last_count,
            "new count was less than last count"
        );
        let delta = new_count - last_count;
        let rate = delta as f64 / (RATE_WAIT_MS as f64 / 1000.0);

        info!(
            "{}/{} ({:.3}%) current rate {} keys/second",
            new_count.to_formatted_string(&Locale::en),
            max_value.to_formatted_string(&Locale::en),
            (new_count as f64 / max_value as f64) * 100.0,
            (rate as u64).to_formatted_string(&Locale::en)
        );

        last_count = new_count;

        if new_count == max_value {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(RATE_WAIT_MS));
    }
    warn!("rate thread completed")
}
