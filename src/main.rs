#![feature(slice_as_chunks, iter_array_chunks, file_create_new)]

use std::{
    io::Write,
    ops::Range,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        mpsc, Arc,
    },
};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockDecryptMut, KeyInit};
use base64::Engine;
use num_format::{Locale, ToFormattedString};
use numtoa::NumToA;
use thiserror::Error;
use tracing::{debug, info, warn};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

const THREAD_COUNT: usize = 16;
const FEEDBACK_CHUNK_SIZE: usize = 5_000_000;
const FEEDBACK_WAIT_MS: u64 = 10000;

#[derive(Debug, Error)]
enum AesCrackError {
    #[error("failed to decrypt data")]
    DecryptionError,
    #[error("decrypted data had no png header")]
    NotPng,
}

type GenericArray16 = GenericArray<u8, aes::cipher::typenum::U16>;

#[derive(Debug)]
struct FeedbackData {
    key: String,
    data: Vec<u8>,
}

fn main() {
    // setup tracing
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info,neuro-brute=debug");
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    debug!("parsing base64 data");
    let b64 = include_str!("base64.txt");
    let engine = base64::engine::general_purpose::STANDARD;
    let data = engine.decode(b64).expect("failed to decode base64");
    assert_eq!(data.len(), 1040, "decoded base64 was not 1040 bytes long");
    let (chunks, extra) = data.as_chunks::<16>();
    assert!(
        extra.is_empty(),
        "decoded data did not fit evenly into 16 byte chunks"
    );
    let chunks = chunks.to_owned();
    let chunks: Vec<GenericArray16> = chunks
        .into_iter()
        .map(|chunk| {
            GenericArray::from_exact_iter(chunk.to_owned())
                .expect("failed to convert chunk to generic array")
        })
        .collect::<Vec<_>>();
    // only check the first 4 chunks for speed
    let chunks = chunks.into_iter().take(4).collect::<Vec<_>>();

    // we want to go through every number that is 16 digits long, starts with 17 and ends with 24
    // this means we havae 10^15 - 1 numbers to go through

    let max_value = 10u64.pow(12);
    let single_range = max_value as f64 / THREAD_COUNT as f64;

    let mut thread_ranges = Vec::with_capacity(THREAD_COUNT);

    for thread in 0..THREAD_COUNT {
        let thread_range =
            ((thread as f64 * single_range) as u64)..(((thread + 1) as f64 * single_range) as u64);
        thread_ranges.push(thread_range);
    }

    println!("ranges: {:?}", thread_ranges);
    let counter = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicBool::new(false));
    let (feedback_send, feedback_rcv) = mpsc::channel::<FeedbackData>();

    let mut crack_threads = vec![];

    for thread_range in thread_ranges {
        let thread_to_crack = chunks.clone();
        let counter = counter.clone();
        let feedback_send = feedback_send.clone();

        let handle = std::thread::Builder::new()
            .name("crack thread".to_string())
            .stack_size(1024 * 1024 * 1024)
            .spawn(move || {
                handle_aes_crack(thread_to_crack, thread_range, counter, feedback_send);
            }).expect("thread spawn failed");
        crack_threads.push(handle);
    }
    drop(feedback_send); // drop the extra sender

    let rate_should_exit = completed.clone();
    let rate_thread = std::thread::spawn(move || {
        let mut last_count = 0;
        loop {
            let new_count = counter.load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                new_count >= last_count,
                "new count was less than last count"
            );
            let delta = new_count - last_count;
            let rate = delta as f64 / (FEEDBACK_WAIT_MS as f64 / 1000.0);

            info!(
                "{}/{} ({:.3}%) current rate {} keys/second",
                new_count.to_formatted_string(&Locale::en),
                max_value.to_formatted_string(&Locale::en),
                (new_count as f64 / max_value as f64) * 100.0,
                (rate as u64).to_formatted_string(&Locale::en)
            );

            last_count = new_count;

            if new_count > 5_000_000_000 {
                std::process::exit(0);
            }

            if rate_should_exit.load(std::sync::atomic::Ordering::Relaxed) {
                warn!("rate thread exiting due to feedback thread exiting");
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(FEEDBACK_WAIT_MS));
        }
    });

    let feedback_thread = std::thread::spawn(move || {
        let mut file =
            std::fs::File::create("./crack_keys.txt").expect("failed to create crack_keys.txt");
        for feedback in feedback_rcv {
            info!("got feedback: {:?}", feedback);
            let to_write = format!("{:?}\n", feedback);
            file.write(to_write.as_bytes())
                .expect("failed to write key to file");
            file.flush().expect("failed to flush file");
        }
        completed.store(true, std::sync::atomic::Ordering::Relaxed);
        warn!("feedback thread exited")
    });

    let mut threads = vec![];
    threads.push(feedback_thread);
    threads.push(rate_thread);
    threads.extend(crack_threads);

    for thread in threads {
        thread.join().expect("thread panicked");
    }

    info!("completed");
}

fn handle_aes_crack(
    to_crack: Vec<GenericArray16>,
    range: Range<u64>,
    counter: Arc<AtomicU64>,
    feedback_send: mpsc::Sender<FeedbackData>,
) {
    let subranges = range.array_chunks::<FEEDBACK_CHUNK_SIZE>();

    let remainder = subranges.clone().into_remainder();

    for subrange in subranges {
        do_aes_range(subrange.to_vec(), to_crack.clone(), feedback_send.clone());
        counter.fetch_add(
            FEEDBACK_CHUNK_SIZE as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    if let Some(extra) = remainder {
        let extra = extra.collect::<Vec<_>>();
        let extra_len = extra.len();
        do_aes_range(extra, to_crack, feedback_send);
        counter.fetch_add(extra_len as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

fn do_aes_range(
    range: Vec<u64>,
    to_crack: Vec<GenericArray16>,
    feedback_send: mpsc::Sender<FeedbackData>,
) {
    let mut key_buffer = [0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x34];
    let mut inner_buffer = [0u8; 12];
    for value in range {
        let to_crack = to_crack.clone();
        let result: Result<Vec<u8>, AesCrackError> = {
            let mut to_crack = to_crack;
            let _ = value.numtoa(10, &mut inner_buffer);
            // let rang = (2 + (12 - inner_buffer.len()))..(14);
            let rang = 2..14;
            // key_buffer.replace_range(rang, inner);
            key_buffer[rang].swap_with_slice(&mut inner_buffer);
            assert_eq!(key_buffer.len(), 16, "key was not 16 bytes long");

            let cipher = aes::Aes128::new_from_slice(&mut key_buffer).expect("cipher failed");

            let chunks = to_crack.as_mut_slice();
            cipher.decrypt_blocks(chunks);

            if chunks[0][..=3] == [0x89, 0x50, 0x4E] {
                Ok(chunks.into_iter().flatten().map(|v| *v).collect::<Vec<_>>())
            } else {
                Err(AesCrackError::NotPng)
            }
        };

        match result {
            Ok(string) => {
                feedback_send
                    .send(FeedbackData {
                        key: get_key_from_value_slow(value),
                        data: string.clone(),
                    })
                    .expect(&format!(
                        "failed to send message back. message was {:x?}",
                        string
                    ));
            }
            Err(error) => match error {
                AesCrackError::DecryptionError => warn!("Decryption error for value {}", value),
                AesCrackError::NotPng => (),
            },
        };
    }
}

fn get_key_from_value_slow(value: u64) -> String {
    format!("17{:0>12}24", value)
}

// fn do_aes_crack(mut to_crack: Vec<GenericArray16>, value: u64) -> Result<String, AesCrackError> {
//     let key = get_key_from_value(value);
//     assert_eq!(key.len(), 16, "key was not 16 bytes long");

//     let cipher =
//         aes::Aes128::new_from_slice(key.as_bytes()).map_err(|_| AesCrackError::DecryptionError)?;

//     let chunks = to_crack.as_mut_slice();
//     cipher.decrypt_blocks(chunks);

//     if let Ok(utf8) =
//         simdutf8::basic::from_utf8(&chunks.into_iter().flatten().map(|v| *v).collect::<Vec<_>>())
//     {
//         Ok(utf8.to_owned())
//     } else {
//         Err(AesCrackError::NotUtf8)
//     }
// }
