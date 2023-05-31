use std::ops::Range;

use numtoa::NumToA;

use crate::crypto::{decrypt_aes, decrypt_aes_with_iv, GenericArray16};

#[inline]
pub fn attempt_range_aes<
    const DATA_SIZE: usize,
    const REPLACE_START: usize,
    const REPLACE_WIDTH: usize,
    const SWAP_FILLER: u8,
>(
    range: Range<u64>,
    data: [GenericArray16; DATA_SIZE],
    key: [u8; 16],
    check: impl Fn(&[u8], [GenericArray16; DATA_SIZE]),
) {
    let mut key_buffer = key.clone();
    let mut replace_buffer = [SWAP_FILLER; REPLACE_WIDTH];
    debug_assert!(
        (range.end as f64).log10() <= REPLACE_WIDTH as f64,
        "range would not fit in replace buffer"
    );

    for value in range {
        value.numtoa(10, &mut replace_buffer);
        key_buffer[REPLACE_START..REPLACE_START + REPLACE_WIDTH]
            .swap_with_slice(&mut replace_buffer);

        let mut data = data.clone();

        decrypt_aes(&key_buffer, &mut data).unwrap();
        check(&key_buffer, data);
    }
}

#[inline]
pub fn attempt_range_aes_with_iv<
    const DATA_SIZE: usize,
    const REPLACE_START: usize,
    const REPLACE_WIDTH: usize,
    const SWAP_FILLER: u8,
>(
    range: Range<u64>,
    data: [u8; DATA_SIZE],
    key: [u8; 16],
    iv: [u8; 16],
    check: impl Fn(&[u8], Result<&[u8], cbc::cipher::block_padding::UnpadError>),
) {
    let mut key_buffer = key.clone();
    let mut replace_buffer = [SWAP_FILLER; REPLACE_WIDTH];
    debug_assert!(
        (range.end as f64).log10() <= REPLACE_WIDTH as f64,
        "range would not fit in replace buffer"
    );

    for value in range {
        value.numtoa(10, &mut replace_buffer);
        key_buffer[REPLACE_START..REPLACE_START + REPLACE_WIDTH]
            .swap_with_slice(&mut replace_buffer);

        let mut data = data.clone();

        let decrypted = decrypt_aes_with_iv(&key_buffer.into(), &iv.into(), &mut data);
        check(&key_buffer, decrypted);
    }
}
