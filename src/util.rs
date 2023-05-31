use std::ops::Range;

use base64::Engine;

pub struct ChunkRanges {
    ranges: Vec<Range<u64>>,
}

impl ChunkRanges {
    fn new(range: Range<u64>, chunk_size: u64) -> Self {
        let mut ranges = vec![];
        let mut last_start = range.start;
        loop {
            let mut next_length = last_start + chunk_size;
            if next_length > range.end {
                next_length = range.end;
            }
            let new_range = last_start..next_length;
            ranges.push(new_range);
            if next_length >= range.end {
                break;
            }
            last_start = next_length;
        }
        ranges.reverse();

        Self { ranges }
    }
}

impl Iterator for ChunkRanges {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ranges.pop()
    }
}

pub trait ChunkRangesExt {
    fn chunk_ranges(&self, chunk_size: u64) -> ChunkRanges;
}

impl ChunkRangesExt for Range<u64> {
    fn chunk_ranges(&self, chunk_size: u64) -> ChunkRanges {
        ChunkRanges::new(self.clone(), chunk_size)
    }
}

pub struct DivideUpRange {
    ranges: Vec<Range<u64>>,
}

impl DivideUpRange {
    fn new(range: Range<u64>, count: usize) -> Self {
        let mut ranges = Vec::with_capacity(count);
        let single_range = (range.end - range.start) as f64 / count as f64;

        for i in 0..count {
            ranges.push(((i as f64 * single_range) as u64)..(((i + 1) as f64 * single_range) as u64));
        }

        Self { ranges }
    }
}

impl Iterator for DivideUpRange {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ranges.pop()
    }
}

pub trait DivideUpRangeExt {
    fn divide_up(&self, count: usize) -> DivideUpRange;
}

impl DivideUpRangeExt for Range<u64> {
    fn divide_up(&self, count: usize) -> DivideUpRange {
        DivideUpRange::new(self.clone(), count)
    }
}

pub fn decode_base64(data: &str) -> Vec<u8> {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(data).expect("failed to decode base64")
}
