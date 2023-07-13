use std::ops::Deref;

use binrw::binrw;

pub mod builder;
mod dir_reader;
mod fst;
mod reader_writer;
pub mod structs;
mod window;

mod new_reader;

pub use fst::{Fst, FstNode, FstToBytes};
pub use new_reader::{CryptPartReader, WiiIsoReader, WiiPartitionReadInfo};
pub use window::IOWindow;

#[rustfmt::skip]
pub const COMMON_KEYS: [[u8; 16]; 2] = [
    /* Normal */
    [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7],
    /* Korean */
    [0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e],
];

pub const BLOCK_SIZE: u64 = 0x8000;
pub const BLOCK_DATA_OFFSET: u64 = 0x400;
pub const BLOCK_DATA_SIZE: u64 = BLOCK_SIZE - BLOCK_DATA_OFFSET;
pub const GROUP_SIZE: u64 = BLOCK_SIZE * 8 * 8;
pub const GROUP_DATA_SIZE: u64 = BLOCK_DATA_SIZE * 8 * 8;

#[binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShiftedU64(
    #[br(map = | x: u32 | (x as u64) << 2)]
    #[bw(map = | x: &u64 | -> u32 { (x >> 2) as u32 })]
    u64,
);

impl Deref for ShiftedU64 {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u64> for ShiftedU64 {
    fn from(v: u64) -> Self {
        ShiftedU64(v)
    }
}
