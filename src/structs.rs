use std::io::{Read, Seek, SeekFrom};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut},
    cipher::{BlockEncryptMut, KeyIvInit},
    Aes128,
};
use binrw::{binrw, BinReaderExt, NullString};

use crate::{ShiftedU64, COMMON_KEYS};

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

pub fn read_u64_shifted<R: Read + Seek>(r: &mut R) -> binrw::BinResult<u64> {
    Ok((r.read_be::<u32>()? as u64) << 2)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[binrw]
#[brw(repr = u32)]
// #[bw(repr = u32)]
pub enum WiiPartType {
    Data,
    Update,
    Channel,
}

impl WiiPartType {
    pub fn try_from_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "DATA" => Some(WiiPartType::Data),
            "CHANNEL" => Some(WiiPartType::Channel),
            "UPDATE" => Some(WiiPartType::Update),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[binrw]
#[brw(repr = u32)]
enum SigType {
    Rsa4096 = 0x00010000,
    Rsa2048 = 0x00010001,
    EllipticalCurve = 0x00010002,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[binrw]
#[brw(repr = u32)]
enum KeyType {
    Rsa4096 = 0x00000000,
    Rsa2048 = 0x00000001,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[binrw]
pub struct WiiPartTableEntry {
    pub(crate) part_data_off: ShiftedU64,
    pub(crate) part_type: WiiPartType,
}

impl WiiPartTableEntry {
    pub fn get_offset(&self) -> u64 {
        *self.part_data_off
    }

    pub fn get_type(&self) -> WiiPartType {
        self.part_type
    }
}

pub fn read_parts<RS: Read + Seek>(r: &mut RS) -> binrw::BinResult<Vec<WiiPartTableEntry>> {
    r.seek(SeekFrom::Start(0x40000))?;
    let mut parts = Vec::new();
    // 4 tables
    // don't preserve what's in what table, probably doesn't matter
    for _ in 0..4 {
        let part_count = r.read_be::<u32>()?;
        let offset = read_u64_shifted(r)?;
        if part_count > 0 {
            let pos = r.stream_position()?;
            r.seek(SeekFrom::Start(offset))?;
            for _ in 0..part_count {
                parts.push(r.read_be::<WiiPartTableEntry>()?);
            }
            r.seek(SeekFrom::Start(pos))?;
        }
    }
    Ok(parts)
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
struct TicketTimeLimit {
    enable_time_limit: u32,
    time_limit: u32,
}

fn decrypt_title_key(key: &[u8; 16], common_key_idx: u8, title_id: &[u8; 8]) -> [u8; 16] {
    let mut decrypted = [0; 16];
    let mut iv = [0u8; 0x10];
    iv[..8].copy_from_slice(title_id);
    Aes128CbcDec::new(&COMMON_KEYS[common_key_idx as usize].into(), &iv.into())
        .decrypt_padded_b2b_mut::<NoPadding>(key, &mut decrypted)
        .unwrap();
    decrypted
}

fn encrypt_title_key(key: &[u8; 16], common_key_idx: u8, title_id: &[u8; 8]) -> [u8; 16] {
    let mut encrypted = [0; 16];
    let mut iv = [0u8; 0x10];
    iv[..8].copy_from_slice(title_id);
    Aes128CbcEnc::new(&COMMON_KEYS[common_key_idx as usize].into(), &iv.into())
        .encrypt_padded_b2b_mut::<NoPadding>(key, &mut encrypted)
        .unwrap();
    encrypted
}

#[binrw]
#[derive(Clone, PartialEq, Debug)]
pub struct Ticket {
    sig_type: SigType,
    sig: [u8; 0x100],
    #[brw(pad_before = 60)]
    sig_issuer: [u8; 0x40],
    ecdh: [u8; 0x3C],
    #[brw(pad_before = 3)]
    #[br(temp)]
    #[bw(calc = encrypt_title_key(title_key, *common_key_idx, title_id))]
    encrypted_key: [u8; 16],
    #[brw(pad_before = 1)]
    ticket_id: [u8; 8],
    console_id: [u8; 4],
    title_id: [u8; 8],
    unk: u16,
    ticket_version: u16,
    permitted_titles_mask: u32,
    permit_mask: u32,
    title_export_allowed: u8,
    common_key_idx: u8,
    #[brw(pad_before = 48)]
    content_access_permissions: [u8; 0x40],
    unk2: u16,
    time_limits: [TicketTimeLimit; 8],
    #[bw(ignore)]
    #[br(calc = decrypt_title_key(&encrypted_key, common_key_idx, &title_id))]
    pub title_key: [u8; 16],
}

#[binrw]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TMDContent {
    id: u32,
    index: u16,
    content_type: u16,
    size: u64,
    hash: [u8; 20],
}

#[binrw]
#[derive(Clone, Debug, PartialEq)]
pub struct TMD {
    sig_type: SigType,
    sig: [u8; 0x100],
    #[brw(pad_before = 60)]
    sig_issuer: [u8; 0x40],
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    #[brw(pad_before = 1)]
    ios_id_major: u32,
    ios_id_minor: u32,
    title_id_major: u32,
    title_id_minor: [u8; 4],
    title_type: u32,
    group_id: u16,
    // used to cal
    fakesign_padding: [u64; 7],
    #[brw(pad_before = 6)]
    access_flags: u32,
    title_version: u16,
    #[bw(calc = contents.len() as u16)]
    num_contents: u16,
    #[brw(pad_after = 2)]
    boot_idx: u16,
    #[br(count = num_contents)]
    contents: Vec<TMDContent>,
}

#[binrw]
#[derive(Clone, Debug, PartialEq)]
pub struct Certificate {
    sig_type: SigType,
    #[br(count = if sig_type == SigType::Rsa4096 { 512 }
    else if sig_type == SigType::Rsa2048 { 256 }
    else if sig_type == SigType::EllipticalCurve { 64 } else { 0 })]
    sig: Vec<u8>,
    #[brw(pad_before = 60)]
    issuer: [u8; 0x40],
    key_type: KeyType,
    subject: [u8; 64],
    #[br(count = if key_type == KeyType::Rsa4096 { 512 } else if key_type == KeyType::Rsa2048 { 256 } else { 0 })]
    key: Vec<u8>,
    modulus: u32,
    #[brw(pad_after = 52)]
    pub_exp: u32,
}

#[binrw]
#[derive(Clone, Debug, PartialEq)]
pub struct WiiPartitionHeader {
    pub ticket: Ticket,
    pub tmd_size: u32,
    pub tmd_off: ShiftedU64,
    pub cert_chain_size: u32,
    pub cert_chain_off: ShiftedU64,
    pub global_hash_table_off: ShiftedU64,
    pub data_off: ShiftedU64,
    pub data_size: ShiftedU64,
}

/// Wii disc header
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscHeader {
    pub game_id: [u8; 6],
    /// Used in multi-disc games
    pub disc_num: u8,
    pub disc_version: u8,
    pub audio_streaming: u8,
    pub audio_stream_buf_size: u8,
    #[brw(pad_before(14))]
    /// If this is a Wii disc, this will be 0x5D1C9EA3
    pub wii_magic: u32,
    /// If this is a GameCube disc, this will be 0xC2339F3D
    pub gcn_magic: u32,
    #[brw(pad_size_to(64))]
    #[br(map = |s| NullString::to_string(&s))]
    #[bw(map = |s| NullString::from(s.clone()))]
    pub game_title: String,
    /// Disable hash verification
    pub disable_hash_verification: u8,
    /// Disable disc encryption and H3 hash table loading and verification
    pub disable_disc_enc: u8,
    #[brw(pad_before(0x39e))]
    pub debug_mon_off: u32,
    pub debug_load_addr: u32,
    #[brw(pad_before(0x18))]
    /// Offset to main DOL
    pub dol_off: ShiftedU64,
    /// Offset to file system table
    pub fst_off: ShiftedU64,
    /// File system size
    pub fst_sz: ShiftedU64,
    /// File system max size
    pub fst_max_sz: ShiftedU64,
    pub fst_memory_address: u32,
    pub user_position: u32,
    #[brw(pad_after(4))]
    pub user_sz: u32,
}

#[binrw]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DOLHeader {
    pub text_off: [u32; 7],
    pub data_off: [u32; 11],
    pub text_starts: [u32; 7],
    pub data_starts: [u32; 11],
    pub text_sizes: [u32; 7],
    pub data_sizes: [u32; 11],
    pub bss_start: u32,
    pub bss_size: u32,
    pub entry_point: u32,
}

#[binrw]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApploaderHeader {
    #[brw(pad_before = 0x14)]
    pub size1: u32,
    pub size2: u32,
}
