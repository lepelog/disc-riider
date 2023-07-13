use std::{
    fs::{create_dir_all, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path},
};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit},
    Aes128,
};
use binrw::{BinReaderExt, BinWriterExt};

use crate::{
    structs::{
        read_parts, ApploaderHeader, Certificate, DOLHeader, DiscHeader, WiiPartTableEntry,
        WiiPartType, WiiPartitionHeader, TMD,
    },
    Fst, FstNode, IOWindow, BLOCK_DATA_OFFSET, BLOCK_DATA_SIZE, BLOCK_SIZE, GROUP_DATA_SIZE,
    GROUP_SIZE,
};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub struct WiiIsoReader<RS: Read + Seek> {
    pub file: RS,
    // TODO: proper structs
    header: DiscHeader,
    region: [u8; 32],
    partitions: Vec<WiiPartTableEntry>,
}

struct EncryptedPartState {
    // TODO: optional check
    // verification_h3: Option<Box<[u8; 0x18000]>>,
    data_offset: u64,
    encryption_key: [u8; 16],
    // the current group loaded in the cache
    current_group: Option<u64>,
    // buffers the bytes for the current group, can be partially encrypted
    group_cache: Box<[u8; GROUP_SIZE as usize]>,
    // position where data is read from
    current_position: u64,
    data_size: u64,
}

impl EncryptedPartState {
    // loads an entire group into cache and decrypts it
    fn do_load_group<RS: Read + Seek>(&mut self, group: u64, rs: &mut RS) -> io::Result<()> {
        self.current_group = None;
        rs.seek(SeekFrom::Start(self.data_offset + group * GROUP_SIZE))?;
        rs.read_exact(self.group_cache.as_mut())?;
        self.current_group = Some(group);
        // decrypt all blocks
        // TODO: it might be possible to optimize this but it introduces some complexity regarding writes
        // and decryption is *relatively* fast anyways
        for block in 0..64 {
            let block_data =
                &mut self.group_cache[(block * BLOCK_SIZE) as usize..][..BLOCK_SIZE as usize];
            let crypto = Aes128CbcDec::new(
                self.encryption_key.as_ref().into(),
                block_data[0x3d0..][..0x10].as_ref().into(),
            );
            crypto
                .decrypt_padded_mut::<NoPadding>(&mut block_data[BLOCK_DATA_OFFSET as usize..])
                // TODO: can bad data cause a panic here?
                .unwrap();
        }
        Ok(())
    }

    fn get_decrypted_block_data<RS: Read + Seek>(
        &mut self,
        group: u64,
        block: u64,
        rs: &mut RS,
    ) -> io::Result<&[u8]> {
        if !self.current_group.map_or(false, |g| g == group) {
            self.do_load_group(group, rs)?;
        }
        let block_data =
            &mut self.group_cache[(block * BLOCK_SIZE) as usize..][..BLOCK_SIZE as usize];
        Ok(&block_data[BLOCK_DATA_OFFSET as usize..])
    }

    /// Reads the specified amount of bytes from the given offset into the buffer, clearing it and ensuring proper capacity
    /// does not affect the current read position
    /// TODO: this only exists cause ReadBuf isn't stable yet...
    pub fn read_into_vec<RS: Read + Seek>(
        &mut self,
        rs: &mut RS,
        mut offset: u64,
        length: u64,
        buffer: &mut Vec<u8>,
    ) -> io::Result<()> {
        buffer.clear();
        buffer.reserve(length as usize);
        let mut group = offset / GROUP_DATA_SIZE;
        let mut block = (offset % GROUP_DATA_SIZE) / BLOCK_DATA_SIZE;
        let mut offset_in_block_data = offset % BLOCK_DATA_SIZE;
        while buffer.len() < length as usize {
            if offset >= self.data_size {
                break;
            }
            // we either copy the entire block or what's needed to fill the vec
            let count_to_copy =
                (BLOCK_DATA_SIZE - offset_in_block_data).min(length - buffer.len() as u64);
            buffer.extend_from_slice(
                &self.get_decrypted_block_data(group, block, rs)?[offset_in_block_data as usize..]
                    [..count_to_copy as usize],
            );
            offset += count_to_copy;
            offset_in_block_data = 0;
            block += 1;
            if block == 64 {
                block = 0;
                group += 1;
            }
        }
        Ok(())
    }

    // reads at most one group
    fn read_into<RS: Read + Seek>(&mut self, rs: &mut RS, mut buf: &mut [u8]) -> io::Result<usize> {
        let group = self.current_position / GROUP_DATA_SIZE;
        let mut block = (self.current_position % GROUP_DATA_SIZE) / BLOCK_DATA_SIZE;
        let mut offset_in_block_data = self.current_position % BLOCK_DATA_SIZE;
        let mut read_bytes = 0;
        while !buf.is_empty() {
            if self.current_position >= self.data_size {
                break;
            }
            // we either copy the entire block or what's needed to fill the slice
            let count_to_copy = (BLOCK_DATA_SIZE - offset_in_block_data).min(buf.len() as u64);
            let to_fill;
            (to_fill, buf) = buf.split_at_mut(count_to_copy as usize);
            to_fill.copy_from_slice(
                &self.get_decrypted_block_data(group, block, rs)?[offset_in_block_data as usize..]
                    [..count_to_copy as usize],
            );
            self.current_position += count_to_copy;
            read_bytes += count_to_copy;
            offset_in_block_data = 0;
            block += 1;
            if block == 64 {
                // read at most one group
                break;
            }
        }
        Ok(read_bytes as usize)
    }
}

pub struct CryptPartReader<'a, RS: Read + Seek> {
    rs: &'a mut RS,
    crypt_part_state: &'a mut EncryptedPartState,
}

impl<'a, RS: Read + Seek> CryptPartReader<'a, RS> {
    pub fn read_into_vec(
        &mut self,
        offset: u64,
        length: u64,
        buffer: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.crypt_part_state
            .read_into_vec(self.rs, offset, length, buffer)
    }

    pub fn into_window(self, offset: u64, length: Option<u64>) -> impl Read + Seek + 'a {
        IOWindow::new(self, offset, length)
    }
}

impl<'a, RS: Read + Seek> Seek for CryptPartReader<'a, RS> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Current(off) => self.crypt_part_state.current_position as i64 + off,
            SeekFrom::Start(off) => off as i64,
            // TODO: support seeking from the end when it's known?
            SeekFrom::End(_off) => return Err(io::Error::from(io::ErrorKind::Unsupported)),
        };
        self.crypt_part_state.current_position = new_pos.max(0) as u64;
        Ok(self.crypt_part_state.current_position)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.crypt_part_state.current_position)
    }
}

impl<'a, RS: Read + Seek> Read for CryptPartReader<'a, RS> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.crypt_part_state.read_into(&mut self.rs, buf)
    }
}

pub struct WiiPartitionReadInfo {
    partition_entry: WiiPartTableEntry,
    wii_partition_header: WiiPartitionHeader,
    // encrypted part
    encrypt_part_state: EncryptedPartState,

    encrypted_header: DiscHeader,

    fst: Fst,
}

impl WiiPartitionReadInfo {
    pub fn get_partition_header(&self) -> &WiiPartitionHeader {
        &self.wii_partition_header
    }

    pub fn get_partition_offset(&self) -> u64 {
        self.partition_entry.get_offset()
    }

    pub fn get_partition_type(&self) -> WiiPartType {
        self.partition_entry.get_type()
    }

    pub fn get_encrypted_header(&self) -> &DiscHeader {
        &self.encrypted_header
    }

    pub fn get_fst(&self) -> &Fst {
        &self.fst
    }

    pub fn read_tmd<RS: Read + Seek>(
        &mut self,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<TMD> {
        reader.file.seek(SeekFrom::Start(
            self.get_partition_offset() + *self.wii_partition_header.tmd_off,
        ))?;
        reader.file.read_be()
    }

    pub fn read_certificates<RS: Read + Seek>(
        &mut self,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<[Certificate; 3]> {
        reader.file.seek(SeekFrom::Start(
            self.get_partition_offset() + *self.wii_partition_header.cert_chain_off,
        ))?;
        reader.file.read_be()
    }

    pub fn read_bi2<RS: Read + Seek>(
        &mut self,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<Vec<u8>> {
        reader
            .file
            .seek(SeekFrom::Start(self.get_partition_offset() + 0x440))?;
        let mut bi2_buf = vec![0; 0x2000];
        reader.file.read_exact(&mut bi2_buf)?;
        Ok(bi2_buf)
    }

    pub fn get_crypto_reader<'a, RS: Read + Seek>(
        &'a mut self,
        reader: &'a mut WiiIsoReader<RS>,
    ) -> CryptPartReader<'a, RS> {
        CryptPartReader {
            rs: &mut reader.file,
            crypt_part_state: &mut self.encrypt_part_state,
        }
    }

    pub fn open_window<'a, RS: Read + Seek>(
        &'a mut self,
        reader: &'a mut WiiIsoReader<RS>,
        offset: u64,
        length: Option<u64>,
    ) -> impl Read + Seek + 'a {
        self.get_crypto_reader(reader).into_window(offset, length)
    }

    pub fn open_file<'a, RS: Read + Seek>(
        &'a mut self,
        reader: &'a mut WiiIsoReader<RS>,
        path: &str,
    ) -> Option<impl Read + Seek + 'a> {
        let (offset, length) = self.fst.find_node_path(path).and_then(|node| match node {
            FstNode::File { offset, length, .. } => Some((*offset, *length as u64)),
            _ => None,
        })?;
        Some(self.open_window(reader, offset, Some(length)))
    }

    pub fn read_apploader<RS: Read + Seek>(
        &mut self,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<Vec<u8>> {
        let mut crypt_part_reader = self.get_crypto_reader(reader);
        crypt_part_reader.seek(SeekFrom::Start(0x2440))?;
        let apploader_header: ApploaderHeader = crypt_part_reader.read_be()?;
        let fullsize = 32 + apploader_header.size1 + apploader_header.size2;
        let mut buf = Vec::new();
        crypt_part_reader.read_into_vec(0x2440, fullsize as u64, &mut buf)?;
        Ok(buf)
    }

    pub fn read_dol<RS: Read + Seek>(
        &mut self,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<Vec<u8>> {
        let dol_offset = *self.encrypted_header.dol_off;
        let mut crypt_part_reader = self.get_crypto_reader(reader);
        crypt_part_reader.seek(SeekFrom::Start(dol_offset))?;
        let dol_header = crypt_part_reader.read_be::<DOLHeader>()?;
        let mut dol_size = dol_header.text_off[0];
        dol_size = dol_size.saturating_add(
            dol_header
                .text_sizes
                .iter()
                .chain(dol_header.data_sizes.iter())
                .cloned()
                .reduce(|accum, item| accum.saturating_add(item))
                .unwrap(),
        );
        if dol_size == u32::MAX {
            Err(binrw::Error::Custom {
                pos: dol_offset,
                err: Box::new("overflow calculating dol size!"),
            })
        } else {
            let mut out_buf = Vec::new();
            crypt_part_reader.read_into_vec(dol_offset, dol_size as u64, &mut out_buf)?;
            Ok(out_buf)
        }
    }

    pub fn extract_system_files<RS: Read + Seek>(
        &mut self,
        path: &Path,
        reader: &mut WiiIsoReader<RS>,
    ) -> binrw::BinResult<()> {
        fn write_file(sys_folder: &Path, filename: &str, data: &[u8]) -> io::Result<()> {
            let mut f = File::create(sys_folder.join(filename))?;
            f.write_all(data)?;
            f.flush()?;
            Ok(())
        }
        let sys_folder = path.join("sys");
        create_dir_all(&sys_folder)?;
        let boot_path = sys_folder.join("boot.bin");
        let mut f = File::create(boot_path)?;
        f.write_be(&self.encrypted_header)?;
        f.flush()?;
        drop(f);
        write_file(&sys_folder, "bi2.bin", &self.read_bi2(reader)?)?;
        write_file(&sys_folder, "apploader.img", &self.read_apploader(reader)?)?;
        write_file(&sys_folder, "main.dol", &self.read_dol(reader)?)?;
        let mut fst_buf = Vec::new();
        let fst_off = *self.encrypted_header.fst_off;
        let fst_sz = *self.encrypted_header.fst_sz;
        self.get_crypto_reader(reader)
            .read_into_vec(fst_off, fst_sz, &mut fst_buf)?;
        write_file(&sys_folder, "fst.bin", &fst_buf)?;
        Ok(())
    }
}

impl<RS: Read + Seek> WiiIsoReader<RS> {
    pub fn open(mut rs: RS) -> binrw::BinResult<Self> {
        rs.seek(SeekFrom::Start(0))?;
        let header: DiscHeader = rs.read_be()?;
        let partitions = read_parts(&mut rs)?;
        let mut region = [0u8; 32];
        rs.seek(SeekFrom::Start(0x4E000))?;
        rs.read_exact(&mut region)?;
        Ok(WiiIsoReader {
            file: rs,
            header,
            region,
            partitions,
        })
    }

    pub fn partitions(&self) -> &[WiiPartTableEntry] {
        &self.partitions
    }

    pub fn get_header(&self) -> &DiscHeader {
        &self.header
    }

    pub fn get_region(&self) -> &[u8; 32] {
        &self.region
    }

    pub fn open_partition(
        &mut self,
        partition: WiiPartTableEntry,
    ) -> binrw::BinResult<WiiPartitionReadInfo> {
        // read unencrypted header
        self.file.seek(SeekFrom::Start(partition.get_offset()))?;
        let wii_partition_header: WiiPartitionHeader = self.file.read_be()?;

        // prepare for encrypted part
        let mut encrypt_part_state = EncryptedPartState {
            current_group: None,
            current_position: 0,
            data_offset: partition.get_offset() + *wii_partition_header.data_off,
            encryption_key: wii_partition_header.ticket.title_key.clone(),
            data_size: *wii_partition_header.data_size,
            group_cache: Box::new([0; GROUP_SIZE as usize]),
        };

        let mut crypt_reader = CryptPartReader {
            rs: &mut self.file,
            crypt_part_state: &mut encrypt_part_state,
        };
        let encrypted_header: DiscHeader = crypt_reader.read_be()?;

        let fst = Fst::read(&mut crypt_reader, *encrypted_header.fst_off)?;

        Ok(WiiPartitionReadInfo {
            partition_entry: partition,
            wii_partition_header,
            encrypted_header,
            encrypt_part_state,
            fst,
        })
    }
}
