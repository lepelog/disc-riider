use std::{
    fs::{create_dir_all, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use aes::{
    cipher::{block_padding::NoPadding, BlockEncryptMut},
    cipher::{BlockDecryptMut, KeyIvInit},
    Aes128,
};
use binrw::{BinReaderExt, BinWrite, BinWriterExt};
use sha1::{Digest, Sha1};
use thiserror::Error;

use crate::{
    structs::{ApploaderHeader, DOLHeader, DiscHeader},
    BLOCK_DATA_OFFSET, BLOCK_DATA_SIZE, BLOCK_SIZE, GROUP_DATA_SIZE, GROUP_SIZE,
};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

enum OpenMode {
    Readonly { max_group: u64 },
    // write can either be "over"write or completely writing from scratch
    // if there is a partition after this, we have a max size constraint
    ReadWrite { max_group: Option<u64> },
}

impl OpenMode {
    fn can_write(&self) -> bool {
        matches!(self, Self::ReadWrite { .. })
    }

    fn get_max_group(&self) -> Option<u64> {
        match self {
            Self::Readonly { max_group } => Some(*max_group),
            Self::ReadWrite { max_group } => *max_group,
        }
    }

    fn get_max_size(&self) -> Option<u64> {
        self.get_max_group().map(|g| g * GROUP_DATA_SIZE)
    }
}

pub struct WiiEncryptedReadWriteStream<'a, RS: Read + Seek> {
    file: &'a mut RS,
    h3: Option<&'a mut [u8; 0x18000]>,
    data_offset: u64,
    encryption_key: [u8; 16],
    open_mode: OpenMode,
    // the current group loaded in the cache
    current_group: Option<u64>,
    // buffers the bytes for the current group, can be partially encrypted
    group_cache: Box<[u8; GROUP_SIZE as usize]>,
    // set when data is written to the current group
    // if true, this is written back to the file
    is_dirty: bool,
    // position where data is read from and written to
    current_position: u64,
    // highest group that exists currently, in write mode this can increase
    // as more groups are written
    filled_groups: u64,
}

fn hash_encrypt_block(
    buffer: &mut [u8; 0x200000],
    h3_ref: Option<&mut [u8; 20]>,
    encryption_key: &[u8; 16],
) {
    // hash the entire block using nintendos complicated algorithm
    // https://github.com/AxioDL/nod/blob/b513a7f4e02d1b2a0c4563af73ba261d6760ab0e/lib/DiscWii.cpp#L625
    let mut hasher = Sha1::new();
    let mut h2 = [0u8; 20 * 8];
    for s in 0..8 {
        let ptr1 = &mut buffer[s * 0x40000..];
        let mut h1 = [0u8; 20 * 8];
        for c in 0..8 {
            let ptr0 = &mut ptr1[c * 0x8000..];
            let mut h0 = [0u8; 20 * 31];
            for j in 0..31 {
                hasher.update(&ptr0[(j + 1) * 0x400..][..0x400]);
                h0[j * 20..][..20].copy_from_slice(&hasher.finalize_reset());
            }
            hasher.update(&h0);
            h1[c * 20..][..20].copy_from_slice(&hasher.finalize_reset());
            ptr0[..h0.len()].copy_from_slice(&h0);
            ptr0[h0.len()..][..0x14].copy_from_slice(&[0; 0x14]);
        }
        hasher.update(&h1);
        h2[s * 20..][..20].copy_from_slice(&hasher.finalize_reset());
        for c in 0..8 {
            let ptr0 = &mut ptr1[c * 0x8000..];
            ptr0[0x280..][..h1.len()].copy_from_slice(&h1);
            ptr0[0x320..][..0x20].copy_from_slice(&[0; 0x20]);
        }
    }

    hasher.update(&h2);
    if let Some(h3_ref) = h3_ref {
        h3_ref.copy_from_slice(&hasher.finalize_reset());
    }

    for s in 0..8 {
        let ptr1 = &mut buffer[s * 0x40000..];
        for c in 0..8 {
            let ptr0 = &mut ptr1[c * 0x8000..];
            ptr0[0x340..][..h2.len()].copy_from_slice(&h2);
            ptr0[0x3E0..][..0x20].copy_from_slice(&[0; 0x20]);
            Aes128CbcEnc::new(encryption_key.into(), [0; 16].as_ref().into())
                .encrypt_padded_mut::<NoPadding>(&mut ptr0[..0x400], 0x400)
                // TODO: can bad data cause a panic here?
                .unwrap();

            Aes128CbcEnc::new(encryption_key.into(), ptr0[0x3D0..][..16].into())
                .encrypt_padded_mut::<NoPadding>(&mut ptr0[0x400..0x8000], 0x8000 - 0x400)
                // TODO: can bad data cause a panic here?
                .unwrap();
        }
    }
}

#[derive(Error, Debug)]
enum VerificationError {
    #[error("H3 is not valid!")]
    H3Invalid,
    #[error("H2 (no. {0}) is not valid!")]
    H2Invalid(usize),
    #[error("H1 (no. {0}) is not valid!")]
    H1Invalid(usize),
    #[error("H0 (no. {0}) is not valid!")]
    H0Invalid(usize),
}

fn decrypt_verify_group(
    buffer: &mut [u8; 0x200000],
    h3_ref: &[u8; 20],
    encryption_key: &[u8; 16],
) -> Result<(), VerificationError> {
    // decrypt block and hashes
    for block in 0..64 {
        let block_data = &mut buffer[(block * BLOCK_SIZE) as usize..][..BLOCK_SIZE as usize];
        let crypto = Aes128CbcDec::new(
            encryption_key.into(),
            block_data[0x3d0..][..0x10].as_ref().into(),
        );
        crypto
            .decrypt_padded_mut::<NoPadding>(&mut block_data[BLOCK_DATA_OFFSET as usize..])
            // TODO: can bad data cause a panic here?
            .unwrap();

        Aes128CbcDec::new(encryption_key.into(), [0; 16].as_ref().into())
            .decrypt_padded_mut::<NoPadding>(&mut block_data[..0x400])
            // TODO: can bad data cause a panic here?
            .unwrap();
    }
    let mut hasher = Sha1::new();
    let mut h2 = [0u8; 20 * 8];
    for s in 0..8 {
        let ptr1 = &buffer[s * 0x40000..];
        let mut h1 = [0u8; 20 * 8];
        for c in 0..8 {
            let ptr0 = &ptr1[c * 0x8000..];
            let mut h0 = [0u8; 20 * 31];
            for j in 0..31 {
                hasher.update(&ptr0[(j + 1) * 0x400..][..0x400]);
                h0[j * 20..][..20].copy_from_slice(&hasher.finalize_reset());
            }
            hasher.update(&h0);
            h1[c * 20..][..20].copy_from_slice(&hasher.finalize_reset());
            if ptr0[..h0.len()] != h0 || ptr0[h0.len()..][..0x14] != [0; 0x14] {
                return Err(VerificationError::H0Invalid(s * 8 + c));
            }
        }
        hasher.update(&h1);
        h2[s * 20..][..20].copy_from_slice(&hasher.finalize_reset());
        for c in 0..8 {
            let ptr0 = &ptr1[c * 0x8000..];
            if ptr0[0x280..][..h1.len()] != h1 || ptr0[0x320..][..0x20] != [0; 0x20] {
                return Err(VerificationError::H1Invalid(s * 8 + c));
            }
        }
    }

    hasher.update(&h2);
    if h3_ref != hasher.finalize_reset().as_slice() {
        return Err(VerificationError::H3Invalid);
    }

    for s in 0..8 {
        let ptr1 = &buffer[s * 0x40000..];
        for c in 0..8 {
            let ptr0 = &ptr1[c * 0x8000..];
            if ptr0[0x340..][..h2.len()] != h2 || ptr0[0x3E0..][..0x20] != [0; 0x20] {
                return Err(VerificationError::H2Invalid(s * 8 + c));
            }
        }
    }
    Ok(())
}

impl<'a, RS: Read + Seek> WiiEncryptedReadWriteStream<'a, RS> {
    pub fn create_readonly(
        file: &'a mut RS,
        data_offset: u64,
        encryption_key: [u8; 16],
        max_group: u64,
    ) -> Self {
        // let group_cache = Box::new([0; GROUP_SIZE as usize]);
        let group_cache = vec![0; GROUP_SIZE as usize]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        WiiEncryptedReadWriteStream {
            file,
            h3: None,
            data_offset,
            encryption_key,
            open_mode: OpenMode::Readonly { max_group },
            current_group: None,
            group_cache,
            is_dirty: false,
            current_position: 0,
            // not relevant for readonly
            filled_groups: 0,
        }
    }
    // loads an entire group into cache and decrypts it
    fn do_load_group(&mut self, group: u64) -> io::Result<()> {
        self.is_dirty = false;
        self.file
            .seek(SeekFrom::Start(self.data_offset + group * GROUP_SIZE))?;
        self.file.read_exact(self.group_cache.as_mut())?;
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

    fn get_decrypted_block_data(&mut self, group: u64, block: u64) -> io::Result<&[u8]> {
        if !self.current_group.map_or(false, |g| g == group) {
            self.do_load_group(group)?;
        }
        let block_data =
            &mut self.group_cache[(block * BLOCK_SIZE) as usize..][..BLOCK_SIZE as usize];
        Ok(&block_data[BLOCK_DATA_OFFSET as usize..])
    }

    /// Reads the specified amount of bytes from the given offset into the buffer, clearing it and ensuring proper capacity
    /// does not affect the current read position
    /// TODO: this only exists cause ReadBuf isn't stable yet...
    pub fn read_into_vec(
        &mut self,
        mut offset: u64,
        length: u64,
        buffer: &mut Vec<u8>,
    ) -> io::Result<()> {
        buffer.clear();
        buffer.reserve(length as usize);
        let max_size = self.open_mode.get_max_size();
        let mut group = offset / GROUP_DATA_SIZE;
        let mut block = (offset % GROUP_DATA_SIZE) / BLOCK_DATA_SIZE;
        let mut offset_in_block_data = offset % BLOCK_DATA_SIZE;
        while buffer.len() < length as usize {
            if max_size.map_or(false, |size| offset >= size) {
                break;
            }
            // we either copy the entire block or what's needed to fill the vec
            let count_to_copy =
                (BLOCK_DATA_SIZE - offset_in_block_data).min(length - buffer.len() as u64);
            buffer.extend_from_slice(
                &self.get_decrypted_block_data(group, block)?[offset_in_block_data as usize..]
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

    pub fn get_inner(&mut self) -> &mut RS {
        self.file
    }

    pub fn get_filled_groups(&self) -> u64 {
        self.filled_groups
    }

    pub fn read_apploader(&mut self) -> binrw::BinResult<Vec<u8>> {
        self.seek(SeekFrom::Start(0x2440))?;
        let apploader_header: ApploaderHeader = self.read_be()?;
        let fullsize = 32 + apploader_header.size1 + apploader_header.size2;
        let mut buf = Vec::new();
        self.read_into_vec(0x2440, fullsize as u64, &mut buf)?;
        Ok(buf)
    }

    pub fn read_dol(&mut self, dol_offset: u64) -> binrw::BinResult<Vec<u8>> {
        self.seek(SeekFrom::Start(dol_offset))?;
        let dol_header = self.read_be::<DOLHeader>()?;
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
            self.read_into_vec(dol_offset, dol_size as u64, &mut out_buf)?;
            Ok(out_buf)
        }
    }

    pub fn read_disc_header(&mut self) -> binrw::BinResult<DiscHeader> {
        self.seek(SeekFrom::Start(0))?;
        self.read_be()
    }

    pub fn extract_system_files(&mut self, path: &Path) -> binrw::BinResult<()> {
        fn write_binrw<B: BinWrite>(
            sys_foler: &PathBuf,
            filename: &str,
            data: &B,
        ) -> binrw::BinResult<()>
        where
            <B as BinWrite>::Args: Default,
        {
            let mut path = sys_foler.clone();
            path.push(filename);
            let mut f = File::create(path)?;
            f.write_be(data)?;
            f.flush()?;
            Ok(())
        }
        fn write_file(sys_folder: &Path, filename: &str, data: &[u8]) -> io::Result<()> {
            let mut path = sys_folder.to_path_buf();
            path.push(filename);
            let mut f = File::create(path)?;
            f.write_all(data)?;
            f.flush()?;
            Ok(())
        }
        let mut sys_folder = PathBuf::from(path);
        sys_folder.push("sys");
        create_dir_all(&sys_folder)?;
        // read header
        self.seek(SeekFrom::Start(0))?;
        let disc_header: DiscHeader = self.read_be()?;
        write_binrw(&sys_folder, "boot.bin", &disc_header)?;
        let mut bi2 = vec![0; 0x2000];
        self.read_exact(&mut bi2)?;
        write_file(&sys_folder, "bi2.bin", &bi2)?;
        println!("{:?}", self.stream_position());
        let apploader = self.read_apploader()?;
        write_file(&sys_folder, "apploader.img", &apploader)?;
        let dol = self.read_dol(*disc_header.dol_off)?;
        write_file(&sys_folder, "main.dol", &dol)?;
        let mut fst_buf = Vec::new();
        self.read_into_vec(
            *disc_header.fst_off,
            *disc_header.fst_sz as u64,
            &mut fst_buf,
        )?;
        write_file(&sys_folder, "fst.bin", &fst_buf)?;
        Ok(())
    }
}

impl<'a, RS: Write + Read + Seek> WiiEncryptedReadWriteStream<'a, RS> {
    /// max_group is used for the limit of groups, it's not possible to write groups past that limit
    /// filled_groups is used to let the writer know how many groups already have content (can be 0 if starting from scratch)
    pub fn create_write(
        file: &'a mut RS,
        h3: &'a mut [u8; 0x18000],
        data_offset: u64,
        encryption_key: [u8; 16],
        max_group: Option<u64>,
        filled_groups: u64,
    ) -> Self {
        // let group_cache = Box::new([0; GROUP_SIZE as usize]);
        let group_cache = vec![0; GROUP_SIZE as usize]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        WiiEncryptedReadWriteStream {
            file,
            h3: Some(h3),
            data_offset,
            encryption_key,
            open_mode: OpenMode::ReadWrite { max_group },
            current_group: None,
            group_cache,
            is_dirty: false,
            current_position: 0,
            filled_groups,
        }
    }
}

impl<'a, RS: Read + Seek> Read for WiiEncryptedReadWriteStream<'a, RS> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let max_size = self.open_mode.get_max_size();
        let mut group = self.current_position / GROUP_DATA_SIZE;
        let mut block = (self.current_position % GROUP_DATA_SIZE) / BLOCK_DATA_SIZE;
        let mut offset_in_block_data = self.current_position % BLOCK_DATA_SIZE;
        let mut read_bytes = 0;
        while !buf.is_empty() {
            if max_size.map_or(false, |size| self.current_position >= size) {
                break;
            }
            // we either copy the entire block or what's needed to fill the vec
            let count_to_copy = (BLOCK_DATA_SIZE - offset_in_block_data).min(buf.len() as u64);
            let to_fill;
            (to_fill, buf) = buf.split_at_mut(count_to_copy as usize);
            to_fill.copy_from_slice(
                &self.get_decrypted_block_data(group, block)?[offset_in_block_data as usize..]
                    [..count_to_copy as usize],
            );
            self.current_position += count_to_copy;
            read_bytes += count_to_copy;
            offset_in_block_data = 0;
            block += 1;
            if block == 64 {
                block = 0;
                group += 1;
            }
        }
        Ok(read_bytes as usize)
    }
}

impl<'a, WS: Write + Read + Seek> Write for WiiEncryptedReadWriteStream<'a, WS> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        match &self.open_mode {
            OpenMode::Readonly { .. } => Err(io::ErrorKind::Unsupported.into()),
            &OpenMode::ReadWrite { max_group, .. } => {
                let mut bytes_written = 0;
                let mut group = self.current_position / GROUP_DATA_SIZE;
                let mut block = (self.current_position % GROUP_DATA_SIZE) / BLOCK_DATA_SIZE;
                let mut offset_in_block =
                    BLOCK_DATA_OFFSET + (self.current_position % BLOCK_DATA_SIZE);
                while !buf.is_empty() {
                    if max_group.map_or(false, |g| g <= group) {
                        // we are above the limit
                        break;
                    }
                    // if we're not in the current group of the buffer anymore, load that group
                    if let Some(current_group) = self.current_group {
                        if current_group != group {
                            if self.is_dirty {
                                hash_encrypt_block(
                                    &mut self.group_cache,
                                    self.h3.as_mut().map(|h3| {
                                        h3[20 * current_group as usize..][..20]
                                            .as_mut()
                                            .try_into()
                                            .unwrap()
                                    }),
                                    &self.encryption_key,
                                );
                                self.file.seek(SeekFrom::Start(
                                    self.data_offset + GROUP_SIZE * current_group,
                                ))?;
                                self.file.write_all(self.group_cache.as_ref())?;
                                self.filled_groups = self.filled_groups.max(current_group);
                            }
                            // we can skip loading the previous data if
                            // - we are at the start of a group and would completely overwrite it
                            // - or if this is a block that didn't exist previously
                            if !((block == 0
                                && offset_in_block == 0x400
                                && buf.len() >= GROUP_DATA_SIZE as usize)
                                || group > self.filled_groups)
                            {
                                // TODO: you *could* seek an entire block ahead, in that case there
                                // would be a completely empty block, but I guess that's fine?
                                self.filled_groups = self.filled_groups.max(group);
                                self.do_load_group(group)?;
                            }
                        }
                    }
                    self.current_group = Some(group);
                    self.is_dirty = true;
                    let bytes_to_copy = (BLOCK_SIZE - offset_in_block).min(buf.len() as u64);
                    self.group_cache[(block * BLOCK_SIZE + offset_in_block) as usize..]
                        [..bytes_to_copy as usize]
                        .copy_from_slice(&buf[..bytes_to_copy as usize]);
                    buf = &buf[bytes_to_copy as usize..];
                    bytes_written += bytes_to_copy;
                    block += 1;
                    if block == 64 {
                        block = 0;
                        group += 1;
                    }
                    offset_in_block = BLOCK_DATA_OFFSET;
                }
                self.current_position += bytes_written;
                Ok(bytes_written as usize)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.open_mode {
            OpenMode::Readonly { .. } => Err(io::ErrorKind::Unsupported.into()),
            OpenMode::ReadWrite { .. } => {
                if let Some(current_group) = self.current_group {
                    if self.is_dirty {
                        hash_encrypt_block(
                            &mut self.group_cache,
                            self.h3.as_mut().map(|h3| {
                                h3[20 * current_group as usize..][..20]
                                    .as_mut()
                                    .try_into()
                                    .unwrap()
                            }),
                            &self.encryption_key,
                        );
                        self.file.seek(SeekFrom::Start(
                            self.data_offset + GROUP_SIZE * current_group,
                        ))?;
                        self.file.write_all(self.group_cache.as_ref())?;
                        self.filled_groups = self.filled_groups.max(current_group);
                        self.file.flush()?;
                        self.current_group = None;
                    }
                }
                Ok(())
            }
        }
    }
}

impl<'a, RS: Read + Seek> Seek for WiiEncryptedReadWriteStream<'a, RS> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Current(off) => self.current_position as i64 + off,
            SeekFrom::Start(off) => off as i64,
            // TODO: support seeking from the end when it's known?
            SeekFrom::End(_off) => return Err(io::Error::from(io::ErrorKind::Unsupported)),
        };
        self.current_position = new_pos.max(0) as u64;
        Ok(self.current_position)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.current_position)
    }
}

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{Cursor, Seek, SeekFrom, Write},
    };

    use crate::{GROUP_DATA_SIZE, GROUP_SIZE};

    use super::WiiEncryptedReadWriteStream;

    #[test]
    fn test_write() {
        // let mut h3 = Box::new([0u8; 0x18000]);
        let mut h3: Box<[u8; 0x18000]> = vec![0u8; 0x18000].into_boxed_slice().try_into().unwrap();
        let mut disc_buf: Vec<u8> = Vec::with_capacity(GROUP_SIZE as usize * 4);
        let mut cur = Cursor::new(&mut disc_buf);
        let mut encrypt_write = WiiEncryptedReadWriteStream::create_write(
            &mut cur,
            &mut h3,
            0,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            None,
            0,
        );
        let garbage = Box::new([12u8; GROUP_DATA_SIZE as usize + 0x1000]);
        encrypt_write.write(garbage.as_ref()).unwrap();
        encrypt_write.seek(SeekFrom::Start(200)).unwrap();
        encrypt_write.write(&[69; 200]).unwrap();
        encrypt_write
            .seek(SeekFrom::Start(GROUP_DATA_SIZE + 100))
            .unwrap();
        encrypt_write.write(&[1; 500]).unwrap();
        encrypt_write.flush().unwrap();
        let mut data = Vec::new();
        encrypt_write
            .read_into_vec(0, GROUP_DATA_SIZE + 0x1000, &mut data)
            .unwrap();
        let mut outf = File::create("test.bin").unwrap();
        outf.write_all(&data).unwrap();
        drop(outf);
        for i in &data[0..200] {
            assert_eq!(*i, 12);
        }
        for i in &data[200..400] {
            assert_eq!(*i, 69);
        }
        for i in &data[400..GROUP_DATA_SIZE as usize + 100] {
            assert_eq!(*i, 12);
        }
        // for i in &data[GROUP_DATA_SIZE as usize + 100..GROUP_DATA_SIZE as usize + 600] {
        //     assert_eq!(*i, 1);
        // }
        for i in &data[GROUP_DATA_SIZE as usize + 600..GROUP_DATA_SIZE as usize + 0x1000] {
            assert_eq!(*i, 12);
        }
        assert_eq!(disc_buf.len() as u64, GROUP_SIZE * 2);
    }
}
