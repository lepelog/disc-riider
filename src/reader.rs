use std::io::{self, Read, Seek, SeekFrom};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit},
    Aes128,
};
use binrw::BinReaderExt;

use crate::{
    fst::Fst,
    structs::{
        read_parts, Certificate, DOLHeader, DiscHeader, WiiPartTableEntry, WiiPartitionHeader, TMD, ApploaderHeader, WiiPartType,
    },
    window::IOWindow,
    BLOCK_DATA_OFFSET, BLOCK_DATA_SIZE, BLOCK_SIZE, reader_writer::WiiEncryptedReadWriteStream, partition_rw::PartitionReader,
};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub struct WiiIsoReader<RS: Read + Seek> {
    pub file: RS,
    // TODO: proper structs
    header: DiscHeader,
    region: [u8; 32],
    partitions: Vec<WiiPartTableEntry>,
}

impl<RS: Read + Seek> WiiIsoReader<RS> {
    pub fn create(mut rs: RS) -> binrw::BinResult<Self> {
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

    pub fn partitions(&self) -> &Vec<WiiPartTableEntry> {
        &self.partitions
    }

    pub fn get_header(&self) -> &DiscHeader {
        &self.header
    }

    pub fn get_region(&self) -> &[u8; 32] {
        &self.region
    }

    pub fn partition_stream(
        &mut self,
        part: &WiiPartTableEntry,
    ) -> binrw::BinResult<WiiPartitionReadStream<RS>> {
        self.partition_read_stream_from_offset(*part.part_data_off)
    }

    fn partition_read_stream_from_offset(
        &mut self,
        offset: u64,
    ) -> binrw::BinResult<WiiPartitionReadStream<RS>> {
        self.file.seek(SeekFrom::Start(offset))?;
        let partition_header = self.file.read_be::<WiiPartitionHeader>()?;
        println!("{:?}", partition_header);
        let now_off = self.file.stream_position()?;
        println!("{}", now_off - offset);
        Ok(WiiPartitionReadStream {
            iso_reader: self,
            data_offset: offset,
            partition_header,
            current_block: None,
            // TODO: try maybe uninit stuff?
            block_cache: vec![0; BLOCK_SIZE as usize],
            read_position: 0,
        })
    }

    pub fn open_partition_stream<'a>(&'a mut self, part_type: &WiiPartType) -> binrw::BinResult<PartitionReader<'a, RS>>{
        let partition = self.partitions.iter()
                .find(|p| p.part_type == *part_type)
                .cloned()
                .unwrap();
        PartitionReader::open_partition(self, *partition.part_data_off)
    }
}

pub struct WiiPartitionReadStream<'a, RS: Read + Seek> {
    iso_reader: &'a mut WiiIsoReader<RS>,
    data_offset: u64,
    partition_header: WiiPartitionHeader,
    current_block: Option<u64>,
    block_cache: Vec<u8>,
    read_position: u64,
}

impl<'a, RS: Read + Seek> WiiPartitionReadStream<'a, RS> {
    #[inline]
    fn get_encrypted_data_offset(&self) -> u64 {
        self.data_offset + *self.partition_header.data_off
    }

    #[inline]
    fn get_block_and_offset(&self, data_offset: u64) -> (u64, u64) {
        (data_offset / BLOCK_DATA_SIZE, data_offset % BLOCK_DATA_SIZE)
    }

    // loads block if necessary
    fn get_decrypted_block_data(&mut self, block: u64) -> io::Result<&[u8]> {
        if !self.current_block.map_or(false, |b| b == block) {
            // load encrypted block
            let disc_block_off = self.get_encrypted_data_offset() + BLOCK_SIZE * block;
            self.iso_reader.file.seek(SeekFrom::Start(disc_block_off))?;
            self.iso_reader.file.read_exact(&mut self.block_cache)?;
            // decrypt
            let crypto = Aes128CbcDec::new(
                self.partition_header.ticket.title_key.as_ref().into(),
                self.block_cache[0x3d0..][..0x10].as_ref().into(),
            );
            crypto
                .decrypt_padded_mut::<NoPadding>(
                    &mut self.block_cache[BLOCK_DATA_OFFSET as usize..],
                )
                // TODO: can bad data cause a panic here?
                .unwrap();
            self.current_block = Some(block);
        }
        Ok(&self.block_cache[BLOCK_DATA_OFFSET as usize..])
    }

    /// Reads the specified amount of bytes from the given offset into the buffer, clearing it and ensuring proper capacity
    /// does not affect the current read position
    pub fn read_into_vec(
        &mut self,
        mut offset: u64,
        length: u64,
        buffer: &mut Vec<u8>,
    ) -> io::Result<()> {
        buffer.clear();
        buffer.reserve(length as usize);
        while buffer.len() < length as usize {
            if offset >= *self.partition_header.data_size {
                break;
            }
            let (block, offset_in_block) = self.get_block_and_offset(offset);
            // we either copy the entire block or what's needed to fill the vec
            let count_to_copy =
                (BLOCK_DATA_SIZE - offset_in_block).min(length - buffer.len() as u64);
            buffer.extend_from_slice(
                &self.get_decrypted_block_data(block)?[offset_in_block as usize..]
                    [..count_to_copy as usize],
            );
            offset += count_to_copy;
        }
        Ok(())
    }

    pub fn get_partition_header(&self) -> &WiiPartitionHeader {
        &self.partition_header
    }

    pub fn read_tmd(&mut self, tmd_offset: u64) -> binrw::BinResult<TMD> {
        self.iso_reader
            .file
            .seek(SeekFrom::Start(self.data_offset + tmd_offset))?;
        self.iso_reader.file.read_be()
    }

    pub fn read_certificates(&mut self, cert_chain_off: u64) -> binrw::BinResult<[Certificate; 3]> {
        self.iso_reader
            .file
            .seek(SeekFrom::Start(self.data_offset + cert_chain_off))?;
        self.iso_reader.file.read_be()
    }

    pub fn read_h3(&mut self, global_hash_table_off: u64) -> binrw::BinResult<Vec<u8>> {
        self.iso_reader
            .file
            .seek(SeekFrom::Start(self.data_offset + global_hash_table_off))?;
        // TODO: use ReadBuf when it's stable,
        let mut h3_buf = vec![0; 0x18000];
        self.iso_reader.file.read_exact(&mut h3_buf)?;
        Ok(h3_buf)
    }

    pub fn read_header(&mut self) -> binrw::BinResult<DiscHeader> {
        self.seek(SeekFrom::Start(0))?;
        let hdr = self.read_be::<DiscHeader>()?;
        println!("{:?}", self.stream_position());
        Ok(hdr)
    }

    pub fn read_fst(&mut self, fst_offset: u64) -> binrw::BinResult<Fst> {
        Fst::read(self, fst_offset)
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
            return Err(binrw::Error::Custom {
                pos: dol_offset,
                err: Box::new("overflow calculating dol size!"),
            });
        } else {
            let mut out_buf = vec![0; dol_size as usize];
            self.seek(SeekFrom::Start(dol_offset))?;
            self.read_exact(&mut out_buf)?;
            Ok(out_buf)
        }
    }
}

impl<'a, RS: Read + Seek> Read for WiiPartitionReadStream<'a, RS> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_size = 0;
        while read_size < buf.len() {
            if self.read_position >= *self.partition_header.data_size {
                break;
            }
            let (block, offset_in_block) = self.get_block_and_offset(self.read_position);
            // we either copy the entire block or what's needed to fill the vec
            let count_to_copy =
                (BLOCK_DATA_SIZE - offset_in_block).min((buf.len() - read_size) as u64);
            buf[read_size as usize..][..count_to_copy as usize].copy_from_slice(
                &self.get_decrypted_block_data(block)?[offset_in_block as usize..]
                    [..count_to_copy as usize],
            );
            self.read_position += count_to_copy;
            read_size += count_to_copy as usize;
        }
        Ok(read_size)
    }
}

impl<'a, RS: Read + Seek> Seek for WiiPartitionReadStream<'a, RS> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Current(off) => self.read_position as i64 + off,
            SeekFrom::Start(off) => off as i64,
            SeekFrom::End(off) => *self.partition_header.data_size as i64 + off,
        };
        self.read_position = new_pos.clamp(0, *self.partition_header.data_size as i64) as u64;
        Ok(self.read_position)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.read_position)
    }
}

pub fn read_apploader<RS: Read + Seek>(rs: &mut WiiEncryptedReadWriteStream<RS>) -> binrw::BinResult<Vec<u8>> {
    rs.seek(SeekFrom::Start(0x2440))?;
    let apploader_header: ApploaderHeader = rs.read_be()?;
    let fullsize = 32 + apploader_header.size1 + apploader_header.size2;
    let mut buf = Vec::new();
    rs.read_into_vec(0x2440, fullsize as u64, &mut buf)?;
    Ok(buf)
}
