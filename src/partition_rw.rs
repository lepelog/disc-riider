use std::io::{Read, Seek, SeekFrom};

use binrw::BinReaderExt;

use crate::{
    reader_writer::WiiEncryptedReadWriteStream,
    structs::{Certificate, WiiPartitionHeader, TMD},
    WiiIsoReader, GROUP_DATA_SIZE,
};

pub struct PartitionReader<'a, RS: Read + Seek> {
    reader: &'a mut WiiIsoReader<RS>,
    partition_offset: u64,
    wii_partition_header: WiiPartitionHeader,
}

impl<'a, RS: Read + Seek> PartitionReader<'a, RS> {
    pub(crate) fn open_partition(
        reader: &'a mut WiiIsoReader<RS>,
        partition_offset: u64,
    ) -> binrw::BinResult<Self> {
        reader.file.seek(SeekFrom::Start(partition_offset))?;
        let wii_partition_header = reader.file.read_be()?;
        Ok(Self {
            reader,
            partition_offset,
            wii_partition_header,
        })
    }

    pub fn get_partition_header(&self) -> &WiiPartitionHeader {
        &self.wii_partition_header
    }

    pub fn get_header(&self) -> &WiiPartitionHeader {
        &self.wii_partition_header
    }

    pub fn get_partition_offset(&self) -> u64 {
        self.partition_offset
    }

    pub fn read_tmd(&mut self) -> binrw::BinResult<TMD> {
        self.reader.file.seek(SeekFrom::Start(
            self.partition_offset + *self.wii_partition_header.tmd_off,
        ))?;
        self.reader.file.read_be()
    }

    pub fn read_certificates(&mut self) -> binrw::BinResult<[Certificate; 3]> {
        self.reader.file.seek(SeekFrom::Start(
            self.partition_offset + *self.wii_partition_header.cert_chain_off,
        ))?;
        self.reader.file.read_be()
    }

    pub fn read_h3(&mut self) -> binrw::BinResult<Box<[u8; 0x18000]>> {
        self.reader.file.seek(SeekFrom::Start(
            self.partition_offset + *self.wii_partition_header.global_hash_table_off,
        ))?;
        // TODO: use ReadBuf when it's stable,
        let mut h3_buf: Box<[u8; 0x18000]> =
            vec![0; 0x18000].into_boxed_slice().try_into().unwrap();
        self.reader.file.read_exact(h3_buf.as_mut())?;
        Ok(h3_buf)
    }

    pub fn get_iso_reader(&mut self) -> &mut WiiIsoReader<RS> {
        self.reader
    }

    pub fn open_encryption_reader(&mut self) -> WiiEncryptedReadWriteStream<RS> {
        WiiEncryptedReadWriteStream::create_readonly(
            &mut self.reader.file,
            self.partition_offset + *self.wii_partition_header.data_off,
            self.wii_partition_header.ticket.title_key,
            *self.wii_partition_header.data_size / GROUP_DATA_SIZE,
        )
    }
}
