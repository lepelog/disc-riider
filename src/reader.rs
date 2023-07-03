use std::io::{Read, Seek, SeekFrom};

use binrw::BinReaderExt;

use crate::{
    partition_rw::PartitionReader,
    reader_writer::WiiEncryptedReadWriteStream,
    structs::{read_parts, ApploaderHeader, DiscHeader, WiiPartTableEntry, WiiPartType},
};

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

    pub fn partitions(&self) -> &[WiiPartTableEntry] {
        &self.partitions
    }

    pub fn get_header(&self) -> &DiscHeader {
        &self.header
    }

    pub fn get_region(&self) -> &[u8; 32] {
        &self.region
    }

    pub fn open_partition_stream_by_index<'a>(
        &'a mut self,
        idx: usize,
    ) -> binrw::BinResult<PartitionReader<'a, RS>> {
        let partition = &self.partitions[idx];
        PartitionReader::open_partition(self, *partition.part_data_off)
    }

    pub fn open_partition_stream<'a>(
        &'a mut self,
        part_type: &WiiPartType,
    ) -> binrw::BinResult<PartitionReader<'a, RS>> {
        let partition = self
            .partitions
            .iter()
            .find(|p| p.part_type == *part_type)
            .cloned()
            .unwrap();
        PartitionReader::open_partition(self, *partition.part_data_off)
    }
}

pub fn read_apploader<RS: Read + Seek>(
    rs: &mut WiiEncryptedReadWriteStream<RS>,
) -> binrw::BinResult<Vec<u8>> {
    rs.seek(SeekFrom::Start(0x2440))?;
    let apploader_header: ApploaderHeader = rs.read_be()?;
    let fullsize = 32 + apploader_header.size1 + apploader_header.size2;
    let mut buf = Vec::new();
    rs.read_into_vec(0x2440, fullsize as u64, &mut buf)?;
    Ok(buf)
}
