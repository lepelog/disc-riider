use std::{
    borrow::{Borrow, Cow},
    convert::Infallible,
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use binrw::{BinReaderExt, BinWriterExt};
use sha1::{Digest, Sha1};

use crate::{
    dir_reader::{self, BuildDirError},
    fst::FstToBytesError,
    reader_writer::WiiEncryptedReadWriteStream,
    structs::{
        Certificate, DiscHeader, Ticket, WiiPartTableEntry, WiiPartType, WiiPartitionHeader, TMD,
    },
    Fst, FstNode, FstToBytes, IOWindow, WiiIsoReader, WiiPartitionReadInfo, GROUP_DATA_SIZE,
    GROUP_SIZE,
};

#[inline]
// only works with power of 2
// also misbehaves on overflow
fn align_next(num: u64, alignment: u64) -> u64 {
    num.wrapping_add(alignment - 1) & !(alignment - 1)
}

#[derive(thiserror::Error, Debug)]
pub enum PartitionAddError<E: Error> {
    #[error("{0}")]
    Custom(E),
    #[error("io error: {0}")]
    IO(#[from] io::Error),
    #[error("binrw error: {0}")]
    BinRW(#[from] binrw::Error),
    #[error("fst build failed: {0}")]
    Fst(#[from] FstToBytesError),
}

// 0: disc header
// 0x40000 partition type + offset info
// 0x50000 partitions start

// partitions
// plain:
//  0: partition header
//  tmd, cert chain, global hash table (h3), actual data (size is what decrypted)
// encrypted
//  disc header
//  apploader: 0x2440
//  dol
//  fst
//  data

/// Trait to implement for building a wii partition.
pub trait WiiPartitionDefinition<E: Error> {
    /// returns the header of the partition which looks like a disc header
    fn get_disc_header(&mut self) -> Result<DiscHeader, PartitionAddError<E>>;
    fn get_bi2<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, PartitionAddError<E>>;

    /// returns the apploader of this partition
    fn get_apploader<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, PartitionAddError<E>>;

    /// returns the file system table for this partition
    /// offset and length of files are just placeholders here
    fn get_fst(&mut self) -> Result<Fst, PartitionAddError<E>>;

    /// returns the dol of this partition
    fn get_dol<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, PartitionAddError<E>>;

    /// this function gets called for every file in the file system table with the full path
    /// returns either the data in a Cow and a size with additional padding or an error
    fn get_file_data<'a>(
        &'a mut self,
        path: &Vec<String>,
    ) -> Result<(Cow<'a, [u8]>, u32), PartitionAddError<E>>;
}

pub struct WiiDiscBuilder<WS: Read + Write + Seek> {
    file: WS,
    disc_header: DiscHeader,
    region: [u8; 32],
    current_data_offset: u64,
    partitions: Vec<WiiPartTableEntry>,
}

impl<WS: Read + Write + Seek> WiiDiscBuilder<WS> {
    pub fn create(file: WS, disc_header: DiscHeader, region: [u8; 32]) -> Self {
        Self {
            file,
            disc_header,
            region,
            current_data_offset: 0x50000,
            partitions: Vec::new(),
        }
    }

    pub fn add_partition<P, E, C>(
        &mut self,
        part_type: WiiPartType,
        ticket: Ticket,
        tmd: TMD,
        cert_chain: [Certificate; 3],
        partition_def: &mut P,
        progress_cb: &mut C,
    ) -> Result<(), PartitionAddError<E>>
    where
        P: WiiPartitionDefinition<E>,
        E: Error,
        C: FnMut(u8),
    {
        progress_cb(0);
        let part_data_off = self.current_data_offset;
        let mut partition_window = IOWindow::new(&mut self.file, part_data_off, None);
        self.partitions.push(WiiPartTableEntry {
            part_data_off: part_data_off.into(),
            part_type,
        });
        // placeholder header
        let mut part_header = WiiPartitionHeader {
            ticket,
            tmd_off: 0.into(),
            tmd_size: 0,
            cert_chain_off: 0.into(),
            cert_chain_size: 0,
            global_hash_table_off: 0.into(),
            data_off: 0.into(),
            data_size: 0.into(),
        };
        // TODO: check that the header has a size of 704
        // already aligned to 0x20
        part_header.tmd_off = 704.into();
        // space for TMD
        let mut tmd_buf = Vec::new();
        Cursor::new(&mut tmd_buf).write_be(&tmd)?;
        part_header.tmd_size = tmd_buf.len() as u32;
        part_header.cert_chain_off =
            align_next(*part_header.tmd_off + part_header.tmd_size as u64, 0x20).into();
        partition_window.seek(SeekFrom::Start(*part_header.cert_chain_off))?;
        partition_window.write_be(&cert_chain)?;
        part_header.cert_chain_size =
            (partition_window.stream_position()? - *part_header.cert_chain_off) as u32;
        // global hash table at 0x8000, encrypted data starts at 0x20000
        // let mut h3: Box<[u8; 0x18000]> = vec![0u8; 0x18000].into_boxed_slice().try_into().unwrap();
        // now we write encrypted data
        let mut crypto_writer = WiiEncryptedReadWriteStream::create_write(
            &mut partition_window,
            0x20000,
            part_header.ticket.title_key,
            None,
            0,
        );
        let source_fst = partition_def.get_fst()?;
        let mut total_files = 0;
        // TODO: currently use total_bytes = 0 as an indicator that the size is unknown
        let mut total_bytes = 0;
        source_fst
            .callback_all_files::<Infallible, _>(&mut |_, node| {
                match node {
                    FstNode::File { length, .. } => {
                        total_files += 1;
                        total_bytes += *length as usize;
                    }
                    _ => (),
                }
                Ok(())
            })
            .unwrap();
        let uses_file_byte_progress = total_bytes != 0;
        let mut fst = FstToBytes::try_from(source_fst)?;
        let mut part_disc_header = partition_def.get_disc_header()?;
        crypto_writer.seek(SeekFrom::Start(0x440))?;
        crypto_writer.write_all(&partition_def.get_bi2()?)?;

        // write apploader (always at the same address)
        crypto_writer.seek(SeekFrom::Start(0x2440))?;
        crypto_writer.write_all(&partition_def.get_apploader()?)?;

        // write dol
        part_disc_header.dol_off = align_next(crypto_writer.stream_position()?, 0x20).into();
        crypto_writer.seek(SeekFrom::Start(*part_disc_header.dol_off))?;
        crypto_writer.write_all(&partition_def.get_dol()?)?;

        // temp write FST
        // will be written again properly later
        part_disc_header.fst_off = align_next(crypto_writer.stream_position()?, 0x20).into();
        crypto_writer.seek(SeekFrom::Start(*part_disc_header.fst_off))?;
        fst.write_to(&mut crypto_writer)?;
        // pad to 4
        crypto_writer.write_all(&[0; 4])?;
        let fst_end = crypto_writer.stream_position()?;
        part_disc_header.fst_sz = (fst_end - *part_disc_header.fst_off).into();
        part_disc_header.fst_max_sz = part_disc_header.fst_sz;

        // now we can actually write the data
        let data_start = align_next(crypto_writer.stream_position()?, 0x40);
        crypto_writer.seek(SeekFrom::Start(data_start))?;
        let mut processed_files = 0;
        let mut processed_file_bytes = 0;
        fst.callback_all_files_mut::<PartitionAddError<E>, _>(&mut |path, offset, size| {
            processed_files += 1;
            *offset = crypto_writer.stream_position()?;
            let (data, padding) = partition_def.get_file_data(path)?;
            let mut remaining_data = data.as_ref();
            *size = remaining_data.len() as u32;
            while remaining_data.len() > 0 {
                let bytes_to_write = remaining_data.len().min(0x1_000_000);
                let batch;
                (batch, remaining_data) = remaining_data.split_at(bytes_to_write);
                crypto_writer.write_all(batch)?;
                if uses_file_byte_progress {
                    processed_file_bytes += bytes_to_write;
                    let done_percent =
                        ((processed_file_bytes as f64) / (total_bytes as f64) * 100f64) as u8;
                    progress_cb(done_percent);
                }
            }
            let next_start = align_next(crypto_writer.stream_position()? + padding as u64, 0x40);
            crypto_writer.seek(SeekFrom::Start(next_start))?;
            if !uses_file_byte_progress {
                let done_percent = ((processed_files as f64) / (total_files as f64) * 100f64) as u8;
                progress_cb(done_percent);
            }
            Ok(())
        })?;

        // align total size to next full group
        let groups = (crypto_writer.stream_position()? + GROUP_DATA_SIZE - 1) / GROUP_DATA_SIZE;
        let total_size = groups * GROUP_DATA_SIZE;
        let total_encrypted_size = groups * GROUP_SIZE;

        self.current_data_offset += 0x20000 /* encrypted data off */ + total_encrypted_size;

        // data is written, write the fst properly now
        crypto_writer.seek(SeekFrom::Start(*part_disc_header.fst_off))?;
        fst.write_to(&mut crypto_writer)?;

        // write partition header
        crypto_writer.seek(SeekFrom::Start(0))?;
        crypto_writer.write_be(&part_disc_header)?;
        crypto_writer.flush()?;
        let h3 = crypto_writer.take_h3().unwrap();
        // we're done with the encrypted part, only need to correct some headers now
        drop(crypto_writer);
        // write h3
        partition_window.seek(SeekFrom::Start(0x8000))?;
        partition_window.write_all(h3.as_ref())?;
        // write info to header
        part_header.global_hash_table_off = 0x8000.into();
        part_header.data_off = 0x20000.into();
        part_header.data_size = total_size.into();

        // fix tmd, see: https://github.com/AxioDL/nod/blob/b513a7f4e02d1b2a0c4563af73ba261d6760ab0e/lib/DiscWii.cpp#L885
        let mut hasher = Sha1::new();
        hasher.update(h3.as_ref());
        let digest = hasher.finalize_reset();
        // replace content hash
        tmd_buf[0x1F4..][..20].copy_from_slice(&digest);
        // replace content size
        tmd_buf[0x1EC..][..8].copy_from_slice(&total_size.to_be_bytes());
        // zero out TMD for simpler brute force
        for b in tmd_buf.iter_mut().skip(4).take(0x100) {
            *b = 0;
        }

        hasher.reset();
        // brute force 0 starting hash
        for i in 0..u64::MAX {
            tmd_buf[0x19A..][..8].copy_from_slice(&i.to_ne_bytes());
            hasher.update(&tmd_buf[0x140..]);
            let hash = hasher.finalize_reset();
            if hash[0] == 0 {
                break;
            }
        }

        partition_window.seek(SeekFrom::Start(*part_header.tmd_off))?;
        partition_window.write_all(&tmd_buf)?;

        // write partition header
        partition_window.seek(SeekFrom::Start(0))?;
        partition_window.write_be(&part_header)?;
        Ok(())
    }

    pub fn finish(&mut self) -> binrw::BinResult<()> {
        // disc header
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_be(&self.disc_header)?;
        // region info
        self.file.seek(SeekFrom::Start(0x4E000))?;
        self.file.write_all(&self.region)?;
        // partition info
        self.file.seek(SeekFrom::Start(0x40000))?;
        // we keep everything in one group, first write count then offset
        self.file.write_be(&(self.partitions.len() as u32))?;
        self.file.write_be(&(0x40020u32 >> 2))?;
        // write entries
        self.file.seek(SeekFrom::Start(0x40020))?;
        for partition in self.partitions.iter() {
            self.file.write_be(partition)?;
        }
        self.file.flush()?;
        Ok(())
    }
}

struct CopyBuilder<'a, RS: Read + Seek> {
    reader: &'a mut WiiIsoReader<RS>,
    part_read_info: WiiPartitionReadInfo,
    bi2: Vec<u8>,
    buffer: Vec<u8>,
    original_fst: Fst,
}

type CpBuildErr = PartitionAddError<std::convert::Infallible>;
impl<'b, RS: Read + Seek> WiiPartitionDefinition<std::convert::Infallible> for CopyBuilder<'b, RS> {
    fn get_disc_header(&mut self) -> Result<DiscHeader, CpBuildErr> {
        Ok(self.part_read_info.get_encrypted_header().clone())
    }

    fn get_bi2<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(Cow::Borrowed(&self.bi2))
    }

    fn get_apploader<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(self.part_read_info.read_apploader(self.reader)?.into())
    }

    fn get_fst(&mut self) -> Result<Fst, CpBuildErr> {
        Ok(self.original_fst.clone())
    }

    fn get_dol<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(self.part_read_info.read_dol(self.reader)?.into())
    }

    fn get_file_data<'a>(
        &'a mut self,
        path: &Vec<String>,
    ) -> Result<(Cow<'a, [u8]>, u32), CpBuildErr> {
        match self
            .original_fst
            .find_node_iter(path.iter().map(Borrow::borrow))
        {
            Some(FstNode::File { offset, length, .. }) => {
                println!("copying {:?}, {}", path, offset);
                self.part_read_info
                    .get_crypto_reader(self.reader)
                    .read_into_vec(*offset, *length as u64, &mut self.buffer)?;
                Ok((Cow::Borrowed(&self.buffer), 0))
            }
            _ => panic!("???"),
        }
    }
}

pub fn build_copy(src: &Path, dest: &Path) -> Result<(), CpBuildErr> {
    let f = File::open(src)?;
    let mut reader = WiiIsoReader::open(f)?;
    let mut builder = WiiDiscBuilder::create(
        OpenOptions::new()
            .truncate(true)
            .read(true)
            .write(true)
            .open(dest)?,
        reader.get_header().clone(),
        *reader.get_region(),
    );
    let data_part = reader
        .partitions()
        .iter()
        .find(|p| p.get_type() == WiiPartType::Data)
        .unwrap()
        .clone();
    let mut part_read_info = reader.open_partition(data_part)?;
    let ticket = part_read_info.get_partition_header().ticket.clone();
    let tmd = part_read_info.read_tmd(&mut reader)?;
    let cert_chain = part_read_info.read_certificates(&mut reader)?;
    let bi2 = part_read_info.read_bi2(&mut reader)?;
    let mut original_fst = part_read_info.get_fst().clone();
    let thp_dir = original_fst.find_node_path_mut("THP").unwrap();
    match thp_dir {
        FstNode::File { .. } => unreachable!(),
        FstNode::Directory { files, .. } => {
            files.retain(|f| f.get_name().starts_with("Demo"));
        }
    }
    let mut copy_builder = CopyBuilder {
        bi2,
        original_fst,
        buffer: Vec::new(),
        part_read_info,
        reader: &mut reader,
    };
    builder.add_partition(
        WiiPartType::Data,
        ticket,
        tmd,
        cert_chain,
        &mut copy_builder,
        &mut |_| -> () {},
    )?;
    builder.finish()?;
    Ok(())
}

pub struct DirPartitionBuilder {
    base_dir: PathBuf,
    fst: Fst,
    buf: Vec<u8>,
}

type DirPartAddErr = PartitionAddError<BuildDirError>;
impl WiiPartitionDefinition<BuildDirError> for DirPartitionBuilder {
    fn get_disc_header(&mut self) -> Result<DiscHeader, DirPartAddErr> {
        let path = self.base_dir.join("sys/boot.bin");
        let header = try_open(path)?.read_be::<DiscHeader>()?;
        Ok(header)
    }

    fn get_bi2<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        let path = self.base_dir.join("sys/bi2.bin");
        let mut f = try_open(path)?;
        self.buf.clear();
        f.read_to_end(&mut self.buf)?;
        Ok(Cow::Borrowed(&self.buf))
    }

    fn get_apploader<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        self.buf.clear();
        let path = self.base_dir.join("sys/apploader.img");
        let mut f = try_open(path)?;
        f.read_to_end(&mut self.buf)?;
        Ok(Cow::Borrowed(&self.buf))
    }

    fn get_fst(&mut self) -> Result<Fst, DirPartAddErr> {
        Ok(self.fst.clone())
    }

    fn get_dol<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        self.buf.clear();
        let path = self.base_dir.join("sys/main.dol");
        let mut f = try_open(path)?;
        f.read_to_end(&mut self.buf)?;
        Ok(Cow::Borrowed(&self.buf))
    }

    fn get_file_data<'a>(
        &'a mut self,
        path: &Vec<String>,
    ) -> Result<(Cow<'a, [u8]>, u32), DirPartAddErr> {
        let mut fs_path = self.base_dir.clone();
        fs_path.push("files");
        for part in path.iter() {
            fs_path.push(part);
        }
        self.buf.clear();
        let mut f = try_open(fs_path)?;
        f.read_to_end(&mut self.buf)?;
        Ok((Cow::Borrowed(&self.buf), 0))
    }
}

fn try_open(path: PathBuf) -> Result<File, DirPartAddErr> {
    if !path.is_file() {
        Err(PartitionAddError::Custom(BuildDirError::NotFound(path)))
    } else {
        File::open(path).map_err(Into::into)
    }
}

pub fn build_from_directory<WS: Write + Seek + Read, C: FnMut(u8)>(
    dir: &Path,
    dest: &mut WS,
    progress_cb: &mut C,
) -> Result<(), DirPartAddErr> {
    let mut disc_header = {
        let path = dir.join("DATA/sys/boot.bin");
        try_open(path)?.read_be::<DiscHeader>()?
    };
    disc_header.disable_disc_enc = 0;
    disc_header.disable_hash_verification = 0;
    let region = {
        let path = dir.join("DATA/disc/region.bin");
        let mut f = try_open(path)?;
        let mut region = [0; 32];
        f.read_exact(&mut region)?;
        region
    };
    let mut builder = WiiDiscBuilder::create(dest, disc_header, region);
    let partition_path = dir.join("DATA");
    let ticket = {
        let path = partition_path.join("ticket.bin");
        let mut f = try_open(path)?;
        f.read_be::<Ticket>()?
    };
    let tmd = {
        let path = partition_path.join("tmd.bin");
        let mut f = try_open(path)?;
        f.read_be::<TMD>()?
    };
    let cert_chain = {
        let path = partition_path.join("cert.bin");
        let mut f = try_open(path)?;
        f.read_be::<[Certificate; 3]>()?
    };
    let files_dir = partition_path.join("files");
    let fst =
        dir_reader::build_fst_from_directory_tree(&files_dir).map_err(PartitionAddError::Custom)?;
    let mut dir_builder = DirPartitionBuilder {
        base_dir: partition_path,
        buf: Vec::new(),
        fst,
    };
    builder.add_partition(
        WiiPartType::Data,
        ticket,
        tmd,
        cert_chain,
        &mut dir_builder,
        progress_cb,
    )?;
    builder.finish()?;
    Ok(())
}
