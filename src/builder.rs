use std::{
    borrow::{Borrow, Cow},
    convert::Infallible,
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use aes::{cipher::KeyIvInit, Aes128};
use binrw::{BinReaderExt, BinWriterExt};
use sha1::{Digest, Sha1};

use crate::{
    dir_reader::{self, BuildDirError},
    fst::FstToBytesError,
    reader_writer::WiiEncryptedReadWriteStream,
    structs::{
        Certificate, DiscHeader, Ticket, WiiPartTableEntry, WiiPartType, WiiPartitionHeader, TMD,
    },
    Fst, FstNode, FstToBytes, IOWindow, WiiIsoReader, GROUP_DATA_SIZE, GROUP_SIZE,
};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

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

    fn progress_callback(&mut self, processed_files: usize, total_files: usize) {}
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

    pub fn add_partition<P, E>(
        &mut self,
        part_type: WiiPartType,
        ticket: Ticket,
        tmd: TMD,
        cert_chain: [Certificate; 3],
        partition_def: &mut P,
    ) -> Result<(), PartitionAddError<E>>
    where
        P: WiiPartitionDefinition<E>,
        E: Error,
    {
        let part_data_off = self.current_data_offset;
        let mut partition_window = IOWindow::new(&mut self.file, part_data_off)?;
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
        println!("{}", part_header.tmd_size);
        part_header.cert_chain_off =
            align_next(*part_header.tmd_off + part_header.tmd_size as u64, 0x20).into();
        partition_window.seek(SeekFrom::Start(*part_header.cert_chain_off))?;
        partition_window.write_be(&cert_chain)?;
        part_header.cert_chain_size =
            (partition_window.stream_position()? - *part_header.cert_chain_off) as u32;
        // global hash table at 0x8000, encrypted data starts at 0x20000
        let mut h3: Box<[u8; 0x18000]> = vec![0u8; 0x18000].into_boxed_slice().try_into().unwrap();
        // now we write encrypted data
        let mut crypto_writer = WiiEncryptedReadWriteStream::create_write(
            &mut partition_window,
            &mut h3,
            0x20000,
            part_header.ticket.title_key,
            None,
            0,
        );
        let source_fst = partition_def.get_fst()?;
        let mut total_files = 0;
        source_fst
            .callback_all_files::<Infallible, _>(&mut |_, node| {
                if matches!(node, FstNode::File { .. }) {
                    total_files += 1;
                }
                Ok(())
            })
            .unwrap();
        let mut fst = FstToBytes::try_from(source_fst)?;
        let mut part_disc_header = partition_def.get_disc_header()?;
        println!("{:?}", crypto_writer.stream_position());
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
        fst.callback_all_files_mut::<PartitionAddError<E>, _>(&mut |path, offset, size| {
            partition_def.progress_callback(processed_files, total_files);
            processed_files += 1;
            *offset = crypto_writer.stream_position()?;
            let (data, padding) = partition_def.get_file_data(path)?;
            *size = data.as_ref().len() as u32;
            crypto_writer.write_all(data.as_ref())?;
            let next_start = align_next(crypto_writer.stream_position()? + padding as u64, 0x40);
            crypto_writer.seek(SeekFrom::Start(next_start))?;
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
                println!("found after {} attempts: {:?}", i, hash);
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
    disc_header: DiscHeader,
    bi2: Vec<u8>,
    buffer: Vec<u8>,
    original_fst: Fst,
    crypto_stream: WiiEncryptedReadWriteStream<'a, RS>,
}

type CpBuildErr = PartitionAddError<std::convert::Infallible>;
impl<'b, RS: Read + Seek> WiiPartitionDefinition<std::convert::Infallible> for CopyBuilder<'b, RS> {
    fn get_disc_header(&mut self) -> Result<DiscHeader, CpBuildErr> {
        Ok(self.disc_header.clone())
    }

    fn get_bi2<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(Cow::Borrowed(&self.bi2))
    }

    fn get_apploader<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(self.crypto_stream.read_apploader()?.into())
    }

    fn get_fst(&mut self) -> Result<Fst, CpBuildErr> {
        Ok(self.original_fst.clone())
    }

    fn get_dol<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CpBuildErr> {
        Ok(self
            .crypto_stream
            .read_dol(*self.disc_header.dol_off)?
            .into())
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
                self.crypto_stream
                    .read_into_vec(*offset, *length as u64, &mut self.buffer)?;
                Ok((Cow::Borrowed(&self.buffer), 0))
            }
            _ => panic!("???"),
        }
    }
}

fn build_copy(src: &Path, dest: &Path) -> Result<(), CpBuildErr> {
    let f = File::open(src)?;
    let mut reader = WiiIsoReader::create(f)?;
    let mut builder = WiiDiscBuilder::create(
        OpenOptions::new()
            .truncate(true)
            .read(true)
            .write(true)
            .open(dest)?,
        reader.get_header().clone(),
        *reader.get_region(),
    );
    let mut part_reader = reader.open_partition_stream(&WiiPartType::Data)?;
    let ticket = part_reader.get_partition_header().ticket.clone();
    let tmd = part_reader.read_tmd()?;
    let cert_chain = part_reader.read_certificates()?;
    let mut crypto_reader = part_reader.open_encryption_reader();
    crypto_reader.seek(SeekFrom::Start(0))?;
    let disc_header: DiscHeader = crypto_reader.read_be()?;
    let mut bi2 = vec![0; 0x2000];
    crypto_reader.read_exact(&mut bi2)?;
    let mut original_fst = Fst::read(&mut crypto_reader, *disc_header.fst_off)?;
    let thp_dir = original_fst.find_node_path_mut("THP").unwrap();
    match thp_dir {
        FstNode::File { .. } => unreachable!(),
        FstNode::Directory { files, .. } => {
            files.retain(|f| f.get_name().starts_with("Demo"));
        }
    }
    let mut copy_builder = CopyBuilder {
        disc_header,
        bi2,
        original_fst,
        buffer: Vec::new(),
        crypto_stream: part_reader.open_encryption_reader(),
    };
    builder.add_partition(
        WiiPartType::Data,
        ticket,
        tmd,
        cert_chain,
        &mut copy_builder,
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
        let mut path = self.base_dir.clone();
        path.push("sys");
        path.push("boot.bin");
        let header = try_open(path)?.read_be::<DiscHeader>()?;
        Ok(header)
    }

    fn get_bi2<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        let mut path = self.base_dir.clone();
        path.push("sys");
        path.push("bi2.bin");
        let mut f = try_open(path)?;
        self.buf.clear();
        f.read_to_end(&mut self.buf)?;
        Ok(Cow::Borrowed(&self.buf))
    }

    fn get_apploader<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        self.buf.clear();
        let mut path = self.base_dir.clone();
        path.push("sys");
        path.push("apploader.img");
        let mut f = try_open(path)?;
        f.read_to_end(&mut self.buf)?;
        Ok(Cow::Borrowed(&self.buf))
    }

    fn get_fst(&mut self) -> Result<Fst, DirPartAddErr> {
        Ok(self.fst.clone())
    }

    fn get_dol<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, DirPartAddErr> {
        self.buf.clear();
        let mut path = self.base_dir.clone();
        path.push("sys");
        path.push("main.dol");
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

pub fn build_from_directory<WS: Write + Seek + Read>(
    dir: &Path,
    dest: &mut WS,
) -> Result<(), DirPartAddErr> {
    let mut disc_header = {
        let mut path = dir.to_owned();
        path.push("DATA");
        path.push("sys");
        path.push("boot.bin");
        try_open(path)?.read_be::<DiscHeader>()?
    };
    disc_header.disable_disc_enc = 0;
    disc_header.disable_hash_verification = 0;
    let region = {
        let mut path = dir.to_owned();
        path.push("DATA");
        path.push("disc");
        path.push("region.bin");
        let mut f = try_open(path)?;
        let mut region = [0; 32];
        f.read_exact(&mut region)?;
        region
    };
    let mut builder = WiiDiscBuilder::create(dest, disc_header, region);
    let mut partition_path = dir.to_owned();
    partition_path.push("DATA");
    let ticket = {
        let mut path = partition_path.clone();
        path.push("ticket.bin");
        let mut f = try_open(path)?;
        f.read_be::<Ticket>()?
    };
    let tmd = {
        let mut path = partition_path.clone();
        path.push("tmd.bin");
        let mut f = try_open(path)?;
        f.read_be::<TMD>()?
    };
    let cert_chain = {
        let mut path = partition_path.clone();
        path.push("cert.bin");
        let mut f = try_open(path)?;
        f.read_be::<[Certificate; 3]>()?
    };
    let mut files_dir = partition_path.clone();
    files_dir.push("files");
    let fst =
        dir_reader::build_fst_from_directory_tree(&files_dir).map_err(PartitionAddError::Custom)?;
    let mut dir_builder = DirPartitionBuilder {
        base_dir: partition_path,
        buf: Vec::new(),
        fst,
    };
    builder.add_partition(WiiPartType::Data, ticket, tmd, cert_chain, &mut dir_builder)?;
    builder.finish()?;
    Ok(())
}
