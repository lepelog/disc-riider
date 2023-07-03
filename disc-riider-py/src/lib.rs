use std::{path::{PathBuf, Path}, fs::{self, create_dir_all, OpenOptions}, convert::Infallible, io::{Read, Write, Seek, SeekFrom}};

use binrw::{BinWrite, BinWriterExt};
use disc_riider::{structs::WiiPartType, reader_writer::WiiEncryptedReadWriteStreamInner, Fst, WiiIsoReader, FstNode, builder::build_from_directory};
use pyo3::{prelude::*, exceptions};
use sha1::{Sha1, Digest};

trait PyErrIoExt<T> {
    fn into_pyerr(self) -> PyResult<T>;
    fn into_pyerr_with_path(self, path: &Path) -> PyResult<T>;
}

impl <T> PyErrIoExt<T> for binrw::BinResult<T> {
    fn into_pyerr(self) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("{e}")))
    }

    fn into_pyerr_with_path(self, path: &Path) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("binrw error at {path:?}: {e}")))
    }
}

impl <T> PyErrIoExt<T> for std::io::Result<T> {
    fn into_pyerr(self) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("{e}")))
    }

    fn into_pyerr_with_path(self, path: &Path) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("io error at {path:?}: {e}")))
    }
}

struct Section {
    part: String,
    fst: Fst,
    read_stream: WiiEncryptedReadWriteStreamInner,
    dol_check: Option<[u8; 20]>,
}

#[pyclass]
struct WiiIsoExtractor {
    iso: WiiIsoReader<fs::File>,
    sections_to_extract: Vec<Section>,
}

pub fn parse_section(section: &str) -> PyResult<WiiPartType> {
    if section.eq_ignore_ascii_case("data") {
        Ok(WiiPartType::Data)
    } else if section.eq_ignore_ascii_case("update") {
        Ok(WiiPartType::Update)
    } else if section.eq_ignore_ascii_case("channel") {
        Ok(WiiPartType::Channel)
    } else {
        Err(exceptions::PyException::new_err(format!("'{section}' isn't a valid section name!")))
    }
}

impl WiiIsoExtractor {
    pub fn get_partition<'a>(&'a mut self, mut section: String) -> PyResult<&'a mut Section> {
        section.make_ascii_uppercase();
        self.sections_to_extract.iter_mut().find(|part| part.part == section).ok_or_else(|| {
            exceptions::PyException::new_err(format!("section {section} doesn't exist!"))
        })
    }
}

pub fn binrw_write_file(p: &Path, value: &impl BinWrite<Args = ()>) -> PyResult<()> {
    let mut f = fs::File::create(p).into_pyerr_with_path(p)?;
    f.write_be(value).into_pyerr_with_path(p)?;
    Ok(())
}

#[pymethods]
impl WiiIsoExtractor {
    #[new]
    pub fn new(path: PathBuf) -> PyResult<Self> {
        let iso_file = fs::File::open(&path).map_err(|e| {
            exceptions::PyException::new_err(format!("{e:?}, file: {path:?}"))
        })?;
        let iso = WiiIsoReader::create(iso_file).map_err(|e| {
            exceptions::PyException::new_err(format!("{e:?}, file: {path:?}"))
        })?;
        Ok(WiiIsoExtractor {
            iso,
            sections_to_extract: vec![]
        })
    }

    pub fn prepare_extract_section(&mut self, mut section: String) -> PyResult<()> {
        section.make_ascii_uppercase();
        if self.sections_to_extract.iter().any(|s| s.part == section) {
            return Err(exceptions::PyValueError::new_err(format!("section {section} already added")));
        }
        let part_type = match section.as_str() {
            "DATA" => WiiPartType::Data,
            "CHANNEL" => WiiPartType::Channel,
            "UPDATE" => WiiPartType::Update,
            _ => return Err(exceptions::PyValueError::new_err(format!("unknown section {section}"))),
        };
        let partition_idx = self.iso.partitions().iter().position(|p| p.part_type == part_type).ok_or_else(|| {
            exceptions::PyException::new_err(format!("section {section} doesn't exist!"))
        })?;
        let mut partition_reader = self.iso.open_partition_stream_by_index(partition_idx).map_err(|e| {
            exceptions::PyException::new_err(format!("cannot open partition: {e:?}"))
        })?;
        let mut crypt_reader = partition_reader.open_encryption_reader();
        let header = crypt_reader.read_disc_header().map_err(|e| {
            exceptions::PyException::new_err(format!("can't read partition header: {e:?}"))
        })?;
        let fst = Fst::read(&mut crypt_reader, *header.fst_off).map_err(|e| {
            exceptions::PyException::new_err(format!("can't read fst: {e:?}"))
        })?;
        self.sections_to_extract.push(Section { part: section, fst, read_stream: crypt_reader.into_inner(), dol_check: Default::default() });
        Ok(())
    }

    pub fn remove_ss_hint_movies(&mut self) -> PyResult<()> {
        let partition = self.get_partition("DATA".into())?;
        if let Some(FstNode::Directory { files, .. }) = partition.fst.find_node_path_mut("THP") {
            files.retain(|f| f.get_name().starts_with("Demo"));
        }
        Ok(())
    }

    // TODO: implement dol check

    pub fn add_hash_check(&mut self, section: String, path: String, hash: [u8; 20]) -> PyResult<()> {
        let partition = self.get_partition(section)?;
        if path != "/sys/main.dol" {
            return Err(exceptions::PyException::new_err("The hash check only supports main.dol for now!"));
        }
        partition.dol_check = Some(hash);
        Ok(())
    }

    pub fn test_print(&self) -> PyResult<()> {
        for partition in self.sections_to_extract.iter() {
            println!("section:");
            partition.fst.callback_all_files::<Infallible, _>(&mut |names, _| {
                println!("{names:?}");
                Ok(())
            })?;
        }
        Ok(())
    }

    pub fn extract_to(&mut self, path: PathBuf, callback: PyObject) -> PyResult<()> {
        Python::with_gil(|py| {
            let _ = callback.call1(py, (0,));
        });
        let disc_header = self.iso.get_header().clone();
        let region = self.iso.get_region().clone();
        for partition in self.sections_to_extract.drain(..) {
            let part_type = parse_section(&partition.part)?;

            let section_path = path.join(format!("{}", partition.part));

            let section_path_disk = section_path.join("disc");
            create_dir_all(&section_path_disk)?;

            binrw_write_file(&section_path_disk.join("header.bin"), &disc_header)?;
            fs::write(section_path_disk.join("region.bin"), region)?;

            let mut wii_encrypt_reader = partition.read_stream.with_file(&mut self.iso.file);
            if let Some(dol_hash) = partition.dol_check.as_ref() {
                let disc_header = wii_encrypt_reader.read_disc_header().into_pyerr()?;
                let dol = wii_encrypt_reader.read_dol(*disc_header.dol_off).into_pyerr()?;
                let mut hasher = Sha1::new();
                hasher.update(&dol);
                let hash = hasher.finalize();
                if hash.as_slice() != dol_hash {
                    let hash_hex = hex::encode(hash.as_slice());
                    return Err(exceptions::PyException::new_err(format!("wrong hash for main.dol: {hash_hex}!")));
                }
            }

            wii_encrypt_reader.extract_system_files(&section_path).into_pyerr()?;
            let mut buffer = [0; 0x10000];
            // count files
            let mut total_bytes = 0usize;
            partition.fst.callback_all_files::<std::io::Error, _>(&mut |_, node| {
                if let FstNode::File { length, .. } = node {
                    total_bytes += *length as usize;
                }

                Ok(())
            })?;

            let mut done_bytes = 0usize;
            partition.fst.callback_all_files::<std::io::Error, _>(&mut |names, node| {
                if let FstNode::File { offset, length, .. } = node {
                    let mut filepath = section_path.join("files");
                    for name in names {
                        filepath.push(name);
                    }
                    // println!("{filepath:?}");
                    // TODO: reduce create dir calls?
                    create_dir_all(filepath.parent().unwrap())?;
                    
                    let mut outfile = fs::File::create(&filepath)?;
                    wii_encrypt_reader.seek(SeekFrom::Start(*offset))?;
                    let mut bytes_left = *length as usize;
                    loop {
                        let bytes_to_read = bytes_left.min(buffer.len());
                        let bytes_read = wii_encrypt_reader.read(&mut buffer[..bytes_to_read])?;
                        if bytes_read == 0 {
                            break;
                        }

                        outfile.write_all(&buffer[..bytes_read])?;
                        done_bytes += bytes_read;
                        bytes_left -= bytes_read;

                        let done_percent = ((done_bytes as f64) / (total_bytes as f64) * 100f64) as u32;
                        Python::with_gil(|py| {
                            let _ = callback.call1(py, (done_percent,));
                        });
                    }
                }

                Ok(())
            })?;

            drop(wii_encrypt_reader);

            let mut reader = self.iso.open_partition_stream(&part_type).into_pyerr()?;
            let certs = reader.read_certificates().into_pyerr()?;
            binrw_write_file(&section_path.join("cert.bin"), &certs)?;
            let tmd = reader.read_tmd().into_pyerr()?;
            binrw_write_file(&section_path.join("tmd.bin"), &tmd)?;
            let ticket = &reader.get_partition_header().ticket;
            binrw_write_file(&section_path.join("ticket.bin"), ticket)?;

        }
        Ok(())
    }
}

#[pyfunction]
pub fn rebuild_from_directory(src_dir: PathBuf, dest_path: PathBuf, callback: PyObject) -> PyResult<()> {
    let mut dest_file = OpenOptions::new()
        .truncate(true)
        .read(true)
        .write(true)
        .create(true)
        .open(&dest_path)?;
    build_from_directory(&src_dir, &mut dest_file, &mut |done_percent| {
        Python::with_gil(|py| {
            let _ = callback.call1(py, (done_percent,));
        });
    }).map_err(|err| {
        exceptions::PyException::new_err(format!("{err:?}"))
    })?;
    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn disc_riider_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<WiiIsoExtractor>()?;
    m.add_function(wrap_pyfunction!(rebuild_from_directory, m)?)?;
    Ok(())
}