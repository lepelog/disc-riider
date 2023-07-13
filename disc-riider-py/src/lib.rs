use std::{
    convert::Infallible,
    fs::{self, create_dir_all, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use binrw::{BinWrite, BinWriterExt};
use disc_riider::{
    builder::build_from_directory, structs::WiiPartType, Fst, FstNode, WiiIsoReader,
    WiiPartitionReadInfo,
};
use pyo3::{exceptions, prelude::*};
use sha1::{Digest, Sha1};

trait PyErrIoExt<T> {
    fn into_pyerr(self) -> PyResult<T>;
    fn into_pyerr_with_path(self, path: &Path) -> PyResult<T>;
}

impl<T> PyErrIoExt<T> for binrw::BinResult<T> {
    fn into_pyerr(self) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("{e}")))
    }

    fn into_pyerr_with_path(self, path: &Path) -> PyResult<T> {
        self.map_err(|e| exceptions::PyException::new_err(format!("binrw error at {path:?}: {e}")))
    }
}

impl<T> PyErrIoExt<T> for std::io::Result<T> {
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
    partition_reader: WiiPartitionReadInfo,
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
        Err(exceptions::PyException::new_err(format!(
            "'{section}' isn't a valid section name!"
        )))
    }
}

impl WiiIsoExtractor {
    pub fn get_partition<'a>(&'a mut self, mut section: String) -> PyResult<&'a mut Section> {
        section.make_ascii_uppercase();
        self.sections_to_extract
            .iter_mut()
            .find(|part| part.part == section)
            .ok_or_else(|| {
                exceptions::PyException::new_err(format!("section {section} doesn't exist!"))
            })
    }
}

pub fn binrw_write_file(p: &Path, value: &impl for<'a> BinWrite<Args<'a> = ()>) -> PyResult<()> {
    let mut f = fs::File::create(p).into_pyerr_with_path(p)?;
    f.write_be(value).into_pyerr_with_path(p)?;
    Ok(())
}

#[pymethods]
impl WiiIsoExtractor {
    #[new]
    pub fn new(path: PathBuf) -> PyResult<Self> {
        let iso_file = fs::File::open(&path)
            .map_err(|e| exceptions::PyException::new_err(format!("{e:?}, file: {path:?}")))?;
        let iso = WiiIsoReader::open(iso_file)
            .map_err(|e| exceptions::PyException::new_err(format!("{e:?}, file: {path:?}")))?;
        Ok(WiiIsoExtractor {
            iso,
            sections_to_extract: vec![],
        })
    }

    pub fn prepare_extract_section(&mut self, mut section: String) -> PyResult<()> {
        section.make_ascii_uppercase();
        if self.sections_to_extract.iter().any(|s| s.part == section) {
            return Err(exceptions::PyValueError::new_err(format!(
                "section {section} already added"
            )));
        }
        let part_type = match section.as_str() {
            "DATA" => WiiPartType::Data,
            "CHANNEL" => WiiPartType::Channel,
            "UPDATE" => WiiPartType::Update,
            _ => {
                return Err(exceptions::PyValueError::new_err(format!(
                    "unknown section {section}"
                )))
            }
        };
        let partition = self
            .iso
            .partitions()
            .iter()
            .find(|p| p.get_type() == part_type)
            .cloned()
            .ok_or_else(|| {
                exceptions::PyException::new_err(format!("section {section} doesn't exist!"))
            })?;
        let partition_reader = self.iso.open_partition(partition).map_err(|e| {
            exceptions::PyException::new_err(format!("cannot open partition: {e:?}"))
        })?;
        self.sections_to_extract.push(Section {
            part: section,
            fst: partition_reader.get_fst().clone(),
            partition_reader,
        });
        Ok(())
    }

    pub fn get_dol_hash(&mut self, mut section: String) -> PyResult<[u8; 20]> {
        section.make_ascii_uppercase();
        let partition = self
            .sections_to_extract
            .iter_mut()
            .find(|part| part.part == section)
            .ok_or_else(|| {
                exceptions::PyException::new_err(format!("section {section} doesn't exist!"))
            })?;
        let dol = partition
            .partition_reader
            .read_dol(&mut self.iso)
            .into_pyerr()?;
        let mut hasher = Sha1::new();
        hasher.update(&dol);
        Ok(hasher.finalize().try_into().unwrap())
    }

    pub fn test_print(&self) -> PyResult<()> {
        for partition in self.sections_to_extract.iter() {
            println!("section:");
            partition
                .fst
                .callback_all_files::<Infallible, _>(&mut |names, _| {
                    println!("{names:?}");
                    Ok(())
                })?;
        }
        Ok(())
    }

    pub fn remove_files_by_callback(&mut self, section: String, callback: PyObject) -> PyResult<()> {
        fn should_remove_file(nodes: &mut Vec<FstNode>, dirstack: &mut Vec<String>, callback: &PyObject) {
            nodes.retain_mut(|node| {
                match node {
                    FstNode::Directory { name, files } => {
                        dirstack.push(name.clone());
                        should_remove_file(files, dirstack, callback);
                        dirstack.pop();
                        true
                    },
                    FstNode::File { name, .. } => {
                        dirstack.push(name.clone());
                        let path = dirstack.join("/");
                        dirstack.pop();
                        let should_remove = Python::with_gil(|py| {
                            callback.call1(py, (path,)).and_then(|obj| obj.is_true(py))
                        }).unwrap_or(false);
                        !should_remove
                    }
                }
            });
        }

        let partition = self.get_partition(section)?;
        should_remove_file(partition.fst.get_entries_mut(), &mut Vec::new(), &callback);
        
        Ok(())
    }

    pub fn extract_to(&mut self, path: PathBuf, callback: PyObject) -> PyResult<()> {
        Python::with_gil(|py| {
            let _ = callback.call1(py, (0,));
        });
        let disc_header = self.iso.get_header().clone();
        let region = self.iso.get_region().clone();
        for mut partition in self.sections_to_extract.drain(..) {
            let section_path = path.join(format!("{}", partition.part));

            let section_path_disk = section_path.join("disc");
            create_dir_all(&section_path_disk)?;

            binrw_write_file(&section_path_disk.join("header.bin"), &disc_header)?;
            fs::write(section_path_disk.join("region.bin"), region)?;

            partition
                .partition_reader
                .extract_system_files(&section_path, &mut self.iso)
                .into_pyerr()?;
            let mut buffer = [0; 0x10_000];
            // count files
            let mut total_bytes = 0usize;
            partition
                .fst
                .callback_all_files::<std::io::Error, _>(&mut |_, node| {
                    if let FstNode::File { length, .. } = node {
                        total_bytes += *length as usize;
                    }

                    Ok(())
                })?;

            let mut done_bytes = 0usize;
            let mut wii_encrypt_reader =
                partition.partition_reader.get_crypto_reader(&mut self.iso);
            partition
                .fst
                .callback_all_files::<std::io::Error, _>(&mut |names, node| {
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
                            let bytes_read =
                                wii_encrypt_reader.read(&mut buffer[..bytes_to_read])?;
                            if bytes_read == 0 {
                                break;
                            }

                            outfile.write_all(&buffer[..bytes_read])?;
                            done_bytes += bytes_read;
                            bytes_left -= bytes_read;

                            let done_percent =
                                ((done_bytes as f64) / (total_bytes as f64) * 100f64) as u32;
                            Python::with_gil(|py| {
                                let _ = callback.call1(py, (done_percent,));
                            });
                        }
                    }

                    Ok(())
                })?;

            drop(wii_encrypt_reader);

            let certs = partition
                .partition_reader
                .read_certificates(&mut self.iso)
                .into_pyerr()?;
            binrw_write_file(&section_path.join("cert.bin"), &certs)?;
            let tmd = partition
                .partition_reader
                .read_tmd(&mut self.iso)
                .into_pyerr()?;
            binrw_write_file(&section_path.join("tmd.bin"), &tmd)?;
            binrw_write_file(
                &section_path.join("ticket.bin"),
                &partition.partition_reader.get_partition_header().ticket,
            )?;
        }
        Ok(())
    }
}

#[pyfunction]
pub fn rebuild_from_directory(
    src_dir: PathBuf,
    dest_path: PathBuf,
    callback: PyObject,
) -> PyResult<()> {
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
    })
    .map_err(|err| exceptions::PyException::new_err(format!("{err:?}")))?;
    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn disc_riider_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<WiiIsoExtractor>()?;
    m.add_function(wrap_pyfunction!(rebuild_from_directory, m)?)?;
    Ok(())
}
