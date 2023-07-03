use clap::Parser;
use disc_riider::{builder, structs::WiiPartType, Fst, WiiIsoReader};
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Parser)]
#[clap(about = "Utility to extract wii isos")]
enum Commands {
    #[clap(about = "show sections of the iso")]
    Sections { filename: PathBuf },
    #[clap(about = "extract the system files of an iso partition to a destination folder")]
    ExtractSys {
        filename: PathBuf,
        destination: PathBuf,
        #[clap(long, default_value = "DATA")]
        section: String,
    },
    #[clap(about = "print all file names present in the given section")]
    PrintFiles {
        filename: PathBuf,
        #[clap(long, default_value = "DATA")]
        section: String,
    },
    #[clap(about = "repack an ISO")]
    Rebuild {
        src_dir: PathBuf,
        dest_file: PathBuf,
    },
}

impl Commands {
    fn get_filename(&self) -> &PathBuf {
        match self {
            Self::Sections { filename } => filename,
            Self::ExtractSys { filename, .. } => filename,
            Self::PrintFiles { filename, .. } => filename,
            Self::Rebuild { dest_file, .. } => dest_file,
        }
    }
}

#[derive(Error, Debug)]
enum MyError {
    #[error("IO Error: {io_error}")]
    IOError {
        #[from]
        io_error: std::io::Error,
    },
    #[error("Read error: {error}")]
    BinrwError {
        #[from]
        error: binrw::error::Error,
    },
    #[error("{0} is not a valid section, options are: DATA, CHANNEL, UPDATE")]
    InvalidSection(String),
    #[error("section {0:?} not present!")]
    SectionNotFound(WiiPartType),
    #[error("{0}")]
    StringError(String),
}

impl From<String> for MyError {
    fn from(s: String) -> Self {
        MyError::StringError(s)
    }
}

fn main() -> Result<(), MyError> {
    let args = Commands::parse();
    match args {
        Commands::Sections { filename } => {
            let f = File::open(filename)?;
            let reader = WiiIsoReader::create(f)?;
            for partition in reader.partitions() {
                println!("{:?}: {:X}", partition.part_type, *partition.part_data_off);
            }
        }
        Commands::PrintFiles { section, filename } => {
            let f = File::open(filename)?;
            let mut reader = WiiIsoReader::create(f)?;
            let part_type = match section.to_ascii_uppercase().as_str() {
                "DATA" => WiiPartType::Data,
                "CHANNEL" => WiiPartType::Channel,
                "UPDATE" => WiiPartType::Update,
                _ => {
                    return Err(MyError::InvalidSection(section));
                }
            };
            let partition = reader
                .partitions()
                .iter()
                .find(|p| p.part_type == part_type)
                .cloned()
                .ok_or_else(|| MyError::SectionNotFound(part_type))?;
            let mut part_reader = reader.open_partition_stream(&part_type)?;
            let mut encr_reader = part_reader.open_encryption_reader();
            let disc_header = encr_reader.read_disc_header()?;
            let fst = Fst::read(&mut encr_reader, *disc_header.fst_off)?;
            fst.print_tree();
        }
        Commands::ExtractSys {
            section,
            destination,
            filename,
        } => {
            let f = File::open(filename)?;
            let mut reader = WiiIsoReader::create(f)?;
            let part_type = match section.to_ascii_uppercase().as_str() {
                "DATA" => WiiPartType::Data,
                "CHANNEL" => WiiPartType::Channel,
                "UPDATE" => WiiPartType::Update,
                _ => return Err(MyError::InvalidSection(section)),
            };
            let partition = reader
                .partitions()
                .iter()
                .find(|p| p.part_type == part_type)
                .cloned()
                .ok_or_else(|| MyError::SectionNotFound(part_type))?;

            let mut part_reader = reader.open_partition_stream(&WiiPartType::Data)?;
            let mut encrytion_reader = part_reader.open_encryption_reader();
            encrytion_reader.extract_system_files(&destination)?;
        }
        Commands::Rebuild { src_dir, dest_file } => {
            let mut f = OpenOptions::new()
                .truncate(true)
                .read(true)
                .write(true)
                .create(true)
                .open(&dest_file)?;
            builder::build_from_directory(&src_dir, &mut f, &mut |_| -> () {}).map_err(|e| format!("{e:?}"))?;
        }
    }
    Ok(())
}
