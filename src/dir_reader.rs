use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use crate::{Fst, FstNode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BuildDirError {
    #[error("io error: {0}")]
    IO(#[from] io::Error),
    #[error("invalid filename: {0:?}")]
    InvalidFilename(OsString),
    #[error("duplicate filename: {0}")]
    DuplicateFilename(String),
    #[error("required file not found: {0}")]
    NotFound(PathBuf),
    #[error("File {0} is too large, has {1} bytes")]
    FileTooLarge(PathBuf, u64),
}

pub fn build_fst_from_directory_tree<P: AsRef<Path> + ?Sized>(
    path: &P,
) -> Result<Fst, BuildDirError> {
    let mut fst = Fst::default();
    let mut dirs = Vec::new();
    build_fst_from_directory_tree_rec(path, &mut dirs, &mut fst)?;
    Ok(fst)
}

fn build_fst_from_directory_tree_rec<P: AsRef<Path> + ?Sized>(
    path: &P,
    dirs: &mut Vec<String>,
    fst: &mut Fst,
) -> Result<(), BuildDirError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let os_filename = entry.file_name();
        let Some(filename) = os_filename.to_str().map(String::from) else {
            return Err(BuildDirError::InvalidFilename(os_filename));
        };
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            // directories, push them to the dir stack
            dirs.push(filename);
            build_fst_from_directory_tree_rec(&path, dirs, fst)?;
            let _ = dirs.pop();
        } else {
            // files, add them to the fst
            if !matches!(
                fst.add_node_iter(
                    dirs.iter().map(|s| s.as_str()),
                    FstNode::File {
                        name: filename,
                        offset: 0,
                        length: metadata
                            .len()
                            .try_into()
                            .map_err(|_| BuildDirError::FileTooLarge(path, metadata.len()))?
                    }
                ),
                Ok(None)
            ) {
                return Err(BuildDirError::DuplicateFilename(
                    os_filename.to_str().unwrap_or_default().to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::build_fst_from_directory_tree;

    #[test]
    pub fn test_dir_read() {
        let fst = build_fst_from_directory_tree("src").unwrap();
        fst.print_tree();
        assert!(fst.get_entries().len() > 4);
    }
}
