use std::{
    cmp::Ordering,
    io::{Read, Seek, SeekFrom, Write},
    iter::once,
};

use binrw::{binrw, BinReaderExt, BinWriterExt, NullString};
use encoding_rs::SHIFT_JIS;
use thiserror::Error;

#[binrw]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFstNode {
    #[br(temp)]
    #[bw(calc = (if *is_directory { 1 } else { 0 }) << 24 | name_offset)]
    type_and_name_offset: u32,

    #[br(calc = (type_and_name_offset >> 24) != 0)]
    #[bw(ignore)]
    is_directory: bool,

    #[br(calc = type_and_name_offset & 0xffffff)]
    #[bw(ignore)]
    name_offset: u32,

    /// For files, this is the partition offset of the file data. (Wii: >> 2)
    ///
    /// For directories, this is the offset of the parent directory in the FST
    offset: u32,

    /// For files, this is the byte size of the file.
    ///
    /// For directories, this is the children end offset in the FST.
    length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents a node in the file system table,
/// either a directory with subnodes or a file
/// with offset into the partition and length
pub enum FstNode {
    File {
        name: String,
        offset: u64,
        length: u32,
    },
    Directory {
        name: String,
        files: Vec<FstNode>,
    },
}

impl FstNode {
    pub fn create_file(name: String) -> Self {
        FstNode::File {
            name,
            length: 0,
            offset: 0,
        }
    }
    pub fn create_dir(name: String) -> Self {
        FstNode::Directory {
            name,
            files: Vec::new(),
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }

    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    pub fn print_tree(&self, ident: usize) {
        for _ in 0..ident {
            print!("  ");
        }
        println!("{}", self.get_name());
        match self {
            Self::Directory { files, .. } => {
                for file in files {
                    file.print_tree(ident + 1);
                }
            }
            _ => (),
        }
    }

    pub fn get_name(&self) -> &String {
        match self {
            FstNode::Directory { name, .. } => name,
            FstNode::File { name, .. } => name,
        }
    }
}

fn ordering_ignore_case(s1: &str, s2: &str) -> Ordering {
    for (chr1, chr2) in s1
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .chain(once(0))
        .zip(s2.bytes().map(|b| b.to_ascii_lowercase()).chain(once(0)))
    {
        match chr1.cmp(&chr2) {
            Ordering::Equal => continue,
            o => return o,
        };
    }
    Ordering::Equal
}

impl FstNode {
    pub fn node_compare(&self, other: &Self) -> Ordering {
        return ordering_ignore_case(self.get_name(), other.get_name());
    }
}

impl AsRef<FstNode> for FstNode {
    fn as_ref(&self) -> &FstNode {
        self
    }
}

impl AsMut<FstNode> for FstNode {
    fn as_mut(&mut self) -> &mut FstNode {
        self
    }
}

fn read_shiftjs<RS: Read + Seek>(rs: &mut RS, offset: u64) -> binrw::BinResult<String> {
    rs.seek(SeekFrom::Start(offset))?;
    let null_str = rs.read_be::<NullString>()?;
    let (res, _, err) = SHIFT_JIS.decode(&null_str);
    if err {
        return Err(binrw::Error::Custom {
            pos: offset,
            err: Box::new(format!("invalid shiftjis: {}", res)),
        });
    }
    Ok(res.into())
}

/// Implements the file system table
#[derive(Default, Clone)]
pub struct Fst {
    entries: Vec<FstNode>,
}

pub fn find_node_iter<'a, 'b, I>(nodes: &'a Vec<FstNode>, mut iter: I) -> Option<&'a FstNode>
where
    I: Iterator<Item = &'b str>,
{
    let cur_part = iter.next()?;
    let mut cur_node = nodes.iter().find(|n| n.get_name() == cur_part)?;
    for cur_part in iter {
        match cur_node {
            FstNode::Directory { files, .. } => {
                cur_node = files.iter().find(|n| n.get_name() == cur_part)?;
            }
            // we can't descend into files
            FstNode::File { .. } => return None,
        }
    }
    Some(cur_node)
}

pub fn find_node_iter_mut<'a, 'b, I>(
    nodes: &'a mut Vec<FstNode>,
    mut iter: I,
) -> Option<&'a mut FstNode>
where
    I: Iterator<Item = &'b str>,
{
    let cur_part = iter.next()?;
    let mut cur_node = nodes.iter_mut().find(|n| n.get_name() == cur_part)?;
    for cur_part in iter {
        match cur_node {
            FstNode::Directory { files, .. } => {
                cur_node = files.iter_mut().find(|n| n.get_name() == cur_part)?;
            }
            // we can't descend into files
            FstNode::File { .. } => return None,
        }
    }
    Some(cur_node)
}

pub fn remove_node_iter<'a, 'b, I>(nodes: &'a mut Vec<FstNode>, iter: I) -> Option<FstNode>
where
    I: Iterator<Item = &'b str>,
{
    let mut peek_iter = iter.peekable();
    let cur_part = peek_iter.next()?;
    if peek_iter.peek().is_none() {
        // iterator is exhausted
        let idx = nodes.iter().position(|n| n.get_name() == cur_part)?;
        return Some(nodes.remove(idx));
    }
    let mut cur_node = nodes.iter_mut().find(|n| n.get_name() == cur_part)?;
    while let Some(cur_part) = peek_iter.next() {
        match cur_node {
            FstNode::Directory { files, .. } => {
                if peek_iter.peek().is_some() {
                    cur_node = files.iter_mut().find(|n| n.get_name() == cur_part)?;
                } else {
                    // iterator is exhausted
                    let idx = files.iter().position(|n| n.get_name() == cur_part)?;
                    return Some(files.remove(idx));
                }
            }
            // we can't descend into files
            FstNode::File { .. } => return None,
        }
    }
    None
}

pub fn add_node_iter<'a, 'b, I>(
    nodes: &'a mut Vec<FstNode>,
    mut iter: I,
    mut new_node: FstNode,
) -> Result<Option<FstNode>, ()>
where
    I: Iterator<Item = &'b str>,
{
    let mut dir_node_files = if let Some(cur_part) = iter.next() {
        // we search the name we want to insert and assume the lists are ordered
        // we either get back the actual position of the element or
        // the position to insert the new node to remain sorted
        let node = match nodes
            .binary_search_by(|probe| ordering_ignore_case(probe.get_name(), cur_part))
        {
            Ok(pos) => &mut nodes[pos],
            Err(pos) => {
                // we need to either create a new directory
                let new_dir_node = FstNode::Directory {
                    name: cur_part.to_string(),
                    files: Vec::new(),
                };
                nodes.insert(pos, new_dir_node);
                &mut nodes[pos]
            }
        };
        match node {
            FstNode::Directory { files, .. } => files,
            // can't insert when the node is a file
            FstNode::File { .. } => return Err(()),
        }
    } else {
        // we have to insert at the root node
        match nodes
            .binary_search_by(|probe| ordering_ignore_case(probe.get_name(), new_node.get_name()))
        {
            Ok(pos) => {
                // since the path is exhausted, replace the node completely
                std::mem::swap(&mut new_node, &mut nodes[pos]);
                return Ok(Some(new_node));
            }
            Err(pos) => {
                // new file, vec is still sorted
                nodes.insert(pos, new_node);
                return Ok(None);
            }
        }
    };
    for cur_part in iter {
        let node = match dir_node_files
            .binary_search_by(|probe| ordering_ignore_case(probe.get_name(), cur_part))
        {
            Ok(pos) => &mut dir_node_files[pos],
            Err(pos) => {
                // we need to either create a new directory
                let new_dir_node = FstNode::Directory {
                    name: cur_part.to_string(),
                    files: Vec::new(),
                };
                dir_node_files.insert(pos, new_dir_node);
                &mut dir_node_files[pos]
            }
        };
        dir_node_files = match node {
            FstNode::Directory { files, .. } => files,
            // can't insert when the node is a file
            FstNode::File { .. } => return Err(()),
        };
    }
    match dir_node_files
        .binary_search_by(|probe| ordering_ignore_case(probe.get_name(), new_node.get_name()))
    {
        Ok(pos) => {
            // since the path is exhausted, replace the node completely
            std::mem::swap(&mut new_node, &mut dir_node_files[pos]);
            Ok(Some(new_node))
        }
        Err(pos) => {
            // new file, vec is still sorted
            dir_node_files.insert(pos, new_node);
            Ok(None)
        }
    }
}

impl Fst {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn read<RS: Read + Seek>(rs: &mut RS, offset: u64) -> binrw::BinResult<Self> {
        rs.seek(SeekFrom::Start(offset))?;
        let root_node: RawFstNode = rs.read_be()?;
        // directory and no name offset
        if !root_node.is_directory || root_node.offset != 0 || root_node.length == 0 {
            return Err(binrw::Error::Custom {
                pos: offset,
                err: Box::new(format!("invalid FST first node: {:?}", &root_node)),
            });
        }
        let total_node_count = root_node.length - 1;
        let mut nodes = Vec::with_capacity(total_node_count as usize);
        nodes.push(root_node);
        for _ in 0..total_node_count {
            nodes.push(rs.read_be::<RawFstNode>()?);
        }
        let str_offset = rs.stream_position()?;

        let fst_nodes =
            Self::transform_fst_rec(rs, str_offset, &nodes, total_node_count + 1, &mut 1)?;
        Ok(Self { entries: fst_nodes })
    }

    fn transform_fst_rec<RS: Read + Seek>(
        rs: &mut RS,
        str_offset: u64,
        raw_nodes: &Vec<RawFstNode>,
        children_end: u32,
        cur_idx: &mut u32,
    ) -> binrw::BinResult<Vec<FstNode>> {
        let mut nodes = Vec::with_capacity(raw_nodes.len());
        while *cur_idx < children_end {
            let node = &raw_nodes[*cur_idx as usize];
            let name = read_shiftjs(rs, str_offset + node.name_offset as u64)?;
            *cur_idx += 1;
            if node.is_directory {
                let files =
                    Self::transform_fst_rec(rs, str_offset, raw_nodes, node.length, cur_idx)?;
                nodes.push(FstNode::Directory { name, files });
            } else {
                nodes.push(FstNode::File {
                    name,
                    offset: (node.offset as u64) << 2,
                    length: node.length,
                });
            }
        }
        assert_eq!(*cur_idx, children_end);
        Ok(nodes)
    }

    pub fn get_entries_mut(&mut self) -> &mut Vec<FstNode> {
        &mut self.entries
    }

    pub fn get_entries(&self) -> &Vec<FstNode> {
        &self.entries
    }

    /// Returns an immutable reference to the FstNode by path if it's found
    pub fn find_node_path<'a>(&'a self, s: &str) -> Option<&'a FstNode> {
        self.find_node_iter(s.split('/').filter(|p| !p.is_empty()))
    }

    pub fn find_node_iter<'a, 'b, I>(&'a self, iter: I) -> Option<&'a FstNode>
    where
        I: Iterator<Item = &'b str>,
    {
        find_node_iter(&self.entries, iter)
    }

    /// Returns an immutable reference to the FstNode by path if it's found
    pub fn find_node_path_mut<'a>(&'a mut self, s: &str) -> Option<&'a mut FstNode> {
        self.find_node_iter_mut(s.split('/').filter(|p| !p.is_empty()))
    }

    pub fn find_node_iter_mut<'a, 'b, I>(&'a mut self, iter: I) -> Option<&'a mut FstNode>
    where
        I: Iterator<Item = &'b str>,
    {
        find_node_iter_mut(&mut self.entries, iter)
    }

    pub fn remove_node_path(&mut self, s: &str) -> Option<FstNode> {
        self.remove_node_iter(s.split('/').filter(|p| !p.is_empty()))
    }

    pub fn remove_node_iter<'a, 'b, I>(&mut self, iter: I) -> Option<FstNode>
    where
        I: Iterator<Item = &'b str>,
    {
        remove_node_iter(&mut self.entries, iter)
    }

    pub fn add_node_path(&mut self, s: &str, node: FstNode) -> Result<Option<FstNode>, ()> {
        self.add_node_iter(s.split('/').filter(|p| !p.is_empty()), node)
    }

    pub fn add_node_iter<'a, 'b, I>(
        &mut self,
        iter: I,
        node: FstNode,
    ) -> Result<Option<FstNode>, ()>
    where
        I: Iterator<Item = &'b str>,
    {
        add_node_iter(&mut self.entries, iter, node)
    }

    /// Prints the entire node tree, using indents to mark folders and their files
    pub fn print_tree(&self) {
        for entry in self.entries.iter() {
            entry.print_tree(0);
        }
    }

    /// Allows to run a callback for all nodes of this fst, which is given
    /// the full path up until that files
    /// this is useful for example for extracting all files,
    pub fn callback_all_files<E, F: FnMut(&Vec<&str>, &FstNode) -> Result<(), E>>(
        &self,
        f: &mut F,
    ) -> Result<(), E> {
        let mut path = Vec::with_capacity(20);
        Self::callback_all_files_rec(f, &self.entries, &mut path)
    }

    fn callback_all_files_rec<'a, E, F: FnMut(&Vec<&str>, &FstNode) -> Result<(), E>>(
        f: &mut F,
        nodes: &'a Vec<FstNode>,
        vec: &mut Vec<&'a str>,
    ) -> Result<(), E> {
        for node in nodes {
            vec.push(node.get_name());
            f(vec, node)?;
            match node {
                FstNode::Directory { files, .. } => {
                    Self::callback_all_files_rec(f, files, vec)?;
                }
                FstNode::File { .. } => {}
            }
            let _ = vec.pop();
        }
        Ok(())
    }

    /// Allows to run a callback for all nodes of this fst, which is given
    /// the full path up until that files
    /// this variant receives a mutable reference to the node
    /// this is useful for example for writing back information into all nodes
    pub fn callback_all_files_mut<E, F: FnMut(&Vec<String>, &mut FstNode) -> Result<(), E>>(
        &mut self,
        f: &mut F,
    ) -> Result<(), E> {
        let mut path = Vec::with_capacity(20);
        Self::callback_all_files_rec_mut(f, &mut self.entries, &mut path)
    }

    fn callback_all_files_rec_mut<'a, E, F: FnMut(&Vec<String>, &mut FstNode) -> Result<(), E>>(
        f: &mut F,
        nodes: &'a mut Vec<FstNode>,
        vec: &mut Vec<String>,
    ) -> Result<(), E> {
        for node in nodes {
            vec.push(node.get_name().clone());
            f(vec, node)?;
            // make sure we have the correct path even if
            // the node name was modified
            if let Some(saved_name) = vec.iter().last() {
                if saved_name != node.get_name() {
                    let _ = vec.pop();
                    vec.push(node.get_name().clone());
                }
            }
            match node {
                FstNode::Directory { files, .. } => {
                    Self::callback_all_files_rec_mut(f, files, vec)?;
                }
                FstNode::File { .. } => {}
            }
            let _ = vec.pop();
        }
        Ok(())
    }

    pub fn fix_ordering(&mut self) {
        Self::fix_ordering_rec(&mut self.entries);
    }

    fn fix_ordering_rec(nodes: &mut Vec<FstNode>) {
        nodes.sort_unstable_by(FstNode::node_compare);
        for node in nodes {
            match node {
                FstNode::Directory { files, .. } => Self::fix_ordering_rec(files),
                _ => {}
            }
        }
    }
}

pub struct FstToBytes {
    fst: Fst,
    str_offsets: Vec<u32>,
    str_bytes: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum FstToBytesError {
    #[error("{0} can't be converted into shift-jis!")]
    InvalidShiftJis(String),
}

fn rec_build_fst_bytes(
    nodes: &Vec<FstNode>,
    name_offsets: &mut Vec<u32>,
    str_bytes: &mut Vec<u8>,
) -> Result<(), FstToBytesError> {
    for node in nodes {
        let (bytes, _, error) = SHIFT_JIS.encode(node.get_name());
        if error {
            return Err(FstToBytesError::InvalidShiftJis(node.get_name().clone()));
        }
        let name_offset = str_bytes.len() as u32;
        str_bytes.extend_from_slice(bytes.as_ref());
        str_bytes.push(0);
        name_offsets.push(name_offset as u32);
        match node {
            FstNode::Directory { files, .. } => {
                rec_build_fst_bytes(files, name_offsets, str_bytes)?;
            }
            &FstNode::File { .. } => {}
        }
    }
    Ok(())
}

impl TryFrom<Fst> for FstToBytes {
    // TODO
    type Error = FstToBytesError;

    fn try_from(value: Fst) -> Result<Self, Self::Error> {
        // buffers
        let mut str_offsets = Vec::new();
        let mut str_bytes = Vec::new();
        // root node
        str_offsets.push(0);
        str_bytes.push(0);
        // recursive
        rec_build_fst_bytes(&value.entries, &mut str_offsets, &mut str_bytes)?;
        Ok(FstToBytes {
            str_offsets,
            str_bytes,
            fst: value,
        })
    }
}

impl FstToBytes {
    /// Allows to run a callback for all file nodes of this fst, which is given
    /// the full path up until that files
    /// this variant receives a mutable reference to file offset and length
    /// this is useful for example for writing back information into all file nodes
    pub fn callback_all_files_mut<
        E,
        F: FnMut(&Vec<String>, &mut u64, &mut u32) -> Result<(), E>,
    >(
        &mut self,
        f: &mut F,
    ) -> Result<(), E> {
        let mut path = Vec::with_capacity(20);
        Self::callback_all_files_rec_mut(f, &mut self.fst.entries, &mut path)
    }

    fn callback_all_files_rec_mut<
        'a,
        E,
        F: FnMut(&Vec<String>, &mut u64, &mut u32) -> Result<(), E>,
    >(
        f: &mut F,
        nodes: &'a mut Vec<FstNode>,
        path: &mut Vec<String>,
    ) -> Result<(), E> {
        for node in nodes {
            path.push(node.get_name().clone());
            match node {
                FstNode::Directory { files, .. } => {
                    Self::callback_all_files_rec_mut(f, files, path)?;
                }
                FstNode::File {
                    ref mut offset,
                    ref mut length,
                    ..
                } => f(path, offset, length)?,
            }
            let _ = path.pop();
        }
        Ok(())
    }

    pub fn get_total_file_count(&self) -> usize {
        Self::get_total_file_count_rec(&self.fst.entries)
    }

    fn get_total_file_count_rec(nodes: &Vec<FstNode>) -> usize {
        nodes
            .iter()
            .map(|node| match node {
                FstNode::File { .. } => 1,
                FstNode::Directory { files, .. } => Self::get_total_file_count_rec(files),
            })
            .sum()
    }

    pub fn write_to<W: Write + Seek>(&self, w: &mut W) -> binrw::BinResult<()> {
        let mut raw_nodes = Vec::with_capacity(self.str_offsets.len());
        raw_nodes.push(RawFstNode {
            is_directory: true,
            name_offset: 0,
            offset: 0,
            length: u32::MAX,
        });
        let mut idx = 1;
        Self::build_node_bytes_rec(
            &self.fst.entries,
            &self.str_offsets,
            &mut raw_nodes,
            &mut idx,
        );
        if let Some(node) = raw_nodes.get_mut(0) {
            node.length = idx;
        }
        w.write_be(&raw_nodes)?;
        w.write_all(&self.str_bytes)?;
        Ok(())
    }

    fn build_node_bytes_rec(
        nodes: &Vec<FstNode>,
        str_offsets: &Vec<u32>,
        raw_nodes: &mut Vec<RawFstNode>,
        idx: &mut u32,
    ) {
        // the first non root node is 1, so this can't underflow
        let parent_idx = idx.wrapping_sub(1);
        for node in nodes.iter() {
            let this_idx = *idx as usize;
            debug_assert_eq!(this_idx, raw_nodes.len());
            let name_offset = str_offsets[this_idx];
            *idx += 1;
            match node {
                FstNode::Directory { files, .. } => {
                    // length (which is the next sibling node here) will be filled in later
                    raw_nodes.push(RawFstNode {
                        is_directory: true,
                        name_offset,
                        offset: parent_idx,
                        length: u32::MAX,
                    });
                    Self::build_node_bytes_rec(files, str_offsets, raw_nodes, idx);
                    // this index is always inbounds, but this way it doesn't introduce a panicking branch
                    if let Some(node) = raw_nodes.get_mut(this_idx) {
                        node.length = *idx;
                    }
                }
                &FstNode::File { length, offset, .. } => {
                    raw_nodes.push(RawFstNode {
                        is_directory: false,
                        name_offset,
                        offset: (offset >> 2) as u32,
                        length,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::{Fst, FstNode};

    use super::FstToBytes;

    fn get_test_fst() -> Fst {
        Fst {
            entries: vec![
                FstNode::Directory {
                    name: "directory".into(),
                    files: vec![
                        FstNode::Directory {
                            name: "moar directories".into(),
                            files: vec![],
                        },
                        FstNode::create_file("moar files".into()),
                    ],
                },
                FstNode::create_file("file1".into()),
            ],
        }
    }

    #[test]
    pub fn test_add() {
        let mut fst = Fst::default();
        assert!(matches!(
            fst.add_node_path("test/path2", FstNode::create_file("file.arc".into())),
            Ok(None)
        ));
        assert!(matches!(
            fst.add_node_path("test/path", FstNode::create_file("file.arc".into())),
            Ok(None)
        ));
        assert!(matches!(
            fst.add_node_path("test/path5", FstNode::create_file("file.arc".into())),
            Ok(None)
        ));
        assert!(matches!(
            fst.add_node_path("test/path5", FstNode::create_file("file.arc".into())),
            Ok(Some(_))
        ));
        assert!(matches!(
            fst.add_node_path("", FstNode::create_file("file.arc".into())),
            Ok(None)
        ));
        assert!(matches!(
            fst.add_node_path("", FstNode::create_file("file.arc".into())),
            Ok(Some(_))
        ));
        assert!(matches!(
            fst.add_node_path("file.arc", FstNode::create_file("test".into())),
            Err(())
        ));

        assert!(fst.find_node_path("file.arc").is_some());
        let test_dir_files = match fst.find_node_path("test").unwrap() {
            FstNode::Directory { name, files } => {
                assert_eq!(name, "test");
                files
            }
            _ => panic!("should be a directory"),
        };
        assert_eq!(test_dir_files[0].get_name(), "path");
        assert_eq!(test_dir_files[1].get_name(), "path2");
        assert_eq!(test_dir_files[2].get_name(), "path5");
    }

    #[test]
    pub fn test_remove() {
        let mut fst = get_test_fst();
        assert!(
            matches!(fst.remove_node_path("directory/moar directories"), Some(FstNode::Directory { name, ..}) if name == "moar directories")
        );
        assert!(
            matches!(fst.remove_node_path("directory"), Some(FstNode::Directory { name, ..}) if name == "directory")
        );
        assert!(
            matches!(fst.remove_node_path("file1"), Some(FstNode::File { name, ..}) if name == "file1")
        );
    }

    #[test]
    pub fn test_find() {
        let fst = get_test_fst();
        assert!(
            matches!(fst.find_node_path("directory/moar directories"), Some(FstNode::Directory { name, ..}) if name == "moar directories")
        );
        assert!(
            matches!(fst.find_node_path("directory"), Some(FstNode::Directory { name, ..}) if name == "directory")
        );
        assert!(
            matches!(fst.find_node_path("file1"), Some(FstNode::File { name, ..}) if name == "file1")
        );
    }

    #[test]
    pub fn test_build() {
        let fst = get_test_fst();
        let nodes = fst.entries.clone();
        let fst_to_bytes = FstToBytes::try_from(fst).unwrap();
        let mut out_vec = Vec::new();
        fst_to_bytes
            .write_to(&mut Cursor::new(&mut out_vec))
            .unwrap();
        let new_fst = Fst::read(&mut Cursor::new(&out_vec), 0).unwrap();
        new_fst.print_tree();
        assert_eq!(nodes, new_fst.entries);
    }
}
