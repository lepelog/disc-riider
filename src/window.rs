use std::io::{self, Read, Seek, SeekFrom, Write};

pub struct IOWindow<'a, R> {
    source: &'a mut R,
    pos: u64,
    start: u64,
}

impl<'a, R> IOWindow<'a, R>
where
    R: Seek,
{
    pub fn new(source: &'a mut R, start: u64) -> io::Result<Self> {
        let mut window = IOWindow {
            source,
            start,
            pos: 0,
        };
        window.seek(SeekFrom::Start(0))?;
        Ok(window)
    }
}

impl<'a, R> Read for IOWindow<'a, R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.source.read(buf) {
            Ok(amt) => {
                self.pos += amt as u64;
                Ok(amt)
            }
            e => e,
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self.source.read_exact(buf) {
            Ok(()) => {
                self.pos += buf.len() as u64;
                Ok(())
            }
            e => e,
        }
    }
}

impl<'a, R> Write for IOWindow<'a, R>
where
    R: Write + Seek,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.source.write(buf) {
            Ok(amt) => {
                self.pos += amt as u64;
                Ok(amt)
            }
            e => e,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.source.flush()
    }
}

impl<'a, R> Seek for IOWindow<'a, R>
where
    R: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let position = self.source.seek(match pos {
            SeekFrom::Current(_) => pos,
            SeekFrom::End(_off) => return Err(io::ErrorKind::Unsupported.into()),
            SeekFrom::Start(off) => SeekFrom::Start(self.start + off),
        })?;
        self.pos = position.saturating_sub(self.start);
        Ok(self.pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.pos)
    }
}

#[cfg(test)]
mod test {
    use binrw::BinReaderExt;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use crate::IOWindow;

    #[test]
    pub fn test_window() {
        let mut buf = vec![0u8; 10];
        let mut cur = Cursor::new(&mut buf);
        let mut win = IOWindow::new(&mut cur, 2).unwrap();
        assert_eq!(win.stream_position().unwrap(), 0);
        win.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(win.stream_position().unwrap(), 3);
        let _ = win.read_be::<u16>();
        assert_eq!(win.stream_position().unwrap(), 5);
        win.write_all(&[1, 2, 3]).unwrap();
        win.seek(SeekFrom::Current(-3)).unwrap();
        let mut result = [0; 3];
        assert_eq!(win.read(&mut result).unwrap(), 3);
        assert_eq!(result, [1, 2, 3]);
    }
}
