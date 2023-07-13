use std::io::{self, Read, Seek, SeekFrom, Write};

pub struct IOWindow<R: Seek> {
    source: R,
    pos: u64,
    start: u64,
    length: Option<u64>,
    needs_seek: bool,
}

impl<R> IOWindow<R>
where
    R: Seek,
{
    pub fn new(source: R, start: u64, length: Option<u64>) -> Self {
        IOWindow {
            source,
            start,
            pos: 0,
            length,
            needs_seek: true,
        }
    }

    fn ensure_seeked(&mut self) -> io::Result<()> {
        if self.needs_seek {
            self.source
                .seek(SeekFrom::Start(self.pos + self.start))
                .map(drop)
        } else {
            Ok(())
        }
    }

    fn bytes_left(&self) -> Option<usize> {
        self.length
            .map(|length| length.saturating_sub(self.pos) as usize)
    }
}

impl<R> Read for IOWindow<R>
where
    R: Read + Seek,
{
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_seeked()?;
        if let Some(bytes_left) = self.bytes_left() {
            let new_len = bytes_left.min(buf.len());
            buf = &mut buf[..new_len];
        }
        match self.source.read(buf) {
            Ok(amt) => {
                self.pos += amt as u64;
                Ok(amt)
            }
            e => {
                self.needs_seek = true;
                e
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if let Some(bytes_left) = self.bytes_left() {
            if bytes_left > buf.len() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        self.ensure_seeked()?;
        match self.source.read_exact(buf) {
            Ok(()) => {
                self.pos += buf.len() as u64;
                Ok(())
            }
            e => {
                self.needs_seek = true;
                e
            }
        }
    }
}

impl<R> Write for IOWindow<R>
where
    R: Write + Seek,
{
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        self.ensure_seeked()?;
        if let Some(bytes_left) = self.bytes_left() {
            let new_len = bytes_left.min(buf.len());
            buf = &buf[..new_len];
        }
        match self.source.write(buf) {
            Ok(amt) => {
                self.pos += amt as u64;
                Ok(amt)
            }
            e => {
                self.needs_seek = true;
                e
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.source.flush()
    }
}

impl<R> Seek for IOWindow<R>
where
    R: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let position = self.source.seek(match pos {
            SeekFrom::Current(_) => pos,
            SeekFrom::End(off) => {
                if let Some(length) = self.length {
                    SeekFrom::Start((self.start + length).saturating_add_signed(off))
                } else {
                    return Err(io::ErrorKind::Unsupported.into());
                }
            }
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
    use std::{
        array,
        io::{Cursor, ErrorKind, Read, Seek, SeekFrom, Write},
    };

    use crate::IOWindow;

    #[test]
    pub fn test_window() {
        let mut buf = vec![0u8; 10];
        let mut cur = Cursor::new(&mut buf);
        let mut win = IOWindow::new(&mut cur, 2, None);
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
        assert_eq!(
            win.seek(SeekFrom::End(0)).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    pub fn test_window_with_len() {
        let buf: [u8; 20] = array::from_fn(|v| v as u8);
        let mut cur = Cursor::new(&buf);
        let mut win = IOWindow::new(&mut cur, 10, Some(3));
        assert_eq!(win.stream_position().unwrap(), 0);
        win.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(win.stream_position().unwrap(), 3);
        win.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(win.stream_position().unwrap(), 0);
        let mut read_buf = [0; 10];
        assert_eq!(win.read(&mut read_buf).unwrap(), 3);
        assert_eq!(read_buf[..3], [10, 11, 12])
    }
}
