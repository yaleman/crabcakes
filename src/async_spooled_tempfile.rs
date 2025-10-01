//! Asynchronous spooled temporary file implementation.
//!
//! This module provides an async version of `tempfile::SpooledTempFile` that stores data
//! in memory until it exceeds a threshold, then spills to disk automatically.
//!
//! Based on: https://github.com/AverageADF/async-spooled-tempfile

use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

#[derive(Debug)]
enum DataLocation {
    InMemory(Option<Cursor<Vec<u8>>>),
    WritingToDisk(JoinHandle<io::Result<File>>),
    OnDisk(File),
    Poisoned,
}

#[derive(Debug)]
struct Inner {
    data_location: DataLocation,
    last_write_err: Option<io::Error>,
}

/// Data stored in a [`SpooledTempFile`] instance.
#[derive(Debug)]
pub enum SpooledData {
    InMemory(Cursor<Vec<u8>>),
    OnDisk(File),
}

/// Asynchronous spooled temporary file.
///
/// This type stores data in memory until it exceeds `max_size`, then automatically
/// spills to a temporary file on disk.
#[derive(Debug)]
pub struct SpooledTempFile {
    max_size: usize,
    inner: Inner,
}

impl SpooledTempFile {
    /// Creates a new instance that can hold up to `max_size` bytes in memory.
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            inner: Inner {
                data_location: DataLocation::InMemory(Some(Cursor::new(Vec::new()))),
                last_write_err: None,
            },
        }
    }

    /// Creates a new instance that can hold up to `max_size` bytes in memory
    /// and pre-allocates space for the in-memory buffer.
    pub fn with_max_size_and_capacity(max_size: usize, capacity: usize) -> Self {
        Self {
            max_size,
            inner: Inner {
                data_location: DataLocation::InMemory(Some(Cursor::new(Vec::with_capacity(
                    capacity,
                )))),
                last_write_err: None,
            },
        }
    }

    /// Returns `true` if the data have been written to a file.
    pub fn is_rolled(&self) -> bool {
        matches!(self.inner.data_location, DataLocation::OnDisk(..))
    }

    /// Determines whether the current instance is poisoned.
    ///
    /// An instance is poisoned if it failed to move its data from memory to disk.
    pub fn is_poisoned(&self) -> bool {
        matches!(self.inner.data_location, DataLocation::Poisoned)
    }

    /// Consumes and returns the inner [`SpooledData`] type.
    pub async fn into_inner(self) -> Result<SpooledData, io::Error> {
        match self.inner.data_location {
            DataLocation::InMemory(opt_mem_buffer) => {
                Ok(SpooledData::InMemory(opt_mem_buffer.unwrap()))
            }
            DataLocation::WritingToDisk(handle) => match handle.await {
                Ok(Ok(file)) => Ok(SpooledData::OnDisk(file)),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(io::Error::other("background task failed")),
            },
            DataLocation::OnDisk(file) => Ok(SpooledData::OnDisk(file)),
            DataLocation::Poisoned => {
                Err(io::Error::other("failed to move data from memory to disk"))
            }
        }
    }

    fn poll_roll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        loop {
            match self.inner.data_location {
                DataLocation::InMemory(ref mut opt_mem_buffer) => {
                    let mut mem_buffer = opt_mem_buffer.take().unwrap();

                    let handle = tokio::task::spawn_blocking(move || {
                        let mut file = tempfile::tempfile()?;

                        file.write_all(mem_buffer.get_mut())?;
                        file.seek(SeekFrom::Start(mem_buffer.position()))?;

                        Ok(File::from_std(file))
                    });

                    self.inner.data_location = DataLocation::WritingToDisk(handle);
                }
                DataLocation::WritingToDisk(ref mut handle) => {
                    let res = ready!(Pin::new(handle).poll(cx));

                    match res {
                        Ok(Ok(file)) => {
                            self.inner.data_location = DataLocation::OnDisk(file);
                        }
                        Ok(Err(err)) => {
                            self.inner.data_location = DataLocation::Poisoned;
                            return Poll::Ready(Err(err));
                        }
                        Err(_) => {
                            self.inner.data_location = DataLocation::Poisoned;
                            return Poll::Ready(Err(io::Error::other("background task failed")));
                        }
                    }
                }
                DataLocation::OnDisk(_) => {
                    return Poll::Ready(Ok(()));
                }
                DataLocation::Poisoned => {
                    return Poll::Ready(Err(io::Error::other(
                        "failed to move data from memory to disk",
                    )));
                }
            }
        }
    }

    /// Moves the data from memory to disk.
    /// Does nothing if the transition has already been made.
    pub async fn roll(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_roll(cx)).await
    }

    /// Truncates or extends the underlying buffer / file.
    ///
    /// If the provided size is greater than `max_size`, data will be moved from
    /// memory to disk regardless of the size of the data held by the current instance.
    pub async fn set_len(&mut self, size: u64) -> Result<(), io::Error> {
        if size > self.max_size as u64 {
            self.roll().await?;
        }

        loop {
            match self.inner.data_location {
                DataLocation::InMemory(ref mut opt_mem_buffer) => {
                    opt_mem_buffer
                        .as_mut()
                        .unwrap()
                        .get_mut()
                        .resize(size as usize, 0);
                    return Ok(());
                }
                DataLocation::WritingToDisk(_) => {
                    self.roll().await?;
                }
                DataLocation::OnDisk(ref mut file) => {
                    return file.set_len(size).await;
                }
                DataLocation::Poisoned => {
                    return Err(io::Error::other("failed to move data from memory to disk"));
                }
            }
        }
    }
}

impl AsyncWrite for SpooledTempFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let me = self.get_mut();

        if let Some(err) = me.inner.last_write_err.take() {
            return Poll::Ready(Err(err));
        }

        loop {
            match me.inner.data_location {
                DataLocation::InMemory(ref mut opt_mem_buffer) => {
                    let mut mem_buffer = opt_mem_buffer.take().unwrap();

                    if mem_buffer.position().saturating_add(buf.len() as u64) > me.max_size as u64 {
                        *opt_mem_buffer = Some(mem_buffer);

                        ready!(me.poll_roll(cx))?;

                        continue;
                    }

                    let res = Pin::new(&mut mem_buffer).poll_write(cx, buf);

                    *opt_mem_buffer = Some(mem_buffer);

                    return res;
                }
                DataLocation::WritingToDisk(_) => {
                    ready!(me.poll_roll(cx))?;
                }
                DataLocation::OnDisk(ref mut file) => {
                    return Pin::new(file).poll_write(cx, buf);
                }
                DataLocation::Poisoned => {
                    return Poll::Ready(Err(io::Error::other(
                        "failed to move data from memory to disk",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let me = self.get_mut();

        match me.inner.data_location {
            DataLocation::InMemory(ref mut opt_mem_buffer) => {
                Pin::new(opt_mem_buffer.as_mut().unwrap()).poll_flush(cx)
            }
            DataLocation::WritingToDisk(_) => me.poll_roll(cx),
            DataLocation::OnDisk(ref mut file) => Pin::new(file).poll_flush(cx),
            DataLocation::Poisoned => Poll::Ready(Err(io::Error::other(
                "failed to move data from memory to disk",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.poll_flush(cx)
    }
}

impl AsyncRead for SpooledTempFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        loop {
            match me.inner.data_location {
                DataLocation::InMemory(ref mut opt_mem_buffer) => {
                    return Pin::new(opt_mem_buffer.as_mut().unwrap()).poll_read(cx, buf);
                }
                DataLocation::WritingToDisk(_) => {
                    if let Err(write_err) = ready!(me.poll_roll(cx)) {
                        me.inner.last_write_err = Some(write_err);
                    }
                }
                DataLocation::OnDisk(ref mut file) => {
                    return Pin::new(file).poll_read(cx, buf);
                }
                DataLocation::Poisoned => {
                    return Poll::Ready(Err(io::Error::other(
                        "failed to move data from memory to disk",
                    )));
                }
            }
        }
    }
}

impl AsyncSeek for SpooledTempFile {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let me = self.get_mut();

        match me.inner.data_location {
            DataLocation::InMemory(ref mut opt_mem_buffer) => {
                Pin::new(opt_mem_buffer.as_mut().unwrap()).start_seek(position)
            }
            DataLocation::WritingToDisk(_) => Err(io::Error::other(
                "other operation is pending, call poll_complete before start_seek",
            )),
            DataLocation::OnDisk(ref mut file) => Pin::new(file).start_seek(position),
            DataLocation::Poisoned => {
                Err(io::Error::other("failed to move data from memory to disk"))
            }
        }
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = self.get_mut();

        loop {
            match me.inner.data_location {
                DataLocation::InMemory(ref mut opt_mem_buffer) => {
                    return Pin::new(opt_mem_buffer.as_mut().unwrap()).poll_complete(cx);
                }
                DataLocation::WritingToDisk(_) => {
                    if let Err(write_err) = ready!(me.poll_roll(cx)) {
                        me.inner.last_write_err = Some(write_err);
                    }
                }
                DataLocation::OnDisk(ref mut file) => {
                    return Pin::new(file).poll_complete(cx);
                }
                DataLocation::Poisoned => {
                    return Poll::Ready(Err(io::Error::other(
                        "failed to move data from memory to disk",
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_small_file_stays_in_memory() {
        // Write 1KB of data (well under 50MB threshold)
        let mut file = SpooledTempFile::new(50 * 1024 * 1024);
        let data = vec![42u8; 1024];

        file.write_all(&data).await.unwrap();
        assert!(!file.is_rolled(), "Small file should stay in memory");
        assert!(!file.is_poisoned(), "File should not be poisoned");

        // Read it back
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, data, "Data read should match data written");
    }

    #[tokio::test]
    async fn test_large_file_spills_to_disk() {
        // Write 150MB of data (exceeds 50MB threshold)
        let mut file = SpooledTempFile::new(50 * 1024 * 1024);
        let chunk_size = 10 * 1024 * 1024; // 10MB chunks
        let num_chunks = 15; // 150MB total
        let chunk = vec![123u8; chunk_size];

        for _ in 0..num_chunks {
            file.write_all(&chunk).await.unwrap();
        }

        // Flush to ensure spillover completes
        file.flush().await.unwrap();

        assert!(file.is_rolled(), "Large file should spill to disk");
        assert!(!file.is_poisoned(), "File should not be poisoned");

        // Read back first chunk to verify
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut buf = vec![0u8; chunk_size];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf, chunk, "Data read should match data written");
    }

    #[tokio::test]
    async fn test_exactly_at_threshold() {
        // Write exactly 50MB
        let threshold = 50 * 1024 * 1024;
        let mut file = SpooledTempFile::new(threshold);
        let data = vec![77u8; threshold];

        file.write_all(&data).await.unwrap();
        file.flush().await.unwrap();

        // At exactly the threshold, should still be in memory
        assert!(!file.is_rolled(), "Data at threshold should stay in memory");

        // Read it back
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf.len(), threshold, "Should read back full data");
    }

    #[tokio::test]
    async fn test_one_byte_over_threshold() {
        // Write 50MB + 1 byte to trigger spillover
        let threshold = 50 * 1024 * 1024;
        let mut file = SpooledTempFile::new(threshold);
        let data = vec![88u8; threshold + 1];

        file.write_all(&data).await.unwrap();
        file.flush().await.unwrap();

        assert!(file.is_rolled(), "Data over threshold should spill to disk");

        // Read it back
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, data, "Data read should match data written");
    }

    #[tokio::test]
    async fn test_seek_operations() {
        let mut file = SpooledTempFile::new(1024 * 1024);

        // Write some data
        file.write_all(b"Hello, World!").await.unwrap();

        // Seek to start
        let pos = file.seek(SeekFrom::Start(0)).await.unwrap();
        assert_eq!(pos, 0);

        // Read "Hello"
        let mut buf = vec![0u8; 5];
        file.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"Hello");

        // Seek to position 7
        let pos = file.seek(SeekFrom::Start(7)).await.unwrap();
        assert_eq!(pos, 7);

        // Read "World"
        let mut buf = vec![0u8; 5];
        file.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"World");

        // Seek from end
        let pos = file.seek(SeekFrom::End(-1)).await.unwrap();
        assert_eq!(pos, 12);

        let mut buf = vec![0u8; 1];
        file.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"!");
    }

    #[tokio::test]
    async fn test_multiple_writes_and_reads() {
        let mut file = SpooledTempFile::new(1024 * 1024);

        // Write multiple chunks
        file.write_all(b"First ").await.unwrap();
        file.write_all(b"Second ").await.unwrap();
        file.write_all(b"Third").await.unwrap();

        // Seek to start and read all
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).await.unwrap();

        assert_eq!(buf, "First Second Third");
    }

    #[tokio::test]
    async fn test_set_len_under_threshold() {
        let mut file = SpooledTempFile::new(1024 * 1024);

        // Set length to 100 bytes (under threshold)
        file.set_len(100).await.unwrap();

        assert!(!file.is_rolled(), "Should stay in memory");

        // Write and read
        file.write_all(b"test").await.unwrap();
        file.seek(SeekFrom::Start(0)).await.unwrap();

        let mut buf = vec![0u8; 4];
        file.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"test");
    }

    #[tokio::test]
    async fn test_set_len_over_threshold() {
        let threshold = 1024;
        let mut file = SpooledTempFile::new(threshold);

        // Set length larger than threshold
        file.set_len((threshold + 100) as u64).await.unwrap();

        assert!(
            file.is_rolled(),
            "Should spill to disk when set_len exceeds threshold"
        );
    }

    #[tokio::test]
    async fn test_into_inner_in_memory() {
        let mut file = SpooledTempFile::new(1024 * 1024);
        file.write_all(b"test data").await.unwrap();

        let data = file.into_inner().await.unwrap();
        match data {
            SpooledData::InMemory(mut cursor) => {
                std::io::Seek::seek(&mut cursor, SeekFrom::Start(0)).unwrap();
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut cursor, &mut buf).unwrap();
                assert_eq!(&buf, b"test data");
            }
            SpooledData::OnDisk(_) => panic!("Expected in-memory data"),
        }
    }

    #[tokio::test]
    async fn test_into_inner_on_disk() {
        let mut file = SpooledTempFile::new(100);
        let data = vec![1u8; 200]; // Exceeds threshold
        file.write_all(&data).await.unwrap();
        file.flush().await.unwrap();

        let spooled_data = file.into_inner().await.unwrap();
        match spooled_data {
            SpooledData::OnDisk(mut f) => {
                use tokio::io::AsyncSeekExt;
                f.seek(SeekFrom::Start(0)).await.unwrap();
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf.len(), 200);
            }
            SpooledData::InMemory(_) => panic!("Expected on-disk data"),
        }
    }

    #[tokio::test]
    async fn test_with_max_size_and_capacity() {
        let file = SpooledTempFile::with_max_size_and_capacity(1024 * 1024, 512);
        assert!(!file.is_rolled());
        assert!(!file.is_poisoned());
    }

    #[tokio::test]
    async fn test_empty_file() {
        let mut file = SpooledTempFile::new(1024);

        // Don't write anything, just read
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf.len(), 0, "Empty file should return empty buffer");
        assert!(!file.is_rolled(), "Empty file should stay in memory");
    }
}
