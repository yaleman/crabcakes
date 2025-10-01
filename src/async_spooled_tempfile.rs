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
