use std::io::SeekFrom;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::async_spooled_tempfile::SpooledTempFile;
use crate::error::CrabCakesError;

const MEMORY_THRESHOLD: usize = 50 * 1024 * 1024; // 50MB

/// A buffered request body that can be stored in memory or spilled to disk
pub struct BufferedBody {
    file: SpooledTempFile,
    size: usize,
}

impl BufferedBody {
    /// Buffer a hyper Incoming body, spilling to disk if it exceeds the threshold
    pub async fn from_incoming(body: Incoming) -> Result<Self, CrabCakesError> {
        let mut body = body;

        let mut written_bytes = 0;
        let mut temp_file = SpooledTempFile::new(MEMORY_THRESHOLD);

        // Collect the body
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| CrabCakesError::other(format!("Body read error: {}", e)))?;

            if let Some(data) = frame.data_ref() {
                temp_file.write_all(data).await.map_err(|e| {
                    CrabCakesError::other(format!("Failed to write to spooled temp file: {}", e))
                })?;
                written_bytes += data.len();
            }
        }

        Ok(BufferedBody {
            file: temp_file,
            size: written_bytes,
        })
    }

    /// Get the body as a byte vector (reading from disk if necessary)
    /// Note: This method rewinds the file to the start before AND after reading
    /// to allow multiple reads from the same buffer.
    pub async fn to_vec(&mut self) -> Result<Vec<u8>, CrabCakesError> {
        let mut buffer = Vec::with_capacity(self.size);
        self.file
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|e| CrabCakesError::other(format!("Failed to rewind spooled file: {}", e)))?;
        self.file
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| CrabCakesError::other(format!("Failed to read spooled file: {}", e)))?;
        // Rewind again so the buffer can be read multiple times
        self.file.seek(SeekFrom::Start(0)).await.map_err(|e| {
            CrabCakesError::other(format!("Failed to rewind spooled file after read: {}", e))
        })?;
        Ok(buffer)
    }
}
