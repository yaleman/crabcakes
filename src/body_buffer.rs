use std::io::Write;

use hyper::body::Incoming;
use http_body_util::BodyExt;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

use crate::error::CrabCakesError;

const MEMORY_THRESHOLD: usize = 50 * 1024 * 1024; // 50MB

/// A buffered request body that can be stored in memory or spilled to disk
pub enum BufferedBody {
    /// Body stored in memory
    Memory(Vec<u8>),
    /// Body stored in a temporary file
    Disk { file: NamedTempFile, size: usize },
}

impl BufferedBody {
    /// Buffer a hyper Incoming body, spilling to disk if it exceeds the threshold
    pub async fn from_incoming(body: Incoming) -> Result<Self, CrabCakesError> {
        let mut buffer = Vec::new();
        let mut body = body;

        // Collect the body
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| CrabCakesError::other(format!("Body read error: {}", e)))?;

            if let Some(data) = frame.data_ref() {
                // Check if we should spill to disk
                if buffer.len() + data.len() > MEMORY_THRESHOLD && buffer.len() < MEMORY_THRESHOLD {
                    info!(
                        current_size = buffer.len(),
                        incoming_size = data.len(),
                        "Request body exceeds memory threshold, spilling to disk"
                    );

                    // Create temporary file
                    let mut temp_file = NamedTempFile::new()
                        .map_err(|e| CrabCakesError::other(format!("Failed to create temp file: {}", e)))?;

                    // Write existing buffer to disk
                    temp_file.write_all(&buffer)
                        .map_err(|e| CrabCakesError::other(format!("Failed to write to temp file: {}", e)))?;

                    // Write current data
                    temp_file.write_all(data)
                        .map_err(|e| CrabCakesError::other(format!("Failed to write to temp file: {}", e)))?;

                    // Continue reading rest of body to disk
                    while let Some(frame) = body.frame().await {
                        let frame = frame.map_err(|e| CrabCakesError::other(format!("Body read error: {}", e)))?;
                        if let Some(data) = frame.data_ref() {
                            temp_file.write_all(data)
                                .map_err(|e| CrabCakesError::other(format!("Failed to write to temp file: {}", e)))?;
                        }
                    }

                    let final_size = temp_file.as_file().metadata()
                        .map_err(|e| CrabCakesError::other(format!("Failed to get file metadata: {}", e)))?
                        .len() as usize;

                    debug!(size = final_size, path = ?temp_file.path(), "Buffered large body to disk");

                    return Ok(BufferedBody::Disk {
                        file: temp_file,
                        size: final_size,
                    });
                } else {
                    buffer.extend_from_slice(data);
                }
            }
        }

        debug!(size = buffer.len(), "Buffered body in memory");
        Ok(BufferedBody::Memory(buffer))
    }

    /// Get the body as a byte vector (reading from disk if necessary)
    pub async fn to_vec(self) -> Result<Vec<u8>, CrabCakesError> {
        match self {
            BufferedBody::Memory(data) => Ok(data),
            BufferedBody::Disk { file, size } => {
                let mut buffer = Vec::with_capacity(size);
                let mut async_file = tokio::fs::File::from_std(file.reopen()
                    .map_err(|e| CrabCakesError::other(format!("Failed to reopen temp file: {}", e)))?);

                async_file.read_to_end(&mut buffer).await
                    .map_err(|e| CrabCakesError::other(format!("Failed to read temp file: {}", e)))?;

                Ok(buffer)
            }
        }
    }

    /// Get the size of the buffered body
    pub fn size(&self) -> usize {
        match self {
            BufferedBody::Memory(data) => data.len(),
            BufferedBody::Disk { size, .. } => *size,
        }
    }

    /// Check if the body is stored on disk
    pub fn is_on_disk(&self) -> bool {
        matches!(self, BufferedBody::Disk { .. })
    }
}