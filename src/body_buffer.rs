//! Smart request body buffering with AWS chunked encoding support.
//!
//! Buffers HTTP request bodies in memory (up to 50MB) with automatic spillover to disk,
//! and optionally decodes AWS chunked encoding for streaming uploads.

use std::io::SeekFrom;

use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::error::CrabCakesError;
use crabcakes_async_spooled_tempfile::SpooledTempFile;
use tracing::{debug, error};

const MEMORY_THRESHOLD: u64 = 50 * 1024 * 1024; // 50MB

/// Decode AWS chunked encoding format
/// Format: `<hex-chunk-size>\r\n<chunk-data>\r\n...\r\n0\r\n<optional-trailers>\r\n\r\n`
fn decode_aws_chunks(data: &[u8]) -> Result<Vec<u8>, CrabCakesError> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Find the end of the chunk size line (look for \r\n)
        let size_line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| {
                CrabCakesError::Sigv4Verification(
                    "Invalid AWS chunk format: missing \\r\\n after chunk size".into(),
                )
            })?;

        // Parse the chunk size (hex string)
        let size_str = std::str::from_utf8(&data[pos..pos + size_line_end]).map_err(|e| {
            CrabCakesError::Sigv4Verification(format!("Invalid chunk size encoding: {}", e))
        })?;

        let chunk_size = usize::from_str_radix(size_str, 16).map_err(|e| {
            CrabCakesError::Sigv4Verification(format!("Invalid chunk size hex: {}", e))
        })?;

        // Move past the chunk size line
        pos += size_line_end + 2; // +2 for \r\n

        // If chunk size is 0, we've reached the end
        if chunk_size == 0 {
            break;
        }

        // Read the chunk data
        if pos + chunk_size > data.len() {
            return Err(CrabCakesError::Sigv4Verification(
                "Invalid AWS chunk: chunk size exceeds remaining data".to_string(),
            ));
        }

        result.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;

        // Skip the trailing \r\n
        if pos + 2 > data.len() || &data[pos..pos + 2] != b"\r\n" {
            return Err(CrabCakesError::Sigv4Verification(
                "Invalid AWS chunk: missing \\r\\n after chunk data".to_string(),
            ));
        }
        pos += 2;
    }

    Ok(result)
}

/// A buffered request body that can be stored in memory or spilled to disk
pub(crate) struct BufferedBody {
    file: SpooledTempFile,
    size: usize,
}

impl BufferedBody {
    /// Buffer a hyper Incoming body, spilling to disk if it exceeds the threshold
    /// If should_decode_aws_chunks is true, will decode AWS chunked encoding format
    pub async fn from_incoming(
        body: Incoming,
        should_decode_aws_chunks: bool,
    ) -> Result<Self, CrabCakesError> {
        debug!("Bodysize: {:?}", body.size_hint());
        debug!(
            "Starting to buffer body, should_decode_aws_chunks={}",
            should_decode_aws_chunks
        );

        let mut temp_file = SpooledTempFile::new(MEMORY_THRESHOLD);
        let written_bytes;

        // For non-chunked requests, use the simpler collect() API which is more reliable
        // For chunked requests, we need the raw data to decode, so collect that way too
        let collected = body
            .collect()
            .await
            .inspect_err(|e| error!("Body read error: {}, error debug: {:?}", e, e))?;

        let body_bytes = collected.to_bytes();
        debug!("Collected {} bytes from body", body_bytes.len());

        // If we need to decode AWS chunks, do it now
        if should_decode_aws_chunks {
            debug!(
                "Decoding AWS chunked encoding from {} bytes",
                body_bytes.len()
            );
            let decoded = decode_aws_chunks(&body_bytes)?;
            debug!("Decoded {} bytes from AWS chunks", decoded.len());
            temp_file.write_all(&decoded).await.inspect_err(|e| {
                error!("Failed to write decoded data to spooled temp file: {}", e)
            })?;
            written_bytes = decoded.len();
        } else {
            // Write directly to temp file
            temp_file
                .write_all(&body_bytes)
                .await
                .inspect_err(|e| error!("Failed to write to spooled temp file: {}", e))?;
            written_bytes = body_bytes.len();
        }

        debug!("Successfully buffered body, final size: {}", written_bytes);
        Ok(BufferedBody {
            file: temp_file,
            size: written_bytes,
        })
    }

    /// Get the body as a byte vector (reading from disk if necessary)
    /// Note: This method rewinds the file to the start before AND after reading
    /// to allow multiple reads from the same buffer.
    #[allow(clippy::wrong_self_convention)]
    pub async fn to_vec(&mut self) -> Result<Vec<u8>, CrabCakesError> {
        let mut buffer = Vec::with_capacity(self.size);
        self.file
            .seek(SeekFrom::Start(0))
            .await
            .inspect_err(|e| error!("Failed to rewind spooled file: {}", e))?;
        self.file
            .read_to_end(&mut buffer)
            .await
            .inspect_err(|e| error!("Failed to read spooled file: {}", e))?;
        // Rewind again so the buffer can be read multiple times
        self.file
            .seek(SeekFrom::Start(0))
            .await
            .inspect_err(|e| error!("Failed to rewind spooled file after read: {}", e))?;
        Ok(buffer)
    }
}
