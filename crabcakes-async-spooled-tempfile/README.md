# crabcakes-async-spooled-tempfile

This'll keep the temporary file in memory until it hits a certain size, then spools to disk for further use. Uses `tokio` to get things done.

PRs and bugs welcome!

## Example

```rust

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
```
