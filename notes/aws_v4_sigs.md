# AWS v4 Signatures

- [Authenticating Requests: Using the Authorization Header (AWS Signature Version 4)](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html)

The following is an example of the Authorization header value. Line breaks are added to this example for readability:

```text
Authorization: AWS4-HMAC-SHA256 
Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, 
SignedHeaders=host;range;x-amz-date,
Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
```


For step-by-step instructions to calculate signature and construct the Authorization header value, see Signature Calculations for the Authorization Header: [Transferring Payload in a Single Chunk (AWS Signature Version 4)](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html).
- [Signature Calculations for the Authorization Header: Transferring Payload in Multiple Chunks (Chunked Upload)](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html)