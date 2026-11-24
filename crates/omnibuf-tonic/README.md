# omnibuf-tonic

OmniBuf `tonic::codec::Codec` implementation for Rust gRPC clients and servers.

## Install

```toml
[dependencies]
omnibuf = "0.1"
omnibuf-tonic = "0.1"
tonic = "0.13"
```

## Usage

```rust
use http::uri::PathAndQuery;
use omnibuf_tonic::OmniBufCodec;
use tonic::client::Grpc;
use tonic::transport::Channel;

async fn get_user(channel: Channel, req: GetUserRequest) -> Result<GetUserResponse, tonic::Status> {
    let mut grpc = Grpc::new(channel);
    grpc.ready().await.map_err(|e| tonic::Status::unavailable(e.to_string()))?;

    let codec = OmniBufCodec::<GetUserRequest, GetUserResponse>::new();
    let path = PathAndQuery::from_static("/acme.v1.UserService/GetUser");
    let response = grpc.unary(tonic::Request::new(req), path, codec).await?;
    Ok(response.into_inner())
}
```

Use `OmniBufCodec::self_describing()` to emit Field #0 schema metadata inline, or `.with_decode_options(...)` to customize wire decoding limits.
