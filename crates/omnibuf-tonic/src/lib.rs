//! OmniBuf `tonic::codec::Codec` implementation for gRPC services (`application/grpc+omnibuf`).

use std::marker::PhantomData;

use bytes::{Buf, BufMut};
use omnibuf::{DecodeOptions, EncodeOptions, Message as OmniBufMessage};
use tonic::Status;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

/// Wire codec subtype for compact OmniBuf gRPC payloads.
pub const CODEC_NAME: &str = "omnibuf";

/// Wire codec subtype for self-describing OmniBuf gRPC payloads carrying `Field #0` inline.
pub const SELF_DESCRIBING_CODEC_NAME: &str = "x-omnibuf";

/// gRPC `Content-Type` header value for compact OmniBuf payloads.
pub const CONTENT_TYPE_GRPC: &str = "application/grpc+omnibuf";

/// A [`tonic::codec::Codec`] that encodes `T` and decodes `U` using OmniBuf wire format.
///
/// Decodes enforce [`DecodeOptions::default_limits()`] unless overridden via
/// [`OmniBufCodec::with_decode_options`].
#[derive(Debug)]
pub struct OmniBufCodec<T, U> {
    encode_options: EncodeOptions,
    decode_options: DecodeOptions,
    _marker: PhantomData<(T, U)>,
}

impl<T, U> Clone for OmniBufCodec<T, U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, U> Copy for OmniBufCodec<T, U> {}

impl<T, U> Default for OmniBufCodec<T, U> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T, U> OmniBufCodec<T, U> {
    /// Creates a compact OmniBuf `tonic` codec (`"omnibuf"`).
    #[inline]
    pub const fn new() -> Self {
        Self {
            encode_options: EncodeOptions {
                deterministic: false,
                self_describing: false,
            },
            decode_options: DecodeOptions::default_limits(),
            _marker: PhantomData,
        }
    }

    /// Creates a self-describing OmniBuf `tonic` codec (`"x-omnibuf"`) that emits
    /// `Field #0` (`SchemaMeta`) inline at byte 0 of each root payload.
    #[inline]
    pub const fn self_describing() -> Self {
        Self {
            encode_options: EncodeOptions::self_describing(),
            decode_options: DecodeOptions::default_limits(),
            _marker: PhantomData,
        }
    }

    /// Enables or disables deterministic map key ordering during encoding.
    #[inline]
    pub const fn deterministic(mut self, deterministic: bool) -> Self {
        self.encode_options.deterministic = deterministic;
        self
    }

    /// Replaces the [`EncodeOptions`] used by this codec.
    #[inline]
    pub const fn with_encode_options(mut self, options: EncodeOptions) -> Self {
        self.encode_options = options;
        self
    }

    /// Replaces the [`DecodeOptions`] resource limits enforced by this codec.
    #[inline]
    pub const fn with_decode_options(mut self, options: DecodeOptions) -> Self {
        self.decode_options = options;
        self
    }

    /// Returns the wire codec subtype (`"omnibuf"` or `"x-omnibuf"`).
    #[inline]
    pub const fn codec_name(&self) -> &'static str {
        if self.encode_options.self_describing {
            SELF_DESCRIBING_CODEC_NAME
        } else {
            CODEC_NAME
        }
    }

    /// Returns the configured [`EncodeOptions`].
    #[inline]
    pub const fn encode_options(&self) -> EncodeOptions {
        self.encode_options
    }

    /// Returns the configured [`DecodeOptions`].
    #[inline]
    pub const fn decode_options(&self) -> DecodeOptions {
        self.decode_options
    }
}

impl<T, U> Codec for OmniBufCodec<T, U>
where
    T: OmniBufMessage + Send + 'static,
    U: OmniBufMessage + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = OmniBufEncoder<T>;
    type Decoder = OmniBufDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        OmniBufEncoder {
            encode_options: self.encode_options,
            _marker: PhantomData,
        }
    }

    fn decoder(&mut self) -> Self::Decoder {
        OmniBufDecoder {
            decode_options: self.decode_options,
            _marker: PhantomData,
        }
    }
}

/// [`tonic::codec::Encoder`] for OmniBuf messages.
#[derive(Debug)]
pub struct OmniBufEncoder<T> {
    encode_options: EncodeOptions,
    _marker: PhantomData<T>,
}

impl<T> Clone for OmniBufEncoder<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OmniBufEncoder<T> {}

impl<T: OmniBufMessage> Encoder for OmniBufEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        let bytes = item
            .encode_omnibuf_with_options(self.encode_options)
            .map_err(|e| Status::internal(format!("omnibuf encode error: {e}")))?;
        dst.put_slice(&bytes);
        Ok(())
    }
}

/// [`tonic::codec::Decoder`] for OmniBuf messages.
#[derive(Debug)]
pub struct OmniBufDecoder<U> {
    decode_options: DecodeOptions,
    _marker: PhantomData<U>,
}

impl<U> Clone for OmniBufDecoder<U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<U> Copy for OmniBufDecoder<U> {}

impl<U: OmniBufMessage> Decoder for OmniBufDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let len = src.remaining();
        let mut buf = vec![0u8; len];
        src.copy_to_slice(&mut buf);
        let msg = omnibuf::from_slice_with_options(&buf, self.decode_options)
            .map_err(|e| Status::internal(format!("omnibuf decode error: {e}")))?;
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http::{Request, Response};
    use omnibuf::{OmniBuf, decode_blind_json};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::body::Body;
    use tonic::server::{NamedService, UnaryService};
    use tonic::transport::{Endpoint, Server};
    use tower::Service;

    use super::*;

    #[derive(Debug, Default, Clone, PartialEq, OmniBuf)]
    #[omnibuf(name = "PingRequest")]
    struct PingRequest {
        #[omnibuf(id = 1, name = "asn")]
        asn: u32,
        #[omnibuf(id = 2, name = "router_id")]
        router_id: String,
        #[omnibuf(id = 3, name = "tags")]
        tags: HashMap<String, String>,
    }

    #[derive(Debug, Default, Clone, PartialEq, OmniBuf)]
    #[omnibuf(name = "PingResponse")]
    struct PingResponse {
        #[omnibuf(id = 1, name = "ok")]
        ok: bool,
        #[omnibuf(id = 2, name = "message")]
        message: String,
        #[omnibuf(id = 3, name = "asn")]
        asn: u32,
    }

    #[derive(Clone, Copy)]
    struct PingUnaryHandler;

    impl UnaryService<PingRequest> for PingUnaryHandler {
        type Response = PingResponse;
        type Future =
            Pin<Box<dyn Future<Output = Result<tonic::Response<Self::Response>, Status>> + Send>>;

        fn call(&mut self, request: tonic::Request<PingRequest>) -> Self::Future {
            let req = request.into_inner();
            Box::pin(async move {
                Ok(tonic::Response::new(PingResponse {
                    ok: true,
                    message: format!("pong:{}", req.router_id),
                    asn: req.asn,
                }))
            })
        }
    }

    #[derive(Clone)]
    struct PingService {
        self_describing: bool,
    }

    impl NamedService for PingService {
        const NAME: &'static str = "omnibuf.test.v1.PingService";
    }

    impl Service<Request<Body>> for PingService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let codec = if self.self_describing {
                OmniBufCodec::<PingResponse, PingRequest>::self_describing()
            } else {
                OmniBufCodec::<PingResponse, PingRequest>::new()
            };
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(codec);
                Ok(grpc.unary(PingUnaryHandler, req).await)
            })
        }
    }

    async fn run_tonic_loopback_round_trip(self_describing: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");
        let incoming = TcpListenerStream::new(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            Server::builder()
                .add_service(PingService { self_describing })
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("tonic server");
        });

        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");

        let mut client = tonic::client::Grpc::new(channel);
        client.ready().await.expect("client ready");

        let codec = if self_describing {
            OmniBufCodec::<PingRequest, PingResponse>::self_describing().deterministic(true)
        } else {
            OmniBufCodec::<PingRequest, PingResponse>::new().deterministic(true)
        };
        let path = http::uri::PathAndQuery::from_static("/omnibuf.test.v1.PingService/Ping");
        let req = tonic::Request::new(PingRequest {
            asn: 64512,
            router_id: "edge-rtr-fra-01".into(),
            tags: HashMap::from([("env".into(), "prod".into())]),
        });

        let res = client
            .unary(req, path, codec)
            .await
            .expect("tonic unary rpc")
            .into_inner();

        assert_eq!(
            res,
            PingResponse {
                ok: true,
                message: "pong:edge-rtr-fra-01".into(),
                asn: 64512,
            }
        );

        let _ = shutdown_tx.send(());
        server_task.await.expect("server join");
    }

    #[test]
    fn constants_and_codec_names() {
        assert_eq!(CODEC_NAME, "omnibuf");
        assert_eq!(SELF_DESCRIBING_CODEC_NAME, "x-omnibuf");
        assert_eq!(CONTENT_TYPE_GRPC, "application/grpc+omnibuf");

        let compact = OmniBufCodec::<PingRequest, PingRequest>::new();
        assert_eq!(compact.codec_name(), CODEC_NAME);

        let sd = OmniBufCodec::<PingRequest, PingRequest>::self_describing();
        assert_eq!(sd.codec_name(), SELF_DESCRIBING_CODEC_NAME);
    }

    #[test]
    fn self_describing_emits_field0() {
        let codec = OmniBufCodec::<PingRequest, PingRequest>::self_describing();
        let msg = PingRequest {
            asn: 65001,
            router_id: "core-nyc-02".into(),
            tags: HashMap::new(),
        };
        let wire = msg
            .encode_omnibuf_with_options(codec.encode_options())
            .expect("encode");
        let json = decode_blind_json(&wire).expect("blind decode");
        assert!(json.contains("\"router_id\":\"core-nyc-02\""));
    }

    #[tokio::test]
    async fn tonic_loopback_unary_compact() {
        run_tonic_loopback_round_trip(false).await;
    }

    #[tokio::test]
    async fn tonic_loopback_unary_self_describing() {
        run_tonic_loopback_round_trip(true).await;
    }
}
