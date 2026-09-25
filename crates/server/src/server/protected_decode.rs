//! Pre-decode validation tower layer (ADR-0013 §5/§7, C3M Task 7.2).
//!
//! Wraps the gRPC routes and scans raw request wire bytes with
//! `pkcs11_proxy_ng_proto::protected_decode::validate_request_wire` BEFORE
//! tonic/prost decode, rejecting duplicate-field encodings that would make
//! prost replace (and unwiped-free) a secret allocation. Rejections are
//! trailers-only gRPC errors; the inner service never sees the payload.
//!
//! Only paths of this service are inspected; health checks and any other
//! traffic forward untouched. Bodies are buffered with the daemon's
//! `max_message_bytes` cap enforced DURING collection (never buffering
//! unbounded input), and requests with the gRPC compression flag set are
//! rejected: the daemon never negotiates compression, so a compressed frame
//! is always foreign and cannot be scanned.
//!
//! Threading: the layer is `Clone` and `Send`; each request is validated
//! independently inside its own future.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use pkcs11_proxy_ng_proto::protected_decode::{is_protected_path, validate_request_wire};
use tonic::body::Body;
use tonic::{Code, Status};
use tower_layer::Layer;
use tower_service::Service;

/// gRPC frame header: 1 compression-flag byte + 4 big-endian length bytes.
const FRAME_HEADER_LEN: usize = 5;

/// Boxed tower error, matching the router's error shape.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct ProtectedDecodeLayer {
    max_message_bytes: usize,
}

impl ProtectedDecodeLayer {
    /// `max_message_bytes` mirrors `proxy.max_message_bytes`: payloads above
    /// it are rejected with `ResourceExhausted`, matching tonic's own
    /// `max_decoding_message_size` verdict one layer down.
    pub fn new(max_message_bytes: usize) -> Self {
        Self { max_message_bytes }
    }
}

impl<S> Layer<S> for ProtectedDecodeLayer {
    type Service = ProtectedDecodeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProtectedDecodeService { inner, max_message_bytes: self.max_message_bytes }
    }
}

#[derive(Clone)]
pub struct ProtectedDecodeService<S> {
    inner: S,
    max_message_bytes: usize,
}

impl<S> Service<Request<Body>> for ProtectedDecodeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Non-service traffic (health checks, probes) bypasses validation
        // entirely so tonic's behavior for it is bit-for-bit unchanged.
        if !is_protected_path(req.uri().path()) {
            // W1-C3-18: cloning the inner service for the async block is
            // sufficient; the old replace-then-restore was a net no-op
            // plus a wasted clone.
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await.map_err(Into::into) });
        }

        let max_message_bytes = self.max_message_bytes;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let path = parts.uri.path().to_owned();
            match collect_and_validate(&path, body, max_message_bytes).await {
                Ok(raw) => {
                    let request = Request::from_parts(parts, Body::new(Full::new(raw)));
                    inner.call(request).await.map_err(Into::into)
                }
                Err(status) => {
                    tracing::warn!(
                        method = %path,
                        code = %status.code(),
                        "protected pre-decode validation rejected request"
                    );
                    Ok(reject(status))
                }
            }
        })
    }
}

/// Buffers one unary frame (capped), validates the payload, and returns the
/// intact raw frame bytes for forwarding.
async fn collect_and_validate(
    path: &str,
    body: Body,
    max_message_bytes: usize,
) -> Result<Bytes, Status> {
    // Cap: frame header + the largest acceptable payload. `saturating_add`
    // keeps a pathological configured cap from wrapping the bound.
    let cap = max_message_bytes.saturating_add(FRAME_HEADER_LEN).saturating_add(1);
    let mut body = body;
    let mut raw = Vec::new();
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|_| Status::new(Code::Internal, "request body collection failed"))?
    {
        let Some(data) = frame.data_ref() else {
            continue;
        };
        if raw.len().saturating_add(data.len()) > cap {
            return Err(Status::new(Code::ResourceExhausted, "request exceeds max_message_bytes"));
        }
        raw.extend_from_slice(data);
    }
    if raw.len() < FRAME_HEADER_LEN {
        return Err(Status::new(Code::InvalidArgument, "short gRPC frame"));
    }
    if raw[0] != 0 {
        return Err(Status::new(Code::Unimplemented, "compressed requests are not accepted"));
    }
    let length = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    if length > max_message_bytes {
        return Err(Status::new(Code::ResourceExhausted, "request exceeds max_message_bytes"));
    }
    if raw.len() != FRAME_HEADER_LEN + length {
        return Err(Status::new(Code::InvalidArgument, "malformed gRPC frame"));
    }
    validate_request_wire(path, &raw[FRAME_HEADER_LEN..])
        .map_err(|violation| Status::new(Code::InvalidArgument, violation.to_string()))?;
    Ok(Bytes::from(raw))
}

/// A trailers-only gRPC error: HTTP 200 with `grpc-status`/`grpc-message`
/// headers and an empty body, which tonic clients surface as the `Status`.
fn reject(status: Status) -> Response<Body> {
    let mut response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(Body::empty())
        .expect("static response parts are valid");
    // `add_header` percent-encodes the message; failure would need
    // pathological bytes that encoding already neutralized.
    let _ = status.add_header(response.headers_mut());
    response
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::LoginRequest;
    use prost::Message as _;

    use super::*;

    const LOGIN_PATH: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login";

    fn login_payload() -> Vec<u8> {
        LoginRequest {
            client_context_id: String::from("ctx"),
            session_handle: 7,
            user_type: 1,
            pin: Some(vec![9, 9, 9]),
        }
        .encode_to_vec()
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut raw = vec![0];
        raw.extend(u32::try_from(payload.len()).expect("test payload fits").to_be_bytes());
        raw.extend(payload);
        raw
    }

    fn request(path: &str, raw: Vec<u8>) -> Request<Body> {
        Request::builder()
            .uri(path)
            .body(Body::new(Full::new(Bytes::from(raw))))
            .expect("test request builds")
    }

    #[derive(Clone, Default)]
    struct MockInner {
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Service<Request<Body>> for MockInner {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let seen = self.seen.clone();
            Box::pin(async move {
                let body = req.into_body().collect().await.expect("collect").to_bytes().to_vec();
                seen.lock().expect("mutex").push(body);
                Ok(Response::builder()
                    .status(200)
                    .body(Body::empty())
                    .expect("test response builds"))
            })
        }
    }

    fn service(max: usize) -> (ProtectedDecodeService<MockInner>, MockInner) {
        let inner = MockInner::default();
        (ProtectedDecodeLayer::new(max).layer(inner.clone()), inner)
    }

    fn grpc_status(response: &Response<Body>) -> &str {
        response.headers().get("grpc-status").expect("grpc-status").to_str().expect("ascii")
    }

    #[tokio::test]
    async fn valid_request_forwards_intact_bytes() {
        let (mut service, inner) = service(1024 * 1024);
        let raw = frame(&login_payload());
        let response = service.call(request(LOGIN_PATH, raw.clone())).await.expect("forward");
        assert_eq!(response.status(), 200);
        assert!(response.headers().get("grpc-status").is_none());
        assert_eq!(inner.seen.lock().expect("mutex").as_slice(), &[raw]);
    }

    #[tokio::test]
    async fn duplicate_field_rejected_before_inner() {
        let (mut service, inner) = service(1024 * 1024);
        let mut payload = login_payload();
        payload.extend([0x22, 0x01, 0x08]);
        let response = service.call(request(LOGIN_PATH, frame(&payload))).await.expect("respond");
        assert_eq!(grpc_status(&response), "3");
        assert!(inner.seen.lock().expect("mutex").is_empty(), "inner must never see the payload");
    }

    #[tokio::test]
    async fn unknown_path_bypasses_validation() {
        let (mut service, inner) = service(1024 * 1024);
        // Not even a valid frame: forwarded untouched.
        let response = service
            .call(request("/grpc.health.v1.Health/Check", vec![0xff, 0x1b]))
            .await
            .expect("forward");
        assert!(response.headers().get("grpc-status").is_none());
        assert_eq!(inner.seen.lock().expect("mutex").as_slice(), &[vec![0xff, 0x1b]]);
    }

    #[tokio::test]
    async fn oversize_payload_rejected() {
        let (mut service, inner) = service(8);
        let response =
            service.call(request(LOGIN_PATH, frame(&login_payload()))).await.expect("respond");
        assert_eq!(grpc_status(&response), "8");
        assert!(inner.seen.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn compressed_frame_rejected() {
        let (mut service, inner) = service(1024 * 1024);
        let mut raw = frame(&login_payload());
        raw[0] = 1;
        let response = service.call(request(LOGIN_PATH, raw)).await.expect("respond");
        assert_eq!(grpc_status(&response), "12");
        assert!(inner.seen.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn trailing_bytes_rejected() {
        let (mut service, inner) = service(1024 * 1024);
        let mut raw = frame(&login_payload());
        raw.extend([0x08, 0x01]);
        let response = service.call(request(LOGIN_PATH, raw)).await.expect("respond");
        assert_eq!(grpc_status(&response), "3");
        assert!(inner.seen.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn short_frame_rejected() {
        let (mut service, inner) = service(1024 * 1024);
        let response = service.call(request(LOGIN_PATH, vec![0, 0])).await.expect("respond");
        assert_eq!(grpc_status(&response), "3");
        assert!(inner.seen.lock().expect("mutex").is_empty());
    }
}
