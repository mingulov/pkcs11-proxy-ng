use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkAttribute;

use super::attr_value_to_bytes;

mod attributes;
mod lifecycle;
mod search;

use crate::server::grpc_service::HandlerContext;
pub(super) async fn find_objects_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    search::find_objects_init(ctx_mgr, backend_ref, request).await
}

pub(super) async fn find_objects(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    search::find_objects(ctx_mgr, backend_ref, request).await
}

pub(super) async fn find_objects_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    search::find_objects_final(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    attributes::get_attribute_value(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_attribute_value_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueExactResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    attributes::get_attribute_value_exact(ctx_mgr, backend_ref, request).await
}

pub(super) async fn set_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetAttributeValueResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    attributes::set_attribute_value(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_object_size(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetObjectSizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetObjectSizeResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    attributes::get_object_size(ctx_mgr, backend_ref, request).await
}

pub(super) async fn create_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CreateObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CreateObjectResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::create_object(ctx_mgr, backend_ref, request).await
}

pub(super) async fn copy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CopyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CopyObjectResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::copy_object(ctx_mgr, backend_ref, request).await
}

pub(super) async fn destroy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DestroyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DestroyObjectResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::destroy_object(ctx_mgr, backend_ref, request).await
}

/// Build the proto `AttributeResult` list from an owned template.
///
/// Consumes `template` so the `Vec<u8>` of each `CkAttributeValue::Bytes`
/// is moved straight into the proto `value` field, and the `String` of
/// each `CkAttributeValue::String` is converted via `into_bytes()`
/// without re-allocating. Saves one heap clone per byte/string-typed
/// attribute on the proto-encode path. (Prost still allocates when
/// serializing the wire form; see `FOLLOWUP-proto-bytes` in
/// `crates/proto/build.rs` for the eventual zero-copy work.) Caller is
/// the gRPC handler owning the template returned from the backend;
/// nothing reads it after this call.
fn attribute_results(template: Vec<CkAttribute>) -> Vec<pkcs11_proxy_ng_proto::AttributeResult> {
    template
        .into_iter()
        .map(|attr| {
            let encoded_value = attr.value.map(attr_value_to_bytes);
            let actual_length = encoded_value.as_ref().map_or(0, |value| value.len() as u64);

            pkcs11_proxy_ng_proto::AttributeResult {
                attr_type: attr.attr_type.0,
                result: encoded_value.map(pkcs11_proxy_ng_proto::attribute_result::Result::Value),
                actual_length,
            }
        })
        .collect()
}
