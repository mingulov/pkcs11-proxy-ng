use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{CkAttribute, CkRv};

use super::attr_value_to_bytes;
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;

mod attributes;
mod lifecycle;
mod search;

use crate::server::grpc_service::HandlerContext;

pub(super) async fn find_objects_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsInitResponse>, Status> {
    search::find_objects_init(ctx, request).await
}

pub(super) async fn find_objects(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsResponse>, Status> {
    search::find_objects(ctx, request).await
}

pub(super) async fn find_objects_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsFinalResponse>, Status> {
    search::find_objects_final(ctx, request).await
}

pub(super) async fn get_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueResponse>, Status> {
    attributes::get_attribute_value(ctx, request).await
}

pub(super) async fn get_attribute_value_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueExactResponse>, Status> {
    attributes::get_attribute_value_exact(ctx, request).await
}

pub(super) async fn set_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetAttributeValueResponse>, Status> {
    attributes::set_attribute_value(ctx, request).await
}

pub(super) async fn get_object_size(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetObjectSizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetObjectSizeResponse>, Status> {
    attributes::get_object_size(ctx, request).await
}

/// Wrapper: captures timing + identity, delegates to lifecycle impl, emits a
/// fail-closed `KeyMgmt` audit record.  `C_CreateObject` creates a key or
/// data object — qualifies as key-management activity.
pub(super) async fn create_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CreateObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CreateObjectResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = lifecycle::create_object(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_CreateObject",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            object_handle: 0,
        }));
    }
    Ok(response)
}

/// Wrapper: captures timing + identity, delegates to lifecycle impl, emits a
/// fail-closed `KeyMgmt` audit record.
pub(super) async fn copy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CopyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CopyObjectResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = lifecycle::copy_object(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_CopyObject",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            new_object_handle: 0,
        }));
    }
    Ok(response)
}

/// Wrapper: captures timing + identity, delegates to lifecycle impl, emits a
/// fail-closed `KeyMgmt` audit record.  `C_DestroyObject` is key extraction
/// risk (permanent deletion = auditworthy).
pub(super) async fn destroy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DestroyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DestroyObjectResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = lifecycle::destroy_object(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_DestroyObject",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }
    Ok(response)
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
