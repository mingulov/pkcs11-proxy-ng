//! Common admission for ordinary, authenticated, and exact wrapping adapters.
//! Preparation may read authorization metadata; it never invokes native wrap.
use pkcs11_proxy_ng_types::{CkMechanism, CkObjectHandle, CkResult, CkRv, CkSessionHandle};
use tonic::Status;

use super::super::HandlerContext;
use super::super::authorization::{extract_is_permitted, mechanism_permitted};
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{parse_mechanism, resolve_session_and_two_objects};
use crate::server::context_manager::ClientContextId;

pub(in crate::server::grpc_service) struct PreparedWrap {
    pub session: CkSessionHandle,
    pub wrapping_key: CkObjectHandle,
    pub key: CkObjectHandle,
    pub mechanism: CkMechanism,
}

pub(in crate::server::grpc_service) async fn prepare_wrap(
    ctx: &HandlerContext,
    context_id: &ClientContextId,
    virtual_session: u64,
    virtual_wrapping_key: u64,
    virtual_key: u64,
    mechanism: Option<pkcs11_proxy_ng_proto::Mechanism>,
) -> Result<CkResult<PreparedWrap>, Status> {
    // Preserve ordinary WrapKey precedence. Direct denied/unknown objects are
    // forwarded as zero by the resolver (ADR-0012); embedded denied nonzero
    // handles are rejected by the remapper rather than made optional zeros.
    let (session, wrapping_key, key) = match resolve_session_and_two_objects(
        ctx,
        context_id,
        virtual_session,
        virtual_wrapping_key,
        virtual_key,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => return Ok(Err(rv)),
    };
    let mut mechanism = match parse_mechanism(mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => return Ok(Err(rv)),
    };
    // W1-C1-13: the mechanism gate runs before remap on every init handler
    // so identical dual-defect requests yield the same RV regardless of op.
    if !mechanism_permitted(ctx, context_id, virtual_session, mechanism.mechanism_type).await {
        return Ok(Err(CkRv::MECHANISM_INVALID));
    }
    if let Err(rv) =
        remap_mechanism_handles(ctx, context_id, virtual_session, session.0, &mut mechanism).await
    {
        return Ok(Err(rv));
    }
    if !extract_is_permitted(ctx, context_id, virtual_session, virtual_key).await? {
        return Ok(Err(CkRv::KEY_FUNCTION_NOT_PERMITTED));
    }
    Ok(Ok(PreparedWrap { session, wrapping_key, key, mechanism }))
}
