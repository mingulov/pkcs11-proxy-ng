use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_session, resolve_slot, spawn_backend};

pub(super) async fn init_token(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    // W1-C8-11: `InitTokenRequest` is `ZeroizeOnDrop`; take owned fields
    // out with `mem::take` instead of moving them.
    let mut req = request.into_inner();
    let ctx_id = ClientContextId(std::mem::take(&mut req.client_context_id));

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv: error.0 }));
        }
    };
    match authorization::slot_is_authorized(
        ctx_mgr,
        backend_ref,
        token_policy,
        &ctx_id,
        backend_slot,
    )
    .await?
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv: error.0 }));
        }
    }

    // Hold the SO PIN in `SecretBytes` (wiped on drop, redacted in Debug).
    let so_pin = std::mem::take(&mut req.so_pin).map(SecretBytes::new);
    let label_for_log = req.label.clone();
    let label = std::mem::take(&mut req.label);
    let backend = backend_ref.clone();
    let ctx_mgr_task = ctx_mgr.clone();
    let result = spawn_backend(move || {
        let so_pin = so_pin.map(SecretBytes::into_zeroizing);
        let outcome =
            backend.init_token(backend_slot.0, so_pin.as_deref().map(Vec::as_slice), &label);
        // T09: invalidate inside backend-completion ownership — before the
        // result is published — so a successful reinit drops the slot's
        // cached label/serial and advances the authz generation even if the
        // RPC future already timed out or was cancelled. W1-L13-18: the
        // reinit destroys the token's objects, so no cached token-object
        // metadata may survive either. Error returns invalidate nothing:
        // sessions, logins and handles stay intact.
        if outcome.is_ok() {
            ctx_mgr_task.invalidate_token_info_on_reinit(backend_slot);
        }
        outcome
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, label = %label_for_log, "Token initialized");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "InitToken failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv }))
}

pub(super) async fn init_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitPinResponse>, Status> {
    // W1-C8-11: `InitPinRequest` is `ZeroizeOnDrop`; take owned fields out
    // with `mem::take` instead of moving them.
    let mut req = request.into_inner();
    let ctx_id = ClientContextId(std::mem::take(&mut req.client_context_id));

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse { ck_rv: error.0 }));
        }
    };

    // Hold the user PIN in `SecretBytes` (wiped on drop, redacted in Debug).
    let pin = std::mem::take(&mut req.pin).map(SecretBytes::new);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        let pin = pin.map(SecretBytes::into_zeroizing);
        backend.init_pin(session, pin.as_deref().map(Vec::as_slice))
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, "InitPIN succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "InitPIN failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse { ck_rv }))
}

pub(super) async fn set_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetPinResponse>, Status> {
    // W1-C8-11: `SetPinRequest` is `ZeroizeOnDrop`; take owned fields out
    // with `mem::take` instead of moving them.
    let mut req = request.into_inner();
    let ctx_id = ClientContextId(std::mem::take(&mut req.client_context_id));

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse { ck_rv: error.0 }));
        }
    };

    // Hold both PINs in `SecretBytes` (wiped on drop, redacted in Debug).
    let old_pin = std::mem::take(&mut req.old_pin).map(SecretBytes::new);
    let new_pin = std::mem::take(&mut req.new_pin).map(SecretBytes::new);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        let old_pin = old_pin.map(SecretBytes::into_zeroizing);
        let new_pin = new_pin.map(SecretBytes::into_zeroizing);
        backend.set_pin(
            session,
            old_pin.as_deref().map(Vec::as_slice),
            new_pin.as_deref().map(Vec::as_slice),
        )
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, "SetPIN succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "SetPIN failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse { ck_rv }))
}

#[cfg(test)]
mod tests {
    /// The management handlers' PIN holders (SO PIN, user PIN, old/new
    /// PINs) must redact secrets in Debug. Mirrors the holder
    /// constructions in `init_token` / `init_pin` / `set_pin`.
    /// Byte-wise assertion: `Vec<u8>` Debug renders decimal byte values,
    /// never the original text.
    #[test]
    fn pin_holders_debug_redact_secrets() {
        use pkcs11_proxy_ng_types::SecretBytes;
        let so_bytes = b"TopSecretSOPin99";
        let old_bytes = b"OldPin!001";
        let new_bytes = b"NewPin!002";
        let so_pin = Some(SecretBytes::new(so_bytes.to_vec()));
        let old_pin = Some(SecretBytes::new(old_bytes.to_vec()));
        let new_pin = Some(SecretBytes::new(new_bytes.to_vec()));
        let rendered = format!("{so_pin:?} {old_pin:?} {new_pin:?}");
        for byte in so_bytes.iter().chain(old_bytes.iter()).chain(new_bytes.iter()) {
            assert!(
                !rendered.contains(&byte.to_string()),
                "management PIN holder leaks secret byte {byte} via Debug: {rendered}"
            );
        }
    }
}
