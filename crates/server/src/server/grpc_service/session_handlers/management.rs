use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};
use zeroize::Zeroizing;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::VirtualHandle;
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_session, resolve_slot, spawn_backend};

pub(super) async fn init_token(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

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

    // Zeroize SO PIN bytes when the closure drops.
    let so_pin = req.so_pin.map(Zeroizing::new);
    let label_for_log = req.label.clone();
    let label = req.label;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        backend.init_token(backend_slot, so_pin.as_deref().map(Vec::as_slice), &label)
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
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse { ck_rv: error.0 }));
        }
    };

    // Zeroize user PIN on closure drop.
    let pin = req.pin.map(Zeroizing::new);
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.init_pin(session, pin.as_deref().map(Vec::as_slice))).await?;

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
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse { ck_rv: error.0 }));
        }
    };

    // Zeroize both old and new PINs on closure drop.
    let old_pin = req.old_pin.map(Zeroizing::new);
    let new_pin = req.new_pin.map(Zeroizing::new);
    // Pre-hash the new PIN and capture (slot, login state) so the per-slot PIN
    // verifier can be refreshed on success: after a PIN change a co-located
    // logical login with the NEW PIN must be accepted, not fail closed against
    // the old verifier (A1 / ADR-0008).
    let new_pin_hash = ctx_mgr.hash_pin(new_pin.as_deref().map(Vec::as_slice));
    let virtual_session = VirtualHandle(req.session_handle);
    let slot_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.session_slots
                .get(&virtual_session)
                .copied()
                .map(|slot| (slot, ctx.login_state.get(&slot).copied()))
        })
        .await
        .flatten();
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        backend.set_pin(
            session,
            old_pin.as_deref().map(Vec::as_slice),
            new_pin.as_deref().map(Vec::as_slice),
        )
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            if let Some((slot, Some(state))) = slot_state {
                ctx_mgr.store_pin_verifier_hash(slot, state, new_pin_hash);
            }
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
