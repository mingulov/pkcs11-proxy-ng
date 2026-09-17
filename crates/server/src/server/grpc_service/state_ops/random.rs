use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::ck_result_to_rv;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, resolve_session, spawn_backend,
};
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::SecretBytes;

pub(super) async fn generate_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GenerateRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateRandomResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateRandomResponse {
                ck_rv: error.0,
                random_data: vec![],
            }));
        }
    };

    let len = req.length;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.generate_random(session, len)).await?;
    let (ck_rv, random_data) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GenerateRandomResponse {
        ck_rv,
        random_data: secret_to_plain(&random_data.unwrap_or_default()),
    }))
}

pub(super) async fn seed_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::SeedRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SeedRandomResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SeedRandomResponse { ck_rv: error.0 }));
        }
    };

    let seed = SecretBytes::new(req.seed);
    let seed_null_len = req.seed_null_len;
    // ADR-0010 sanitize_inputs: validate NULL seed pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, seed_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SeedRandomResponse { ck_rv: rv.0 }));
    }
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        seed.expose(|raw| backend.seed_random(session, input_from_wire(raw, seed_null_len)))
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SeedRandomResponse { ck_rv: ck_rv_only(result) }))
}
