use crate::server::slot_map::BackendSlotId;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_slot, spawn_backend};

pub(super) async fn get_slot_list(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotListRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotListResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            slot_ids: vec![],
        }));
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_slot_list(req.token_present)).await?;

    match result {
        Ok(backend_slots) => {
            let mut slot_ids = Vec::with_capacity(backend_slots.len());
            // W1-C1-06: a per-slot authorization error must not abort the
            // whole listing. Only `TOKEN_NOT_PRESENT` (surfaced as
            // unauthorized by `slot_is_authorized`) and denied slots skip
            // silently; other per-slot errors are collected (first one
            // reported) while the remaining slots are still listed.
            let mut first_error: Option<CkRv> = None;
            for backend_slot in backend_slots {
                let backend_slot = BackendSlotId(backend_slot);
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
                    Ok(false) => continue,
                    Err(error) => {
                        tracing::warn!(
                            slot_id = backend_slot.0.0,
                            rv = error.0,
                            "GetSlotList: skipping slot after authorization error"
                        );
                        first_error.get_or_insert(error);
                        continue;
                    }
                }

                if let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await {
                    slot_ids.push(virtual_slot.0);
                    continue;
                }
                ctx_mgr.register_slot(backend_slot).await;
                if let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await {
                    slot_ids.push(virtual_slot.0);
                }
            }
            let ck_rv = first_error.map_or(CkRv::OK.0, |error| error.0);
            Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse { ck_rv, slot_ids }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
            ck_rv: error.0,
            slot_ids: vec![],
        })),
    }
}

pub(super) async fn get_slot_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                info: None,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_slot_info(backend_slot.0)).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (CkRv::OK.0, Some(pkcs11_proxy_ng_proto::SlotInfo::from(&info))),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse { ck_rv, info }))
}

pub(super) async fn get_token_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetTokenInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetTokenInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                info: None,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_token_info(backend_slot.0)).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (CkRv::OK.0, Some(pkcs11_proxy_ng_proto::TokenInfo::from(&info))),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse { ck_rv, info }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::server::context_manager::ContextManager;
    use pkcs11_proxy_ng_backend::MockBackend;

    fn allow_all_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: true,
            anonymous_principal: None,
            policy: vec![],
        })
        .expect("policy must parse")
    }

    async fn setup_two_slots()
    -> (Arc<ContextManager>, Arc<MockBackend>, Arc<dyn Pkcs11Backend>, ClientContextId) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![]));
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(Some("uid=1000".into())).await.unwrap();
        (ctx_mgr, mock, backend, ctx_id)
    }

    /// W1-C1-06: one failing slot must yield a partial list + its error, not
    /// abort the whole `GetSlotList` with an empty list.
    #[tokio::test]
    async fn get_slot_list_partial_list_on_single_slot_error() {
        let (ctx_mgr, mock, backend, ctx_id) = setup_two_slots().await;
        let policy = allow_all_policy();
        // Serve slot 0's token identity from the authz cache so only slot 1
        // reaches the (failing) backend token-info fetch.
        ctx_mgr.cache_token_info(BackendSlotId(CkSlotId(0)), "MockToken".into(), "0001".into());
        mock.inject_error(CkRv::DEVICE_ERROR);

        let resp = get_slot_list(
            &ctx_mgr,
            &backend,
            &policy,
            Request::new(pkcs11_proxy_ng_proto::GetSlotListRequest {
                client_context_id: ctx_id.0.clone(),
                token_present: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::DEVICE_ERROR.0, "failing slot's error must be reported");
        assert_eq!(resp.slot_ids, vec![1], "healthy slot must still be listed (partial list)");
    }

    /// W1-C1-06 characterization: all-healthy output is unchanged (OK + full list).
    #[tokio::test]
    async fn get_slot_list_all_healthy_unchanged() {
        let (ctx_mgr, _mock, backend, ctx_id) = setup_two_slots().await;
        let policy = allow_all_policy();

        let resp = get_slot_list(
            &ctx_mgr,
            &backend,
            &policy,
            Request::new(pkcs11_proxy_ng_proto::GetSlotListRequest {
                client_context_id: ctx_id.0.clone(),
                token_present: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.slot_ids, vec![1, 2]);
    }
}
