use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::CkAttributeQuery;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::service_utils::{
    ck_rv_only, resolve_session_and_object, spawn_backend, spawn_task,
};
use super::super::{ck_result_to_rv, convert_template};
use super::attribute_results;

fn validate_exact_attribute_results(
    queries: &[CkAttributeQuery],
    results: &[pkcs11_proxy_ng_types::CkAttributeQueryResult],
) -> Result<(), Status> {
    if results.len() != queries.len() {
        return Err(Status::internal(
            "backend returned mismatched GetAttributeValueExact result count",
        ));
    }

    for (query, result) in queries.iter().zip(results.iter()) {
        if result.attr_type != query.attr_type {
            return Err(Status::internal(
                "backend returned misaligned GetAttributeValueExact results",
            ));
        }
    }

    Ok(())
}

pub(super) async fn get_attribute_value(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        };

    let mut template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                ck_rv: error,
                results: vec![],
            }));
        }
    };

    let backend = backend_ref.clone();
    let (result, template) = spawn_task(move || {
        let rv = backend.get_attribute_value(session, object, &mut template);
        (rv, template)
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
        ck_rv: ck_rv_only(result),
        results: attribute_results(&template),
    }))
}

pub(super) async fn get_attribute_value_exact(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueExactResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        };

    let queries = req.queries.iter().map(CkAttributeQuery::from).collect::<Vec<_>>();
    let backend_queries = queries.clone();
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.get_attribute_value_exact(session, object, &backend_queries))
            .await?;

    match result {
        Ok((ck_rv, results)) => {
            validate_exact_attribute_results(&queries, &results)?;
            Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                ck_rv: ck_rv.0,
                results: results
                    .iter()
                    .map(pkcs11_proxy_ng_proto::AttributeQueryResult::from)
                    .collect(),
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
            ck_rv: error.0,
            results: vec![],
        })),
    }
}

pub(super) async fn set_attribute_value(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetAttributeValueResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                    ck_rv: error.0,
                }));
            }
        };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                ck_rv: error,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.set_attribute_value(session, object, &template)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
        ck_rv: ck_rv_only(result),
    }))
}

pub(super) async fn get_object_size(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetObjectSizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetObjectSizeResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
                    ck_rv: error.0,
                    size: 0,
                }));
            }
        };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_object_size(session, object)).await?;
    let (ck_rv, size) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
        ck_rv,
        size: size.unwrap_or(0),
    }))
}

#[cfg(test)]
mod tests {
    use super::validate_exact_attribute_results;
    use pkcs11_proxy_ng_types::{CkAttributeQuery, CkAttributeQueryResult, CkAttributeType};
    use tonic::Code;

    #[test]
    fn exact_result_validation_rejects_result_count_mismatch() {
        let status = validate_exact_attribute_results(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
            &[],
        )
        .expect_err("expected count mismatch");

        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn exact_result_validation_rejects_attr_type_mismatch() {
        let status = validate_exact_attribute_results(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
            &[CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: 0,
                value: None,
                ck_rv: None,
                nested: None,
            }],
        )
        .expect_err("expected attr_type mismatch");

        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn exact_result_validation_accepts_aligned_results() {
        validate_exact_attribute_results(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: 3,
                nested: None,
            }],
            &[CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: Some(b"key".to_vec()),
                ck_rv: None,
                nested: None,
            }],
        )
        .expect("aligned results");
    }
}
