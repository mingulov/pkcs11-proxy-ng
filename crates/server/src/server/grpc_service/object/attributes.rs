use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_proto::version::{
    exact_effects_version_rejected, exact_output_effects_version_supported,
};
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{
    CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkAttributeValue, CkRv, SecretBytes,
    is_value_bearing_secret,
};

use super::super::super::context_manager::{CachedAttr, ClientContextId};
use super::super::HandlerContext;
use super::super::audit_events::emit_auth_event;
use super::super::authorization::extract_is_permitted;
use super::super::service_utils::{
    ExactCompletion, ck_rv_only, resolve_session_and_object, spawn_backend, spawn_backend_exact,
    spawn_task,
};
use super::super::{attr_value_to_bytes, ck_result_to_rv, convert_template, convert_template_opt};
use super::attribute_results;

// ── R2 coalescer helpers ──────────────────────────────────────────────────────

/// Convert a fetched attribute value into a single wiping owner (W1-L13-15,
/// ADR-0013 §5: consume a secret owner instead of cloning). `Bytes`/`String`
/// payloads are adopted by move — no copy; scalar/template shapes encode
/// fresh, byte-identically to [`attr_value_to_bytes`].
fn attr_value_to_secret_bytes(value: CkAttributeValue) -> SecretBytes {
    match value {
        CkAttributeValue::Bytes(secret) | CkAttributeValue::String(secret) => secret,
        scalar => SecretBytes::new(attr_value_to_bytes(scalar)),
    }
}

/// Build a proto `AttributeResult` from a cached attribute entry (R2 coalescer).
///
/// Serves the cached bytes directly — byte-identical to what `attribute_results`
/// produces for a fresh backend fetch, because the bytes were stored as-is from
/// `attr_value_to_bytes` during the previous fetch. Borrows the entry
/// (W1-L13-15) so the hit path copies once, for the wire encoding only.
fn proto_result_from_cache(
    attr_type: CkAttributeType,
    cached: &CachedAttr,
) -> pkcs11_proxy_ng_proto::AttributeResult {
    let actual_length = cached.value.len() as u64;
    // ADR-0013 §5: the prost response owns a plain `Vec<u8>`; the cached
    // `SecretBytes` is borrowed for the copy and wiped when `cached` drops.
    let value = secret_to_plain(&cached.value);
    pkcs11_proxy_ng_proto::AttributeResult {
        attr_type: attr_type.0,
        result: Some(pkcs11_proxy_ng_proto::attribute_result::Result::Value(value)),
        actual_length,
    }
}

/// Reconstruct an exact-path query result from a cached attribute entry (R2).
///
/// Mirrors the backend's buffer semantics byte-for-byte on LP64 platforms:
/// - size query (`!buffer_present`): returns the cached length, no value.
/// - data query with small buffer: returns `CKR_BUFFER_TOO_SMALL`.
/// - data query with adequate buffer: returns the cached value bytes.
///
/// On cross-ABI (ILP32) backends the `CK_ULONG` encoding differs from
/// `attr_value_to_bytes` output; those tests should not use the coalescer
/// for `Ulong` attributes.
fn exact_result_from_cache(
    query: &CkAttributeQuery,
    cached: &CachedAttr,
) -> CkAttributeQueryResult {
    let value_len = cached.value.len() as u64;
    if !query.buffer_present {
        CkAttributeQueryResult {
            apply_returned_len: true,
            apply_type: false,
            attr_type: query.attr_type,
            returned_len: value_len,
            value: None,
            ck_rv: None,
            nested: None,
        }
    } else if query.buffer_len < value_len {
        CkAttributeQueryResult {
            apply_returned_len: true,
            apply_type: false,
            attr_type: query.attr_type,
            returned_len: u64::MAX,
            value: None,
            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
            nested: None,
        }
    } else {
        CkAttributeQueryResult {
            apply_returned_len: true,
            apply_type: false,
            attr_type: query.attr_type,
            returned_len: value_len,
            value: Some(cached.value.clone()),
            ck_rv: None,
            nested: None,
        }
    }
}

/// Merge two exact-path overall `CK_RV` values in native call order (W1-L3-10).
///
/// A native single call ranks multi-attribute failures by a priority ladder,
/// not by template position and not by 336-dominance: SoftHSM 2.6.1 answers
/// SENSITIVE over INVALID over BUFFER_TOO_SMALL in BOTH template orders
/// (full 2x2x2 mixed-error matrix; probe evidence recorded in the Task 29
/// campaign report). Template-position first-error would diverge from
/// observed native ([336-first, INVALID-second] is INVALID natively), so the
/// merge implements the ladder. Call-aborting failures (device/session
/// class — anything outside the per-attribute ladder and OK) outrank every
/// per-attribute classification: a native call that hits one answers it,
/// never a per-attribute outcome.
///
/// Tie-break (T29 M4): two distinct call-aborting RVs share the top rank,
/// so the FIRST argument wins. At the call site the first argument is the
/// cache side, hence cache-abort beats backend-abort. Harmless: both sides
/// are hard errors, so either choice fails the call loudly.
fn merge_exact_rv(a: CkRv, b: CkRv) -> CkRv {
    fn rank(rv: CkRv) -> u8 {
        if rv == CkRv::OK {
            0
        } else if rv == CkRv::BUFFER_TOO_SMALL {
            1
        } else if rv == CkRv::ATTRIBUTE_TYPE_INVALID {
            2
        } else if rv == CkRv::ATTRIBUTE_SENSITIVE {
            3
        } else {
            4
        }
    }
    if rank(b) > rank(a) { b } else { a }
}

// ── Per-attr RV contribution from a reconstructed exact result ────────────────

/// Extract the rv contribution from a reconstructed exact result.
/// Returns `None` for success, `Some(rv)` for any per-attr error.
fn exact_result_rv(r: &CkAttributeQueryResult) -> CkRv {
    r.ck_rv.unwrap_or(CkRv::OK)
}

// ── validate_exact_attribute_results ─────────────────────────────────────────

fn validate_exact_attribute_results(
    query_types: &[CkAttributeType],
    results: &[CkAttributeQueryResult],
) -> Result<(), Status> {
    if results.len() != query_types.len() {
        return Err(Status::internal(
            "backend returned mismatched GetAttributeValueExact result count",
        ));
    }

    for (&query_type, result) in query_types.iter().zip(results.iter()) {
        if result.attr_type != query_type {
            return Err(Status::internal(
                "backend returned misaligned GetAttributeValueExact results",
            ));
        }
    }

    Ok(())
}

// ── get_attribute_value ───────────────────────────────────────────────────────

pub(super) async fn get_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueResponse>, Status> {
    let started = Instant::now();
    crate::server::resilience::record_get_attribute_value();
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let object_handle = req.object_handle;

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, object_handle).await {
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

    // Extract-deny gate (G2-PR2): if any queried attribute is value-bearing-
    // secret AND the principal's grant denies extraction, return
    // KEY_FUNCTION_NOT_PERMITTED without calling the backend. Public attributes
    // such as CKA_MODULUS are unaffected (is_value_bearing_secret returns false
    // for them). Unauthenticated / no-policy / no-extract-deny → passes through.
    // I3: emit a KeyMgmt audit record for the denial so monitoring can detect
    // extraction attempts; do NOT audit the allowed path (data-plane volume).
    let has_secret_attr = template.iter().any(|attr| is_value_bearing_secret(attr.attr_type));
    if has_secret_attr
        && !extract_is_permitted(ctx, &ctx_id, req.session_handle, object_handle).await?
    {
        if emit_auth_event(
            ctx,
            &ctx_id,
            "C_GetAttributeValue",
            EventClass::KeyMgmt,
            None,
            Some(req.session_handle),
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            started,
        )
        .is_err()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                ck_rv: CkRv::FUNCTION_FAILED.0,
                results: vec![],
            }));
        }
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            results: vec![],
        }));
    }

    // Off-path: coalescer disabled → pass through unchanged (byte-identical to
    // today; no cache lookup, no cache put).
    if !crate::server::resilience::coalesce_enabled() {
        let backend = ctx.backend.clone();
        let (result, template) = spawn_task(move || {
            let rv = backend.get_attribute_value(session, object, &mut template);
            (rv, template)
        })
        .await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
            ck_rv: ck_rv_only(result),
            results: attribute_results(template),
        }));
    }

    // Coalesce path: partition the template into cached vs. to-fetch.
    //
    // Security invariant: this path is reached AFTER the extract-deny gate and
    // object resolution. A denied object never touches the cache; the cache is
    // a pure performance layer under authz.
    let original_len = template.len();
    let mut ordered_results: Vec<Option<pkcs11_proxy_ng_proto::AttributeResult>> =
        vec![None; original_len];
    let mut fetch_positions: Vec<usize> = Vec::new();
    let mut fetch_template = Vec::new();

    for (i, attr) in template.iter().enumerate() {
        if !is_value_bearing_secret(attr.attr_type) {
            // W1-L13-15: build the response from a borrowed entry — the hit
            // path copies once, for the wire encoding only.
            let hit = ctx
                .context_manager
                .attr_cache_get_with(&ctx_id, object_handle, attr.attr_type, |cached| {
                    proto_result_from_cache(attr.attr_type, cached)
                })
                .await;
            if let Some(result) = hit {
                crate::server::resilience::record_attr_coalesce_hit();
                ordered_results[i] = Some(result);
                continue;
            }
            crate::server::resilience::record_attr_coalesce_miss();
        }
        fetch_positions.push(i);
        fetch_template.push(attr.clone());
    }

    // Skip the backend only when a non-empty template was fully served from
    // cache. An empty template must always reach the backend — PKCS#11
    // applications use `C_GetAttributeValue` with no attributes as a probe for
    // session/object handle validity; bypassing the backend would return OK for
    // an invalid or foreign object handle, breaking the isolation invariant.
    let overall_ck_rv = if fetch_template.is_empty() && original_len > 0 {
        // Every attribute in a non-empty template is a cache hit.
        CkRv::OK.0
    } else {
        let backend = ctx.backend.clone();
        let (result, fetched_template) = spawn_task(move || {
            let rv = backend.get_attribute_value(session, object, &mut fetch_template);
            (rv, fetch_template)
        })
        .await?;
        let rv = ck_rv_only(result);

        // Populate per-position results and store cacheable entries.
        for (fetched_attr, &orig_i) in fetched_template.into_iter().zip(fetch_positions.iter()) {
            // W1-L13-15: single-owner the bytes per ADR-0013 §5 — adopt the
            // fetched value into one wiping owner by move (no copy for
            // Bytes/String payloads), copy once for the prost wire boundary,
            // and move the owner into the cache put below.
            let secret_value = fetched_attr.value.map(attr_value_to_secret_bytes);
            let actual_length = secret_value.as_ref().map_or(0, |b| b.len() as u64);
            // ADR-0013 §5: the prost response owns a plain `Vec<u8>`; the
            // single permitted copy happens here, at the wire boundary.
            let plain_value = secret_value.as_ref().map(secret_to_plain);

            // Cache non-secret attrs whose value was successfully returned
            // (per-attr rv = OK, implied by value_bytes = Some).
            // NEVER cache: (a) value-bearing-secret attrs, (b) attrs with no value
            //              (sensitive-denial or invalid-type — we can't tell which, so skip).
            //
            // M1 encoding note: this non-exact path encodes values via
            // `attr_value_to_bytes` (e.g. CK_ULONG → 8-byte native-order on LP64),
            // while the exact path (get_attribute_value_exact) stores raw backend
            // bytes (4-byte on an ILP32 backend). Both use the SAME attr_cache key
            // space.  The two encodings are identical on LP64 (native platform) —
            // native order on both sides keeps them identical on big-endian LP64
            // too — and diverge only on a cross-ABI ILP32 backend, which the shim
            // does not use (the shim reaches the exact RPC exclusively).  This is
            // therefore safe today and on all planned platforms.  If a non-LP64
            // backend is ever added, the non-exact path must be excluded from cache
            // reads/writes to avoid serving an LP64-encoded value in response to
            // an exact (raw-byte) query.
            if !is_value_bearing_secret(fetched_attr.attr_type)
                && let Some(secret) = secret_value
            {
                ctx.context_manager
                    .attr_cache_put(
                        &ctx_id,
                        object_handle,
                        fetched_attr.attr_type,
                        // W1-L13-15: the wiping owner moves in — no cache-put clone.
                        CachedAttr { value: secret, ck_rv: CkRv::OK.0 },
                    )
                    .await;
            }

            ordered_results[orig_i] = Some(pkcs11_proxy_ng_proto::AttributeResult {
                attr_type: fetched_attr.attr_type.0,
                result: plain_value.map(pkcs11_proxy_ng_proto::attribute_result::Result::Value),
                actual_length,
            });
        }
        rv
    };

    // Safety: every slot was filled by either the cache or the backend path.
    let results = ordered_results.into_iter().map(Option::unwrap).collect();

    Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
        ck_rv: overall_ck_rv,
        results,
    }))
}

// ── get_attribute_value_exact ─────────────────────────────────────────────────

pub(super) async fn get_attribute_value_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueExactResponse>, Status> {
    let started = Instant::now();
    crate::server::resilience::record_get_attribute_value();
    let req = request.into_inner();
    // W1-L5-04: compatibility-range gate, never an equality literal.
    if !exact_output_effects_version_supported(req.exact_output_effects_version) {
        return Err(exact_effects_version_rejected(req.exact_output_effects_version));
    }
    let ctx_id = ClientContextId(req.client_context_id);
    let object_handle = req.object_handle;

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, object_handle).await {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    exact_output_effects_version: 1,
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        };

    let queries = req.queries.iter().map(CkAttributeQuery::from).collect::<Vec<_>>();
    // Keep only the (Copy) attribute types for post-call alignment validation,
    // then move the full query vector into the backend call — avoids cloning the
    // whole query vector on this hot read path (M8).
    let query_types: Vec<CkAttributeType> = queries.iter().map(|q| q.attr_type).collect();

    // Extract-deny gate (G2-PR2): same semantics as get_attribute_value above.
    // I3: emit a KeyMgmt audit record for the denial; do NOT audit the allowed
    // path (data-plane volume). No secret/attribute values in the record.
    let has_secret_attr = query_types.iter().any(|&t| is_value_bearing_secret(t));
    if has_secret_attr
        && !extract_is_permitted(ctx, &ctx_id, req.session_handle, object_handle).await?
    {
        if emit_auth_event(
            ctx,
            &ctx_id,
            "C_GetAttributeValueExact",
            EventClass::KeyMgmt,
            None,
            Some(req.session_handle),
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            started,
        )
        .is_err()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                exact_output_effects_version: 1,
                ck_rv: CkRv::FUNCTION_FAILED.0,
                results: vec![],
            }));
        }
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
            exact_output_effects_version: 1,
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            results: vec![],
        }));
    }

    // Off-path: coalescer disabled → pass through unchanged.
    if !crate::server::resilience::coalesce_enabled() {
        let backend = ctx.backend.clone();
        let result = spawn_backend_exact(move || {
            ExactCompletion::capture(backend.get_attribute_value_exact(session, object, &queries))
        })
        .await?;
        return match result {
            Ok((ck_rv, results)) => {
                validate_exact_attribute_results(&query_types, &results)?;
                Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    exact_output_effects_version: 1,
                    ck_rv: ck_rv.0,
                    results: results
                        .into_iter()
                        .map(pkcs11_proxy_ng_proto::AttributeQueryResult::from)
                        .collect(),
                }))
            }
            Err(error) => {
                Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    exact_output_effects_version: 1,
                    ck_rv: error.0,
                    results: vec![],
                }))
            }
        };
    }

    // Coalesce path: partition queries into cached vs. to-fetch.
    //
    // Security invariant: same as get_attribute_value — cache is under authz/gate.
    let n = queries.len();
    let mut ordered_results: Vec<Option<CkAttributeQueryResult>> = vec![None; n];
    let mut fetch_positions: Vec<usize> = Vec::new();
    let mut fetch_queries: Vec<CkAttributeQuery> = Vec::new();
    let mut cache_overall_rv = CkRv::OK;

    for (i, query) in queries.iter().enumerate() {
        if !is_value_bearing_secret(query.attr_type) {
            // W1-L13-15: build the result from a borrowed entry instead of
            // cloning it out of the map (the `value` clone inside
            // `exact_result_from_cache` is inherent — the cache retains
            // ownership while the response takes its own owner).
            let hit = ctx
                .context_manager
                .attr_cache_get_with(&ctx_id, object_handle, query.attr_type, |cached| {
                    exact_result_from_cache(query, cached)
                })
                .await;
            if let Some(result) = hit {
                crate::server::resilience::record_attr_coalesce_hit();
                cache_overall_rv = merge_exact_rv(cache_overall_rv, exact_result_rv(&result));
                ordered_results[i] = Some(result);
                continue;
            }
            crate::server::resilience::record_attr_coalesce_miss();
        }
        fetch_positions.push(i);
        fetch_queries.push(query.clone());
    }

    // Skip the backend only when a non-empty query list was fully served from
    // cache — same rationale as get_attribute_value (empty-template probe).
    let combined_rv = if fetch_queries.is_empty() && n > 0 {
        // Every query in a non-empty list is a cache hit.
        cache_overall_rv
    } else {
        let fetch_query_types: Vec<CkAttributeType> =
            fetch_queries.iter().map(|q| q.attr_type).collect();
        let backend = ctx.backend.clone();
        let result = spawn_backend_exact(move || {
            ExactCompletion::capture(backend.get_attribute_value_exact(
                session,
                object,
                &fetch_queries,
            ))
        })
        .await?;

        match result {
            Ok((backend_rv, fetched_results)) => {
                validate_exact_attribute_results(&fetch_query_types, &fetched_results)?;

                // Populate per-position results and store cacheable entries.
                for (fetched_result, &orig_i) in
                    fetched_results.into_iter().zip(fetch_positions.iter())
                {
                    // Cache non-secret attrs with a successful data result
                    // (ck_rv = None AND value = Some means the backend returned bytes).
                    // Do NOT cache: size-only results (value = None with ck_rv = None),
                    // sensitive, invalid-type, or buffer-too-small results.
                    //
                    // M1 encoding note: this exact path stores raw backend bytes (e.g.
                    // CK_ULONG → 4-byte on ILP32). The non-exact path (get_attribute_value)
                    // uses `attr_value_to_bytes` (8-byte native-order on LP64). The two
                    // encodings are identical on LP64 (current and planned platform,
                    // either byte order) and share the same attr_cache key space — safe
                    // today (see full note at the non-exact put site above).
                    if !is_value_bearing_secret(fetched_result.attr_type)
                        && fetched_result.ck_rv.is_none()
                        && let Some(bytes) = &fetched_result.value
                    {
                        ctx.context_manager
                            .attr_cache_put(
                                &ctx_id,
                                object_handle,
                                fetched_result.attr_type,
                                CachedAttr { value: bytes.clone(), ck_rv: CkRv::OK.0 },
                            )
                            .await;
                    }

                    ordered_results[orig_i] = Some(fetched_result);
                }

                merge_exact_rv(cache_overall_rv, backend_rv)
            }
            Err(error) => {
                // Transport-level error for the fetched subset. Return the error
                // for the whole request (cannot assemble a partial response with
                // some attrs still missing). Cache hits from this request are
                // discarded — the caller will retry from scratch.
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    exact_output_effects_version: 1,
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        }
    };

    // Safety: every slot was filled by either the cache or the backend path.
    let results = ordered_results
        .into_iter()
        .map(|r| pkcs11_proxy_ng_proto::AttributeQueryResult::from(r.unwrap()))
        .collect();

    Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
        exact_output_effects_version: 1,
        ck_rv: combined_rv.0,
        results,
    }))
}

// ── set_attribute_value ───────────────────────────────────────────────────────

pub(super) async fn set_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetAttributeValueResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let object_handle = req.object_handle;

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, object_handle).await {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                    ck_rv: error.0,
                }));
            }
        };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                ck_rv: error,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.set_attribute_value(session, object, template.as_deref()))
            .await?;
    let ck_rv = ck_rv_only(result);

    // On a successful set, drop all cached attribute entries for this object so
    // the next read fetches the updated values (R2 coalescer invalidation).
    if crate::server::resilience::coalesce_enabled() && ck_rv == CkRv::OK.0 {
        ctx.context_manager.attr_cache_invalidate_object(&ctx_id, object_handle).await;
    }

    Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse { ck_rv }))
}

// ── get_object_size ───────────────────────────────────────────────────────────

pub(super) async fn get_object_size(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetObjectSizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetObjectSizeResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
                    ck_rv: error.0,
                    size: 0,
                }));
            }
        };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.get_object_size(session, object)).await?;
    let (ck_rv, size) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
        ck_rv,
        size: size.unwrap_or(0),
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use super::super::attr_value_to_bytes;
    use super::validate_exact_attribute_results;
    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::{BackendHandle, VirtualHandle};
    use tonic::Code;

    // --- existing alignment tests ---

    #[test]
    fn exact_result_validation_rejects_result_count_mismatch() {
        let status = validate_exact_attribute_results(&[CkAttributeType::LABEL], &[])
            .expect_err("expected count mismatch");

        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn exact_result_validation_rejects_attr_type_mismatch() {
        let status = validate_exact_attribute_results(
            &[CkAttributeType::LABEL],
            &[CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
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
            &[CkAttributeType::LABEL],
            &[CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: Some(b"key".to_vec().into()),
                ck_rv: None,
                nested: None,
            }],
        )
        .expect("aligned results");
    }

    // --- extract-deny gate tests ---

    const MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

    fn deny_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: MTLS_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Deny,
                    objects: None,
                })]),
            }],
        })
        .unwrap()
    }

    fn allow_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: MTLS_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:MockToken".into())]),
            }],
        })
        .unwrap()
    }

    /// Build a test HandlerContext with a given policy and a session registered
    /// on slot 0, with token info pre-cached. Returns `(ctx, ctx_id, session_handle)`.
    async fn setup(
        policy: TokenPolicy,
        identity: Option<String>,
    ) -> (HandlerContext, ClientContextId, u64) {
        setup_with_mock(
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS])),
            policy,
            identity,
        )
        .await
    }

    async fn setup_with_mock(
        mock: Arc<MockBackend>,
        policy: TokenPolicy,
        identity: Option<String>,
    ) -> (HandlerContext, ClientContextId, u64) {
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, ctx_id, session_vh.0)
    }

    #[tokio::test]
    async fn get_attribute_value_denies_secret_attr_when_extract_denied() {
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                // CKA_VALUE is a secret attribute.
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::VALUE.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "querying CKA_VALUE with extract=Deny must return KEY_FUNCTION_NOT_PERMITTED"
        );
    }

    #[tokio::test]
    async fn get_attribute_value_allows_public_attr_when_extract_denied() {
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                // CKA_MODULUS is a public attribute — not value-bearing-secret.
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::MODULUS.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        // The backend (MockBackend) will handle the call. It may return any
        // CK_RV, but it must NOT be KEY_FUNCTION_NOT_PERMITTED — that would
        // mean the gate incorrectly blocked a public attribute.
        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "querying CKA_MODULUS with extract=Deny must reach the backend unchanged"
        );
    }

    #[tokio::test]
    async fn get_attribute_value_allows_secret_attr_when_extract_allowed() {
        let (ctx, ctx_id, session_handle) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::VALUE.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "CKA_VALUE query with extract=Allow must reach the backend unchanged"
        );
    }

    // --- R2 coalescer tests ---

    /// Enable the coalescer for all coalesce-ON tests. W1-C2-11: holds the
    /// resilience serial guard for the whole test so a concurrent config
    /// reset cannot flip the flag mid-test; first call wins as before.
    async fn enable_coalesce() -> tokio::sync::MutexGuard<'static, ()> {
        let guard = crate::server::resilience::CONFIG_TEST_GUARD.lock().await;
        crate::server::resilience::configure(None, true);
        guard
    }

    /// Build a MockBackend with CKA_ID and CKA_LABEL registered for object 1,
    /// with a real backend session (handle 1) and object (handle 1) so that
    /// `get_attribute_value_impl` passes its session/object validity checks.
    fn mock_with_attrs() -> Arc<MockBackend> {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        // Create backend session 1 and object 1 in the mock's live state.
        // `open_session_impl` doesn't require initialize(); session handle starts at 1.
        let session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        mock.create_object(session, Some(&[])).unwrap(); // CkObjectHandle(1)

        mock.set_attribute(
            CkObjectHandle(1),
            CkAttributeType::ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(b"my-id".to_vec().into())),
        );
        mock.set_attribute(
            CkObjectHandle(1),
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("my-label".to_owned().into())),
        );
        // CKA_VALUE is registered as secret (VALUE_BEARING_SECRET); no need to
        // set it — the backend will return no value for unregistered attrs by default.
        // We add a Sensitive slot so CKR_ATTRIBUTE_SENSITIVE is explicit.
        mock.set_attribute(
            CkObjectHandle(1),
            CkAttributeType::SENSITIVE,
            MockAttributeSlot::Sensitive,
        );
        mock
    }

    #[tokio::test]
    async fn coalesce_on_second_read_of_cacheable_attr_is_a_cache_hit() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;

        // Object handle 1 was registered in the backend; use virtual handle 0
        // (MockBackend ignores session for object existence checks and uses
        // the handle directly). Resolve virtual→backend by registering it in
        // the context manager.
        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1)); // virtual = 1
                // D6(1) fixture provisioning: the mock object carries no
                // CKA_PRIVATE (public by default), mirroring what mint
                // registration records, so USE needs no backend probe.
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;
        let object_handle = 1u64; // virtual handle

        let make_request = || pkcs11_proxy_ng_proto::GetAttributeValueRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            template: vec![pkcs11_proxy_ng_proto::Attribute {
                attr_type: CkAttributeType::ID.0,
                value: None,
            }],
        };

        // First read — cache miss, backend called.
        let resp1 = super::get_attribute_value(&ctx, Request::new(make_request()))
            .await
            .unwrap()
            .into_inner();
        let count_after_first = mock.attr_get_call_count();
        assert_eq!(count_after_first, 1, "first read must call the backend");
        assert_eq!(resp1.ck_rv, CkRv::OK.0, "first read must succeed");

        // Second read — cache hit, backend must NOT be called again.
        let resp2 = super::get_attribute_value(&ctx, Request::new(make_request()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            mock.attr_get_call_count(),
            count_after_first,
            "second read of a cached attr must not call the backend"
        );
        assert_eq!(resp2.ck_rv, CkRv::OK.0, "second read must succeed");

        // Byte-identical: same result as the first read.
        assert_eq!(
            resp1.results, resp2.results,
            "cached read must be byte-identical to fresh read"
        );
    }

    #[tokio::test]
    async fn coalesce_on_mixed_template_fetches_only_uncached_attrs() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;

        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1));
                // D6(1) fixture provisioning: the mock object carries no
                // CKA_PRIVATE (public by default), mirroring what mint
                // registration records, so USE needs no backend probe.
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;
        let object_handle = 1u64;

        // Warm the cache for CKA_ID.
        let _ = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::ID.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();
        let count_after_warm = mock.attr_get_call_count();

        // Request [CKA_ID (cached), CKA_LABEL (not yet cached)] in that order.
        let mixed_resp = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                template: vec![
                    pkcs11_proxy_ng_proto::Attribute {
                        attr_type: CkAttributeType::ID.0,
                        value: None,
                    },
                    pkcs11_proxy_ng_proto::Attribute {
                        attr_type: CkAttributeType::LABEL.0,
                        value: None,
                    },
                ],
            }),
        )
        .await
        .unwrap()
        .into_inner();

        // Backend called exactly once more (only CKA_LABEL was fetched).
        assert_eq!(
            mock.attr_get_call_count(),
            count_after_warm + 1,
            "mixed template should call the backend once (for CKA_LABEL only)"
        );
        assert_eq!(mixed_resp.ck_rv, CkRv::OK.0);
        assert_eq!(mixed_resp.results.len(), 2, "must have results for both attrs");

        // Result at position 0 must be CKA_ID (cached).
        assert_eq!(mixed_resp.results[0].attr_type, CkAttributeType::ID.0);
        // Result at position 1 must be CKA_LABEL (freshly fetched).
        assert_eq!(mixed_resp.results[1].attr_type, CkAttributeType::LABEL.0);
        // Byte-identical for the individual attrs is covered by the single-attr test above.
    }

    #[tokio::test]
    async fn coalesce_on_value_bearing_secret_never_cached() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        // Don't register CKA_VALUE — MockBackend returns no-op (Ok, value stays None)
        // for unregistered attrs; the backend IS reached each time.
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;

        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1));
                // D6(1) fixture provisioning: the mock object carries no
                // CKA_PRIVATE (public by default), mirroring what mint
                // registration records, so USE needs no backend probe.
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;

        let make_req = || pkcs11_proxy_ng_proto::GetAttributeValueRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle: 1,
            template: vec![pkcs11_proxy_ng_proto::Attribute {
                attr_type: CkAttributeType::VALUE.0,
                value: None,
            }],
        };

        super::get_attribute_value(&ctx, Request::new(make_req())).await.unwrap();
        let after_first = mock.attr_get_call_count();
        super::get_attribute_value(&ctx, Request::new(make_req())).await.unwrap();
        assert_eq!(
            mock.attr_get_call_count(),
            after_first + 1,
            "CKA_VALUE (value-bearing-secret) must never be cached; backend called on every read"
        );
    }

    #[tokio::test]
    async fn coalesce_on_sensitive_result_not_cached() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;

        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1));
                // D6(1) fixture provisioning: the mock object carries no
                // CKA_PRIVATE (public by default), mirroring what mint
                // registration records, so USE needs no backend probe.
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;

        // CKA_SENSITIVE is registered as MockAttributeSlot::Sensitive — backend
        // returns CKR_ATTRIBUTE_SENSITIVE. Must not be cached.
        let make_req = || pkcs11_proxy_ng_proto::GetAttributeValueRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle: 1,
            template: vec![pkcs11_proxy_ng_proto::Attribute {
                attr_type: CkAttributeType::SENSITIVE.0,
                value: None,
            }],
        };

        super::get_attribute_value(&ctx, Request::new(make_req())).await.unwrap();
        let after_first = mock.attr_get_call_count();
        super::get_attribute_value(&ctx, Request::new(make_req())).await.unwrap();
        assert_eq!(
            mock.attr_get_call_count(),
            after_first + 1,
            "CKR_ATTRIBUTE_SENSITIVE result must not be cached; backend called on every read"
        );
    }

    #[tokio::test]
    async fn coalesce_on_set_invalidates_cache() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;

        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1));
                // D6(1) fixture provisioning: the mock object carries no
                // CKA_PRIVATE (public by default), mirroring what mint
                // registration records, so USE needs no backend probe.
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;
        let object_handle = 1u64;

        // Warm the cache with CKA_ID.
        super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::ID.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();
        let after_first_read = mock.attr_get_call_count();

        // Perform a successful set_attribute_value — should invalidate the cache.
        let set_rv = super::set_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::SetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::LABEL.0,
                    value: None,
                }],

                template_null: false,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(set_rv, CkRv::OK.0, "set_attribute_value must succeed");

        // Next read of CKA_ID must go to the backend (cache invalidated).
        super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::ID.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            mock.attr_get_call_count(),
            after_first_read + 1,
            "after set_attribute_value, next read must re-fetch (cache was invalidated)"
        );
    }

    #[tokio::test]
    async fn exact_path_cache_served_result_is_byte_identical_to_fresh() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                c.object_handles.insert(BackendHandle(1));
            })
            .await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(allow_policy());

        let session_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.session_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();
        let object_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.object_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();

        let make_req = || pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![pkcs11_proxy_ng_proto::AttributeQuery {
                attr_type: CkAttributeType::ID.0,
                buffer_present: true,
                buffer_len: 64,
                nested: None,
            }],
        };

        // First call — cache miss, backend reached.
        let fresh = super::get_attribute_value_exact(&ctx, Request::new(make_req()))
            .await
            .unwrap()
            .into_inner();
        let after_first = mock.attr_get_exact_call_count();
        assert_eq!(after_first, 1, "exact: first read must reach the backend");

        // Second call — cache hit, backend NOT reached.
        let cached_resp = super::get_attribute_value_exact(&ctx, Request::new(make_req()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            mock.attr_get_exact_call_count(),
            after_first,
            "exact: second read must NOT reach the backend (cache hit)"
        );

        // Byte-identical: same ck_rv and same per-attr results.
        assert_eq!(fresh.ck_rv, cached_resp.ck_rv, "exact: ck_rv must be identical");
        assert_eq!(
            fresh.results, cached_resp.results,
            "exact: per-attr results must be byte-identical to fresh fetch"
        );
    }

    /// M3(a): exact-path SIZE-QUERY hit — when the cache holds a data result,
    /// a subsequent size query (buffer_present=false) must be served from cache
    /// and its returned_len must equal a fresh size query's returned_len.
    #[tokio::test]
    async fn exact_path_size_query_cache_hit_is_byte_identical_to_fresh() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                c.object_handles.insert(BackendHandle(1));
            })
            .await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(allow_policy());

        let session_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.session_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();
        let object_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.object_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();

        // Step 1: warm the cache with an adequate-buffer data query.
        let data_req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![pkcs11_proxy_ng_proto::AttributeQuery {
                attr_type: CkAttributeType::ID.0,
                buffer_present: true,
                buffer_len: 64,
                nested: None,
            }],
        };
        let fresh_data = super::get_attribute_value_exact(&ctx, Request::new(data_req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(fresh_data.ck_rv, CkRv::OK.0, "data query must succeed");
        let expected_len = fresh_data.results[0].returned_len;
        let after_warm = mock.attr_get_exact_call_count();

        // Step 2: size query (buffer_present=false) — must be served from cache.
        let size_req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![pkcs11_proxy_ng_proto::AttributeQuery {
                attr_type: CkAttributeType::ID.0,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
        };
        let cached_size = super::get_attribute_value_exact(&ctx, Request::new(size_req))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            mock.attr_get_exact_call_count(),
            after_warm,
            "M3(a): size query must be served from cache (backend must not be called)"
        );
        assert_eq!(cached_size.ck_rv, CkRv::OK.0, "M3(a): size-query cache hit must return OK");
        assert_eq!(
            cached_size.results[0].returned_len, expected_len,
            "M3(a): size-query cache hit returned_len must match the data query's returned_len"
        );
        // Size query has no value bytes (None in proto).
        assert!(
            cached_size.results[0].value.is_none(),
            "M3(a): size-query cache hit must have no value bytes (size-only result)"
        );
    }

    /// M3(b): exact-path BUFFER_TOO_SMALL cache hit — when the cache holds a data
    /// result, a subsequent query with an under-sized buffer must be served from
    /// cache with CKR_BUFFER_TOO_SMALL (byte-identical to a fresh backend response).
    #[tokio::test]
    async fn exact_path_buffer_too_small_cache_hit_returns_buffer_too_small() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                c.object_handles.insert(BackendHandle(1));
            })
            .await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(allow_policy());

        let session_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.session_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();
        let object_handle = ctx_mgr
            .get_context(&ctx_id, |c| c.object_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap();

        // Step 1: warm the cache with an adequate-buffer data query.
        let data_req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![pkcs11_proxy_ng_proto::AttributeQuery {
                attr_type: CkAttributeType::ID.0,
                buffer_present: true,
                buffer_len: 64,
                nested: None,
            }],
        };
        super::get_attribute_value_exact(&ctx, Request::new(data_req)).await.unwrap();
        let after_warm = mock.attr_get_exact_call_count();

        // Step 2: buffer-too-small query (buffer_len = 1) — must be served from cache.
        let small_req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![pkcs11_proxy_ng_proto::AttributeQuery {
                attr_type: CkAttributeType::ID.0,
                buffer_present: true,
                buffer_len: 1,
                nested: None,
            }],
        };
        let cached_small = super::get_attribute_value_exact(&ctx, Request::new(small_req))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            mock.attr_get_exact_call_count(),
            after_warm,
            "M3(b): buffer-too-small query must be served from cache (backend must not be called)"
        );
        // Overall RV must be BUFFER_TOO_SMALL (sole error on the native ladder).
        assert_eq!(
            cached_small.ck_rv,
            CkRv::BUFFER_TOO_SMALL.0,
            "M3(b): buffer-too-small cache hit must return BUFFER_TOO_SMALL"
        );
        // Per-attr returned_len must be CK_UNAVAILABLE_INFORMATION (u64::MAX) per PKCS#11.
        assert_eq!(
            cached_small.results[0].returned_len,
            u64::MAX,
            "M3(b): buffer-too-small cache hit must set returned_len to CK_UNAVAILABLE_INFORMATION"
        );
    }

    /// W1-L13-15: the single-owner conversion must adopt `Bytes`/`String`
    /// payloads by move (no second allocation) and encode scalars
    /// byte-identically to `attr_value_to_bytes`.
    #[test]
    fn single_owner_adopts_secret_payloads_without_copy() {
        for value in [
            CkAttributeValue::Bytes(SecretBytes::new(vec![0x5au8; 64])),
            CkAttributeValue::String(SecretBytes::new(b"label-bytes".to_vec())),
        ] {
            let before = match &value {
                CkAttributeValue::Bytes(secret) | CkAttributeValue::String(secret) => {
                    secret.expose(|bytes| bytes.as_ptr())
                }
                _ => unreachable!("fixture holds only secret payloads"),
            };
            let owned = super::attr_value_to_secret_bytes(value);
            let after = owned.expose(|bytes| bytes.as_ptr());
            assert_eq!(before, after, "secret payloads must be adopted by move, not copied");
        }
        for scalar in [
            CkAttributeValue::Ulong(0x0102_0304_0506_0708),
            CkAttributeValue::Bool(true),
            CkAttributeValue::NestedTemplate(vec![]),
        ] {
            let expected = attr_value_to_bytes(scalar.clone());
            let owned = super::attr_value_to_secret_bytes(scalar);
            owned.expose(|bytes| {
                assert_eq!(bytes, expected.as_slice(), "scalar encoding must match");
            });
        }
    }

    /// W1-L13-15: the single-owner coalesced path serves byte-identical
    /// responses with one copy — a repeated read hits the cache (no second
    /// backend call) and returns identical bytes.
    #[tokio::test]
    async fn single_owner_coalesced_responses_byte_identical() {
        let _coalesce_guard = enable_coalesce().await;
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;
        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1)); // virtual = 1
                c.object_private.insert(VirtualHandle(1), false);
            })
            .await;

        let make_request = || pkcs11_proxy_ng_proto::GetAttributeValueRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle: 1,
            template: vec![pkcs11_proxy_ng_proto::Attribute {
                attr_type: CkAttributeType::LABEL.0,
                value: None,
            }],
        };

        let resp1 = super::get_attribute_value(&ctx, Request::new(make_request()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp1.ck_rv, CkRv::OK.0);
        assert_eq!(mock.attr_get_call_count(), 1, "first read must call the backend once");
        // T12: the oneof enum is `ZeroizeOnDrop`, so the payload cannot
        // move out of it even through a clone — match by reference instead.
        let first_value = match &resp1.results[0].result {
            Some(pkcs11_proxy_ng_proto::attribute_result::Result::Value(bytes)) => bytes.clone(),
            other => panic!("LABEL must return bytes, got {other:?}"),
        };
        assert_eq!(first_value, b"my-label", "response bytes must match the backend value");

        let resp2 = super::get_attribute_value(&ctx, Request::new(make_request()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            mock.attr_get_call_count(),
            1,
            "repeated read must be served from cache (no second backend call)"
        );
        assert_eq!(resp1.results, resp2.results, "cached read must be byte-identical");

        // The cache put received the moved owner: the entry matches the response.
        let cached = ctx
            .context_manager
            .attr_cache_get(&ctx_id, 1, CkAttributeType::LABEL)
            .await
            .expect("LABEL must be cached after the fetch");
        cached.value.expose(|bytes| {
            assert_eq!(bytes, b"my-label", "cached bytes must match the response");
        });
    }

    // --- W1-L3-10: native-order RV merge ---
    //
    // Differential contract (proxy vs observed native): SoftHSM 2.6.1
    // answers mixed-error C_GetAttributeValue with a priority ladder —
    // SENSITIVE > INVALID > BUFFER_TOO_SMALL — in BOTH template orders
    // (probe evidence recorded in the Task 29 campaign report).
    // Template-position first-error would diverge from observed native
    // ([336-first, INVALID-second] is INVALID natively), so the merge
    // implements the native ladder, not position order and not 336-dominance.

    #[test]
    fn merge_exact_rv_follows_native_priority_ladder() {
        let cases = [
            ((CkRv::OK, CkRv::OK), CkRv::OK),
            ((CkRv::OK, CkRv::BUFFER_TOO_SMALL), CkRv::BUFFER_TOO_SMALL),
            ((CkRv::BUFFER_TOO_SMALL, CkRv::OK), CkRv::BUFFER_TOO_SMALL),
            ((CkRv::BUFFER_TOO_SMALL, CkRv::BUFFER_TOO_SMALL), CkRv::BUFFER_TOO_SMALL),
            ((CkRv::BUFFER_TOO_SMALL, CkRv::ATTRIBUTE_SENSITIVE), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::ATTRIBUTE_SENSITIVE, CkRv::BUFFER_TOO_SMALL), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::BUFFER_TOO_SMALL, CkRv::ATTRIBUTE_TYPE_INVALID), CkRv::ATTRIBUTE_TYPE_INVALID),
            ((CkRv::ATTRIBUTE_TYPE_INVALID, CkRv::BUFFER_TOO_SMALL), CkRv::ATTRIBUTE_TYPE_INVALID),
            ((CkRv::ATTRIBUTE_SENSITIVE, CkRv::ATTRIBUTE_TYPE_INVALID), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::ATTRIBUTE_TYPE_INVALID, CkRv::ATTRIBUTE_SENSITIVE), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::OK, CkRv::ATTRIBUTE_SENSITIVE), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::ATTRIBUTE_SENSITIVE, CkRv::OK), CkRv::ATTRIBUTE_SENSITIVE),
            ((CkRv::OK, CkRv::ATTRIBUTE_TYPE_INVALID), CkRv::ATTRIBUTE_TYPE_INVALID),
            ((CkRv::ATTRIBUTE_TYPE_INVALID, CkRv::OK), CkRv::ATTRIBUTE_TYPE_INVALID),
            // Call-aborting class outranks per-attr classes: a native call
            // that hits a device/session failure answers it, never a
            // per-attribute classification.
            ((CkRv::BUFFER_TOO_SMALL, CkRv::DEVICE_ERROR), CkRv::DEVICE_ERROR),
            ((CkRv::DEVICE_ERROR, CkRv::BUFFER_TOO_SMALL), CkRv::DEVICE_ERROR),
            ((CkRv::OK, CkRv::DEVICE_ERROR), CkRv::DEVICE_ERROR),
            ((CkRv::DEVICE_ERROR, CkRv::OK), CkRv::DEVICE_ERROR),
            ((CkRv::ATTRIBUTE_SENSITIVE, CkRv::DEVICE_ERROR), CkRv::DEVICE_ERROR),
        ];
        for ((a, b), expected) in cases {
            assert_eq!(
                super::merge_exact_rv(a, b),
                expected,
                "W1-L3-10: merge({a:?}, {b:?}) must follow the native ladder"
            );
        }
    }

    #[test]
    fn merge_exact_rv_call_aborting_tie_goes_to_first_arg() {
        // T29 M4: two distinct call-aborting RVs share the top rank, so
        // the first argument (the cache side at the call site) wins, in
        // both orders. Characterization: both are hard errors, so either
        // choice fails the call loudly.
        assert_eq!(
            super::merge_exact_rv(CkRv::DEVICE_ERROR, CkRv::SESSION_HANDLE_INVALID),
            CkRv::DEVICE_ERROR,
        );
        assert_eq!(
            super::merge_exact_rv(CkRv::SESSION_HANDLE_INVALID, CkRv::DEVICE_ERROR),
            CkRv::SESSION_HANDLE_INVALID,
        );
    }

    fn exact_query(
        attr_type: CkAttributeType,
        buffer_len: u64,
    ) -> pkcs11_proxy_ng_proto::AttributeQuery {
        pkcs11_proxy_ng_proto::AttributeQuery {
            attr_type: attr_type.0,
            buffer_present: true,
            buffer_len,
            nested: None,
        }
    }

    async fn exact_mixed_setup() -> (HandlerContext, ClientContextId, u64, u64, Arc<MockBackend>) {
        let mock = mock_with_attrs();
        let (ctx, ctx_id, session_handle) =
            setup_with_mock(mock.clone(), allow_policy(), Some(MTLS_IDENTITY.into())).await;
        ctx.context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(1));
            })
            .await;
        let object_handle = ctx_mgr_object_virtual(&ctx, &ctx_id).await;
        // Warm the cache: ID ("my-id", 5 bytes) with an adequate buffer.
        let warm = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx_id.0.clone(),
            session_handle,
            object_handle,
            queries: vec![exact_query(CkAttributeType::ID, 64)],
        };
        let warmed =
            super::get_attribute_value_exact(&ctx, Request::new(warm)).await.unwrap().into_inner();
        assert_eq!(warmed.ck_rv, CkRv::OK.0, "cache-warming read must succeed");
        (ctx, ctx_id, session_handle, object_handle, mock)
    }

    async fn ctx_mgr_object_virtual(ctx: &HandlerContext, ctx_id: &ClientContextId) -> u64 {
        ctx.context_manager
            .get_context(ctx_id, |c| c.object_handles.virtual_handles().next().unwrap().0)
            .await
            .unwrap()
    }

    async fn run_exact_mixed(
        ctx: &HandlerContext,
        ctx_id: &ClientContextId,
        session_handle: u64,
        object_handle: u64,
        queries: Vec<pkcs11_proxy_ng_proto::AttributeQuery>,
    ) -> pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
        super::get_attribute_value_exact(
            ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
                exact_output_effects_version: 1,
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle,
                queries,
            }),
        )
        .await
        .unwrap()
        .into_inner()
    }

    /// Cache-336 at position 0 + fetched SENSITIVE at position 1: native
    /// answers SENSITIVE in both orders; dominance answers 336.
    #[tokio::test]
    async fn coalesced_cache_too_small_then_sensitive_matches_native() {
        let _coalesce_guard = enable_coalesce().await;
        let (ctx, ctx_id, session_handle, object_handle, _) = exact_mixed_setup().await;
        let resp = run_exact_mixed(
            &ctx,
            &ctx_id,
            session_handle,
            object_handle,
            vec![exact_query(CkAttributeType::ID, 1), exact_query(CkAttributeType::SENSITIVE, 8)],
        )
        .await;
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].ck_rv, Some(CkRv::BUFFER_TOO_SMALL.0));
        assert_eq!(resp.results[1].ck_rv, Some(CkRv::ATTRIBUTE_SENSITIVE.0));
        assert_eq!(
            resp.ck_rv,
            CkRv::ATTRIBUTE_SENSITIVE.0,
            "W1-L3-10: coalesced RV must equal native (SENSITIVE), not 336-dominant"
        );
    }

    /// Fetched SENSITIVE at position 0 + cache-336 at position 1: native
    /// answers SENSITIVE here too (ladder is position-insensitive).
    #[tokio::test]
    async fn coalesced_sensitive_then_cache_too_small_matches_native() {
        let _coalesce_guard = enable_coalesce().await;
        let (ctx, ctx_id, session_handle, object_handle, _) = exact_mixed_setup().await;
        let resp = run_exact_mixed(
            &ctx,
            &ctx_id,
            session_handle,
            object_handle,
            vec![exact_query(CkAttributeType::SENSITIVE, 8), exact_query(CkAttributeType::ID, 1)],
        )
        .await;
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].ck_rv, Some(CkRv::ATTRIBUTE_SENSITIVE.0));
        assert_eq!(resp.results[1].ck_rv, Some(CkRv::BUFFER_TOO_SMALL.0));
        assert_eq!(
            resp.ck_rv,
            CkRv::ATTRIBUTE_SENSITIVE.0,
            "W1-L3-10: coalesced RV must equal native (SENSITIVE) in either order"
        );
    }

    /// Cache-336 + fetched INVALID (unregistered MODULUS): native answers
    /// INVALID in both orders.
    #[tokio::test]
    async fn coalesced_cache_too_small_then_invalid_matches_native() {
        let _coalesce_guard = enable_coalesce().await;
        let (ctx, ctx_id, session_handle, object_handle, _) = exact_mixed_setup().await;
        let resp = run_exact_mixed(
            &ctx,
            &ctx_id,
            session_handle,
            object_handle,
            vec![exact_query(CkAttributeType::ID, 1), exact_query(CkAttributeType::MODULUS, 8)],
        )
        .await;
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].ck_rv, Some(CkRv::BUFFER_TOO_SMALL.0));
        assert_eq!(resp.results[1].ck_rv, Some(CkRv::ATTRIBUTE_TYPE_INVALID.0));
        assert_eq!(
            resp.ck_rv,
            CkRv::ATTRIBUTE_TYPE_INVALID.0,
            "W1-L3-10: coalesced RV must equal native (INVALID), not 336-dominant"
        );
    }

    /// Fetched INVALID + cache-336: native answers INVALID here too.
    #[tokio::test]
    async fn coalesced_invalid_then_cache_too_small_matches_native() {
        let _coalesce_guard = enable_coalesce().await;
        let (ctx, ctx_id, session_handle, object_handle, _) = exact_mixed_setup().await;
        let resp = run_exact_mixed(
            &ctx,
            &ctx_id,
            session_handle,
            object_handle,
            vec![exact_query(CkAttributeType::MODULUS, 8), exact_query(CkAttributeType::ID, 1)],
        )
        .await;
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].ck_rv, Some(CkRv::ATTRIBUTE_TYPE_INVALID.0));
        assert_eq!(resp.results[1].ck_rv, Some(CkRv::BUFFER_TOO_SMALL.0));
        assert_eq!(
            resp.ck_rv,
            CkRv::ATTRIBUTE_TYPE_INVALID.0,
            "W1-L3-10: coalesced RV must equal native (INVALID) in either order"
        );
    }

    // --- W1-L5-04: range-gate behavior (attributes.rs exemplar; the
    // byte_output_exact.rs source scan pins the other five gate sites) ---

    /// Out-of-range versions fail loudly: FAILED_PRECONDITION naming the
    /// supported range (message half is RED pre-range, code half pins).
    #[tokio::test]
    async fn exact_gate_rejects_out_of_range_version_loudly() {
        let (ctx, ctx_id, session_handle) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;
        // No object registration needed: the version gate precedes resolution.
        let err = super::get_attribute_value_exact(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
                exact_output_effects_version: 2,
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                queries: vec![],
            }),
        )
        .await
        .expect_err("out-of-range version must be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message().contains("1..=1"),
            "rejection must name the supported range, got: {}",
            err.message()
        );
    }

    /// The current version passes the gate (here: onward to session
    /// resolution, which fails for the bogus handle — proving the gate
    /// did not trip). Characterization: green before and after.
    #[tokio::test]
    async fn exact_gate_accepts_current_version() {
        let (ctx, ctx_id, _) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;
        let resp = super::get_attribute_value_exact(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
                exact_output_effects_version: 1,
                client_context_id: ctx_id.0.clone(),
                session_handle: u64::MAX,
                object_handle: 0,
                queries: vec![],
            }),
        )
        .await
        .expect("current version must pass the gate");
        assert_eq!(
            resp.into_inner().ck_rv,
            CkRv::SESSION_HANDLE_INVALID.0,
            "v1 request must reach session resolution"
        );
    }

    #[test]
    fn ulong_encodes_native_order_for_cache_coherence() {
        // The non-exact path shares the attr_cache key space with the exact
        // path's raw backend bytes: both must be native-order on every host.
        // 0x0102_0304_0506_0708 distinguishes LE from BE absolutely.
        // (Lives here, not in grpc_service/mod.rs, because the consistency
        // scanner parses every `(...)` after `impl_proxy_service!` there as
        // a handler tuple.)
        assert_eq!(
            attr_value_to_bytes(CkAttributeValue::Ulong(0x0102_0304_0506_0708)),
            0x0102_0304_0506_0708u64.to_ne_bytes().to_vec()
        );
        assert_eq!(attr_value_to_bytes(CkAttributeValue::Bool(true)), vec![1]);
    }
}
