//! Virtualization of object handles embedded inside mechanism parameters (B1).
//!
//! The primary key handle of an operation (the base key of `C_DeriveKey`, the
//! wrapping key of `C_WrapKey`, …) is translated from the caller's per-context
//! *virtual* handle space into the *backend* handle space by the handlers
//! themselves. But several mechanism parameter shapes embed *additional*
//! `CK_OBJECT_HANDLE` values (HKDF salt key, ECDH/MQV private-data keys, TLS
//! key-material secrets, IKE/Signal key handles, …). Those reached the backend
//! FFI as raw `as` casts of the wire value, so a client could embed another
//! client's (or a guessed) backend handle and reach an object it does not own.
//!
//! [`remap_param_handles`] walks a mechanism's parameters and remaps every such
//! embedded handle through a caller-supplied resolver. It is an **exhaustive**
//! match by construction: a newly added `CkMechanismParams` variant will not
//! compile until it is explicitly classified as handle-bearing or handle-free,
//! so a future parameter shape cannot silently bypass the translation.

use std::collections::HashMap;

use pkcs11_proxy_ng_types::{
    CkMechanism, CkMechanismParams, CkObjectHandle, CkRv, CkSessionHandle,
};

use super::super::context_manager::ClientContextId;
use super::super::handle_map::{BackendHandle, VirtualHandle};

/// Remap every embedded object handle in `mechanism`'s parameters from the
/// caller's per-context virtual handle space into the backend handle space,
/// gating each through object and class authorization when active.
///
/// When neither object nor class policy is active (the common case),
/// handles are remapped with a single context-lock acquisition — zero-overhead
/// transparent forwarding.
///
/// When object or class authorization is active, the function uses four phases:
/// 1. Collect all non-zero embedded virtual handles (read-only scan).
/// 2. Resolve each virtual→backend inside the context lock.
/// 3. Gate each resolved handle through `gate_object_handle` (async, one call
///    per embedded handle).  A denied handle gates to `CkObjectHandle(0)`.
/// 4. Re-walk params writing the gated backend handles. A gated-to-0 (denied /
///    fail-closed) embedded handle is NOT forwarded to the backend as 0 —
///    for an embedded handle a backend value of 0 means "no key / not
///    applicable" (a different, potentially insecure operation), so Phase 4
///    instead rejects the whole operation with `CKR_OBJECT_HANDLE_INVALID`
///    BEFORE the backend call. This yields the SAME RV a genuinely nonexistent
///    embedded handle produces (Phase 3 `None`), preserving the
///    denied==nonexistent invisible-denial property at the RV/audit/metric axes
///    (the first-access UID-fetch timing difference is the documented I1 limit).
///
/// This structure ensures every handle-bearing mechanism variant — including
/// nested CmsSig/Kip/Ecies sub-mechanisms and SP800-108 byte-encoded key
/// handles (the latter handled by a separate resolver in
/// `key_ops/generation.rs`) — is gated through the same single
/// `gate_object_handle` choke point.
///
/// D6(1): embedding a private key in mechanism parameters is a USE of that
/// key — every collected non-zero embedded (virtual, backend) pair is gated
/// through `ensure_private_use_allowed` on BOTH paths below, so a logged-out
/// caller gets `CKR_USER_NOT_LOGGED_IN` instead of reaching the backend
/// through another tenant's login.
///
/// Returns `CKR_CRYPTOKI_NOT_INITIALIZED` if the context no longer exists,
/// `CKR_USER_NOT_LOGGED_IN` if a private embedded key is used while the
/// caller is logically logged out, `CKR_OBJECT_HANDLE_INVALID` if any
/// embedded handle is not owned by the caller or is denied by object/class
/// policy. A mechanism with no parameters is a no-op.
pub(super) async fn remap_mechanism_handles(
    ctx: &super::HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session_handle: u64,
    backend_session_handle: u64,
    mechanism: &mut CkMechanism,
) -> Result<(), CkRv> {
    let Some(params) = mechanism.params.as_mut() else {
        return Ok(());
    };

    if !ctx.token_policy.per_object_active() && !ctx.token_policy.per_class_active() {
        // Fast path (no object or class policy configured): collect embedded
        // handles, resolve virtual→backend under a single context-lock
        // acquisition, D6(1)-check each pair, then remap.
        let virtual_handles = collect_param_handles(params);
        if virtual_handles.is_empty() {
            return Ok(()); // no embedded handles → nothing to remap
        }
        let resolved: Vec<(u64, Option<u64>)> = match ctx
            .context_manager
            .get_context(ctx_id, |lci| {
                virtual_handles
                    .iter()
                    .map(|&vh| (vh, lci.object_handles.resolve(VirtualHandle(vh)).map(|b| b.0)))
                    .collect::<Vec<_>>()
            })
            .await
        {
            Some(pairs) => pairs,
            None => return Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        };
        let backend_session = CkSessionHandle(backend_session_handle);
        for (virtual_h, backend_h) in &resolved {
            if let Some(backend_h) = backend_h
                && *backend_h != 0
            {
                super::service_utils::ensure_private_use_allowed(
                    ctx,
                    ctx_id,
                    virtual_session_handle,
                    *virtual_h,
                    backend_session,
                    CkObjectHandle(*backend_h),
                )
                .await?;
            }
        }
        let remapped: HashMap<u64, u64> =
            resolved.into_iter().filter_map(|(vh, bh)| bh.map(|b| (vh, b))).collect();
        return remap_param_handles(params, &|h| remapped.get(&h).copied());
    }

    // Gating path — object or class policy is active.

    // Phase 1: collect all non-zero embedded virtual handles.
    let virtual_handles = collect_param_handles(params);
    if virtual_handles.is_empty() {
        return Ok(()); // no embedded handles → nothing to remap
    }

    // Phase 2: resolve each virtual handle to a backend handle inside the
    // context lock, collecting (virtual, Option<backend>) pairs.
    let resolved: Vec<(u64, Option<u64>)> = match ctx
        .context_manager
        .get_context(ctx_id, |lci| {
            virtual_handles
                .iter()
                .map(|&vh| (vh, lci.object_handles.resolve(VirtualHandle(vh)).map(|b| b.0)))
                .collect::<Vec<_>>()
        })
        .await
    {
        Some(pairs) => pairs,
        None => return Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
    };

    // Phase 3: gate each resolved handle asynchronously.
    // Builds virtual_h → gated_backend_h map.
    let mut gated: HashMap<u64, u64> = HashMap::with_capacity(resolved.len());
    let backend_session = BackendHandle(backend_session_handle);
    for (virtual_h, backend_h_opt) in resolved {
        match backend_h_opt {
            None => return Err(CkRv::OBJECT_HANDLE_INVALID), // not in caller's map
            Some(0) => {
                gated.insert(virtual_h, 0); // CK_INVALID_HANDLE passes through
            }
            Some(bh) => {
                // D6(1): embedding a private key is a USE of that key — refuse
                // while logically logged out, before the per-object gate (the
                // same authn-before-authz order as the primary-handle
                // chokepoints). `Some(0)` is handled by the arm above, so `bh`
                // is non-zero here.
                super::service_utils::ensure_private_use_allowed(
                    ctx,
                    ctx_id,
                    virtual_session_handle,
                    virtual_h,
                    CkSessionHandle(backend_session_handle),
                    CkObjectHandle(bh),
                )
                .await?;
                let gated_h = super::service_utils::gate_object_handle(
                    ctx,
                    ctx_id,
                    virtual_session_handle,
                    virtual_h,
                    backend_session,
                    CkObjectHandle(bh),
                )
                .await
                .0;
                gated.insert(virtual_h, gated_h);
            }
        }
    }

    // Phase 4: remap params using the gated map.
    // The resolver maps each virtual handle to its gated backend handle.
    // · None (absent in map)  → indicates a collect/resolve bug → fail-closed.
    // · Some(0) after gating  → denied or fail-closed by per-object authz.
    //   Returning None here (rather than Some(0)) causes remap_param_handles
    //   to yield CKR_OBJECT_HANDLE_INVALID, blocking the operation before the
    //   backend call. This is necessary because for embedded/secondary handles
    //   (e.g. HKDF salt_key_handle) a backend value of 0 means "no key /
    //   not applicable" — a semantically different (and potentially insecure)
    //   operation, not a hard error.
    // · Some(bh != 0)         → permitted handle, use as-is.
    remap_param_handles(params, &|h| match gated.get(&h).copied() {
        Some(0) | None => None, // denied, fail-closed, or collect bug → reject
        other => other,
    })
}

/// Collect all non-zero embedded object-handle values from `params`.
///
/// Mirrors the structure of [`remap_param_handles`] exactly — every
/// handle-bearing variant pushes its non-zero fields, every handle-free
/// variant is a no-op. Nested CmsSig/Kip/Ecies sub-mechanisms are walked
/// recursively.
/// SP800-108 byte-encoded key handles are NOT collected here (they are
/// resolved by a dedicated path in `key_ops/generation.rs`).
fn collect_param_handles(params: &CkMechanismParams) -> Vec<u64> {
    let mut handles = Vec::new();
    push_param_handles(params, &mut handles);
    handles
}

fn push_param_handles(params: &CkMechanismParams, out: &mut Vec<u64>) {
    let push = |h: u64, out: &mut Vec<u64>| {
        if h != 0 {
            out.push(h);
        }
    };
    use CkMechanismParams as P;
    match params {
        P::Hkdf(p) => push(p.salt_key_handle.0, out),
        P::Ecdh2Derive(p) => push(p.private_data_handle.0, out),
        P::EcmqvDerive(p) => {
            push(p.private_data_handle.0, out);
            push(p.public_key_handle.0, out);
        }
        P::X942Dh2Derive(p) => push(p.private_data_handle.0, out),
        P::X942MqvDerive(p) => {
            push(p.private_data_handle.0, out);
            push(p.public_key_handle.0, out);
        }
        P::Gostr3410KeyWrap(p) => push(p.key_handle.0, out),
        P::Ssl3KeyMat(p) => {
            push(p.client_mac_secret_handle.0, out);
            push(p.server_mac_secret_handle.0, out);
            push(p.client_key_handle.0, out);
            push(p.server_key_handle.0, out);
        }
        P::WtlsKeyMat(p) => {
            push(p.mac_secret_handle.0, out);
            push(p.key_handle.0, out);
        }
        P::IkePrfDerive(p) => push(p.new_key_handle.0, out),
        P::Ike1PrfDerive(p) => {
            push(p.keygxy_handle.0, out);
            push(p.prev_key_handle.0, out);
        }
        P::Ike1ExtendedDerive(p) => push(p.keygxy_handle.0, out),
        P::Ike2PrfPlusDerive(p) => push(p.seed_key_handle.0, out),
        P::X3dhInitiate(p) => {
            push(p.peer_identity_handle.0, out);
            push(p.peer_prekey_handle.0, out);
            push(p.onetime_key_handle.0, out);
            push(p.own_identity_handle.0, out);
            push(p.own_ephemeral_handle.0, out);
        }
        P::X3dhRespond(p) => {
            push(p.identity_handle.0, out);
            push(p.prekey_handle.0, out);
            push(p.onetime_key_handle.0, out);
            push(p.initiator_identity_handle.0, out);
            push(p.initiator_ephemeral_handle.0, out);
        }
        P::X2RatchetInitialize(p) => {
            push(p.peer_public_prekey_handle.0, out);
            push(p.peer_public_identity_handle.0, out);
            push(p.own_public_identity_handle.0, out);
        }
        P::X2RatchetRespond(p) => {
            push(p.own_prekey_handle.0, out);
            push(p.initiator_identity_handle.0, out);
            push(p.own_identity_handle.0, out);
        }
        P::Kip(p) => {
            push(p.key_handle.0, out);
            if let Some(inner) = p.mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
        }
        P::Ecies(p) => {
            if let Some(inner) = p.derivation_mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
            if let Some(inner) = p.encryption_mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
            if let Some(inner) = p.mac_mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
        }
        P::ObjectHandle(p) => push(p.handle.0, out),
        P::Kmac(p) => push(p.key_handle.0, out),
        P::MuGen(p) => push(p.key_handle.0, out),
        P::Kyber(p) => push(p.secret_handle.0, out),
        P::CmsSig(p) => {
            push(p.certificate_handle.0, out);
            if let Some(inner) = p.signing_mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
            if let Some(inner) = p.digest_mechanism.params.as_ref() {
                push_param_handles(inner, out);
            }
        }

        // SP800-108: byte-encoded key handles resolved by a dedicated path.
        P::Sp800108Kdf(_) | P::Sp800108FeedbackKdf(_) => {}

        // No embedded object handles.
        P::RsaPkcsPss(_)
        | P::RsaPkcsOaep(_)
        | P::Gcm(_)
        | P::Ecdh1Derive(_)
        | P::Iv(_)
        | P::Rc5(_)
        | P::Rc5MacGeneral(_)
        | P::Rc2MacGeneral(_)
        | P::Xeddsa(_)
        | P::TlsMac(_)
        | P::AesCtr(_)
        | P::CamelliaCtr(_)
        | P::Rc2Cbc(_)
        | P::Rc5Cbc(_)
        | P::AesCbcEncryptData(_)
        | P::DesCbcEncryptData(_)
        | P::AriaCbcEncryptData(_)
        | P::CamelliaCbcEncryptData(_)
        | P::SeedCbcEncryptData(_)
        | P::Ccm(_)
        | P::ChaCha20(_)
        | P::Salsa20(_)
        | P::Salsa20ChaCha20Poly1305(_)
        | P::GcmWrap(_)
        | P::CcmWrap(_)
        | P::X942Dh1Derive(_)
        | P::Eddsa(_)
        | P::Gostr3410Derive(_)
        | P::KeaDerive(_)
        | P::EcdhAesKeyWrap(_)
        | P::RsaAesKeyWrap(_)
        | P::KeyWrapSetOaep(_)
        | P::Pbe(_)
        | P::Pkcs5Pbkd2(_)
        | P::TlsPrf(_)
        | P::TlsKdf(_)
        | P::Ssl3MasterKeyDerive(_)
        | P::Tls12MasterKeyDerive(_)
        | P::Tls12ExtendedMasterKeyDerive(_)
        | P::WtlsMasterKeyDerive(_)
        | P::WtlsPrf(_)
        | P::Otp(_)
        | P::SkipjackPrivateWrap(_)
        | P::SkipjackRelayx(_)
        | P::MacGeneral(_)
        | P::Extract(_)
        | P::SignAdditionalContext(_)
        | P::KeyDerivationString(_)
        | P::Raw(_)
        | P::AesCmacKeyDerivation(_)
        | P::Dilithium(_)
        | P::HdKeyDerive(_)
        | P::VendorObjectExtract(_)
        | P::VendorObjectInsert(_) => {}
    }
}

/// Remap a single embedded object-handle field in place.
///
/// A zero value is `CK_INVALID_HANDLE` ("no handle"): optional handle fields
/// legitimately carry it, so it passes through untouched. Any other value is a
/// client virtual handle that must resolve to a backend handle; an unresolvable
/// handle rejects the whole call with `CKR_OBJECT_HANDLE_INVALID` (matching how
/// the proxy already reports cross-context/unknown object handles).
fn remap_handle(
    field: &mut CkObjectHandle,
    resolve: &impl Fn(u64) -> Option<u64>,
) -> Result<(), CkRv> {
    if field.0 == 0 {
        return Ok(());
    }
    match resolve(field.0) {
        Some(backend) => {
            field.0 = backend;
            Ok(())
        }
        None => Err(CkRv::OBJECT_HANDLE_INVALID),
    }
}

/// Walk `params` and remap every embedded object handle from the caller's
/// virtual handle space into the backend handle space via `resolve`
/// (`virtual -> Some(backend)`, or `None` when the caller does not own it).
///
/// Exhaustive over `CkMechanismParams`: handle-bearing variants remap their
/// fields, every other variant is explicitly listed as handle-free. SP800-108
/// is deliberately excluded here — its input key handle is *byte-encoded* inside
/// `PrfDataParam` values (translated by the dedicated SP800-108 resolver), and
/// its `additional_derived_keys` handles are *outputs*, not inputs.
pub(super) fn remap_param_handles(
    params: &mut CkMechanismParams,
    resolve: &impl Fn(u64) -> Option<u64>,
) -> Result<(), CkRv> {
    use CkMechanismParams as P;
    match params {
        P::Hkdf(p) => remap_handle(&mut p.salt_key_handle, resolve)?,
        P::Ecdh2Derive(p) => remap_handle(&mut p.private_data_handle, resolve)?,
        P::EcmqvDerive(p) => {
            remap_handle(&mut p.private_data_handle, resolve)?;
            remap_handle(&mut p.public_key_handle, resolve)?;
        }
        P::X942Dh2Derive(p) => remap_handle(&mut p.private_data_handle, resolve)?,
        P::X942MqvDerive(p) => {
            remap_handle(&mut p.private_data_handle, resolve)?;
            remap_handle(&mut p.public_key_handle, resolve)?;
        }
        P::Gostr3410KeyWrap(p) => remap_handle(&mut p.key_handle, resolve)?,
        P::Ssl3KeyMat(p) => {
            remap_handle(&mut p.client_mac_secret_handle, resolve)?;
            remap_handle(&mut p.server_mac_secret_handle, resolve)?;
            remap_handle(&mut p.client_key_handle, resolve)?;
            remap_handle(&mut p.server_key_handle, resolve)?;
        }
        P::WtlsKeyMat(p) => {
            remap_handle(&mut p.mac_secret_handle, resolve)?;
            remap_handle(&mut p.key_handle, resolve)?;
        }
        P::IkePrfDerive(p) => remap_handle(&mut p.new_key_handle, resolve)?,
        P::Ike1PrfDerive(p) => {
            remap_handle(&mut p.keygxy_handle, resolve)?;
            remap_handle(&mut p.prev_key_handle, resolve)?;
        }
        P::Ike1ExtendedDerive(p) => remap_handle(&mut p.keygxy_handle, resolve)?,
        P::Ike2PrfPlusDerive(p) => remap_handle(&mut p.seed_key_handle, resolve)?,
        P::X3dhInitiate(p) => {
            remap_handle(&mut p.peer_identity_handle, resolve)?;
            remap_handle(&mut p.peer_prekey_handle, resolve)?;
            remap_handle(&mut p.onetime_key_handle, resolve)?;
            remap_handle(&mut p.own_identity_handle, resolve)?;
            remap_handle(&mut p.own_ephemeral_handle, resolve)?;
        }
        P::X3dhRespond(p) => {
            remap_handle(&mut p.identity_handle, resolve)?;
            remap_handle(&mut p.prekey_handle, resolve)?;
            remap_handle(&mut p.onetime_key_handle, resolve)?;
            remap_handle(&mut p.initiator_identity_handle, resolve)?;
            remap_handle(&mut p.initiator_ephemeral_handle, resolve)?;
        }
        P::X2RatchetInitialize(p) => {
            remap_handle(&mut p.peer_public_prekey_handle, resolve)?;
            remap_handle(&mut p.peer_public_identity_handle, resolve)?;
            remap_handle(&mut p.own_public_identity_handle, resolve)?;
        }
        P::X2RatchetRespond(p) => {
            remap_handle(&mut p.own_prekey_handle, resolve)?;
            remap_handle(&mut p.initiator_identity_handle, resolve)?;
            remap_handle(&mut p.own_identity_handle, resolve)?;
        }
        P::Kip(p) => {
            remap_handle(&mut p.key_handle, resolve)?;
            // The nested mechanism may itself carry params with embedded
            // handles, so recurse (mirrors the CmsSig sub-mechanisms).
            if let Some(inner) = p.mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
        }
        P::Ecies(p) => {
            // All three nested mechanisms may carry embedded handles.
            if let Some(inner) = p.derivation_mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
            if let Some(inner) = p.encryption_mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
            if let Some(inner) = p.mac_mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
        }
        P::ObjectHandle(p) => remap_handle(&mut p.handle, resolve)?,
        P::Kmac(p) => remap_handle(&mut p.key_handle, resolve)?,
        P::MuGen(p) => remap_handle(&mut p.key_handle, resolve)?,
        P::Kyber(p) => remap_handle(&mut p.secret_handle, resolve)?,
        P::CmsSig(p) => {
            remap_handle(&mut p.certificate_handle, resolve)?;
            // The signing/digest sub-mechanisms may themselves carry params
            // with embedded handles, so recurse into each.
            if let Some(inner) = p.signing_mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
            if let Some(inner) = p.digest_mechanism.params.as_mut() {
                remap_param_handles(inner, resolve)?;
            }
        }

        // SP800-108: input key handle is byte-encoded in `PrfDataParam` values
        // (resolved by the dedicated SP800-108 path); `additional_derived_keys`
        // handles are outputs. Nothing plain to remap here.
        P::Sp800108Kdf(_) | P::Sp800108FeedbackKdf(_) => {}

        // No embedded object handles.
        P::RsaPkcsPss(_)
        | P::RsaPkcsOaep(_)
        | P::Gcm(_)
        | P::Ecdh1Derive(_)
        | P::Iv(_)
        | P::Rc5(_)
        | P::Rc5MacGeneral(_)
        | P::Rc2MacGeneral(_)
        | P::Xeddsa(_)
        | P::TlsMac(_)
        | P::AesCtr(_)
        | P::CamelliaCtr(_)
        | P::Rc2Cbc(_)
        | P::Rc5Cbc(_)
        | P::AesCbcEncryptData(_)
        | P::DesCbcEncryptData(_)
        | P::AriaCbcEncryptData(_)
        | P::CamelliaCbcEncryptData(_)
        | P::SeedCbcEncryptData(_)
        | P::Ccm(_)
        | P::ChaCha20(_)
        | P::Salsa20(_)
        | P::Salsa20ChaCha20Poly1305(_)
        | P::GcmWrap(_)
        | P::CcmWrap(_)
        | P::X942Dh1Derive(_)
        | P::Eddsa(_)
        | P::Gostr3410Derive(_)
        | P::KeaDerive(_)
        | P::EcdhAesKeyWrap(_)
        | P::RsaAesKeyWrap(_)
        | P::KeyWrapSetOaep(_)
        | P::Pbe(_)
        | P::Pkcs5Pbkd2(_)
        | P::TlsPrf(_)
        | P::TlsKdf(_)
        | P::Ssl3MasterKeyDerive(_)
        | P::Tls12MasterKeyDerive(_)
        | P::Tls12ExtendedMasterKeyDerive(_)
        | P::WtlsMasterKeyDerive(_)
        | P::WtlsPrf(_)
        | P::Otp(_)
        | P::SkipjackPrivateWrap(_)
        | P::SkipjackRelayx(_)
        | P::MacGeneral(_)
        | P::Extract(_)
        | P::SignAdditionalContext(_)
        | P::KeyDerivationString(_)
        | P::Raw(_)
        | P::AesCmacKeyDerivation(_)
        | P::Dilithium(_)
        | P::HdKeyDerive(_)
        | P::VendorObjectExtract(_)
        | P::VendorObjectInsert(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_types::{HkdfParams, IvParams, X3dhInitiateParams};
    use std::collections::HashMap;

    /// Build a resolver mapping the given virtual->backend pairs; unknown
    /// virtual handles resolve to `None`.
    fn resolver(pairs: &[(u64, u64)]) -> impl Fn(u64) -> Option<u64> + '_ {
        let map: HashMap<u64, u64> = pairs.iter().copied().collect();
        move |v| map.get(&v).copied()
    }

    fn hkdf(salt: u64) -> CkMechanismParams {
        CkMechanismParams::Hkdf(HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: pkcs11_proxy_ng_types::CkMechanismType(0),
            salt_type: 0,
            salt: Vec::new().into(),
            salt_key_handle: CkObjectHandle(salt),
            info: Vec::new().into(),
        })
    }

    fn x3dh(handles: [u64; 5]) -> CkMechanismParams {
        CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
            kdf: 0,
            peer_identity_handle: CkObjectHandle(handles[0]),
            peer_prekey_handle: CkObjectHandle(handles[1]),
            prekey_signature: Vec::new(),
            onetime_key_handle: CkObjectHandle(handles[2]),
            own_identity_handle: CkObjectHandle(handles[3]),
            own_ephemeral_handle: CkObjectHandle(handles[4]),
        })
    }

    #[test]
    fn zero_handle_passes_through_untouched() {
        // CK_INVALID_HANDLE means "no salt key" — must not be treated as a miss.
        let mut p = hkdf(0);
        remap_param_handles(&mut p, &resolver(&[])).unwrap();
        let CkMechanismParams::Hkdf(out) = p else { panic!() };
        assert_eq!(out.salt_key_handle.0, 0);
    }

    #[test]
    fn known_handle_is_translated_to_backend_value() {
        let mut p = hkdf(7);
        remap_param_handles(&mut p, &resolver(&[(7, 4242)])).unwrap();
        let CkMechanismParams::Hkdf(out) = p else { panic!() };
        assert_eq!(out.salt_key_handle.0, 4242);
    }

    #[test]
    fn unknown_handle_is_rejected() {
        let mut p = hkdf(9);
        let err = remap_param_handles(&mut p, &resolver(&[(7, 4242)])).unwrap_err();
        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn multi_handle_variant_remaps_every_field() {
        // Five handles, one of them the "absent" 0 sentinel.
        let mut p = x3dh([1, 2, 0, 3, 4]);
        remap_param_handles(&mut p, &resolver(&[(1, 11), (2, 22), (3, 33), (4, 44)])).unwrap();
        let CkMechanismParams::X3dhInitiate(out) = p else { panic!() };
        assert_eq!(
            (
                out.peer_identity_handle,
                out.peer_prekey_handle,
                out.onetime_key_handle,
                out.own_identity_handle,
                out.own_ephemeral_handle
            ),
            (
                CkObjectHandle(11),
                CkObjectHandle(22),
                CkObjectHandle(0),
                CkObjectHandle(33),
                CkObjectHandle(44)
            )
        );
    }

    #[test]
    fn one_unresolvable_field_rejects_the_whole_param() {
        let mut p = x3dh([1, 2, 0, 3, 999]); // 999 not owned
        let err = remap_param_handles(&mut p, &resolver(&[(1, 11), (2, 22), (3, 33)])).unwrap_err();
        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn handle_free_param_is_left_unchanged() {
        let mut p = CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] });
        remap_param_handles(&mut p, &resolver(&[])).unwrap();
        assert!(matches!(p, CkMechanismParams::Iv(_)));
    }

    // -----------------------------------------------------------------------
    // W1-L4-09 + W1-C5-B01: nested Kip/Ecies handles must be remapped too
    // -----------------------------------------------------------------------

    fn paramless() -> pkcs11_proxy_ng_types::CkMechanism {
        pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: pkcs11_proxy_ng_types::CkMechanismType(0),
            params: None,
        }
    }

    fn with_params(inner: CkMechanismParams) -> pkcs11_proxy_ng_types::CkMechanism {
        pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: pkcs11_proxy_ng_types::CkMechanismType(0),
            params: Some(inner),
        }
    }

    fn kip(key_handle: u64, inner: CkMechanismParams) -> CkMechanismParams {
        CkMechanismParams::Kip(pkcs11_proxy_ng_types::KipParams {
            mechanism: Box::new(with_params(inner)),
            key_handle: CkObjectHandle(key_handle),
            seed: Vec::new().into(),
        })
    }

    fn ecies(
        derivation: pkcs11_proxy_ng_types::CkMechanism,
        encryption: pkcs11_proxy_ng_types::CkMechanism,
        mac: pkcs11_proxy_ng_types::CkMechanism,
    ) -> CkMechanismParams {
        CkMechanismParams::Ecies(pkcs11_proxy_ng_types::EciesParams {
            derivation_mechanism: Box::new(derivation),
            encryption_mechanism: Box::new(encryption),
            mac_mechanism: Box::new(mac),
            shared_data: Vec::new().into(),
        })
    }

    #[test]
    fn kip_nested_unmapped_handle_is_rejected() {
        // Nested handle 9 is not owned → must reject exactly like a
        // top-level unmapped handle, before any backend call.
        let mut p = kip(0, hkdf(9));
        let err = remap_param_handles(&mut p, &resolver(&[])).unwrap_err();
        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn kip_nested_mapped_handle_is_remapped() {
        let mut p = kip(7, hkdf(9));
        remap_param_handles(&mut p, &resolver(&[(7, 700), (9, 900)])).unwrap();
        let CkMechanismParams::Kip(out) = p else { panic!() };
        assert_eq!(out.key_handle.0, 700);
        let Some(CkMechanismParams::Hkdf(inner)) = out.mechanism.params.as_ref() else { panic!() };
        assert_eq!(inner.salt_key_handle.0, 900);
    }

    #[test]
    fn ecies_nested_unmapped_handle_is_rejected() {
        let mut p = ecies(with_params(hkdf(9)), paramless(), paramless());
        let err = remap_param_handles(&mut p, &resolver(&[])).unwrap_err();
        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn ecies_nested_mapped_handles_are_remapped() {
        let mut p = ecies(with_params(hkdf(1)), with_params(hkdf(2)), with_params(hkdf(3)));
        remap_param_handles(&mut p, &resolver(&[(1, 11), (2, 22), (3, 33)])).unwrap();
        let CkMechanismParams::Ecies(out) = p else { panic!() };
        let salt_of = |m: &pkcs11_proxy_ng_types::CkMechanism| {
            let Some(CkMechanismParams::Hkdf(inner)) = m.params.as_ref() else { panic!() };
            inner.salt_key_handle
        };
        assert_eq!(salt_of(&out.derivation_mechanism), CkObjectHandle(11));
        assert_eq!(salt_of(&out.encryption_mechanism), CkObjectHandle(22));
        assert_eq!(salt_of(&out.mac_mechanism), CkObjectHandle(33));
    }

    // -----------------------------------------------------------------------
    // C1: per-object authz gating via the full remap_mechanism_handles path
    // -----------------------------------------------------------------------

    /// Build a [`HandlerContext`] with a per-object policy that allows only
    /// objects whose CKA_UNIQUE_ID == ALLOWED_UID_BYTES for `identity`.
    ///
    /// Returns `(ctx, ctx_id, virtual_session, backend_session, virtual_object)`.
    async fn setup_c1_test(
        uid_bytes: Option<Vec<u8>>,
    ) -> (
        super::super::HandlerContext,
        super::super::super::context_manager::ClientContextId,
        u64, // virtual session handle
        u64, // backend session handle (for fetch_object_unique_id)
        u64, // virtual object handle
    ) {
        use std::sync::Arc;
        use std::time::Duration;

        use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockAttributeSlot};
        use pkcs11_proxy_ng_types::{CkAttributeType, CkAttributeValue, CkSessionFlags, CkSlotId};

        use super::super::super::context_manager::ContextManager;
        use super::super::super::handle_map::BackendHandle;
        use super::super::HandlerContext;
        use crate::config::{
            AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig,
            TokenAccessSpec,
        };
        use crate::server::auth::policy::TokenPolicy;

        const IDENTITY: &str = "uid=1000";
        const ALLOWED_UID_HEX: &str = "aabbcc";

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        // Always set CLASS and TOKEN so fetch_object_metadata's 3-element template works.
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        if let Some(uid) = uid_bytes {
            mock.set_attribute(
                backend_object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.into())),
            );
        }

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let (vs, vo) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(backend_object.0));
                (vs, vo)
            })
            .await
            .unwrap();

        let policy = Arc::new(
            TokenPolicy::from_config(&AuthConfig {
                allow_all_authenticated: false,
                anonymous_principal: None,
                policy: vec![PolicyEntry {
                    identity: IDENTITY.into(),
                    tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                        token: "label:MockToken".into(),
                        classes: None,
                        mechanisms: None,
                        extract: ExtractPolicyConfig::Allow,
                        objects: Some(vec![crate::config::ObjectAclSpec::Bare(
                            ALLOWED_UID_HEX.into(),
                        )]),
                    })]),
                }],
            })
            .expect("per-object policy must parse"),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;
        (ctx, ctx_id, vs.0, backend_session.0, vo.0)
    }

    /// When per-object authz is active and the embedded HKDF salt key handle
    /// refers to an object with a DIFFERENT uid (denied), the gate produces
    /// CkObjectHandle(0), which causes remap_mechanism_handles to return
    /// CKR_OBJECT_HANDLE_INVALID (C1 bypass-closure check).
    #[tokio::test]
    async fn c1_hkdf_salt_denied_handle_returns_invalid() {
        use pkcs11_proxy_ng_types::{CkMechanism, HkdfParams};

        // Set up: object has OTHER uid (not in the allow-list).
        const OTHER_UID: &[u8] = &[0x11, 0x22, 0x33];
        let (ctx, ctx_id, vs, bs, vo) = setup_c1_test(Some(OTHER_UID.to_vec())).await;

        assert!(
            ctx.token_policy.per_object_active(),
            "policy must have per_object_active==true for this test"
        );

        // Build an HKDF mechanism embedding `vo` as the salt_key_handle.
        let mut mechanism = CkMechanism {
            mechanism_type: pkcs11_proxy_ng_types::CkMechanismType(0),
            params: Some(CkMechanismParams::Hkdf(HkdfParams {
                extract: true,
                expand: true,
                prf_hash_mechanism: pkcs11_proxy_ng_types::CkMechanismType(0),
                salt_type: 0,
                salt: Vec::new().into(),
                salt_key_handle: CkObjectHandle(vo), // this virtual handle is denied (wrong uid)
                info: Vec::new().into(),
            })),
        };

        let result = remap_mechanism_handles(&ctx, &ctx_id, vs, bs, &mut mechanism).await;
        assert_eq!(
            result,
            Err(CkRv::OBJECT_HANDLE_INVALID),
            "denied embedded handle must produce OBJECT_HANDLE_INVALID (C1)"
        );
    }

    /// When per-object authz is active and the embedded HKDF salt key handle
    /// refers to an object with the ALLOWED uid, remap succeeds (C1 pass).
    #[tokio::test]
    async fn c1_hkdf_salt_allowed_handle_remaps_successfully() {
        use pkcs11_proxy_ng_types::{CkMechanism, HkdfParams};

        const ALLOWED_UID: &[u8] = &[0xaa, 0xbb, 0xcc];
        let (ctx, ctx_id, vs, bs, vo) = setup_c1_test(Some(ALLOWED_UID.to_vec())).await;

        let mut mechanism = CkMechanism {
            mechanism_type: pkcs11_proxy_ng_types::CkMechanismType(0),
            params: Some(CkMechanismParams::Hkdf(HkdfParams {
                extract: true,
                expand: true,
                prf_hash_mechanism: pkcs11_proxy_ng_types::CkMechanismType(0),
                salt_type: 0,
                salt: Vec::new().into(),
                salt_key_handle: CkObjectHandle(vo), // this virtual handle is allowed
                info: Vec::new().into(),
            })),
        };

        let result = remap_mechanism_handles(&ctx, &ctx_id, vs, bs, &mut mechanism).await;
        assert!(result.is_ok(), "allowed embedded handle must remap successfully (C1): {result:?}");
        // The handle must remain non-zero (0 would mean denied/not-found).
        let CkMechanism { params: Some(CkMechanismParams::Hkdf(out)), .. } = mechanism else {
            panic!("mechanism params must still be Hkdf after remap");
        };
        assert_ne!(
            out.salt_key_handle.0, 0,
            "remapped backend handle must be non-zero for allowed object"
        );
    }
}
