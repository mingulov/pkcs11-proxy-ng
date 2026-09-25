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

use std::sync::Arc;

use pkcs11_proxy_ng_types::{CkMechanism, CkMechanismParams, CkRv};

use super::super::context_manager::{ClientContextId, ContextManager};
use super::super::handle_map::VirtualHandle;

/// Remap every embedded object handle in `mechanism`'s parameters from the
/// caller's per-context virtual handle space into the backend handle space,
/// using the context's object-handle map. All handles in the parameter are
/// resolved under a single context lock.
///
/// Returns `CKR_CRYPTOKI_NOT_INITIALIZED` if the context no longer exists, or
/// `CKR_OBJECT_HANDLE_INVALID` if any embedded handle is not owned by the
/// caller. A mechanism with no parameters is a no-op.
pub(super) async fn remap_mechanism_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    mechanism: &mut CkMechanism,
) -> Result<(), CkRv> {
    let Some(params) = mechanism.params.as_mut() else {
        return Ok(());
    };
    match ctx_mgr
        .get_context(ctx_id, |ctx| {
            remap_param_handles(params, &|h| {
                ctx.object_handles.resolve(VirtualHandle(h)).map(|backend| backend.0)
            })
        })
        .await
    {
        Some(result) => result,
        None => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
    }
}

/// Remap a single embedded object-handle field in place.
///
/// A zero value is `CK_INVALID_HANDLE` ("no handle"): optional handle fields
/// legitimately carry it, so it passes through untouched. Any other value is a
/// client virtual handle that must resolve to a backend handle; an unresolvable
/// handle rejects the whole call with `CKR_OBJECT_HANDLE_INVALID` (matching how
/// the proxy already reports cross-context/unknown object handles).
fn remap_handle(field: &mut u64, resolve: &impl Fn(u64) -> Option<u64>) -> Result<(), CkRv> {
    if *field == 0 {
        return Ok(());
    }
    match resolve(*field) {
        Some(backend) => {
            *field = backend;
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
        P::Kip(p) => remap_handle(&mut p.key_handle, resolve)?,
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
        | P::Ecies(_)
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
            prf_hash_mechanism: 0,
            salt_type: 0,
            salt: Vec::new(),
            salt_key_handle: salt,
            info: Vec::new(),
        })
    }

    fn x3dh(handles: [u64; 5]) -> CkMechanismParams {
        CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
            kdf: 0,
            peer_identity_handle: handles[0],
            peer_prekey_handle: handles[1],
            prekey_signature: Vec::new(),
            onetime_key_handle: handles[2],
            own_identity_handle: handles[3],
            own_ephemeral_handle: handles[4],
        })
    }

    #[test]
    fn zero_handle_passes_through_untouched() {
        // CK_INVALID_HANDLE means "no salt key" — must not be treated as a miss.
        let mut p = hkdf(0);
        remap_param_handles(&mut p, &resolver(&[])).unwrap();
        let CkMechanismParams::Hkdf(out) = p else { panic!() };
        assert_eq!(out.salt_key_handle, 0);
    }

    #[test]
    fn known_handle_is_translated_to_backend_value() {
        let mut p = hkdf(7);
        remap_param_handles(&mut p, &resolver(&[(7, 4242)])).unwrap();
        let CkMechanismParams::Hkdf(out) = p else { panic!() };
        assert_eq!(out.salt_key_handle, 4242);
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
            (11, 22, 0, 33, 44)
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
}
