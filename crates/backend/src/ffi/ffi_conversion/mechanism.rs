//! Mechanism parameter conversion Rust -> C: FfiMechanism owns the
//! reconstructed parameter structs; mechanism_to_ffi is ONE flat
//! per-shape match, kept flat by design for auditability (see the
//! contributor rules).

use super::*;
use crate::ffi::native_allocation::NativeAllocation;

#[cfg(test)]
mod native_owner_tests;
#[cfg(test)]
mod x3dh_tests;

/// Owns the `CK_MECHANISM` and any backing storage that `pParameter` points
/// into.  The C struct fields reference heap allocations inside `_backing`,
/// which stay at a stable address as long as `FfiMechanism` is alive.
///
/// **Safety contract:** callers must not move the byte buffers inside
/// `_backing` (no realloc) while `ck_mechanism` is in use.  Since all fields
/// are private except `ck_mechanism`, and we never push to a Vec after
/// construction, this is upheld automatically.
pub(crate) struct FfiMechanism {
    pub ck_mechanism: cryptoki_sys::CK_MECHANISM,
    _backing: FfiParamBacking,
}

impl FfiMechanism {
    pub(in crate::ffi) fn validate_authenticated_inputs(
        &self,
        input: &CkMechanism,
    ) -> CkResult<()> {
        let valid = match (&self._backing, input.params.as_ref()) {
            (FfiParamBacking::None, None) => true,
            (FfiParamBacking::Bytes(bytes), Some(CkMechanismParams::Iv(iv))) => {
                bytes.len() == iv.iv.len()
            }
            (
                FfiParamBacking::Gostr3410KeyWrap(native, oid, ukm),
                Some(CkMechanismParams::Gostr3410KeyWrap(input)),
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let native = unsafe { native.snapshot() };
                let pointer_matches = |pointer: *mut u8, bytes: &[u8]| {
                    if bytes.is_empty() {
                        pointer.is_null()
                    } else {
                        std::ptr::eq(pointer, bytes.as_ptr())
                    }
                };
                pointer_matches(native.pWrapOID, oid)
                    && pointer_matches(native.pUKM, ukm)
                    && native.ulWrapOIDLen as u64 == input.wrap_oid.len() as u64
                    && native.ulUKMLen as u64 == input.ukm.len() as u64
                    && native.hKey as u64 == input.key_handle
                    && oid == &input.wrap_oid
                    && ukm == &input.ukm
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(CkRv::DEVICE_ERROR) }
    }

    /// Read owned IV bytes only. Never read the native parameter structure as
    /// bytes or return the typed input, which may contain remapped handles.
    pub(in crate::ffi) fn authenticated_output(
        &self,
    ) -> CkResult<pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput> {
        use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
        match &self._backing {
            FfiParamBacking::None | FfiParamBacking::Gostr3410KeyWrap(..) => {
                Ok(AuthenticatedOutput::Unchanged)
            }
            FfiParamBacking::Bytes(iv) => Ok(AuthenticatedOutput::Iv(iv.clone())),
            _ => Err(CkRv::MECHANISM_PARAM_INVALID),
        }
    }
    /// Build an `FfiMechanism` from a parameter pointer, length, and backing.
    ///
    /// **SAFETY INVARIANT (callers must uphold):** `ptr` must point into the
    /// `backing` value (typically `Box::into_raw(...)` or the data pointer of
    /// a `Vec` stored inside `backing`), so that the pointer remains valid for
    /// as long as `_backing` is held. This helper does not enforce the
    /// invariant; it only packages the fields into the `CK_MECHANISM` shape
    /// so the 70+ construction sites in `mechanism_to_ffi` don't repeat the
    /// same struct-literal boilerplate.
    fn with_param(
        mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
        ptr: *mut std::ffi::c_void,
        len: usize,
        backing: FfiParamBacking,
    ) -> Self {
        Self {
            ck_mechanism: cryptoki_sys::CK_MECHANISM {
                mechanism: mech_type,
                pParameter: ptr,
                ulParameterLen: len as cryptoki_sys::CK_ULONG,
            },
            _backing: backing,
        }
    }

    /// Build an `FfiMechanism` with no parameter (`pParameter = NULL`).
    fn no_param(mech_type: cryptoki_sys::CK_MECHANISM_TYPE) -> Self {
        Self::with_param(mech_type, std::ptr::null_mut(), 0, FfiParamBacking::None)
    }

    /// Build an `FfiMechanism` from a `Box<T>` C-struct: derives the
    /// `pParameter` pointer from the box's heap allocation (stable
    /// address) and the `ulParameterLen` from `size_of::<T>()`.
    /// The caller passes a closure that constructs the matching
    /// `FfiParamBacking` variant from the same box; this keeps the
    /// box and the pointer-into-box tied together in one expression
    /// and removes the `Box::into_raw` / `std::mem::size_of::<...>()`
    /// boilerplate that repeated at 60+ sites in `mechanism_to_ffi`.
    ///
    /// **Provenance (C3M.2, defect I1):** the raw root is projected from
    /// the persistent [`NativeAllocation`] established by a single
    /// `Box::into_raw`, never from a reborrow (`&mut *boxed`) of a box
    /// that is subsequently moved into backing: that reborrow pattern
    /// invalidates pointer provenance under Miri's borrow models as soon
    /// as the box moves. Ownership transfers exactly once into backing,
    /// so one allocation keeps one owner and one final `Drop`.
    ///
    /// **SAFETY INVARIANT:** `make_backing(a)` MUST move `a` into a
    /// variant of `FfiParamBacking` so that the C struct's allocation
    /// (and any pointers the struct itself holds into side-data) stay
    /// live for as long as the returned `FfiMechanism`. The allocation
    /// moves as a [`NativeAllocation`]: its raw root never reborrows, so
    /// later owner moves cannot strand the stored `pParameter`.
    fn from_box<T>(
        mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
        boxed: Box<T>,
        make_backing: impl FnOnce(NativeAllocation<T>) -> FfiParamBacking,
    ) -> Self {
        let len = std::mem::size_of::<T>();
        let allocation = NativeAllocation::from_box(boxed);
        let ptr = allocation.root() as *mut std::ffi::c_void;
        Self::with_param(mech_type, ptr, len, make_backing(allocation))
    }

    pub(in crate::ffi) fn output_params(&self) -> Option<CkMechanismParams> {
        match &self._backing {
            FfiParamBacking::Gcm(gcm, iv, aad) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let gcm = unsafe { gcm.snapshot() };
                let iv_len = (gcm.ulIvLen as usize).min(iv.len());
                let aad_len = (gcm.ulAADLen as usize).min(aad.len());
                Some(CkMechanismParams::Gcm(GcmParams {
                    iv: iv[..iv_len].to_vec(),
                    iv_bits: gcm.ulIvBits as u64,
                    iv_buffer_len: iv.len() as u64,
                    aad: aad[..aad_len].to_vec(),
                    tag_bits: gcm.ulTagBits as u64,
                }))
            }
            FfiParamBacking::Tls12MasterKeyDerive(tls12, client_random, server_random, version) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                // CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion is OUT —
                // the HSM writes the negotiated CK_VERSION here when
                // pVersion is non-NULL. Surface the version_major /
                // version_minor back to the caller; the random data
                // and PRF mechanism are unchanged by the derive (those
                // fields are caller-supplied inputs).
                Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random: client_random.clone(),
                        server_random: server_random.clone(),
                    },
                    version_major: version.major as u32,
                    version_minor: version.minor as u32,
                    prf_hash_mechanism: tls12.prfHashMechanism as u64,
                }))
            }
            FfiParamBacking::WtlsMasterKeyDerive(wtls, client_random, server_random, version) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                    digest_mechanism: wtls.DigestMechanism as u64,
                    random_info: WtlsRandomData {
                        client_random: client_random.clone(),
                        server_random: server_random.clone(),
                    },
                    version: version.first().copied().unwrap_or_default() as u32,
                }))
            }
            FfiParamBacking::WtlsKeyMat(wtls, client_random, server_random, key_mat_out, iv) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                let iv_len = (((wtls.ulIVSizeInBits as usize).saturating_add(7)) / 8).min(iv.len());
                let output_iv =
                    if key_mat_out.pIV.is_null() { Vec::new() } else { iv[..iv_len].to_vec() };
                Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                    digest_mechanism: wtls.DigestMechanism as u64,
                    mac_size_bits: wtls.ulMacSizeInBits as u64,
                    key_size_bits: wtls.ulKeySizeInBits as u64,
                    iv_size_bits: wtls.ulIVSizeInBits as u64,
                    sequence_number: wtls.ulSequenceNumber as u64,
                    is_export: wtls.bIsExport != 0,
                    random_info: WtlsRandomData {
                        client_random: client_random.clone(),
                        server_random: server_random.clone(),
                    },
                    mac_secret_handle: key_mat_out.hMacSecret as u64,
                    key_handle: key_mat_out.hKey as u64,
                    iv: output_iv,
                }))
            }
            FfiParamBacking::Ssl3KeyMat(
                ssl3,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let ssl3 = unsafe { ssl3.snapshot() };
                let iv_len =
                    (((ssl3.ulIVSizeInBits as usize).saturating_add(7)) / 8).min(client_iv.len());
                Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: ssl3.ulMacSizeInBits as u64,
                    key_size_bits: ssl3.ulKeySizeInBits as u64,
                    iv_size_bits: ssl3.ulIVSizeInBits as u64,
                    is_export: ssl3.bIsExport != 0,
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random: client_random.clone(),
                        server_random: server_random.clone(),
                    },
                    prf_hash_mechanism: 0,
                    client_mac_secret_handle: key_mat_out.hClientMacSecret as u64,
                    server_mac_secret_handle: key_mat_out.hServerMacSecret as u64,
                    client_key_handle: key_mat_out.hClientKey as u64,
                    server_key_handle: key_mat_out.hServerKey as u64,
                    client_iv: if key_mat_out.pIVClient.is_null() {
                        Vec::new()
                    } else {
                        client_iv[..iv_len].to_vec()
                    },
                    server_iv: if key_mat_out.pIVServer.is_null() {
                        Vec::new()
                    } else {
                        server_iv[..iv_len.min(server_iv.len())].to_vec()
                    },
                }))
            }
            FfiParamBacking::Tls12KeyMat(
                tls12,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                let iv_len =
                    (((tls12.ulIVSizeInBits as usize).saturating_add(7)) / 8).min(client_iv.len());
                Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: tls12.ulMacSizeInBits as u64,
                    key_size_bits: tls12.ulKeySizeInBits as u64,
                    iv_size_bits: tls12.ulIVSizeInBits as u64,
                    is_export: tls12.bIsExport != 0,
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random: client_random.clone(),
                        server_random: server_random.clone(),
                    },
                    prf_hash_mechanism: tls12.prfHashMechanism as u64,
                    client_mac_secret_handle: key_mat_out.hClientMacSecret as u64,
                    server_mac_secret_handle: key_mat_out.hServerMacSecret as u64,
                    client_key_handle: key_mat_out.hClientKey as u64,
                    server_key_handle: key_mat_out.hServerKey as u64,
                    client_iv: if key_mat_out.pIVClient.is_null() {
                        Vec::new()
                    } else {
                        client_iv[..iv_len].to_vec()
                    },
                    server_iv: if key_mat_out.pIVServer.is_null() {
                        Vec::new()
                    } else {
                        server_iv[..iv_len.min(server_iv.len())].to_vec()
                    },
                }))
            }
            FfiParamBacking::Sp800108Kdf(sp800, data_params, data_buffers, derived_keys)
                if !derived_keys.is_empty() =>
            {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: sp800.prfType as u64,
                    data_params: sp800_108_data_params_from_ffi(data_params, data_buffers),
                    additional_derived_keys: derived_keys.output_keys(),
                }))
            }
            FfiParamBacking::Sp800108FeedbackKdf(
                sp800,
                data_params,
                data_buffers,
                iv,
                derived_keys,
            ) if !derived_keys.is_empty() => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: sp800.prfType as u64,
                    data_params: sp800_108_data_params_from_ffi(data_params, data_buffers),
                    iv: iv[..(sp800.ulIVLen as usize).min(iv.len())].to_vec(),
                    additional_derived_keys: derived_keys.output_keys(),
                }))
            }
            FfiParamBacking::Pbe(pbe, init_vector, _password, _salt) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let pbe = unsafe { pbe.snapshot() };
                if pbe.pInitVector.is_null() {
                    return None;
                }
                // CK_PBE_PARAMS.pInitVector is OUT — the HSM writes the generated
                // 8-byte IV here during PBE key generation. Surface ONLY the IV;
                // the password and salt are caller-supplied secrets/inputs and
                // must never be echoed back over the wire (AGENTS.md §4).
                Some(CkMechanismParams::Pbe(PbeParams {
                    init_vector: init_vector.clone(),
                    password: Vec::new(),
                    salt: Vec::new(),
                    iteration: pbe.ulIteration as u64,
                }))
            }
            _ => None,
        }
    }
}

fn sp800_108_data_params_from_ffi(
    params: &[cryptoki_sys::CK_PRF_DATA_PARAM],
    buffers: &[Vec<u8>],
) -> Vec<PrfDataParam> {
    params
        .iter()
        .zip(buffers.iter())
        .map(|(param, value)| PrfDataParam { type_: param.type_ as u64, value: value.clone() })
        .collect()
}

struct FfiSp800108DerivedKeys {
    original: Vec<Sp800108DerivedKey>,
    _templates: Vec<FfiAttrs>,
    handles: Vec<cryptoki_sys::CK_OBJECT_HANDLE>,
    derived_keys: Vec<cryptoki_sys::CK_DERIVED_KEY>,
}

impl FfiSp800108DerivedKeys {
    fn new(keys: &[Sp800108DerivedKey]) -> CkResult<Self> {
        let mut templates: Vec<FfiAttrs> = keys
            .iter()
            .map(|key| FfiAttrs::from_slice(&key.template))
            .collect::<CkResult<Vec<_>>>()?;
        let mut handles: Vec<cryptoki_sys::CK_OBJECT_HANDLE> = keys
            .iter()
            .map(|key| narrow_wire_ulong(key.key_handle))
            .collect::<CkResult<Vec<_>>>()?;
        let handle_ptr = handles.as_mut_ptr();
        let mut derived_keys = Vec::with_capacity(keys.len());

        for (index, template) in templates.iter_mut().enumerate() {
            let template_ptr = if template.attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                template.attrs.as_mut_ptr()
            };
            derived_keys.push(cryptoki_sys::CK_DERIVED_KEY {
                pTemplate: template_ptr,
                ulAttributeCount: template.attrs.len() as cryptoki_sys::CK_ULONG,
                phKey: unsafe { handle_ptr.add(index) },
            });
        }

        Ok(Self { original: keys.to_vec(), _templates: templates, handles, derived_keys })
    }

    fn is_empty(&self) -> bool {
        self.derived_keys.is_empty()
    }

    fn ptr(&mut self) -> *mut cryptoki_sys::CK_DERIVED_KEY {
        if self.derived_keys.is_empty() {
            std::ptr::null_mut()
        } else {
            self.derived_keys.as_mut_ptr()
        }
    }

    fn len(&self) -> cryptoki_sys::CK_ULONG {
        self.derived_keys.len() as cryptoki_sys::CK_ULONG
    }

    fn output_keys(&self) -> Vec<Sp800108DerivedKey> {
        self.original
            .iter()
            .zip(self.handles.iter())
            .map(|(original, handle)| Sp800108DerivedKey {
                template: original.template.clone(),
                key_handle: *handle as u64,
            })
            .collect()
    }
}

/// Backing storage variants.  Each variant holds the C param struct and any
/// heap buffers whose addresses are embedded in that struct.
#[allow(dead_code)]
enum FfiParamBacking {
    /// Parameterless mechanism — no backing needed.
    None,
    /// Raw byte buffer (IV params, raw params, MacGeneral ulong, etc.)
    Bytes(Vec<u8>),
    /// Scalar-only C struct stored as a pinned Box (PSS, RC5, RC2MacGeneral, etc.)
    Pss(NativeAllocation<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>),
    Rc5(NativeAllocation<cryptoki_sys::CK_RC5_PARAMS>),
    Rc5MacGeneral(NativeAllocation<cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS>),
    Rc2MacGeneral(NativeAllocation<cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS>),
    Xeddsa(NativeAllocation<cryptoki_sys::CK_XEDDSA_PARAMS>),
    TlsMac(NativeAllocation<cryptoki_sys::CK_TLS_MAC_PARAMS>),
    Rc2Cbc(NativeAllocation<cryptoki_sys::CK_RC2_CBC_PARAMS>),
    AesCtr(NativeAllocation<cryptoki_sys::CK_AES_CTR_PARAMS>),
    CamelliaCtr(NativeAllocation<cryptoki_sys::CK_CAMELLIA_CTR_PARAMS>),
    /// Struct with pointer fields — struct + borrowed buffers.
    Oaep(NativeAllocation<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>, Vec<u8>),
    Gcm(NativeAllocation<cryptoki_sys::CK_GCM_PARAMS>, Vec<u8>, Vec<u8>),
    Ccm(NativeAllocation<cryptoki_sys::CK_CCM_PARAMS>, Vec<u8>, Vec<u8>),
    Ecdh1(NativeAllocation<cryptoki_sys::CK_ECDH1_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Rc5Cbc(NativeAllocation<cryptoki_sys::CK_RC5_CBC_PARAMS>, Vec<u8>),
    Eddsa(NativeAllocation<cryptoki_sys::CK_EDDSA_PARAMS>, Vec<u8>),
    Hkdf(NativeAllocation<cryptoki_sys::CK_HKDF_PARAMS>, Vec<u8>, Vec<u8>),
    KeyDerivationString(NativeAllocation<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>, Vec<u8>),
    AesCbcEncryptData(NativeAllocation<cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    DesCbcEncryptData(NativeAllocation<cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    AriaCbcEncryptData(NativeAllocation<cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    CamelliaCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>,
        Vec<u8>,
    ),
    SeedCbcEncryptData(NativeAllocation<cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    GcmWrap(NativeAllocation<cryptoki_sys::CK_GCM_WRAP_PARAMS>, Vec<u8>, Vec<u8>),
    CcmWrap(NativeAllocation<cryptoki_sys::CK_CCM_WRAP_PARAMS>, Vec<u8>, Vec<u8>),
    ChaCha20(NativeAllocation<cryptoki_sys::CK_CHACHA20_PARAMS>, Vec<u8>, Vec<u8>),
    Salsa20(NativeAllocation<cryptoki_sys::CK_SALSA20_PARAMS>, Vec<u8>, Vec<u8>),
    Salsa20ChaCha20Poly1305(
        NativeAllocation<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS>,
        Vec<u8>,
        Vec<u8>,
    ),
    RsaAesKeyWrap(
        NativeAllocation<FfiRsaAesKeyWrapParams>,
        Box<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>,
        Vec<u8>,
    ),
    SignAdditionalContext(NativeAllocation<FfiSignAdditionalContext>, Vec<u8>),
    HashSignAdditionalContext(NativeAllocation<FfiHashSignAdditionalContext>, Vec<u8>),
    Kmac(NativeAllocation<FfiKmacParams>, Vec<u8>),
    MuGen(NativeAllocation<FfiMuGenParams>, Vec<u8>, Vec<u8>),
    // Last field is the caller password — wiped on drop (E1).
    Pkcs5Pbkd2(
        NativeAllocation<cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2>,
        Vec<u8>,
        Vec<u8>,
        Zeroizing<Vec<u8>>,
    ),
    Tls12MasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    TlsPrf(
        NativeAllocation<cryptoki_sys::CK_TLS_PRF_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_ULONG>,
    ),
    TlsKdf(NativeAllocation<cryptoki_sys::CK_TLS_KDF_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    Ssl3MasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    Tls12ExtendedMasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    Ssl3KeyMat(
        NativeAllocation<cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>,
        Vec<u8>,
        Vec<u8>,
    ),
    Tls12KeyMat(
        NativeAllocation<cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>,
        Vec<u8>,
        Vec<u8>,
    ),
    // Middle field is the caller password — wiped on drop (E1).
    Pbe(NativeAllocation<cryptoki_sys::CK_PBE_PARAMS>, Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>),
    EcdhAesKeyWrap(NativeAllocation<cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS>, Vec<u8>),
    Ecdh2Derive(NativeAllocation<cryptoki_sys::CK_ECDH2_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    EcmqvDerive(NativeAllocation<cryptoki_sys::CK_ECMQV_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    X942Dh1Derive(NativeAllocation<cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    X942Dh2Derive(
        NativeAllocation<cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    X942MqvDerive(
        NativeAllocation<cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    Gostr3410Derive(NativeAllocation<cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Gostr3410KeyWrap(
        NativeAllocation<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>,
        Vec<u8>,
        Vec<u8>,
    ),
    KeyWrapSetOaep(NativeAllocation<cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS>, Vec<u8>),
    KeaDerive(NativeAllocation<cryptoki_sys::CK_KEA_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    IkePrfDerive(NativeAllocation<cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Ike1PrfDerive(NativeAllocation<cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Ike1ExtendedDerive(NativeAllocation<cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS>, Vec<u8>),
    Ike2PrfPlusDerive(NativeAllocation<cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS>, Vec<u8>),
    WtlsMasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    WtlsPrf(
        NativeAllocation<cryptoki_sys::CK_WTLS_PRF_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_ULONG>,
    ),
    WtlsKeyMat(
        NativeAllocation<cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_WTLS_KEY_MAT_OUT>,
        Vec<u8>,
    ),
    Sp800108Kdf(
        NativeAllocation<cryptoki_sys::CK_SP800_108_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Vec<u8>>,
        FfiSp800108DerivedKeys,
    ),
    Sp800108FeedbackKdf(
        NativeAllocation<cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Vec<u8>>,
        Vec<u8>,
        FfiSp800108DerivedKeys,
    ),
    X3dhInitiate(NativeAllocation<cryptoki_sys::CK_X3DH_INITIATE_PARAMS>, Vec<u8>, Vec<u8>),
    X3dhRespond(
        NativeAllocation<cryptoki_sys::CK_X3DH_RESPOND_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    X2RatchetInitialize(NativeAllocation<cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS>, Vec<u8>),
    X2RatchetRespond(NativeAllocation<cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS>, Vec<u8>),
    Otp(
        NativeAllocation<cryptoki_sys::CK_OTP_PARAMS>,
        Vec<cryptoki_sys::CK_OTP_PARAM>,
        Vec<Vec<u8>>,
    ),
    // Last field keeps the inner mechanism's own parameter backing alive for as
    // long as the KIP params reference its C struct (L8 — replaces a mem::forget
    // that permanently leaked the inner backing).
    Kip(
        NativeAllocation<cryptoki_sys::CK_KIP_PARAMS>,
        Box<cryptoki_sys::CK_MECHANISM>,
        Vec<u8>,
        Box<FfiParamBacking>,
    ),
    CmsSig(
        NativeAllocation<cryptoki_sys::CK_CMS_SIG_PARAMS>,
        Box<cryptoki_sys::CK_MECHANISM>,
        Box<cryptoki_sys::CK_MECHANISM>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        // Inner signing/digest mechanism backings, kept alive (L8).
        Box<FfiParamBacking>,
        Box<FfiParamBacking>,
    ),
    SkipjackPrivateWrap(
        NativeAllocation<cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS>,
        Zeroizing<Vec<u8>>, // password — wiped on drop (E1)
        Vec<u8>,            // public_data
        Vec<u8>,            // random_a
        Vec<u8>,            // prime_p
        Vec<u8>,            // base_g
        Vec<u8>,            // subprime_q
    ),
    SkipjackRelayx(
        NativeAllocation<cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS>,
        Vec<u8>,            // old_wrapped_x
        Zeroizing<Vec<u8>>, // old_password — wiped on drop (E1)
        Vec<u8>,            // old_public_data
        Vec<u8>,            // old_random_a
        Zeroizing<Vec<u8>>, // new_password — wiped on drop (E1)
        Vec<u8>,            // new_public_data
        Vec<u8>,            // new_random_a
    ),
}

/// CK_RSA_AES_KEY_WRAP_PARAMS -- not in cryptoki-sys, defined per PKCS#11 v3 spec.
// LLP64 (Windows x64): the PKCS#11 headers `#pragma pack(1)` their structs, so
// a hand-rolled mirror must be packed there to match `ulParameterLen` /
// field offsets. Natural alignment is correct on LP64/ILP32 (ADR-0011 Bucket 2).
#[repr(C)]
#[cfg_attr(windows, repr(packed))]
pub(in crate::ffi) struct FfiRsaAesKeyWrapParams {
    pub(in crate::ffi) ul_aes_key_bits: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_oaep_params: *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS,
}

/// CK_SIGN_ADDITIONAL_CONTEXT — not in cryptoki-sys, defined per PKCS#11 3.2 spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiSignAdditionalContext {
    pub(in crate::ffi) hedge_variant: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_context: *mut cryptoki_sys::CK_BYTE,
    pub(in crate::ffi) ul_context_len: cryptoki_sys::CK_ULONG,
}

/// CK_HASH_SIGN_ADDITIONAL_CONTEXT — CK_SIGN_ADDITIONAL_CONTEXT plus the explicit
/// `hash` mechanism, for the generic CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiHashSignAdditionalContext {
    pub(in crate::ffi) hedge_variant: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_context: *mut cryptoki_sys::CK_BYTE,
    pub(in crate::ffi) ul_context_len: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) hash: cryptoki_sys::CK_MECHANISM_TYPE,
}

/// CK_KMAC_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiKmacParams {
    pub(in crate::ffi) h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    pub(in crate::ffi) ul_mac_length: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_customization_string: cryptoki_sys::CK_VOID_PTR,
    pub(in crate::ffi) ul_customization_string_len: cryptoki_sys::CK_ULONG,
}

/// CK_MU_GEN_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiMuGenParams {
    pub(in crate::ffi) h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    pub(in crate::ffi) p_tr: cryptoki_sys::CK_BYTE_PTR,
    pub(in crate::ffi) ul_tr_len: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_ctx: cryptoki_sys::CK_BYTE_PTR,
    pub(in crate::ffi) ul_ctx_len: cryptoki_sys::CK_ULONG,
}

/// Convert a `CkMechanism` to an `FfiMechanism` for FFI calls.
///
/// Parameterless mechanisms use null `pParameter`.  Parameterized mechanisms
/// allocate the appropriate C struct on the heap (via `Box`) so that
/// `pParameter` has a stable address for the lifetime of the returned
/// `FfiMechanism`.
///
/// Takes `&CkMechanism` by reference and clones each parameter buffer (IV, AAD,
/// salt, …) into the `FfiParamBacking`. Taking it *by value* to move those
/// buffers (M10) was evaluated and deliberately not adopted: it would require
/// changing every `Pkcs11Backend` crypto method to own its `CkMechanism`,
/// rippling through all backend implementors and every server call site — the
/// highest-risk FFI boundary — to remove a per-`*Init` copy of small buffers
/// that is already dominated by the protobuf decode which copied the same
/// fields a few microseconds earlier. Revisit only if profiling shows mechanism
/// backing copies as a hotspot (e.g. very large-AAD AEAD workloads).
pub(in crate::ffi) fn mechanism_to_ffi(mechanism: &CkMechanism) -> CkResult<FfiMechanism> {
    let mech_type = narrow_wire_ulong(mechanism.mechanism_type.0)?;

    let params = match &mechanism.params {
        None => return Ok(FfiMechanism::no_param(mech_type)),
        Some(p) => p,
    };

    match params {
        // -- IV: raw bytes as the parameter ---------------------------------
        CkMechanismParams::Iv(iv_params) => {
            let mut buf = iv_params.iv.clone();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Bytes(buf)))
        }

        // -- RSA-PSS: scalar-only struct ------------------------------------
        CkMechanismParams::RsaPkcsPss(p) => {
            let pss = Box::new(cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: narrow_wire_ulong(p.hash_alg.0)?,
                mgf: narrow_wire_ulong(p.mgf)?,
                sLen: narrow_wire_ulong(p.salt_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, pss, FfiParamBacking::Pss))
        }

        // -- RSA-OAEP: struct with pointer to source_data -------------------
        CkMechanismParams::RsaPkcsOaep(p) => {
            let mut source_data = p.source_data.clone();
            let (src_ptr, src_len) = if source_data.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (source_data.as_mut_ptr() as *mut std::ffi::c_void, source_data.len())
            };
            let oaep = Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: narrow_wire_ulong(p.hash_alg.0)?,
                mgf: narrow_wire_ulong(p.mgf)?,
                source: narrow_wire_ulong(p.source)?,
                pSourceData: src_ptr,
                ulSourceDataLen: src_len as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, oaep, |b| FfiParamBacking::Oaep(b, source_data)))
        }

        // -- GCM: struct with pointers to IV and AAD ------------------------
        CkMechanismParams::Gcm(p) => {
            let iv_capacity = gcm_iv_capacity(p)?;
            let input_iv_len = p.iv.len();
            let mut iv = p.iv.clone();
            if iv_capacity > iv.len() {
                iv.resize(iv_capacity, 0);
            }
            let mut aad = p.aad.clone();
            let iv_ptr = if iv.is_empty() { std::ptr::null_mut() } else { iv.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let gcm = Box::new(cryptoki_sys::CK_GCM_PARAMS {
                pIv: iv_ptr,
                ulIvLen: input_iv_len as cryptoki_sys::CK_ULONG,
                ulIvBits: narrow_wire_ulong(p.iv_bits)?,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulTagBits: narrow_wire_ulong(p.tag_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gcm, |b| FfiParamBacking::Gcm(b, iv, aad)))
        }

        // -- CCM: struct with pointers to nonce and AAD ---------------------
        CkMechanismParams::Ccm(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let ccm = Box::new(cryptoki_sys::CK_CCM_PARAMS {
                ulDataLen: narrow_wire_ulong(p.data_len)?,
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulMACLen: narrow_wire_ulong(p.mac_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ccm, |b| FfiParamBacking::Ccm(b, nonce, aad)))
        }

        // -- ECDH1 Derive: struct with pointers to shared + public data -----
        CkMechanismParams::Ecdh1Derive(p) => {
            let mut shared = p.shared_data.clone();
            let mut public = p.public_data.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let public_ptr =
                if public.is_empty() { std::ptr::null_mut() } else { public.as_mut_ptr() };
            let ecdh = Box::new(cryptoki_sys::CK_ECDH1_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ecdh, |b| {
                FfiParamBacking::Ecdh1(b, shared, public)
            }))
        }

        // -- AES-CTR: scalar + fixed 16-byte counter block ------------------
        CkMechanismParams::AesCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let ctr = Box::new(cryptoki_sys::CK_AES_CTR_PARAMS {
                ulCounterBits: narrow_wire_ulong(p.counter_bits)?,
                cb,
            });
            Ok(FfiMechanism::from_box(mech_type, ctr, FfiParamBacking::AesCtr))
        }

        // -- Camellia-CTR: scalar + fixed 16-byte counter block -------------
        CkMechanismParams::CamelliaCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let ctr = Box::new(cryptoki_sys::CK_CAMELLIA_CTR_PARAMS {
                ulCounterBits: narrow_wire_ulong(p.counter_bits)?,
                cb,
            });
            Ok(FfiMechanism::from_box(mech_type, ctr, FfiParamBacking::CamelliaCtr))
        }

        // -- RC2-CBC: scalar + fixed 8-byte IV ------------------------------
        CkMechanismParams::Rc2Cbc(p) => {
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let rc2 = Box::new(cryptoki_sys::CK_RC2_CBC_PARAMS {
                ulEffectiveBits: narrow_wire_ulong(p.effective_bits)?,
                iv,
            });
            Ok(FfiMechanism::from_box(mech_type, rc2, FfiParamBacking::Rc2Cbc))
        }

        // -- RC5-CBC: scalars + pointer to IV -------------------------------
        CkMechanismParams::Rc5Cbc(p) => {
            let mut iv_buf = p.iv.clone();
            let iv_ptr = if iv_buf.is_empty() { std::ptr::null_mut() } else { iv_buf.as_mut_ptr() };
            let rc5 = Box::new(cryptoki_sys::CK_RC5_CBC_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
                pIv: iv_ptr,
                ulIvLen: iv_buf.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5, |b| FfiParamBacking::Rc5Cbc(b, iv_buf)))
        }

        // -- Trivial scalar-only structs ------------------------------------
        CkMechanismParams::Rc5(p) => {
            let rc5 = Box::new(cryptoki_sys::CK_RC5_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5, FfiParamBacking::Rc5))
        }

        CkMechanismParams::Rc5MacGeneral(p) => {
            let rc5mg = Box::new(cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5mg, FfiParamBacking::Rc5MacGeneral))
        }

        CkMechanismParams::Rc2MacGeneral(p) => {
            let rc2mg = Box::new(cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS {
                ulEffectiveBits: narrow_wire_ulong(p.effective_bits)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc2mg, FfiParamBacking::Rc2MacGeneral))
        }

        CkMechanismParams::Xeddsa(p) => {
            let xed = Box::new(cryptoki_sys::CK_XEDDSA_PARAMS { hash: narrow_wire_ulong(p.hash)? });
            Ok(FfiMechanism::from_box(mech_type, xed, FfiParamBacking::Xeddsa))
        }

        CkMechanismParams::TlsMac(p) => {
            let tls = Box::new(cryptoki_sys::CK_TLS_MAC_PARAMS {
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
                ulServerOrClient: narrow_wire_ulong(p.server_or_client)?,
            });
            Ok(FfiMechanism::from_box(mech_type, tls, FfiParamBacking::TlsMac))
        }

        // -- CBC encrypt data variants (fixed IV + pointer to data) ---------
        CkMechanismParams::AesCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::AesCbcEncryptData(b, data)
            }))
        }

        CkMechanismParams::DesCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::DesCbcEncryptData(b, data)
            }))
        }

        CkMechanismParams::AriaCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::AriaCbcEncryptData(b, data)
            }))
        }

        CkMechanismParams::CamelliaCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::CamelliaCbcEncryptData(b, data)
            }))
        }

        CkMechanismParams::SeedCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::SeedCbcEncryptData(b, data)
            }))
        }

        // -- HKDF: struct with pointers to salt and info --------------------
        CkMechanismParams::Hkdf(p) => {
            let mut salt = p.salt.clone();
            let mut info = p.info.clone();
            let salt_ptr = if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() };
            let info_ptr = if info.is_empty() { std::ptr::null_mut() } else { info.as_mut_ptr() };
            let hkdf = Box::new(cryptoki_sys::CK_HKDF_PARAMS {
                bExtract: if p.extract { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                bExpand: if p.expand { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism)?,
                ulSaltType: narrow_wire_ulong(p.salt_type)?,
                pSalt: salt_ptr,
                ulSaltLen: salt.len() as cryptoki_sys::CK_ULONG,
                hSaltKey: narrow_wire_ulong(p.salt_key_handle)?,
                pInfo: info_ptr,
                ulInfoLen: info.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, hkdf, |b| FfiParamBacking::Hkdf(b, salt, info)))
        }

        // -- EdDSA: struct with pointer to context data ---------------------
        CkMechanismParams::Eddsa(p) => {
            let mut ctx = p.context_data.clone();
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let eddsa = Box::new(cryptoki_sys::CK_EDDSA_PARAMS {
                phFlag: if p.ph_flag { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulContextDataLen: ctx.len() as cryptoki_sys::CK_ULONG,
                pContextData: ctx_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, eddsa, |b| FfiParamBacking::Eddsa(b, ctx)))
        }

        // -- GCM Wrap: struct with pointers to IV and AAD -------------------
        CkMechanismParams::GcmWrap(p) => {
            let mut iv = p.iv.clone();
            let mut aad = p.aad.clone();
            let iv_ptr = if iv.is_empty() { std::ptr::null_mut() } else { iv.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let gw = Box::new(cryptoki_sys::CK_GCM_WRAP_PARAMS {
                pIv: iv_ptr,
                ulIvLen: iv.len() as cryptoki_sys::CK_ULONG,
                ulIvFixedBits: narrow_wire_ulong(p.iv_fixed_bits)?,
                ivGenerator: narrow_wire_ulong(p.iv_generator)?,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulTagBits: narrow_wire_ulong(p.tag_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gw, |b| FfiParamBacking::GcmWrap(b, iv, aad)))
        }

        // -- CCM Wrap: struct with pointers to nonce and AAD ----------------
        CkMechanismParams::CcmWrap(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let cw = Box::new(cryptoki_sys::CK_CCM_WRAP_PARAMS {
                ulDataLen: narrow_wire_ulong(p.data_len)?,
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                ulNonceFixedBits: narrow_wire_ulong(p.nonce_fixed_bits)?,
                nonceGenerator: narrow_wire_ulong(p.nonce_generator)?,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulMACLen: narrow_wire_ulong(p.mac_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, cw, |b| FfiParamBacking::CcmWrap(b, nonce, aad)))
        }

        // -- ChaCha20: struct with pointers to block counter and nonce ------
        CkMechanismParams::ChaCha20(p) => {
            let mut bc = p.block_counter.clone();
            let mut nonce = p.nonce.clone();
            let bc_ptr = if bc.is_empty() { std::ptr::null_mut() } else { bc.as_mut_ptr() };
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let ch = Box::new(cryptoki_sys::CK_CHACHA20_PARAMS {
                pBlockCounter: bc_ptr,
                blockCounterBits: narrow_wire_ulong(p.block_counter_bits)?,
                pNonce: nonce_ptr,
                ulNonceBits: narrow_wire_ulong(p.nonce_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ch, |b| FfiParamBacking::ChaCha20(b, bc, nonce)))
        }

        // -- Salsa20: struct with pointers to block counter and nonce -------
        CkMechanismParams::Salsa20(p) => {
            let mut bc = p.block_counter.clone();
            let mut nonce = p.nonce.clone();
            let bc_ptr = if bc.is_empty() { std::ptr::null_mut() } else { bc.as_mut_ptr() };
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let sa = Box::new(cryptoki_sys::CK_SALSA20_PARAMS {
                pBlockCounter: bc_ptr,
                pNonce: nonce_ptr,
                ulNonceBits: narrow_wire_ulong(p.nonce_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, sa, |b| FfiParamBacking::Salsa20(b, bc, nonce)))
        }

        // -- Salsa20/ChaCha20-Poly1305: struct with pointers to nonce + AAD -
        CkMechanismParams::Salsa20ChaCha20Poly1305(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let sp = Box::new(cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS {
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Salsa20ChaCha20Poly1305(b, nonce, aad)
            }))
        }

        // -- MacGeneral: single CK_ULONG -----------------------------------
        CkMechanismParams::MacGeneral(p) => {
            let val = narrow_wire_ulong(p.mac_length)?;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Bytes(buf)))
        }

        // -- Extract: single CK_ULONG bit position --------------------------
        CkMechanismParams::Extract(p) => {
            let val = narrow_wire_ulong(p.bit_position)?;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Bytes(buf)))
        }

        // -- KeyDerivationStringData: struct with pointer to data -----------
        CkMechanismParams::KeyDerivationString(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let kds = Box::new(cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA {
                pData: data_ptr,
                ulLen: data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, kds, |b| {
                FfiParamBacking::KeyDerivationString(b, data)
            }))
        }

        // -- RSA-AES key wrap: nested OAEP params pointer ---------------------
        CkMechanismParams::RsaAesKeyWrap(p) => {
            // Build the nested OAEP params first (same pattern as the Oaep arm)
            let mut source_data = p.oaep_params.source_data.clone();
            let (src_ptr, src_len) = if source_data.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (source_data.as_mut_ptr() as *mut std::ffi::c_void, source_data.len())
            };
            let mut oaep = Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: narrow_wire_ulong(p.oaep_params.hash_alg.0)?,
                mgf: narrow_wire_ulong(p.oaep_params.mgf)?,
                source: narrow_wire_ulong(p.oaep_params.source)?,
                pSourceData: src_ptr,
                ulSourceDataLen: src_len as cryptoki_sys::CK_ULONG,
            });
            let oaep_ptr = &mut *oaep as *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS;

            let wrap = Box::new(FfiRsaAesKeyWrapParams {
                ul_aes_key_bits: narrow_wire_ulong(p.aes_key_bits)?,
                p_oaep_params: oaep_ptr,
            });
            // C3M.2: project the outer root from the persistent allocation,
            // never from a reborrow of the moved box.
            let wrap_allocation = NativeAllocation::from_box(wrap);
            let ptr = wrap_allocation.root() as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiRsaAesKeyWrapParams>();
            Ok(FfiMechanism::with_param(
                mech_type,
                ptr,
                len,
                FfiParamBacking::RsaAesKeyWrap(wrap_allocation, oaep, source_data),
            ))
        }

        // -- ObjectHandle: single CK_OBJECT_HANDLE ----------------------------
        CkMechanismParams::ObjectHandle(p) => {
            let val = narrow_wire_ulong(p.handle)?;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Bytes(buf)))
        }

        // -- SignAdditionalContext: CK_SIGN_ADDITIONAL_CONTEXT (hash == 0) or
        //    CK_HASH_SIGN_ADDITIONAL_CONTEXT (hash != 0, generic CKM_HASH_*_DSA).
        //    `from_box` sets the exact ulParameterLen from the chosen struct.
        CkMechanismParams::SignAdditionalContext(p) => {
            let mut ctx = p.context.clone();
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let hedge = narrow_wire_ulong(p.hedge_variant)?;
            let ctx_len = ctx.len() as cryptoki_sys::CK_ULONG;
            if p.hash == 0 {
                let sac = Box::new(FfiSignAdditionalContext {
                    hedge_variant: hedge,
                    p_context: ctx_ptr,
                    ul_context_len: ctx_len,
                });
                Ok(FfiMechanism::from_box(mech_type, sac, |b| {
                    FfiParamBacking::SignAdditionalContext(b, ctx)
                }))
            } else {
                let sac = Box::new(FfiHashSignAdditionalContext {
                    hedge_variant: hedge,
                    p_context: ctx_ptr,
                    ul_context_len: ctx_len,
                    hash: narrow_wire_ulong(p.hash)?,
                });
                Ok(FfiMechanism::from_box(mech_type, sac, |b| {
                    FfiParamBacking::HashSignAdditionalContext(b, ctx)
                }))
            }
        }

        // -- KMAC: CK_KMAC_PARAMS -----------------------------------------
        CkMechanismParams::Kmac(p) => {
            let mut customization_string = p.customization_string.clone();
            let customization_ptr = if customization_string.is_empty() {
                std::ptr::null_mut()
            } else {
                customization_string.as_mut_ptr() as cryptoki_sys::CK_VOID_PTR
            };
            let kmac = Box::new(FfiKmacParams {
                h_key: narrow_wire_ulong(p.key_handle)?,
                ul_mac_length: narrow_wire_ulong(p.mac_length)?,
                p_customization_string: customization_ptr,
                ul_customization_string_len: customization_string.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, kmac, |b| {
                FfiParamBacking::Kmac(b, customization_string)
            }))
        }

        // -- ML-DSA external mu generation: CK_MU_GEN_PARAMS ---------------
        CkMechanismParams::MuGen(p) => {
            let mut tr = p.tr.clone();
            let mut ctx = p.context.clone();
            let tr_ptr = if tr.is_empty() { std::ptr::null_mut() } else { tr.as_mut_ptr() };
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let mu_gen = Box::new(FfiMuGenParams {
                h_key: narrow_wire_ulong(p.key_handle)?,
                p_tr: tr_ptr,
                ul_tr_len: tr.len() as cryptoki_sys::CK_ULONG,
                p_ctx: ctx_ptr,
                ul_ctx_len: ctx.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, mu_gen, |b| FfiParamBacking::MuGen(b, tr, ctx)))
        }

        // -- Raw: reject at FFI boundary to prevent SIGSEGV ------------------
        // Raw bytes may contain stale pointer values from the client process.
        // If the backend interprets them as a C struct with embedded pointers
        // (e.g., CK_ECDH1_DERIVE_PARAMS.pPublicData), it will dereference
        // garbage addresses and segfault. Safe mechanisms are modeled with
        // explicit parameter shapes that properly serialize pointer-bearing
        // fields. Unknown mechanisms must be added to the TOML registry.
        CkMechanismParams::Raw(_) => Err(CkRv::MECHANISM_PARAM_INVALID),

        // -- Unsupported variants: reject at the FFI boundary ---------------
        // These require nested CK_MECHANISM pointers, complex multi-struct
        // -- TLS 1.2 Master Key Derive: nested SSL3_RANDOM_DATA + pVersion ---
        CkMechanismParams::Tls12MasterKeyDerive(p) => {
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            // pVersion = NULL for DH variants (version is 0.0 sentinel)
            let version_is_null = p.version_major == 0 && p.version_minor == 0;
            let mut version = Box::new(cryptoki_sys::CK_VERSION {
                major: p.version_major as cryptoki_sys::CK_BYTE,
                minor: p.version_minor as cryptoki_sys::CK_BYTE,
            });
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let version_ptr =
                if version_is_null { std::ptr::null_mut() } else { &mut *version as *mut _ };
            let tls12 = Box::new(cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pVersion: version_ptr,
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism)?,
            });
            Ok(FfiMechanism::from_box(mech_type, tls12, |b| {
                FfiParamBacking::Tls12MasterKeyDerive(b, client_random, server_random, version)
            }))
        }

        // -- PKCS#5 PBKDF2: struct with 3 embedded pointers ----------------
        CkMechanismParams::Pkcs5Pbkd2(p) => {
            let mut salt = p.salt_source_data.clone();
            let mut prf_data = p.prf_data.clone();
            let mut password = Zeroizing::new(p.password.clone());
            let salt_ptr =
                if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() as *mut _ };
            let prf_ptr = if prf_data.is_empty() {
                std::ptr::null_mut()
            } else {
                prf_data.as_mut_ptr() as *mut _
            };
            let pass_ptr =
                if password.is_empty() { std::ptr::null_mut() } else { password.as_mut_ptr() };
            let pbkd2 = Box::new(cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2 {
                saltSource: narrow_wire_ulong(p.salt_source)?,
                pSaltSourceData: salt_ptr,
                ulSaltSourceDataLen: salt.len() as cryptoki_sys::CK_ULONG,
                iterations: narrow_wire_ulong(p.iterations)?,
                prf: narrow_wire_ulong(p.prf)?,
                pPrfData: prf_ptr,
                ulPrfDataLen: prf_data.len() as cryptoki_sys::CK_ULONG,
                pPassword: pass_ptr,
                ulPasswordLen: password.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, pbkd2, |b| {
                FfiParamBacking::Pkcs5Pbkd2(b, salt, prf_data, password)
            }))
        }

        // -- TLS PRF: struct with 4 pointers (seed, label, output, outputLen) --
        CkMechanismParams::TlsPrf(p) => {
            let mut seed = p.seed.clone();
            let mut label = p.label.clone();
            let mut output = vec![0u8; p.output_len as usize];
            let mut output_len = Box::new(narrow_wire_ulong(p.output_len)?);
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let label_ptr =
                if label.is_empty() { std::ptr::null_mut() } else { label.as_mut_ptr() };
            let output_ptr =
                if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr() };
            let tls = Box::new(cryptoki_sys::CK_TLS_PRF_PARAMS {
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
                pLabel: label_ptr,
                ulLabelLen: label.len() as cryptoki_sys::CK_ULONG,
                pOutput: output_ptr,
                pulOutputLen: &mut *output_len as *mut _,
            });
            Ok(FfiMechanism::from_box(mech_type, tls, |b| {
                FfiParamBacking::TlsPrf(b, seed, label, output, output_len)
            }))
        }

        // -- TLS KDF: PRF mechanism + label + nested SSL3_RANDOM_DATA + context --
        CkMechanismParams::TlsKdf(p) => {
            let mut label = p.label.clone();
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            let mut context_data = p.context_data.clone();
            let label_ptr =
                if label.is_empty() { std::ptr::null_mut() } else { label.as_mut_ptr() };
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let ctx_ptr = if context_data.is_empty() {
                std::ptr::null_mut()
            } else {
                context_data.as_mut_ptr()
            };
            let tls = Box::new(cryptoki_sys::CK_TLS_KDF_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism)?,
                pLabel: label_ptr,
                ulLabelLength: label.len() as cryptoki_sys::CK_ULONG,
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pContextData: ctx_ptr,
                ulContextDataLength: context_data.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, tls, |b| {
                FfiParamBacking::TlsKdf(b, label, client_random, server_random, context_data)
            }))
        }

        // -- SSL3 Master Key Derive: nested SSL3_RANDOM_DATA + pVersion ----------
        CkMechanismParams::Ssl3MasterKeyDerive(p) => {
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            let version_is_null = p.version_major == 0 && p.version_minor == 0;
            let mut version = Box::new(cryptoki_sys::CK_VERSION {
                major: p.version_major as cryptoki_sys::CK_BYTE,
                minor: p.version_minor as cryptoki_sys::CK_BYTE,
            });
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let ssl3 = Box::new(cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pVersion: if version_is_null {
                    std::ptr::null_mut()
                } else {
                    &mut *version as *mut _
                },
            });
            Ok(FfiMechanism::from_box(mech_type, ssl3, |b| {
                FfiParamBacking::Ssl3MasterKeyDerive(b, client_random, server_random, version)
            }))
        }

        // -- TLS 1.2 Extended Master Key Derive: PRF + session hash + pVersion ----
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(p) => {
            let mut session_hash = p.session_hash.clone();
            let version_is_null = p.version_major == 0 && p.version_minor == 0;
            let mut version = Box::new(cryptoki_sys::CK_VERSION {
                major: p.version_major as cryptoki_sys::CK_BYTE,
                minor: p.version_minor as cryptoki_sys::CK_BYTE,
            });
            let hash_ptr = if session_hash.is_empty() {
                std::ptr::null_mut()
            } else {
                session_hash.as_mut_ptr()
            };
            let version_ptr =
                if version_is_null { std::ptr::null_mut() } else { &mut *version as *mut _ };
            let ext = Box::new(cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism)?,
                pSessionHash: hash_ptr,
                ulSessionHashLen: session_hash.len() as cryptoki_sys::CK_ULONG,
                pVersion: version_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ext, |b| {
                FfiParamBacking::Tls12ExtendedMasterKeyDerive(b, session_hash, version)
            }))
        }

        // -- SSL3/TLS Key Mat: nested random data + output key material -----------
        CkMechanismParams::Ssl3KeyMat(p) => {
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let iv_bytes = ((p.iv_size_bits as usize).saturating_add(7)) / 8;
            let mut iv_client = if p.client_iv.is_empty() {
                vec![0u8; iv_bytes]
            } else {
                let mut iv = p.client_iv.clone();
                iv.resize(iv_bytes, 0);
                iv
            };
            let mut iv_server = if p.server_iv.is_empty() {
                vec![0u8; iv_bytes]
            } else {
                let mut iv = p.server_iv.clone();
                iv.resize(iv_bytes, 0);
                iv
            };
            let iv_client_ptr =
                if iv_client.is_empty() { std::ptr::null_mut() } else { iv_client.as_mut_ptr() };
            let iv_server_ptr =
                if iv_server.is_empty() { std::ptr::null_mut() } else { iv_server.as_mut_ptr() };
            let mut key_mat_out = Box::new(cryptoki_sys::CK_SSL3_KEY_MAT_OUT {
                hClientMacSecret: narrow_wire_ulong(p.client_mac_secret_handle)?,
                hServerMacSecret: narrow_wire_ulong(p.server_mac_secret_handle)?,
                hClientKey: narrow_wire_ulong(p.client_key_handle)?,
                hServerKey: narrow_wire_ulong(p.server_key_handle)?,
                pIVClient: iv_client_ptr,
                pIVServer: iv_server_ptr,
            });
            // Decide whether to use SSL3 or TLS12 key mat based on prf_hash_mechanism:
            // if prf_hash_mechanism == 0, use CK_SSL3_KEY_MAT_PARAMS; else TLS12.
            if p.prf_hash_mechanism == 0 {
                let km = Box::new(cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS {
                    ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                    ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                    ulIVSizeInBits: narrow_wire_ulong(p.iv_size_bits)?,
                    bIsExport: if p.is_export {
                        cryptoki_sys::CK_TRUE
                    } else {
                        cryptoki_sys::CK_FALSE
                    },
                    RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                        pClientRandom: client_ptr,
                        ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                        pServerRandom: server_ptr,
                        ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                    },
                    pReturnedKeyMaterial: &mut *key_mat_out as *mut _,
                });
                Ok(FfiMechanism::from_box(mech_type, km, |b| {
                    FfiParamBacking::Ssl3KeyMat(
                        b,
                        client_random,
                        server_random,
                        key_mat_out,
                        iv_client,
                        iv_server,
                    )
                }))
            } else {
                // TLS12 variant: uses CK_TLS12_KEY_MAT_PARAMS (superset of SSL3)
                let km = Box::new(cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS {
                    ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                    ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                    ulIVSizeInBits: narrow_wire_ulong(p.iv_size_bits)?,
                    bIsExport: if p.is_export {
                        cryptoki_sys::CK_TRUE
                    } else {
                        cryptoki_sys::CK_FALSE
                    },
                    RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                        pClientRandom: client_ptr,
                        ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                        pServerRandom: server_ptr,
                        ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                    },
                    pReturnedKeyMaterial: &mut *key_mat_out as *mut _,
                    prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism)?,
                });
                Ok(FfiMechanism::from_box(mech_type, km, |b| {
                    FfiParamBacking::Tls12KeyMat(
                        b,
                        client_random,
                        server_random,
                        key_mat_out,
                        iv_client,
                        iv_server,
                    )
                }))
            }
        }

        // -- PBE: struct with 3 pointers (init_vector, password, salt) -----------
        CkMechanismParams::Pbe(p) => {
            let mut init_vector = p.init_vector.clone();
            let mut password = Zeroizing::new(p.password.clone());
            let mut salt = p.salt.clone();
            let iv_ptr = if init_vector.is_empty() {
                std::ptr::null_mut()
            } else {
                init_vector.as_mut_ptr()
            };
            let pass_ptr =
                if password.is_empty() { std::ptr::null_mut() } else { password.as_mut_ptr() };
            let salt_ptr = if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() };
            let pbe = Box::new(cryptoki_sys::CK_PBE_PARAMS {
                pInitVector: iv_ptr,
                pPassword: pass_ptr,
                ulPasswordLen: password.len() as cryptoki_sys::CK_ULONG,
                pSalt: salt_ptr,
                ulSaltLen: salt.len() as cryptoki_sys::CK_ULONG,
                ulIteration: narrow_wire_ulong(p.iteration)?,
            });
            Ok(FfiMechanism::from_box(mech_type, pbe, |b| {
                FfiParamBacking::Pbe(b, init_vector, password, salt)
            }))
        }

        // -- ECDH-AES Key Wrap: struct with 1 pointer ---------------------------
        CkMechanismParams::EcdhAesKeyWrap(p) => {
            let mut shared = p.shared_data.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let ew = Box::new(cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS {
                ulAESKeyBits: narrow_wire_ulong(p.aes_key_bits)?,
                kdf: narrow_wire_ulong(p.kdf)?,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ew, |b| {
                FfiParamBacking::EcdhAesKeyWrap(b, shared)
            }))
        }

        // -- ECDH2 Derive: struct with 3 pointers -------------------------------
        CkMechanismParams::Ecdh2Derive(p) => {
            let mut shared = p.shared_data.clone();
            let mut public = p.public_data.clone();
            let mut public2 = p.public_data2.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let public_ptr =
                if public.is_empty() { std::ptr::null_mut() } else { public.as_mut_ptr() };
            let public2_ptr =
                if public2.is_empty() { std::ptr::null_mut() } else { public2.as_mut_ptr() };
            let ecdh2 = Box::new(cryptoki_sys::CK_ECDH2_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle)?,
                ulPublicDataLen2: public2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: public2_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ecdh2, |b| {
                FfiParamBacking::Ecdh2Derive(b, shared, public, public2)
            }))
        }

        // -- ECMQV Derive: struct with 3 pointers + handle ---------------------
        CkMechanismParams::EcmqvDerive(p) => {
            let mut shared = p.shared_data.clone();
            let mut public = p.public_data.clone();
            let mut public2 = p.public_data2.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let public_ptr =
                if public.is_empty() { std::ptr::null_mut() } else { public.as_mut_ptr() };
            let public2_ptr =
                if public2.is_empty() { std::ptr::null_mut() } else { public2.as_mut_ptr() };
            let ecmqv = Box::new(cryptoki_sys::CK_ECMQV_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle)?,
                ulPublicDataLen2: public2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: public2_ptr,
                publicKey: narrow_wire_ulong(p.public_key_handle)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ecmqv, |b| {
                FfiParamBacking::EcmqvDerive(b, shared, public, public2)
            }))
        }

        // -- X9.42 DH1 Derive: struct with 2 pointers ---------------------------
        CkMechanismParams::X942Dh1Derive(p) => {
            let mut other_info = p.other_info.clone();
            let mut public_data = p.public_data.clone();
            let oi_ptr =
                if other_info.is_empty() { std::ptr::null_mut() } else { other_info.as_mut_ptr() };
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            let x942 = Box::new(cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                pOtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pPublicData: pub_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942Dh1Derive(b, other_info, public_data)
            }))
        }

        // -- X9.42 DH2 Derive: struct with 3 pointers + handle ------------------
        CkMechanismParams::X942Dh2Derive(p) => {
            let mut other_info = p.other_info.clone();
            let mut public_data = p.public_data.clone();
            let mut public_data2 = p.public_data2.clone();
            let oi_ptr =
                if other_info.is_empty() { std::ptr::null_mut() } else { other_info.as_mut_ptr() };
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            let pub2_ptr = if public_data2.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data2.as_mut_ptr()
            };
            let x942 = Box::new(cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                pOtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pPublicData: pub_ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle)?,
                ulPublicDataLen2: public_data2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: pub2_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942Dh2Derive(b, other_info, public_data, public_data2)
            }))
        }

        // -- X9.42 MQV Derive: struct with 3 pointers + 2 handles ---------------
        CkMechanismParams::X942MqvDerive(p) => {
            let mut other_info = p.other_info.clone();
            let mut public_data = p.public_data.clone();
            let mut public_data2 = p.public_data2.clone();
            let oi_ptr =
                if other_info.is_empty() { std::ptr::null_mut() } else { other_info.as_mut_ptr() };
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            let pub2_ptr = if public_data2.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data2.as_mut_ptr()
            };
            let x942 = Box::new(cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                OtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                PublicData: pub_ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle)?,
                ulPublicDataLen2: public_data2.len() as cryptoki_sys::CK_ULONG,
                PublicData2: pub2_ptr,
                publicKey: narrow_wire_ulong(p.public_key_handle)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942MqvDerive(b, other_info, public_data, public_data2)
            }))
        }

        // -- GOSTR3410 Derive: struct with 2 pointers ---------------------------
        CkMechanismParams::Gostr3410Derive(p) => {
            let mut public_data = p.public_data.clone();
            let mut ukm = p.ukm.clone();
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            let ukm_ptr = if ukm.is_empty() { std::ptr::null_mut() } else { ukm.as_mut_ptr() };
            let gost = Box::new(cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                pPublicData: pub_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pUKM: ukm_ptr,
                ulUKMLen: ukm.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, gost, |b| {
                FfiParamBacking::Gostr3410Derive(b, public_data, ukm)
            }))
        }

        // -- GOSTR3410 Key Wrap: struct with 2 pointers + handle ----------------
        CkMechanismParams::Gostr3410KeyWrap(p) => {
            let mut wrap_oid = p.wrap_oid.clone();
            let mut ukm = p.ukm.clone();
            let oid_ptr =
                if wrap_oid.is_empty() { std::ptr::null_mut() } else { wrap_oid.as_mut_ptr() };
            let ukm_ptr = if ukm.is_empty() { std::ptr::null_mut() } else { ukm.as_mut_ptr() };
            let gost = Box::new(cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS {
                pWrapOID: oid_ptr,
                ulWrapOIDLen: wrap_oid.len() as cryptoki_sys::CK_ULONG,
                pUKM: ukm_ptr,
                ulUKMLen: ukm.len() as cryptoki_sys::CK_ULONG,
                hKey: narrow_wire_ulong(p.key_handle)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gost, |b| {
                FfiParamBacking::Gostr3410KeyWrap(b, wrap_oid, ukm)
            }))
        }

        // -- Key Wrap Set OAEP: struct with 1 pointer ---------------------------
        CkMechanismParams::KeyWrapSetOaep(p) => {
            let mut x = p.x.clone();
            let x_ptr = if x.is_empty() { std::ptr::null_mut() } else { x.as_mut_ptr() };
            let kw = Box::new(cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS {
                bBC: p.bc as cryptoki_sys::CK_BYTE,
                pX: x_ptr,
                ulXLen: x.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, kw, |b| FfiParamBacking::KeyWrapSetOaep(b, x)))
        }

        // -- KEA Derive: struct with 3 pointers ---------------------------------
        CkMechanismParams::KeaDerive(p) => {
            let mut random_a = p.random_a.clone();
            let mut random_b = p.random_b.clone();
            let mut public_data = p.public_data.clone();
            let ra_ptr =
                if random_a.is_empty() { std::ptr::null_mut() } else { random_a.as_mut_ptr() };
            let rb_ptr =
                if random_b.is_empty() { std::ptr::null_mut() } else { random_b.as_mut_ptr() };
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            // KEA random_a and random_b must have the same length (ulRandomLen)
            let random_len = random_a.len() as cryptoki_sys::CK_ULONG;
            let kea = Box::new(cryptoki_sys::CK_KEA_DERIVE_PARAMS {
                isSender: if p.is_sender { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulRandomLen: random_len,
                RandomA: ra_ptr,
                RandomB: rb_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                PublicData: pub_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, kea, |b| {
                FfiParamBacking::KeaDerive(b, random_a, random_b, public_data)
            }))
        }

        // -- IKE PRF Derive: struct with 2 pointers -----------------------------
        CkMechanismParams::IkePrfDerive(p) => {
            let mut ni = p.ni.clone();
            let mut nr = p.nr.clone();
            let ni_ptr = if ni.is_empty() { std::ptr::null_mut() } else { ni.as_mut_ptr() };
            let nr_ptr = if nr.is_empty() { std::ptr::null_mut() } else { nr.as_mut_ptr() };
            let ike = Box::new(cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism)?,
                bDataAsKey: if p.data_as_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                bRekey: if p.rekey { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                pNi: ni_ptr,
                ulNiLen: ni.len() as cryptoki_sys::CK_ULONG,
                pNr: nr_ptr,
                ulNrLen: nr.len() as cryptoki_sys::CK_ULONG,
                hNewKey: narrow_wire_ulong(p.new_key_handle)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| FfiParamBacking::IkePrfDerive(b, ni, nr)))
        }

        // -- IKE1 PRF Derive: struct with 2 pointers + handles ------------------
        CkMechanismParams::Ike1PrfDerive(p) => {
            let mut ckyi = p.ckyi.clone();
            let mut ckyr = p.ckyr.clone();
            let ckyi_ptr = if ckyi.is_empty() { std::ptr::null_mut() } else { ckyi.as_mut_ptr() };
            let ckyr_ptr = if ckyr.is_empty() { std::ptr::null_mut() } else { ckyr.as_mut_ptr() };
            let ike = Box::new(cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism)?,
                bHasPrevKey: if p.has_prev_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: narrow_wire_ulong(p.keygxy_handle)?,
                hPrevKey: narrow_wire_ulong(p.prev_key_handle)?,
                pCKYi: ckyi_ptr,
                ulCKYiLen: ckyi.len() as cryptoki_sys::CK_ULONG,
                pCKYr: ckyr_ptr,
                ulCKYrLen: ckyr.len() as cryptoki_sys::CK_ULONG,
                keyNumber: p.key_number as cryptoki_sys::CK_BYTE,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike1PrfDerive(b, ckyi, ckyr)
            }))
        }

        // -- IKE1 Extended Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike1ExtendedDerive(p) => {
            let mut extra = p.extra_data.clone();
            let extra_ptr =
                if extra.is_empty() { std::ptr::null_mut() } else { extra.as_mut_ptr() };
            let ike = Box::new(cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism)?,
                bHasKeygxy: if p.has_keygxy {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: narrow_wire_ulong(p.keygxy_handle)?,
                pExtraData: extra_ptr,
                ulExtraDataLen: extra.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike1ExtendedDerive(b, extra)
            }))
        }

        // -- IKE2 PRF Plus Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike2PrfPlusDerive(p) => {
            let mut seed = p.seed_data.clone();
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let ike = Box::new(cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism)?,
                bHasSeedKey: if p.has_seed_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hSeedKey: narrow_wire_ulong(p.seed_key_handle)?,
                pSeedData: seed_ptr,
                ulSeedDataLen: seed.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike2PrfPlusDerive(b, seed)
            }))
        }

        // -- WTLS Master Key Derive: digest mechanism + WTLS random data + pVersion --
        CkMechanismParams::WtlsMasterKeyDerive(p) => {
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            let mut version_buf = vec![p.version as u8];
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let wtls = Box::new(cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism)?,
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pVersion: version_buf.as_mut_ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsMasterKeyDerive(b, client_random, server_random, version_buf)
            }))
        }

        // -- WTLS PRF: digest mechanism + seed + label + output -----------------
        CkMechanismParams::WtlsPrf(p) => {
            let mut seed = p.seed.clone();
            let mut label = p.label.clone();
            let mut output = vec![0u8; p.output_len as usize];
            let mut output_len = Box::new(narrow_wire_ulong(p.output_len)?);
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let label_ptr =
                if label.is_empty() { std::ptr::null_mut() } else { label.as_mut_ptr() };
            let output_ptr =
                if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr() };
            let wtls = Box::new(cryptoki_sys::CK_WTLS_PRF_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism)?,
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
                pLabel: label_ptr,
                ulLabelLen: label.len() as cryptoki_sys::CK_ULONG,
                pOutput: output_ptr,
                pulOutputLen: &mut *output_len as *mut _,
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsPrf(b, seed, label, output, output_len)
            }))
        }

        // -- WTLS Key Mat: digest mechanism + nested random data + output -------
        CkMechanismParams::WtlsKeyMat(p) => {
            let mut client_random = p.random_info.client_random.clone();
            let mut server_random = p.random_info.server_random.clone();
            let client_ptr = if client_random.is_empty() {
                std::ptr::null_mut()
            } else {
                client_random.as_mut_ptr()
            };
            let server_ptr = if server_random.is_empty() {
                std::ptr::null_mut()
            } else {
                server_random.as_mut_ptr()
            };
            let iv_bytes = ((p.iv_size_bits as usize).saturating_add(7)) / 8;
            let mut iv_buf = if p.iv.is_empty() {
                vec![0u8; iv_bytes]
            } else {
                let mut iv = p.iv.clone();
                iv.resize(iv_bytes, 0);
                iv
            };
            let iv_ptr = if iv_buf.is_empty() { std::ptr::null_mut() } else { iv_buf.as_mut_ptr() };
            let mut kmo = Box::new(cryptoki_sys::CK_WTLS_KEY_MAT_OUT {
                hMacSecret: narrow_wire_ulong(p.mac_secret_handle)?,
                hKey: narrow_wire_ulong(p.key_handle)?,
                pIV: iv_ptr,
            });
            let wtls = Box::new(cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism)?,
                ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                ulIVSizeInBits: narrow_wire_ulong(p.iv_size_bits)?,
                ulSequenceNumber: narrow_wire_ulong(p.sequence_number)?,
                bIsExport: if p.is_export { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pReturnedKeyMaterial: &mut *kmo as *mut _,
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsKeyMat(b, client_random, server_random, kmo, iv_buf)
            }))
        }

        // -- SP800-108 KDF: PRF type + data params array -------------------------
        CkMechanismParams::Sp800108Kdf(p) => {
            // Build CK_PRF_DATA_PARAM array and backing buffers
            let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(p.data_params.len());
            let mut c_params: Vec<cryptoki_sys::CK_PRF_DATA_PARAM> =
                Vec::with_capacity(p.data_params.len());
            for dp in &p.data_params {
                let mut buf = dp.value.clone();
                let buf_ptr = if buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr() as *mut std::ffi::c_void
                };
                c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: narrow_wire_ulong(dp.type_)?,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let data_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut derived_keys = FfiSp800108DerivedKeys::new(&p.additional_derived_keys)?;
            let sp = Box::new(cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: narrow_wire_ulong(p.prf_type)?,
                ulNumberOfDataParams: c_params.len() as cryptoki_sys::CK_ULONG,
                pDataParams: data_ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Sp800108Kdf(b, c_params, buffers, derived_keys)
            }))
        }

        // -- SP800-108 Feedback KDF: same + IV ----------------------------------
        CkMechanismParams::Sp800108FeedbackKdf(p) => {
            let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(p.data_params.len());
            let mut c_params: Vec<cryptoki_sys::CK_PRF_DATA_PARAM> =
                Vec::with_capacity(p.data_params.len());
            for dp in &p.data_params {
                let mut buf = dp.value.clone();
                let buf_ptr = if buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr() as *mut std::ffi::c_void
                };
                c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: narrow_wire_ulong(dp.type_)?,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let data_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut iv = p.iv.clone();
            let iv_ptr = if iv.is_empty() { std::ptr::null_mut() } else { iv.as_mut_ptr() };
            let mut derived_keys = FfiSp800108DerivedKeys::new(&p.additional_derived_keys)?;
            let sp = Box::new(cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
                prfType: narrow_wire_ulong(p.prf_type)?,
                ulNumberOfDataParams: c_params.len() as cryptoki_sys::CK_ULONG,
                pDataParams: data_ptr,
                ulIVLen: iv.len() as cryptoki_sys::CK_ULONG,
                pIV: iv_ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Sp800108FeedbackKdf(b, c_params, buffers, iv, derived_keys)
            }))
        }

        // -- X3DH Initiate: struct with 2 pointers + 4 handles ------------------
        CkMechanismParams::X3dhInitiate(p) => {
            let mut prekey_sig = p.prekey_signature.clone();
            let sig_ptr =
                if prekey_sig.is_empty() { std::ptr::null_mut() } else { prekey_sig.as_mut_ptr() };
            // pOnetime_key is a pointer in the C struct — but it represents an
            // object handle packed as a pointer. In PKCS#11, CK_X3DH_INITIATE_PARAMS
            // has pOnetime_key as *mut CK_BYTE. We pass the handle as a pointer.
            let mut onetime_buf = (narrow_wire_ulong(p.onetime_key_handle)?).to_ne_bytes().to_vec();
            let onetime_ptr = onetime_buf.as_mut_ptr();
            let x3dh = Box::new(cryptoki_sys::CK_X3DH_INITIATE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                pPeer_identity: narrow_wire_ulong(p.peer_identity_handle)?,
                pPeer_prekey: narrow_wire_ulong(p.peer_prekey_handle)?,
                pPrekey_signature: sig_ptr,
                pOnetime_key: onetime_ptr,
                pOwn_identity: narrow_wire_ulong(p.own_identity_handle)?,
                pOwn_ephemeral: narrow_wire_ulong(p.own_ephemeral_handle)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x3dh, |b| {
                FfiParamBacking::X3dhInitiate(b, prekey_sig, onetime_buf)
            }))
        }

        // -- X3DH Respond: struct with 4 pointers + 2 scalars -------------------
        CkMechanismParams::X3dhRespond(p) => {
            let mut identity_buf = (narrow_wire_ulong(p.identity_handle)?).to_ne_bytes().to_vec();
            let mut prekey_buf = (narrow_wire_ulong(p.prekey_handle)?).to_ne_bytes().to_vec();
            let mut onetime_buf = (narrow_wire_ulong(p.onetime_key_handle)?).to_ne_bytes().to_vec();
            // pInitiator_ephemeral is also a *mut CK_BYTE in the C struct
            let mut ephem_buf =
                (narrow_wire_ulong(p.initiator_ephemeral_handle)?).to_ne_bytes().to_vec();
            // All four buffers have their final size before pointer capture.
            // Each is retained unchanged in the owner until the native call ends.
            let x3dh = Box::new(cryptoki_sys::CK_X3DH_RESPOND_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                pIdentity_id: identity_buf.as_mut_ptr(),
                pPrekey_id: prekey_buf.as_mut_ptr(),
                pOnetime_id: onetime_buf.as_mut_ptr(),
                pInitiator_identity: narrow_wire_ulong(p.initiator_identity_handle)?,
                pInitiator_ephemeral: ephem_buf.as_mut_ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, x3dh, |b| {
                FfiParamBacking::X3dhRespond(b, identity_buf, prekey_buf, onetime_buf, ephem_buf)
            }))
        }

        // -- X2Ratchet Initialize: struct with 1 pointer + handles --------------
        CkMechanismParams::X2RatchetInitialize(p) => {
            let mut sk = p.sk.clone();
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let x2r = Box::new(cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS {
                sk: sk_ptr,
                peer_public_prekey: narrow_wire_ulong(p.peer_public_prekey_handle)?,
                peer_public_identity: narrow_wire_ulong(p.peer_public_identity_handle)?,
                own_public_identity: narrow_wire_ulong(p.own_public_identity_handle)?,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: narrow_wire_ulong(p.curve)?,
                aeadMechanism: narrow_wire_ulong(p.aead_mechanism)?,
                kdfMechanism: narrow_wire_ulong(p.kdf_mechanism)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x2r, |b| {
                FfiParamBacking::X2RatchetInitialize(b, sk)
            }))
        }

        // -- X2Ratchet Respond: struct with 1 pointer + handles -----------------
        CkMechanismParams::X2RatchetRespond(p) => {
            let mut sk = p.sk.clone();
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let x2r = Box::new(cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS {
                sk: sk_ptr,
                own_prekey: narrow_wire_ulong(p.own_prekey_handle)?,
                initiator_identity: narrow_wire_ulong(p.initiator_identity_handle)?,
                own_public_identity: narrow_wire_ulong(p.own_identity_handle)?,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: narrow_wire_ulong(p.curve)?,
                aeadMechanism: narrow_wire_ulong(p.aead_mechanism)?,
                kdfMechanism: narrow_wire_ulong(p.kdf_mechanism)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x2r, |b| FfiParamBacking::X2RatchetRespond(b, sk)))
        }

        // -- OTP: array of CK_OTP_PARAM ----------------------------------------
        CkMechanismParams::Otp(p) => {
            let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(p.params.len());
            let mut c_params: Vec<cryptoki_sys::CK_OTP_PARAM> = Vec::with_capacity(p.params.len());
            for op in &p.params {
                let mut buf = op.value.clone();
                let buf_ptr = if buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr() as *mut std::ffi::c_void
                };
                c_params.push(cryptoki_sys::CK_OTP_PARAM {
                    type_: narrow_wire_ulong(op.type_)?,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let params_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let otp = Box::new(cryptoki_sys::CK_OTP_PARAMS {
                pParams: params_ptr,
                ulCount: c_params.len() as cryptoki_sys::CK_ULONG,
            });
            Ok(FfiMechanism::from_box(mech_type, otp, |b| {
                FfiParamBacking::Otp(b, c_params, buffers)
            }))
        }

        // -- KIP: nested mechanism pointer + seed + handle ----------------------
        CkMechanismParams::Kip(p) => {
            let inner_ffi = mechanism_to_ffi(&p.mechanism)?;
            let mut inner_mech = Box::new(inner_ffi.ck_mechanism);
            let mut seed = p.seed.clone();
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let kip = Box::new(cryptoki_sys::CK_KIP_PARAMS {
                pMechanism: &mut *inner_mech as *mut _,
                hKey: narrow_wire_ulong(p.key_handle)?,
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
            });
            // Keep the inner mechanism's parameter backing alive by moving it
            // into the KIP backing, so any pointers the inner C struct holds
            // stay valid for the call and are freed afterwards (L8 — was a
            // mem::forget that leaked it permanently).
            Ok(FfiMechanism::from_box(mech_type, kip, |b| {
                FfiParamBacking::Kip(b, inner_mech, seed, Box::new(inner_ffi._backing))
            }))
        }

        // -- CMS Sig: nested mechanisms + content type + attribute buffers -------
        CkMechanismParams::CmsSig(p) => {
            let sign_ffi = mechanism_to_ffi(&p.signing_mechanism)?;
            let digest_ffi = mechanism_to_ffi(&p.digest_mechanism)?;
            let mut sign_mech = Box::new(sign_ffi.ck_mechanism);
            let mut digest_mech = Box::new(digest_ffi.ck_mechanism);
            let mut content_type = p.content_type.as_bytes().to_vec();
            content_type.push(0); // null-terminate
            let mut req_attrs = p.requested_attributes.clone();
            let mut reqd_attrs = p.required_attributes.clone();
            let ct_ptr = content_type.as_mut_ptr();
            let req_ptr =
                if req_attrs.is_empty() { std::ptr::null_mut() } else { req_attrs.as_mut_ptr() };
            let reqd_ptr =
                if reqd_attrs.is_empty() { std::ptr::null_mut() } else { reqd_attrs.as_mut_ptr() };
            let cms = Box::new(cryptoki_sys::CK_CMS_SIG_PARAMS {
                certificateHandle: narrow_wire_ulong(p.certificate_handle)?,
                pSigningMechanism: &mut *sign_mech as *mut _,
                pDigestMechanism: &mut *digest_mech as *mut _,
                pContentType: ct_ptr,
                pRequestedAttributes: req_ptr,
                ulRequestedAttributesLen: req_attrs.len() as cryptoki_sys::CK_ULONG,
                pRequiredAttributes: reqd_ptr,
                ulRequiredAttributesLen: reqd_attrs.len() as cryptoki_sys::CK_ULONG,
            });
            // Keep both inner mechanism backings alive by moving them into the
            // CmsSig backing (L8 — was a mem::forget that leaked them).
            Ok(FfiMechanism::from_box(mech_type, cms, |b| {
                FfiParamBacking::CmsSig(
                    b,
                    sign_mech,
                    digest_mech,
                    content_type,
                    req_attrs,
                    reqd_attrs,
                    Box::new(sign_ffi._backing),
                    Box::new(digest_ffi._backing),
                )
            }))
        }

        // -- Skipjack Private Wrap: struct with many pointers -------------------
        CkMechanismParams::SkipjackPrivateWrap(p) => {
            let mut password = Zeroizing::new(p.password.clone());
            let mut public_data = p.public_data.clone();
            let mut random_a = p.random_a.clone();
            let mut prime_p = p.prime_p.clone();
            let mut base_g = p.base_g.clone();
            let mut subprime_q = p.subprime_q.clone();
            let pass_ptr =
                if password.is_empty() { std::ptr::null_mut() } else { password.as_mut_ptr() };
            let pub_ptr = if public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                public_data.as_mut_ptr()
            };
            let ra_ptr =
                if random_a.is_empty() { std::ptr::null_mut() } else { random_a.as_mut_ptr() };
            let pp_ptr =
                if prime_p.is_empty() { std::ptr::null_mut() } else { prime_p.as_mut_ptr() };
            let bg_ptr = if base_g.is_empty() { std::ptr::null_mut() } else { base_g.as_mut_ptr() };
            let sq_ptr =
                if subprime_q.is_empty() { std::ptr::null_mut() } else { subprime_q.as_mut_ptr() };
            // ulPAndGLen = length of prime_p (and base_g, which share the same length)
            let p_and_g_len = prime_p.len() as cryptoki_sys::CK_ULONG;
            let q_len = subprime_q.len() as cryptoki_sys::CK_ULONG;
            let random_len = random_a.len() as cryptoki_sys::CK_ULONG;
            let sj = Box::new(cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
                ulPasswordLen: narrow_wire_ulong(p.password_length)?,
                pPassword: pass_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pPublicData: pub_ptr,
                ulPAndGLen: p_and_g_len,
                ulQLen: q_len,
                ulRandomLen: random_len,
                pRandomA: ra_ptr,
                pPrimeP: pp_ptr,
                pBaseG: bg_ptr,
                pSubprimeQ: sq_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, sj, |b| {
                FfiParamBacking::SkipjackPrivateWrap(
                    b,
                    password,
                    public_data,
                    random_a,
                    prime_p,
                    base_g,
                    subprime_q,
                )
            }))
        }

        // -- Skipjack Relayx: struct with 7 pointers ----------------------------
        CkMechanismParams::SkipjackRelayx(p) => {
            let mut old_wrapped_x = p.old_wrapped_x.clone();
            let mut old_password = Zeroizing::new(p.old_password.clone());
            let mut old_public_data = p.old_public_data.clone();
            let mut old_random_a = p.old_random_a.clone();
            let mut new_password = Zeroizing::new(p.new_password.clone());
            let mut new_public_data = p.new_public_data.clone();
            let mut new_random_a = p.new_random_a.clone();
            let owx_ptr = if old_wrapped_x.is_empty() {
                std::ptr::null_mut()
            } else {
                old_wrapped_x.as_mut_ptr()
            };
            let op_ptr = if old_password.is_empty() {
                std::ptr::null_mut()
            } else {
                old_password.as_mut_ptr()
            };
            let opd_ptr = if old_public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                old_public_data.as_mut_ptr()
            };
            let ora_ptr = if old_random_a.is_empty() {
                std::ptr::null_mut()
            } else {
                old_random_a.as_mut_ptr()
            };
            let np_ptr = if new_password.is_empty() {
                std::ptr::null_mut()
            } else {
                new_password.as_mut_ptr()
            };
            let npd_ptr = if new_public_data.is_empty() {
                std::ptr::null_mut()
            } else {
                new_public_data.as_mut_ptr()
            };
            let nra_ptr = if new_random_a.is_empty() {
                std::ptr::null_mut()
            } else {
                new_random_a.as_mut_ptr()
            };
            let sj = Box::new(cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS {
                ulOldWrappedXLen: old_wrapped_x.len() as cryptoki_sys::CK_ULONG,
                pOldWrappedX: owx_ptr,
                ulOldPasswordLen: old_password.len() as cryptoki_sys::CK_ULONG,
                pOldPassword: op_ptr,
                ulOldPublicDataLen: old_public_data.len() as cryptoki_sys::CK_ULONG,
                pOldPublicData: opd_ptr,
                ulOldRandomLen: old_random_a.len() as cryptoki_sys::CK_ULONG,
                pOldRandomA: ora_ptr,
                ulNewPasswordLen: new_password.len() as cryptoki_sys::CK_ULONG,
                pNewPassword: np_ptr,
                ulNewPublicDataLen: new_public_data.len() as cryptoki_sys::CK_ULONG,
                pNewPublicData: npd_ptr,
                ulNewRandomLen: new_random_a.len() as cryptoki_sys::CK_ULONG,
                pNewRandomA: nra_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, sj, |b| {
                FfiParamBacking::SkipjackRelayx(
                    b,
                    old_wrapped_x,
                    old_password,
                    old_public_data,
                    old_random_a,
                    new_password,
                    new_public_data,
                    new_random_a,
                )
            }))
        }

        // -- Vendor-specific: these reference nested CkMechanism or complex -----
        // vendor layouts that cannot be safely reconstructed generically.
        CkMechanismParams::Ecies(_)
        | CkMechanismParams::AesCmacKeyDerivation(_)
        | CkMechanismParams::Dilithium(_)
        | CkMechanismParams::Kyber(_)
        | CkMechanismParams::HdKeyDerive(_)
        | CkMechanismParams::VendorObjectExtract(_)
        | CkMechanismParams::VendorObjectInsert(_) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn gcm_iv_capacity(p: &GcmParams) -> CkResult<usize> {
    let requested = usize::try_from(p.iv_buffer_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let capacity = p.iv.len().max(requested);
    const MAX_GCM_IV_BUFFER_LEN: usize = 512 * 1024 * 1024;
    if capacity > MAX_GCM_IV_BUFFER_LEN {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(capacity)
}
