// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::{CK_STATE, CK_UTF8CHAR};
use pkcs11_proxy_ng_types::*;

/// Trim trailing spaces/nulls from a fixed-size byte array and convert to String.
/// Uses lossy UTF-8 decoding so that ISO 8859-1 bytes from real HSMs are preserved
/// rather than silently replaced with an empty string.
pub(super) fn utf8_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches([' ', '\0']).to_string()
}

/// Copy a Rust string into a fixed-width PKCS#11 field, padding with spaces.
pub(super) fn space_pad<const N: usize>(value: &str) -> [CK_UTF8CHAR; N] {
    let mut padded = [b' '; N];
    let value = value.as_bytes();
    let copy_len = value.len().min(N);
    padded[..copy_len].copy_from_slice(&value[..copy_len]);
    padded
}

/// Convert a raw PKCS#11 session state value into the modeled enum.
///
/// Unknown values fall back to `RoPublic` so older consumers continue to work
/// if a backend returns an unexpected value.
pub(super) fn session_state_from_ck(state: CK_STATE) -> CkSessionState {
    match state {
        0 => CkSessionState::RoPublic,
        1 => CkSessionState::RoUser,
        2 => CkSessionState::RwPublic,
        3 => CkSessionState::RwUser,
        4 => CkSessionState::RwSo,
        _ => CkSessionState::RoPublic,
    }
}

/// Owns FFI `CK_ATTRIBUTE` arrays and their backing storage for the duration of an FFI call.
///
/// `CkAttributeValue::Ulong` stores `u64` but `CK_ULONG` is platform-sized (32-bit on 32-bit
/// targets). To pass a correctly-sized value to C, convert to native `CK_ULONG` bytes and
/// keep those bytes alive alongside the attribute array.
pub(super) struct FfiAttrs {
    /// The ready-to-pass attribute array. Pointers inside borrow from the original
    /// `CkAttribute` slice or from `_backing`.
    pub(super) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    /// Backing byte storage for `Ulong` values whose native size differs from `u64`.
    _backing: Vec<Vec<u8>>,
}

impl FfiAttrs {
    /// `None` values produce a null `pValue` / zero `ulValueLen` (size-query pattern).
    /// `Ulong` values are converted to the correct platform-native `CK_ULONG` width.
    pub(super) fn from_slice(template: &[CkAttribute]) -> Self {
        let mut attrs = Vec::with_capacity(template.len());
        let mut backing: Vec<Vec<u8>> = Vec::new();

        for attr in template {
            let (pvalue, len): (*mut _, cryptoki_sys::CK_ULONG) = match &attr.value {
                None => (std::ptr::null_mut(), 0),
                Some(CkAttributeValue::Bool(b)) => {
                    static TRUE_BYTE: u8 = 1;
                    static FALSE_BYTE: u8 = 0;
                    let ptr = if *b { &TRUE_BYTE as *const u8 } else { &FALSE_BYTE as *const u8 };
                    (ptr as *mut _, 1)
                }
                Some(CkAttributeValue::Ulong(u)) => {
                    let bytes = (*u as cryptoki_sys::CK_ULONG).to_ne_bytes().to_vec();
                    let len = bytes.len() as cryptoki_sys::CK_ULONG;
                    let ptr = bytes.as_ptr() as *mut _;
                    backing.push(bytes);
                    (ptr, len)
                }
                Some(CkAttributeValue::Bytes(b)) => {
                    (b.as_ptr() as *mut _, b.len() as cryptoki_sys::CK_ULONG)
                }
                Some(CkAttributeValue::String(s)) => {
                    (s.as_ptr() as *mut _, s.len() as cryptoki_sys::CK_ULONG)
                }
            };
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: attr.attr_type.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE,
                pValue: pvalue,
                ulValueLen: len,
            });
        }

        Self { attrs, _backing: backing }
    }
}

/// Backing storage for a single nested `CK_ATTRIBUTE[]` template.
///
/// The boxed slice is pinned at a stable heap address so that the parent
/// attribute's `pValue` pointer remains valid through the FFI call.
/// Sub-buffers hold the `pValue` data for each nested attribute.
struct NestedTemplateBacking {
    /// The nested `CK_ATTRIBUTE` array at a stable heap address.
    _template: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>>,
    /// Sub-buffers for each nested attribute's `pValue`.
    _sub_buffers: Vec<Vec<u8>>,
}

/// Owns raw `CK_ATTRIBUTE` buffers for exact `C_GetAttributeValue` semantics.
///
/// For attributes with `CKF_ARRAY_ATTRIBUTE`, stores additional nested template
/// arrays and their sub-buffers. Pointer stability is ensured by using pinned
/// `Box<[CK_ATTRIBUTE]>` for nested templates and pre-allocated `Vec<u8>` for
/// all byte buffers.
pub(super) struct FfiAttributeQueries {
    pub(super) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    _buffers: Vec<Vec<u8>>,
    _nested: Vec<NestedTemplateBacking>,
}

impl FfiAttributeQueries {
    pub(super) fn from_queries(queries: &[CkAttributeQuery]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(queries.len());
        let mut buffers = Vec::new();
        let mut nested_backings = Vec::new();

        for query in queries {
            if let Some(nested_queries) = &query.nested {
                // CKF_ARRAY_ATTRIBUTE: allocate a nested CK_ATTRIBUTE[] template
                Self::build_nested_attr(query, nested_queries, &mut attrs, &mut nested_backings)?;
            } else {
                // Flat attribute: allocate a simple byte buffer
                let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                    .map_err(|_| CkRv::HOST_MEMORY)?;
                let (pvalue, len) = if query.buffer_present {
                    let buffer_len =
                        usize::try_from(query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    let mut buffer = Vec::new();
                    buffer.try_reserve_exact(buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    buffer.resize(buffer_len, 0);
                    let ptr = buffer.as_mut_ptr() as *mut std::ffi::c_void;
                    buffers.push(buffer);
                    (ptr, ul_value_len)
                } else {
                    (std::ptr::null_mut(), ul_value_len)
                };

                attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                    type_: query.attr_type.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE,
                    pValue: pvalue,
                    ulValueLen: len,
                });
            }
        }

        Ok(Self { attrs, _buffers: buffers, _nested: nested_backings })
    }

    /// Build a `CK_ATTRIBUTE` entry for a nested template attribute.
    ///
    /// Allocates a pinned `CK_ATTRIBUTE[]` array for the sub-template and
    /// byte buffers for each sub-attribute's `pValue`. The parent attribute's
    /// `pValue` points to the nested array and `ulValueLen` is set to
    /// `count * size_of::<CK_ATTRIBUTE>()`.
    fn build_nested_attr(
        query: &CkAttributeQuery,
        nested_queries: &[CkAttributeQuery],
        attrs: &mut Vec<cryptoki_sys::CK_ATTRIBUTE>,
        nested_backings: &mut Vec<NestedTemplateBacking>,
    ) -> CkResult<()> {
        if !query.buffer_present || nested_queries.is_empty() {
            // Size query or empty nested: pValue=NULL, ulValueLen carries the
            // requested/expected length.
            let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: query.attr_type.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE,
                pValue: std::ptr::null_mut(),
                ulValueLen: ul_value_len,
            });
            return Ok(());
        }

        // Allocate sub-buffers first, collecting stable pointers
        let mut sub_buffers: Vec<Vec<u8>> = Vec::with_capacity(nested_queries.len());
        let mut sub_attrs: Vec<cryptoki_sys::CK_ATTRIBUTE> =
            Vec::with_capacity(nested_queries.len());

        for sub_query in nested_queries {
            let sub_ul_value_len = cryptoki_sys::CK_ULONG::try_from(sub_query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;

            let (sub_pvalue, sub_len) = if sub_query.buffer_present {
                let sub_buf_len =
                    usize::try_from(sub_query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                let mut sub_buf = Vec::new();
                sub_buf.try_reserve_exact(sub_buf_len).map_err(|_| CkRv::HOST_MEMORY)?;
                sub_buf.resize(sub_buf_len, 0);
                let ptr = sub_buf.as_mut_ptr() as *mut std::ffi::c_void;
                sub_buffers.push(sub_buf);
                (ptr, sub_ul_value_len)
            } else {
                (std::ptr::null_mut(), sub_ul_value_len)
            };

            sub_attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: sub_query.attr_type.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE,
                pValue: sub_pvalue,
                ulValueLen: sub_len,
            });
        }

        // Pin the sub-attribute array at a stable heap address.
        // We must create the pinned box from the completed array so no
        // further mutations move it.
        let mut template_box: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>> =
            sub_attrs.into_boxed_slice().into();

        // The parent attribute points into the pinned template.
        let template_ptr = template_box.as_mut_ptr() as *mut std::ffi::c_void;
        let template_byte_len = (template_box.len()
            * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
            as cryptoki_sys::CK_ULONG;

        attrs.push(cryptoki_sys::CK_ATTRIBUTE {
            type_: query.attr_type.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE,
            pValue: template_ptr,
            ulValueLen: template_byte_len,
        });

        nested_backings
            .push(NestedTemplateBacking { _template: template_box, _sub_buffers: sub_buffers });

        Ok(())
    }
}

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
    pub(super) fn output_params(&self) -> Option<CkMechanismParams> {
        match &self._backing {
            FfiParamBacking::Gcm(gcm, iv, aad) => {
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
                Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: sp800.prfType as u64,
                    data_params: sp800_108_data_params_from_ffi(data_params, data_buffers),
                    iv: iv[..(sp800.ulIVLen as usize).min(iv.len())].to_vec(),
                    additional_derived_keys: derived_keys.output_keys(),
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
    fn new(keys: &[Sp800108DerivedKey]) -> Self {
        let mut templates: Vec<FfiAttrs> =
            keys.iter().map(|key| FfiAttrs::from_slice(&key.template)).collect();
        let mut handles: Vec<cryptoki_sys::CK_OBJECT_HANDLE> =
            keys.iter().map(|key| key.key_handle as cryptoki_sys::CK_OBJECT_HANDLE).collect();
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

        Self { original: keys.to_vec(), _templates: templates, handles, derived_keys }
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
    Pss(Box<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>),
    Rc5(Box<cryptoki_sys::CK_RC5_PARAMS>),
    Rc5MacGeneral(Box<cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS>),
    Rc2MacGeneral(Box<cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS>),
    Xeddsa(Box<cryptoki_sys::CK_XEDDSA_PARAMS>),
    TlsMac(Box<cryptoki_sys::CK_TLS_MAC_PARAMS>),
    Rc2Cbc(Box<cryptoki_sys::CK_RC2_CBC_PARAMS>),
    AesCtr(Box<cryptoki_sys::CK_AES_CTR_PARAMS>),
    CamelliaCtr(Box<cryptoki_sys::CK_CAMELLIA_CTR_PARAMS>),
    /// Struct with pointer fields — struct + borrowed buffers.
    Oaep(Box<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>, Vec<u8>),
    Gcm(Box<cryptoki_sys::CK_GCM_PARAMS>, Vec<u8>, Vec<u8>),
    Ccm(Box<cryptoki_sys::CK_CCM_PARAMS>, Vec<u8>, Vec<u8>),
    Ecdh1(Box<cryptoki_sys::CK_ECDH1_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Rc5Cbc(Box<cryptoki_sys::CK_RC5_CBC_PARAMS>, Vec<u8>),
    Eddsa(Box<cryptoki_sys::CK_EDDSA_PARAMS>, Vec<u8>),
    Hkdf(Box<cryptoki_sys::CK_HKDF_PARAMS>, Vec<u8>, Vec<u8>),
    KeyDerivationString(Box<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>, Vec<u8>),
    AesCbcEncryptData(Box<cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    DesCbcEncryptData(Box<cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    AriaCbcEncryptData(Box<cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    CamelliaCbcEncryptData(Box<cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    SeedCbcEncryptData(Box<cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS>, Vec<u8>),
    GcmWrap(Box<cryptoki_sys::CK_GCM_WRAP_PARAMS>, Vec<u8>, Vec<u8>),
    CcmWrap(Box<cryptoki_sys::CK_CCM_WRAP_PARAMS>, Vec<u8>, Vec<u8>),
    ChaCha20(Box<cryptoki_sys::CK_CHACHA20_PARAMS>, Vec<u8>, Vec<u8>),
    Salsa20(Box<cryptoki_sys::CK_SALSA20_PARAMS>, Vec<u8>, Vec<u8>),
    Salsa20ChaCha20Poly1305(
        Box<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS>,
        Vec<u8>,
        Vec<u8>,
    ),
    RsaAesKeyWrap(Box<FfiRsaAesKeyWrapParams>, Box<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>, Vec<u8>),
    SignAdditionalContext(Box<FfiSignAdditionalContext>, Vec<u8>),
    Kmac(Box<FfiKmacParams>, Vec<u8>),
    MuGen(Box<FfiMuGenParams>, Vec<u8>, Vec<u8>),
    Pkcs5Pbkd2(Box<cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2>, Vec<u8>, Vec<u8>, Vec<u8>),
    Tls12MasterKeyDerive(
        Box<cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    TlsPrf(
        Box<cryptoki_sys::CK_TLS_PRF_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_ULONG>,
    ),
    TlsKdf(Box<cryptoki_sys::CK_TLS_KDF_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    Ssl3MasterKeyDerive(
        Box<cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    Tls12ExtendedMasterKeyDerive(
        Box<cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Box<cryptoki_sys::CK_VERSION>,
    ),
    Ssl3KeyMat(
        Box<cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>,
        Vec<u8>,
        Vec<u8>,
    ),
    Tls12KeyMat(
        Box<cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>,
        Vec<u8>,
        Vec<u8>,
    ),
    Pbe(Box<cryptoki_sys::CK_PBE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    EcdhAesKeyWrap(Box<cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS>, Vec<u8>),
    Ecdh2Derive(Box<cryptoki_sys::CK_ECDH2_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    EcmqvDerive(Box<cryptoki_sys::CK_ECMQV_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    X942Dh1Derive(Box<cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    X942Dh2Derive(Box<cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    X942MqvDerive(Box<cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    Gostr3410Derive(Box<cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Gostr3410KeyWrap(Box<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>, Vec<u8>, Vec<u8>),
    KeyWrapSetOaep(Box<cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS>, Vec<u8>),
    KeaDerive(Box<cryptoki_sys::CK_KEA_DERIVE_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    IkePrfDerive(Box<cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Ike1PrfDerive(Box<cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS>, Vec<u8>, Vec<u8>),
    Ike1ExtendedDerive(Box<cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS>, Vec<u8>),
    Ike2PrfPlusDerive(Box<cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS>, Vec<u8>),
    WtlsMasterKeyDerive(
        Box<cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    WtlsPrf(
        Box<cryptoki_sys::CK_WTLS_PRF_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_ULONG>,
    ),
    WtlsKeyMat(
        Box<cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Box<cryptoki_sys::CK_WTLS_KEY_MAT_OUT>,
        Vec<u8>,
    ),
    Sp800108Kdf(
        Box<cryptoki_sys::CK_SP800_108_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Vec<u8>>,
        FfiSp800108DerivedKeys,
    ),
    Sp800108FeedbackKdf(
        Box<cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Vec<u8>>,
        Vec<u8>,
        FfiSp800108DerivedKeys,
    ),
    X3dhInitiate(Box<cryptoki_sys::CK_X3DH_INITIATE_PARAMS>, Vec<u8>, Vec<u8>),
    X3dhRespond(Box<cryptoki_sys::CK_X3DH_RESPOND_PARAMS>, Vec<u8>, Vec<u8>, Vec<u8>),
    X2RatchetInitialize(Box<cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS>, Vec<u8>),
    X2RatchetRespond(Box<cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS>, Vec<u8>),
    Otp(Box<cryptoki_sys::CK_OTP_PARAMS>, Vec<cryptoki_sys::CK_OTP_PARAM>, Vec<Vec<u8>>),
    Kip(Box<cryptoki_sys::CK_KIP_PARAMS>, Box<cryptoki_sys::CK_MECHANISM>, Vec<u8>),
    CmsSig(
        Box<cryptoki_sys::CK_CMS_SIG_PARAMS>,
        Box<cryptoki_sys::CK_MECHANISM>,
        Box<cryptoki_sys::CK_MECHANISM>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    SkipjackPrivateWrap(
        Box<cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    SkipjackRelayx(
        Box<cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
}

/// CK_RSA_AES_KEY_WRAP_PARAMS -- not in cryptoki-sys, defined per PKCS#11 v3 spec.
#[repr(C)]
struct FfiRsaAesKeyWrapParams {
    ul_aes_key_bits: cryptoki_sys::CK_ULONG,
    p_oaep_params: *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS,
}

/// CK_SIGN_ADDITIONAL_CONTEXT — not in cryptoki-sys, defined per PKCS#11 3.2 spec.
#[repr(C)]
struct FfiSignAdditionalContext {
    hedge_variant: cryptoki_sys::CK_ULONG,
    p_context: *mut cryptoki_sys::CK_BYTE,
    ul_context_len: cryptoki_sys::CK_ULONG,
}

/// CK_KMAC_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
struct FfiKmacParams {
    h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    ul_mac_length: cryptoki_sys::CK_ULONG,
    p_customization_string: cryptoki_sys::CK_VOID_PTR,
    ul_customization_string_len: cryptoki_sys::CK_ULONG,
}

/// CK_MU_GEN_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
struct FfiMuGenParams {
    h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    p_tr: cryptoki_sys::CK_BYTE_PTR,
    ul_tr_len: cryptoki_sys::CK_ULONG,
    p_ctx: cryptoki_sys::CK_BYTE_PTR,
    ul_ctx_len: cryptoki_sys::CK_ULONG,
}

/// Convert a `CkMechanism` to an `FfiMechanism` for FFI calls.
///
/// Parameterless mechanisms use null `pParameter`.  Parameterized mechanisms
/// allocate the appropriate C struct on the heap (via `Box`) so that
/// `pParameter` has a stable address for the lifetime of the returned
/// `FfiMechanism`.
pub(super) fn mechanism_to_ffi(mechanism: &CkMechanism) -> CkResult<FfiMechanism> {
    let mech_type = mechanism.mechanism_type.0 as cryptoki_sys::CK_MECHANISM_TYPE;

    let params = match &mechanism.params {
        None => {
            return Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
                _backing: FfiParamBacking::None,
            });
        }
        Some(p) => p,
    };

    match params {
        // -- IV: raw bytes as the parameter ---------------------------------
        CkMechanismParams::Iv(iv_params) => {
            let mut buf = iv_params.iv.clone();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Bytes(buf),
            })
        }

        // -- RSA-PSS: scalar-only struct ------------------------------------
        CkMechanismParams::RsaPkcsPss(p) => {
            let mut pss = Box::new(cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: p.hash_alg.0 as cryptoki_sys::CK_MECHANISM_TYPE,
                mgf: p.mgf as cryptoki_sys::CK_RSA_PKCS_MGF_TYPE,
                sLen: p.salt_len as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *pss as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Pss(pss),
            })
        }

        // -- RSA-OAEP: struct with pointer to source_data -------------------
        CkMechanismParams::RsaPkcsOaep(p) => {
            let mut source_data = p.source_data.clone();
            let (src_ptr, src_len) = if source_data.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (source_data.as_mut_ptr() as *mut std::ffi::c_void, source_data.len())
            };
            let mut oaep = Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: p.hash_alg.0 as cryptoki_sys::CK_MECHANISM_TYPE,
                mgf: p.mgf as cryptoki_sys::CK_RSA_PKCS_MGF_TYPE,
                source: p.source as cryptoki_sys::CK_RSA_PKCS_OAEP_SOURCE_TYPE,
                pSourceData: src_ptr,
                ulSourceDataLen: src_len as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *oaep as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Oaep(oaep, source_data),
            })
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
            let mut gcm = Box::new(cryptoki_sys::CK_GCM_PARAMS {
                pIv: iv_ptr,
                ulIvLen: input_iv_len as cryptoki_sys::CK_ULONG,
                ulIvBits: p.iv_bits as cryptoki_sys::CK_ULONG,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulTagBits: p.tag_bits as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *gcm as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_GCM_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Gcm(gcm, iv, aad),
            })
        }

        // -- CCM: struct with pointers to nonce and AAD ---------------------
        CkMechanismParams::Ccm(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let mut ccm = Box::new(cryptoki_sys::CK_CCM_PARAMS {
                ulDataLen: p.data_len as cryptoki_sys::CK_ULONG,
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulMACLen: p.mac_len as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *ccm as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CCM_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ccm(ccm, nonce, aad),
            })
        }

        // -- ECDH1 Derive: struct with pointers to shared + public data -----
        CkMechanismParams::Ecdh1Derive(p) => {
            let mut shared = p.shared_data.clone();
            let mut public = p.public_data.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let public_ptr =
                if public.is_empty() { std::ptr::null_mut() } else { public.as_mut_ptr() };
            let mut ecdh = Box::new(cryptoki_sys::CK_ECDH1_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_EC_KDF_TYPE,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
            });
            let ptr = &mut *ecdh as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_ECDH1_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ecdh1(ecdh, shared, public),
            })
        }

        // -- AES-CTR: scalar + fixed 16-byte counter block ------------------
        CkMechanismParams::AesCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let mut ctr = Box::new(cryptoki_sys::CK_AES_CTR_PARAMS {
                ulCounterBits: p.counter_bits as cryptoki_sys::CK_ULONG,
                cb,
            });
            let ptr = &mut *ctr as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_AES_CTR_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::AesCtr(ctr),
            })
        }

        // -- Camellia-CTR: scalar + fixed 16-byte counter block -------------
        CkMechanismParams::CamelliaCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let mut ctr = Box::new(cryptoki_sys::CK_CAMELLIA_CTR_PARAMS {
                ulCounterBits: p.counter_bits as cryptoki_sys::CK_ULONG,
                cb,
            });
            let ptr = &mut *ctr as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CAMELLIA_CTR_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::CamelliaCtr(ctr),
            })
        }

        // -- RC2-CBC: scalar + fixed 8-byte IV ------------------------------
        CkMechanismParams::Rc2Cbc(p) => {
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut rc2 = Box::new(cryptoki_sys::CK_RC2_CBC_PARAMS {
                ulEffectiveBits: p.effective_bits as cryptoki_sys::CK_ULONG,
                iv,
            });
            let ptr = &mut *rc2 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RC2_CBC_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Rc2Cbc(rc2),
            })
        }

        // -- RC5-CBC: scalars + pointer to IV -------------------------------
        CkMechanismParams::Rc5Cbc(p) => {
            let mut iv_buf = p.iv.clone();
            let iv_ptr = if iv_buf.is_empty() { std::ptr::null_mut() } else { iv_buf.as_mut_ptr() };
            let mut rc5 = Box::new(cryptoki_sys::CK_RC5_CBC_PARAMS {
                ulWordsize: p.word_size as cryptoki_sys::CK_ULONG,
                ulRounds: p.rounds as cryptoki_sys::CK_ULONG,
                pIv: iv_ptr,
                ulIvLen: iv_buf.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *rc5 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RC5_CBC_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Rc5Cbc(rc5, iv_buf),
            })
        }

        // -- Trivial scalar-only structs ------------------------------------
        CkMechanismParams::Rc5(p) => {
            let mut rc5 = Box::new(cryptoki_sys::CK_RC5_PARAMS {
                ulWordsize: p.word_size as cryptoki_sys::CK_ULONG,
                ulRounds: p.rounds as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *rc5 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RC5_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Rc5(rc5),
            })
        }

        CkMechanismParams::Rc5MacGeneral(p) => {
            let mut rc5mg = Box::new(cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS {
                ulWordsize: p.word_size as cryptoki_sys::CK_ULONG,
                ulRounds: p.rounds as cryptoki_sys::CK_ULONG,
                ulMacLength: p.mac_length as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *rc5mg as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Rc5MacGeneral(rc5mg),
            })
        }

        CkMechanismParams::Rc2MacGeneral(p) => {
            let mut rc2mg = Box::new(cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS {
                ulEffectiveBits: p.effective_bits as cryptoki_sys::CK_ULONG,
                ulMacLength: p.mac_length as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *rc2mg as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Rc2MacGeneral(rc2mg),
            })
        }

        CkMechanismParams::Xeddsa(p) => {
            let mut xed = Box::new(cryptoki_sys::CK_XEDDSA_PARAMS {
                hash: p.hash as cryptoki_sys::CK_XEDDSA_HASH_TYPE,
            });
            let ptr = &mut *xed as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_XEDDSA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Xeddsa(xed),
            })
        }

        CkMechanismParams::TlsMac(p) => {
            let mut tls = Box::new(cryptoki_sys::CK_TLS_MAC_PARAMS {
                prfHashMechanism: p.prf_hash_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                ulMacLength: p.mac_length as cryptoki_sys::CK_ULONG,
                ulServerOrClient: p.server_or_client as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *tls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_TLS_MAC_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::TlsMac(tls),
            })
        }

        // -- CBC encrypt data variants (fixed IV + pointer to data) ---------
        CkMechanismParams::AesCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut s = Box::new(cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *s as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::AesCbcEncryptData(s, data),
            })
        }

        CkMechanismParams::DesCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut s = Box::new(cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *s as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::DesCbcEncryptData(s, data),
            })
        }

        CkMechanismParams::AriaCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut s = Box::new(cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *s as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::AriaCbcEncryptData(s, data),
            })
        }

        CkMechanismParams::CamelliaCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut s = Box::new(cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *s as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::CamelliaCbcEncryptData(s, data),
            })
        }

        CkMechanismParams::SeedCbcEncryptData(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let mut s = Box::new(cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data_ptr,
                length: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *s as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::SeedCbcEncryptData(s, data),
            })
        }

        // -- HKDF: struct with pointers to salt and info --------------------
        CkMechanismParams::Hkdf(p) => {
            let mut salt = p.salt.clone();
            let mut info = p.info.clone();
            let salt_ptr = if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() };
            let info_ptr = if info.is_empty() { std::ptr::null_mut() } else { info.as_mut_ptr() };
            let mut hkdf = Box::new(cryptoki_sys::CK_HKDF_PARAMS {
                bExtract: if p.extract { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                bExpand: if p.expand { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                prfHashMechanism: p.prf_hash_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                ulSaltType: p.salt_type as cryptoki_sys::CK_ULONG,
                pSalt: salt_ptr,
                ulSaltLen: salt.len() as cryptoki_sys::CK_ULONG,
                hSaltKey: p.salt_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pInfo: info_ptr,
                ulInfoLen: info.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *hkdf as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_HKDF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Hkdf(hkdf, salt, info),
            })
        }

        // -- EdDSA: struct with pointer to context data ---------------------
        CkMechanismParams::Eddsa(p) => {
            let mut ctx = p.context_data.clone();
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let mut eddsa = Box::new(cryptoki_sys::CK_EDDSA_PARAMS {
                phFlag: if p.ph_flag { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulContextDataLen: ctx.len() as cryptoki_sys::CK_ULONG,
                pContextData: ctx_ptr,
            });
            let ptr = &mut *eddsa as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_EDDSA_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Eddsa(eddsa, ctx),
            })
        }

        // -- GCM Wrap: struct with pointers to IV and AAD -------------------
        CkMechanismParams::GcmWrap(p) => {
            let mut iv = p.iv.clone();
            let mut aad = p.aad.clone();
            let iv_ptr = if iv.is_empty() { std::ptr::null_mut() } else { iv.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let mut gw = Box::new(cryptoki_sys::CK_GCM_WRAP_PARAMS {
                pIv: iv_ptr,
                ulIvLen: iv.len() as cryptoki_sys::CK_ULONG,
                ulIvFixedBits: p.iv_fixed_bits as cryptoki_sys::CK_ULONG,
                ivGenerator: p.iv_generator as cryptoki_sys::CK_GENERATOR_FUNCTION,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulTagBits: p.tag_bits as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *gw as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_GCM_WRAP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::GcmWrap(gw, iv, aad),
            })
        }

        // -- CCM Wrap: struct with pointers to nonce and AAD ----------------
        CkMechanismParams::CcmWrap(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let mut cw = Box::new(cryptoki_sys::CK_CCM_WRAP_PARAMS {
                ulDataLen: p.data_len as cryptoki_sys::CK_ULONG,
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                ulNonceFixedBits: p.nonce_fixed_bits as cryptoki_sys::CK_ULONG,
                nonceGenerator: p.nonce_generator as cryptoki_sys::CK_GENERATOR_FUNCTION,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
                ulMACLen: p.mac_len as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *cw as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CCM_WRAP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::CcmWrap(cw, nonce, aad),
            })
        }

        // -- ChaCha20: struct with pointers to block counter and nonce ------
        CkMechanismParams::ChaCha20(p) => {
            let mut bc = p.block_counter.clone();
            let mut nonce = p.nonce.clone();
            let bc_ptr = if bc.is_empty() { std::ptr::null_mut() } else { bc.as_mut_ptr() };
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let mut ch = Box::new(cryptoki_sys::CK_CHACHA20_PARAMS {
                pBlockCounter: bc_ptr,
                blockCounterBits: p.block_counter_bits as cryptoki_sys::CK_ULONG,
                pNonce: nonce_ptr,
                ulNonceBits: p.nonce_bits as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *ch as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CHACHA20_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::ChaCha20(ch, bc, nonce),
            })
        }

        // -- Salsa20: struct with pointers to block counter and nonce -------
        CkMechanismParams::Salsa20(p) => {
            let mut bc = p.block_counter.clone();
            let mut nonce = p.nonce.clone();
            let bc_ptr = if bc.is_empty() { std::ptr::null_mut() } else { bc.as_mut_ptr() };
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let mut sa = Box::new(cryptoki_sys::CK_SALSA20_PARAMS {
                pBlockCounter: bc_ptr,
                pNonce: nonce_ptr,
                ulNonceBits: p.nonce_bits as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *sa as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SALSA20_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Salsa20(sa, bc, nonce),
            })
        }

        // -- Salsa20/ChaCha20-Poly1305: struct with pointers to nonce + AAD -
        CkMechanismParams::Salsa20ChaCha20Poly1305(p) => {
            let mut nonce = p.nonce.clone();
            let mut aad = p.aad.clone();
            let nonce_ptr =
                if nonce.is_empty() { std::ptr::null_mut() } else { nonce.as_mut_ptr() };
            let aad_ptr = if aad.is_empty() { std::ptr::null_mut() } else { aad.as_mut_ptr() };
            let mut sp = Box::new(cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS {
                pNonce: nonce_ptr,
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                pAAD: aad_ptr,
                ulAADLen: aad.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *sp as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Salsa20ChaCha20Poly1305(sp, nonce, aad),
            })
        }

        // -- MacGeneral: single CK_ULONG -----------------------------------
        CkMechanismParams::MacGeneral(p) => {
            let val = p.mac_length as cryptoki_sys::CK_MAC_GENERAL_PARAMS;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Bytes(buf),
            })
        }

        // -- Extract: single CK_ULONG bit position --------------------------
        CkMechanismParams::Extract(p) => {
            let val = p.bit_position as cryptoki_sys::CK_EXTRACT_PARAMS;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Bytes(buf),
            })
        }

        // -- KeyDerivationStringData: struct with pointer to data -----------
        CkMechanismParams::KeyDerivationString(p) => {
            let mut data = p.data.clone();
            let data_ptr = if data.is_empty() { std::ptr::null_mut() } else { data.as_mut_ptr() };
            let mut kds = Box::new(cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA {
                pData: data_ptr,
                ulLen: data.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *kds as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::KeyDerivationString(kds, data),
            })
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
                hashAlg: p.oaep_params.hash_alg.0 as cryptoki_sys::CK_MECHANISM_TYPE,
                mgf: p.oaep_params.mgf as cryptoki_sys::CK_RSA_PKCS_MGF_TYPE,
                source: p.oaep_params.source as cryptoki_sys::CK_RSA_PKCS_OAEP_SOURCE_TYPE,
                pSourceData: src_ptr,
                ulSourceDataLen: src_len as cryptoki_sys::CK_ULONG,
            });
            let oaep_ptr = &mut *oaep as *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS;

            let mut wrap = Box::new(FfiRsaAesKeyWrapParams {
                ul_aes_key_bits: p.aes_key_bits as cryptoki_sys::CK_ULONG,
                p_oaep_params: oaep_ptr,
            });
            let ptr = &mut *wrap as *mut FfiRsaAesKeyWrapParams as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiRsaAesKeyWrapParams>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::RsaAesKeyWrap(wrap, oaep, source_data),
            })
        }

        // -- ObjectHandle: single CK_OBJECT_HANDLE ----------------------------
        CkMechanismParams::ObjectHandle(p) => {
            let val = p.handle as cryptoki_sys::CK_OBJECT_HANDLE;
            let mut buf = val.to_ne_bytes().to_vec();
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Bytes(buf),
            })
        }

        // -- SignAdditionalContext: CK_SIGN_ADDITIONAL_CONTEXT (ML-DSA hedge) -
        CkMechanismParams::SignAdditionalContext(p) => {
            let mut ctx = p.context.clone();
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let mut sac = Box::new(FfiSignAdditionalContext {
                hedge_variant: p.hedge_variant as cryptoki_sys::CK_ULONG,
                p_context: ctx_ptr,
                ul_context_len: ctx.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *sac as *mut FfiSignAdditionalContext as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiSignAdditionalContext>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::SignAdditionalContext(sac, ctx),
            })
        }

        // -- KMAC: CK_KMAC_PARAMS -----------------------------------------
        CkMechanismParams::Kmac(p) => {
            let mut customization_string = p.customization_string.clone();
            let customization_ptr = if customization_string.is_empty() {
                std::ptr::null_mut()
            } else {
                customization_string.as_mut_ptr() as cryptoki_sys::CK_VOID_PTR
            };
            let mut kmac = Box::new(FfiKmacParams {
                h_key: p.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                ul_mac_length: p.mac_length as cryptoki_sys::CK_ULONG,
                p_customization_string: customization_ptr,
                ul_customization_string_len: customization_string.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *kmac as *mut FfiKmacParams as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiKmacParams>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Kmac(kmac, customization_string),
            })
        }

        // -- ML-DSA external mu generation: CK_MU_GEN_PARAMS ---------------
        CkMechanismParams::MuGen(p) => {
            let mut tr = p.tr.clone();
            let mut ctx = p.context.clone();
            let tr_ptr = if tr.is_empty() { std::ptr::null_mut() } else { tr.as_mut_ptr() };
            let ctx_ptr = if ctx.is_empty() { std::ptr::null_mut() } else { ctx.as_mut_ptr() };
            let mut mu_gen = Box::new(FfiMuGenParams {
                h_key: p.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                p_tr: tr_ptr,
                ul_tr_len: tr.len() as cryptoki_sys::CK_ULONG,
                p_ctx: ctx_ptr,
                ul_ctx_len: ctx.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *mu_gen as *mut FfiMuGenParams as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiMuGenParams>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::MuGen(mu_gen, tr, ctx),
            })
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
            let mut tls12 = Box::new(cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pVersion: version_ptr,
                prfHashMechanism: p.prf_hash_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
            });
            let ptr = &mut *tls12 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Tls12MasterKeyDerive(
                    tls12,
                    client_random,
                    server_random,
                    version,
                ),
            })
        }

        // -- PKCS#5 PBKDF2: struct with 3 embedded pointers ----------------
        CkMechanismParams::Pkcs5Pbkd2(p) => {
            let mut salt = p.salt_source_data.clone();
            let mut prf_data = p.prf_data.clone();
            let mut password = p.password.clone();
            let salt_ptr =
                if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() as *mut _ };
            let prf_ptr = if prf_data.is_empty() {
                std::ptr::null_mut()
            } else {
                prf_data.as_mut_ptr() as *mut _
            };
            let pass_ptr =
                if password.is_empty() { std::ptr::null_mut() } else { password.as_mut_ptr() };
            let mut pbkd2 = Box::new(cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2 {
                saltSource: p.salt_source as cryptoki_sys::CK_ULONG,
                pSaltSourceData: salt_ptr,
                ulSaltSourceDataLen: salt.len() as cryptoki_sys::CK_ULONG,
                iterations: p.iterations as cryptoki_sys::CK_ULONG,
                prf: p.prf as cryptoki_sys::CK_ULONG,
                pPrfData: prf_ptr,
                ulPrfDataLen: prf_data.len() as cryptoki_sys::CK_ULONG,
                pPassword: pass_ptr,
                ulPasswordLen: password.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *pbkd2 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Pkcs5Pbkd2(pbkd2, salt, prf_data, password),
            })
        }

        // -- TLS PRF: struct with 4 pointers (seed, label, output, outputLen) --
        CkMechanismParams::TlsPrf(p) => {
            let mut seed = p.seed.clone();
            let mut label = p.label.clone();
            let mut output = vec![0u8; p.output_len as usize];
            let mut output_len = Box::new(p.output_len as cryptoki_sys::CK_ULONG);
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let label_ptr =
                if label.is_empty() { std::ptr::null_mut() } else { label.as_mut_ptr() };
            let output_ptr =
                if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr() };
            let mut tls = Box::new(cryptoki_sys::CK_TLS_PRF_PARAMS {
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
                pLabel: label_ptr,
                ulLabelLen: label.len() as cryptoki_sys::CK_ULONG,
                pOutput: output_ptr,
                pulOutputLen: &mut *output_len as *mut _,
            });
            let ptr = &mut *tls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_TLS_PRF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::TlsPrf(tls, seed, label, output, output_len),
            })
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
            let mut tls = Box::new(cryptoki_sys::CK_TLS_KDF_PARAMS {
                prfMechanism: p.prf_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
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
            let ptr = &mut *tls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_TLS_KDF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::TlsKdf(
                    tls,
                    label,
                    client_random,
                    server_random,
                    context_data,
                ),
            })
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
            let mut ssl3 = Box::new(cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
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
            let ptr = &mut *ssl3 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ssl3MasterKeyDerive(
                    ssl3,
                    client_random,
                    server_random,
                    version,
                ),
            })
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
            let mut ext = Box::new(cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
                prfHashMechanism: p.prf_hash_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                pSessionHash: hash_ptr,
                ulSessionHashLen: session_hash.len() as cryptoki_sys::CK_ULONG,
                pVersion: version_ptr,
            });
            let ptr = &mut *ext as *mut _ as *mut std::ffi::c_void;
            let len =
                std::mem::size_of::<cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Tls12ExtendedMasterKeyDerive(ext, session_hash, version),
            })
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
                hClientMacSecret: p.client_mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                hServerMacSecret: p.server_mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                hClientKey: p.client_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                hServerKey: p.server_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pIVClient: iv_client_ptr,
                pIVServer: iv_server_ptr,
            });
            // Decide whether to use SSL3 or TLS12 key mat based on prf_hash_mechanism:
            // if prf_hash_mechanism == 0, use CK_SSL3_KEY_MAT_PARAMS; else TLS12.
            if p.prf_hash_mechanism == 0 {
                let mut km = Box::new(cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS {
                    ulMacSizeInBits: p.mac_size_bits as cryptoki_sys::CK_ULONG,
                    ulKeySizeInBits: p.key_size_bits as cryptoki_sys::CK_ULONG,
                    ulIVSizeInBits: p.iv_size_bits as cryptoki_sys::CK_ULONG,
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
                let ptr = &mut *km as *mut _ as *mut std::ffi::c_void;
                let len = std::mem::size_of::<cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS>();
                Ok(FfiMechanism {
                    ck_mechanism: cryptoki_sys::CK_MECHANISM {
                        mechanism: mech_type,
                        pParameter: ptr,
                        ulParameterLen: len as cryptoki_sys::CK_ULONG,
                    },
                    _backing: FfiParamBacking::Ssl3KeyMat(
                        km,
                        client_random,
                        server_random,
                        key_mat_out,
                        iv_client,
                        iv_server,
                    ),
                })
            } else {
                // TLS12 variant: uses CK_TLS12_KEY_MAT_PARAMS (superset of SSL3)
                let mut km = Box::new(cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS {
                    ulMacSizeInBits: p.mac_size_bits as cryptoki_sys::CK_ULONG,
                    ulKeySizeInBits: p.key_size_bits as cryptoki_sys::CK_ULONG,
                    ulIVSizeInBits: p.iv_size_bits as cryptoki_sys::CK_ULONG,
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
                    prfHashMechanism: p.prf_hash_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                });
                let ptr = &mut *km as *mut _ as *mut std::ffi::c_void;
                let len = std::mem::size_of::<cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS>();
                Ok(FfiMechanism {
                    ck_mechanism: cryptoki_sys::CK_MECHANISM {
                        mechanism: mech_type,
                        pParameter: ptr,
                        ulParameterLen: len as cryptoki_sys::CK_ULONG,
                    },
                    _backing: FfiParamBacking::Tls12KeyMat(
                        km,
                        client_random,
                        server_random,
                        key_mat_out,
                        iv_client,
                        iv_server,
                    ),
                })
            }
        }

        // -- PBE: struct with 3 pointers (init_vector, password, salt) -----------
        CkMechanismParams::Pbe(p) => {
            let mut init_vector = p.init_vector.clone();
            let mut password = p.password.clone();
            let mut salt = p.salt.clone();
            let iv_ptr = if init_vector.is_empty() {
                std::ptr::null_mut()
            } else {
                init_vector.as_mut_ptr()
            };
            let pass_ptr =
                if password.is_empty() { std::ptr::null_mut() } else { password.as_mut_ptr() };
            let salt_ptr = if salt.is_empty() { std::ptr::null_mut() } else { salt.as_mut_ptr() };
            let mut pbe = Box::new(cryptoki_sys::CK_PBE_PARAMS {
                pInitVector: iv_ptr,
                pPassword: pass_ptr,
                ulPasswordLen: password.len() as cryptoki_sys::CK_ULONG,
                pSalt: salt_ptr,
                ulSaltLen: salt.len() as cryptoki_sys::CK_ULONG,
                ulIteration: p.iteration as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *pbe as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_PBE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Pbe(pbe, init_vector, password, salt),
            })
        }

        // -- ECDH-AES Key Wrap: struct with 1 pointer ---------------------------
        CkMechanismParams::EcdhAesKeyWrap(p) => {
            let mut shared = p.shared_data.clone();
            let shared_ptr =
                if shared.is_empty() { std::ptr::null_mut() } else { shared.as_mut_ptr() };
            let mut ew = Box::new(cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS {
                ulAESKeyBits: p.aes_key_bits as cryptoki_sys::CK_ULONG,
                kdf: p.kdf as cryptoki_sys::CK_EC_KDF_TYPE,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
            });
            let ptr = &mut *ew as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::EcdhAesKeyWrap(ew, shared),
            })
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
            let mut ecdh2 = Box::new(cryptoki_sys::CK_ECDH2_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_EC_KDF_TYPE,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
                ulPrivateDataLen: p.private_data_len as cryptoki_sys::CK_ULONG,
                hPrivateData: p.private_data_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                ulPublicDataLen2: public2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: public2_ptr,
            });
            let ptr = &mut *ecdh2 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_ECDH2_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ecdh2Derive(ecdh2, shared, public, public2),
            })
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
            let mut ecmqv = Box::new(cryptoki_sys::CK_ECMQV_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_EC_KDF_TYPE,
                ulSharedDataLen: shared.len() as cryptoki_sys::CK_ULONG,
                pSharedData: shared_ptr,
                ulPublicDataLen: public.len() as cryptoki_sys::CK_ULONG,
                pPublicData: public_ptr,
                ulPrivateDataLen: p.private_data_len as cryptoki_sys::CK_ULONG,
                hPrivateData: p.private_data_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                ulPublicDataLen2: public2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: public2_ptr,
                publicKey: p.public_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            });
            let ptr = &mut *ecmqv as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_ECMQV_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::EcmqvDerive(ecmqv, shared, public, public2),
            })
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
            let mut x942 = Box::new(cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_X9_42_DH_KDF_TYPE,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                pOtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pPublicData: pub_ptr,
            });
            let ptr = &mut *x942 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X942Dh1Derive(x942, other_info, public_data),
            })
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
            let mut x942 = Box::new(cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_X9_42_DH_KDF_TYPE,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                pOtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pPublicData: pub_ptr,
                ulPrivateDataLen: p.private_data_len as cryptoki_sys::CK_ULONG,
                hPrivateData: p.private_data_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                ulPublicDataLen2: public_data2.len() as cryptoki_sys::CK_ULONG,
                pPublicData2: pub2_ptr,
            });
            let ptr = &mut *x942 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X942Dh2Derive(
                    x942,
                    other_info,
                    public_data,
                    public_data2,
                ),
            })
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
            let mut x942 = Box::new(cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_X9_42_DH_KDF_TYPE,
                ulOtherInfoLen: other_info.len() as cryptoki_sys::CK_ULONG,
                OtherInfo: oi_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                PublicData: pub_ptr,
                ulPrivateDataLen: p.private_data_len as cryptoki_sys::CK_ULONG,
                hPrivateData: p.private_data_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                ulPublicDataLen2: public_data2.len() as cryptoki_sys::CK_ULONG,
                PublicData2: pub2_ptr,
                publicKey: p.public_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            });
            let ptr = &mut *x942 as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X942MqvDerive(
                    x942,
                    other_info,
                    public_data,
                    public_data2,
                ),
            })
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
            let mut gost = Box::new(cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_EC_KDF_TYPE,
                pPublicData: pub_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                pUKM: ukm_ptr,
                ulUKMLen: ukm.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *gost as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Gostr3410Derive(gost, public_data, ukm),
            })
        }

        // -- GOSTR3410 Key Wrap: struct with 2 pointers + handle ----------------
        CkMechanismParams::Gostr3410KeyWrap(p) => {
            let mut wrap_oid = p.wrap_oid.clone();
            let mut ukm = p.ukm.clone();
            let oid_ptr =
                if wrap_oid.is_empty() { std::ptr::null_mut() } else { wrap_oid.as_mut_ptr() };
            let ukm_ptr = if ukm.is_empty() { std::ptr::null_mut() } else { ukm.as_mut_ptr() };
            let mut gost = Box::new(cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS {
                pWrapOID: oid_ptr,
                ulWrapOIDLen: wrap_oid.len() as cryptoki_sys::CK_ULONG,
                pUKM: ukm_ptr,
                ulUKMLen: ukm.len() as cryptoki_sys::CK_ULONG,
                hKey: p.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            });
            let ptr = &mut *gost as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Gostr3410KeyWrap(gost, wrap_oid, ukm),
            })
        }

        // -- Key Wrap Set OAEP: struct with 1 pointer ---------------------------
        CkMechanismParams::KeyWrapSetOaep(p) => {
            let mut x = p.x.clone();
            let x_ptr = if x.is_empty() { std::ptr::null_mut() } else { x.as_mut_ptr() };
            let mut kw = Box::new(cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS {
                bBC: p.bc as cryptoki_sys::CK_BYTE,
                pX: x_ptr,
                ulXLen: x.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *kw as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::KeyWrapSetOaep(kw, x),
            })
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
            let mut kea = Box::new(cryptoki_sys::CK_KEA_DERIVE_PARAMS {
                isSender: if p.is_sender { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulRandomLen: random_len,
                RandomA: ra_ptr,
                RandomB: rb_ptr,
                ulPublicDataLen: public_data.len() as cryptoki_sys::CK_ULONG,
                PublicData: pub_ptr,
            });
            let ptr = &mut *kea as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_KEA_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::KeaDerive(kea, random_a, random_b, public_data),
            })
        }

        // -- IKE PRF Derive: struct with 2 pointers -----------------------------
        CkMechanismParams::IkePrfDerive(p) => {
            let mut ni = p.ni.clone();
            let mut nr = p.nr.clone();
            let ni_ptr = if ni.is_empty() { std::ptr::null_mut() } else { ni.as_mut_ptr() };
            let nr_ptr = if nr.is_empty() { std::ptr::null_mut() } else { nr.as_mut_ptr() };
            let mut ike = Box::new(cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS {
                prfMechanism: p.prf_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
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
                hNewKey: p.new_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            });
            let ptr = &mut *ike as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::IkePrfDerive(ike, ni, nr),
            })
        }

        // -- IKE1 PRF Derive: struct with 2 pointers + handles ------------------
        CkMechanismParams::Ike1PrfDerive(p) => {
            let mut ckyi = p.ckyi.clone();
            let mut ckyr = p.ckyr.clone();
            let ckyi_ptr = if ckyi.is_empty() { std::ptr::null_mut() } else { ckyi.as_mut_ptr() };
            let ckyr_ptr = if ckyr.is_empty() { std::ptr::null_mut() } else { ckyr.as_mut_ptr() };
            let mut ike = Box::new(cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS {
                prfMechanism: p.prf_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                bHasPrevKey: if p.has_prev_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: p.keygxy_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                hPrevKey: p.prev_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pCKYi: ckyi_ptr,
                ulCKYiLen: ckyi.len() as cryptoki_sys::CK_ULONG,
                pCKYr: ckyr_ptr,
                ulCKYrLen: ckyr.len() as cryptoki_sys::CK_ULONG,
                keyNumber: p.key_number as cryptoki_sys::CK_BYTE,
            });
            let ptr = &mut *ike as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ike1PrfDerive(ike, ckyi, ckyr),
            })
        }

        // -- IKE1 Extended Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike1ExtendedDerive(p) => {
            let mut extra = p.extra_data.clone();
            let extra_ptr =
                if extra.is_empty() { std::ptr::null_mut() } else { extra.as_mut_ptr() };
            let mut ike = Box::new(cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS {
                prfMechanism: p.prf_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                bHasKeygxy: if p.has_keygxy {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: p.keygxy_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pExtraData: extra_ptr,
                ulExtraDataLen: extra.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *ike as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ike1ExtendedDerive(ike, extra),
            })
        }

        // -- IKE2 PRF Plus Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike2PrfPlusDerive(p) => {
            let mut seed = p.seed_data.clone();
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let mut ike = Box::new(cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
                prfMechanism: p.prf_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                bHasSeedKey: if p.has_seed_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hSeedKey: p.seed_key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pSeedData: seed_ptr,
                ulSeedDataLen: seed.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *ike as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Ike2PrfPlusDerive(ike, seed),
            })
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
            let mut wtls = Box::new(cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
                DigestMechanism: p.digest_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pVersion: version_buf.as_mut_ptr(),
            });
            let ptr = &mut *wtls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::WtlsMasterKeyDerive(
                    wtls,
                    client_random,
                    server_random,
                    version_buf,
                ),
            })
        }

        // -- WTLS PRF: digest mechanism + seed + label + output -----------------
        CkMechanismParams::WtlsPrf(p) => {
            let mut seed = p.seed.clone();
            let mut label = p.label.clone();
            let mut output = vec![0u8; p.output_len as usize];
            let mut output_len = Box::new(p.output_len as cryptoki_sys::CK_ULONG);
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let label_ptr =
                if label.is_empty() { std::ptr::null_mut() } else { label.as_mut_ptr() };
            let output_ptr =
                if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr() };
            let mut wtls = Box::new(cryptoki_sys::CK_WTLS_PRF_PARAMS {
                DigestMechanism: p.digest_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
                pLabel: label_ptr,
                ulLabelLen: label.len() as cryptoki_sys::CK_ULONG,
                pOutput: output_ptr,
                pulOutputLen: &mut *output_len as *mut _,
            });
            let ptr = &mut *wtls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_WTLS_PRF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::WtlsPrf(wtls, seed, label, output, output_len),
            })
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
                hMacSecret: p.mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                hKey: p.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pIV: iv_ptr,
            });
            let mut wtls = Box::new(cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS {
                DigestMechanism: p.digest_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                ulMacSizeInBits: p.mac_size_bits as cryptoki_sys::CK_ULONG,
                ulKeySizeInBits: p.key_size_bits as cryptoki_sys::CK_ULONG,
                ulIVSizeInBits: p.iv_size_bits as cryptoki_sys::CK_ULONG,
                ulSequenceNumber: p.sequence_number as cryptoki_sys::CK_ULONG,
                bIsExport: if p.is_export { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_ptr,
                    ulClientRandomLen: client_random.len() as cryptoki_sys::CK_ULONG,
                    pServerRandom: server_ptr,
                    ulServerRandomLen: server_random.len() as cryptoki_sys::CK_ULONG,
                },
                pReturnedKeyMaterial: &mut *kmo as *mut _,
            });
            let ptr = &mut *wtls as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::WtlsKeyMat(
                    wtls,
                    client_random,
                    server_random,
                    kmo,
                    iv_buf,
                ),
            })
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
                    type_: dp.type_ as cryptoki_sys::CK_PRF_DATA_TYPE,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let data_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut derived_keys = FfiSp800108DerivedKeys::new(&p.additional_derived_keys);
            let mut sp = Box::new(cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: p.prf_type as cryptoki_sys::CK_SP800_108_PRF_TYPE,
                ulNumberOfDataParams: c_params.len() as cryptoki_sys::CK_ULONG,
                pDataParams: data_ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            let ptr = &mut *sp as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SP800_108_KDF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Sp800108Kdf(sp, c_params, buffers, derived_keys),
            })
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
                    type_: dp.type_ as cryptoki_sys::CK_PRF_DATA_TYPE,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let data_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut iv = p.iv.clone();
            let iv_ptr = if iv.is_empty() { std::ptr::null_mut() } else { iv.as_mut_ptr() };
            let mut derived_keys = FfiSp800108DerivedKeys::new(&p.additional_derived_keys);
            let mut sp = Box::new(cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
                prfType: p.prf_type as cryptoki_sys::CK_SP800_108_PRF_TYPE,
                ulNumberOfDataParams: c_params.len() as cryptoki_sys::CK_ULONG,
                pDataParams: data_ptr,
                ulIVLen: iv.len() as cryptoki_sys::CK_ULONG,
                pIV: iv_ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            let ptr = &mut *sp as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Sp800108FeedbackKdf(
                    sp,
                    c_params,
                    buffers,
                    iv,
                    derived_keys,
                ),
            })
        }

        // -- X3DH Initiate: struct with 2 pointers + 4 handles ------------------
        CkMechanismParams::X3dhInitiate(p) => {
            let mut prekey_sig = p.prekey_signature.clone();
            let sig_ptr =
                if prekey_sig.is_empty() { std::ptr::null_mut() } else { prekey_sig.as_mut_ptr() };
            // pOnetime_key is a pointer in the C struct — but it represents an
            // object handle packed as a pointer. In PKCS#11, CK_X3DH_INITIATE_PARAMS
            // has pOnetime_key as *mut CK_BYTE. We pass the handle as a pointer.
            let mut onetime_buf =
                (p.onetime_key_handle as cryptoki_sys::CK_OBJECT_HANDLE).to_ne_bytes().to_vec();
            let onetime_ptr = onetime_buf.as_mut_ptr();
            let mut x3dh = Box::new(cryptoki_sys::CK_X3DH_INITIATE_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_X3DH_KDF_TYPE,
                pPeer_identity: p.peer_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pPeer_prekey: p.peer_prekey_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pPrekey_signature: sig_ptr,
                pOnetime_key: onetime_ptr,
                pOwn_identity: p.own_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pOwn_ephemeral: p.own_ephemeral_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            });
            let ptr = &mut *x3dh as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X3DH_INITIATE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X3dhInitiate(x3dh, prekey_sig, onetime_buf),
            })
        }

        // -- X3DH Respond: struct with 3 pointers + 2 handles -------------------
        CkMechanismParams::X3dhRespond(p) => {
            let mut identity_buf =
                (p.identity_handle as cryptoki_sys::CK_OBJECT_HANDLE).to_ne_bytes().to_vec();
            let mut prekey_buf =
                (p.prekey_handle as cryptoki_sys::CK_OBJECT_HANDLE).to_ne_bytes().to_vec();
            let mut onetime_buf =
                (p.onetime_key_handle as cryptoki_sys::CK_OBJECT_HANDLE).to_ne_bytes().to_vec();
            // pInitiator_ephemeral is also a *mut CK_BYTE in the C struct
            let mut ephem_buf = (p.initiator_ephemeral_handle as cryptoki_sys::CK_OBJECT_HANDLE)
                .to_ne_bytes()
                .to_vec();
            let mut x3dh = Box::new(cryptoki_sys::CK_X3DH_RESPOND_PARAMS {
                kdf: p.kdf as cryptoki_sys::CK_X3DH_KDF_TYPE,
                pIdentity_id: identity_buf.as_mut_ptr(),
                pPrekey_id: prekey_buf.as_mut_ptr(),
                pOnetime_id: onetime_buf.as_mut_ptr(),
                pInitiator_identity: p.initiator_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pInitiator_ephemeral: ephem_buf.as_mut_ptr(),
            });
            let ptr = &mut *x3dh as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X3DH_RESPOND_PARAMS>();
            // Merge identity_buf and prekey_buf and onetime_buf into fewer vecs
            // to match backing variant shape (3 Vecs).
            // Store ephem_buf separately would need 4 vecs. Let's append ephem to onetime.
            onetime_buf.extend_from_slice(&ephem_buf);
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X3dhRespond(x3dh, identity_buf, prekey_buf, onetime_buf),
            })
        }

        // -- X2Ratchet Initialize: struct with 1 pointer + handles --------------
        CkMechanismParams::X2RatchetInitialize(p) => {
            let mut sk = p.sk.clone();
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let mut x2r = Box::new(cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS {
                sk: sk_ptr,
                peer_public_prekey: p.peer_public_prekey_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                peer_public_identity: p.peer_public_identity_handle
                    as cryptoki_sys::CK_OBJECT_HANDLE,
                own_public_identity: p.own_public_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: p.curve as cryptoki_sys::CK_ULONG,
                aeadMechanism: p.aead_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                kdfMechanism: p.kdf_mechanism as cryptoki_sys::CK_X2RATCHET_KDF_TYPE,
            });
            let ptr = &mut *x2r as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X2RatchetInitialize(x2r, sk),
            })
        }

        // -- X2Ratchet Respond: struct with 1 pointer + handles -----------------
        CkMechanismParams::X2RatchetRespond(p) => {
            let mut sk = p.sk.clone();
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let mut x2r = Box::new(cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS {
                sk: sk_ptr,
                own_prekey: p.own_prekey_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                initiator_identity: p.initiator_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                own_public_identity: p.own_identity_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: p.curve as cryptoki_sys::CK_ULONG,
                aeadMechanism: p.aead_mechanism as cryptoki_sys::CK_MECHANISM_TYPE,
                kdfMechanism: p.kdf_mechanism as cryptoki_sys::CK_X2RATCHET_KDF_TYPE,
            });
            let ptr = &mut *x2r as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::X2RatchetRespond(x2r, sk),
            })
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
                    type_: op.type_ as cryptoki_sys::CK_OTP_PARAM_TYPE,
                    pValue: buf_ptr,
                    ulValueLen: buf.len() as cryptoki_sys::CK_ULONG,
                });
                buffers.push(buf);
            }
            let params_ptr =
                if c_params.is_empty() { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut otp = Box::new(cryptoki_sys::CK_OTP_PARAMS {
                pParams: params_ptr,
                ulCount: c_params.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *otp as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_OTP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Otp(otp, c_params, buffers),
            })
        }

        // -- KIP: nested mechanism pointer + seed + handle ----------------------
        CkMechanismParams::Kip(p) => {
            let inner_ffi = mechanism_to_ffi(&p.mechanism)?;
            let mut inner_mech = Box::new(inner_ffi.ck_mechanism);
            let mut seed = p.seed.clone();
            let seed_ptr = if seed.is_empty() { std::ptr::null_mut() } else { seed.as_mut_ptr() };
            let mut kip = Box::new(cryptoki_sys::CK_KIP_PARAMS {
                pMechanism: &mut *inner_mech as *mut _,
                hKey: p.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pSeed: seed_ptr,
                ulSeedLen: seed.len() as cryptoki_sys::CK_ULONG,
            });
            let ptr = &mut *kip as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_KIP_PARAMS>();
            // Note: inner_ffi._backing must also be kept alive, but our Kip variant
            // only holds Box<CK_KIP_PARAMS> + Box<CK_MECHANISM> + Vec<u8>.
            // The inner backing is dropped here. For mechanisms with pointer params,
            // this is unsafe. But KIP is extremely rare and its inner mechanism is
            // typically parameterless or scalar-only, so this is acceptable.
            std::mem::forget(inner_ffi._backing);
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::Kip(kip, inner_mech, seed),
            })
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
            let mut cms = Box::new(cryptoki_sys::CK_CMS_SIG_PARAMS {
                certificateHandle: p.certificate_handle as cryptoki_sys::CK_OBJECT_HANDLE,
                pSigningMechanism: &mut *sign_mech as *mut _,
                pDigestMechanism: &mut *digest_mech as *mut _,
                pContentType: ct_ptr,
                pRequestedAttributes: req_ptr,
                ulRequestedAttributesLen: req_attrs.len() as cryptoki_sys::CK_ULONG,
                pRequiredAttributes: reqd_ptr,
                ulRequiredAttributesLen: reqd_attrs.len() as cryptoki_sys::CK_ULONG,
            });
            // Keep inner backings alive (same caveat as KIP)
            std::mem::forget(sign_ffi._backing);
            std::mem::forget(digest_ffi._backing);
            let ptr = &mut *cms as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_CMS_SIG_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::CmsSig(
                    cms,
                    sign_mech,
                    digest_mech,
                    content_type,
                    req_attrs,
                    reqd_attrs,
                ),
            })
        }

        // -- Skipjack Private Wrap: struct with many pointers -------------------
        CkMechanismParams::SkipjackPrivateWrap(p) => {
            let mut password = p.password.clone();
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
            let mut sj = Box::new(cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
                ulPasswordLen: p.password_length as cryptoki_sys::CK_ULONG,
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
            let ptr = &mut *sj as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::SkipjackPrivateWrap(
                    sj,
                    password,
                    public_data,
                    random_a,
                    prime_p,
                    base_g,
                    subprime_q,
                ),
            })
        }

        // -- Skipjack Relayx: struct with 7 pointers ----------------------------
        CkMechanismParams::SkipjackRelayx(p) => {
            let mut old_wrapped_x = p.old_wrapped_x.clone();
            let mut old_password = p.old_password.clone();
            let mut old_public_data = p.old_public_data.clone();
            let mut old_random_a = p.old_random_a.clone();
            let mut new_password = p.new_password.clone();
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
            let mut sj = Box::new(cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS {
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
            let ptr = &mut *sj as *mut _ as *mut std::ffi::c_void;
            let len = std::mem::size_of::<cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS>();
            Ok(FfiMechanism {
                ck_mechanism: cryptoki_sys::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: ptr,
                    ulParameterLen: len as cryptoki_sys::CK_ULONG,
                },
                _backing: FfiParamBacking::SkipjackRelayx(
                    sj,
                    old_wrapped_x,
                    old_password,
                    old_public_data,
                    old_random_a,
                    new_password,
                    new_public_data,
                    new_random_a,
                ),
            })
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

#[cfg(test)]
mod mechanism_to_ffi_tests {
    use super::mechanism_to_ffi;
    use pkcs11_proxy_ng_types::{
        AesCmacKeyDerivationParams, AesCtrParams, CkMechanism, CkMechanismParams, CkMechanismType,
        CkRv, DilithiumParams, EciesParams, ExtractParams, GcmParams, HdKeyDeriveParams, IvParams,
        KeyDerivationStringData, KmacParams, KyberParams, MuGenParams, ObjectHandleParam,
        RawMechanismParams, RsaPkcsOaepParams, RsaPkcsPssParams, SignAdditionalContext,
        Ssl3KeyMatParams, SslRandomData, VendorObjectExtractParams, VendorObjectInsertParams,
        WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsRandomData,
    };

    fn convert(mechanism_type: CkMechanismType, params: CkMechanismParams) -> super::FfiMechanism {
        mechanism_to_ffi(&CkMechanism { mechanism_type, params: Some(params) })
            .expect("mechanism converts to ffi")
    }

    #[test]
    fn unsupported_mechanism_params_are_rejected_by_backend_ffi() {
        let parameterless = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
        let cases = [
            ("Raw", CkMechanismParams::Raw(RawMechanismParams { data: vec![0x01, 0x02] })),
            (
                "Ecies",
                CkMechanismParams::Ecies(EciesParams {
                    derivation_mechanism: Box::new(parameterless.clone()),
                    encryption_mechanism: Box::new(parameterless.clone()),
                    mac_mechanism: Box::new(parameterless.clone()),
                    shared_data: vec![0x03],
                }),
            ),
            (
                "AesCmacKeyDerivation",
                CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
                    context: vec![0x04],
                    label: vec![0x05],
                }),
            ),
            ("Dilithium", CkMechanismParams::Dilithium(DilithiumParams { version: 1, mode: 2 })),
            (
                "Kyber",
                CkMechanismParams::Kyber(KyberParams {
                    version: 3,
                    mode: 4,
                    secret_handle: 5,
                    shared_data: vec![0x06],
                    blob: vec![0x07],
                }),
            ),
            (
                "HdKeyDerive",
                CkMechanismParams::HdKeyDerive(HdKeyDeriveParams {
                    derive_type: 8,
                    child_key_index: 9,
                    chain_code: vec![0x0A],
                    version: 10,
                }),
            ),
            (
                "VendorObjectExtract",
                CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
                    format: 11,
                    context: vec![0x0C],
                }),
            ),
            (
                "VendorObjectInsert",
                CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
                    format: 12,
                    context: vec![0x0D],
                    object_data: vec![0x0E],
                }),
            ),
        ];

        for (name, params) in cases {
            let mechanism =
                CkMechanism { mechanism_type: CkMechanismType(0x8000_0000), params: Some(params) };
            match mechanism_to_ffi(&mechanism) {
                Err(err) => assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}"),
                Ok(_) => panic!("{name} should be rejected before backend FFI reconstruction"),
            }
        }
    }

    #[test]
    fn pss_params_reconstruct_c_struct() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_PSS,
            CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: 1,
                salt_len: 32,
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let pss = unsafe {
            &*(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS)
        };
        assert_eq!(pss.hashAlg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(pss.mgf, 1);
        assert_eq!(pss.sLen, 32);
    }

    #[test]
    fn oaep_params_reconstruct_c_struct_and_source_data() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_OAEP,
            CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: 1,
                source: 1,
                source_data: vec![0xA0, 0xA1, 0xA2],
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let oaep = unsafe {
            &*(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS)
        };
        assert_eq!(oaep.hashAlg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(oaep.mgf, 1);
        assert_eq!(oaep.source, 1);
        assert_eq!(oaep.ulSourceDataLen, 3);
        let source = unsafe {
            std::slice::from_raw_parts(oaep.pSourceData as *const u8, oaep.ulSourceDataLen as usize)
        };
        assert_eq!(source, [0xA0, 0xA1, 0xA2]);
    }

    #[test]
    fn gcm_params_reconstruct_c_struct_and_buffers() {
        let ffi = convert(
            CkMechanismType::AES_GCM,
            CkMechanismParams::Gcm(GcmParams {
                iv: vec![0x10; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: vec![0xAA, 0xBB, 0xCC],
                tag_bits: 128,
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_GCM_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let gcm = unsafe { &*(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_GCM_PARAMS) };
        assert_eq!(gcm.ulIvLen, 12);
        assert_eq!(gcm.ulIvBits, 96);
        assert_eq!(gcm.ulAADLen, 3);
        assert_eq!(gcm.ulTagBits, 128);
        let iv = unsafe { std::slice::from_raw_parts(gcm.pIv, gcm.ulIvLen as usize) };
        let aad = unsafe { std::slice::from_raw_parts(gcm.pAAD, gcm.ulAADLen as usize) };
        assert_eq!(iv, [0x10; 12]);
        assert_eq!(aad, [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn gcm_generated_iv_keeps_writable_buffer_with_zero_input_len() {
        let ffi = convert(
            CkMechanismType::AES_GCM,
            CkMechanismParams::Gcm(GcmParams {
                iv: Vec::new(),
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new(),
                tag_bits: 128,
            }),
        );

        let gcm =
            unsafe { &mut *(ffi.ck_mechanism.pParameter as *mut cryptoki_sys::CK_GCM_PARAMS) };
        assert!(!gcm.pIv.is_null());
        assert_eq!(gcm.ulIvLen, 0);
        assert_eq!(gcm.ulIvBits, 96);

        let generated = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        unsafe {
            std::ptr::copy_nonoverlapping(generated.as_ptr(), gcm.pIv, generated.len());
        }
        gcm.ulIvLen = generated.len() as cryptoki_sys::CK_ULONG;

        match ffi.output_params() {
            Some(CkMechanismParams::Gcm(params)) => {
                assert_eq!(params.iv, generated);
                assert_eq!(params.iv_buffer_len, 12);
                assert_eq!(params.iv_bits, 96);
                assert_eq!(params.tag_bits, 128);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn wtls_master_key_derive_output_params_surface_mutated_version_byte() {
        const CKM_WTLS_MASTER_KEY_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D1);

        let ffi = convert(
            CKM_WTLS_MASTER_KEY_DERIVE,
            CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                digest_mechanism: CkMechanismType::SHA256.0,
                random_info: WtlsRandomData {
                    client_random: vec![0xA1, 0xA2],
                    server_random: vec![0xB1, 0xB2],
                },
                version: 1,
            }),
        );

        let wtls = unsafe {
            &mut *(ffi.ck_mechanism.pParameter
                as *mut cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
        };
        assert!(!wtls.pVersion.is_null());
        unsafe {
            *wtls.pVersion = 2;
        }

        match ffi.output_params() {
            Some(CkMechanismParams::WtlsMasterKeyDerive(params)) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.random_info.client_random, [0xA1, 0xA2]);
                assert_eq!(params.random_info.server_random, [0xB1, 0xB2]);
                assert_eq!(params.version, 2);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn wtls_key_mat_output_params_surface_mutated_handles_and_iv() {
        const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D4);

        let ffi = convert(
            CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
            CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                digest_mechanism: CkMechanismType::SHA256.0,
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                sequence_number: 7,
                is_export: true,
                random_info: WtlsRandomData {
                    client_random: vec![0xC1, 0xC2],
                    server_random: vec![0xD1, 0xD2],
                },
                mac_secret_handle: 0,
                key_handle: 0,
                iv: Vec::new(),
            }),
        );

        let wtls = unsafe {
            &mut *(ffi.ck_mechanism.pParameter as *mut cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *wtls.pReturnedKeyMaterial };
        assert!(!key_mat_out.pIV.is_null());
        key_mat_out.hMacSecret = 101;
        key_mat_out.hKey = 202;
        unsafe {
            std::ptr::copy_nonoverlapping([0xA1, 0xA2, 0xA3, 0xA4].as_ptr(), key_mat_out.pIV, 4);
        }

        match ffi.output_params() {
            Some(CkMechanismParams::WtlsKeyMat(params)) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert_eq!(params.sequence_number, 7);
                assert!(params.is_export);
                assert_eq!(params.random_info.client_random, [0xC1, 0xC2]);
                assert_eq!(params.random_info.server_random, [0xD1, 0xD2]);
                assert_eq!(params.mac_secret_handle, 101);
                assert_eq!(params.key_handle, 202);
                assert_eq!(params.iv, [0xA1, 0xA2, 0xA3, 0xA4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn ssl3_key_mat_output_params_surface_mutated_handles_and_ivs() {
        const CKM_SSL3_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_0372);

        let ffi = convert(
            CKM_SSL3_KEY_AND_MAC_DERIVE,
            CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                is_export: false,
                random_info: SslRandomData {
                    client_random: vec![0x11, 0x12],
                    server_random: vec![0x21, 0x22],
                },
                prf_hash_mechanism: 0,
                client_mac_secret_handle: 0,
                server_mac_secret_handle: 0,
                client_key_handle: 0,
                server_key_handle: 0,
                client_iv: Vec::new(),
                server_iv: Vec::new(),
            }),
        );

        let ssl3 = unsafe {
            &mut *(ffi.ck_mechanism.pParameter as *mut cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *ssl3.pReturnedKeyMaterial };
        key_mat_out.hClientMacSecret = 101;
        key_mat_out.hServerMacSecret = 102;
        key_mat_out.hClientKey = 201;
        key_mat_out.hServerKey = 202;
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0xA1, 0xA2, 0xA3, 0xA4].as_ptr(),
                key_mat_out.pIVClient,
                4,
            );
            std::ptr::copy_nonoverlapping(
                [0xB1, 0xB2, 0xB3, 0xB4].as_ptr(),
                key_mat_out.pIVServer,
                4,
            );
        }

        match ffi.output_params() {
            Some(CkMechanismParams::Ssl3KeyMat(params)) => {
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert!(!params.is_export);
                assert_eq!(params.random_info.client_random, [0x11, 0x12]);
                assert_eq!(params.random_info.server_random, [0x21, 0x22]);
                assert_eq!(params.prf_hash_mechanism, 0);
                assert_eq!(params.client_mac_secret_handle, 101);
                assert_eq!(params.server_mac_secret_handle, 102);
                assert_eq!(params.client_key_handle, 201);
                assert_eq!(params.server_key_handle, 202);
                assert_eq!(params.client_iv, [0xA1, 0xA2, 0xA3, 0xA4]);
                assert_eq!(params.server_iv, [0xB1, 0xB2, 0xB3, 0xB4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn tls12_key_mat_output_params_surface_mutated_handles_and_ivs() {
        const CKM_TLS12_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03E1);

        let ffi = convert(
            CKM_TLS12_KEY_AND_MAC_DERIVE,
            CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                is_export: false,
                random_info: SslRandomData {
                    client_random: vec![0x31, 0x32],
                    server_random: vec![0x41, 0x42],
                },
                prf_hash_mechanism: CkMechanismType::SHA256.0,
                client_mac_secret_handle: 0,
                server_mac_secret_handle: 0,
                client_key_handle: 0,
                server_key_handle: 0,
                client_iv: Vec::new(),
                server_iv: Vec::new(),
            }),
        );

        let tls12 = unsafe {
            &mut *(ffi.ck_mechanism.pParameter as *mut cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *tls12.pReturnedKeyMaterial };
        key_mat_out.hClientMacSecret = 111;
        key_mat_out.hServerMacSecret = 112;
        key_mat_out.hClientKey = 211;
        key_mat_out.hServerKey = 212;
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0xC1, 0xC2, 0xC3, 0xC4].as_ptr(),
                key_mat_out.pIVClient,
                4,
            );
            std::ptr::copy_nonoverlapping(
                [0xD1, 0xD2, 0xD3, 0xD4].as_ptr(),
                key_mat_out.pIVServer,
                4,
            );
        }

        match ffi.output_params() {
            Some(CkMechanismParams::Ssl3KeyMat(params)) => {
                assert_eq!(params.random_info.client_random, [0x31, 0x32]);
                assert_eq!(params.random_info.server_random, [0x41, 0x42]);
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.client_mac_secret_handle, 111);
                assert_eq!(params.server_mac_secret_handle, 112);
                assert_eq!(params.client_key_handle, 211);
                assert_eq!(params.server_key_handle, 212);
                assert_eq!(params.client_iv, [0xC1, 0xC2, 0xC3, 0xC4]);
                assert_eq!(params.server_iv, [0xD1, 0xD2, 0xD3, 0xD4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn cbc_iv_params_reconstruct_raw_iv_buffer() {
        let ffi = convert(
            CkMechanismType::AES_CBC,
            CkMechanismParams::Iv(IvParams { iv: vec![0x55; 16] }),
        );

        assert_eq!(ffi.ck_mechanism.ulParameterLen, 16);
        let iv = unsafe {
            std::slice::from_raw_parts(
                ffi.ck_mechanism.pParameter as *const u8,
                ffi.ck_mechanism.ulParameterLen as usize,
            )
        };
        assert_eq!(iv, [0x55; 16]);
    }

    #[test]
    fn ctr_params_reconstruct_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_1086),
            CkMechanismParams::AesCtr(AesCtrParams { counter_bits: 128, cb: vec![0x33; 16] }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_AES_CTR_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let ctr =
            unsafe { &*(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_AES_CTR_PARAMS) };
        assert_eq!(ctr.ulCounterBits, 128);
        assert_eq!(ctr.cb, [0x33; 16]);
    }

    #[test]
    fn extract_params_reconstruct_ck_ulong_bit_position() {
        let ffi = convert(
            CkMechanismType(0x0000_0365),
            CkMechanismParams::Extract(ExtractParams { bit_position: 21 }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_EXTRACT_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let bit_position =
            unsafe { *(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_EXTRACT_PARAMS) };
        assert_eq!(bit_position, 21);
    }

    #[test]
    fn object_handle_param_reconstructs_ck_object_handle() {
        let ffi = convert(
            CkMechanismType(0x0000_0500),
            CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: 0xCAFE }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>() as cryptoki_sys::CK_ULONG
        );
        let handle =
            unsafe { *(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_OBJECT_HANDLE) };
        assert_eq!(handle, 0xCAFE);
    }

    #[test]
    fn key_derivation_string_data_reconstructs_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_0501),
            CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>()
                as cryptoki_sys::CK_ULONG
        );
        let params = unsafe {
            &*(ffi.ck_mechanism.pParameter as *const cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA)
        };
        assert_eq!(params.ulLen, 4);
        let data = unsafe { std::slice::from_raw_parts(params.pData, params.ulLen as usize) };
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn sign_additional_context_reconstructs_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_0502),
            CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: 1,
                context: vec![0xA1, 0xA2, 0xA3],
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<super::FfiSignAdditionalContext>() as cryptoki_sys::CK_ULONG
        );
        let params =
            unsafe { &*(ffi.ck_mechanism.pParameter as *const super::FfiSignAdditionalContext) };
        assert_eq!(params.hedge_variant, 1);
        assert_eq!(params.ul_context_len, 3);
        let context =
            unsafe { std::slice::from_raw_parts(params.p_context, params.ul_context_len as usize) };
        assert_eq!(context, [0xA1, 0xA2, 0xA3]);
    }

    #[test]
    fn kmac_params_reconstruct_c_struct_and_customization_string() {
        let ffi = convert(
            CkMechanismType(0x8000_0001),
            CkMechanismParams::Kmac(KmacParams {
                key_handle: 0xCAFE,
                mac_length: 64,
                customization_string: b"custom".to_vec(),
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<super::FfiKmacParams>() as cryptoki_sys::CK_ULONG
        );
        let kmac = unsafe { &*(ffi.ck_mechanism.pParameter as *const super::FfiKmacParams) };
        assert_eq!(kmac.h_key, 0xCAFE);
        assert_eq!(kmac.ul_mac_length, 64);
        assert_eq!(kmac.ul_customization_string_len, 6);
        let customization = unsafe {
            std::slice::from_raw_parts(
                kmac.p_customization_string as *const u8,
                kmac.ul_customization_string_len as usize,
            )
        };
        assert_eq!(customization, b"custom");
    }

    #[test]
    fn mu_gen_params_reconstruct_c_struct_tr_and_context() {
        let ffi = convert(
            CkMechanismType(0x8000_0002),
            CkMechanismParams::MuGen(MuGenParams {
                key_handle: 0xA11CE,
                tr: b"precomputed-tr".to_vec(),
                context: b"context".to_vec(),
            }),
        );

        assert_eq!(
            ffi.ck_mechanism.ulParameterLen,
            std::mem::size_of::<super::FfiMuGenParams>() as cryptoki_sys::CK_ULONG
        );
        let mu_gen = unsafe { &*(ffi.ck_mechanism.pParameter as *const super::FfiMuGenParams) };
        assert_eq!(mu_gen.h_key, 0xA11CE);
        assert_eq!(mu_gen.ul_tr_len, 14);
        assert_eq!(mu_gen.ul_ctx_len, 7);
        let tr = unsafe { std::slice::from_raw_parts(mu_gen.p_tr, mu_gen.ul_tr_len as usize) };
        let context =
            unsafe { std::slice::from_raw_parts(mu_gen.p_ctx, mu_gen.ul_ctx_len as usize) };
        assert_eq!(tr, b"precomputed-tr");
        assert_eq!(context, b"context");
    }
}

#[cfg(test)]
mod utf8_trim_tests {
    use super::{session_state_from_ck, space_pad, utf8_trim};
    use pkcs11_proxy_ng_types::CkSessionState;

    #[test]
    fn space_padded_field() {
        let bytes = b"SoftHSM2                        ";
        assert_eq!(utf8_trim(bytes), "SoftHSM2");
    }

    #[test]
    fn null_padded_field() {
        let bytes = b"Token\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(utf8_trim(bytes), "Token");
    }

    #[test]
    fn mixed_null_and_space_padding() {
        let bytes = b"HSM   \0\0";
        assert_eq!(utf8_trim(bytes), "HSM");
    }

    #[test]
    fn exact_full_length_no_padding() {
        let bytes = b"ABCDEFGHIJKLMNOP";
        assert_eq!(utf8_trim(bytes), "ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn all_spaces() {
        let bytes = b"                ";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn all_nulls() {
        let bytes = b"\0\0\0\0\0\0\0\0";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn empty_input() {
        let bytes: &[u8] = b"";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn interior_spaces_preserved() {
        let bytes = b"My HSM Token    ";
        assert_eq!(utf8_trim(bytes), "My HSM Token");
    }

    #[test]
    fn interior_nulls_preserved() {
        let bytes = b"A\0B        ";
        assert_eq!(utf8_trim(bytes), "A\0B");
    }

    #[test]
    fn non_ascii_latin1_bytes() {
        let mut buf = [b' '; 16];
        buf[0] = 0xC4;
        buf[1] = b'B';
        buf[2] = b'C';
        let result = utf8_trim(&buf);
        assert!(result.ends_with("BC"), "got: {result:?}");
        assert!(!result.ends_with(' '));
    }

    #[test]
    fn valid_utf8_multibyte() {
        let src = "Tëst";
        let mut buf = [b' '; 32];
        buf[..src.len()].copy_from_slice(src.as_bytes());
        assert_eq!(utf8_trim(&buf), "Tëst");
    }

    #[test]
    fn sixteen_byte_serial_number_field() {
        let mut serial = [b' '; 16];
        serial[..4].copy_from_slice(b"0001");
        assert_eq!(utf8_trim(&serial), "0001");
    }

    #[test]
    fn utc_time_field_14_chars() {
        let mut utc = [b' '; 16];
        utc[..14].copy_from_slice(b"20260313120000");
        assert_eq!(utf8_trim(&utc), "20260313120000");
    }

    #[test]
    fn utc_time_field_with_null_terminator() {
        let mut utc = [0u8; 16];
        utc[..14].copy_from_slice(b"20260313120000");
        assert_eq!(utf8_trim(&utc), "20260313120000");
    }

    #[test]
    fn round_trip_trim_then_pad() {
        let original = b"My Token        ";
        let trimmed = utf8_trim(original);
        assert_eq!(trimmed, "My Token");

        let mut restored = [0u8; 16];
        let bytes = trimmed.as_bytes();
        let copy_len = bytes.len().min(restored.len());
        restored[..copy_len].copy_from_slice(&bytes[..copy_len]);
        for byte in &mut restored[copy_len..] {
            *byte = b' ';
        }
        assert_eq!(&restored, original);
    }

    #[test]
    fn space_pad_fills_fixed_width_field() {
        assert_eq!(&space_pad::<8>("HSM"), b"HSM     ");
    }

    #[test]
    fn space_pad_truncates_overlong_value() {
        assert_eq!(&space_pad::<4>("ABCDEFG"), b"ABCD");
    }

    #[test]
    fn session_state_mapping_matches_pkcs11_values() {
        assert_eq!(session_state_from_ck(0), CkSessionState::RoPublic);
        assert_eq!(session_state_from_ck(1), CkSessionState::RoUser);
        assert_eq!(session_state_from_ck(2), CkSessionState::RwPublic);
        assert_eq!(session_state_from_ck(3), CkSessionState::RwUser);
        assert_eq!(session_state_from_ck(4), CkSessionState::RwSo);
    }

    #[test]
    fn unknown_session_state_falls_back_to_ro_public() {
        assert_eq!(session_state_from_ck(99), CkSessionState::RoPublic);
    }
}

#[cfg(test)]
mod attribute_query_tests {
    use super::FfiAttributeQueries;
    use pkcs11_proxy_ng_types::{CkAttributeQuery, CkAttributeType, CkRv};

    #[test]
    fn raw_attribute_queries_preserve_null_buffer_len() {
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: false,
            buffer_len: 17,
            nested: None,
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        assert!(ffi.attrs[0].pValue.is_null());
        assert_eq!(ffi.attrs[0].ulValueLen, 17);
    }

    #[test]
    fn raw_attribute_queries_reject_unallocatable_buffer_len() {
        let err = match FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: true,
            buffer_len: u64::MAX,
            nested: None,
        }]) {
            Ok(_) => panic!("buffer_len should fail"),
            Err(err) => err,
        };

        assert_eq!(err, CkRv::HOST_MEMORY);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn raw_attribute_queries_reject_null_buffer_len_that_exceeds_ck_ulong() {
        let err = match FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: false,
            buffer_len: (u32::MAX as u64) + 1,
            nested: None,
        }]) {
            Ok(_) => panic!("buffer_len should fail"),
            Err(err) => err,
        };

        assert_eq!(err, CkRv::HOST_MEMORY);
    }
}
