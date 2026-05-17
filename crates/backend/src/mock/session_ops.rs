use pkcs11_proxy_ng_types::*;

use super::{MockBackend, compute_session_state};

impl MockBackend {
    pub(super) fn noop_ok(&self) -> CkResult<()> {
        Ok(())
    }

    pub(super) fn initialize_backend(&self) -> CkResult<()> {
        let mut queue = self.slot_event_queue.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if state.initialized {
            return Err(CkRv::CRYPTOKI_ALREADY_INITIALIZED);
        }
        queue.clear();
        state.initialized = true;
        Ok(())
    }

    pub(super) fn finalize_backend(&self) -> CkResult<()> {
        {
            let mut state = self.state.lock().unwrap();
            if !state.initialized {
                return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
            }
            state.initialized = false;
            state.open_sessions.clear();
            state.login_state.clear();
            state.live_objects.clear();
            state.session_objects.clear();
            state.active_ops.clear();
        }
        self.slot_event_queue.lock().unwrap().clear();
        self.slot_event_condvar.notify_all();
        self.attribute_store.lock().unwrap().clear();
        self.clear_all_session_scoped_side_state();
        Ok(())
    }

    pub(super) fn backend_info(&self) -> CkResult<CkInfo> {
        Ok(CkInfo {
            cryptoki_version: (3, 0),
            manufacturer_id: "MockBackend".into(),
            flags: 0,
            library_description: "Mock PKCS#11 for testing".into(),
            library_version: (0, 1),
        })
    }

    pub(super) fn slot_list(&self) -> CkResult<Vec<CkSlotId>> {
        Ok(self.slots.clone())
    }

    pub(super) fn slot_list_for_presence(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        if token_present {
            Ok(self
                .slots
                .iter()
                .copied()
                .filter(|slot| self.token_present_for_slot(*slot))
                .collect())
        } else {
            self.slot_list()
        }
    }

    pub(super) fn slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        let mut flags = CkSlotFlags::HW_SLOT;
        if self.token_present_for_slot(slot_id) {
            flags |= CkSlotFlags::TOKEN_PRESENT;
        }
        Ok(CkSlotInfo {
            slot_description: format!("Mock Slot {}", slot_id.0),
            manufacturer_id: "Mock".into(),
            flags: CkSlotFlags(flags),
            hardware_version: (1, 0),
            firmware_version: (1, 0),
        })
    }

    pub(super) fn token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        Ok(CkTokenInfo {
            label: "MockToken".into(),
            manufacturer_id: "Mock".into(),
            model: "Software".into(),
            serial_number: "0001".into(),
            flags: CkTokenFlags(CkTokenFlags::TOKEN_INITIALIZED),
            max_session_count: 256,
            session_count: 0,
            max_rw_session_count: 256,
            rw_session_count: 0,
            max_pin_len: 64,
            min_pin_len: 4,
            total_public_memory: u64::MAX,
            free_public_memory: u64::MAX,
            total_private_memory: u64::MAX,
            free_private_memory: u64::MAX,
            hardware_version: (1, 0),
            firmware_version: (1, 0),
            utc_time: String::new(),
        })
    }

    pub(super) fn mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        Ok(self.mechanisms_for_slot(slot_id))
    }

    pub(super) fn mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        if !self.mechanisms_for_slot(slot_id).contains(&mech) {
            return Err(CkRv::MECHANISM_INVALID);
        }
        Ok(CkMechanismInfo {
            min_key_size: 2048,
            max_key_size: 4096,
            flags: CkMechanismFlags(mock_mechanism_workflow_flags(mech)),
        })
    }

    pub(super) fn open_session_impl(
        &self,
        slot_id: CkSlotId,
        flags: CkSessionFlags,
    ) -> CkResult<CkSessionHandle> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        let mut state = self.state.lock().unwrap();
        if self.max_sessions > 0 && state.open_sessions.len() as u64 >= self.max_sessions {
            return Err(CkRv::SESSION_COUNT);
        }
        let handle = CkSessionHandle(state.next_session);
        state.next_session += 1;
        state.open_sessions.push((handle, slot_id, flags));
        Ok(handle)
    }

    pub(super) fn close_session_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(pos) = state.open_sessions.iter().position(|(handle, _, _)| *handle == session)
        {
            let (_, slot_id, _) = state.open_sessions.remove(pos);
            state.active_ops.remove(&session.0);
            self.remove_session_owned_objects(&mut state, &[session.0]);
            self.clear_session_scoped_side_state(session.0);
            if !state.open_sessions.iter().any(|(_, open_slot, _)| *open_slot == slot_id) {
                state.login_state.remove(&slot_id);
            }
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    pub(super) fn close_all_sessions_impl(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.require_known_slot(slot_id)?;
        let mut state = self.state.lock().unwrap();
        let closing: Vec<u64> = state
            .open_sessions
            .iter()
            .filter(|(_, open_slot, _)| *open_slot == slot_id)
            .map(|(handle, _, _)| handle.0)
            .collect();
        state.open_sessions.retain(|(_, open_slot, _)| *open_slot != slot_id);
        for handle in &closing {
            state.active_ops.remove(handle);
        }
        self.remove_session_owned_objects(&mut state, &closing);
        for handle in &closing {
            self.clear_session_scoped_side_state(*handle);
        }
        state.login_state.remove(&slot_id);
        Ok(())
    }

    pub(super) fn session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        let state = self.state.lock().unwrap();
        if let Some((slot_id, flags)) = state.session_record(session) {
            let login_user = state.login_state.get(&slot_id).copied();
            Ok(CkSessionInfo {
                slot_id,
                state: compute_session_state(flags, login_user),
                flags: CkSessionFlags(flags.0 | CkSessionFlags::SERIAL_SESSION),
                device_error: 0,
            })
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    pub(super) fn login_impl(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        let slot_id = match state.session_record(session) {
            Some((slot_id, _)) => slot_id,
            None => return Err(CkRv::SESSION_HANDLE_INVALID),
        };
        if state.login_state.contains_key(&slot_id) {
            return Err(CkRv::USER_ALREADY_LOGGED_IN);
        }
        state.login_state.insert(slot_id, user_type);
        Ok(())
    }

    pub(super) fn logout_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        let slot_id = match state.session_record(session) {
            Some((slot_id, _)) => slot_id,
            None => return Err(CkRv::SESSION_HANDLE_INVALID),
        };
        if state.login_state.remove(&slot_id).is_none() {
            return Err(CkRv::USER_NOT_LOGGED_IN);
        }
        Ok(())
    }

    pub(super) fn wait_for_slot_event_impl(&self, flags: u64) -> CkResult<CkSlotId> {
        let dont_block = flags & 0x1 != 0;
        let mut queue = self.slot_event_queue.lock().unwrap();

        loop {
            if !self.state.lock().unwrap().initialized {
                return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
            }
            if let Some(slot) = queue.pop_front() {
                return Ok(slot);
            }
            if dont_block {
                return Err(CkRv::NO_EVENT);
            }
            queue = self.slot_event_condvar.wait(queue).unwrap();
        }
    }
}

pub(super) fn mock_mechanism_workflow_flags(mech: CkMechanismType) -> u64 {
    let encrypt_decrypt = CkMechanismFlags::ENCRYPT | CkMechanismFlags::DECRYPT;
    let sign_verify = CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY;
    let sign_recover_verify_recover =
        CkMechanismFlags::SIGN_RECOVER | CkMechanismFlags::VERIFY_RECOVER;
    let wrap_unwrap = CkMechanismFlags::WRAP | CkMechanismFlags::UNWRAP;
    let message_encrypt_decrypt =
        CkMechanismFlags::MESSAGE_ENCRYPT | CkMechanismFlags::MESSAGE_DECRYPT;
    let encapsulate_decapsulate = CkMechanismFlags::ENCAPSULATE | CkMechanismFlags::DECAPSULATE;
    let generate_and_generate_key_pair =
        CkMechanismFlags::GENERATE | CkMechanismFlags::GENERATE_KEY_PAIR;

    match mech {
        CkMechanismType::RSA_PKCS_KEY_PAIR_GEN
        | CkMechanismType::RSA_X9_31_KEY_PAIR_GEN
        | CkMechanismType::DH_PKCS_KEY_PAIR_GEN
        | CkMechanismType::X9_42_DH_KEY_PAIR_GEN
        | CkMechanismType::GOSTR3410_KEY_PAIR_GEN
        | CkMechanismType::EC_KEY_PAIR_GEN
        | CkMechanismType::EC_EDWARDS_KEY_PAIR_GEN
        | CkMechanismType::EC_MONTGOMERY_KEY_PAIR_GEN
        | CkMechanismType::HSS_KEY_PAIR_GEN
        | CkMechanismType::XMSS_KEY_PAIR_GEN
        | CkMechanismType::XMSSMT_KEY_PAIR_GEN => CkMechanismFlags::GENERATE_KEY_PAIR,
        CkMechanismType(0x0000_000F)
        | CkMechanismType(0x0000_0010)
        | CkMechanismType(0x0000_001C)
        | CkMechanismType(0x0000_002D) => CkMechanismFlags::GENERATE_KEY_PAIR,
        CkMechanismType(0x0000_2000)
        | CkMechanismType(0x0000_2003)
        | CkMechanismType(0x0000_2004)
        | CkMechanismType(0x0000_2005)
        | CkMechanismType::DH_PKCS_PARAMETER_GEN
        | CkMechanismType::X9_42_DH_PARAMETER_GEN
        | CkMechanismType::EC_KEY_PAIR_GEN_W_EXTRA_BITS => generate_and_generate_key_pair,
        CkMechanismType(0x0000_0017) => encapsulate_decapsulate,
        CkMechanismType(0x0000_02A0) => sign_verify,
        CkMechanismType(0x0000_02A1) => CkMechanismFlags::GENERATE,
        CkMechanismType::AES_KEY_GEN
        | CkMechanismType::AES_XTS_KEY_GEN
        | CkMechanismType::CHACHA20_KEY_GEN
        | CkMechanismType::SALSA20_KEY_GEN
        | CkMechanismType::POLY1305_KEY_GEN
        | CkMechanismType::ARIA_KEY_GEN
        | CkMechanismType::CAMELLIA_KEY_GEN
        | CkMechanismType::SEED_KEY_GEN
        | CkMechanismType::DES_KEY_GEN
        | CkMechanismType::DES2_KEY_GEN
        | CkMechanismType::DES3_KEY_GEN
        | CkMechanismType::BLOWFISH_KEY_GEN
        | CkMechanismType::TWOFISH_KEY_GEN
        | CkMechanismType::SECURID_KEY_GEN
        | CkMechanismType::HOTP_KEY_GEN
        | CkMechanismType::PBE_SHA1_DES3_EDE_CBC
        | CkMechanismType::PBE_SHA1_DES2_EDE_CBC
        | CkMechanismType::PKCS5_PBKD2
        | CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC
        | CkMechanismType::GOST28147_KEY_GEN
        | CkMechanismType::SSL3_PRE_MASTER_KEY_GEN
        | CkMechanismType::TLS_PRE_MASTER_KEY_GEN
        | CkMechanismType::WTLS_PRE_MASTER_KEY_GEN
        | CkMechanismType::GENERIC_SECRET_KEY_GEN
        | CkMechanismType::HKDF_KEY_GEN => CkMechanismFlags::GENERATE,
        CkMechanismType::MD2
        | CkMechanismType::MD5
        | CkMechanismType(0x0000_0220)
        | CkMechanismType::SHA256
        | CkMechanismType(0x0000_0255)
        | CkMechanismType::SHA384
        | CkMechanismType::SHA512
        | CkMechanismType(0x0000_0048)
        | CkMechanismType(0x0000_004C)
        | CkMechanismType(0x0000_0050)
        | CkMechanismType(0x0000_400C)
        | CkMechanismType(0x0000_4011)
        | CkMechanismType(0x0000_4016)
        | CkMechanismType(0x0000_401B)
        | CkMechanismType(0x0000_02B5)
        | CkMechanismType(0x0000_02B0)
        | CkMechanismType(0x0000_02C0)
        | CkMechanismType(0x0000_02D0)
        | CkMechanismType::GOSTR3411 => CkMechanismFlags::DIGEST,
        CkMechanismType(0x0000_0221)
        | CkMechanismType(0x0000_0222)
        | CkMechanismType(0x0000_0256)
        | CkMechanismType(0x0000_0257)
        | CkMechanismType(0x0000_0251)
        | CkMechanismType(0x0000_0252)
        | CkMechanismType(0x0000_0261)
        | CkMechanismType(0x0000_0262)
        | CkMechanismType(0x0000_0271)
        | CkMechanismType(0x0000_0272)
        | CkMechanismType(0x0000_0049)
        | CkMechanismType(0x0000_004A)
        | CkMechanismType(0x0000_004D)
        | CkMechanismType(0x0000_004E)
        | CkMechanismType(0x0000_0051)
        | CkMechanismType(0x0000_0052)
        | CkMechanismType(0x0000_400D)
        | CkMechanismType(0x0000_400E)
        | CkMechanismType(0x0000_4012)
        | CkMechanismType(0x0000_4013)
        | CkMechanismType(0x0000_4017)
        | CkMechanismType(0x0000_4018)
        | CkMechanismType(0x0000_401C)
        | CkMechanismType(0x0000_401D)
        | CkMechanismType(0x0000_02B6)
        | CkMechanismType(0x0000_02B7)
        | CkMechanismType(0x0000_02B1)
        | CkMechanismType(0x0000_02B2)
        | CkMechanismType(0x0000_02C1)
        | CkMechanismType(0x0000_02C2)
        | CkMechanismType(0x0000_02D1)
        | CkMechanismType(0x0000_02D2)
        | CkMechanismType::AES_MAC
        | CkMechanismType::AES_MAC_GENERAL
        | CkMechanismType::AES_CMAC
        | CkMechanismType::AES_CMAC_GENERAL
        | CkMechanismType::AES_XCBC_MAC
        | CkMechanismType::AES_XCBC_MAC_96
        | CkMechanismType::AES_GMAC
        | CkMechanismType::POLY1305
        | CkMechanismType::ARIA_MAC
        | CkMechanismType::ARIA_MAC_GENERAL
        | CkMechanismType::CAMELLIA_MAC
        | CkMechanismType::CAMELLIA_MAC_GENERAL
        | CkMechanismType::SEED_MAC
        | CkMechanismType::SEED_MAC_GENERAL
        | CkMechanismType::DES_MAC
        | CkMechanismType::DES3_MAC
        | CkMechanismType::DES3_MAC_GENERAL
        | CkMechanismType::DES3_CMAC
        | CkMechanismType::DES3_CMAC_GENERAL
        | CkMechanismType::SECURID
        | CkMechanismType::HOTP
        | CkMechanismType::SSL3_MD5_MAC
        | CkMechanismType::SSL3_SHA1_MAC
        | CkMechanismType::TLS_MAC
        | CkMechanismType::TLS12_MAC
        | CkMechanismType::RSA_X9_31
        | CkMechanismType::GOSTR3410
        | CkMechanismType::GOSTR3410_WITH_GOSTR3411
        | CkMechanismType::GOSTR3411_HMAC
        | CkMechanismType::GOST28147_MAC
        | CkMechanismType::KIP_MAC => sign_verify,
        CkMechanismType::RSA_PKCS => {
            encapsulate_decapsulate
                | encrypt_decrypt
                | sign_verify
                | sign_recover_verify_recover
                | wrap_unwrap
        }
        CkMechanismType::RSA_X_509 => {
            encapsulate_decapsulate
                | encrypt_decrypt
                | sign_verify
                | sign_recover_verify_recover
                | wrap_unwrap
        }
        CkMechanismType::RSA_PKCS_OAEP => encapsulate_decapsulate | encrypt_decrypt | wrap_unwrap,
        CkMechanismType::RSA_PKCS_TPM_1_1 | CkMechanismType::RSA_PKCS_OAEP_TPM_1_1 => {
            encrypt_decrypt | wrap_unwrap
        }
        CkMechanismType::RSA_9796 | CkMechanismType::CMS_SIG => {
            sign_verify | sign_recover_verify_recover
        }
        CkMechanismType::RSA_PKCS_PSS
        | CkMechanismType(0x0000_0004)
        | CkMechanismType(0x0000_0005)
        | CkMechanismType(0x0000_0007)
        | CkMechanismType(0x0000_0008)
        | CkMechanismType(0x0000_0006)
        | CkMechanismType(0x0000_000E)
        | CkMechanismType(0x0000_000C)
        | CkMechanismType(0x0000_0046)
        | CkMechanismType(0x0000_0047)
        | CkMechanismType::SHA256_RSA_PKCS
        | CkMechanismType(0x0000_0043)
        | CkMechanismType::SHA384_RSA_PKCS
        | CkMechanismType(0x0000_0044)
        | CkMechanismType::SHA512_RSA_PKCS
        | CkMechanismType(0x0000_0045)
        | CkMechanismType(0x0000_0066)
        | CkMechanismType(0x0000_0067)
        | CkMechanismType(0x0000_0060)
        | CkMechanismType(0x0000_0063)
        | CkMechanismType(0x0000_0061)
        | CkMechanismType(0x0000_0064)
        | CkMechanismType(0x0000_0062)
        | CkMechanismType(0x0000_0065)
        | CkMechanismType(0x0000_0011)
        | CkMechanismType(0x0000_0012)
        | CkMechanismType(0x0000_0013)
        | CkMechanismType(0x0000_0014)
        | CkMechanismType(0x0000_0015)
        | CkMechanismType(0x0000_0016)
        | CkMechanismType(0x0000_0018)
        | CkMechanismType(0x0000_0019)
        | CkMechanismType(0x0000_001A)
        | CkMechanismType(0x0000_001B)
        | CkMechanismType(0x0000_001D)
        | CkMechanismType(0x0000_001F)
        | CkMechanismType(0x0000_0023)
        | CkMechanismType(0x0000_0024)
        | CkMechanismType(0x0000_0025)
        | CkMechanismType(0x0000_0026)
        | CkMechanismType(0x0000_0027)
        | CkMechanismType(0x0000_0028)
        | CkMechanismType(0x0000_0029)
        | CkMechanismType(0x0000_002A)
        | CkMechanismType(0x0000_002B)
        | CkMechanismType(0x0000_002C)
        | CkMechanismType(0x0000_002E)
        | CkMechanismType(0x0000_0034)
        | CkMechanismType(0x0000_0036)
        | CkMechanismType(0x0000_0037)
        | CkMechanismType(0x0000_0038)
        | CkMechanismType(0x0000_0039)
        | CkMechanismType(0x0000_003A)
        | CkMechanismType(0x0000_003B)
        | CkMechanismType(0x0000_003C)
        | CkMechanismType(0x0000_003D)
        | CkMechanismType(0x0000_003E)
        | CkMechanismType(0x0000_003F)
        | CkMechanismType::ECDSA
        | CkMechanismType::ECDSA_SHA1
        | CkMechanismType::ECDSA_SHA224
        | CkMechanismType::ECDSA_SHA256
        | CkMechanismType::ECDSA_SHA384
        | CkMechanismType::ECDSA_SHA512
        | CkMechanismType::ECDSA_SHA3_224
        | CkMechanismType::ECDSA_SHA3_256
        | CkMechanismType::ECDSA_SHA3_384
        | CkMechanismType::ECDSA_SHA3_512
        | CkMechanismType::EDDSA
        | CkMechanismType::XEDDSA
        | CkMechanismType::HSS
        | CkMechanismType::XMSS
        | CkMechanismType::XMSSMT => sign_verify,
        CkMechanismType::DH_PKCS_DERIVE
        | CkMechanismType::X9_42_DH_DERIVE
        | CkMechanismType::ECDH1_DERIVE
        | CkMechanismType::ECDH1_COFACTOR_DERIVE => {
            CkMechanismFlags::DERIVE | encapsulate_decapsulate
        }
        CkMechanismType::ECDH_AES_KEY_WRAP
        | CkMechanismType::ECDH_COF_AES_KEY_WRAP
        | CkMechanismType::ECDH_X_AES_KEY_WRAP
        | CkMechanismType::RSA_AES_KEY_WRAP
        | CkMechanismType::GOSTR3410_KEY_WRAP
        | CkMechanismType::GOST28147_KEY_WRAP
        | CkMechanismType::KIP_WRAP => wrap_unwrap,
        CkMechanismType::AES_GCM | CkMechanismType::AES_CCM => {
            message_encrypt_decrypt | encrypt_decrypt | wrap_unwrap
        }
        CkMechanismType::CHACHA20_POLY1305 | CkMechanismType::SALSA20_POLY1305 => {
            message_encrypt_decrypt | encrypt_decrypt
        }
        CkMechanismType::DES_ECB
        | CkMechanismType::DES_CBC_PAD
        | CkMechanismType::DES_OFB64
        | CkMechanismType::DES_OFB8
        | CkMechanismType::DES_CFB64
        | CkMechanismType::DES_CFB8 => encrypt_decrypt,
        CkMechanismType::AES_ECB
        | CkMechanismType::AES_CBC
        | CkMechanismType::AES_CBC_PAD
        | CkMechanismType::AES_CTR
        | CkMechanismType::AES_CTS
        | CkMechanismType::AES_XTS
        | CkMechanismType::AES_OFB
        | CkMechanismType::AES_CFB64
        | CkMechanismType::AES_CFB8
        | CkMechanismType::AES_CFB128
        | CkMechanismType::AES_CFB1
        | CkMechanismType::CHACHA20
        | CkMechanismType::SALSA20
        | CkMechanismType::ARIA_ECB
        | CkMechanismType::ARIA_CBC
        | CkMechanismType::ARIA_CBC_PAD
        | CkMechanismType::CAMELLIA_ECB
        | CkMechanismType::CAMELLIA_CBC
        | CkMechanismType::CAMELLIA_CBC_PAD
        | CkMechanismType::SEED_ECB
        | CkMechanismType::SEED_CBC
        | CkMechanismType::SEED_CBC_PAD
        | CkMechanismType::DES3_ECB
        | CkMechanismType::DES3_CBC
        | CkMechanismType::DES3_CBC_PAD
        | CkMechanismType::GOST28147_ECB
        | CkMechanismType::GOST28147
        | CkMechanismType::BLOWFISH_CBC
        | CkMechanismType::BLOWFISH_CBC_PAD
        | CkMechanismType::TWOFISH_CBC
        | CkMechanismType::TWOFISH_CBC_PAD => encrypt_decrypt | wrap_unwrap,
        CkMechanismType::AES_KEY_WRAP
        | CkMechanismType::AES_KEY_WRAP_PAD
        | CkMechanismType::AES_KEY_WRAP_KWP
        | CkMechanismType::AES_KEY_WRAP_PKCS7 => encrypt_decrypt | wrap_unwrap,
        CkMechanismType::AES_ECB_ENCRYPT_DATA
        | CkMechanismType::AES_CBC_ENCRYPT_DATA
        | CkMechanismType::ARIA_ECB_ENCRYPT_DATA
        | CkMechanismType::ARIA_CBC_ENCRYPT_DATA
        | CkMechanismType::CAMELLIA_ECB_ENCRYPT_DATA
        | CkMechanismType::CAMELLIA_CBC_ENCRYPT_DATA
        | CkMechanismType::SEED_ECB_ENCRYPT_DATA
        | CkMechanismType::SEED_CBC_ENCRYPT_DATA
        | CkMechanismType::DES_ECB_ENCRYPT_DATA
        | CkMechanismType::DES_CBC_ENCRYPT_DATA
        | CkMechanismType::DES3_ECB_ENCRYPT_DATA
        | CkMechanismType::DES3_CBC_ENCRYPT_DATA
        | CkMechanismType::X9_42_DH_HYBRID_DERIVE
        | CkMechanismType::X9_42_MQV_DERIVE
        | CkMechanismType::GOSTR3410_DERIVE
        | CkMechanismType::X3DH_INITIALIZE
        | CkMechanismType::X3DH_RESPOND
        | CkMechanismType::X2RATCHET_INITIALIZE
        | CkMechanismType::X2RATCHET_RESPOND
        | CkMechanismType::ECMQV_DERIVE
        | CkMechanismType::CONCATENATE_BASE_AND_KEY
        | CkMechanismType::CONCATENATE_BASE_AND_DATA
        | CkMechanismType::CONCATENATE_DATA_AND_BASE
        | CkMechanismType::XOR_BASE_AND_DATA
        | CkMechanismType::EXTRACT_KEY_FROM_KEY
        | CkMechanismType::PUB_KEY_FROM_PRIV_KEY
        | CkMechanismType::HKDF_DERIVE
        | CkMechanismType::HKDF_DATA
        | CkMechanismType::KIP_DERIVE
        | CkMechanismType::IKE2_PRF_PLUS_DERIVE
        | CkMechanismType::IKE_PRF_DERIVE
        | CkMechanismType::IKE1_PRF_DERIVE
        | CkMechanismType::IKE1_EXTENDED_DERIVE
        | CkMechanismType::SHAKE_128_KEY_DERIVATION
        | CkMechanismType::SHAKE_256_KEY_DERIVATION
        | CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE
        | CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
        | CkMechanismType::SSL3_KEY_AND_MAC_DERIVE
        | CkMechanismType::TLS12_MASTER_KEY_DERIVE
        | CkMechanismType::SSL3_MASTER_KEY_DERIVE
        | CkMechanismType::SSL3_MASTER_KEY_DERIVE_DH
        | CkMechanismType::WTLS_MASTER_KEY_DERIVE
        | CkMechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC
        | CkMechanismType::WTLS_PRF
        | CkMechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE
        | CkMechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE
        | CkMechanismType::TLS12_KDF
        | CkMechanismType::TLS_PRF
        | CkMechanismType::TLS12_KEY_AND_MAC_DERIVE
        | CkMechanismType::TLS12_MASTER_KEY_DERIVE_DH
        | CkMechanismType::TLS12_KEY_SAFE_DERIVE
        | CkMechanismType::TLS_KDF
        | CkMechanismType(0x0000_0392)
        | CkMechanismType(0x0000_0396)
        | CkMechanismType(0x0000_0393)
        | CkMechanismType(0x0000_0394)
        | CkMechanismType(0x0000_0395)
        | CkMechanismType(0x0000_004B)
        | CkMechanismType(0x0000_004F)
        | CkMechanismType(0x0000_0053)
        | CkMechanismType(0x0000_400F)
        | CkMechanismType(0x0000_4014)
        | CkMechanismType(0x0000_4019)
        | CkMechanismType(0x0000_401E)
        | CkMechanismType(0x0000_0398)
        | CkMechanismType(0x0000_0397)
        | CkMechanismType(0x0000_0399)
        | CkMechanismType(0x0000_039A)
        | CkMechanismType(0x0000_03AC)
        | CkMechanismType(0x0000_03AD)
        | CkMechanismType(0x0000_03AE) => CkMechanismFlags::DERIVE,
        CkMechanismType::X2RATCHET_ENCRYPT | CkMechanismType::X2RATCHET_DECRYPT => {
            encrypt_decrypt | wrap_unwrap
        }
        CkMechanismType::NULL => {
            encrypt_decrypt
                | sign_verify
                | sign_recover_verify_recover
                | CkMechanismFlags::DIGEST
                | wrap_unwrap
                | CkMechanismFlags::DERIVE
        }
        CkMechanismType(0x0000_4003)
        | CkMechanismType(0x0000_4004)
        | CkMechanismType(0x0000_4005)
        | CkMechanismType(0x0000_4006)
        | CkMechanismType(0x0000_4007)
        | CkMechanismType(0x0000_4008)
        | CkMechanismType(0x0000_4009)
        | CkMechanismType(0x0000_400A)
        | CkMechanismType(0x0000_4010)
        | CkMechanismType(0x0000_4015)
        | CkMechanismType(0x0000_401A)
        | CkMechanismType(0x0000_401F)
        | CkMechanismType(0x0000_02B8)
        | CkMechanismType(0x0000_02B3)
        | CkMechanismType(0x0000_02C3)
        | CkMechanismType(0x0000_02D3) => CkMechanismFlags::GENERATE,
        _ => 0,
    }
}
