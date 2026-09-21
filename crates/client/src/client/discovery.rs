use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn get_info(&mut self) -> CkResult<CkInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetInfoRequest { client_context_id: ctx };
        let resp = pkcs11_unary_call!(self.grpc.get_info(req), false);
        // Absent info = uninterpretable daemon payload (W1-L3-06).
        let info = resp.info.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        Ok(CkInfo::try_from(&info)?)
    }

    pub async fn get_slot_list(&mut self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        let ctx = self.context_id()?;
        let req =
            pkcs11_proxy_ng_proto::GetSlotListRequest { client_context_id: ctx, token_present };
        let resp = pkcs11_unary_call!(self.grpc.get_slot_list(req), false);
        Ok(resp.slot_ids.into_iter().map(CkSlotId).collect())
    }

    pub async fn get_slot_info(&mut self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetSlotInfoRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_slot_info(req), false);
        // Absent info = uninterpretable daemon payload (W1-L3-06).
        let info = resp.info.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        Ok(CkSlotInfo::try_from(&info)?)
    }

    pub async fn get_token_info(&mut self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetTokenInfoRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_token_info(req), false);
        // Absent info = uninterpretable daemon payload (W1-L3-06).
        let info = resp.info.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        Ok(CkTokenInfo::try_from(&info)?)
    }

    pub async fn get_mechanism_list(
        &mut self,
        slot_id: CkSlotId,
    ) -> CkResult<Vec<CkMechanismType>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetMechanismListRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_mechanism_list(req), false);
        Ok(resp.mechanism_types.into_iter().map(CkMechanismType).collect())
    }

    pub async fn get_mechanism_info(
        &mut self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetMechanismInfoRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
            mechanism_type: mech.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_mechanism_info(req), false);
        // Absent info = uninterpretable daemon payload (W1-L3-06).
        let info = resp.info.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        Ok(CkMechanismInfo::from(&info))
    }
}

#[cfg(test)]
mod tests {
    // W1-L3-06: an absent `info` payload on an otherwise-OK discovery
    // response (malformed/older daemon) must map to FUNCTION_NOT_SUPPORTED —
    // the exact-path convention for uninterpretable daemon payloads — never
    // DEVICE_ERROR, which collides with backend errors. The mapping is
    // inline at each call site (no seam for a mock), so this pins all 4
    // discovery sites by source scan; the 5th absent-info site
    // (get_session_info) is pinned by the twin scan in session.rs.
    // Recorded pre-fix state: all 4 sites used `ok_or(CkRv::DEVICE_ERROR)`.
    #[test]
    fn absent_info_maps_to_function_not_supported() {
        let source = include_str!("discovery.rs");
        let prod = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(!prod.contains("DEVICE_ERROR"), "no absent-info site may map to DEVICE_ERROR");
        assert_eq!(
            prod.matches("ok_or(CkRv::FUNCTION_NOT_SUPPORTED)").count(),
            4,
            "all 4 discovery absent-info sites must map to FUNCTION_NOT_SUPPORTED"
        );
    }

    // W1-C10-05: crate-wide confirmation of the L3-06 mapping — no
    // absent-payload site ANYWHERE in the client maps to DEVICE_ERROR
    // (which collides with backend errors); all 10 use
    // FUNCTION_NOT_SUPPORTED (4 discovery + 1 session_info + 3
    // authenticated-output + 2 exact-path). The reconnect-redial
    // `.map_err(|_| CkRv::DEVICE_ERROR)` in lifecycle.rs is a transport
    // failure, not an absent payload, and is intentionally out of scope.
    // Must not revert Task 8: the per-file L3-06 pins above stay untouched.
    #[test]
    fn no_absent_payload_site_maps_to_device_error_crate_wide() {
        const SOURCES: &[(&str, &str)] = &[
            ("async_ops.rs", include_str!("async_ops.rs")),
            ("deadline.rs", include_str!("deadline.rs")),
            ("discovery.rs", include_str!("discovery.rs")),
            ("kem.rs", include_str!("kem.rs")),
            ("key_ops.rs", include_str!("key_ops.rs")),
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("mod.rs", include_str!("mod.rs")),
            ("object.rs", include_str!("object.rs")),
            ("raw_output.rs", include_str!("raw_output.rs")),
            ("session.rs", include_str!("session.rs")),
            ("session_3x.rs", include_str!("session_3x.rs")),
            ("crypto/authenticated_typed.rs", include_str!("crypto/authenticated_typed.rs")),
            ("crypto/authenticated_wrap.rs", include_str!("crypto/authenticated_wrap.rs")),
            ("crypto/combined.rs", include_str!("crypto/combined.rs")),
            ("crypto/digest_cipher.rs", include_str!("crypto/digest_cipher.rs")),
            ("crypto/message_crypto.rs", include_str!("crypto/message_crypto.rs")),
            ("crypto/mod.rs", include_str!("crypto/mod.rs")),
            ("crypto/sign_verify.rs", include_str!("crypto/sign_verify.rs")),
            ("crypto/verify_signature.rs", include_str!("crypto/verify_signature.rs")),
        ];
        let mut fns_sites = 0;
        for (name, source) in SOURCES {
            let prod = source.split("#[cfg(test)]").next().unwrap_or(source);
            assert!(
                !prod.contains("ok_or(CkRv::DEVICE_ERROR)"),
                "{name}: absent-payload site maps to DEVICE_ERROR"
            );
            fns_sites += prod.matches("ok_or(CkRv::FUNCTION_NOT_SUPPORTED)").count();
        }
        assert_eq!(fns_sites, 10, "all 10 absent-payload sites must map to FUNCTION_NOT_SUPPORTED");
    }
}
