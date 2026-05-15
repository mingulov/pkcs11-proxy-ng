use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn get_info(&mut self) -> CkResult<CkInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetInfoRequest { client_context_id: ctx };
        let resp = pkcs11_unary_call!(self.grpc.get_info(req), false);
        let info = resp.info.ok_or(CkRv::DEVICE_ERROR)?;
        Ok(CkInfo::from(&info))
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
        let info = resp.info.ok_or(CkRv::DEVICE_ERROR)?;
        Ok(CkSlotInfo::from(&info))
    }

    pub async fn get_token_info(&mut self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetTokenInfoRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_token_info(req), false);
        let info = resp.info.ok_or(CkRv::DEVICE_ERROR)?;
        Ok(CkTokenInfo::from(&info))
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
        let info = resp.info.ok_or(CkRv::DEVICE_ERROR)?;
        Ok(CkMechanismInfo::from(&info))
    }
}
