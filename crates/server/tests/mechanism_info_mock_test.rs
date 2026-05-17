//! MockBackend-backed integration coverage for `C_GetMechanismInfo`.
//!
//! Provider artifacts often do not expose legacy published-header mechanisms
//! that lack working-spec workflow evidence. This test uses MockBackend as the
//! deterministic internal provider so the client -> gRPC -> backend path proves
//! the no-source zero-flag policy without depending on host provider support.

use std::sync::Arc;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock_daemon};

const CKM_BATON_KEY_GEN: CkMechanismType = CkMechanismType(0x0000_1030);

#[tokio::test]
async fn grpc_mechanism_info_preserves_zero_flags_without_source_workflow_evidence() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_BATON_KEY_GEN]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let info = client.get_mechanism_info(slots[0], CKM_BATON_KEY_GEN).await.unwrap();

    assert_eq!(info.min_key_size, 2048);
    assert_eq!(info.max_key_size, 4096);
    assert_eq!(info.flags, CkMechanismFlags::default());
}
