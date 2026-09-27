//! Compile-only consumer example. Run it only with a configured proxy daemon.
//! The client crate is the only direct project dependency.

use pkcs11_proxy_ng_client::{
    CcmMessageParams, GcmMessageParams, MessageEffects, MessageParameter, Pkcs11Client,
    Salsa20ChaCha20Poly1305MessageParams, types,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let endpoint = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:50051".to_owned());
    let mut client = Pkcs11Client::connect(&endpoint).await.expect("connect to proxy daemon");
    client.initialize().await.expect("initialize client context");

    let slots = client.get_slot_list(true).await.expect("list token slots");
    if let Some(slot) = slots.first().copied() {
        let mechanisms = client.get_mechanism_list(slot).await.expect("list mechanisms");
        if let Some(kind) = mechanisms.first().copied() {
            let _info = client.get_mechanism_info(slot, kind).await.expect("mechanism info");
            let _mechanism = types::CkMechanism { mechanism_type: kind, params: None };
        }
        let session = client
            .open_session(slot, types::CkSessionFlags::SERIAL_SESSION)
            .await
            .expect("open session");
        client.close_session(session).await.expect("close session");
    }

    // Protocol-owned message parameters are available through the client crate.
    let _: Option<MessageParameter> = None;
    let _: Option<GcmMessageParams> = None;
    let _: Option<CcmMessageParams> = None;
    let _: Option<Salsa20ChaCha20Poly1305MessageParams> = None;
    let _: Option<MessageEffects> = None;
}
