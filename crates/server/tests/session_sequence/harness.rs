//! Test-owned loaded module, loopback server and checked bounded teardown.
use super::native_cleanup::{NativeOwner, settle_native};
use super::oracle_types::*;
use libloading::Library;
use pkcs11_proxy_ng::server::{context_manager::ContextManager, grpc_service::Pkcs11ProxyService};
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::{CloseSessionResponse, Pkcs11ProxyServer};
use pkcs11_proxy_ng_types::{CkSessionHandle, CkSlotId};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::task::JoinHandle;

pub const DEADLINE: Duration = Duration::from_secs(2);
type CommandFn = unsafe extern "C" fn(*const CommandV1) -> u32;
type ObserveFn = unsafe extern "C" fn(*mut ObservationV1, u32) -> u32;
type ResetFn = unsafe extern "C" fn() -> u32;
pub type CloseTask = JoinHandle<Result<tonic::Response<CloseSessionResponse>, tonic::Status>>;

pub struct Control {
    command: CommandFn,
    observe: ObserveFn,
    reset: ResetFn,
    _library: Library,
}
impl Control {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let library = unsafe { Library::new(path) }.map_err(|e| format!("load control: {e}"))?;
        unsafe {
            let control = Self {
                command: *library.get(b"SessionOracle_CommandV1\0").map_err(|e| e.to_string())?,
                observe: *library
                    .get(b"SessionOracle_GetObservationV1\0")
                    .map_err(|e| e.to_string())?,
                reset: *library.get(b"SessionOracle_ResetV1\0").map_err(|e| e.to_string())?,
                _library: library,
            };
            if (control.reset)() != 0 {
                return Err("oracle reset refused existing work".into());
            }
            Ok(control)
        }
    }
    pub fn command(&self, kind: u32, raw: u64, value: u64) -> Result<(), String> {
        if unsafe { (self.command)(&CommandV1::new(kind, raw, value)) } == 0 {
            Ok(())
        } else {
            Err(format!("oracle command {kind} refused S(raw={raw})"))
        }
    }
    pub fn observe(&self) -> Result<Box<ObservationV1>, String> {
        let mut observation = Box::new(ObservationV1::default());
        if unsafe { (self.observe)(&mut *observation, std::mem::size_of::<ObservationV1>() as u32) }
            != 0
        {
            return Err("oracle observation failed".into());
        }
        Ok(observation)
    }
    pub async fn wait(
        &self,
        what: &str,
        ready: impl Fn(&ObservationV1) -> bool,
    ) -> Result<Box<ObservationV1>, String> {
        tokio::time::timeout(DEADLINE, async {
            loop {
                let observation = self.observe()?;
                if ready(&observation) {
                    return Ok(observation);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .map_err(|_| format!("timed out waiting for {what}"))?
    }

    /// A local deadline cannot prove native quiescence. Release the controlled
    /// fixture gate, then retain this harness until completion or outer process stop.
    async fn quiescent(&self, errors: &mut Vec<String>) -> Box<ObservationV1> {
        match self.wait("native quiescence", |o| o.pending_closes == 0 && o.gate_holders == 0).await
        {
            Ok(observation) => return observation,
            Err(error) => errors.push(error),
        }
        if let Err(error) = self.command(RELEASE_CLOSE_GATE, 0, 0) {
            errors.push(error);
        }
        loop {
            match self.observe() {
                Ok(observation)
                    if observation.pending_closes == 0 && observation.gate_holders == 0 =>
                {
                    return observation;
                }
                Ok(_) => {}
                // Unknown ownership cannot authorize native finalization/unload.
                Err(_) => std::process::exit(71),
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

pub struct Harness {
    pub client: Pkcs11Client,
    pub slot: CkSlotId,
    pub service: Pkcs11ProxyService,
    pub control: Control,
    pub handler: Option<CloseTask>,
    backend: Arc<dyn Pkcs11Backend>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}
impl Harness {
    pub async fn start() -> Result<Self, String> {
        let path = PathBuf::from(
            std::env::var_os("PKCS11_PROXY_SESSION_ORACLE_LIB")
                .ok_or("PKCS11_PROXY_SESSION_ORACLE_LIB is required; no passing skip")?,
        );
        let path = path.canonicalize().map_err(|e| format!("oracle path: {e}"))?;
        // Bind before native initialization: bind/address failures own no provider state.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let endpoint = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
        let control = Control::load(&path)?;
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(FfiBackend::load(&path)?);
        backend.initialize().map_err(|rv| format!("native initialize: {rv}"))?;
        let contexts = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
        if let Err(rv) = contexts.populate_slots(&backend).await {
            backend.finalize().map_err(|cleanup| format!("populate {rv}; finalize {cleanup}"))?;
            return Err(format!("populate slots: {rv}"));
        }
        let service = Pkcs11ProxyService::insecure_for_tests(contexts, backend.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = service.clone();
        let mut server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(Pkcs11ProxyServer::new(served))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
        });
        let client = Pkcs11Client::connect(&endpoint).await;
        let mut client = match client {
            Ok(client) => client,
            Err(error) => {
                let _ = stop.send(());
                let joined = match tokio::time::timeout(DEADLINE, &mut server).await {
                    Ok(result) => format!("{result:?}"),
                    Err(error) => {
                        server.abort();
                        let cancelled = tokio::time::timeout(DEADLINE, server).await;
                        format!("timeout={error}; aborted join={cancelled:?}")
                    }
                };
                backend
                    .finalize()
                    .map_err(|rv| format!("connect {error}; native finalize {rv}"))?;
                return Err(format!("connect {error}; server join={joined:?}"));
            }
        };
        client.set_rpc_timeout(DEADLINE);
        // Construct ownership before fallible client setup; setup failures use the same cleanup.
        let mut harness = Self {
            client,
            slot: CkSlotId(0),
            service,
            control,
            handler: None,
            backend,
            stop: Some(stop),
            server: Some(server),
        };
        let setup = async {
            harness.client.initialize().await.map_err(|rv| format!("client initialize: {rv}"))?;
            let slots = harness
                .client
                .get_slot_list(true)
                .await
                .map_err(|rv| format!("slot list: {rv}"))?;
            if slots.len() != 1 {
                return Err(format!("expected one slot, got {}", slots.len()));
            }
            harness.slot = slots[0];
            Ok(())
        }
        .await;
        if let Err(error) = setup {
            let cleanup = harness.finish().await;
            return Err(format!("{error}; setup cleanup={cleanup:?}"));
        }
        Ok(harness)
    }

    /// Release first, join every owned task, then finalize. Cleanup errors override success.
    pub async fn finish(mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(error) = self.control.command(RELEASE_CLOSE_GATE, 0, 0) {
            errors.push(error);
        }
        if let Some(mut handler) = self.handler.take() {
            match tokio::time::timeout(DEADLINE, &mut handler).await {
                Ok(Ok(Ok(_))) => {}
                Ok(Err(error)) if error.is_cancelled() => {}
                Err(error) => {
                    handler.abort();
                    let cancelled = tokio::time::timeout(DEADLINE, handler).await;
                    errors.push(format!(
                        "handler cleanup timeout: {error}; aborted join={cancelled:?}"
                    ));
                }
                other => errors.push(format!("handler cleanup: {other:?}")),
            }
        }
        if self.client.context_id_opt().is_some() {
            if let Err(rv) = self.client.close_all_sessions(self.slot).await {
                errors.push(format!("cleanup close-all: {rv}"));
            }
            if let Err(rv) = self.client.finalize().await {
                errors.push(format!("cleanup context finalize: {rv}"));
            }
        }
        if let Some(stop) = self.stop.take()
            && stop.send(()).is_err()
        {
            errors.push("server stop delivery failed".into());
        }
        if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(DEADLINE, &mut server).await {
                Ok(Ok(Ok(()))) => {}
                other => {
                    server.abort();
                    let joined = match tokio::time::timeout(DEADLINE, &mut server).await {
                        Ok(result) => format!("{result:?}"),
                        Err(error) => {
                            server.abort();
                            let cancelled = tokio::time::timeout(DEADLINE, server).await;
                            format!("timeout={error}; aborted join={cancelled:?}")
                        }
                    };
                    errors.push(format!("server cleanup: {other:?}; aborted join={joined:?}"));
                }
            }
        }
        // A failure must still retire every fixture-owned session, including unregistered carriers.
        let observation = self.control.quiescent(&mut errors).await;
        if observation.session_count as usize > MAX_SESSIONS {
            std::process::exit(71); // ownership inventory is not trustworthy
        }
        let remaining: Vec<_> = observation.sessions[..observation.session_count as usize]
            .iter()
            .filter(|s| s.live != 0)
            .map(|s| s.raw)
            .collect();
        for raw in remaining {
            errors.push(format!("native session {raw} survived normal context cleanup"));
            let backend = self.backend.clone();
            let mut owner = NativeOwner::spawn(move || backend.close_session(CkSessionHandle(raw)));
            let joined = settle_native(
                &mut owner,
                DEADLINE,
                || self.control.command(RELEASE_CLOSE_GATE, 0, 0),
                &mut errors,
                "fallback retirement",
            )
            .await;
            if !matches!(joined, Some(Ok(Ok(())))) {
                errors.push(format!("fallback retirement: {joined:?}"));
            }
            if owner.pending() {
                std::process::exit(71);
            }
        }
        let before_finalize = self.control.quiescent(&mut errors).await;
        if before_finalize.sessions.iter().any(|s| s.live != 0) {
            // A joined error still owns a live native session. Do not unload it.
            std::process::exit(71);
        }
        let backend = self.backend.clone();
        let mut owner = NativeOwner::spawn(move || backend.finalize());
        let joined = settle_native(
            &mut owner,
            DEADLINE,
            || self.control.command(RELEASE_CLOSE_GATE, 0, 0),
            &mut errors,
            "native finalize",
        )
        .await;
        if !matches!(joined, Some(Ok(Ok(())))) {
            errors.push(format!("native finalize: {joined:?}"));
        }
        if owner.pending() {
            std::process::exit(71);
        }
        let after = self.control.observe()?;
        if after.initialized != 0
            || after.logged_in != 0
            || after.pending_closes != 0
            || after.gate_holders != 0
            || after.sessions.iter().any(|s| s.live != 0)
        {
            errors.push("native fixture not finalized and empty".into());
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }
}
