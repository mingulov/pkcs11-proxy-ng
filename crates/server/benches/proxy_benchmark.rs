//! Benchmark baselines for core proxy flows (Item 94).
//!
//! Measures end-to-end latency through the gRPC stack using MockBackend.
//! These benchmarks establish baselines; regressions can be caught by
//! comparing `cargo bench` output across commits.
//!
//! Run: `cargo bench --bench proxy_benchmark`

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use tokio::sync::Mutex;

// W1-C3-12: daemon harness shared with the sibling bench files.
#[path = "common/mod.rs"]
mod common;
use common::start_daemon;

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

fn bench_initialize_finalize(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });

    c.bench_function("initialize_finalize", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
                client.initialize().await.unwrap();
                client.finalize().await.unwrap();
            });
        });
    });
}

fn bench_get_slot_list(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });
    let client = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        Arc::new(Mutex::new(c))
    });

    c.bench_function("get_slot_list", |b| {
        b.iter(|| {
            rt.block_on(async {
                client.lock().await.get_slot_list(false).await.unwrap();
            });
        });
    });
}

fn bench_open_close_session(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });
    let client = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        Arc::new(Mutex::new((c, slots[0])))
    });

    c.bench_function("open_close_session", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = client.lock().await;
                let (ref mut c, slot) = *guard;
                let session = c.open_session(slot, CKF_SERIAL).await.unwrap();
                c.close_session(session).await.unwrap();
            });
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        let key = c.create_object(session, Some(&[])).await.unwrap();
        Arc::new(Mutex::new((c, session, key)))
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    c.bench_function("sign_init_sign", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session, key) = *guard;
                c.sign_init(session, &mech, key).await.unwrap();
                c.sign(session, b"benchmark-data").await.unwrap();
            });
        });
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        let key = c.create_object(session, Some(&[])).await.unwrap();
        Arc::new(Mutex::new((c, session, key)))
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    c.bench_function("encrypt_decrypt_roundtrip", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session, key) = *guard;
                c.encrypt_init(session, &mech, key).await.unwrap();
                let ct = c.encrypt(session, b"benchmark-data").await.unwrap();
                c.decrypt_init(session, &mech, key).await.unwrap();
                c.decrypt(session, &ct).await.unwrap();
            });
        });
    });
}

fn bench_generate_random(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon().await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        Arc::new(Mutex::new((c, session)))
    });

    c.bench_function("generate_random_32", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session) = *guard;
                c.generate_random(session, 32).await.unwrap();
            });
        });
    });
}

criterion_group!(
    benches,
    bench_initialize_finalize,
    bench_get_slot_list,
    bench_open_close_session,
    bench_sign,
    bench_encrypt_decrypt,
    bench_generate_random,
);
criterion_main!(benches);
