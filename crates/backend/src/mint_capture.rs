//! Call-scoped capture of freshly minted object lifetimes.
//!
//! Detached late-mint settlement must destroy exactly the objects a
//! mint call created — never a later replacement that reuses the
//! numeric handle. Querying `object_lifetime` when the settlement
//! payload is built (after the mint returned) is not atomic with
//! the mint: a destroy+recreate landing before the query makes the
//! payload capture the *replacement's* lifetime, and settlement
//! then destroys a valid object.
//!
//! Instead, the caller that owns the mint begins a capture on the
//! minting thread before the backend call ([`begin`]); each
//! backend's fresh-lifetime record site reports the `(handle,
//! lifetime)` pair it just assigned into the active capture for
//! that session ([`report`], called by the FFI lifetime table and
//! the mock's allocation funnel). The mint closure runs
//! synchronously on one blocking thread, so the collected pairs
//! are exactly the mint's own objects, immune to any later reuse
//! of the numeric handles. A backend that never reports yields an
//! empty capture, which settlement treats as the untracked legacy
//! path (no captured lifetime for any handle).

use std::cell::RefCell;

use pkcs11_proxy_ng_types::{CkObjectHandle, CkSessionHandle};

#[derive(Clone)]
struct CaptureState {
    session: u64,
    pairs: Vec<(u64, u64)>,
}

thread_local! {
    static ACTIVE: RefCell<Option<CaptureState>> = const { RefCell::new(None) };
}

/// Begin a mint capture for `session` on the current thread. The
/// returned guard collects every fresh `(handle, lifetime)` pair
/// reported for that session until it drops; dropping restores any
/// previously active capture (captures may nest, though mint calls
/// do not). Hold the guard across exactly one synchronous backend
/// mint call and read [`MintCapture::captured`] before dropping it.
pub fn begin(session: CkSessionHandle) -> MintCapture {
    ACTIVE.with(|active| {
        let previous =
            active.borrow_mut().replace(CaptureState { session: session.0, pairs: Vec::new() });
        MintCapture { previous, session: session.0 }
    })
}

/// Report a freshly assigned object lifetime into the active
/// capture, when one is running for `session` on this thread.
/// Backends call this at their fresh-record site; it is a no-op
/// outside a capture, for a different session, and for the null
/// handle / zero lifetime (neither names a minted object).
pub fn report(session: CkSessionHandle, object: CkObjectHandle, lifetime: u64) {
    if object.0 == 0 || lifetime == 0 {
        return;
    }
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow_mut().as_mut()
            && state.session == session.0
        {
            match state.pairs.iter_mut().find(|(handle, _)| *handle == object.0) {
                Some(pair) => pair.1 = lifetime,
                None => state.pairs.push((object.0, lifetime)),
            }
        }
    });
}

/// An active mint capture (see [`begin`]). Not meaningful across
/// threads: it reads the capture state of whichever thread calls
/// [`Self::captured`], so keep it on the minting thread.
pub struct MintCapture {
    previous: Option<CaptureState>,
    session: u64,
}

impl MintCapture {
    /// The `(handle, lifetime)` pairs collected so far for this
    /// capture's session, in report order.
    pub fn captured(&self) -> Vec<(CkObjectHandle, u64)> {
        ACTIVE.with(|active| match &*active.borrow() {
            Some(state) if state.session == self.session => state
                .pairs
                .iter()
                .map(|&(handle, lifetime)| (CkObjectHandle(handle), lifetime))
                .collect(),
            _ => Vec::new(),
        })
    }

    /// The captured lifetime for `object`, when the mint that this
    /// capture wrapped created it.
    pub fn lifetime_for(&self, object: CkObjectHandle) -> Option<u64> {
        self.captured()
            .into_iter()
            .find(|(handle, _)| *handle == object)
            .map(|(_, lifetime)| lifetime)
    }
}

impl Drop for MintCapture {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            *active.borrow_mut() = self.previous.take();
        });
    }
}
