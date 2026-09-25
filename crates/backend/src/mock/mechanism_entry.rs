//! Metadata-only observations of semantic backend entry points.
//!
//! These count mock trait dispatches, not native FFI calls. Convenience wrappers
//! are observed only at their underlying implementation, so delegation does not
//! count twice. No mechanism bytes or other payloads are retained.

use super::*;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MockMechanismEntry {
    DigestInit,
    DigestInitCancel,
    VerifySignatureInit,
    VerifySignatureCancel,
    EncapsulateKey,
    EncapsulateKeyExact,
    DecapsulateKey,
    GenerateKey,
    GenerateKeyPair,
    DeriveKey,
    SignInit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MockEmbeddedHandles {
    HkdfSalt(u64),
    /// (Native handle, encoded width in bytes).
    Sp800108(Vec<(u64, usize)>),
}

#[derive(Default)]
pub(super) struct MechanismEntries {
    counts: HashMap<MockMechanismEntry, usize>,
    handles: HashMap<MockMechanismEntry, MockEmbeddedHandles>,
}

impl MockBackend {
    pub fn mechanism_entry_count(&self, entry: MockMechanismEntry) -> usize {
        self.mechanism_entries.lock().unwrap().counts.get(&entry).copied().unwrap_or(0)
    }

    pub fn last_embedded_handles(&self, entry: MockMechanismEntry) -> Option<MockEmbeddedHandles> {
        self.mechanism_entries.lock().unwrap().handles.get(&entry).cloned()
    }

    pub(super) fn record_mechanism_entry(
        &self,
        entry: MockMechanismEntry,
        mechanism: Option<&CkMechanism>,
    ) {
        let mut entries = self.mechanism_entries.lock().unwrap();
        *entries.counts.entry(entry).or_default() += 1;
        entries.handles.remove(&entry);
        let params = mechanism.and_then(|m| m.params.as_ref());
        let handles = match params {
            Some(CkMechanismParams::Hkdf(p)) => MockEmbeddedHandles::HkdfSalt(p.salt_key_handle),
            Some(CkMechanismParams::Sp800108Kdf(p)) => {
                MockEmbeddedHandles::Sp800108(encoded_handles(&p.data_params))
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(p)) => {
                MockEmbeddedHandles::Sp800108(encoded_handles(&p.data_params))
            }
            _ => return,
        };
        entries.handles.insert(entry, handles);
    }
}

fn encoded_handles(params: &[PrfDataParam]) -> Vec<(u64, usize)> {
    params
        .iter()
        .filter(|p| p.type_ == CK_SP800_108_KEY_HANDLE)
        .filter_map(|p| match p.value.len() {
            4 => Some((u32::from_ne_bytes(p.value.as_slice().try_into().unwrap()) as u64, 4)),
            8 => Some((u64::from_ne_bytes(p.value.as_slice().try_into().unwrap()), 8)),
            _ => None,
        })
        .collect()
}
