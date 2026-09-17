//! Descriptor-aware pre-decode validation (ADR-0013 §5/§7, C3M Task 7.2).
//!
//! prost decodes a duplicate singular field by replacing the first decoded
//! allocation, freeing a possibly long secret buffer without wiping. The
//! daemon therefore scans raw request wire bytes with [`validate_request_wire`]
//! BEFORE tonic/prost decode (see the `ProtectedDecode` tower layer in
//! `crates/server`) and rejects dangerous encodings with `InvalidArgument`.
//!
//! The enforced rule is uniform and has no interop cost (no conforming client
//! emits duplicates):
//!
//! * every field number occurs at most once per message level, except
//!   `repeated` fields (which prost appends, never replaces);
//! * every `oneof` carries at most one member occurrence (any second member,
//!   even of a different field, replaces the first decoded value);
//! * groups are rejected (proto3 never emits them);
//! * truncated/overflowing length prefixes are rejected.
//!
//! The scan recurses into nested messages using the build-time descriptor
//! index (`protected_decode_tables.rs`, emitted from the protobuf schema),
//! so duplicates hidden inside a submessage are caught as well. Unknown field
//! numbers are skipped by wire type: prost discards them without retaining an
//! allocation, so they cannot smuggle a replacement. Unknown gRPC paths (e.g.
//! health checks, whose descriptors are not ours) pass through untouched.
//!
//! [`validate_request_wire`]: crate::protected_decode::validate_request_wire

include!(concat!(env!("OUT_DIR"), "/protected_decode_tables.rs"));

use std::fmt;

/// Maximum nested-message depth the scanner descends. The schema nests at
/// most a few levels; the cap only stops adversarial depth bombs (each level
/// costs the attacker bytes but the scanner stack frames).
const MAX_DEPTH: u32 = 64;

/// Why a request payload was rejected before decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectedDecodeViolation {
    /// A singular field number occurred twice at one message level. The
    /// second occurrence would replace (and unwiped-free) the first decoded
    /// allocation.
    DuplicateField {
        /// Descriptor name of the message level carrying the duplicate.
        message: &'static str,
        /// Duplicated protobuf field number.
        number: u32,
    },
    /// Two members of one `oneof` occurred at one message level. prost keeps
    /// the last, dropping the first decoded value without wiping.
    OneofRepeated {
        /// Descriptor name of the message level.
        message: &'static str,
    },
    /// A group start/end wire type, which proto3 never emits.
    GroupsRejected {
        /// Descriptor name of the message level.
        message: &'static str,
    },
    /// Truncated tag/varint/length-delimited payload.
    Truncated {
        /// Descriptor name of the message level.
        message: &'static str,
    },
    /// Nesting deeper than [`MAX_DEPTH`].
    DepthExceeded,
}

impl fmt::Display for ProtectedDecodeViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateField { message, number } => write!(
                formatter,
                "duplicate field {number} in {message}: singular fields must occur once"
            ),
            Self::OneofRepeated { message } => write!(
                formatter,
                "repeated oneof member in {message}: oneof members must occur once"
            ),
            Self::GroupsRejected { message } => {
                write!(formatter, "groups are not accepted in {message}")
            }
            Self::Truncated { message } => {
                write!(formatter, "truncated wire encoding in {message}")
            }
            Self::DepthExceeded => write!(formatter, "message nesting exceeds {MAX_DEPTH} levels"),
        }
    }
}

impl std::error::Error for ProtectedDecodeViolation {}

/// Validates raw request wire bytes for `path` (a full gRPC path such as
/// `/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login`) before prost decode.
///
/// Returns `Ok(())` when the payload carries no dangerous duplicate-field
/// encoding, or when `path` names no method of this service (health checks
/// and future services have no descriptor entry and pass through).
pub fn validate_request_wire(path: &str, payload: &[u8]) -> Result<(), ProtectedDecodeViolation> {
    let index = match REQUEST_MESSAGES.binary_search_by(|(candidate, _)| candidate.cmp(&path)) {
        Ok(position) => REQUEST_MESSAGES[position].1,
        Err(_) => return Ok(()),
    };
    validate_message(index, payload, 0)
}

/// Full gRPC paths covered by pre-decode validation, sorted. Exposed so tests
/// can audit coverage against `service.proto`.
pub fn protected_request_paths() -> Vec<&'static str> {
    REQUEST_MESSAGES.iter().map(|(path, _)| *path).collect()
}

/// Whether `path` names a method of this service. The daemon's tower layer
/// forwards anything else (health checks, probes) untouched, preserving
/// tonic's exact behavior for non-service traffic.
pub fn is_protected_path(path: &str) -> bool {
    REQUEST_MESSAGES.binary_search_by(|(candidate, _)| candidate.cmp(&path)).is_ok()
}

fn validate_message(
    index: u32,
    mut payload: &[u8],
    depth: u32,
) -> Result<(), ProtectedDecodeViolation> {
    if depth > MAX_DEPTH {
        return Err(ProtectedDecodeViolation::DepthExceeded);
    }
    let descriptor = &MESSAGE_DESCRIPTORS[index as usize];
    // Singular field numbers already seen at this level, plus oneof indexes
    // already occupied. Per-message field counts are small (dozens at most),
    // so linear scans stay cheaper than hashing.
    let mut seen_numbers: Vec<u32> = Vec::new();
    let mut seen_oneofs: Vec<u32> = Vec::new();
    while !payload.is_empty() {
        let tag = read_varint(&mut payload, descriptor.name)?;
        let raw_number = tag >> 3;
        if raw_number == 0 || raw_number >= 536_870_912 {
            return Err(ProtectedDecodeViolation::Truncated { message: descriptor.name });
        }
        let number = raw_number as u32;
        let field = descriptor.fields.binary_search_by_key(&number, |field| field.number).ok();
        match tag & 0x07 {
            0 => {
                check_occurrence(descriptor, field, number, &mut seen_numbers, &mut seen_oneofs)?;
                let _ = read_varint(&mut payload, descriptor.name)?;
            }
            1 => {
                check_occurrence(descriptor, field, number, &mut seen_numbers, &mut seen_oneofs)?;
                payload = advance(descriptor.name, payload, 8)?;
            }
            2 => {
                check_occurrence(descriptor, field, number, &mut seen_numbers, &mut seen_oneofs)?;
                let length = read_varint(&mut payload, descriptor.name)?;
                let length: usize = length.try_into().map_err(|_| {
                    ProtectedDecodeViolation::Truncated { message: descriptor.name }
                })?;
                if length > payload.len() {
                    return Err(ProtectedDecodeViolation::Truncated { message: descriptor.name });
                }
                let (value, rest) = payload.split_at(length);
                if let Some(position) = field {
                    let nested = descriptor.fields[position].nested;
                    if nested != NO_NESTED {
                        validate_message(nested, value, depth + 1)?;
                    }
                }
                payload = rest;
            }
            5 => {
                check_occurrence(descriptor, field, number, &mut seen_numbers, &mut seen_oneofs)?;
                payload = advance(descriptor.name, payload, 4)?;
            }
            3 | 4 => {
                return Err(ProtectedDecodeViolation::GroupsRejected { message: descriptor.name });
            }
            _ => return Err(ProtectedDecodeViolation::Truncated { message: descriptor.name }),
        }
    }
    Ok(())
}

/// Enforces the at-most-once rule for a known field occurrence. Unknown field
/// numbers (`None`) are always accepted: prost discards them.
fn check_occurrence(
    descriptor: &MessageDesc,
    field: Option<usize>,
    number: u32,
    seen_numbers: &mut Vec<u32>,
    seen_oneofs: &mut Vec<u32>,
) -> Result<(), ProtectedDecodeViolation> {
    let Some(position) = field else {
        return Ok(());
    };
    let field = &descriptor.fields[position];
    if field.oneof != NO_ONEOF {
        if seen_oneofs.contains(&field.oneof) {
            return Err(ProtectedDecodeViolation::OneofRepeated { message: descriptor.name });
        }
        seen_oneofs.push(field.oneof);
        return Ok(());
    }
    if field.repeated {
        return Ok(());
    }
    if seen_numbers.contains(&number) {
        return Err(ProtectedDecodeViolation::DuplicateField { message: descriptor.name, number });
    }
    seen_numbers.push(number);
    Ok(())
}

fn advance<'a>(
    message: &'static str,
    payload: &'a [u8],
    length: usize,
) -> Result<&'a [u8], ProtectedDecodeViolation> {
    if payload.len() < length {
        return Err(ProtectedDecodeViolation::Truncated { message });
    }
    Ok(&payload[length..])
}

fn read_varint(
    payload: &mut &[u8],
    message: &'static str,
) -> Result<u64, ProtectedDecodeViolation> {
    let mut value: u64 = 0;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = payload.split_first() else {
            return Err(ProtectedDecodeViolation::Truncated { message });
        };
        *payload = rest;
        let bits = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(ProtectedDecodeViolation::Truncated { message })?;
        // A set payload bit that `|` would drop (only possible in a
        // non-canonical 10-byte varint) is rejected rather than wrapped.
        if shift == 63 && byte & 0x7e != 0 {
            return Err(ProtectedDecodeViolation::Truncated { message });
        }
        value |= bits;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtectedDecodeViolation::Truncated { message })
}

#[cfg(test)]
mod tests;
