//! Deterministic echo engine for mock operation outputs.
//!
//! The mock is not a crypto engine; its outputs only need to be *stable*
//! (assertable byte-exact across runs and architectures), *input-derived*
//! (a changed input, mechanism, or operation domain changes the bytes,
//! unlike a canned constant), and *domain-separated* (a "sign" output
//! never collides with a "digest" output for the same input). A chained
//! FNV-1a mix over (domain, seeds) meets all three with no dependencies
//! and no cryptographic pretense.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut state: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        state ^= b as u64;
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

/// Produce exactly `len` deterministic bytes derived from `domain` + `seeds`.
pub fn echo_bytes(domain: &str, seeds: &[&[u8]], len: usize) -> Vec<u8> {
    let mut state = fnv1a(FNV_OFFSET, domain.as_bytes());
    // Length-prefix every seed so ["ab","c"] never collides with ["a","bc"].
    for seed in seeds {
        state = fnv1a(state, &(seed.len() as u64).to_le_bytes());
        state = fnv1a(state, seed);
    }
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let block = fnv1a(state, &counter.to_le_bytes()).to_le_bytes();
        out.extend_from_slice(&block[..block.len().min(len - out.len())]);
        counter += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::echo_bytes;

    #[test]
    fn echo_is_deterministic_and_length_exact() {
        for len in [0usize, 1, 2, 4, 7, 8, 9, 32, 100] {
            let a = echo_bytes("digest", &[b"input"], len);
            let b = echo_bytes("digest", &[b"input"], len);
            assert_eq!(a, b);
            assert_eq!(a.len(), len);
        }
    }

    #[test]
    fn echo_separates_domains_inputs_and_seed_boundaries() {
        let base = echo_bytes("digest", &[b"input"], 8);
        assert_ne!(base, echo_bytes("sign", &[b"input"], 8), "domain separation");
        assert_ne!(base, echo_bytes("digest", &[b"inpuT"], 8), "input sensitivity");
        assert_ne!(
            echo_bytes("digest", &[b"ab", b"c"], 8),
            echo_bytes("digest", &[b"a", b"bc"], 8),
            "seed boundaries are length-prefixed"
        );
    }

    /// Randomized law sweep (seeded xorshift, dependency-free): arbitrary
    /// domains/seeds stay deterministic, length-exact, and sensitive to
    /// every seed byte.
    #[test]
    fn law_echo_is_stable_and_seed_sensitive_across_random_inputs() {
        let mut state: u64 = 0xEC40_0000_0000_0001;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let cases = if cfg!(miri) { 48 } else { 2048 };
        for _ in 0..cases {
            let seed: Vec<u8> = (0..(next() % 32)).map(|_| next() as u8).collect();
            let len = (next() % 64) as usize;
            let a = echo_bytes("law", &[&seed], len);
            assert_eq!(a.len(), len);
            assert_eq!(a, echo_bytes("law", &[&seed], len), "deterministic");
            if !seed.is_empty() && len >= 8 {
                let mut flipped = seed.clone();
                let idx = (next() as usize) % flipped.len();
                flipped[idx] ^= 0x01;
                assert_ne!(
                    a,
                    echo_bytes("law", &[&flipped], len),
                    "one flipped seed bit changes the output"
                );
            }
        }
    }

    #[test]
    fn echo_prefixes_are_consistent_across_lengths() {
        let long = echo_bytes("digest", &[b"x"], 32);
        let short = echo_bytes("digest", &[b"x"], 4);
        assert_eq!(&long[..4], &short[..], "shorter output is a prefix");
    }
}
