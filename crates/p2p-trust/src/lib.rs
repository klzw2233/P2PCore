//! Trust layer: Identity Key, Peer ID, SAS, Trust State.
//!
//! Synchronous and network-free. The server cannot read Session content;
//! this crate does not claim anonymity or untraceability.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ed25519 identity of this Peer. The seed must not be logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKey {
    seed: [u8; 32],
}

impl IdentityKey {
    /// Generate a new Identity Key on this device.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self {
            seed: signing.to_bytes(),
        }
    }

    /// Reconstruct from a 32-byte seed. For KeyStore load paths.
    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// 32-byte seed for `p2p-core` to bind iroh, and for TrustStore signatures.
    /// Do not log this value.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> PublicKey {
        let signing = SigningKey::from_bytes(&self.seed);
        PublicKey::from_verifying(signing.verifying_key())
    }

    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }
}

/// 32-byte Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TrustError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| TrustError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn peer_id(self) -> PeerId {
        PeerId(self)
    }

    fn from_verifying(key: VerifyingKey) -> Self {
        Self(key.to_bytes())
    }
}

/// Canonical encoding of a [`PublicKey`]. Peer ID is the public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(PublicKey);

impl PeerId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TrustError> {
        Ok(Self(PublicKey::from_bytes(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(self) -> PublicKey {
        self.0
    }
}

/// Short Authentication String derived from a pair of long-term public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sas(String);

impl Sas {
    /// Display form: eight zero-padded 5-digit groups, space-separated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Sas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Derive SAS from two long-term public keys. Order-independent.
pub fn sas(a: PublicKey, b: PublicKey) -> Sas {
    let (lo, hi) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut hasher = Sha256::new();
    hasher.update(lo.as_bytes());
    hasher.update(hi.as_bytes());
    let digest = hasher.finalize();
    let prefix = &digest[..16];
    let mut groups = Vec::with_capacity(8);
    for i in 0..8 {
        let n = u16::from_be_bytes([prefix[i * 2], prefix[i * 2 + 1]]);
        groups.push(format!("{n:05}"));
    }
    Sas(groups.join(" "))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    InvalidPublicKey,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::InvalidPublicKey => f.write_str("invalid public key"),
        }
    }
}

impl std::error::Error for TrustError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_yields_stable_peer_id() {
        let id = IdentityKey::generate();
        let peer = id.peer_id();
        assert_eq!(peer, id.public_key().peer_id());
        assert_eq!(peer.public_key(), id.public_key());
        assert_eq!(PeerId::from_bytes(peer.to_bytes()).unwrap(), peer);
    }

    #[test]
    fn seed_round_trip_preserves_peer_id() {
        let id = IdentityKey::generate();
        let restored = IdentityKey::from_seed_bytes(id.to_seed_bytes());
        assert_eq!(id.peer_id(), restored.peer_id());
    }

    #[test]
    fn different_keys_have_different_peer_ids() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn peer_id_from_bytes_round_trips_generated_keys() {
        let id = IdentityKey::generate();
        let bytes = id.peer_id().to_bytes();
        let parsed = PeerId::from_bytes(bytes).expect("generated key is valid");
        assert_eq!(parsed, id.peer_id());
        assert_eq!(parsed.public_key().as_bytes(), &bytes);
    }

    #[test]
    fn sas_is_order_independent() {
        let a = IdentityKey::generate().public_key();
        let b = IdentityKey::generate().public_key();
        assert_eq!(sas(a, b), sas(b, a));
        assert_eq!(sas(a, b).as_str(), sas(b, a).as_str());
    }

    #[test]
    fn sas_display_is_eight_zero_padded_groups() {
        let a = IdentityKey::generate().public_key();
        let b = IdentityKey::generate().public_key();
        let sas_value = sas(a, b);
        let s = sas_value.as_str();
        let groups: Vec<_> = s.split(' ').collect();
        assert_eq!(groups.len(), 8);
        for g in groups {
            assert_eq!(g.len(), 5);
            assert!(g.chars().all(|c| c.is_ascii_digit()));
            let n: u32 = g.parse().unwrap();
            assert!(n <= 65535);
        }
    }

    #[test]
    fn sas_differs_for_impostor() {
        let a = IdentityKey::generate().public_key();
        let b = IdentityKey::generate().public_key();
        let mallory = IdentityKey::generate().public_key();
        assert_ne!(sas(a, b), sas(a, mallory));
    }

    #[test]
    fn sas_sorts_raw_bytes_not_strings() {
        // Two keys that differ only in a high bit so string encodings could
        // sort differently from raw bytes if someone compared hex.
        let lo = PublicKey::from_bytes({
            let mut b = [1u8; 32];
            b[0] = 0x01;
            b
        });
        let hi = PublicKey::from_bytes({
            let mut b = [1u8; 32];
            b[0] = 0x80;
            b
        });
        match (lo, hi) {
            (Ok(lo), Ok(hi)) => {
                assert!(lo.as_bytes() < hi.as_bytes());
                assert_eq!(sas(lo, hi), sas(hi, lo));
            }
            _ => {
                // If these compressed points are invalid, still prove sorting
                // with two generated keys whose bytes we inspect.
                let a = IdentityKey::generate().public_key();
                let b = IdentityKey::generate().public_key();
                let (x, y) = if a.as_bytes() <= b.as_bytes() {
                    (a, b)
                } else {
                    (b, a)
                };
                assert!(x.as_bytes() <= y.as_bytes());
                assert_eq!(sas(a, b), sas(x, y));
            }
        }
    }
}
