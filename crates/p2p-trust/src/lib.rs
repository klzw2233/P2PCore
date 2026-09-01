//! Trust layer: Identity Key, Peer ID, SAS, Trust State.
//!
//! Synchronous and network-free. The server cannot read Session content;
//! this crate does not claim anonymity or untraceability.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ed25519 identity of this Peer. The seed must not be logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKey {
    seed: [u8; 32],
}

impl Clone for IdentityKey {
    fn clone(&self) -> Self {
        Self { seed: self.seed }
    }
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

/// How the application obtained a Peer ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntroductionChannel {
    /// Face-to-face QR (or other trusted out-of-band channel).
    Trusted,
    /// Paste, forward, web page, or other untrusted channel.
    Untrusted,
}

/// Trust level stored for a Peer. Unknown means no record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustState {
    Unknown,
    Tofu,
    Verified,
}

/// Persisted trust level (never Unknown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredTrust {
    Tofu,
    Verified,
}

impl From<StoredTrust> for TrustState {
    fn from(value: StoredTrust) -> Self {
        match value {
            StoredTrust::Tofu => TrustState::Tofu,
            StoredTrust::Verified => TrustState::Verified,
        }
    }
}

/// Local record for one device public key.
///
/// Primary key is the device public key. `_reserved_endorsements` keeps room for
/// a future primary-identity endorsement field (ADR-0003) without a model break.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRecord {
    pub public_key: PublicKey,
    pub state: StoredTrust,
    _reserved_endorsements: (),
}

impl TrustRecord {
    pub fn new(public_key: PublicKey, state: StoredTrust) -> Self {
        Self {
            public_key,
            state,
            _reserved_endorsements: (),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.public_key.peer_id()
    }
}

/// Result of [`TrustEngine::evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvaluateDecision {
    Allow {
        state: StoredTrust,
    },
    /// Intended Peer was Verified; presented key does not match.
    RejectVerifiedMismatch {
        intended: PeerId,
        presented: PublicKey,
    },
    /// Intended Peer was TOFU; presented key does not match. Application decides.
    AlertTofuMismatch {
        intended: PeerId,
        presented: PublicKey,
        previous: StoredTrust,
    },
    /// No record for intended, and presented key is a different Peer.
    RejectUnknownMismatch {
        intended: PeerId,
        presented: PublicKey,
    },
}

/// Persist this Peer's Identity Key.
pub trait KeyStore {
    fn load(&self) -> Result<Option<IdentityKey>, TrustError>;
    fn save(&mut self, key: &IdentityKey) -> Result<(), TrustError>;
}

/// Persist Trust State keyed by device public key.
pub trait TrustStore {
    fn get(&self, peer: &PeerId) -> Result<Option<TrustRecord>, TrustError>;
    fn put(&mut self, record: TrustRecord) -> Result<(), TrustError>;
}

/// In-memory KeyStore for tests and diskless environments.
#[derive(Clone, Default, Debug)]
pub struct MemoryKeyStore {
    seed: Option<[u8; 32]>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self) -> Result<Option<IdentityKey>, TrustError> {
        Ok(self.seed.map(IdentityKey::from_seed_bytes))
    }

    fn save(&mut self, key: &IdentityKey) -> Result<(), TrustError> {
        self.seed = Some(key.to_seed_bytes());
        Ok(())
    }
}

/// In-memory TrustStore for tests and diskless environments.
#[derive(Clone, Default, Debug)]
pub struct MemoryTrustStore {
    records: BTreeMap<[u8; 32], TrustRecord>,
}

impl MemoryTrustStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrustStore for MemoryTrustStore {
    fn get(&self, peer: &PeerId) -> Result<Option<TrustRecord>, TrustError> {
        Ok(self.records.get(peer.as_bytes()).cloned())
    }

    fn put(&mut self, record: TrustRecord) -> Result<(), TrustError> {
        self.records.insert(record.public_key.to_bytes(), record);
        Ok(())
    }
}

/// Synchronous trust engine used as the Session gate.
pub struct TrustEngine {
    identity: IdentityKey,
    trust_store: Box<dyn TrustStore>,
}

impl TrustEngine {
    pub fn new(identity: IdentityKey, trust_store: Box<dyn TrustStore>) -> Self {
        Self {
            identity,
            trust_store,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    pub fn public_key(&self) -> PublicKey {
        self.identity.public_key()
    }

    /// Seed for transport binding. Do not log.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.identity.to_seed_bytes()
    }

    pub fn trust_state(&self, peer: &PeerId) -> Result<TrustState, TrustError> {
        Ok(match self.trust_store.get(peer)? {
            None => TrustState::Unknown,
            Some(r) => r.state.into(),
        })
    }

    /// Introduce a Peer ID obtained through `channel`.
    ///
    /// Trusted introduction of an unknown Peer → Verified.
    /// Untrusted → TOFU. Never downgrades Verified. Trusted introduction does
    /// **not** upgrade an existing TOFU (only [`Self::mark_verified`] does).
    pub fn introduce(
        &mut self,
        peer: PeerId,
        channel: IntroductionChannel,
    ) -> Result<StoredTrust, TrustError> {
        let existing = self.trust_store.get(&peer)?;
        let next = match (existing.as_ref().map(|r| r.state), channel) {
            (None, IntroductionChannel::Trusted) => StoredTrust::Verified,
            (None, IntroductionChannel::Untrusted) => StoredTrust::Tofu,
            (Some(StoredTrust::Verified), _) => StoredTrust::Verified,
            (Some(StoredTrust::Tofu), _) => StoredTrust::Tofu,
        };
        self.trust_store
            .put(TrustRecord::new(peer.public_key(), next))?;
        Ok(next)
    }

    /// After out-of-band SAS comparison. Only upgrade path from TOFU → Verified.
    pub fn mark_verified(&mut self, peer: PeerId) -> Result<StoredTrust, TrustError> {
        match self.trust_store.get(&peer)? {
            None => Err(TrustError::UnknownPeer),
            Some(r) => {
                let next = StoredTrust::Verified;
                self.trust_store
                    .put(TrustRecord::new(r.public_key, next))?;
                Ok(next)
            }
        }
    }

    /// Session gate: compare intended Peer ID with the public key presented by transport.
    pub fn evaluate(
        &mut self,
        intended: PeerId,
        presented: PublicKey,
    ) -> Result<EvaluateDecision, TrustError> {
        let presented_peer = presented.peer_id();
        if presented_peer == intended {
            let state = match self.trust_store.get(&intended)? {
                Some(r) => r.state,
                None => {
                    let state = StoredTrust::Tofu;
                    self.trust_store
                        .put(TrustRecord::new(presented, state))?;
                    state
                }
            };
            return Ok(EvaluateDecision::Allow { state });
        }

        match self.trust_store.get(&intended)? {
            Some(r) if r.state == StoredTrust::Verified => {
                Ok(EvaluateDecision::RejectVerifiedMismatch {
                    intended,
                    presented,
                })
            }
            Some(r) if r.state == StoredTrust::Tofu => Ok(EvaluateDecision::AlertTofuMismatch {
                intended,
                presented,
                previous: r.state,
            }),
            Some(_) => unreachable!(),
            None => Ok(EvaluateDecision::RejectUnknownMismatch {
                intended,
                presented,
            }),
        }
    }

    /// Accept a TOFU key-change alert by recording the new key as Untrusted (TOFU).
    pub fn accept_tofu_replacement(
        &mut self,
        presented: PublicKey,
    ) -> Result<StoredTrust, TrustError> {
        self.introduce(presented.peer_id(), IntroductionChannel::Untrusted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    InvalidPublicKey,
    UnknownPeer,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::InvalidPublicKey => f.write_str("invalid public key"),
            TrustError::UnknownPeer => f.write_str("unknown peer"),
        }
    }
}

impl std::error::Error for TrustError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> TrustEngine {
        TrustEngine::new(IdentityKey::generate(), Box::new(MemoryTrustStore::new()))
    }

    fn peer() -> (IdentityKey, PeerId, PublicKey) {
        let id = IdentityKey::generate();
        let pk = id.public_key();
        let peer = id.peer_id();
        (id, peer, pk)
    }

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

    #[test]
    fn memory_keystore_round_trips_identity() {
        let id = IdentityKey::generate();
        let mut store = MemoryKeyStore::new();
        assert!(store.load().unwrap().is_none());
        store.save(&id).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.peer_id(), id.peer_id());
    }

    #[test]
    fn trusted_introduce_makes_verified() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Unknown);
        assert_eq!(
            eng.introduce(peer, IntroductionChannel::Trusted).unwrap(),
            StoredTrust::Verified
        );
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }

    #[test]
    fn untrusted_introduce_makes_tofu() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        assert_eq!(
            eng.introduce(peer, IntroductionChannel::Untrusted)
                .unwrap(),
            StoredTrust::Tofu
        );
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Tofu);
    }

    #[test]
    fn trusted_introduce_does_not_upgrade_tofu() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        eng.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        assert_eq!(
            eng.introduce(peer, IntroductionChannel::Trusted).unwrap(),
            StoredTrust::Tofu
        );
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Tofu);
    }

    #[test]
    fn verified_never_downgrades() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        eng.introduce(peer, IntroductionChannel::Trusted).unwrap();
        assert_eq!(
            eng.introduce(peer, IntroductionChannel::Untrusted)
                .unwrap(),
            StoredTrust::Verified
        );
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }

    #[test]
    fn mark_verified_is_only_tofu_upgrade_path() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        eng.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        assert_eq!(eng.mark_verified(peer).unwrap(), StoredTrust::Verified);
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }

    #[test]
    fn mark_verified_unknown_peer_errors() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        assert_eq!(eng.mark_verified(peer), Err(TrustError::UnknownPeer));
    }

    #[test]
    fn introduce_is_idempotent() {
        let mut eng = engine();
        let (_, peer, _) = peer();
        eng.introduce(peer, IntroductionChannel::Trusted).unwrap();
        eng.introduce(peer, IntroductionChannel::Trusted).unwrap();
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }

    #[test]
    fn evaluate_first_contact_records_tofu() {
        let mut eng = engine();
        let (_, peer, pk) = peer();
        let decision = eng.evaluate(peer, pk).unwrap();
        assert_eq!(
            decision,
            EvaluateDecision::Allow {
                state: StoredTrust::Tofu
            }
        );
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Tofu);
    }

    #[test]
    fn evaluate_allows_matching_verified() {
        let mut eng = engine();
        let (_, peer, pk) = peer();
        eng.introduce(peer, IntroductionChannel::Trusted).unwrap();
        assert_eq!(
            eng.evaluate(peer, pk).unwrap(),
            EvaluateDecision::Allow {
                state: StoredTrust::Verified
            }
        );
    }

    #[test]
    fn evaluate_rejects_verified_mismatch() {
        let mut eng = engine();
        let (_, intended, _) = peer();
        let (_, _, presented) = peer();
        eng.introduce(intended, IntroductionChannel::Trusted)
            .unwrap();
        assert_eq!(
            eng.evaluate(intended, presented).unwrap(),
            EvaluateDecision::RejectVerifiedMismatch {
                intended,
                presented
            }
        );
    }

    #[test]
    fn evaluate_alerts_tofu_mismatch_and_accept_stays_tofu() {
        let mut eng = engine();
        let (_, intended, _) = peer();
        let (_, new_peer, presented) = peer();
        eng.introduce(intended, IntroductionChannel::Untrusted)
            .unwrap();
        assert_eq!(
            eng.evaluate(intended, presented).unwrap(),
            EvaluateDecision::AlertTofuMismatch {
                intended,
                presented,
                previous: StoredTrust::Tofu
            }
        );
        assert_eq!(
            eng.accept_tofu_replacement(presented).unwrap(),
            StoredTrust::Tofu
        );
        assert_eq!(eng.trust_state(&new_peer).unwrap(), TrustState::Tofu);
        assert_eq!(eng.trust_state(&intended).unwrap(), TrustState::Tofu);
    }

    #[test]
    fn no_server_directory_entry_point_on_public_api() {
        // Threat model b: trust state only from local introduce / first evaluate /
        // mark_verified. This test documents the absence of any server-fed API.
        let mut eng = engine();
        let (_, peer, pk) = peer();
        eng.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        eng.evaluate(peer, pk).unwrap();
        eng.mark_verified(peer).unwrap();
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }
}
