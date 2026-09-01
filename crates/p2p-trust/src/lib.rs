//! Trust layer: Identity Key, Peer ID, SAS, Trust State.
//!
//! Synchronous and network-free. The server cannot read Session content;
//! this crate does not claim anonymity or untraceability.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
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

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key().sign(msg).to_bytes()
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

    fn verifying_key(self) -> Result<VerifyingKey, TrustError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| TrustError::InvalidPublicKey)
    }

    fn verify(self, msg: &[u8], signature: &[u8; 64]) -> Result<(), TrustError> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key()?
            .verify(msg, &sig)
            .map_err(|_| TrustError::CorruptStore)
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

const KEYSTORE_MAGIC: &[u8; 8] = b"P2PKEY01";
const TRUSTSTORE_MAGIC: &[u8; 8] = b"P2PTRS01";
const ARGON2_M_KIB: u32 = 19 * 1024;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

fn io_err(_: io::Error) -> TrustError {
    TrustError::Io
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(io_err)?;
        f.write_all(bytes).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
    }
    fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], TrustError> {
    let params = argon2::Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|_| TrustError::CorruptStore)?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| TrustError::CorruptStore)?;
    Ok(out)
}

/// Password-encrypted file KeyStore. Root directory is supplied by the caller.
pub struct FileKeyStore {
    path: PathBuf,
    password: Vec<u8>,
}

impl FileKeyStore {
    pub fn new(root: impl AsRef<Path>, password: impl AsRef<[u8]>) -> Self {
        Self {
            path: root.as_ref().join("identity.key"),
            password: password.as_ref().to_vec(),
        }
    }

    /// Re-encrypt the stored Identity Key with a new password.
    pub fn change_password(&mut self, new_password: impl AsRef<[u8]>) -> Result<(), TrustError> {
        let key = self.load()?.ok_or(TrustError::UnknownPeer)?;
        self.password = new_password.as_ref().to_vec();
        self.save(&key)
    }
}

impl Drop for FileKeyStore {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<Option<IdentityKey>, TrustError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(e)),
        };
        if bytes.len() < 8 + 16 + 12 + 16 {
            return Err(TrustError::CorruptStore);
        }
        if &bytes[..8] != KEYSTORE_MAGIC {
            return Err(TrustError::CorruptStore);
        }
        let salt: [u8; 16] = bytes[8..24]
            .try_into()
            .map_err(|_| TrustError::CorruptStore)?;
        let nonce_bytes: [u8; 12] = bytes[24..36]
            .try_into()
            .map_err(|_| TrustError::CorruptStore)?;
        let ciphertext = &bytes[36..];
        let mut derived = derive_key(&self.password, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
        derived.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| TrustError::WrongPassword)?;
        if plain.len() != 32 {
            return Err(TrustError::CorruptStore);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&plain);
        Ok(Some(IdentityKey::from_seed_bytes(seed)))
    }

    fn save(&mut self, key: &IdentityKey) -> Result<(), TrustError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut derived = derive_key(&self.password, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
        derived.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let seed = key.to_seed_bytes();
        let ciphertext = cipher
            .encrypt(nonce, seed.as_ref())
            .map_err(|_| TrustError::CorruptStore)?;
        let mut out = Vec::with_capacity(8 + 16 + 12 + ciphertext.len());
        out.extend_from_slice(KEYSTORE_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        atomic_write(&self.path, &out)
    }
}

fn encode_trust_body(records: &BTreeMap<[u8; 32], StoredTrust>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (pk, state) in records {
        body.extend_from_slice(pk);
        body.push(match state {
            StoredTrust::Tofu => 1,
            StoredTrust::Verified => 2,
        });
    }
    body
}

fn decode_trust_body(body: &[u8]) -> Result<BTreeMap<[u8; 32], StoredTrust>, TrustError> {
    if body.len() < 4 {
        return Err(TrustError::CorruptStore);
    }
    let n = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
    let mut records = BTreeMap::new();
    let mut i = 4;
    for _ in 0..n {
        if i + 33 > body.len() {
            return Err(TrustError::CorruptStore);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&body[i..i + 32]);
        let tag = body[i + 32];
        i += 33;
        let state = match tag {
            1 => StoredTrust::Tofu,
            2 => StoredTrust::Verified,
            _ => return Err(TrustError::CorruptStore),
        };
        PublicKey::from_bytes(pk)?;
        records.insert(pk, state);
    }
    if i != body.len() {
        return Err(TrustError::CorruptStore);
    }
    Ok(records)
}

/// Signed (not encrypted) file TrustStore. Root directory is supplied by the caller.
pub struct FileTrustStore {
    path: PathBuf,
    identity: IdentityKey,
    records: BTreeMap<[u8; 32], StoredTrust>,
}

impl FileTrustStore {
    pub fn open(root: impl AsRef<Path>, identity: IdentityKey) -> Result<Self, TrustError> {
        let path = root.as_ref().join("trust.store");
        let records = match fs::read(&path) {
            Ok(bytes) => parse_trust_file(&bytes, identity.public_key())?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(io_err(e)),
        };
        Ok(Self {
            path,
            identity,
            records,
        })
    }

    fn persist(&self) -> Result<(), TrustError> {
        let body = encode_trust_body(&self.records);
        let sig = self.identity.sign(&body);
        let mut out = Vec::with_capacity(8 + 64 + body.len());
        out.extend_from_slice(TRUSTSTORE_MAGIC);
        out.extend_from_slice(&sig);
        out.extend_from_slice(&body);
        atomic_write(&self.path, &out)
    }
}

fn parse_trust_file(
    bytes: &[u8],
    owner: PublicKey,
) -> Result<BTreeMap<[u8; 32], StoredTrust>, TrustError> {
    if bytes.len() < 8 + 64 {
        return Err(TrustError::CorruptStore);
    }
    if &bytes[..8] != TRUSTSTORE_MAGIC {
        return Err(TrustError::CorruptStore);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[8..72]);
    let body = &bytes[72..];
    owner.verify(body, &sig)?;
    decode_trust_body(body)
}

impl TrustStore for FileTrustStore {
    fn get(&self, peer: &PeerId) -> Result<Option<TrustRecord>, TrustError> {
        Ok(self.records.get(peer.as_bytes()).map(|state| {
            TrustRecord::new(peer.public_key(), *state)
        }))
    }

    fn put(&mut self, record: TrustRecord) -> Result<(), TrustError> {
        self.records
            .insert(record.public_key.to_bytes(), record.state);
        self.persist()
    }
}

/// Persist Trust State keyed by device public key.
pub trait TrustStore: Send {
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
    WrongPassword,
    CorruptStore,
    Io,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::InvalidPublicKey => f.write_str("invalid public key"),
            TrustError::UnknownPeer => f.write_str("unknown peer"),
            TrustError::WrongPassword => f.write_str("wrong password"),
            TrustError::CorruptStore => f.write_str("corrupt store"),
            TrustError::Io => f.write_str("io error"),
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
        //k_verified. This test documents the absence of any server-fed API.
        let mut eng = engine();
        let (_, peer, pk) = peer();
        eng.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        eng.evaluate(peer, pk).unwrap();
        eng.mark_verified(peer).unwrap();
        assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
    }

    fn temp_root(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "p2p-trust-{}-{}-{}",
            label,
            std::process::id(),
            IdentityKey::generate().peer_id().to_bytes()[0]
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn file_keystore_round_trip_and_wrong_password() {
        let root = temp_root("ks");
        let id = IdentityKey::generate();
        {
            let mut ks = FileKeyStore::new(&root, b"correct-horse");
            assert!(ks.load().unwrap().is_none());
            ks.save(&id).unwrap();
            assert_eq!(ks.load().unwrap().unwrap().peer_id(), id.peer_id());
        }
        let bad = FileKeyStore::new(&root, b"wrong-battery");
        match bad.load() {
            Err(TrustError::WrongPassword) => {}
            other => panic!("expected WrongPassword, got {:?}", other.err()),
        }
        let mut good = FileKeyStore::new(&root, b"correct-horse");
        assert_eq!(good.load().unwrap().unwrap().peer_id(), id.peer_id());
        good.change_password(b"new-staple").unwrap();
        match FileKeyStore::new(&root, b"correct-horse").load() {
            Err(TrustError::WrongPassword) => {}
            other => panic!("expected WrongPassword after change, got {:?}", other.err()),
        }
        assert_eq!(
            FileKeyStore::new(&root, b"new-staple")
                .load()
                .unwrap()
                .unwrap()
                .peer_id(),
            id.peer_id()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_truststore_survives_reopen_and_rejects_tamper() {
        let root = temp_root("ts");
        let id = IdentityKey::generate();
        let (_, peer, pk) = peer();
        {
            let store = FileTrustStore::open(&root, id.clone()).unwrap();
            let mut eng = TrustEngine::new(id.clone(), Box::new(store));
            eng.introduce(peer, IntroductionChannel::Trusted).unwrap();
            assert_eq!(
                eng.evaluate(peer, pk).unwrap(),
                EvaluateDecision::Allow {
                    state: StoredTrust::Verified
                }
            );
        }
        {
            let store = FileTrustStore::open(&root, id.clone()).unwrap();
            let eng = TrustEngine::new(id.clone(), Box::new(store));
            assert_eq!(eng.trust_state(&peer).unwrap(), TrustState::Verified);
        }
        let path = root.join("trust.store");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            FileTrustStore::open(&root, id).err(),
            Some(TrustError::CorruptStore)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_and_memory_engines_agree_on_state_machine() {
        let root = temp_root("both");
        let id = IdentityKey::generate();
        let (_, peer, pk) = peer();
        let mut mem = TrustEngine::new(id.clone(), Box::new(MemoryTrustStore::new()));
        let file = FileTrustStore::open(&root, id.clone()).unwrap();
        let mut disk = TrustEngine::new(id, Box::new(file));
        mem.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        disk.introduce(peer, IntroductionChannel::Untrusted).unwrap();
        assert_eq!(
            mem.trust_state(&peer).unwrap(),
            disk.trust_state(&peer).unwrap()
        );
        mem.mark_verified(peer).unwrap();
        disk.mark_verified(peer).unwrap();
        assert_eq!(
            mem.evaluate(peer, pk).unwrap(),
            disk.evaluate(peer, pk).unwrap()
        );
        let _ = fs::remove_dir_all(&root);
    }
}
