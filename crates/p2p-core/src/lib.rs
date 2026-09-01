//! Session API over [`p2p-trust`], wired to iroh.
//!
//! The server cannot read Session content. Identity Key remains Ed25519;
//! Session handshake prefers hybrid KEM.

#![forbid(unsafe_code)]

use std::sync::Arc;

use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint as IrohEndpoint, SecretKey};
use p2p_trust::{IdentityKey, KeyStore, PeerId, TrustEngine, TrustStore};
use rustls::crypto::aws_lc_rs::{self, kx_group};

/// ALPN for this crate's Session. Set at bind so the endpoint is ready.
pub const SESSION_ALPN: &[u8] = b"p2p-core/session/0";

/// How this endpoint reaches a Relay.
///
/// Default is [`RelayConfig::disabled`]: no n0 public relays.
pub struct RelayConfig {
    kind: RelayKind,
    #[cfg(test)]
    skip_tls_verify: bool,
}

enum RelayKind {
    Disabled,
    Custom(Vec<iroh::RelayUrl>),
    N0Public,
}

impl RelayConfig {
    /// No Relay. This is the production default.
    pub fn disabled() -> Self {
        Self {
            kind: RelayKind::Disabled,
            #[cfg(test)]
            skip_tls_verify: false,
        }
    }

    /// Self-hosted Relay URLs (e.g. `https://relay.example`).
    pub fn custom(urls: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, Error> {
        let parsed: Result<Vec<iroh::RelayUrl>, _> =
            urls.into_iter().map(|u| u.as_ref().parse()).collect();
        let parsed = parsed.map_err(|_| Error::InvalidRelayUrl)?;
        if parsed.is_empty() {
            return Err(Error::InvalidRelayUrl);
        }
        Ok(Self {
            kind: RelayKind::Custom(parsed),
            #[cfg(test)]
            skip_tls_verify: false,
        })
    }

    /// Explicit opt-in to n0 public relays. Development only.
    pub fn n0_public() -> Self {
        Self {
            kind: RelayKind::N0Public,
            #[cfg(test)]
            skip_tls_verify: false,
        }
    }

    /// Skip Relay TLS verification. Only for iroh test-utils certificates.
    #[cfg(test)]
    fn with_insecure_tls(mut self) -> Self {
        self.skip_tls_verify = true;
        self
    }
}

/// Local endpoint. Holds an iroh endpoint internally; iroh types stay private.
pub struct Endpoint {
    inner: IrohEndpoint,
    engine: TrustEngine,
}

impl Endpoint {
    /// Bind using the Identity Key in `key_store`.
    ///
    /// If the store is empty, a new Identity Key is generated and saved.
    /// The iroh secret is always derived from that seed; iroh never generates
    /// its own production key.
    pub async fn bind(
        key_store: &mut dyn KeyStore,
        trust_store: Box<dyn TrustStore>,
        relay: RelayConfig,
    ) -> Result<Self, Error> {
        let identity = match key_store.load().map_err(Error::Trust)? {
            Some(id) => id,
            None => {
                let id = IdentityKey::generate();
                key_store.save(&id).map_err(Error::Trust)?;
                id
            }
        };
        let seed = identity.to_seed_bytes();
        let secret = SecretKey::from_bytes(&seed);
        let engine = TrustEngine::new(identity, trust_store);

        let provider = hybrid_pq_provider();

        let mut builder = IrohEndpoint::builder(presets::Empty)
            .secret_key(secret)
            .crypto_provider(provider)
            .alpns(vec![SESSION_ALPN.to_vec()]);

        builder = match relay.kind {
            RelayKind::Disabled => builder.relay_mode(RelayMode::Disabled),
            RelayKind::Custom(urls) => builder.relay_mode(RelayMode::custom(urls)),
            RelayKind::N0Public => builder.relay_mode(RelayMode::Default),
        };

        #[cfg(test)]
        if relay.skip_tls_verify {
            builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
        }

        let inner = builder.bind().await.map_err(|_| Error::Bind)?;
        Ok(Self { inner, engine })
    }

    pub fn peer_id(&self) -> PeerId {
        let id = self.engine.peer_id();
        debug_assert_eq!(id.to_bytes(), *self.inner.id().as_bytes());
        id
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

fn hybrid_pq_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ];
    Arc::new(provider)
}

#[cfg(test)]
fn kx_names(provider: &rustls::crypto::CryptoProvider) -> Vec<&'static str> {
    provider
        .kx_groups
        .iter()
        .map(|g| g.name().as_str().expect("known kx group"))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Bind,
    InvalidRelayUrl,
    Trust(p2p_trust::TrustError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bind => f.write_str("failed to bind endpoint"),
            Error::InvalidRelayUrl => f.write_str("invalid relay url"),
            Error::Trust(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_trust::{MemoryKeyStore, MemoryTrustStore};

    async fn bind_disabled(ks: &mut MemoryKeyStore) -> Endpoint {
        Endpoint::bind(
            ks,
            Box::new(MemoryTrustStore::new()),
            RelayConfig::disabled(),
        )
        .await
        .expect("bind")
    }

    #[tokio::test]
    async fn bind_peer_id_matches_keystore() {
        let mut ks = MemoryKeyStore::new();
        let ep = bind_disabled(&mut ks).await;
        let stored = ks.load().unwrap().unwrap();
        assert_eq!(ep.peer_id(), stored.peer_id());
        ep.close().await;
    }

    #[tokio::test]
    async fn restart_same_keystore_same_peer_id() {
        let mut ks = MemoryKeyStore::new();
        let first = bind_disabled(&mut ks).await;
        let id = first.peer_id();
        first.close().await;
        let second = bind_disabled(&mut ks).await;
        assert_eq!(second.peer_id(), id);
        second.close().await;
    }

    #[test]
    fn prefers_hybrid_pq_key_exchange() {
        let groups = kx_names(&hybrid_pq_provider());
        assert_eq!(groups.first().copied(), Some("X25519MLKEM768"));
        assert!(groups.contains(&"X25519"));
    }

    #[test]
    fn public_api_has_no_zero_rtt_entry() {
        // Threat model e: application data is 1-RTT only. Scan production
        // source only; this comment lives in the test module.
        let src = include_str!("lib.rs");
        let prod = src.split("#[cfg(test)]").next().expect("prod");
        assert!(!prod.contains("into_0rtt"));
        assert!(!prod.contains("ZeroRtt"));
        assert!(!prod.contains("SecretKey::generate"));
    }

    #[test]
    fn custom_relay_rejects_empty_and_garbage() {
        assert!(matches!(
            RelayConfig::custom(std::iter::empty::<&str>()),
            Err(Error::InvalidRelayUrl)
        ));
        assert!(matches!(
            RelayConfig::custom(["not a url"]),
            Err(Error::InvalidRelayUrl)
        ));
        assert!(RelayConfig::custom(["https://relay.example.invalid."]).is_ok());
    }

    #[test]
    fn n0_public_is_explicit_opt_in() {
        let _ = RelayConfig::n0_public();
        let _ = RelayConfig::disabled();
    }

    #[tokio::test]
    async fn in_process_relay_bind() {
        let (_map, url, _server) = iroh::test_utils::run_relay_server()
            .await
            .expect("in-process relay");
        let mut ks = MemoryKeyStore::new();
        let relay = RelayConfig::custom([url.to_string()])
            .unwrap()
            .with_insecure_tls();
        let ep = Endpoint::bind(&mut ks, Box::new(MemoryTrustStore::new()), relay)
            .await
            .expect("bind with in-process relay");
        let _ = ep.peer_id();
        ep.close().await;
    }
}
