//! Session API over [`p2p-trust`], wired to iroh.
//!
//! The server cannot read Session content. Identity Key remains Ed25519;
//! Session handshake prefers hybrid KEM.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, RelayMode, SendStream, presets};
use iroh::{Endpoint as IrohEndpoint, EndpointAddr, SecretKey};
use p2p_trust::{
    EvaluateDecision, IdentityKey, IntroductionChannel, KeyStore, PeerId, PublicKey, StoredTrust,
    TrustEngine, TrustStore,
};
use rustls::crypto::aws_lc_rs::{self, kx_group};

/// ALPN for this crate's Session. Set at bind so the endpoint is ready.
pub const SESSION_ALPN: &[u8] = b"p2p-core/session/0";

/// How long outbound dial waits before [`Error::PeerOffline`].
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

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

/// How to reach a Peer when there is no Address Lookup.
///
/// Relay URL strings, not iroh types.
#[derive(Clone, Debug, Default)]
pub struct DialHints {
    relay_urls: Vec<String>,
}

impl DialHints {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn relays(urls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            relay_urls: urls.into_iter().map(Into::into).collect(),
        }
    }
}

/// Local endpoint. Holds an iroh endpoint internally; iroh types stay private.
pub struct Endpoint {
    inner: IrohEndpoint,
    engine: Mutex<TrustEngine>,
    live: Arc<Mutex<HashSet<PeerId>>>,
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
        let identity = match key_store.load() {
            Ok(Some(id)) => id,
            Ok(None) => {
                let id = IdentityKey::generate();
                key_store.save(&id).map_err(Error::Trust)?;
                id
            }
            Err(_) => return Err(Error::UnlockFailed),
        };
        let seed = identity.to_seed_bytes();
        let secret = SecretKey::from_bytes(&seed);
        let engine = Mutex::new(TrustEngine::new(identity, trust_store));

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
        Ok(Self {
            inner,
            engine,
            live: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        let id = self.engine.lock().expect("trust engine").peer_id();
        debug_assert_eq!(id.to_bytes(), *self.inner.id().as_bytes());
        id
    }

    pub fn trust_state(&self, peer: &PeerId) -> Result<p2p_trust::TrustState, Error> {
        self.engine
            .lock()
            .expect("trust engine")
            .trust_state(peer)
            .map_err(Error::Trust)
    }

    pub fn introduce(
        &self,
        peer: PeerId,
        channel: IntroductionChannel,
    ) -> Result<StoredTrust, Error> {
        self.engine
            .lock()
            .expect("trust engine")
            .introduce(peer, channel)
            .map_err(Error::Trust)
    }

    pub fn mark_verified(&self, peer: PeerId) -> Result<StoredTrust, Error> {
        self.engine
            .lock()
            .expect("trust engine")
            .mark_verified(peer)
            .map_err(Error::Trust)
    }

    /// Accept a TOFU key-change alert. Records the new key as Untrusted (TOFU).
    pub fn accept_tofu_replacement(&self, presented: PublicKey) -> Result<StoredTrust, Error> {
        self.engine
            .lock()
            .expect("trust engine")
            .accept_tofu_replacement(presented)
            .map_err(Error::Trust)
    }

    /// Dial `intended`. Handshake then `evaluate(intended, presented)`.
    ///
    /// At most one live Session per remote Peer ID; a second dial is
    /// [`Error::AlreadyConnected`] until the first is closed.
    pub async fn dial(&self, intended: PeerId, hints: DialHints) -> Result<Session, Error> {
        self.reserve(intended)?;
        let endpoint_id = iroh_endpoint_id(intended)?;
        let mut addr = EndpointAddr::new(endpoint_id);
        for url in &hints.relay_urls {
            let relay: iroh::RelayUrl = url.parse().map_err(|_| Error::InvalidRelayUrl)?;
            addr = addr.with_relay_url(relay);
        }
        let conn = match tokio::time::timeout(DIAL_TIMEOUT, self.inner.connect(addr, SESSION_ALPN))
            .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                self.release(intended);
                return Err(classify_dial(e, hints.relay_urls.is_empty()));
            }
            Err(_) => {
                self.release(intended);
                return Err(if hints.relay_urls.is_empty() {
                    Error::RelayUnreachable
                } else {
                    Error::PeerOffline
                });
            }
        };
        let presented = match presented_from_conn(&conn) {
            Ok(p) => p,
            Err(e) => {
                conn.close(0u32.into(), b"trust");
                self.release(intended);
                return Err(e);
            }
        };
        let decision = match self.evaluate(intended, presented) {
            Ok(d) => d,
            Err(e) => {
                conn.close(0u32.into(), b"trust");
                self.release(intended);
                return Err(e);
            }
        };
        match decision {
            EvaluateDecision::Allow { .. } => {
                // QUIC bi-stream is lazy: acceptor's accept_bi waits until this write.
                let (mut send, recv) = match conn.open_bi().await {
                    Ok(s) => s,
                    Err(_) => {
                        conn.close(0u32.into(), b"stream");
                        self.release(intended);
                        return Err(Error::Stream);
                    }
                };
                if send.write_all(&[0]).await.is_err() {
                    conn.close(0u32.into(), b"stream");
                    self.release(intended);
                    return Err(Error::Stream);
                }
                Ok(Session::new(intended, conn, send, recv, self.live.clone()))
            }
            other => {
                self.release(intended);
                Err(self.gate_fail(conn, other))
            }
        }
    }

    /// Accept one incoming dial. `intended = presented`.
    pub async fn accept(&self) -> Result<Session, Error> {
        let incoming = self.inner.accept().await.ok_or(Error::Closed)?;
        let conn = incoming.await.map_err(|_| Error::Accept)?;
        let presented = match presented_from_conn(&conn) {
            Ok(p) => p,
            Err(e) => {
                conn.close(0u32.into(), b"trust");
                return Err(e);
            }
        };
        let intended = presented.peer_id();
        if let Err(e) = self.reserve(intended) {
            conn.close(0u32.into(), b"busy");
            return Err(e);
        }
        let decision = match self.evaluate(intended, presented) {
            Ok(d) => d,
            Err(e) => {
                conn.close(0u32.into(), b"trust");
                self.release(intended);
                return Err(e);
            }
        };
        match decision {
            EvaluateDecision::Allow { .. } => {
                let (send, mut recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => {
                        conn.close(0u32.into(), b"stream");
                        self.release(intended);
                        return Err(Error::Stream);
                    }
                };
                let mut opener = [0u8; 1];
                if recv.read_exact(&mut opener).await.is_err() {
                    conn.close(0u32.into(), b"stream");
                    self.release(intended);
                    return Err(Error::Stream);
                }
                Ok(Session::new(intended, conn, send, recv, self.live.clone()))
            }
            other => {
                self.release(intended);
                Err(self.gate_fail(conn, other))
            }
        }
    }

    fn reserve(&self, peer: PeerId) -> Result<(), Error> {
        let mut live = self.live.lock().expect("live sessions");
        if !live.insert(peer) {
            return Err(Error::AlreadyConnected { peer });
        }
        Ok(())
    }

    fn release(&self, peer: PeerId) {
        self.live.lock().expect("live sessions").remove(&peer);
    }

    fn evaluate(
        &self,
        intended: PeerId,
        presented: PublicKey,
    ) -> Result<EvaluateDecision, Error> {
        self.engine
            .lock()
            .expect("trust engine")
            .evaluate(intended, presented)
            .map_err(Error::Trust)
    }

    fn gate_fail(&self, conn: Connection, decision: EvaluateDecision) -> Error {
        conn.close(0u32.into(), b"trust");
        match decision {
            EvaluateDecision::Allow { .. } => unreachable!("allow is not a gate fail"),
            EvaluateDecision::RejectVerifiedMismatch { intended, presented }
            | EvaluateDecision::RejectUnknownMismatch { intended, presented } => {
                Error::Rejected { intended, presented }
            }
            EvaluateDecision::AlertTofuMismatch {
                intended,
                presented,
                previous,
            } => Error::Alert {
                intended,
                presented,
                previous,
            },
        }
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

fn iroh_endpoint_id(peer: PeerId) -> Result<iroh::EndpointId, Error> {
    iroh::PublicKey::from_bytes(peer.as_bytes())
        .map_err(|_| Error::Trust(p2p_trust::TrustError::InvalidPublicKey))
}

fn presented_from_conn(conn: &Connection) -> Result<PublicKey, Error> {
    PublicKey::from_bytes(*conn.remote_id().as_bytes()).map_err(Error::Trust)
}

fn classify_dial(err: iroh::endpoint::ConnectError, no_relay_hint: bool) -> Error {
    use iroh::endpoint::{ConnectError, ConnectWithOptsError};
    if no_relay_hint {
        return Error::RelayUnreachable;
    }
    match err {
        ConnectError::Connect {
            source: ConnectWithOptsError::NoAddress { .. },
            ..
        } => Error::RelayUnreachable,
        _ => Error::PeerOffline,
    }
}

/// One authenticated Session: one connection + one bidirectional reliable stream.
pub struct Session {
    remote: PeerId,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    live: Arc<Mutex<HashSet<PeerId>>>,
}

impl Session {
    fn new(
        remote: PeerId,
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        live: Arc<Mutex<HashSet<PeerId>>>,
    ) -> Self {
        Self {
            remote,
            conn,
            send,
            recv,
            live,
        }
    }

    pub fn remote_peer_id(&self) -> PeerId {
        self.remote
    }

    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.send.write_all(bytes).await.map_err(|_| Error::Io)
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(_) => Err(Error::Io),
        }
    }

    pub async fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.recv.read_exact(buf).await.map_err(|_| Error::Io)
    }

    /// End this Session. The peer observes end on the next recv; later send fails.
    pub fn close(&self) {
        self.end();
    }

    fn end(&self) {
        self.conn.close(0u32.into(), b"session");
        self.live.lock().expect("live sessions").remove(&self.remote);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.end();
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Bind,
    InvalidRelayUrl,
    PeerOffline,
    RelayUnreachable,
    UnlockFailed,
    Accept,
    Stream,
    Io,
    Closed,
    AlreadyConnected {
        peer: PeerId,
    },
    Trust(p2p_trust::TrustError),
    Rejected {
        intended: PeerId,
        presented: PublicKey,
    },
    Alert {
        intended: PeerId,
        presented: PublicKey,
        previous: StoredTrust,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bind => f.write_str("failed to bind endpoint"),
            Error::InvalidRelayUrl => f.write_str("invalid relay url"),
            Error::PeerOffline => f.write_str("peer offline"),
            Error::RelayUnreachable => f.write_str("relay unreachable"),
            Error::UnlockFailed => f.write_str("failed to unlock local identity"),
            Error::Accept => f.write_str("accept failed"),
            Error::Stream => f.write_str("stream failed"),
            Error::Io => f.write_str("session io failed"),
            Error::Closed => f.write_str("endpoint closed"),
            Error::AlreadyConnected { .. } => f.write_str("session already connected"),
            Error::Trust(e) => write!(f, "{e}"),
            Error::Rejected { .. } => f.write_str("evaluate rejected session"),
            Error::Alert { .. } => f.write_str("evaluate alerted on key change"),
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
        // Threat model e: application data is 1-RTT only. Cut at `mod tests`,
        // not the first `#[cfg(test)]` (that is skip_tls_verify on RelayConfig).
        let src = include_str!("lib.rs");
        let prod = src.split("mod tests").next().expect("prod");
        assert!(prod.contains("pub struct Endpoint"));
        assert!(prod.contains("pub async fn bind"));
        assert!(prod.contains("pub async fn dial"));
        assert!(prod.contains("pub async fn accept"));
        assert!(!prod.contains("into_0rtt"));
        assert!(!prod.contains("ZeroRtt"));
        assert!(!prod.contains("SecretKey::generate"));
        assert!(!prod.contains("pub use iroh"));
        assert!(!prod.contains("pub type Connection"));
        assert!(!prod.contains("pub struct EndpointId"));
        assert!(!prod.contains("pub const DIAL_TIMEOUT"));
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

    struct Pair {
        a: Endpoint,
        b: Endpoint,
        url: String,
        _keep: Box<dyn std::any::Any + Send>,
    }

    async fn pair() -> Pair {
        let (map, url, server) = iroh::test_utils::run_relay_server()
            .await
            .expect("in-process relay");
        let relay_a = RelayConfig::custom([url.to_string()])
            .unwrap()
            .with_insecure_tls();
        let relay_b = RelayConfig::custom([url.to_string()])
            .unwrap()
            .with_insecure_tls();
        let mut ks_a = MemoryKeyStore::new();
        let mut ks_b = MemoryKeyStore::new();
        let a = Endpoint::bind(&mut ks_a, Box::new(MemoryTrustStore::new()), relay_a)
            .await
            .expect("bind a");
        let b = Endpoint::bind(&mut ks_b, Box::new(MemoryTrustStore::new()), relay_b)
            .await
            .expect("bind b");
        a.inner.online().await;
        b.inner.online().await;
        Pair {
            a,
            b,
            url: url.to_string(),
            _keep: Box::new((map, server)),
        }
    }

    fn hints(url: &str) -> DialHints {
        DialHints::relays([url])
    }

    #[tokio::test]
    async fn alpn_is_fixed_session_zero() {
        assert_eq!(SESSION_ALPN, b"p2p-core/session/0");
    }

    #[tokio::test]
    async fn dial_accept_bytes_round_trip() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        let payload = b"hello-session";
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, hints(&pair.url)), pair.b.accept());
        let mut sa = sa.expect("dial");
        let mut sb = sb.expect("accept");
        assert_eq!(sa.remote_peer_id(), b_id);
        assert_eq!(sb.remote_peer_id(), pair.a.peer_id());
        sa.send(payload).await.expect("send");
        let mut buf = [0u8; 13];
        sb.recv_exact(&mut buf).await.expect("recv");
        assert_eq!(&buf, payload);
        sb.send(b"ack").await.expect("reply");
        let mut ack = [0u8; 3];
        sa.recv_exact(&mut ack).await.expect("ack");
        assert_eq!(&ack, b"ack");
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn first_inbound_is_tofu_not_verified() {
        let pair = pair().await;
        let a_id = pair.a.peer_id();
        let b_id = pair.b.peer_id();
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, hints(&pair.url)), pair.b.accept());
        let sa = sa.expect("dial");
        let sb = sb.expect("accept");
        assert_eq!(sa.remote_peer_id(), b_id);
        assert_eq!(sb.remote_peer_id(), a_id);
        assert_eq!(
            pair.b.trust_state(&a_id).unwrap(),
            p2p_trust::TrustState::Tofu
        );
        assert_eq!(
            pair.a.trust_state(&b_id).unwrap(),
            p2p_trust::TrustState::Tofu
        );
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn accept_tofu_replacement_is_explicit_and_untrusted() {
        let pair = pair().await;
        let presented = IdentityKey::generate().public_key();
        assert_eq!(
            pair.a.accept_tofu_replacement(presented).unwrap(),
            StoredTrust::Tofu
        );
        assert_eq!(
            pair.a.trust_state(&presented.peer_id()).unwrap(),
            p2p_trust::TrustState::Tofu
        );
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn verified_peer_dials_without_sas() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        pair.a
            .introduce(b_id, IntroductionChannel::Trusted)
            .expect("introduce");
        assert_eq!(
            pair.a.trust_state(&b_id).unwrap(),
            p2p_trust::TrustState::Verified
        );
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, hints(&pair.url)), pair.b.accept());
        let sa = sa.expect("dial verified");
        let sb = sb.expect("accept");
        assert_eq!(sa.remote_peer_id(), b_id);
        assert_eq!(sb.remote_peer_id(), pair.a.peer_id());
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn close_is_observed_and_further_send_fails() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, hints(&pair.url)), pair.b.accept());
        let mut sa = sa.expect("dial");
        let mut sb = sb.expect("accept");
        sa.close();
        let mut buf = [0u8; 8];
        let ended = sb.recv(&mut buf).await;
        assert!(
            matches!(ended, Ok(0) | Err(_)),
            "peer must observe Session end, got {ended:?}"
        );
        assert!(sa.send(b"after-close").await.is_err());
        assert!(sb.send(b"after-end").await.is_err());
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn drop_without_close_still_ends_peer_session() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, hints(&pair.url)), pair.b.accept());
        let sa = sa.expect("dial");
        let mut sb = sb.expect("accept");
        drop(sa);
        let mut buf = [0u8; 8];
        let ended = sb.recv(&mut buf).await;
        assert!(
            matches!(ended, Ok(0) | Err(_)),
            "drop must end the Session, got {ended:?}"
        );
        assert!(sb.send(b"after-drop").await.is_err());
        pair.a.close().await;
        pair.b.close().await;
    }

    struct Trio {
        a: Endpoint,
        b: Endpoint,
        c: Endpoint,
        url: String,
        _keep: Box<dyn std::any::Any + Send>,
    }

    async fn trio() -> Trio {
        let (map, url, server) = iroh::test_utils::run_relay_server()
            .await
            .expect("in-process relay");
        let bind = async || {
            let mut ks = MemoryKeyStore::new();
            let relay = RelayConfig::custom([url.to_string()])
                .unwrap()
                .with_insecure_tls();
            Endpoint::bind(&mut ks, Box::new(MemoryTrustStore::new()), relay)
                .await
                .expect("bind")
        };
        let a = bind().await;
        let b = bind().await;
        let c = bind().await;
        a.inner.online().await;
        b.inner.online().await;
        c.inner.online().await;
        Trio {
            a,
            b,
            c,
            url: url.to_string(),
            _keep: Box::new((map, server)),
        }
    }

    #[tokio::test]
    async fn concurrent_sessions_do_not_cross_bytes() {
        let trio = trio().await;
        let b_id = trio.b.peer_id();
        let c_id = trio.c.peer_id();
        let h = hints(&trio.url);
        let (ab, ba, ac, ca) = tokio::join!(
            trio.a.dial(b_id, h.clone()),
            trio.b.accept(),
            trio.a.dial(c_id, h),
            trio.c.accept(),
        );
        let mut ab = ab.expect("a->b");
        let mut ba = ba.expect("b accept");
        let mut ac = ac.expect("a->c");
        let mut ca = ca.expect("c accept");
        ab.send(b"for-b").await.expect("to b");
        ac.send(b"for-c").await.expect("to c");
        let mut bbuf = [0u8; 5];
        let mut cbuf = [0u8; 5];
        ba.recv_exact(&mut bbuf).await.expect("b recv");
        ca.recv_exact(&mut cbuf).await.expect("c recv");
        assert_eq!(&bbuf, b"for-b");
        assert_eq!(&cbuf, b"for-c");
        trio.a.close().await;
        trio.b.close().await;
        trio.c.close().await;
    }

    #[tokio::test]
    async fn second_dial_to_same_peer_is_already_connected() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        let h = hints(&pair.url);
        let (sa, sb) = tokio::join!(pair.a.dial(b_id, h.clone()), pair.b.accept());
        let sa = sa.expect("first dial");
        let sb = sb.expect("accept");
        let again = pair.a.dial(b_id, h.clone()).await;
        assert!(
            matches!(again, Err(Error::AlreadyConnected { peer }) if peer == b_id),
            "got {:?}",
            again.as_ref().err()
        );
        sa.close();
        drop(sb);
        let (sa2, sb2) = tokio::join!(pair.a.dial(b_id, h), pair.b.accept());
        sa2.expect("redial after close");
        sb2.expect("accept after close");
        pair.a.close().await;
        pair.b.close().await;
    }

    #[tokio::test]
    async fn dial_offline_peer_errors_without_hanging() {
        let pair = pair().await;
        let b_id = pair.b.peer_id();
        pair.b.close().await;
        let err = pair
            .a
            .dial(b_id, hints(&pair.url))
            .await
            .err()
            .expect("no Session when peer is offline");
        assert!(matches!(err, Error::PeerOffline), "got {err:?}");
        pair.a.close().await;
    }

    #[tokio::test]
    async fn dial_without_relay_fails_and_does_not_use_n0() {
        let mut ks_a = MemoryKeyStore::new();
        let mut ks_b = MemoryKeyStore::new();
        let a = bind_disabled(&mut ks_a).await;
        let b = bind_disabled(&mut ks_b).await;
        let b_id = b.peer_id();
        let err = a
            .dial(b_id, DialHints::none())
            .await
            .err()
            .expect("no Session without Relay or direct path");
        assert!(matches!(err, Error::RelayUnreachable), "got {err:?}");
        a.close().await;
        b.close().await;
    }

    #[test]
    fn errors_are_matchable_failure_reasons() {
        let intended = IdentityKey::generate().peer_id();
        let presented = IdentityKey::generate().public_key();
        let cases = [
            Error::PeerOffline,
            Error::RelayUnreachable,
            Error::UnlockFailed,
            Error::Rejected {
                intended,
                presented,
            },
        ];
        for e in cases {
            match e {
                Error::PeerOffline
                | Error::RelayUnreachable
                | Error::UnlockFailed
                | Error::Rejected { .. } => {}
                other => panic!("unmatchable {other:?}"),
            }
        }
    }

    struct FailKeyStore;

    impl KeyStore for FailKeyStore {
        fn load(&self) -> Result<Option<IdentityKey>, p2p_trust::TrustError> {
            Err(p2p_trust::TrustError::WrongPassword)
        }
        fn save(&mut self, _: &IdentityKey) -> Result<(), p2p_trust::TrustError> {
            Err(p2p_trust::TrustError::Io)
        }
    }

    #[tokio::test]
    async fn bind_unlock_failure_is_distinct() {
        let err = Endpoint::bind(
            &mut FailKeyStore,
            Box::new(MemoryTrustStore::new()),
            RelayConfig::disabled(),
        )
        .await
        .err()
        .expect("unlock must fail");
        assert!(matches!(err, Error::UnlockFailed), "got {err:?}");
    }

    #[tokio::test]
    async fn bystander_on_same_relay_does_not_receive_session_bytes() {
        // Threat model a (passive listen): content confidentiality is TLS 1.3.
        // This test only asserts we do not hand plaintext to a bystander Peer D
        // on the same Relay. Do not set SSLKEYLOGFILE.
        let trio = trio().await;
        let b_id = trio.b.peer_id();
        let secret = b"high-entropy-session-key-material";
        let (sa, sb) = tokio::join!(trio.a.dial(b_id, hints(&trio.url)), trio.b.accept());
        let mut sa = sa.expect("dial");
        let mut sb = sb.expect("accept");
        sa.send(secret).await.expect("send secret");
        let mut got = [0u8; 33];
        sb.recv_exact(&mut got).await.expect("b recv");
        assert_eq!(&got, secret);
        let sneak = tokio::time::timeout(
            Duration::from_millis(300),
            trio.c.dial(b_id, hints(&trio.url)),
        )
        .await;
        match sneak {
            Ok(Ok(_)) => panic!("D must not obtain a Session carrying A↔B bytes"),
            Ok(Err(Error::AlreadyConnected { peer })) => assert_eq!(peer, b_id),
            Ok(Err(_)) | Err(_) => {}
        }
        trio.a.close().await;
        trio.b.close().await;
        trio.c.close().await;
    }

    #[tokio::test]
    async fn dial_b_cannot_be_hijacked_to_mallory() {
        // Threat model b: a malicious Relay cannot make A-dial-B land on Mallory.
        // Peer ID is the public key; handshake authenticates that key.
        let trio = trio().await;
        let b_id = trio.b.peer_id();
        let mallory_id = trio.c.peer_id();
        let (sa, sb) = tokio::join!(trio.a.dial(b_id, hints(&trio.url)), trio.b.accept());
        let sa = sa.expect("dial B");
        let sb = sb.expect("B accept");
        assert_eq!(sa.remote_peer_id(), b_id);
        assert_ne!(sa.remote_peer_id(), mallory_id);
        assert_eq!(sb.remote_peer_id(), trio.a.peer_id());
        trio.a.close().await;
        trio.b.close().await;
        trio.c.close().await;
    }

    #[tokio::test]
    async fn mallory_without_b_secret_cannot_complete_as_b() {
        // Threat model c: Mallory has no B private key, so cannot finish
        // handshake as B. A dialing B never yields remote = Mallory.
        // (iroh EndpointId is the public key; a forged identity cannot complete.)
        let trio = trio().await;
        let b_id = trio.b.peer_id();
        let mallory_id = trio.c.peer_id();
        let (sa, sb) = tokio::join!(trio.a.dial(b_id, hints(&trio.url)), trio.b.accept());
        let sa = sa.expect("A dials B");
        let sb = sb.expect("B accepts");
        assert_eq!(sa.remote_peer_id(), b_id);
        assert_ne!(sa.remote_peer_id(), mallory_id);
        assert_eq!(sb.remote_peer_id(), trio.a.peer_id());
        assert_ne!(sb.remote_peer_id(), mallory_id);
        trio.a.close().await;
        trio.b.close().await;
        trio.c.close().await;
    }
}
