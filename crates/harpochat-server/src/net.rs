// SPDX-License-Identifier: Apache-2.0
//! Links: TCP → TLS 1.3 → WebSocket (binary) → Noise XX (spec §5, design §5.1–5.2).
//!
//! TLS only makes the traffic look like ordinary HTTPS and survive mobile
//! middleboxes; the certificate is self-signed, generated in RAM at each
//! start, and **not** trusted by anyone. Authentication is Noise: a node
//! proves its Ed25519 identity inside the handshake. After the handshake,
//! every WebSocket message is one Noise message of a fixed class size.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use harpochat_core::keys::{SigningKey, X25519Secret};
use harpochat_core::link::{LinkFrame, SizeClass};
use harpochat_core::noise::{Handshake, Peer, Transport};
use harpochat_core::CoreError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// Handshake (TLS + WS + Noise) must complete within this delay.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest WebSocket message accepted (a Large Noise message).
pub const MAX_WS_MESSAGE: usize = 32 * 1024;

/// Link failure. Never carries peer addresses or payloads.
#[derive(Debug)]
pub enum NetError {
    /// Socket error.
    Io(std::io::Error),
    /// TLS error.
    Tls(String),
    /// WebSocket error.
    Ws(String),
    /// Noise or framing error.
    Protocol(CoreError),
    /// Handshake too slow.
    Timeout,
    /// Peer closed the link.
    Closed,
    /// Peer is not the node we expected.
    WrongPeer,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "socket: {e}"),
            NetError::Tls(e) => write!(f, "tls: {e}"),
            NetError::Ws(e) => write!(f, "websocket: {e}"),
            NetError::Protocol(e) => write!(f, "protocole: {e}"),
            NetError::Timeout => f.write_str("délai de poignée de main dépassé"),
            NetError::Closed => f.write_str("lien fermé"),
            NetError::WrongPeer => f.write_str("le pair n'est pas le nœud attendu"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<WsError> for NetError {
    fn from(e: WsError) -> Self {
        match e {
            WsError::ConnectionClosed | WsError::AlreadyClosed => NetError::Closed,
            other => NetError::Ws(other.to_string()),
        }
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE))
}

/// TLS acceptor with a fresh self-signed certificate (RAM only, TLS 1.3 only).
pub fn tls_acceptor() -> Result<TlsAcceptor, NetError> {
    let ck = rcgen::generate_simple_self_signed(vec!["harpochat".to_string()])
        .map_err(|e| NetError::Tls(e.to_string()))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| NetError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .map_err(|e| NetError::Tls(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accepts any server certificate but still checks the TLS handshake
/// signatures. Peer authentication is done by Noise, not by TLS.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS connector that accepts self-signed certificates (TLS 1.3 only).
pub fn tls_connector() -> Result<TlsConnector, NetError> {
    let p = provider();
    let config = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| NetError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

type WsStream = Pin<Box<dyn Stream<Item = Result<Message, WsError>> + Send>>;
type WsSink = Pin<Box<dyn Sink<Message, Error = WsError> + Send>>;

/// Receiving half of a link.
pub struct LinkReader {
    stream: WsStream,
    noise: Arc<Mutex<Transport>>,
}

/// Sending half of a link.
pub struct LinkWriter {
    sink: WsSink,
    noise: Arc<Mutex<Transport>>,
}

async fn next_binary(stream: &mut WsStream) -> Result<Vec<u8>, NetError> {
    loop {
        match stream.next().await {
            None => return Err(NetError::Closed),
            Some(Err(e)) => return Err(e.into()),
            Some(Ok(Message::Binary(b))) => return Ok(b.to_vec()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => return Err(NetError::Closed),
            Some(Ok(_)) => return Err(NetError::Protocol(CoreError::Malformed)),
        }
    }
}

async fn noise_handshake(
    stream: &mut WsStream,
    sink: &mut WsSink,
    mut hs: Handshake,
    initiator: bool,
) -> Result<(Transport, Peer), NetError> {
    // XX: initiator writes 1 and 3, responder writes 2.
    for step in 0..3 {
        let we_write = (step % 2 == 0) == initiator;
        if we_write {
            let m = hs.write_message().map_err(NetError::Protocol)?;
            sink.send(Message::Binary(m.into())).await?;
        } else {
            let m = next_binary(stream).await?;
            hs.read_message(&m).map_err(NetError::Protocol)?;
        }
    }
    hs.into_transport().map_err(NetError::Protocol)
}

fn halves<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> (WsStream, WsSink)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    (Box::pin(stream), Box::pin(sink))
}

fn finish(stream: WsStream, sink: WsSink, t: Transport) -> (LinkReader, LinkWriter) {
    let noise = Arc::new(Mutex::new(t));
    (
        LinkReader {
            stream,
            noise: noise.clone(),
        },
        LinkWriter { sink, noise },
    )
}

/// Accept an incoming link as this node.
pub async fn accept(
    tcp: TcpStream,
    tls: &TlsAcceptor,
    noise_static: &X25519Secret,
    identity: &SigningKey,
) -> Result<(LinkReader, LinkWriter, Peer), NetError> {
    let hs = Handshake::responder(noise_static, Some(identity)).map_err(NetError::Protocol)?;
    let fut = async {
        let tls = tls.accept(tcp).await.map_err(NetError::Io)?;
        let ws = tokio_tungstenite::accept_async_with_config(tls, Some(ws_config())).await?;
        let (mut stream, mut sink) = halves(ws);
        let (t, peer) = noise_handshake(&mut stream, &mut sink, hs, false).await?;
        let (r, w) = finish(stream, sink, t);
        Ok((r, w, peer))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| NetError::Timeout)?
}

/// Dial a node by address. `identity` is `None` for a phone (anonymous).
/// If `expected_node` is set, the peer must prove exactly that identity.
pub async fn connect(
    addr: SocketAddr,
    noise_static: &X25519Secret,
    identity: Option<&SigningKey>,
    expected_node: Option<[u8; 32]>,
) -> Result<(LinkReader, LinkWriter, Peer), NetError> {
    connect_named(
        addr,
        &addr.to_string(),
        noise_static,
        identity,
        expected_node,
    )
    .await
}

/// SNI host of a `host:port` string (`[v6]:port` accepted).
fn sni_host(host_port: &str) -> &str {
    let host = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host_port,
    };
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Like [`connect`], but presents `host_port` (an endpoint's `host:port`)
/// as TLS SNI and WebSocket `Host`, so the link also works through a
/// reverse proxy that routes by name. The proxy is not trusted: the peer
/// is still authenticated by the Noise handshake only.
pub async fn connect_named(
    addr: SocketAddr,
    host_port: &str,
    noise_static: &X25519Secret,
    identity: Option<&SigningKey>,
    expected_node: Option<[u8; 32]>,
) -> Result<(LinkReader, LinkWriter, Peer), NetError> {
    let name = ServerName::try_from(sni_host(host_port).to_owned())
        .or_else(|_| ServerName::try_from("harpochat"))
        .expect("static name");
    let url = format!("wss://{host_port}/");
    let hs = Handshake::initiator(noise_static, identity).map_err(NetError::Protocol)?;
    let connector = tls_connector()?;
    let fut = async {
        let tcp = TcpStream::connect(addr).await.map_err(NetError::Io)?;
        let tls = connector.connect(name, tcp).await.map_err(NetError::Io)?;
        let (ws, _) =
            tokio_tungstenite::client_async_with_config(url.as_str(), tls, Some(ws_config()))
                .await?;
        let (mut stream, mut sink) = halves(ws);
        let (t, peer) = noise_handshake(&mut stream, &mut sink, hs, true).await?;
        if let Some(expected) = expected_node {
            if peer.node_id != Some(expected) {
                return Err(NetError::WrongPeer);
            }
        }
        let (r, w) = finish(stream, sink, t);
        Ok((r, w, peer))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| NetError::Timeout)?
}

impl LinkReader {
    /// Next frame. Any malformed or wrong-size message is an error: the
    /// caller must close the link.
    pub async fn recv(&mut self) -> Result<(SizeClass, LinkFrame), NetError> {
        let msg = next_binary(&mut self.stream).await?;
        let plain = self
            .noise
            .lock()
            .expect("noise lock")
            .decrypt(&msg)
            .map_err(NetError::Protocol)?;
        LinkFrame::decode(&plain).map_err(NetError::Protocol)
    }
}

impl LinkWriter {
    /// Send one frame in the given size class.
    pub async fn send(&mut self, frame: &LinkFrame, class: SizeClass) -> Result<(), NetError> {
        let plain = frame.encode(class).map_err(NetError::Protocol)?;
        let ct = self
            .noise
            .lock()
            .expect("noise lock")
            .encrypt(&plain)
            .map_err(NetError::Protocol)?;
        self.sink.send(Message::Binary(ct.into())).await?;
        Ok(())
    }

    /// Send a raw WebSocket message (tests of malformed traffic only).
    #[doc(hidden)]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> Result<(), NetError> {
        self.sink.send(Message::Binary(bytes.into())).await?;
        Ok(())
    }
}

/// Token bucket limiting frames per link (spec §11: per Noise link, not per IP).
#[derive(Debug, Clone)]
pub struct RateLimit {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Option<Instant>,
}

impl RateLimit {
    /// Default per-link limit: 50 frames/s, bursts of 200.
    pub const DEFAULT_RATE: u32 = 50;
    /// Default burst.
    pub const DEFAULT_BURST: u32 = 200;

    /// New full bucket.
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate: rate_per_sec as f64,
            burst: burst as f64,
            tokens: burst as f64,
            last: None,
        }
    }

    /// Take one token if available.
    pub fn allow(&mut self, now: Instant) -> bool {
        if let Some(last) = self.last {
            let dt = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        }
        self.last = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sni_host_strips_port_and_brackets() {
        assert_eq!(super::sni_host("harpo.cronix.fr:443"), "harpo.cronix.fr");
        assert_eq!(super::sni_host("[::1]:8443"), "::1");
        assert_eq!(super::sni_host("127.0.0.1:1"), "127.0.0.1");
        assert_eq!(super::sni_host("host"), "host");
    }

    use super::*;
    use harpochat_core::link::FrameKind;
    use tokio::net::TcpListener;

    async fn pair() -> (
        (LinkReader, LinkWriter, Peer),
        (LinkReader, LinkWriter, Peer),
        [u8; 32],
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let node_static = X25519Secret::generate();
        let node_id = SigningKey::generate();
        let id = node_id.public();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = tls_acceptor().unwrap();
            accept(tcp, &tls, &node_static, &node_id).await.unwrap()
        });
        let client = connect(addr, &X25519Secret::generate(), None, Some(id))
            .await
            .unwrap();
        (client, server.await.unwrap(), id)
    }

    #[tokio::test]
    async fn handshake_over_tls_ws() {
        let ((_, _, seen_by_client), (_, _, seen_by_node), id) = pair().await;
        assert_eq!(seen_by_client.node_id, Some(id));
        assert_eq!(seen_by_node.node_id, None);
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let ((mut cr, mut cw, _), (mut sr, mut sw, _), _) = pair().await;
        let f = LinkFrame {
            kind: FrameKind::RegisterInbox,
            body: vec![7; 32],
        };
        cw.send(&f, SizeClass::Small).await.unwrap();
        assert_eq!(sr.recv().await.unwrap(), (SizeClass::Small, f.clone()));
        sw.send(&f, SizeClass::Large).await.unwrap();
        assert_eq!(cr.recv().await.unwrap(), (SizeClass::Large, f));
    }

    #[tokio::test]
    async fn wrong_expected_identity_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = tls_acceptor().unwrap();
            let _ = accept(
                tcp,
                &tls,
                &X25519Secret::generate(),
                &SigningKey::generate(),
            )
            .await;
        });
        let r = connect(addr, &X25519Secret::generate(), None, Some([9; 32])).await;
        assert!(matches!(r, Err(NetError::WrongPeer)));
    }

    #[tokio::test]
    async fn wrong_size_message_is_an_error() {
        let ((_, mut cw, _), (mut sr, _, _), _) = pair().await;
        cw.send_raw(vec![0; 100]).await.unwrap();
        assert!(matches!(
            sr.recv().await,
            Err(NetError::Protocol(CoreError::Malformed))
        ));
    }

    #[test]
    fn rate_limit_bucket() {
        let mut rl = RateLimit::new(10, 3);
        let t0 = Instant::now();
        assert!(rl.allow(t0) && rl.allow(t0) && rl.allow(t0));
        assert!(!rl.allow(t0));
        assert!(rl.allow(t0 + Duration::from_millis(150)));
        assert!(!rl.allow(t0 + Duration::from_millis(160)));
    }
}
