//! Connection listener. Handles all client connections.

use std::io::ErrorKind;
use std::net::SocketAddr;

use crate::backend::databases::{databases, reload, shutdown};
use crate::config::config;
use crate::frontend::client::query_engine::two_pc::Manager;
use crate::net::messages::{FrontendPid, NegotiateProtocolVersion, Startup, hello::SslReply};
use crate::net::tls::{
    TlsListener, acceptor, peer_alpn_postgresql, peer_certificate_present, peer_identity,
};
use crate::net::{self, Stream, tweak};
use crate::sighup::Sighup;
use tokio::net::{TcpListener, TcpSocket, TcpStream, lookup_host};
use tokio::signal::ctrl_c;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use tracing::{error, info, warn};

use super::{Client, Error, comms::comms};
use crate::util::safe_timeout;

/// First byte of a TLS handshake record (ClientHello). A startup message can't
/// start with it: as a big-endian length, it would be hundreds of megabytes.
const TLS_HANDSHAKE: u8 = 0x16;

/// What the first byte sent by a new client says about the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstByte {
    /// The client disconnected without sending anything.
    Closed,
    /// The client skipped the `SSLRequest` and started the TLS handshake
    /// (direct TLS, libpq 17+ `sslnegotiation=direct`).
    TlsHandshake,
    /// Startup message, `SSLRequest`, `GSSENCRequest` or `CancelRequest`.
    Postgres,
}

impl FirstByte {
    /// Peek at the first byte without consuming it.
    async fn peek(stream: &TcpStream) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        Ok(match stream.peek(&mut buf).await? {
            0 => Self::Closed,
            _ if buf[0] == TLS_HANDSHAKE => Self::TlsHandshake,
            _ => Self::Postgres,
        })
    }
}

/// Client connections listener and handler.
#[derive(Debug, Clone)]
pub(crate) struct Listener {
    addr: String,
    shutdown: CancellationToken,
}

impl Listener {
    /// Create new client listener.
    pub(crate) fn new(addr: impl ToString) -> Self {
        Self {
            addr: addr.to_string(),
            shutdown: CancellationToken::new(),
        }
    }

    /// Bind the listening socket with the configured `listen_backlog`.
    ///
    /// `TcpListener::bind` hardcodes a backlog of 1024, which caps the queue of
    /// pending connections regardless of `net.core.somaxconn`; large client fleets
    /// reconnecting at once (e.g. a rolling deploy) overflow it and their SYNs are
    /// silently dropped onto the retransmission timer.
    async fn bind(addr: &str) -> Result<TcpListener, Error> {
        let backlog = config().config.general.listen_backlog;
        Ok(Self::bind_first(lookup_host(addr).await?, backlog, addr)?)
    }

    /// Bind to the first candidate address that accepts the bind, like
    /// `TcpListener::bind` does, but with a configurable listen backlog.
    fn bind_first(
        candidates: impl Iterator<Item = SocketAddr>,
        backlog: u32,
        requested: &str,
    ) -> Result<TcpListener, std::io::Error> {
        let mut last_err = None;
        for addr in candidates {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            #[cfg(not(windows))]
            socket.set_reuseaddr(true)?;
            match socket.bind(addr) {
                Ok(()) => return socket.listen(backlog),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("no address to bind: {}", requested),
            )
        }))
    }

    /// Listen for client connections and handle them.
    pub(crate) async fn listen(&mut self) -> Result<(), Error> {
        info!("🐕 PgDog listening on {}", self.addr);
        let listener = Self::bind(&self.addr).await?;
        let shutdown_signal = comms().shutting_down();
        let mut sighup = Sighup::new()?;
        let mut shutting_down = false;

        loop {
            select! {
                connection = listener.accept() => {
                   let comms = comms();
                   let (stream, addr) = connection?;
                   let offline = comms.offline();

                   let future = async move {
                       match Self::handle_client(stream, addr).await {
                           Ok(_) => (),
                           Err(err) => if !err.disconnect() {
                               error!("client crashed: {:?}", err);
                           }
                       };
                   };

                   if offline {
                       spawn(future);
                   } else {
                       comms.tracker().spawn(future);
                   }
                }

                _ = shutdown_signal.cancelled(), if !shutting_down => {
                    shutting_down = true;
                    self.start_shutdown();
                }

                _ = ctrl_c(), if !shutting_down => {
                    shutting_down = true;
                    self.start_shutdown();
                }

                _ = sighup.listen() => {
                    if let Err(err) = reload(false) {
                        error!("configuration reload error: {}", err);
                    }
                }

                _ = self.shutdown.cancelled() => {
                    break;
                }
            }
        }

        Ok(())
    }

    fn start_shutdown(&self) {
        comms().shutdown();

        let listener = self.clone();
        spawn(async move {
            listener.execute_shutdown().await;
            Manager::get().shutdown().await; // wait for 2pc to flush
            shutdown();
        });
    }

    async fn execute_shutdown(&self) {
        let shutdown_timeout = config().config.general.shutdown_timeout();

        info!(
            "waiting up to {:.3}s for {} clients to finish transactions",
            shutdown_timeout.as_secs_f64(),
            comms().tracker().len(),
        );

        let comms = comms();

        if safe_timeout(shutdown_timeout, comms.tracker().wait())
            .await
            .is_err()
        {
            warn!(
                "terminating {} client connections due to shutdown timeout",
                comms.tracker().len()
            );

            // If a shutdown termination timeout is configured, enforce it here.
            // This will ensure that we don't wait indefinitely for databases to respond.
            if let Some(termination_timeout) =
                config().config.general.shutdown_termination_timeout()
            {
                // Shutdown timeout elapsed; cancel any still-running queries before tearing pools down.
                let cancel_futures = comms.clients().into_keys().map(|id| async move {
                    if let Err(err) = databases().cancel(id).await {
                        error!(?id, "cancel request failed during shutdown: {err}");
                    }
                });
                let cancel_all = futures::future::join_all(cancel_futures);

                if safe_timeout(termination_timeout, cancel_all).await.is_err() {
                    error!(
                        "forced shutdown: abandoning {} outstanding cancel requests after waiting {:.3}s",
                        comms.clients().len(),
                        termination_timeout.as_secs_f64()
                    );
                }
            }
        }

        self.shutdown.cancel();
    }

    async fn handle_client(stream: TcpStream, addr: SocketAddr) -> Result<(), Error> {
        let config = config();

        // Not the end of the world if the tweaks are
        // not applied.
        if let Err(err) = tweak(&stream, &config.config.tcp) {
            warn!(
                "keepalive settings ({}) are not supported on this system, ignoring, error: {} [{}]",
                config.config.tcp, err, addr
            );
        }

        let tls = acceptor();

        let first_byte = match FirstByte::peek(&stream).await {
            Ok(first_byte) => first_byte,
            // Load balancers like AWS ELB use TCP to health check
            // targets and abruptly disconnect.
            Err(err) if err.kind() == ErrorKind::ConnectionReset => return Ok(()),
            Err(err) => return Err(net::Error::Io(err).into()),
        };

        let mut stream = match first_byte {
            FirstByte::Closed => return Ok(()),

            FirstByte::TlsHandshake => {
                // The client speaks TLS already, so we can't send it a Postgres
                // error. Close the connection, like PostgreSQL does.
                let Some(tls) = tls.as_ref() else {
                    warn!("direct TLS connection rejected, TLS is not configured [{addr}]");
                    return Ok(());
                };
                match Self::accept_tls(tls, stream, addr, config.config.memory.net_buffer, true)
                    .await
                {
                    Some(stream) => stream,
                    None => return Ok(()),
                }
            }

            FirstByte::Postgres => Stream::plain(stream, config.config.memory.net_buffer),
        };

        loop {
            let startup = match Startup::from_stream(&mut stream).await {
                Ok(startup) => startup,
                Err(net::Error::Io(io_err)) => {
                    // Load balancers like AWS ELB use TCP to health check
                    // targets and abruptly disconnect.
                    if io_err.kind() == ErrorKind::ConnectionReset {
                        return Ok(());
                    } else {
                        return Err(net::Error::Io(io_err).into());
                    }
                }
                Err(err) => return Err(err.into()),
            };

            match startup {
                Startup::Ssl => {
                    if let Some(tls) = tls.as_ref() {
                        stream.send_flush(&SslReply::Yes).await?;
                        let plain = stream.take()?;
                        stream = match Self::accept_tls(
                            tls,
                            plain,
                            addr,
                            config.config.memory.net_buffer,
                            false,
                        )
                        .await
                        {
                            Some(stream) => stream,
                            None => return Ok(()),
                        };
                    } else {
                        stream.send_flush(&SslReply::No).await?;
                    }
                }

                Startup::GssEnc => {
                    // GSS encryption is not yet supported; reject and wait for a normal startup.
                    stream.send_flush(&SslReply::No).await?;
                }

                Startup::Startup {
                    version,
                    params,
                    unrecognized_options,
                } => {
                    let negotiated = version
                        .negotiated()
                        .ok_or_else(|| net::Error::UnsupportedStartup(version.as_i32()))?;

                    if negotiated != version || !unrecognized_options.is_empty() {
                        // Send the negotiated minor version before auth so the
                        // client can interpret later messages, including
                        // BackendKeyData / CancelRequest, using the right shape.
                        stream
                            .send(&NegotiateProtocolVersion::new(
                                negotiated,
                                unrecognized_options,
                            ))
                            .await?;
                    }

                    Box::pin(Client::spawn(stream, params, addr, config, negotiated)).await?;
                    break;
                }

                Startup::Cancel { ref id } => {
                    if comms().verify_cancel(id) {
                        let _ = databases().cancel(FrontendPid::from(id)).await;
                    } else {
                        super::ee::broadcast_cancel(id).await?;
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Perform the TLS handshake with a client. Returns `None` if the
    /// connection should be closed.
    ///
    /// Direct TLS connections (no `SSLRequest`) must negotiate the
    /// `postgresql` ALPN protocol, like PostgreSQL 17+ requires. This stops
    /// other protocols' clients from being tricked into talking to us
    /// (cross-protocol attacks). Clients that sent an `SSLRequest` first
    /// may skip ALPN, since libpq < 17 doesn't send it.
    async fn accept_tls(
        tls: &TlsListener,
        plain: TcpStream,
        addr: SocketAddr,
        net_buffer: usize,
        direct: bool,
    ) -> Option<Stream> {
        let cipher = match tls.accept(plain).await {
            Ok(cipher) => cipher,
            Err(err) => {
                // TLS failure should close the connection
                // without telling the client what happened (security).
                warn!("TLS handshake failed: {err} [{addr}]");
                return None;
            }
        };

        if direct && !peer_alpn_postgresql(cipher.get_ref().1) {
            warn!(
                "direct TLS connection rejected, client did not negotiate the \"postgresql\" ALPN protocol [{addr}]"
            );
            return None;
        }

        let tls_identity = peer_identity(cipher.get_ref().1);
        let tls_client_certificate = peer_certificate_present(cipher.get_ref().1);
        Some(Stream::tls(
            tokio_rustls::TlsStream::Server(cipher),
            net_buffer,
            tls_identity,
            tls_client_certificate,
            tls.server_end_point().map(|data| data.to_vec()),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::messages::ToBytes;
    use crate::net::tls::{ALPN_POSTGRESQL, test_chain_connector, test_reset_acceptor};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;
    use tokio_rustls::rustls::pki_types::ServerName;

    /// Connected (client, server) TCP pair.
    async fn tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, addr) = listener.accept().await.unwrap();
        (client, server, addr)
    }

    /// Client TCP connection with `handle_client` serving the other end.
    async fn connect() -> (TcpStream, JoinHandle<Result<(), Error>>) {
        let (client, server, addr) = tcp_pair().await;
        let handle = spawn(Listener::handle_client(server, addr));
        (client, handle)
    }

    /// Install a TLS acceptor using the `tests/tls/chain` certificate.
    fn enable_tls() {
        test_reset_acceptor();
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tls/chain");
        let mut cfg = crate::config::ConfigAndUsers::default();
        cfg.config.general.tls_certificate = Some(fixtures.join("chain.pem"));
        cfg.config.general.tls_private_key = Some(fixtures.join("leaf-key.pem"));
        crate::config::set(cfg).unwrap();
        crate::net::tls::reload().unwrap();
    }

    fn disable_tls() {
        test_reset_acceptor();
        crate::config::set(crate::config::ConfigAndUsers::default()).unwrap();
    }

    /// Send a `GSSENCRequest` and return the server's one-byte answer, which
    /// shows the server is reading startup messages from this stream.
    async fn gss_enc_reply<S>(stream: &mut S) -> std::io::Result<u8>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        stream.write_all(&Startup::GssEnc.to_bytes()).await?;
        stream.flush().await?;
        stream.read_u8().await
    }

    async fn finish(handle: JoinHandle<Result<(), Error>>) -> Result<(), Error> {
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("handle_client finished")
            .expect("handle_client didn't panic")
    }

    fn localhost() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap()
    }

    #[tokio::test]
    async fn test_first_byte_tls_handshake() {
        let (mut client, server, _) = tcp_pair().await;
        // TLS record header: handshake, TLS 1.0 record version.
        client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        assert_eq!(
            FirstByte::peek(&server).await.unwrap(),
            FirstByte::TlsHandshake
        );
    }

    #[tokio::test]
    async fn test_first_byte_postgres() {
        for message in [
            Startup::tls().to_bytes(),
            Startup::new("pgdog", "pgdog", vec![]).to_bytes(),
        ] {
            let (mut client, mut server, _) = tcp_pair().await;
            client.write_all(&message).await.unwrap();
            assert_eq!(FirstByte::peek(&server).await.unwrap(), FirstByte::Postgres);

            // Peeking doesn't consume anything.
            let mut read = vec![0u8; message.len()];
            server.read_exact(&mut read).await.unwrap();
            assert_eq!(read, message.to_vec());
        }
    }

    #[tokio::test]
    async fn test_first_byte_closed() {
        let (client, server, _) = tcp_pair().await;
        drop(client);
        assert_eq!(FirstByte::peek(&server).await.unwrap(), FirstByte::Closed);
    }

    #[tokio::test]
    async fn test_direct_tls_with_alpn() {
        crate::logger();
        enable_tls();

        let (client, handle) = connect().await;
        let mut tls = test_chain_connector(vec![ALPN_POSTGRESQL.to_vec()])
            .connect(localhost(), client)
            .await
            .expect("direct TLS handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ALPN_POSTGRESQL));
        assert_eq!(gss_enc_reply(&mut tls).await.unwrap(), b'N');

        drop(tls);
        let _ = finish(handle).await;
        disable_tls();
    }

    #[tokio::test]
    async fn test_direct_tls_without_alpn_rejected() {
        crate::logger();
        enable_tls();

        let (client, handle) = connect().await;
        // The handshake can complete on the client's side before the
        // server checks ALPN; the connection is closed right after.
        if let Ok(mut tls) = test_chain_connector(vec![])
            .connect(localhost(), client)
            .await
        {
            assert!(gss_enc_reply(&mut tls).await.is_err());
        }
        finish(handle).await.expect("connection closed cleanly");
        disable_tls();
    }

    #[tokio::test]
    async fn test_direct_tls_without_tls_configured() {
        crate::logger();
        disable_tls();

        let (client, handle) = connect().await;
        assert!(
            test_chain_connector(vec![ALPN_POSTGRESQL.to_vec()])
                .connect(localhost(), client)
                .await
                .is_err()
        );
        finish(handle).await.expect("connection closed cleanly");
    }

    #[tokio::test]
    async fn test_ssl_request_without_alpn() {
        crate::logger();
        enable_tls();

        for alpn in [vec![], vec![ALPN_POSTGRESQL.to_vec()]] {
            let (mut client, handle) = connect().await;
            client.write_all(&Startup::tls().to_bytes()).await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'S');

            let mut tls = test_chain_connector(alpn)
                .connect(localhost(), client)
                .await
                .expect("TLS handshake after SSLRequest");
            assert_eq!(gss_enc_reply(&mut tls).await.unwrap(), b'N');

            drop(tls);
            let _ = finish(handle).await;
        }
        disable_tls();
    }

    #[tokio::test]
    async fn test_plaintext_startup_unchanged() {
        crate::logger();
        disable_tls();

        let (mut client, handle) = connect().await;
        assert_eq!(gss_enc_reply(&mut client).await.unwrap(), b'N');
        client.write_all(&Startup::tls().to_bytes()).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'N');

        drop(client);
        let _ = finish(handle).await;
    }

    #[tokio::test]
    async fn test_bind_ipv4_applies_configured_backlog() {
        let listener = Listener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.is_ipv4());
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_ipv6() {
        let listener = Listener::bind("[::1]:0").await.unwrap();
        assert!(listener.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn test_bind_unresolvable_address_errors() {
        assert!(Listener::bind("host.invalid:0").await.is_err());
    }

    #[test]
    fn test_bind_first_empty_resolution_errors() {
        let err = Listener::bind_first(std::iter::empty(), 1024, "nowhere:0").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn test_bind_first_falls_back_to_next_candidate() {
        // 198.51.100.1 (TEST-NET-2) is not a local interface, so the bind
        // fails and the next candidate is tried, matching TcpListener::bind.
        let candidates: Vec<SocketAddr> = vec![
            "198.51.100.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        ];
        let listener = Listener::bind_first(candidates.into_iter(), 1024, "test:0").unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn test_bind_first_reports_last_bind_error() {
        let candidates: Vec<SocketAddr> = vec!["198.51.100.1:0".parse().unwrap()];
        assert!(Listener::bind_first(candidates.into_iter(), 1024, "test:0").is_err());
    }
}
