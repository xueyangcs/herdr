//! WebSocket server — runs on the remote machine.
//!
//! Listens on an HTTP port, upgrades connections to WebSocket, authenticates,
//! then bridges the WebSocket byte-stream to the local `herdr-client.sock`.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt as _;
use futures_util::StreamExt as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::Message;

use super::auth;
use super::tls;

/// Configuration for `herdr ws-server`.
#[derive(Debug, Clone, Default)]
pub struct WsServerConfig {
    /// TCP port to listen on (default 8080).
    pub port: u16,
    /// Bearer password for token-style auth; `None` disables password checking.
    pub password: Option<String>,
    /// Enable TLS (wss://). Certificate is auto-generated if paths are None.
    pub tls: bool,
    /// Path to PEM certificate file (optional; auto-generated if absent).
    pub cert_path: Option<PathBuf>,
    /// Path to PEM private key file (optional; auto-generated if absent).
    pub key_path: Option<PathBuf>,
    /// Enable SSH public-key challenge-response auth.
    pub pubkey_auth: bool,
    /// Path to `authorized_keys` file (default: `~/.ssh/authorized_keys`).
    pub authorized_keys: Option<PathBuf>,
}

/// Parse CLI args for `herdr ws-server [options]`.
pub fn parse_args(args: &[String]) -> Result<WsServerConfig, String> {
    let mut cfg = WsServerConfig {
        port: 8080,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let val = args.get(i + 1).ok_or("--port requires a value")?;
                cfg.port = val.parse().map_err(|_| format!("invalid port: {val}"))?;
                i += 2;
            }
            arg if arg.starts_with("--port=") => {
                let val = &arg["--port=".len()..];
                cfg.port = val.parse().map_err(|_| format!("invalid port: {val}"))?;
                i += 1;
            }
            "--password" => {
                cfg.password = Some(
                    args.get(i + 1)
                        .ok_or("--password requires a value")?
                        .clone(),
                );
                i += 2;
            }
            arg if arg.starts_with("--password=") => {
                cfg.password = Some(arg["--password=".len()..].to_string());
                i += 1;
            }
            "--tls" => {
                cfg.tls = true;
                i += 1;
            }
            "--cert" => {
                cfg.cert_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--cert requires a value")?,
                ));
                i += 2;
            }
            "--key" => {
                cfg.key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--key requires a value")?,
                ));
                i += 2;
            }
            "--pubkey-auth" => {
                cfg.pubkey_auth = true;
                i += 1;
            }
            "--authorized-keys" => {
                cfg.authorized_keys = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or("--authorized-keys requires a value")?,
                ));
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(cfg)
}

fn print_help() {
    println!("herdr ws-server — WebSocket gateway for remote herdr clients");
    println!();
    println!("Usage: herdr ws-server [options]");
    println!();
    println!("Behaviour:");
    println!("  Reuses the running herdr session if one exists; otherwise spawns");
    println!("  a headless herdr server in the background before accepting WS clients.");
    println!();
    println!("Options:");
    println!("  --port <port>            TCP port to listen on (default: 8080)");
    println!("  --password <pw>          Require Bearer password on connect");
    println!("  --tls                    Enable TLS (wss://); cert auto-generated");
    println!("  --cert <path>            PEM certificate path (with --tls)");
    println!("  --key  <path>            PEM private key path (with --tls)");
    println!("  --pubkey-auth            Enable SSH public-key challenge-response");
    println!("  --authorized-keys <path> authorized_keys file (default: ~/.ssh/authorized_keys)");
}

/// Entry point for `herdr ws-server`.
pub fn run_ws_server(config: WsServerConfig) -> io::Result<()> {
    // rustls 0.23 requires an explicit crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    preflight_checks(&config)?;
    ensure_herdr_backend()?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

/// Validate configuration before binding so the user gets clear, actionable
/// errors instead of cryptic OS messages mid-flight.
fn preflight_checks(config: &WsServerConfig) -> io::Result<()> {
    // Port range
    if config.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid --port: must be 1-65535",
        ));
    }

    // Port already in use? Probe with a short blocking bind.
    let probe = std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], config.port)));
    match probe {
        Ok(listener) => drop(listener),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "port {} is already in use. Stop the existing process or pass --port <other>.",
                    config.port
                ),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "permission denied binding port {}. Ports below 1024 require root; use --port <≥1024>.",
                    config.port
                ),
            ));
        }
        Err(err) => return Err(err),
    }

    // TLS cert/key consistency
    if !config.tls && (config.cert_path.is_some() || config.key_path.is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--cert/--key require --tls",
        ));
    }
    if let (Some(cert), Some(key)) = (&config.cert_path, &config.key_path) {
        if !cert.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("certificate not found: {}", cert.display()),
            ));
        }
        if !key.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("private key not found: {}", key.display()),
            ));
        }
    }

    // Pubkey-auth needs a usable authorized_keys file
    if config.pubkey_auth {
        let path = config
            .authorized_keys
            .clone()
            .unwrap_or_else(auth::default_authorized_keys);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "--pubkey-auth: authorized_keys not found at {}.\n  \
                     Create it (with the public key of each allowed client) or pass --authorized-keys <path>.",
                    path.display()
                ),
            ));
        }
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "--pubkey-auth: authorized_keys at {} is empty; no client could authenticate.",
                    path.display()
                ),
            ));
        }
    }

    // Encourage at least one auth method when bound to public interfaces.
    if config.password.is_none() && !config.pubkey_auth {
        eprintln!(
            "herdr ws-server: warning: no authentication enabled. \
             Anyone who can reach port {} will get a herdr session. \
             Pass --password <pw> or --pubkey-auth.",
            config.port
        );
    }

    Ok(())
}

/// Ensure a herdr backend (`herdr server`) is running on the same machine so
/// `herdr-client.sock` is ready when WS clients arrive. Reuses the existing
/// server if one is already listening; otherwise spawns one as a daemon.
fn ensure_herdr_backend() -> io::Result<()> {
    use crate::server::{autodetect, headless::client_socket_path};

    let socket_path = client_socket_path();
    if autodetect::is_server_listening() {
        return Ok(());
    }

    eprintln!("herdr ws-server: no herdr backend detected, starting one...");
    autodetect::spawn_server_daemon()?;
    autodetect::wait_for_server_socket(&socket_path, Duration::from_secs(5))?;
    eprintln!(
        "herdr ws-server: herdr backend ready at {}",
        socket_path.display()
    );
    Ok(())
}

async fn serve(config: WsServerConfig) -> io::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;

    let tls_acceptor = if config.tls {
        let (_, acceptor) =
            tls::load_or_generate_tls(config.cert_path.as_deref(), config.key_path.as_deref())?;
        Some(acceptor)
    } else {
        None
    };

    let scheme = if config.tls { "wss" } else { "ws" };
    eprintln!(
        "herdr ws-server listening on {scheme}://0.0.0.0:{}",
        config.port
    );
    if config.password.is_some() {
        eprintln!("  auth: password");
    }
    if config.pubkey_auth {
        let ak = config
            .authorized_keys
            .clone()
            .unwrap_or_else(auth::default_authorized_keys);
        eprintln!("  auth: SSH public key ({})", ak.display());
    }

    let config = Arc::new(config);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let config = Arc::clone(&config);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tcp(tcp, peer, config, tls_acceptor).await {
                eprintln!("herdr ws-server: {peer} connection error: {e}");
            }
        });
    }
}

async fn handle_tcp(
    tcp: TcpStream,
    peer: SocketAddr,
    config: Arc<WsServerConfig>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> io::Result<()> {
    eprintln!("herdr ws-server: connection from {peer}");

    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor.accept(tcp).await?;
        let ws = accept_hdr_async(tls, PasswordCheck(config.password.clone()))
            .await
            .map_err(ws_to_io)?;
        handle_ws(ws, peer, config).await
    } else {
        let ws = accept_hdr_async(tcp, PasswordCheck(config.password.clone()))
            .await
            .map_err(ws_to_io)?;
        handle_ws(ws, peer, config).await
    }
}

async fn handle_ws<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    peer: SocketAddr,
    config: Arc<WsServerConfig>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Phase 4: SSH pubkey challenge-response
    if config.pubkey_auth {
        let authorized_keys = config
            .authorized_keys
            .clone()
            .unwrap_or_else(auth::default_authorized_keys);

        let challenge = auth::make_challenge();
        let nonce = challenge[1..].to_vec();
        ws.send(Message::Binary(challenge.into()))
            .await
            .map_err(ws_to_io)?;

        match ws.next().await {
            Some(Ok(Message::Binary(resp))) => {
                if let Err(e) = auth::verify_auth_response(&resp, &nonce, &authorized_keys) {
                    let fail = vec![auth::MSG_AUTH_FAILED];
                    let _ = ws.send(Message::Binary(fail.into())).await;
                    eprintln!("herdr ws-server: {peer} pubkey auth failed: {e}");
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        e.to_string(),
                    ));
                }
            }
            other => {
                eprintln!("herdr ws-server: {peer} expected auth response, got: {other:?}");
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "no auth response",
                ));
            }
        }

        ws.send(Message::Binary(vec![auth::MSG_AUTH_OK].into()))
            .await
            .map_err(ws_to_io)?;
        eprintln!("herdr ws-server: {peer} pubkey auth succeeded");
    }

    // Connect to local herdr-client.sock and bridge bytes
    let socket_path = crate::server::headless::client_socket_path();
    let unix = tokio::net::UnixStream::connect(&socket_path)
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to connect to {}: {e}", socket_path.display()),
            )
        })?;
    eprintln!("herdr ws-server: {peer} authenticated — bridging to herdr-client.sock");

    bridge_ws_unix(ws, unix).await
}

/// Bridge WebSocket binary frames ↔ Unix socket byte-stream.
async fn bridge_ws_unix<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    unix: tokio::net::UnixStream,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut unix_read, mut unix_write) = tokio::io::split(unix);

    // unix → ws: read Unix bytes, send as WS binary frames
    let unix_to_ws = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = unix_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_sink
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .map_err(ws_to_io)?;
        }
        ws_sink.close().await.map_err(ws_to_io)?;
        Ok::<(), io::Error>(())
    };

    // ws → unix: receive WS binary frames, write raw bytes to Unix socket
    let ws_to_unix = async {
        while let Some(msg) = ws_stream.next().await {
            match msg.map_err(ws_to_io)? {
                Message::Binary(data) => {
                    unix_write.write_all(&data).await?;
                }
                Message::Close(_) => break,
                // Ping/Pong are handled automatically by tokio-tungstenite
                _ => {}
            }
        }
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        r = unix_to_ws => r,
        r = ws_to_unix => r,
    }
}

// ---------------------------------------------------------------------------
// Password auth callback for the WS HTTP upgrade
// ---------------------------------------------------------------------------

struct PasswordCheck(Option<String>);

impl Callback for PasswordCheck {
    fn on_request(self, req: &Request, resp: Response) -> Result<Response, ErrorResponse> {
        if let Some(expected) = self.0 {
            let ok = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    // Accept either "Bearer <pw>" or the raw password for ergonomics.
                    v.eq_ignore_ascii_case(&format!("Bearer {expected}")) || v == expected
                })
                .unwrap_or(false);
            if !ok {
                let err: ErrorResponse = http::Response::builder()
                    .status(401)
                    .body(Some(
                        "Unauthorized: invalid or missing password".to_string(),
                    ))
                    .unwrap_or_else(|_| http::Response::new(None));
                return Err(err);
            }
        }
        Ok(resp)
    }
}

fn ws_to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
}
