//! WebSocket client bridge — runs locally as a subprocess.
//!
//! Spawned by `remote.rs` instead of `ssh -T …`. Connects to the remote
//! `herdr ws-server`, authenticates, then bridges its own stdin/stdout to the
//! WebSocket byte-stream.  The parent process connects to the local bridge
//! Unix socket and copies bytes over, exactly as it does with SSH today.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::SinkExt as _;
use futures_util::StreamExt as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;

use super::auth;
use super::tls;

/// Configuration for `herdr ws-client-bridge <url> [options]`.
#[derive(Debug, Clone)]
pub struct WsBridgeConfig {
    /// WebSocket URL: `ws://…` or `wss://…`.
    pub url: String,
    /// Bearer password (`Authorization: Bearer <password>`).
    pub password: Option<String>,
    /// Expected TLS cert SHA-256 fingerprint, formatted as `SHA256:<base64>`.
    pub fingerprint: Option<String>,
    /// SSH private key path for public-key auth.
    pub identity_file: Option<PathBuf>,
}

/// Parse CLI args for `herdr ws-client-bridge <url> [options]`.
pub fn parse_args(args: &[String]) -> Result<WsBridgeConfig, String> {
    let url = args
        .first()
        .ok_or("ws-client-bridge requires a URL argument")?
        .clone();
    let mut cfg = WsBridgeConfig {
        url,
        password: None,
        fingerprint: None,
        identity_file: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
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
            "--fingerprint" => {
                cfg.fingerprint = Some(
                    args.get(i + 1)
                        .ok_or("--fingerprint requires a value")?
                        .clone(),
                );
                i += 2;
            }
            arg if arg.starts_with("--fingerprint=") => {
                cfg.fingerprint = Some(arg["--fingerprint=".len()..].to_string());
                i += 1;
            }
            "--identity" | "-i" => {
                cfg.identity_file = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--identity requires a value")?,
                ));
                i += 2;
            }
            "--pubkey-auth" => {
                // presence implies identity auto-detection; no-op here
                i += 1;
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
    println!("herdr ws-client-bridge — internal WebSocket bridge subprocess");
    println!();
    println!("Usage: herdr ws-client-bridge <url> [options]");
    println!();
    println!("Options:");
    println!("  --password <pw>        Bearer password for auth");
    println!("  --fingerprint <fp>     Expected TLS cert fingerprint (SHA256:...)");
    println!("  --identity <path>      SSH private key for pubkey auth");
}

/// Entry point for `herdr ws-client-bridge`.
pub fn run_ws_client_bridge(config: WsBridgeConfig) -> io::Result<()> {
    // rustls 0.23 requires an explicit crypto provider for wss:// connections.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_bridge(config))
}

async fn run_bridge(config: WsBridgeConfig) -> io::Result<()> {
    let is_tls = config.url.starts_with("wss://") || config.url.starts_with("https://");

    // Build the HTTP upgrade request with optional auth header
    let mut request =
        config.url.as_str().into_client_request().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL: {e}"))
        })?;

    if let Some(password) = &config.password {
        let val = format!("Bearer {password}").parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("password header: {e}"))
        })?;
        request.headers_mut().insert("authorization", val);
    }

    let ws = if is_tls {
        connect_tls(request, &config).await?
    } else {
        connect_plain(request, &config).await?
    };

    debug!("WebSocket connected to {}", config.url);
    bridge_stdio(ws, &config).await
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_plain(
    request: impl IntoClientRequest + Unpin,
    _config: &WsBridgeConfig,
) -> io::Result<WsStream> {
    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused, format!("WS connect: {e}"))
        })?;
    Ok(ws)
}

async fn connect_tls(
    request: impl IntoClientRequest + Unpin,
    config: &WsBridgeConfig,
) -> io::Result<WsStream> {
    let map_tls_err = |e: tokio_tungstenite::tungstenite::Error| {
        let msg = e.to_string();
        // Give a clear hint when the server is likely running without TLS.
        let hint = if msg.contains("InvalidContentType") || msg.contains("corrupt") {
            " (hint: server may not have TLS enabled — use ws:// instead of wss://)"
        } else {
            ""
        };
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("wss:// connect failed: {e}{hint}"),
        )
    };

    if let Some(fp_str) = &config.fingerprint {
        // Custom TLS: skip chain validation, pin by SHA-256 fingerprint.
        let fp = tls::parse_fingerprint(fp_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(tls::FingerprintVerifier::new(fp)))
            .with_no_client_auth();

        let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(map_tls_err)?;
        Ok(ws)
    } else {
        // Standard TLS: validate with system certificate roots.
        let (ws, _) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(map_tls_err)?;
        Ok(ws)
    }
}

async fn bridge_stdio(mut ws: WsStream, config: &WsBridgeConfig) -> io::Result<()> {
    // Phase 4: SSH pubkey challenge-response
    let need_pubkey_auth = config.identity_file.is_some();
    if need_pubkey_auth {
        let identity = resolve_identity(config)?;
        perform_pubkey_auth(&mut ws, &identity).await?;
    }

    // Now bridge stdin/stdout ↔ WebSocket
    let (mut ws_sink, mut ws_stream) = ws.split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let stdin_to_ws = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_sink
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("ws send: {e}")))?;
        }
        let _ = ws_sink.close().await;
        Ok::<(), io::Error>(())
    };

    let ws_to_stdout = async {
        while let Some(msg) = ws_stream.next().await {
            match msg.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))? {
                Message::Binary(data) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        r = stdin_to_ws => r,
        r = ws_to_stdout => r,
    }
}

async fn perform_pubkey_auth(ws: &mut WsStream, identity: &std::path::Path) -> io::Result<()> {
    // Receive challenge
    let challenge = match ws.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("expected pubkey challenge, got: {:?}", other),
            ));
        }
    };

    // Sign and send response
    let response = auth::sign_challenge(&challenge, identity)?;
    ws.send(Message::Binary(response.into()))
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("send auth response: {e}"),
            )
        })?;

    // Receive auth result
    match ws.next().await {
        Some(Ok(Message::Binary(data))) if data.first() == Some(&auth::MSG_AUTH_OK) => {
            debug!("pubkey auth succeeded");
            Ok(())
        }
        Some(Ok(Message::Binary(data))) if data.first() == Some(&auth::MSG_AUTH_FAILED) => {
            let msg = String::from_utf8_lossy(data.get(1..).unwrap_or_default());
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("auth failed: {msg}"),
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("unexpected auth result: {:?}", other),
        )),
    }
}

fn resolve_identity(config: &WsBridgeConfig) -> io::Result<PathBuf> {
    if let Some(path) = &config.identity_file {
        if path.exists() {
            return Ok(path.clone());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("identity file not found: {}", path.display()),
        ));
    }
    // Auto-detect
    for path in auth::default_identity_files() {
        if path.exists() {
            debug!("using identity file: {}", path.display());
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no SSH private key found; use --ws-identity to specify one",
    ))
}
