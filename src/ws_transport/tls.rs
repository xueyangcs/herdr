//! TLS certificate management for the WebSocket transport.
//!
//! On first `herdr ws-server --tls` run, generates a self-signed ECDSA cert and
//! stores it at `~/.config/herdr/ws-tls-cert.pem` + `~/.config/herdr/ws-tls-key.pem`.
//! Prints the SHA-256 DER fingerprint as `SHA256:<base64>` for the client to pin.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

use base64::Engine as _;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Fingerprint of a TLS certificate as `SHA256:<base64>`.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Build a rustls `ServerName` for a URL host (DNS name or IP literal).
pub fn server_name_from_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid TLS server name: {host}"))
}

/// Parse a `SHA256:<base64>` fingerprint string into raw bytes.
pub fn parse_fingerprint(fp: &str) -> Result<[u8; 32], String> {
    let b64 = fp
        .strip_prefix("SHA256:")
        .ok_or_else(|| format!("fingerprint must start with 'SHA256:', got: {fp}"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("fingerprint base64 decode error: {e}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("fingerprint must be 32 bytes (SHA-256), got {len} bytes"))
}

fn default_cert_dir() -> PathBuf {
    let home = dirs_or_home();
    home.join(".config").join("herdr")
}

fn dirs_or_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn default_cert_path() -> PathBuf {
    default_cert_dir().join("ws-tls-cert.pem")
}

pub fn default_key_path() -> PathBuf {
    default_cert_dir().join("ws-tls-key.pem")
}

/// Ensure a self-signed TLS cert and key pair exist at the default paths.
/// Returns the SHA-256 fingerprint of the certificate, ready to be displayed
/// to the user. Used by the Settings UI so we can show the connection
/// command without binding sockets.
pub fn ensure_default_cert_and_read_fingerprint() -> io::Result<String> {
    let cert_path = default_cert_path();
    let key_path = default_key_path();
    if !cert_path.exists() || !key_path.exists() {
        generate_and_save(&cert_path, &key_path)?;
    }
    let cert_pem = fs::read(&cert_path)?;
    let first_cert_der: Vec<u8> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no certificate in PEM"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cert parse: {e}")))?
        .as_ref()
        .to_vec();
    Ok(cert_fingerprint(&first_cert_der))
}

/// Load or generate a self-signed TLS cert.
/// Returns `(cert_der_bytes, tls_acceptor)` and prints the fingerprint to stderr.
pub fn load_or_generate_tls(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> io::Result<(Vec<u8>, TlsAcceptor)> {
    let cert_path = cert_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_cert_path);
    let key_path = key_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_key_path);

    // Generate if either file is missing
    if !cert_path.exists() || !key_path.exists() {
        generate_and_save(&cert_path, &key_path)?;
    }

    load_tls_from_files(&cert_path, &key_path)
}

fn generate_and_save(cert_path: &Path, key_path: &Path) -> io::Result<()> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Include localhost + loopback IP so clients can use hostnames or 127.0.0.1.
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![
            "herdr-ws".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .map_err(|e| io::Error::other(format!("cert generation failed: {e}")))?;

    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, signing_key.serialize_pem())?;
    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated self-signed TLS certificate"
    );
    Ok(())
}

fn load_tls_from_files(cert_path: &Path, key_path: &Path) -> io::Result<(Vec<u8>, TlsAcceptor)> {
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("cert parse error: {e}"))
        })?;

    let first_cert_der = certs
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no certificates in PEM file"))?
        .as_ref()
        .to_vec();

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key parse error: {e}")))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in PEM file"))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("TLS config error: {e}"))
        })?;

    let fingerprint = cert_fingerprint(&first_cert_der);
    eprintln!("  TLS fingerprint: {fingerprint}");
    eprintln!("  Pass to client:  --fingerprint {fingerprint}");

    Ok((first_cert_der, TlsAcceptor::from(Arc::new(server_config))))
}

// ---------------------------------------------------------------------------
// Client-side: custom verifier that pins by SHA-256 fingerprint
// ---------------------------------------------------------------------------

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Rustls `ServerCertVerifier` that accepts any cert whose SHA-256 DER
/// fingerprint matches the pinned value. Chain validation is skipped.
#[derive(Debug)]
pub struct FingerprintVerifier {
    expected: [u8; 32],
}

impl FingerprintVerifier {
    pub fn new(expected: [u8; 32]) -> Self {
        Self { expected }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "TLS certificate fingerprint mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
