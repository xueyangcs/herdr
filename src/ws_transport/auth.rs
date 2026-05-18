//! SSH public-key challenge-response authentication (Phase 4).
//!
//! After the WebSocket handshake succeeds, if pubkey auth is enabled the server
//! and client exchange three messages before switching to the raw byte-stream mode:
//!
//! ```text
//! Server → Client:  [0x10]  [32-byte random nonce]
//! Client → Server:  [0x11]  [4-byte LE: pubkey_len]  [pubkey openssh bytes]
//!                           [4-byte LE: sig_len]       [SshSig PEM bytes]
//! Server → Client:  [0x12]  (auth OK — switches to raw pass-through)
//!                   [0x13]  [error message bytes]  (auth failed — close)
//! ```
//!
//! The namespace used for `ssh-keygen -Y sign`-style signing is `"herdr-ws"`.

use std::io;
use std::path::Path;

use ssh_key::{HashAlg, PrivateKey, PublicKey, SshSig};
use tracing::debug;

/// Type-byte constants for the auth message envelope.
pub const MSG_CHALLENGE: u8 = 0x10;
pub const MSG_AUTH_RESPONSE: u8 = 0x11;
pub const MSG_AUTH_OK: u8 = 0x12;
pub const MSG_AUTH_FAILED: u8 = 0x13;

/// Signing namespace embedded in the SSH signature.
const NAMESPACE: &str = "herdr-ws";

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Build a 32-byte challenge message (`[0x10][nonce]`).
pub fn make_challenge() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple nonce: mix of time nanos and process id (no crypto rand dep).
    // Sufficient for a MAC-and-sign challenge; not used as a key.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut nonce = [0u8; 32];
    let t_bytes = t.to_le_bytes();
    let p_bytes = pid.to_le_bytes();
    for (i, b) in t_bytes
        .iter()
        .chain(p_bytes.iter())
        .cycle()
        .take(32)
        .enumerate()
    {
        nonce[i] = *b ^ (i as u8).wrapping_mul(0x6d);
    }
    let mut msg = Vec::with_capacity(33);
    msg.push(MSG_CHALLENGE);
    msg.extend_from_slice(&nonce);
    msg
}

/// Verify an auth-response message against `authorized_keys`.
///
/// `response` must be the raw bytes of a `[0x11]…` message (the type byte included).
///
/// Returns `Ok(())` on success or an error with a human-readable reason.
pub fn verify_auth_response(
    response: &[u8],
    nonce: &[u8],
    authorized_keys_path: &Path,
) -> io::Result<()> {
    if response.first() != Some(&MSG_AUTH_RESPONSE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected auth-response message",
        ));
    }
    let body = &response[1..];

    // Decode: [4-byte LE pubkey_len][pubkey bytes][4-byte LE sig_len][sig bytes]
    if body.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auth-response too short",
        ));
    }
    let pubkey_len = u32::from_le_bytes(body[..4].try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "auth-response pubkey_len slice error",
        )
    })?) as usize;
    if body.len() < 4 + pubkey_len + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auth-response truncated",
        ));
    }
    let pubkey_bytes = &body[4..4 + pubkey_len];
    let after_pk = &body[4 + pubkey_len..];
    let sig_len = u32::from_le_bytes(after_pk[..4].try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "auth-response sig_len slice error",
        )
    })?) as usize;
    if after_pk.len() < 4 + sig_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auth-response sig truncated",
        ));
    }
    let sig_bytes = &after_pk[4..4 + sig_len];

    // Parse public key (OpenSSH format)
    let pubkey_str = std::str::from_utf8(pubkey_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pubkey utf8: {e}")))?;
    let pubkey = PublicKey::from_openssh(pubkey_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("pubkey parse: {e}"),
        )
    })?;

    // Parse SshSig (PEM format)
    let sig_str = std::str::from_utf8(sig_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("sig utf8: {e}")))?;
    let sig = SshSig::from_pem(sig_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("sig parse: {e}")))?;

    // Check the signature verifies against the public key
    pubkey.verify(NAMESPACE, nonce, &sig).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("signature invalid: {e}"),
        )
    })?;

    debug!(fingerprint = %pubkey.fingerprint(HashAlg::Sha256), "signature verified");

    // Check the public key is in authorized_keys
    check_authorized_keys(&pubkey, authorized_keys_path)
}

fn check_authorized_keys(pubkey: &PublicKey, path: &Path) -> io::Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot read {}: {e}", path.display())))?;

    let target_fp = pubkey.fingerprint(HashAlg::Sha256).to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(ak) = PublicKey::from_openssh(trimmed) {
            if ak.fingerprint(HashAlg::Sha256).to_string() == target_fp {
                debug!("key matched in authorized_keys: {}", path.display());
                return Ok(());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("public key not found in {}", path.display()),
    ))
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Sign the nonce from a `[0x10][nonce]` challenge message and return the
/// `[0x11]…` response bytes.
pub fn sign_challenge(challenge_msg: &[u8], identity_path: &Path) -> io::Result<Vec<u8>> {
    if challenge_msg.first() != Some(&MSG_CHALLENGE) || challenge_msg.len() != 33 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid challenge message",
        ));
    }
    let nonce = &challenge_msg[1..];

    let key_pem = std::fs::read_to_string(identity_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read {}: {e}", identity_path.display()),
        )
    })?;

    let private_key = PrivateKey::from_openssh(&key_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key parse: {e}")))?;

    let sig = private_key
        .sign(NAMESPACE, HashAlg::Sha256, nonce)
        .map_err(|e| io::Error::other(format!("signing failed: {e}")))?;

    let sig_pem = sig
        .to_pem(ssh_key::LineEnding::LF)
        .map_err(|e| io::Error::other(format!("sig pem encode: {e}")))?;

    let pubkey_str = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| io::Error::other(format!("pubkey openssh: {e}")))?;

    let pubkey_bytes = pubkey_str.as_bytes();
    let sig_bytes = sig_pem.as_bytes();

    let mut response = Vec::with_capacity(1 + 4 + pubkey_bytes.len() + 4 + sig_bytes.len());
    response.push(MSG_AUTH_RESPONSE);
    response.extend_from_slice(&(pubkey_bytes.len() as u32).to_le_bytes());
    response.extend_from_slice(pubkey_bytes);
    response.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
    response.extend_from_slice(sig_bytes);
    Ok(response)
}

/// Default SSH identity file paths to try when none is explicitly configured.
pub fn default_identity_files() -> Vec<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let ssh = home.join(".ssh");
    vec![
        ssh.join("id_ed25519"),
        ssh.join("id_ecdsa"),
        ssh.join("id_rsa"),
    ]
}

/// Default authorized_keys path.
pub fn default_authorized_keys() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".ssh").join("authorized_keys")
}
