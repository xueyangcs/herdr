//! WebSocket-based remote transport for herdr.
//!
//! Enables `herdr --remote ws://host:8080` and `herdr --remote wss://host:8080`
//! as an alternative to the SSH stdio bridge when port 22 is unreachable.
//!
//! Architecture:
//! ```text
//! [local herdr UI]
//!     ↓ Unix socket (local bridge path)
//! [WsStdioBridge - runs in remote.rs]
//!     ↓ subprocess stdio
//! [herdr ws-client-bridge <url> ...]   ← LOCAL subprocess
//!     ↓ WebSocket (ws:// or wss://)
//! [herdr ws-server --port 8080 ...]    ← on remote machine
//!     ↓ Unix socket (herdr-client.sock)
//! [herdr headless server]
//! ```
//!
//! Security layers:
//! - Phase 2: Bearer token in HTTP upgrade `Authorization` header
//! - Phase 3: TLS (wss://) with self-signed cert + SHA-256 fingerprint pinning
//! - Phase 4: SSH public-key challenge-response over the WebSocket channel

pub mod auth;
pub mod bridge;
pub mod control;
pub mod server;
pub mod tls;

pub use bridge::run_ws_client_bridge;
pub use server::run_ws_server;
