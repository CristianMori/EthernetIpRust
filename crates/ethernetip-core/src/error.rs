//! Central error type shared across every crate in the workspace.
//!
//! Each variant maps to a distinct wire / runtime failure — `Io` for socket
//! problems, `Encap` for a non-zero encapsulation status, `Cip` for a non-zero
//! CIP general status (with any extended-status words), `Short` for a
//! truncated buffer, `Protocol` for a wire-structure mismatch, and the
//! session-lifecycle variants for register / close bookkeeping.

use std::io;
use thiserror::Error;

/// All errors surfaced by the core transport.
#[derive(Debug, Error)]
pub enum EipError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Non-zero status in the encapsulation header of a reply.
    #[error("EIP encapsulation status 0x{0:08X}")]
    Encap(u32),

    /// Non-zero CIP general status in a reply.
    #[error("CIP status 0x{status:02X}{ext_suffix}", ext_suffix = format_ext(ext))]
    Cip { status: u8, ext: Vec<u16> },

    /// Reply too short for the operation being decoded.
    #[error("short reply: got {actual} bytes, need at least {expected}")]
    Short { expected: usize, actual: usize },

    /// Wire structure did not match what the decoder expected.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Operation attempted before [`EipSession::register`] succeeded.
    #[error("session is not registered")]
    NotRegistered,

    /// Operation attempted on a closed session.
    #[error("session is closed")]
    Closed,
}

fn format_ext(ext: &[u16]) -> String {
    if ext.is_empty() {
        String::new()
    } else {
        let words: Vec<String> = ext.iter().map(|w| format!("0x{:04X}", w)).collect();
        format!(" (ext: {})", words.join(", "))
    }
}

/// Convenience alias for `Result<T, EipError>`.
pub type Result<T> = std::result::Result<T, EipError>;
