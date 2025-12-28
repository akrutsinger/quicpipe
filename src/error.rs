//! Error handling utilities for connection and stream errors.

use std::io;

/// Check if an IO error represents a graceful connection close.
pub fn is_io_close_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Interrupted
    )
}

/// Check if an anyhow::Error represents a graceful connection close or reset.
///
/// This checks for:
/// - Standard IO errors (ConnectionReset, BrokenPipe, etc.)
/// - Quinn connection errors (ConnectionClosed, Reset, etc.)
/// - Quinn read errors (ConnectionLost, Reset)
pub fn is_graceful_close(err: &anyhow::Error) -> bool {
    // Check for io::Error
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        return is_io_close_error(io_err);
    }

    // Check for Quinn connection errors
    if let Some(conn_err) = err.downcast_ref::<quinn::ConnectionError>() {
        return matches!(
            conn_err,
            quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::Reset
                | quinn::ConnectionError::LocallyClosed
        );
    }

    // Check for Quinn read errors
    if let Some(read_err) = err.downcast_ref::<quinn::ReadError>() {
        return matches!(
            read_err,
            quinn::ReadError::ConnectionLost(_) | quinn::ReadError::Reset(_)
        );
    }

    false
}
