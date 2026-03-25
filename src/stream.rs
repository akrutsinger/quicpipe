//! Stream forwarding utilities.

use std::io;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

/// Copy from a reader to a quinn stream.
///
/// Will gracefully finish the stream when done, or send reset if cancelled. Also exits gracefully
/// if the peer sends `STOP_SENDING` (`send.stopped()`).
///
/// Returns the number of bytes copied in case of success.
pub(crate) async fn copy_to_quinn(
    mut from: impl AsyncRead + Unpin,
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tracing::trace!("copying to quinn");
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            send.finish().ok();
            Ok(size)
        }
        _ = token.cancelled() => {
            send.reset(0u8.into()).ok();
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        }
    }
}

/// Copy from a quinn stream to a writer.
///
/// Will gracefully handle stream completion or cancellation.
///
/// Returns the number of bytes copied in case of success.
pub(crate) async fn copy_from_quinn(
    mut recv: quinn::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => Ok(res?),
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        }
    }
}

fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

fn finish_result(stdout_result: io::Result<u64>, stdin_result: io::Result<u64>) -> Result<()> {
    match (stdout_result, stdin_result) {
        (Ok(down), Ok(up)) => {
            tracing::debug!("forwarded {up} bytes up, {down} bytes down");
            Ok(())
        }
        (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
            // Cancellation is expected and not an error
            Ok(())
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

/// Bidirectionally forward data between a quinn stream and an arbitrary tokio reader/writer pair.
///
/// Both directions run concurrently. Either direction erroring cancels the other. Use this for
/// TCP/QUIC bridge scenarios where a response may arrive after the request stream closes.
pub(crate) async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
    cancel: CancellationToken,
) -> Result<()> {
    let local = cancel.child_token();
    let token1 = local.clone();
    let token2 = local.clone();
    let forward_from_stdin = tokio::spawn(async move {
        copy_to_quinn(from1, to2, token1.clone())
            .await
            .map_err(cancel_token(token1))
    });
    let forward_to_stdout = tokio::spawn(async move {
        copy_from_quinn(from2, to1, token2.clone())
            .await
            .map_err(cancel_token(token2))
    });

    let (stdout_result, stdin_result) = tokio::join!(forward_to_stdout, forward_from_stdin);
    finish_result(stdout_result?, stdin_result?)
}

/// Bidirectionally forward data between a quinn stream and stdio (stdin/stdout).
///
/// Unlike [`forward_bidi`], when either direction completes (successfully or with an error), the
/// other is cancelled. This prevents TTY stdin from blocking indefinitely after the remote peer
/// closes its send stream, which would otherwise deadlock the connection.
pub(crate) async fn forward_stdio(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
    cancel: CancellationToken,
) -> Result<()> {
    let local = cancel.child_token();
    let token1 = local.clone();
    let token2 = local.clone();
    let forward_from_stdin = tokio::spawn(async move {
        let result = copy_to_quinn(from1, to2, token1.clone()).await;
        token1.cancel();
        result
    });
    let forward_to_stdout = tokio::spawn(async move {
        let result = copy_from_quinn(from2, to1, token2.clone()).await;
        token2.cancel();
        result
    });

    let (stdout_result, stdin_result) = tokio::join!(forward_to_stdout, forward_from_stdin);
    finish_result(stdout_result?, stdin_result?)
}
