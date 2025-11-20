//! Stream forwarding utilities.

use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

/// Copy from a reader to a quinn stream.
///
/// Will gracefully finish the stream when done, or send reset if cancelled.
///
/// Returns the number of bytes copied in case of success.
pub async fn copy_to_quinn(
    mut from: impl AsyncRead + Unpin,
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tracing::trace!("copying to quinn");
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            // Gracefully finish the stream instead of resetting
            send.finish().ok();
            Ok(size)
        }
        _ = token.cancelled() => {
            // Gracefully finish instead of reset to avoid "reset by peer" errors
            send.finish().ok();
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        }
    }
}

/// Copy from a quinn stream to a writer.
///
/// Will gracefully handle stream completion or cancellation.
///
/// Returns the number of bytes copied in case of success.
pub async fn copy_from_quinn(
    mut recv: quinn::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => {
            match res {
                Ok(size) => Ok(size),
                Err(e) => {
                    // Check if this is a stream reset error
                    if is_quinn_reset_error(&e) {
                        tracing::debug!("stream finished by peer");
                        Ok(0)
                    } else {
                        Err(e)
                    }
                }
            }
        },
        _ = token.cancelled() => {
            // Don't send stop - just let the stream close naturally
            recv.stop(0u8.into()).ok();
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        }
    }
}

/// Check if an IO error is a Quinn stream reset error
fn is_quinn_reset_error(err: &io::Error) -> bool {
    let err_str = err.to_string().to_lowercase();
    err_str.contains("reset") || err_str.contains("stream")
}

pub fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio reader/writer pair,
/// aborting both sides when either one forwarder is done, or when control-c is pressed.
pub async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
) -> anyhow::Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
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
    let _control_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });

    // Wait for both tasks and handle errors gracefully
    let stdout_result = forward_to_stdout.await?;
    let stdin_result = forward_from_stdin.await?;

    // Check if either failed with a non-cancellation error
    match (stdout_result, stdin_result) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
            // Cancellation is expected and not an error
            Ok(())
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}
