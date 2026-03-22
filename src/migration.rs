//! Network interface monitoring for QUIC connection migration.
//!
//! This module provides event-driven interface monitoring using the `netwatcher` crate. When a
//! network change is detected (IP address removed from an interface matching the connection's
//! address family), it triggers a rebind on the QUIC endpoint to initiate connection migration.

use std::collections::HashMap;
use std::net::SocketAddr;

use quinn::Endpoint;
use tokio::sync::watch;

/// Get a wildcard bind address matching the IP version of the target.
///
/// Uses the wildcard address (`0.0.0.0:0` or `[::]:0`) so the kernel picks the source IP
/// automatically based on routing. This avoids binding to a specific IP that could become invalid
/// on the next network change.
fn wildcard_bind_addr(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    }
}

/// Spawns a task that monitors network interfaces and triggers rebind when changes occur.
///
/// Returns a shutdown sender that can be used to stop the monitoring task.
///
/// # Arguments
/// * `endpoint` - The QUIC endpoint to rebind on network changes
/// * `target` - The remote server address (used to match IP version)
pub(crate) fn spawn_migration_monitor(endpoint: Endpoint, target: SocketAddr) -> watch::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(());

    tokio::spawn(async move {
        let (rebind_tx, mut rebind_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        let is_v4 = target.is_ipv4();
        let mut prev_interfaces: HashMap<u32, netwatcher::Interface> = HashMap::new();

        let watch_result = netwatcher::watch_interfaces(move |update| {
            let should_rebind =
                // Any removed interface that previously had IPs of our family
                update.diff.removed.iter().any(|idx| {
                    prev_interfaces
                        .get(idx)
                        .is_some_and(|iface| iface.ips.iter().any(|r| is_v4 == r.ip.is_ipv4()))
                }) ||
                // Any modified interface that lost IPs of our family
                update.diff.modified.values().any(|diff| {
                    diff.addrs_removed.iter().any(|r| is_v4 == r.ip.is_ipv4())
                });

            // Track previous state so we can look up IPs of removed interfaces (removed interfaces
            // only appear as indices in the diff)
            prev_interfaces.clone_from(&update.interfaces);

            if should_rebind {
                let _ = rebind_tx.send(());
            }
        });

        let _watch_handle = match watch_result {
            Ok(handle) => {
                tracing::debug!("migration monitor started");
                handle
            }
            Err(e) => {
                tracing::warn!("failed to start migration monitor: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                Some(()) = rebind_rx.recv() => {
                    let old_local = endpoint.local_addr().ok();
                    let new_addr = wildcard_bind_addr(target);
                    match std::net::UdpSocket::bind(new_addr) {
                        Ok(socket) => match endpoint.rebind(socket) {
                            Ok(()) => {
                                tracing::info!(
                                    "connection migration: {:?} -> {:?}",
                                    old_local,
                                    endpoint.local_addr().ok()
                                );
                            }
                            Err(e) => tracing::warn!("failed to rebind endpoint: {e}"),
                        },
                        Err(e) => tracing::warn!("failed to bind new socketto {new_addr}: {e}"),
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::debug!("migration monitor shutting down");
                    break;
                }
            }
        }
    });

    shutdown_tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_bind_addr_v4() {
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let addr = wildcard_bind_addr(target);
        assert!(addr.ip().is_unspecified());
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn wildcard_bind_addr_v6() {
        let target: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let addr = wildcard_bind_addr(target);
        assert!(addr.ip().is_unspecified());
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 0);
    }
}
