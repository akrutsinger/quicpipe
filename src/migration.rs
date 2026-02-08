//! Network interface monitoring for QUIC connection migration.
//!
//! This module provides lightweight interface monitoring using the `if-addrs` crate. When a network
//! change is detected (IP address change on the interface used for the connection), it triggers a
//! rebind on the QUIC endpoint to initiate connection migration.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use quinn::Endpoint;
use tokio::sync::watch;

/// Default polling interval for interface changes.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Get current IP addresses matching the given address family.
fn get_ips_for_family(target: SocketAddr) -> HashSet<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .map(|iface| iface.ip())
                .filter(|ip| {
                    matches!(
                        (ip, &target),
                        (IpAddr::V4(_), SocketAddr::V4(_)) | (IpAddr::V6(_), SocketAddr::V6(_))
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

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
/// * `poll_interval` - How often to check for interface changes
pub fn spawn_migration_monitor(
    endpoint: Endpoint,
    target: SocketAddr,
    poll_interval: Duration,
) -> watch::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(());

    tokio::spawn(async move {
        let mut last_ips = get_ips_for_family(target);

        tracing::debug!(
            "Migration monitor started, tracking {} addresses",
            last_ips.len()
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                _ = shutdown_rx.changed() => {
                    tracing::debug!("Migration monitor shutting down");
                    break;
                }
            }

            let current_ips = get_ips_for_family(target);
            if current_ips == last_ips {
                continue;
            }

            let removed: Vec<_> = last_ips.difference(&current_ips).collect();
            let added: Vec<_> = current_ips.difference(&last_ips).collect();
            tracing::debug!("IP changes - added: {:?}, removed: {:?}", added, removed);

            if !removed.is_empty() {
                let old_local = endpoint.local_addr().ok();
                let new_addr = wildcard_bind_addr(target);
                match std::net::UdpSocket::bind(new_addr) {
                    Ok(socket) => match endpoint.rebind(socket) {
                        Ok(()) => {
                            tracing::info!(
                                "Connection migration: {:?} -> {:?}",
                                old_local,
                                endpoint.local_addr().ok()
                            );
                        }
                        Err(e) => tracing::warn!("Failed to rebind endpoint: {}", e),
                    },
                    Err(e) => tracing::warn!("Failed to bind new socket to {}: {}", new_addr, e),
                }
            }

            last_ips = current_ips;
        }
    });

    shutdown_tx
}
