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

/// Get all current IP addresses from network interfaces.
fn get_current_ips() -> HashSet<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|ifaces| ifaces.into_iter().map(|iface| iface.ip()).collect())
        .unwrap_or_default()
}

/// Check if a specific IP address is still available on any interface.
fn is_ip_available(ip: IpAddr) -> bool {
    get_current_ips().contains(&ip)
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
        // Track the last known set of IPs
        let mut last_ips = get_current_ips();
        let mut last_local_addr = endpoint.local_addr().ok();

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

            let current_ips = get_current_ips();

            // Check if the set of IPs has changed
            if current_ips != last_ips {
                tracing::info!(
                    "Network change detected: {} -> {} addresses",
                    last_ips.len(),
                    current_ips.len()
                );

                // Check if our current local address is still valid
                let local_addr = endpoint.local_addr().ok();
                let current_local_ip = local_addr.map(|a| a.ip());

                let need_rebind = match current_local_ip {
                    Some(ip) if !is_ip_available(ip) => {
                        tracing::info!("Local address {} no longer available", ip);
                        true
                    }
                    _ if current_ips != last_ips => {
                        // IPs changed - might be on a new network
                        // Check if we should proactively rebind
                        let added: HashSet<_> = current_ips.difference(&last_ips).collect();
                        let removed: HashSet<_> = last_ips.difference(&current_ips).collect();

                        tracing::debug!("IP changes - added: {:?}, removed: {:?}", added, removed);

                        // Rebind if our local address was removed or if significant changes
                        !removed.is_empty()
                    }
                    _ => false,
                };

                if need_rebind {
                    let new_addr = wildcard_bind_addr(target);
                    match std::net::UdpSocket::bind(new_addr) {
                        Ok(socket) => match endpoint.rebind(socket) {
                            Ok(()) => {
                                let new_local = endpoint.local_addr().ok();
                                tracing::info!(
                                    "Connection migration: {:?} -> {:?}",
                                    last_local_addr,
                                    new_local
                                );
                                last_local_addr = new_local;
                            }
                            Err(e) => {
                                tracing::warn!("Failed to rebind endpoint: {}", e);
                            }
                        },
                        Err(e) => {
                            tracing::warn!("Failed to bind new socket to {}: {}", new_addr, e);
                        }
                    }
                }

                last_ips = current_ips;
            }
        }
    });

    shutdown_tx
}
