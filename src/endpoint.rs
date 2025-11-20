//! QUIC endpoint creation and configuration.

use anyhow::Result;
use quinn::Endpoint;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::config::CommonArgs;

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self)
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Creates a QUIC server config with a self-signed certificate.
pub fn configure_server(alpns: Vec<Vec<u8>>) -> Result<(quinn::ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("Failed to serialize private key: {}", e))?;
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;

    server_crypto.alpn_protocols = alpns;

    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let transport_config = std::sync::Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    // Set the idle timeout to higher values
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(5 * 60).try_into()?));

    Ok((server_config, cert_der))
}

/// Creates a QUIC client config that skips certificate verification.
pub fn configure_client(alpns: Vec<Vec<u8>>) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    crypto.alpn_protocols = alpns;

    // Set timeout to 5min
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(5 * 60).try_into()?));

    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(transport_config.into());

    Ok(client_config)
}

/// Creates a QUIC endpoint with both server and client capabilities.
pub async fn create_endpoint(common: &CommonArgs, alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    let bind_addr = common.bind_addr();

    let (server_config, _cert_der) = configure_server(alpns.clone())?;
    let client_config = configure_client(alpns)?;

    // Create and bind the endpoint
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Creates a QUIC endpoint bound to an address matching the target's IP version.
///
/// Even though this is indeed a client endpoint, it is created with both server and client
/// capabilities to allow for flexibility in usage (e.g., accepting incoming connections if needed)
/// to support various QUIC functionality like hole punching and connection migration.
pub async fn create_client_endpoint(
    common: &CommonArgs,
    alpns: Vec<Vec<u8>>,
    target: std::net::SocketAddr,
) -> Result<Endpoint> {
    let bind_addr = common.bind_addr_for_target(target);

    let (server_config, _cert_der) = configure_server(alpns.clone())?;
    let client_config = configure_client(alpns)?;

    // Create and bind the endpoint with both server and client capabilities
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}
