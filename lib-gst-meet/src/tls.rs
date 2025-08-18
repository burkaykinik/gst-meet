#[cfg(any(
  feature = "tls-rustls-native-roots",
  feature = "tls-rustls-webpki-roots"
))]
use std::sync::Arc;

#[cfg(not(feature = "tls-insecure"))]
use anyhow::bail;
use anyhow::{Context, Result};
use tokio_tungstenite::Connector;

#[cfg(feature = "tls-rustls-native-roots")]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut roots = rustls::RootCertStore::empty();
  for cert in
    rustls_native_certs::load_native_certs().context("failed to load native root certs")?
  {
    roots.add(cert).context("failed to add native root certs")?;
  }

  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  #[cfg(feature = "tls-insecure")]
  if insecure {
    config
      .dangerous()
      .set_certificate_verifier(Arc::new(InsecureServerCertVerifier));
  }
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::Rustls(Arc::new(config)))
}

#[cfg(feature = "tls-rustls-webpki-roots")]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut roots = rustls::RootCertStore::empty();
  roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject,
      ta.spki,
      ta.name_constraints,
    )
  }));

  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  #[cfg(feature = "tls-insecure")]
  if insecure {
    config
      .dangerous()
      .set_certificate_verifier(Arc::new(InsecureServerCertVerifier));
  }
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::Rustls(Arc::new(config)))
}

#[cfg(any(feature = "tls-native", feature = "tls-native-vendored"))]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut builder = native_tls::TlsConnector::builder();
  builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
  #[cfg(feature = "tls-insecure")]
  if insecure {
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
  }
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::NativeTls(
    builder
      .build()
      .context("failed to build native TLS connector")?,
  ))
}

#[cfg(all(
  feature = "tls-insecure",
  any(
    feature = "tls-rustls-native-roots",
    feature = "tls-rustls-webpki-roots"
  )
))]
#[derive(Debug)] 
struct InsecureServerCertVerifier;

#[cfg(all(
  feature = "tls-insecure",
  any(
    feature = "tls-rustls-native-roots",
    feature = "tls-rustls-webpki-roots"
  )
))]
impl rustls::client::danger::ServerCertVerifier for InsecureServerCertVerifier {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer,
    _intermediates: &[rustls::pki_types::CertificateDer],
    _server_name: &rustls::pki_types::ServerName,
    _ocsp_response: &[u8],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    vec![
      rustls::SignatureScheme::RSA_PKCS1_SHA1,
      rustls::SignatureScheme::ECDSA_SHA1_Legacy,
      rustls::SignatureScheme::RSA_PKCS1_SHA256,
      rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
      rustls::SignatureScheme::RSA_PKCS1_SHA384,
      rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
      rustls::SignatureScheme::RSA_PKCS1_SHA512,
      rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
      rustls::SignatureScheme::RSA_PSS_SHA256,
      rustls::SignatureScheme::RSA_PSS_SHA384,
      rustls::SignatureScheme::RSA_PSS_SHA512,
      rustls::SignatureScheme::ED25519,
      rustls::SignatureScheme::ED448,
    ]
  }
}