use std::sync::{Arc, OnceLock};

use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
    MD_5_WITH_RSA_ENCRYPTION, SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};

use crate::error::{Error, Result};
use crate::opts::Opts;

/// Returns `opts.tls_config`, or the shared platform config when it is unset.
pub fn client_config(opts: &Opts) -> Result<Arc<ClientConfig>> {
    match &opts.tls_config {
        Some(config) => Ok(Arc::clone(config)),
        None => platform_client_config(),
    }
}

/// Returns the rustls client config shared by all TLS connections without
/// `Opts::tls_config`.
///
/// The platform verifier is built on the first call and reused afterwards.
fn platform_client_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    let config = Arc::new(build_client_config()?);
    Ok(Arc::clone(CONFIG.get_or_init(|| config)))
}

fn build_client_config() -> Result<ClientConfig> {
    // An explicit provider avoids a panic when both aws-lc-rs and ring are
    // enabled in the dependency graph and no process default is installed.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth())
}

pub fn server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| Error::InvalidUsage(format!("invalid TLS server name {host:?}: {e}")))
}

pub fn tls_server_end_point(certificate: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let signature_algorithm = Certificate::from_der(certificate)
        .ok()?
        .signature_algorithm()
        .oid;
    match signature_algorithm {
        MD_5_WITH_RSA_ENCRYPTION
        | SHA_1_WITH_RSA_ENCRYPTION
        | SHA_256_WITH_RSA_ENCRYPTION
        | ECDSA_WITH_SHA_256 => Some(Sha256::digest(certificate).to_vec()),
        SHA_224_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_224 => {
            Some(Sha224::digest(certificate).to_vec())
        }
        SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => {
            Some(Sha384::digest(certificate).to_vec())
        }
        SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => {
            Some(Sha512::digest(certificate).to_vec())
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    pub(crate) const ECDSA_SHA256_CERTIFICATE: &str = "MIIBbjCCAROgAwIBAgIUasFTZMaMUPyZ0QsjJUXoQBrtl+kwCgYIKoZIzj0EAwIwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAwYHeOfV8e+LZRkPrN54YtRK3Z77nzZNWl+XPEx8qm/gCIQCCHiR9ohH1MyZSkL5Mu2mBu2JfW4q29eDgRB8xsURQjA==";
    pub(crate) const ECDSA_SHA256_END_POINT: &str = "uOaTl9N0AszO9Xq50+zSSqtTcvdgy2WoIwLIpvRQwKI=";

    const ECDSA_SHA384_CERTIFICATE: &str = "MIIBbTCCAROgAwIBAgIUWBbjmLp4i1+Vz+6fxjE9IaUnNl0wCgYIKoZIzj0EAwMwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNIADBFAiEApki8wjwMWM8hrgB4zlZCFI76qy9/IyXGh+KVr5oYTZkCIDn3j24kXHeKmP76Wenz6wFEWCJQ24tr+JEZkNWco0qV";
    const ECDSA_SHA384_END_POINT: &str =
        "3bJ+x7Vld4HoJruu/z3f5fmN+KDo6iVHfs7D2qMpnXmdMsd8WAnBxP5BfqBKxVhq";

    const ECDSA_SHA512_CERTIFICATE: &str = "MIIBbTCCAROgAwIBAgIUNM8k5xZ+fVLzO7mGBywKmrxfWnIwCgYIKoZIzj0EAwQwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDBANIADBFAiEAk63vdkPOOMgtf6ZvPWPmt5znPS+IcNg/9EsCJIVamSMCIA5ruX/ifu4AeHfbeTY/YVEW6K5Z1El48xfMmMhRdM5U";
    const ECDSA_SHA512_END_POINT: &str =
        "dtI+xnLxSSpPYFjFk74gpU+KFtemmyrbucJJBBQMyL3lYaLjXSWrCUzBWXTqR3SKBh44FxNE6R3mP++tirfTNg==";

    const RSA_SHA256_CERTIFICATE: &str = "MIIB9DCCAV2gAwIBAgIUSosdcOqNowour/G35w8U46MFeqYwDQYJKoZIhvcNAQELBQAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2CgxzffyEMf1HklxiErM3zAIQuLiSpUhdnr4NC99Btlp0oziXXUE0zlADp+t+ASKsQ51gU0wNhfM9kf2wkNLcvBqaN3MDaXr78NL9NrmxaV8JfdtMMPpnW/nK3hAchK8GtsuzH7YFCC/+LUiAoUZOAdCGd1bhD17RbigK4LnD1AgMBAAGjUzBRMB0GA1UdDgQWBBTtWZM7zFYMXuGnKLEWie0SN2flXjAfBgNVHSMEGDAWgBTtWZM7zFYMXuGnKLEWie0SN2flXjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAK90e5aajlFtBZC7AQbgve1MPP/tO8wGxvX+olrrSt5qzB0OOFWFGo2gnHGtEFH+YyaQLGw+9xHpCvTNeJLjJlDVJB7LMv+luDdVx+kRVnaYTLJ1iBtWiWtcMYuhVWTwYb38IwZe8Pd4cDbt655gjKiTxQOLCLIZezdGLRSljw3v";
    const RSA_SHA256_END_POINT: &str = "3Jh/GMRofKru7lb0QyNh7efpkoNUga4lDWrqczZokqw=";

    const RSA_SHA1_CERTIFICATE: &str = "MIIB9DCCAV2gAwIBAgIUHt+arhdme9FGK2jJBG+ubgoAdWcwDQYJKoZIhvcNAQEFBQAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2CgxzffyEMf1HklxiErM3zAIQuLiSpUhdnr4NC99Btlp0oziXXUE0zlADp+t+ASKsQ51gU0wNhfM9kf2wkNLcvBqaN3MDaXr78NL9NrmxaV8JfdtMMPpnW/nK3hAchK8GtsuzH7YFCC/+LUiAoUZOAdCGd1bhD17RbigK4LnD1AgMBAAGjUzBRMB0GA1UdDgQWBBTtWZM7zFYMXuGnKLEWie0SN2flXjAfBgNVHSMEGDAWgBTtWZM7zFYMXuGnKLEWie0SN2flXjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBALWLbMdCZ8AS44qKZA1JvTjjGQM+uz2QbD8WTpin5fmOLouASrExn/ZVMGrjxGr3jhh6cYGT4ZblGEbgJ1FCOOHwhwVPuJB0RX4l0TfcQofm6AB56qokgDh4hmQTkbFv1KLY8tcsqaOsbYfHNA78lve2LaHXsjHXQAponVKhaZRF";
    const RSA_SHA1_END_POINT: &str = "Qv47MT4jLNH88nKB6NZ12QARNmv8lLn7OF8iVnIO3Eo=";

    pub(crate) const ED25519_CERTIFICATE: &str = "MIIBLDCB36ADAgECAhQP41jlX5clwMzHyiXLxwDG9a7awTAFBgMrZXAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwKjAFBgMrZXADIQC9PCz1tfRaOXpWBjIcz6s5FGEykzOZGmXWVEMRH5Yza6NTMFEwHQYDVR0OBBYEFJCBKQpCDsK6JlYvrmPllhcep6cHMB8GA1UdIwQYMBaAFJCBKQpCDsK6JlYvrmPllhcep6cHMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAnE9mLmQCfY4BlySSz/MafQ93G1o4VppD360iXX45jdYFjcx+r+PkI/UnFvBs2sZe4+a4McU+ZFzHz8f4D99IBQ==";

    fn decode(encoded: &str) -> Vec<u8> {
        STANDARD.decode(encoded).unwrap()
    }

    fn end_point_of(encoded_certificate: &str) -> Option<Vec<u8>> {
        tls_server_end_point(&CertificateDer::from(decode(encoded_certificate)))
    }

    #[test]
    fn ecdsa_with_sha256_hashes_with_sha256() {
        let end_point = end_point_of(ECDSA_SHA256_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(ECDSA_SHA256_END_POINT));
    }

    #[test]
    fn ecdsa_with_sha384_hashes_with_sha384() {
        let end_point = end_point_of(ECDSA_SHA384_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 48);
        assert_eq!(end_point, decode(ECDSA_SHA384_END_POINT));
    }

    #[test]
    fn ecdsa_with_sha512_hashes_with_sha512() {
        let end_point = end_point_of(ECDSA_SHA512_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 64);
        assert_eq!(end_point, decode(ECDSA_SHA512_END_POINT));
    }

    #[test]
    fn sha256_with_rsa_hashes_with_sha256() {
        let end_point = end_point_of(RSA_SHA256_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_SHA256_END_POINT));
    }

    #[test]
    fn sha1_with_rsa_upgrades_to_sha256() {
        let end_point = end_point_of(RSA_SHA1_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_SHA1_END_POINT));
    }

    #[test]
    fn ed25519_has_no_end_point() {
        assert_eq!(end_point_of(ED25519_CERTIFICATE), None);
    }

    #[test]
    fn non_certificate_bytes_have_no_end_point() {
        assert_eq!(
            tls_server_end_point(&CertificateDer::from(b"not a certificate".to_vec())),
            None
        );
        assert_eq!(
            tls_server_end_point(&CertificateDer::from(Vec::new())),
            None
        );
    }
}
